// CLISignIn.swift
// SwiftCLIKitAuth
// Created by Justin Purnell on 2026-10-25.

import Foundation
import SwiftIdentity

/// Signs someone in from a command line: experience A.
///
/// ```swift
/// import SwiftCLIKit
/// import SwiftCLIKitAuth
/// import SwiftIdentity
///
/// func signIn(people: FileCredentialStore, terminal: any TerminalBackend) async throws -> AccessLease {
///     let sessions = SessionStore(subjects: { id in people.subject(id: id) })
///     var generator = SystemRandomNumberGenerator()
///     return try await CLISignIn.signIn(
///         sources: [Together(PromptedPassword(), PromptedCode())],
///         authenticator: Authenticator(stores: [people], audit: nil, now: { Date() }),
///         admission: .minimumAssurance(.multiFactor),
///         presenter: TerminalPresenter(backend: terminal),
///         sessions: sessions, lifetime: 8 * 3600, reresolveEvery: .seconds(300),
///         generator: &generator
///     )
/// }
/// ```
public enum CLISignIn {

    /// Runs the sources in order until one signs someone in the app admits, and starts their lease.
    ///
    /// - A source that doesn't apply, or whose credentials don't resolve to a subject, passes to
    ///   the next: an unrecognised key falls through to a device sign-in.
    /// - A source that throws stops the sign-in. No later source is asked. A cancellation is
    ///   rethrown as it is; any other error fails the sign-in.
    /// - A subject that resolves but isn't admitted fails the sign-in at once.
    ///
    /// Every failure shows ``SignInPrompt/failed`` and nothing more: why is for SwiftIdentity's
    /// audit, through the `Authenticator`'s caller-facing `authentication(for:)`, which can't say.
    ///
    /// - Parameters:
    ///   - sources: Tried in order.
    ///   - authenticator: Decides who the credentials prove.
    ///   - admission: Whether the app admits them.
    ///   - presenter: How to talk to the person.
    ///   - sessions: Where the lease's session token is minted; its `subjects` lookup must read
    ///     the live roster.
    ///   - lifetime: How long the session lasts, in seconds.
    ///   - reresolveEvery: How often the lease re-checks the session: the longest a revocation
    ///     goes unnoticed.
    ///   - now: The wall clock, the one `sessions` reads.
    ///   - clock: What the lease's re-checks sleep on.
    ///   - generator: The randomness the session token is drawn from.
    /// - Returns: The admitted person's lease, which can step up through the same sources.
    /// - Throws: ``SignInError/failed``, ``SignInError/cancelled`` or ``SignInError/inputEnded``.
    public static func signIn<Generator: RandomNumberGenerator & Sendable>(
        sources: [any CredentialSource],
        authenticator: Authenticator,
        admission: Admission,
        presenter: any SignInPresenter,
        sessions: SessionStore,
        lifetime: TimeInterval,
        reresolveEvery: Duration,
        now: @escaping @Sendable () -> Date = { Date() },
        clock: any Clock<Duration> = ContinuousClock(),
        generator: inout Generator
    ) async throws -> AccessLease {
        let (authentication, _) = try await SignInRun.authenticate(
            sources, authenticator: authenticator, admission: admission, presenter: presenter
        )
        return await AccessLease(
            authentication: authentication, sessions: sessions, lifetime: lifetime,
            reresolveEvery: reresolveEvery,
            stepUp: StepUp(sources: sources, authenticator: authenticator, presenter: presenter),
            now: now, clock: clock, generator: &generator
        )
    }
}

/// The sign-in loop `CLISignIn` and the SSH sign-in gate share.
package enum SignInRun {

    /// Runs sources in order until one's credentials resolve, and checks admission.
    ///
    /// A source that doesn't apply, or whose credentials don't resolve, passes to the next; one
    /// that throws stops the run, a cancellation or end of input rethrown as itself and anything
    /// else as ``SignInError/failed``. A resolved subject that isn't admitted fails at once. Every
    /// failure shows ``SignInPrompt/failed`` first.
    /// - Returns: The authentication, and the credentials that produced it.
    package static func authenticate(
        _ sources: [any CredentialSource], authenticator: Authenticator, admission: Admission,
        presenter: any SignInPresenter
    ) async throws -> (Authentication, [any Credential]) {
        let found: Found
        do {
            found = try await firstResolving(sources, authenticator: authenticator, presenter: presenter)
        } catch SignInError.cancelled {
            throw SignInError.cancelled
        } catch SignInError.inputEnded {
            throw SignInError.inputEnded
        } catch {
            await presenter.show(.failed)
            throw SignInError.failed
        }
        guard await admission.admits(found.authentication) else {
            await found.observe(.notAdmitted)
            await presenter.show(.failed)
            throw SignInError.failed
        }
        await found.observe(.admitted)
        return (found.authentication, found.credentials)
    }

    /// The credentials that resolved, what they proved, and who to tell how they fared.
    private struct Found {
        let authentication: Authentication
        let credentials: [any Credential]
        let observe: @Sendable (SignInOutcome) async -> Void
    }

    /// The first source's credentials that resolve, or ``SignInError/failed`` if none do. A
    /// source whose credentials don't resolve is told so before the next is asked.
    private static func firstResolving(
        _ sources: [any CredentialSource], authenticator: Authenticator, presenter: any SignInPresenter
    ) async throws -> Found {
        let context = SignInContext(presenter: presenter)
        for source in sources {
            guard let gathered = try await gather(source, context) else { continue }
            if let authentication = await authenticator.authentication(for: gathered.credentials) {
                return Found(authentication: authentication, credentials: gathered.credentials, observe: gathered.observe)
            }
            await gathered.observe(.unresolved)
        }
        throw SignInError.failed
    }

    /// A source's credentials, with its observer if it has one.
    private static func gather(_ source: any CredentialSource, _ context: SignInContext) async throws -> ObservedCredentials? {
        if let observing = source as? any OutcomeObservingSource {
            return try await observing.gather(context)
        }
        return try await source.credentials(context).map(ObservedCredentials.unobserved)
    }
}

/// How a source's credentials fared in a sign-in.
enum SignInOutcome: Sendable, Equatable {
    /// They didn't resolve to a subject.
    case unresolved
    /// They resolved, but the app doesn't admit the subject.
    case notAdmitted
    /// They signed the person in.
    case admitted
}

/// Credentials, and who to tell how they fared.
struct ObservedCredentials: Sendable {
    /// The credentials to present.
    let credentials: [any Credential]
    /// Told the outcome once, by the sign-in loop.
    let observe: @Sendable (SignInOutcome) async -> Void

    /// Credentials whose outcome nobody needs.
    static func unobserved(_ credentials: [any Credential]) -> ObservedCredentials {
        ObservedCredentials(credentials: credentials, observe: { _ in })
    }
}

/// A source that learns how its credentials fared, so it can remember or forget them.
///
/// Only ``SignInRun`` reports outcomes: nested in ``Together``, or asked by
/// ``AccessLease/reverify(minimum:maximumAge:)``, such a source presents its credentials and
/// learns nothing.
protocol OutcomeObservingSource: CredentialSource {
    /// The credentials, with the observer for this one sign-in.
    /// - Parameter context: Where it runs.
    /// - Returns: The credentials and their observer, or `nil` if the source doesn't apply.
    /// - Throws: As ``CredentialSource/credentials(_:)`` does.
    func gather(_ context: SignInContext) async throws -> ObservedCredentials?
}
