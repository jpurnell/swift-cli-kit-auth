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
        let authentication: Authentication
        do {
            authentication = try await firstAuthentication(sources, authenticator: authenticator, presenter: presenter)
        } catch SignInError.cancelled {
            throw SignInError.cancelled
        } catch SignInError.inputEnded {
            throw SignInError.inputEnded
        } catch {
            await presenter.show(.failed)
            throw SignInError.failed
        }
        guard await admission.admits(authentication) else {
            await presenter.show(.failed)
            throw SignInError.failed
        }
        return await AccessLease(
            authentication: authentication, sessions: sessions, lifetime: lifetime,
            reresolveEvery: reresolveEvery,
            stepUp: StepUp(sources: sources, authenticator: authenticator, presenter: presenter),
            now: now, clock: clock, generator: &generator
        )
    }

    /// The first source's credentials that resolve, or ``SignInError/failed`` if none do.
    private static func firstAuthentication(
        _ sources: [any CredentialSource], authenticator: Authenticator, presenter: any SignInPresenter
    ) async throws -> Authentication {
        let context = SignInContext(presenter: presenter)
        for source in sources {
            guard let credentials = try await source.credentials(context) else { continue }
            if let authentication = await authenticator.authentication(for: credentials) {
                return authentication
            }
        }
        throw SignInError.failed
    }
}
