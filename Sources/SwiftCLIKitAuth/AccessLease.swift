// AccessLease.swift
// SwiftCLIKitAuth
// Created by Justin Purnell on 2026-10-25.

import Foundation
import SwiftIdentity

/// Why an ``AccessLease`` ended.
public enum LeaseEnd: Sendable, Equatable {
    /// The app ended it, with ``AccessLease/end()``: the person signed out.
    case signedOut
    /// The session stopped resolving before it lapsed: the subject was revoked or removed from
    /// the roster, or its sessions were revoked (`SessionStore.revokeAll(forSubject:)`).
    case revoked
    /// The session reached the end of its lifetime.
    case expired
}

/// How an ``AccessLease`` proves more when ``AccessLease/reverify(minimum:maximumAge:)`` needs it.
///
/// The sources are asked in order and the first that returns credentials is the one
/// authenticated, so a step-up to multi-factor is one source presenting both factors together:
/// SwiftIdentity computes assurance from one set of credentials, never by adding sets up.
///
/// ```swift
/// import SwiftCLIKitAuth
/// import SwiftIdentity
///
/// struct NoPresenter: SignInPresenter {
///     func show(_ prompt: SignInPrompt) async {}
///     func readText(_ label: String) async throws -> String { throw SignInError.inputEnded }
///     func readSecret(_ label: String) async throws -> String { throw SignInError.inputEnded }
///     func progress(_ message: String) async {}
/// }
///
/// let authenticator = Authenticator(stores: [], audit: nil, now: { Date() })
/// let stepUp = StepUp(sources: [], authenticator: authenticator, presenter: NoPresenter())
/// ```
public struct StepUp: Sendable {
    /// Asked in order; the first that applies is authenticated.
    public let sources: [any CredentialSource]
    /// Decides who the credentials prove.
    public let authenticator: Authenticator
    /// How the sources talk to the person, and where "Sign-in failed" is shown.
    public let presenter: any SignInPresenter

    /// Creates a step-up.
    /// - Parameters:
    ///   - sources: Asked in order. A source that returns `nil` passes to the next; one that
    ///     throws ends the step-up.
    ///   - authenticator: SwiftIdentity's authenticator, over the app's stores.
    ///   - presenter: How to talk to the person.
    public init(sources: [any CredentialSource], authenticator: Authenticator, presenter: any SignInPresenter) {
        self.sources = sources
        self.authenticator = authenticator
        self.presenter = presenter
    }
}

/// An admitted session's lifetime.
///
/// SwiftIdentity makes a revocation take effect at the next verification, and a long terminal or
/// SSH session has none. So the lease makes its own: on creation it mints a token in the app's
/// `SessionStore`, and re-resolves that token every `reresolveEvery`. The store reads the
/// subject's status on every resolution, so revoking the subject, or revoking their sessions,
/// ends the lease within one interval.
///
/// **The lease never keeps the sign-in credentials.** Re-presenting them would mean holding a
/// password for the life of the session and paying its key derivation every interval; the token
/// is the only thing kept, and it is never shown or logged.
///
/// ## Ending
///
/// ``ended`` yields one ``LeaseEnd`` and finishes. Whichever way the lease ends, its token is
/// revoked in the store and its re-resolution task is cancelled. A lease released without ending
/// cancels its task too, and ``ended`` then finishes without a value; its token lapses at the end
/// of its lifetime.
///
/// ## Step-up
///
/// ``reverify(minimum:maximumAge:)`` is "confirm before deleting": it returns the current
/// authentication if that is strong and recent enough, and otherwise asks the ``StepUp``'s
/// sources for the same subject.
///
/// ```swift
/// import SwiftCLIKitAuth
/// import SwiftIdentity
///
/// func run(_ admitted: Authentication, sessions: SessionStore) async {
///     var generator = SystemRandomNumberGenerator()
///     let lease = await AccessLease(
///         authentication: admitted, sessions: sessions, lifetime: 8 * 3_600,
///         reresolveEvery: .seconds(60), stepUp: nil, now: { Date() }, generator: &generator
///     )
///     for await reason in lease.ended {
///         print("Session ended: \(reason)")
///     }
/// }
/// ```
public actor AccessLease {
    /// The shortest re-resolution interval a lease uses. A shorter one asked for is raised to
    /// this, so a zero interval can't spin.
    public static let minimumReresolveInterval: Duration = .seconds(1)

    /// Who is signed in, how strongly, and when that was proven. Replaced by a successful step-up.
    public private(set) var authentication: Authentication

    /// Whether the lease has not yet ended.
    public private(set) var isActive = true

    /// Yields once, when the lease ends, and then finishes. Meant for one consumer.
    public nonisolated let ended: AsyncStream<LeaseEnd>

    private let continuation: AsyncStream<LeaseEnd>.Continuation
    private let sessions: SessionStore
    private let session: MintedSession
    private let stepUp: StepUp?
    private let now: @Sendable () -> Date
    private var reresolution: Task<Void, any Error>?

    /// Starts a lease: mints a session token for the authenticated subject and begins
    /// re-resolving it.
    ///
    /// - Parameters:
    ///   - authentication: The admitted authentication.
    ///   - sessions: The app's session store. Its `subjects` lookup must read the live roster,
    ///     since that is how a revocation reaches the lease.
    ///   - lifetime: How long the session lasts, in seconds, before it ends as
    ///     ``LeaseEnd/expired``.
    ///   - reresolveEvery: How often the token is re-resolved: the longest a revocation goes
    ///     unnoticed. Raised to ``minimumReresolveInterval`` if shorter.
    ///   - stepUp: How ``reverify(minimum:maximumAge:)`` proves more, or `nil` for a lease that
    ///     can't step up.
    ///   - now: The wall clock, which should be the one `sessions` reads; it decides expiry and
    ///     an authentication's age.
    ///   - clock: What the re-resolution task sleeps on. Injected so tests advance it by hand.
    ///   - generator: The randomness the session token is drawn from.
    public init<Generator: RandomNumberGenerator & Sendable>(
        authentication: Authentication,
        sessions: SessionStore,
        lifetime: TimeInterval,
        reresolveEvery: Duration,
        stepUp: StepUp?,
        now: @escaping @Sendable () -> Date,
        clock: any Clock<Duration> = ContinuousClock(),
        generator: inout Generator
    ) async {
        let (stream, continuation) = AsyncStream<LeaseEnd>.makeStream(bufferingPolicy: .bufferingNewest(1))
        self.ended = stream
        self.continuation = continuation
        self.authentication = authentication
        self.sessions = sessions
        self.stepUp = stepUp
        self.now = now
        self.session = await sessions.mint(for: authentication.subject.id, lifetime: lifetime, using: &generator)

        let interval = max(reresolveEvery, Self.minimumReresolveInterval)
        // Throwing only to stop: the one error is the sleep's cancellation, when the lease ends.
        reresolution = Task { [weak self] in
            while !Task.isCancelled {
                try await clock.sleep(for: interval)
                guard let lease = self, await lease.reresolve() else { return }
            }
        }
    }

    deinit {
        reresolution?.cancel()
        continuation.finish()
    }

    /// Signs out: revokes the session token and ends the lease as ``LeaseEnd/signedOut``.
    /// Ending an ended lease does nothing.
    public func end() async {
        await finish(.signedOut)
    }

    /// Confirms who is signed in, strongly and recently enough for what comes next.
    ///
    /// The token is re-resolved first, so a revocation is seen here without waiting for the next
    /// interval. Then, if the current authentication's assurance is at least `minimum` and it is
    /// younger than `maximumAge`, it is returned without asking anything. Otherwise the step-up's
    /// sources are asked in order; the first that returns credentials is authenticated, and the
    /// result is accepted only if it proves the **same** subject at `minimum` or above. It then
    /// becomes ``authentication``.
    ///
    /// - Parameters:
    ///   - minimum: The assurance required.
    ///   - maximumAge: How recently it must have been proven, or `nil` for any age.
    /// - Returns: The authentication that satisfies both.
    /// - Throws: ``SignInError/failed`` if the lease has ended, there is no step-up, no source
    ///   applies, or the credentials don't prove the same subject strongly enough; "Sign-in
    ///   failed" is shown for the last two, never with a reason. Whatever a source throws is
    ///   rethrown, and no later source is asked.
    public func reverify(minimum: Assurance, maximumAge: Duration?) async throws -> Authentication {
        guard await reresolve() else { throw SignInError.failed }
        if satisfies(authentication, minimum: minimum, maximumAge: maximumAge) {
            return authentication
        }
        guard let stepUp else { throw SignInError.failed }

        let subjectID = authentication.subject.id
        let context = SignInContext(presenter: stepUp.presenter, subjectID: subjectID)
        var presented: [any Credential]?
        for source in stepUp.sources {
            presented = try await source.credentials(context)
            if presented != nil { break }
        }
        guard let presented,
              let proven = await stepUp.authenticator.authentication(for: presented),
              proven.subject.id == subjectID,
              proven.assurance >= minimum
        else {
            await stepUp.presenter.show(.failed)
            throw SignInError.failed
        }
        // The lease may have ended while the person was answering.
        guard isActive else { throw SignInError.failed }
        authentication = proven
        return proven
    }

    /// Whether `candidate` is strong and recent enough.
    private func satisfies(_ candidate: Authentication, minimum: Assurance, maximumAge: Duration?) -> Bool {
        guard candidate.assurance >= minimum else { return false }
        guard let maximumAge else { return true }
        return Duration.seconds(now().timeIntervalSince(candidate.at)) < maximumAge
    }

    /// Re-resolves the token, ending the lease if it no longer resolves.
    /// - Returns: Whether the lease is still active.
    private func reresolve() async -> Bool {
        guard isActive else { return false }
        let resolved = await sessions.subject(for: session.token)
        // `end()` may have run while the store was being asked.
        guard isActive else { return false }
        guard resolved == nil else { return true }
        await finish(now() >= session.expires ? .expired : .revoked)
        return false
    }

    /// Ends the lease once: revokes the token, stops re-resolving, and yields `reason`.
    private func finish(_ reason: LeaseEnd) async {
        guard isActive else { return }
        isActive = false
        reresolution?.cancel()
        reresolution = nil
        continuation.yield(reason)
        continuation.finish()
        await sessions.revoke(session.token)
    }
}
