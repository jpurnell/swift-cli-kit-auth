// SignInGate.swift
// SwiftCLIKitAuthSSH
// Created by Justin Purnell on 2026-10-26.

import Foundation
import SwiftCLIKit
import SwiftCLIKitAuth
import SwiftCLIKitSSH
import SwiftIdentity
#if canImport(os)
import os
#endif

/// The SSH key the connection being signed in was admitted with, as a credential source.
///
/// No interaction: it applies only when the connection presented a plain public key, and the
/// key resolves only if an ``SSHKeyStore`` remembers it. ``SignInGate`` tells it which
/// connection it's looking at.
public struct ConnectionKey: CredentialSource {
    /// The connection the current sign-in is for, set by ``SignInGate`` around each sign-in.
    @TaskLocal public static var connection: SSHClientIdentity?

    /// Creates the source.
    public init() {}

    /// It needs nothing from the person.
    public var requirements: SourceRequirements { [] }

    /// The connection's key, if it presented one.
    /// - Parameter context: Unused: the key comes from the connection, not the person.
    /// - Returns: One ``SSHPublicKeyCredential``, or `nil` when the connection has no plain key.
    public func credentials(_ context: SignInContext) async throws -> [any Credential]? {
        guard let identity = Self.connection, let key = SSHPublicKeyCredential(identity) else { return nil }
        return [key]
    }
}

/// Signs people in to an SSH app before it runs: experience B.
///
/// Serve with `authMode: .publicKey`, so every client that proves it holds a key gets a session,
/// then let the gate decide inside it:
///
/// ```swift
/// import Foundation
/// import SwiftCLIKitAuth
/// import SwiftCLIKitAuthSSH
/// import SwiftCLIKitSSH
/// import SwiftIdentity
///
/// func serve(people: FileCredentialStore, keys: SSHKeyStore, device: DeviceSignIn) async throws {
///     let sessions = SessionStore(subjects: { id in people.subject(id: id) })
///     let gate = SignInGate(
///         sources: [ConnectionKey(), device],
///         authenticator: Authenticator(stores: [keys, people], audit: nil, now: { Date() }),
///         admission: .attribute("team", equals: "ops"),
///         keys: keys, rememberFor: .seconds(30 * 24 * 3600),
///         sessions: sessions, sessionLifetime: 8 * 3600, reresolveEvery: .seconds(300),
///         generator: { SystemRandomNumberGenerator() }
///     )
///     let server = SSHServer(port: 2222, configuration: SSHConfiguration(authMode: .publicKey))
///     try await server.start(sessionHandler: gate.wrap { backend, _, lease in
///         backend.write("Signed in as \(await lease.authentication.subject.id)\r\n")
///     })
/// }
/// ```
///
/// ## How a connection goes
///
/// 1. A password already verified at connect (``ConnectionPassword``) is the sign-in; no source
///    is asked.
/// 2. Otherwise the sources run in order, as ``SwiftCLIKitAuth/CLISignIn`` runs them: one that
///    doesn't apply or doesn't resolve passes to the next, so a key ``keys`` doesn't remember
///    falls through to a device sign-in; one that throws ends the attempt.
/// 3. If the person signed in some other way and connected with a key, the key is bound to them
///    for ``rememberFor``, so their next connection goes straight in.
/// 4. The app runs with an ``SwiftCLIKitAuth/AccessLease``. When the lease ends (the subject was
///    revoked, or the session expired) the app is cancelled and the session closes.
///
/// A refusal shows "Sign-in failed." and the session closes; why is for the audit.
public struct SignInGate: Sendable {
    #if canImport(os)
    private static let logger = Logger(subsystem: "com.swiftclikitauth", category: "SignInGate")
    #endif

    /// The sources, tried in order.
    public let sources: [any CredentialSource]
    /// Decides who the credentials prove.
    public let authenticator: Authenticator
    /// Whether the app admits them.
    public let admission: Admission
    /// Where keys are remembered, or `nil` to remember none.
    public let keys: SSHKeyStore?
    /// How long a remembered key stands for its subject. No default: the deployer's call.
    public let rememberFor: Duration
    private let sessions: SessionStore
    private let sessionLifetime: TimeInterval
    private let reresolveEvery: Duration
    private let now: @Sendable () -> Date
    private let clock: any Clock<Duration>
    private let makeGenerator: @Sendable () -> any RandomNumberGenerator & Sendable

    /// Creates a gate.
    /// - Parameters:
    ///   - sources: Tried in order; put ``ConnectionKey`` first so a remembered key needs no prompt.
    ///   - authenticator: Over the app's stores, including `keys` if keys are remembered.
    ///   - admission: Who the app admits.
    ///   - keys: Where keys are remembered, or `nil`.
    ///   - rememberFor: How long a remembered key stands for its subject.
    ///   - sessions: Where each session's lease token is minted; its `subjects` lookup must read the
    ///     live roster.
    ///   - sessionLifetime: How long a session lasts, in seconds.
    ///   - reresolveEvery: How often a lease re-checks its session.
    ///   - now: The wall clock, the one `sessions` and `keys` read.
    ///   - clock: What leases sleep on between re-checks.
    ///   - generator: Makes the randomness each session's lease token is drawn from, such as
    ///     `{ SystemRandomNumberGenerator() }`. No default, as SwiftIdentity's `SessionStore` takes
    ///     none: a predictable token is a forgeable one, so the choice is made where it can be seen.
    public init(
        sources: [any CredentialSource],
        authenticator: Authenticator,
        admission: Admission,
        keys: SSHKeyStore?,
        rememberFor: Duration,
        sessions: SessionStore,
        sessionLifetime: TimeInterval,
        reresolveEvery: Duration,
        now: @escaping @Sendable () -> Date = { Date() },
        clock: any Clock<Duration> = ContinuousClock(),
        generator: @escaping @Sendable () -> any RandomNumberGenerator & Sendable
    ) {
        self.sources = sources
        self.authenticator = authenticator
        self.admission = admission
        self.keys = keys
        self.rememberFor = rememberFor
        self.sessions = sessions
        self.sessionLifetime = sessionLifetime
        self.reresolveEvery = reresolveEvery
        self.now = now
        self.clock = clock
        self.makeGenerator = generator
    }

    /// Wraps an app so it runs only for someone signed in and admitted.
    /// - Parameter app: The app, handed the session's lease.
    /// - Returns: A session handler for `SSHServer.start(sessionHandler:)`.
    public func wrap(
        _ app: @escaping @Sendable (SSHBackend, SSHSession, AccessLease) async throws -> Void
    ) -> @Sendable (SSHBackend, SSHSession) async throws -> Void {
        let gate = self
        return { backend, session in
            guard let lease = await gate.admit(backend, session) else { return }
            try await Self.run(app, backend: backend, session: session, lease: lease)
        }
    }

    /// Signs the connection in and starts its lease, or shows the refusal and returns nil.
    private func admit(_ backend: SSHBackend, _ session: SSHSession) async -> AccessLease? {
        let presenter = TerminalPresenter(backend: backend)
        let authentication: Authentication
        do {
            authentication = try await signIn(session, presenter: presenter)
        } catch {
            // The person has been shown all they're told; the service gets the outcome's name,
            // which is a case of SignInError and carries no credential.
            #if canImport(os)
            Self.logger.notice("SSH sign-in ended without a session: \(String(describing: error), privacy: .public)")
            #endif
            return nil
        }
        await remember(session, for: authentication)
        var generator = makeGenerator()
        return await AccessLease(
            authentication: authentication, sessions: sessions, lifetime: sessionLifetime,
            reresolveEvery: reresolveEvery,
            stepUp: StepUp(sources: sources, authenticator: authenticator, presenter: presenter),
            now: now, clock: clock, generator: &generator
        )
    }

    /// The connection's verified password, or the first source that resolves.
    private func signIn(_ session: SSHSession, presenter: any SignInPresenter) async throws -> Authentication {
        if let atConnect = session.authentication {
            guard await admission.admits(atConnect) else {
                await presenter.show(.failed)
                throw SignInError.failed
            }
            return atConnect
        }
        let (authentication, _) = try await ConnectionKey.$connection.withValue(session.clientIdentity) {
            try await SignInRun.authenticate(sources, authenticator: authenticator, admission: admission, presenter: presenter)
        }
        return authentication
    }

    /// Binds the connection's key to the subject, unless it was the key that signed them in.
    private func remember(_ session: SSHSession, for authentication: Authentication) async {
        guard let keys, let identity = session.clientIdentity, let key = SSHPublicKeyCredential(identity),
              !authentication.factors.contains(where: { $0.kind == SSHPublicKeyCredential.kind })
        else { return }
        let seconds = Double(rememberFor.components.seconds)
        do {
            try await keys.bind(key, to: authentication.subject.id, until: now().addingTimeInterval(seconds))
        } catch {
            // The sign-in stands; only the remembering failed, so the next connection asks again.
            #if canImport(os)
            Self.logger.error("couldn't remember an SSH key: \(String(describing: error), privacy: .public)")
            #endif
        }
    }

    /// Runs the app until it returns or the lease ends, whichever is first, then ends the lease.
    private static func run(
        _ app: @escaping @Sendable (SSHBackend, SSHSession, AccessLease) async throws -> Void,
        backend: SSHBackend, session: SSHSession, lease: AccessLease
    ) async throws {
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask { try await app(backend, session, lease) }
                group.addTask {
                    for await _ in lease.ended { break }
                }
                // Whichever finishes first decides: the app returning, or the lease ending.
                defer { group.cancelAll() }
                try await group.next()
            }
        } catch {
            // However the app ended, its session is signed out before the error goes on.
            await lease.end()
            throw error
        }
        await lease.end()
    }
}
