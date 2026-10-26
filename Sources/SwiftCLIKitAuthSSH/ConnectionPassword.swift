// ConnectionPassword.swift
// SwiftCLIKitAuthSSH
// Created by Justin Purnell on 2026-10-25.

import SwiftCLIKitAuth
import SwiftCLIKitSSH
import SwiftIdentity

/// Admits an SSH client by the password it signed in with, resolved through SwiftIdentity.
///
/// Install it as the server's verifier. SwiftCLIKit asks it about each password attempt before
/// any session exists, so a wrong password never reaches your session handler:
///
/// ```swift
/// import Foundation
/// import SwiftCLIKitSSH
/// import SwiftIdentity
/// import SwiftCLIKitAuthSSH
///
/// func serve(credentials directory: String) async throws {
///     let store = try FileCredentialStore(directory: directory)
///     let authenticator = Authenticator(stores: [store], audit: nil, now: { Date() })
///     let verifier = ConnectionPassword(authenticator: authenticator) { authentication in
///         authentication.subject.attributes["role"] == "operator"
///     }
///     let server = SSHServer(configuration: SSHConfiguration(authMode: .verifier(verifier)))
///     try await server.start { backend, session in
///         let subject = session.authentication?.subject.id ?? ""
///         backend.write("Signed in as \(subject)\r\n")
///     }
/// }
/// ```
///
/// ## What it decides, and what it doesn't
///
/// SwiftIdentity's `Authenticator` decides who someone is: the SSH username and password become
/// a `Passphrase`, and the authenticator resolves it with
/// `Authenticator/authentication(for:)`, the caller-facing form that returns an
/// `Authentication` or nothing and so cannot carry a reason out. The `admits` closure then
/// decides whether the app lets that subject in. Only both together admit, and an admitted
/// connection's sessions carry the `Authentication` as ``SwiftCLIKitSSH/SSHSession/authentication``.
///
/// A refusal is a refusal whatever the cause — an unknown user, a wrong password, a throttled
/// subject or one the app doesn't admit all look the same to the client. The reason is in
/// SwiftIdentity's audit trail, if the stores were given one.
///
/// ## The password
///
/// It is read from the attempt once, handed to SwiftIdentity, and not kept: this type stores
/// nothing but the authenticator and the closure, and logs nothing. The username is passed
/// through exactly as the client sent it; SSH usernames are case-sensitive, and SwiftIdentity
/// canonicalises the passphrase itself.
public struct ConnectionPassword: SSHClientVerifier {
    private let authenticator: Authenticator
    private let admits: @Sendable (Authentication) async -> Bool

    /// Creates a verifier.
    ///
    /// - Parameters:
    ///   - authenticator: Decides who a username and password prove, over the app's stores.
    ///   - admits: The app's admission rule: whether a subject SwiftIdentity has proved may
    ///     connect. Asked only after the password has been verified, never about a refusal.
    ///     Defaults to admitting every proved subject.
    public init(
        authenticator: Authenticator,
        admits: @escaping @Sendable (Authentication) async -> Bool = { _ in true }
    ) {
        self.authenticator = authenticator
        self.admits = admits
    }

    /// Creates a verifier whose admission rule is an ``SwiftCLIKitAuth/Admission``.
    ///
    /// - Parameters:
    ///   - authenticator: Decides who a username and password prove, over the app's stores.
    ///   - admission: Who the app admits, asked only after the password has been verified.
    public init(authenticator: Authenticator, admission: Admission) {
        self.init(authenticator: authenticator, admits: { await admission.admits($0) })
    }

    /// Passwords, and nothing else: a public-key attempt is refused without being asked about.
    public var methods: SSHVerificationMethods {
        .password
    }

    /// Decides one password attempt.
    ///
    /// - Parameter attempt: The username and password the client presented.
    /// - Returns: An admitting verdict carrying the `Authentication` when SwiftIdentity proves
    ///   the username's subject with the password and the app admits it; otherwise
    ///   `SSHVerdict.refuse`, including for any attempt that isn't a password.
    public func verify(_ attempt: SSHAuthenticationAttempt) async -> SSHVerdict {
        guard attempt.evidence == .password, let password = attempt.password else { return .refuse }
        let passphrase = Passphrase(subjectID: attempt.username, secret: password)
        guard let authentication = await authenticator.authentication(for: [passphrase]) else { return .refuse }
        guard await admits(authentication) else { return .refuse }
        return .admit(attaching: authentication)
    }
}
