// CredentialSource.swift
// SwiftCLIKitAuth
// Created by Justin Purnell on 2026-10-25.

import Foundation
import SwiftIdentity

/// What a source needs from where it runs, so a host can tell before running it whether it
/// fits: an unattended job can't answer a prompt, and a session with no browser at hand can't
/// follow a URL.
public struct SourceRequirements: OptionSet, Sendable, Hashable {
    /// The raw bits.
    public let rawValue: UInt8

    /// Creates a set from its raw bits.
    /// - Parameter rawValue: The bits.
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// It asks the person something.
    public static let interaction = SourceRequirements(rawValue: 1 << 0)
    /// It shows a URL the person must visit.
    public static let showsURL = SourceRequirements(rawValue: 1 << 1)
    /// It reads a secret.
    public static let readsSecret = SourceRequirements(rawValue: 1 << 2)
    /// It reaches a server.
    public static let network = SourceRequirements(rawValue: 1 << 3)
}

/// Where a source runs: how to talk to the person, and who they have already said they are.
public struct SignInContext: Sendable {
    /// How to talk to the person.
    public let presenter: any SignInPresenter
    /// The subject an earlier source in the same sign-in named, if any, so a one-time code after
    /// a password doesn't ask for the username twice.
    public let subjectID: String?

    /// Creates a context.
    /// - Parameters:
    ///   - presenter: How to talk to the person.
    ///   - subjectID: The subject already named in this sign-in, if any.
    public init(presenter: any SignInPresenter, subjectID: String? = nil) {
        self.presenter = presenter
        self.subjectID = subjectID
    }
}

/// One way to obtain credentials for SwiftIdentity to resolve.
///
/// A source gathers; it never decides who someone is. SwiftIdentity's `Authenticator` does that,
/// over the credentials a source returns.
public protocol CredentialSource: Sendable {
    /// What the source needs from where it runs.
    var requirements: SourceRequirements { get }

    /// The credentials to present.
    /// - Parameter context: How to talk to the person, and who they've said they are.
    /// - Returns: The credentials, or `nil` if this source doesn't apply here (no key on the
    ///   connection, say), in which case the next source is tried.
    /// - Throws: Only for a genuine stop, such as ``SignInError/cancelled``. A source that throws
    ///   ends the sign-in; it never falls through to the next source.
    func credentials(_ context: SignInContext) async throws -> [any Credential]?
}
