// Fixtures.swift
// SwiftCLIKitAuthTests
// Created by Justin Purnell on 2026-10-25.

import Foundation
import SwiftIdentity
import SwiftCLIKitAuth

/// A credential of a phishing-resistant kind, standing in for a passkey assertion.
struct PasskeyStandIn: Credential, Equatable {
    static let kind = "test-passkey"
    static let isPhishingResistant = true
    let value: String
}

/// A store that knows a fixed table, and the algorithm it verified each entry with: the
/// construction SwiftIdentity's own `AuthenticatorTests` use, so these tests exercise admission
/// rather than identity.
struct TableStore: CredentialStore {
    let table: [String: (Resolution, String?)]

    func resolve(_ credential: any Credential) async -> Resolution {
        await resolveVerifying(credential).0
    }

    func resolveVerifying(_ credential: any Credential) async -> (Resolution, algorithm: String?) {
        guard let entry = table[Self.key(credential)] else { return (.refused(.unknown), nil) }
        return (entry.0, algorithm: entry.1)
    }

    static func key(_ credential: any Credential) -> String {
        switch credential {
        case let passphrase as Passphrase: "passphrase:\(passphrase.subjectID):\(passphrase.secret)"
        case let code as OneTimeCode: "totp:\(code.subjectID):\(code.code)"
        case let bearer as BearerKey: "bearer:\(bearer.value)"
        case let passkey as PasskeyStandIn: "passkey:\(passkey.value)"
        default: "other"
        }
    }
}

enum Fixture {
    static let instant = Date(timeIntervalSince1970: 1_800_000_000)
    static let ada = Subject(id: "ada", kind: .person, attributes: ["team": "ops"])
    static let grace = Subject(id: "grace", kind: .person, attributes: ["team": "research"])

    static let store = TableStore(table: [
        "passphrase:ada:right": (.verified(ada), "pbkdf2-sha256-c1"),
        "totp:ada:123456": (.verified(ada), "totp-sha1-6-30"),
        "bearer:ada-key": (.verified(ada), nil),
        "bearer:grace-key": (.verified(grace), nil),
        "passkey:ada-passkey": (.verified(ada), "-7"),
    ])

    static let authenticator = Authenticator(stores: [store], audit: nil, now: { instant })

    /// A real `Authentication`, which has no public initializer, from the real `Authenticator`.
    static func authentication(_ credentials: [any Credential]) async throws -> Authentication {
        guard let result = await authenticator.authentication(for: credentials) else {
            throw FixtureError.notAuthenticated
        }
        return result
    }

    enum FixtureError: Error { case notAuthenticated }
}

/// A presenter that answers from a script and records what it was shown and asked.
actor ScriptedPresenter: SignInPresenter {
    enum Answer: Sendable {
        case text(String)
        case fail(SignInError)
    }

    private var answers: [Answer]
    private(set) var shown: [SignInPrompt] = []
    private(set) var asked: [String] = []
    private(set) var progressMessages: [String] = []

    init(_ answers: [Answer] = []) {
        self.answers = answers
    }

    func show(_ prompt: SignInPrompt) async {
        shown.append(prompt)
    }

    func readText(_ label: String) async throws -> String {
        asked.append("text:\(label)")
        return try next()
    }

    func readSecret(_ label: String) async throws -> String {
        asked.append("secret:\(label)")
        return try next()
    }

    func progress(_ message: String) async {
        progressMessages.append(message)
    }

    private func next() throws -> String {
        guard !answers.isEmpty else { throw SignInError.inputEnded }
        switch answers.removeFirst() {
        case .text(let value): return value
        case .fail(let error): throw error
        }
    }
}
