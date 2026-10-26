// IdentityFixture.swift
// SwiftCLIKitAuthTests
// Created by Justin Purnell on 2026-10-25.

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import os
import SwiftCLIKitAuth
import SwiftIdentity
import Testing

/// A wall-clock stand-in the test moves by hand.
struct TestDate: Sendable {
    private let current = OSAllocatedUnfairLock(initialState: Date(timeIntervalSince1970: 1_800_000_000))

    /// The current instant.
    var instant: Date {
        current.withLock { $0 }
    }

    /// Moves the instant forward.
    /// - Parameter interval: Seconds to move.
    func advance(_ interval: TimeInterval) {
        current.withLock { $0 += interval }
    }
}

/// The roster a `SessionStore` reads at every resolution: a real `FileCredentialStore`, re-read
/// from disk when the test changes the files, as a deployment would on a roster change.
actor Roster {
    private let directory: String
    private let now: @Sendable () -> Date
    private var store: FileCredentialStore

    init(directory: String, now: @escaping @Sendable () -> Date) throws {
        self.directory = directory
        self.now = now
        self.store = try FileCredentialStore(directory: directory, now: now)
    }

    /// The roster's current entry for `id`.
    func subject(id: String) -> Subject? {
        store.subject(id: id)
    }

    /// Rewrites the subjects file and re-reads the store.
    func rewriteSubjects(_ text: String) throws {
        try IdentityFixture.write(text, to: (directory as NSString).appendingPathComponent(FileCredentialStore.subjectsFile))
        store = try FileCredentialStore(directory: directory, now: now)
    }
}

/// Two people, ada and grace, each with a passphrase (knowledge) and a bearer key (possession),
/// in a real `FileCredentialStore` in a fresh private directory.
struct IdentityFixture {
    static let adaPassphrase = Passphrase(subjectID: "ada", secret: "correct horse battery staple")
    static let gracePassphrase = Passphrase(subjectID: "grace", secret: "tr0ub4dor and three more words")
    static let adaKey = BearerKey("ada-possession-key-0123456789abcdef")
    static let graceKey = BearerKey("grace-possession-key-0123456789abcdef")

    static let activeSubjects = """
        ada    person  active
        grace  person  active
        """

    let date: TestDate
    let roster: Roster
    let authenticator: Authenticator
    let sessions: SessionStore

    static func write(_ text: String, to path: String) throws {
        try Data(text.utf8).write(to: URL(fileURLWithPath: path))
        #expect(chmod(path, 0o600) == 0)
    }

    init() throws {
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("AccessLease-\(UUID().uuidString)", isDirectory: true).standardized
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        #expect(chmod(url.path, 0o700) == 0)
        let directory = url.path

        var generator = SplitMix64(seed: 0x5EED)
        let ada = try PassphraseVerifier(for: Self.adaPassphrase, using: &generator, rounds: PassphraseVerifier.roundFloor)
        let grace = try PassphraseVerifier(for: Self.gracePassphrase, using: &generator, rounds: PassphraseVerifier.roundFloor)
        let adaKey = try #require(FileCredentialStore.storedDigest(for: Self.adaKey))
        let graceKey = try #require(FileCredentialStore.storedDigest(for: Self.graceKey))

        try Self.write(Self.activeSubjects, to: (directory as NSString).appendingPathComponent(FileCredentialStore.subjectsFile))
        try Self.write("""
            ada    passphrase  \(ada.encoded)    -
            ada    bearer      \(adaKey)         -
            grace  passphrase  \(grace.encoded)  -
            grace  bearer      \(graceKey)       -
            """, to: (directory as NSString).appendingPathComponent(FileCredentialStore.verifiersFile))

        let date = TestDate()
        let now: @Sendable () -> Date = { date.instant }
        let roster = try Roster(directory: directory, now: now)
        self.date = date
        self.roster = roster
        self.authenticator = Authenticator(
            stores: [try FileCredentialStore(directory: directory, now: now)], audit: nil, now: now
        )
        self.sessions = SessionStore(subjects: { id in await roster.subject(id: id) }, now: now)
    }

    /// A real authentication from the fixture's authenticator.
    func authenticate(_ credentials: [any Credential]) async throws -> Authentication {
        try #require(await authenticator.authentication(for: credentials))
    }
}

/// Records what a sign-in showed, and answers nothing.
struct RecordingPresenter: SignInPresenter {
    actor Log {
        var shown: [SignInPrompt] = []
        func append(_ prompt: SignInPrompt) { shown.append(prompt) }
    }

    let log = Log()

    func show(_ prompt: SignInPrompt) async {
        await log.append(prompt)
    }

    func readText(_ label: String) async throws -> String {
        throw SignInError.inputEnded
    }

    func readSecret(_ label: String) async throws -> String {
        throw SignInError.inputEnded
    }

    func progress(_ message: String) async {}
}

/// Counts how many times a source was asked.
actor CallCounter {
    private(set) var calls = 0
    private(set) var subjectIDs: [String?] = []
    func record(_ subjectID: String?) {
        calls += 1
        subjectIDs.append(subjectID)
    }
}

/// A source that returns fixed credentials and counts its calls.
struct FixedSource: CredentialSource {
    let credentials: [any Credential]?
    let counter = CallCounter()

    var requirements: SourceRequirements { [] }

    func credentials(_ context: SignInContext) async throws -> [any Credential]? {
        await counter.record(context.subjectID)
        return credentials
    }
}

/// A source that stops the sign-in.
struct ThrowingSource: CredentialSource {
    let counter = CallCounter()

    var requirements: SourceRequirements { .interaction }

    func credentials(_ context: SignInContext) async throws -> [any Credential]? {
        await counter.record(context.subjectID)
        throw SignInError.cancelled
    }
}

/// SplitMix64 (Steele, Lea and Flood, 2014): a seeded generator, so a run's tokens and salts are
/// the same every time it runs.
struct SplitMix64: RandomNumberGenerator, Sendable {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var mixed = state
        mixed = (mixed ^ (mixed >> 30)) &* 0xBF58_476D_1CE4_E5B9
        mixed = (mixed ^ (mixed >> 27)) &* 0x94D0_49BB_1331_11EB
        return mixed ^ (mixed >> 31)
    }
}
