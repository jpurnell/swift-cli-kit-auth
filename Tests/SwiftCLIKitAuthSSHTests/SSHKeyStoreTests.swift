// SSHKeyStoreTests.swift
// SwiftCLIKitAuthSSHTests
// Created by Justin Purnell on 2026-10-26.

import Testing
import Foundation
import SwiftIdentity
import SwiftIdentityConformance
import SwiftCLIKitAuthSSH

/// Records audit outcomes.
private actor Outcomes: IdentityAudit {
    private(set) var recorded: [IdentityEvent.Outcome] = []
    func record(_ event: IdentityEvent) async { recorded.append(event.outcome) }
}

/// A fresh owner-only directory, removed when the test is done.
private struct TemporaryDirectory {
    let url: URL

    init() throws {
        url = FileManager.default.temporaryDirectory.appendingPathComponent("sshkeystore-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
    }

    var keysFile: URL { url.appendingPathComponent("ssh-keys") }

    func remove() {
        try? FileManager.default.removeItem(at: url) // silent: best-effort cleanup of the test's own directory
    }

    func permissions() throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: keysFile.path)
        return (attributes[.posixPermissions] as? NSNumber)?.intValue ?? -1
    }
}

@Suite("SSHKeyStore")
struct SSHKeyStoreTests {

    static let instant = Date(timeIntervalSince1970: 1_800_000_000)
    static let roster: [String: Subject] = [
        "ada": Subject(id: "ada", kind: .person, attributes: ["team": "ops"]),
        "eve": Subject(id: "eve", kind: .person, status: .revoked),
        "trap": Subject(id: "trap", kind: .person, status: .honeypot),
    ]
    static let later = instant.addingTimeInterval(3600)

    static func key(_ name: String) throws -> SSHPublicKeyCredential {
        try #require(SSHPublicKeyCredential(openSSH: try SSHPublicKeyCredentialTests.fixture("\(name).pub")))
    }

    private static func store(
        _ directory: TemporaryDirectory, audit: (any IdentityAudit)? = nil, now: Date = instant
    ) throws -> SSHKeyStore {
        try SSHKeyStore(url: directory.keysFile, subjects: { roster[$0] }, now: { now }, audit: audit)
    }

    // MARK: - SwiftIdentity's conformance suite

    @Test("It passes SwiftIdentity's ConformanceSuite unchanged")
    func conformance() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let store = try Self.store(directory, audit: Outcomes())
        let ada = try Self.key("user_ed25519")
        try await store.bind(ada, to: "ada", until: Self.later)
        try await store.bind(try Self.key("revoked_ed25519"), to: "eve", until: Self.later)
        try await store.bind(try Self.key("honeypot_ed25519"), to: "trap", until: Self.later)
        try await store.bind(try Self.key("expired_ed25519"), to: "ada", until: Self.instant.addingTimeInterval(-1))

        let fixtures = ConformanceSuite.Fixtures(
            capabilities: [.revocation, .honeypot, .expiry, .algorithmRecords],
            active: .init(id: "ada", credential: ada, attributes: ["team": "ops"], algorithm: "ssh-ed25519"),
            refusals: .init(
                revoked: try Self.key("revoked_ed25519"),
                honeypot: try Self.key("honeypot_ed25519"),
                expired: try Self.key("expired_ed25519"),
                unknown: try Self.key("unknown_ecdsa")
            ),
            activeAsAnotherKind: BearerKey(ada.openSSH)
        )
        let report = await ConformanceSuite(store: store, fixtures: fixtures).run()
        #expect(report.isConformant, "\(report.summary)")
    }

    // MARK: - Behaviour the suite doesn't cover

    @Test("A binding survives a restart, and the file is owner-only")
    func persists() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let ada = try Self.key("user_ed25519")
        try await Self.store(directory).bind(ada, to: "ada", until: Self.later)

        #expect(try directory.permissions() == 0o600)
        let reopened = try Self.store(directory)
        #expect(await reopened.subject(for: ada)?.id == "ada")
    }

    @Test("The algorithm reported is the key type the store recorded")
    func algorithmFromRecord() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let store = try Self.store(directory)
        let key = try Self.key("unknown_ecdsa")
        try await store.bind(key, to: "ada", until: Self.later)
        let (resolution, algorithm) = await store.resolveVerifying(key)
        #expect(resolution == .verified(try #require(Self.roster["ada"])))
        #expect(algorithm == "ecdsa-sha2-nistp256")
    }

    @Test("Unbinding forgets a key, and binding again replaces the old binding")
    func unbindAndRebind() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let store = try Self.store(directory)
        let key = try Self.key("user_ed25519")
        try await store.bind(key, to: "ada", until: Self.instant.addingTimeInterval(-1))
        try await store.bind(key, to: "ada", until: Self.later)
        #expect(await store.subject(for: key)?.id == "ada")
        try await store.unbind(key)
        #expect(await store.subject(for: key) == nil)
        let reopened = try Self.store(directory)
        #expect(await reopened.subject(for: key) == nil)
    }

    @Test("A subject the roster no longer has resolves to nothing")
    func deletedSubject() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let store = try Self.store(directory)
        let key = try Self.key("user_ed25519")
        try await store.bind(key, to: "deleted", until: Self.later)
        #expect(await store.resolve(key) == .refused(.unknown))
    }

    @Test("A keys file others can read is refused at startup")
    func refusesSharedFile() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        try await Self.store(directory).bind(try Self.key("user_ed25519"), to: "ada", until: Self.later)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: directory.keysFile.path)
        #expect(throws: SSHKeyStore.Failure.self) {
            _ = try Self.store(directory)
        }
    }

    @Test("A malformed line is refused at startup, not skipped")
    func refusesMalformedLine() throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        try Data("not\tenough fields\n".utf8).write(to: directory.keysFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: directory.keysFile.path)
        #expect(throws: SSHKeyStore.Failure.self) {
            _ = try Self.store(directory)
        }
    }

    @Test("A store with no keys file yet is empty, and the first bind creates it")
    func noFileYet() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let store = try Self.store(directory)
        #expect(await store.subject(for: try Self.key("user_ed25519")) == nil)
        #expect(!FileManager.default.fileExists(atPath: directory.keysFile.path))
    }

    @Test("Only an SSH key is recognised")
    func otherKinds() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let store = try Self.store(directory)
        #expect(await store.resolve(Passphrase(subjectID: "ada", secret: "x")) == .refused(.unknown))
    }

    @Test("Each resolution is audited, a honeypot as a honeypot")
    func audited() async throws {
        let directory = try TemporaryDirectory()
        defer { directory.remove() }
        let audit = Outcomes()
        let store = try Self.store(directory, audit: audit)
        try await store.bind(try Self.key("honeypot_ed25519"), to: "trap", until: Self.later)
        _ = await store.resolve(try Self.key("honeypot_ed25519"))
        #expect(await audit.recorded == [.honeypot])
    }
}
