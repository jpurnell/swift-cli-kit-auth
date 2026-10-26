// SignInGateTests.swift
// SwiftCLIKitAuthSSHTests
// Created by Justin Purnell on 2026-10-26.

import Testing
import Foundation
import NIOConcurrencyHelpers
import SwiftCLIKit
import SwiftCLIKitSSH
import SwiftIdentity
import SwiftCLIKitAuth
import SwiftCLIKitAuthSSH

/// Grants a bearer key to Ada: what a device sign-in's token resolves to, in these tests.
private struct DeviceTokens: CredentialStore {
    static let ada = Subject(id: "ada", kind: .person, attributes: ["team": "ops"])
    func resolve(_ credential: any Credential) async -> Resolution {
        guard let bearer = credential as? BearerKey, bearer.value == "ada-device-token" else { return .refused(.unknown) }
        return .verified(Self.ada)
    }
}

/// Counts calls, across tasks.
private final class Counter: Sendable {
    private let box = NIOLockedValueBox(0)
    func bump() { box.withLockedValue { $0 += 1 } }
    var value: Int { box.withLockedValue { $0 } }
}

/// What a session's app saw, and everything written to its terminal.
private final class SessionRecord: Sendable {
    private let box = NIOLockedValueBox<(subject: String?, output: String)>((nil, ""))
    func ran(as subject: String) { box.withLockedValue { $0.subject = subject } }
    func wrote(_ text: String) { box.withLockedValue { $0.output += text } }
    var subject: String? { box.withLockedValue { $0.subject } }
    var output: String { box.withLockedValue { $0.output } }
}

@Suite("SignInGate")
struct SignInGateTests {

    static let instant = Date(timeIntervalSince1970: 1_800_000_000)

    /// A key store, the device-token store, and a gate over both, in a fresh directory.
    private struct Harness {
        let directory: URL
        let keys: SSHKeyStore
        let sessions: SessionStore
        let authenticator: Authenticator

        init() throws {
            directory = FileManager.default.temporaryDirectory.appendingPathComponent("gate-\(UUID().uuidString)")
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
            )
            let roster: @Sendable (String) async -> Subject? = { $0 == "ada" ? DeviceTokens.ada : nil }
            keys = try SSHKeyStore(url: directory.appendingPathComponent("ssh-keys"), subjects: roster, now: { SignInGateTests.instant })
            sessions = SessionStore(subjects: roster, now: { SignInGateTests.instant })
            authenticator = Authenticator(stores: [keys, DeviceTokens()], audit: nil, now: { SignInGateTests.instant })
        }

        func gate(_ sources: [any CredentialSource], admission: Admission = .anyone) -> SignInGate {
            SignInGate(
                sources: sources, authenticator: authenticator, admission: admission, keys: keys,
                rememberFor: .seconds(30 * 24 * 3600), sessions: sessions, sessionLifetime: 8 * 3600,
                reresolveEvery: .seconds(1), now: { SignInGateTests.instant },
                generator: { SplitMix64(seed: 2026) }
            )
        }

        func remove() {
            try? FileManager.default.removeItem(at: directory) // silent: best-effort cleanup of the test's own directory
        }
    }

    private static func key() throws -> SSHPublicKeyCredential {
        try #require(SSHPublicKeyCredential(openSSH: try SSHPublicKeyCredentialTests.fixture("user_ed25519.pub")))
    }

    private static func session(_ identity: SSHClientIdentity?, verification: (any Sendable)? = nil) -> SSHSession {
        SSHSession(
            id: "s", remoteAddress: "127.0.0.1", terminalSize: TerminalSize(columns: 80, rows: 24),
            clientIdentity: identity, verification: verification
        )
    }

    private static func backend(_ record: SessionRecord) throws -> SSHBackend {
        try SSHBackend(outputHandler: { record.wrote($0) })
    }

    /// A device sign-in that counts its calls and yields Ada's device token.
    private static func device(_ calls: Counter) -> DeviceSignIn {
        DeviceSignIn { _ in
            calls.bump()
            return BearerKey("ada-device-token")
        }
    }

    @Test("A remembered key admits with no prompt, and the device flow is never called")
    func rememberedKey() async throws {
        let harness = try Harness()
        defer { harness.remove() }
        let key = try Self.key()
        try await harness.keys.bind(key, to: "ada", until: Self.instant.addingTimeInterval(3600))
        let calls = Counter()
        let record = SessionRecord()

        let handler = harness.gate([ConnectionKey(), Self.device(calls)]).wrap { _, _, lease in
            record.ran(as: await lease.authentication.subject.id)
        }
        try await handler(try Self.backend(record), Self.session(SSHClientIdentity(username: "ada", evidence: .publicKey(openSSH: key.openSSH))))

        #expect(record.subject == "ada")
        #expect(calls.value == 0)
        #expect(record.output.isEmpty)
    }

    @Test("An unknown key falls through to the device sign-in, and the key is remembered for next time")
    func unknownKeyThenBind() async throws {
        let harness = try Harness()
        defer { harness.remove() }
        let key = try Self.key()
        let calls = Counter()
        let record = SessionRecord()

        let handler = harness.gate([ConnectionKey(), Self.device(calls)]).wrap { _, _, lease in
            record.ran(as: await lease.authentication.subject.id)
        }
        try await handler(try Self.backend(record), Self.session(SSHClientIdentity(username: "ada", evidence: .publicKey(openSSH: key.openSSH))))

        #expect(record.subject == "ada")
        #expect(calls.value == 1)
        #expect(await harness.keys.subject(for: key)?.id == "ada")
    }

    @Test("A source that throws never falls through: the device flow isn't called and the app never runs")
    func throwStops() async throws {
        let harness = try Harness()
        defer { harness.remove() }
        struct Stop: CredentialSource {
            var requirements: SourceRequirements { [] }
            func credentials(_ context: SignInContext) async throws -> [any Credential]? { throw SignInError.cancelled }
        }
        let calls = Counter()
        let record = SessionRecord()

        let handler = harness.gate([Stop(), Self.device(calls)]).wrap { _, _, _ in record.ran(as: "anyone") }
        try await handler(try Self.backend(record), Self.session(nil))

        #expect(record.subject == nil)
        #expect(calls.value == 0)
    }

    @Test("A subject the app doesn't admit sees only that sign-in failed, and nothing is remembered")
    func notAdmitted() async throws {
        let harness = try Harness()
        defer { harness.remove() }
        let key = try Self.key()
        let record = SessionRecord()

        let handler = harness.gate([ConnectionKey(), Self.device(Counter())], admission: .subjects(["grace"])).wrap { _, _, _ in
            record.ran(as: "anyone")
        }
        try await handler(try Self.backend(record), Self.session(SSHClientIdentity(username: "ada", evidence: .publicKey(openSSH: key.openSSH))))

        #expect(record.subject == nil)
        #expect(record.output.contains("Sign-in failed."))
        #expect(await harness.keys.subject(for: key) == nil)
    }

    @Test("A password already verified at connect is the sign-in; no source is asked")
    func passwordAtConnect() async throws {
        let harness = try Harness()
        defer { harness.remove() }
        let authentication = try #require(await harness.authenticator.authentication(for: [BearerKey("ada-device-token")]))
        let calls = Counter()
        let record = SessionRecord()

        let handler = harness.gate([Self.device(calls)]).wrap { _, _, lease in
            record.ran(as: await lease.authentication.subject.id)
        }
        try await handler(try Self.backend(record), Self.session(SSHClientIdentity(username: "ada", evidence: .password), verification: authentication))

        #expect(record.subject == "ada")
        #expect(calls.value == 0)
    }

    @Test("When the lease ends mid-session, the app is cancelled")
    func leaseEndEndsSession() async throws {
        let harness = try Harness()
        defer { harness.remove() }
        let record = SessionRecord()
        let cancelled = Counter()

        let handler = harness.gate([Self.device(Counter())]).wrap { _, _, lease in
            record.ran(as: await lease.authentication.subject.id)
            await harness.sessions.revokeAll(forSubject: "ada")
            do {
                try await Task.sleep(for: .seconds(30))
            } catch {
                cancelled.bump()
            }
        }
        try await handler(try Self.backend(record), Self.session(nil))

        #expect(record.subject == "ada")
        #expect(cancelled.value == 1, "the app was cancelled, not left to sleep out its 30 seconds")
    }
}
