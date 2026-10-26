// RememberedSignInTests.swift
// SwiftCLIKitAuthTests
// Created by Justin Purnell on 2026-10-26.

import Testing
import Foundation
import SwiftIdentity
import SwiftCLIKitAuth

/// A cache in memory, recording what was done to it.
private actor MemoryCache: TokenCache {
    private(set) var token: String?
    private(set) var saves = 0
    private(set) var clears = 0
    private let loadError: (any Error)?
    private let saveError: (any Error)?

    init(_ token: String? = nil, loadError: (any Error)? = nil, saveError: (any Error)? = nil) {
        self.token = token
        self.loadError = loadError
        self.saveError = saveError
    }

    func load() async throws -> String? {
        if let loadError { throw loadError }
        return token
    }

    func save(_ token: String) async throws {
        saves += 1
        if let saveError { throw saveError }
        self.token = token
    }

    func clear() async throws {
        clears += 1
        token = nil
    }
}

private struct DiskTrouble: Error {}

@Suite("Remembered sign-in")
struct RememberedSignInTests {

    private static func signIn(
        _ sources: [any CredentialSource], admission: Admission = .anyone, presenter: ScriptedPresenter = ScriptedPresenter()
    ) async throws -> AccessLease {
        let sessions = SessionStore(subjects: { id in [Fixture.ada, Fixture.grace].first { $0.id == id } }, now: { Fixture.instant })
        var generator = SplitMix64(seed: 11)
        return try await CLISignIn.signIn(
            sources: sources, authenticator: Fixture.authenticator, admission: admission, presenter: presenter,
            sessions: sessions, lifetime: 3600, reresolveEvery: .seconds(300), now: { Fixture.instant },
            generator: &generator
        )
    }

    /// A device sign-in that counts its calls and returns `token`.
    private static func device(_ calls: CallCounter, token: String = "ada-key") -> DeviceSignIn {
        DeviceSignIn { _ in
            await calls.record(nil)
            return BearerKey(token)
        }
    }

    /// The same, remembering what it returns in `cache`.
    private static func remembering(_ cache: MemoryCache, token: String = "ada-key") -> DeviceSignIn {
        DeviceSignIn(remembering: cache, credential: BearerKey.init) { _ in token }
    }

    // MARK: - RememberedToken

    @Test("With no remembered token, the source doesn't apply and the next one runs")
    func nothingRemembered() async throws {
        let calls = CallCounter()
        let lease = try await Self.signIn([RememberedToken(cache: MemoryCache(), credential: BearerKey.init), Self.device(calls)])
        #expect(await calls.calls == 1)
        #expect(await lease.authentication.subject.id == "ada")
        await lease.end()
    }

    @Test("A remembered token that resolves signs in with no prompt, and is kept")
    func remembered() async throws {
        let cache = MemoryCache("ada-key")
        let calls = CallCounter()
        let presenter = ScriptedPresenter()

        let lease = try await Self.signIn(
            [RememberedToken(cache: cache, credential: BearerKey.init), Self.device(calls)], presenter: presenter
        )

        #expect(await lease.authentication.subject.id == "ada")
        #expect(await calls.calls == 0)
        #expect(await presenter.shown.isEmpty)
        #expect(await cache.token == "ada-key")
        #expect(await cache.clears == 0)
        await lease.end()
    }

    @Test("A remembered token that no longer resolves is forgotten, and the next source runs")
    func stale() async throws {
        let cache = MemoryCache("revoked-at-the-idp")
        let calls = CallCounter()

        let lease = try await Self.signIn([RememberedToken(cache: cache, credential: BearerKey.init), Self.device(calls)])

        #expect(await cache.token == nil)
        #expect(await cache.clears == 1)
        #expect(await calls.calls == 1)
        #expect(await lease.authentication.subject.id == "ada")
        await lease.end()
    }

    @Test("A remembered token for someone the app doesn't admit is forgotten, and the sign-in fails")
    func notAdmitted() async throws {
        let cache = MemoryCache("grace-key")
        let presenter = ScriptedPresenter()

        await #expect(throws: SignInError.failed) {
            try await Self.signIn(
                [RememberedToken(cache: cache, credential: BearerKey.init)], admission: .subjects(["ada"]), presenter: presenter
            )
        }

        #expect(await cache.token == nil)
        #expect(await presenter.shown == [.failed])
    }

    @Test("A cache that can't be loaded stops the sign-in: no later source runs, nothing is cleared")
    func loadFails() async throws {
        let cache = MemoryCache("ada-key", loadError: DiskTrouble())
        let calls = CallCounter()
        let presenter = ScriptedPresenter()

        await #expect(throws: SignInError.failed) {
            try await Self.signIn([RememberedToken(cache: cache, credential: BearerKey.init), Self.device(calls)], presenter: presenter)
        }

        #expect(await calls.calls == 0)
        #expect(await cache.clears == 0)
        #expect(await presenter.shown == [.failed])
    }

    @Test("It asks nothing of the person")
    func requirements() {
        #expect(RememberedToken(cache: MemoryCache(), credential: BearerKey.init).requirements.isEmpty)
    }

    // MARK: - DeviceSignIn(remembering:)

    @Test("A device sign-in that's admitted remembers its token")
    func savesAdmitted() async throws {
        let cache = MemoryCache()
        let lease = try await Self.signIn([Self.remembering(cache)])
        #expect(await cache.token == "ada-key")
        await lease.end()
    }

    @Test("A device sign-in that resolves but isn't admitted remembers nothing")
    func notAdmittedNotSaved() async throws {
        let cache = MemoryCache()
        await #expect(throws: SignInError.failed) {
            try await Self.signIn([Self.remembering(cache, token: "grace-key")], admission: .subjects(["ada"]))
        }
        #expect(await cache.saves == 0)
    }

    @Test("A device token that doesn't resolve is never remembered")
    func unresolvedNotSaved() async throws {
        let cache = MemoryCache()
        await #expect(throws: SignInError.failed) {
            try await Self.signIn([Self.remembering(cache, token: "nobody-knows-this")])
        }
        #expect(await cache.saves == 0)
    }

    @Test("A token that can't be saved leaves the sign-in standing")
    func saveFails() async throws {
        let cache = MemoryCache(saveError: DiskTrouble())
        let lease = try await Self.signIn([Self.remembering(cache)])
        #expect(await cache.saves == 1)
        #expect(await lease.authentication.subject.id == "ada")
        await lease.end()
    }

    @Test("A stale token is forgotten before the device sign-in runs, and its new token is remembered")
    func staleThenDevice() async throws {
        let cache = MemoryCache("revoked-at-the-idp")
        let lease = try await Self.signIn([
            RememberedToken(cache: cache, credential: BearerKey.init), Self.remembering(cache),
        ])
        #expect(await cache.clears == 1)
        #expect(await cache.token == "ada-key")
        await lease.end()
    }

    @Test("Remembering a device sign-in changes neither what it asks of the person nor what it shows")
    func rememberingShowsPrompt() async throws {
        let cache = MemoryCache()
        let presenter = ScriptedPresenter()
        let uri = try #require(URL(string: "https://example.com/device"))
        let device = DeviceSignIn(remembering: cache, credential: BearerKey.init) { present in
            try await present(DevicePrompt(userCode: "WDJB-MJHT", verificationURI: uri))
            return "ada-key"
        }

        let lease = try await Self.signIn([device], presenter: presenter)

        #expect(device.requirements == DeviceSignIn { _ in BearerKey("") }.requirements)
        #expect(await presenter.shown == [.visit(userCode: "WDJB-MJHT", verificationURI: uri, verificationURIComplete: nil)])
        await lease.end()
    }
}
