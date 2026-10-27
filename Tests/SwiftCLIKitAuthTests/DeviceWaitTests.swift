// DeviceWaitTests.swift
// SwiftCLIKitAuthTests
// Created by Justin Purnell on 2026-10-27.

import Testing
import Foundation
import SwiftCLIKit
import SwiftIdentity
import SwiftCLIKitAuth

/// Whether a device flow saw its task cancelled.
private actor FlowRecord {
    private(set) var started = false
    private(set) var cancelled = false
    func start() { started = true }
    func cancel() { cancelled = true }
}

/// A device sign-in can be cancelled while it waits for approval: Ctrl-C or Escape stops the
/// flow's polling, and when the flow finishes first no key is taken from the app.
@Suite("Cancelling a device sign-in while it waits")
struct DeviceWaitTests {

    private static let uri = URL(fileURLWithPath: "/device")

    /// A flow that shows its prompt, then polls until approved or cancelled.
    private static func waitingFlow(_ record: FlowRecord, approvedAfter: Duration? = nil) -> DeviceSignIn {
        DeviceSignIn { present in
            try await present(DevicePrompt(userCode: "WDJB-MJHT", verificationURI: uri))
            await record.start()
            do {
                try await Task.sleep(for: approvedAfter ?? .seconds(30))
            } catch {
                await record.cancel()
                throw error
            }
            return BearerKey("ada-key")
        }
    }

    /// Waits until the flow is polling, so a key typed now is typed during the wait.
    private static func untilPolling(_ record: FlowRecord) async throws {
        for _ in 0..<200 where await !record.started {
            try await Task.sleep(for: .milliseconds(5))
        }
    }

    private static func gather(_ source: DeviceSignIn, _ backend: TestBackend) async throws -> [any Credential]? {
        try await source.credentials(SignInContext(presenter: TerminalPresenter(backend: backend)))
    }

    @Test("Ctrl-C while waiting cancels the sign-in and stops the flow", arguments: [Key.ctrlC, Key.escape])
    func cancelKey(_ key: Key) async throws {
        let backend = TestBackend(width: 80, height: 24)
        let record = FlowRecord()
        let source = Self.waitingFlow(record)

        let gathering = Task { try await Self.gather(source, backend) }
        try await Self.untilPolling(record)
        await backend.inject(.key(key))

        await #expect(throws: SignInError.cancelled) { _ = try await gathering.value }
        #expect(await record.cancelled)
    }

    @Test("Input ending while waiting ends the sign-in, and stops the flow")
    func inputEnds() async throws {
        let backend = TestBackend(width: 80, height: 24)
        let record = FlowRecord()
        let source = Self.waitingFlow(record)

        let gathering = Task { try await Self.gather(source, backend) }
        try await Self.untilPolling(record)
        backend.endInput()

        await #expect(throws: SignInError.inputEnded) { _ = try await gathering.value }
        #expect(await record.cancelled)
    }

    @Test("Other keys while waiting are ignored")
    func otherKeys() async throws {
        let backend = TestBackend(width: 80, height: 24)
        let record = FlowRecord()
        let source = Self.waitingFlow(record, approvedAfter: .milliseconds(200))

        let gathering = Task { try await Self.gather(source, backend) }
        try await Self.untilPolling(record)
        await backend.inject(.key(.character("x")))

        let credentials = try #require(try await gathering.value)
        #expect((credentials.first as? BearerKey)?.value == "ada-key")
    }

    @Test("When the flow finishes first, the watch stops and the app's next key isn't taken")
    func approvedFirst() async throws {
        let backend = TestBackend(width: 80, height: 24)
        let record = FlowRecord()

        let credentials = try #require(try await Self.gather(Self.waitingFlow(record, approvedAfter: .milliseconds(20)), backend))

        #expect((credentials.first as? BearerKey)?.value == "ada-key")
        #expect(!backend.isAwaitingKey)
        let next = Task { await backend.nextKey() }
        await backend.inject(.key(.character("q")))
        #expect(await next.value == .character("q"))
    }

    @Test("A presenter that can't watch for keys still runs the flow to the end")
    func defaultWatch() async throws {
        let presenter = ScriptedPresenter()
        let source = DeviceSignIn { present in
            try await present(DevicePrompt(userCode: "WDJB-MJHT", verificationURI: Self.uri))
            return BearerKey("ada-key")
        }
        let credentials = try #require(try await source.credentials(SignInContext(presenter: presenter)))
        #expect((credentials.first as? BearerKey)?.value == "ada-key")
    }
}
