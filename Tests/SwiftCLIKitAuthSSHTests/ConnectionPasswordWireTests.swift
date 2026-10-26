// ConnectionPasswordWireTests.swift
// SwiftCLIKitAuthSSHTests
// Created by Justin Purnell on 2026-10-25.

import Testing
import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import NIOSSH
import SwiftIdentity
@testable import SwiftCLIKitSSH
import SwiftCLIKitAuthSSH

/// Offers one password, then gives up.
private final class OfferPasswordOnce: NIOSSHClientUserAuthenticationDelegate, Sendable {
    private let offer: NIOSSHUserAuthenticationOffer
    private let offered = NIOLockedValueBox(false)

    init(username: String, password: String) {
        offer = .init(username: username, serviceName: "", offer: .password(.init(password: password)))
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        let first = offered.withLockedValue { done -> Bool in
            defer { done = true }
            return !done
        }
        nextChallengePromise.succeed(first ? offer : nil)
    }
}

private final class TrustAnyHostKey: NIOSSHClientServerAuthenticationDelegate, Sendable {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        validationCompletePromise.succeed(())
    }
}

/// The sessions a server's handler ran for.
private final class Sessions: Sendable {
    private let state = NIOLockedValueBox<[SSHSession]>([])

    func record(_ session: SSHSession) {
        state.withLockedValue { $0.append(session) }
    }

    var values: [SSHSession] {
        state.withLockedValue { $0 }
    }
}

/// A real NIOSSH client against a real `SSHServer` whose verifier is `ConnectionPassword` over a
/// real `FileCredentialStore`. Rev 8's promise is checked where it matters: a wrong password
/// never reaches the session handler.
@Suite("ConnectionPassword over the wire")
struct ConnectionPasswordWireTests {

    /// Signs in with a password and opens a session; returns once the server closes it. Throws
    /// if the session doesn't open before `deadline`, so a refusal fails rather than hangs.
    private static func signIn(
        port: Int, group: any EventLoopGroup, username: String, password: String,
        deadline: TimeAmount = .seconds(10)
    ) async throws {
        let delegate = OfferPasswordOnce(username: username, password: password)
        let client = try await ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(
                        NIOSSHHandler(
                            role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: TrustAnyHostKey())),
                            allocator: channel.allocator,
                            inboundChildChannelInitializer: nil
                        )
                    )
                }
            }
            .connect(host: "127.0.0.1", port: port)
            .get()
        let opened = client.eventLoop.makePromise(of: Channel.self)
        let timer = client.eventLoop.scheduleTask(in: deadline) {
            opened.fail(ChannelError.connectTimeout(deadline))
            client.close(promise: nil)
        }
        defer { timer.cancel() }
        client.eventLoop.execute {
            do {
                let handler = try client.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
                handler.createChannel(opened, channelType: .session) { child, _ in
                    child.eventLoop.makeSucceededVoidFuture()
                }
            } catch {
                opened.fail(error)
            }
        }
        let session = try await opened.futureResult.get()
        try await session.triggerUserOutboundEvent(SSHChannelRequestEvent.ShellRequest(wantReply: false)).get()
        try await session.closeFuture.get()
        try await client.close()
    }

    /// Runs `body` against a server admitting through `verifier`, returning the sessions its
    /// handler ran for.
    private static func withServer(
        _ verifier: ConnectionPassword,
        _ body: (Int, any EventLoopGroup) async throws -> Void
    ) async throws -> [SSHSession] {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let sessions = Sessions()
        let server = SSHServer(port: 0, configuration: SSHConfiguration(authMode: .verifier(verifier)))
        let listener = try await server.bindListener(group: group) { _, session in
            sessions.record(session)
        }
        do {
            let port = try #require(listener.localAddress?.port)
            try await body(port, group)
        } catch {
            try await listener.close()
            try await group.shutdownGracefully()
            throw error
        }
        try await listener.close()
        try await group.shutdownGracefully()
        return sessions.values
    }

    @Test("The right password opens a session that carries the subject's Authentication")
    func rightPasswordOpensSession() async throws {
        let fixture = try PassphraseStoreFixture()
        defer { fixture.remove() }
        let verifier = ConnectionPassword(authenticator: fixture.authenticator)

        let sessions = try await Self.withServer(verifier) { port, group in
            try await Self.signIn(port: port, group: group, username: "ada", password: PassphraseStoreFixture.secret)
        }

        let session = try #require(sessions.first)
        #expect(sessions.count == 1)
        #expect(session.authentication?.subject.id == "ada")
        #expect(session.clientIdentity == SSHClientIdentity(username: "ada", evidence: .password))
    }

    @Test("A wrong password is refused, and the session handler never runs")
    func wrongPasswordOpensNothing() async throws {
        let fixture = try PassphraseStoreFixture()
        defer { fixture.remove() }
        let verifier = ConnectionPassword(authenticator: fixture.authenticator)

        let sessions = try await Self.withServer(verifier) { port, group in
            await #expect(throws: (any Error).self) {
                try await Self.signIn(
                    port: port, group: group, username: "ada", password: "wrong", deadline: .seconds(3)
                )
            }
        }

        #expect(sessions.isEmpty)
    }

    @Test("A proven subject the app doesn't admit gets no session either")
    func unadmittedSubjectOpensNothing() async throws {
        let fixture = try PassphraseStoreFixture()
        defer { fixture.remove() }
        let verifier = ConnectionPassword(authenticator: fixture.authenticator) { _ in false }

        let sessions = try await Self.withServer(verifier) { port, group in
            await #expect(throws: (any Error).self) {
                try await Self.signIn(
                    port: port, group: group, username: "ada", password: PassphraseStoreFixture.secret,
                    deadline: .seconds(3)
                )
            }
        }

        #expect(sessions.isEmpty)
    }
}
