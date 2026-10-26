// SSHSessionAuthenticationTests.swift
// SwiftCLIKitAuthSSHTests
// Created by Justin Purnell on 2026-10-25.

import Testing
import SwiftCLIKit
import SwiftCLIKitSSH
import SwiftCLIKitAuthSSH

@Suite("SSHSession.authentication")
struct SSHSessionAuthenticationTests {

    @Test("A session whose verifier attached something else has no authentication")
    func otherAttachment() {
        let session = SSHSession(
            id: "s", remoteAddress: "127.0.0.1", terminalSize: TerminalSize(columns: 80, rows: 24),
            clientIdentity: nil, verification: "not an authentication"
        )
        #expect(session.authentication == nil)
    }
}
