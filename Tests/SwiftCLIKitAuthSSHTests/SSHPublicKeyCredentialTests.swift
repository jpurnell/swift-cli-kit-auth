// SSHPublicKeyCredentialTests.swift
// SwiftCLIKitAuthSSHTests
// Created by Justin Purnell on 2026-10-26.

import Testing
import Foundation
import SwiftCLIKitSSH
import SwiftIdentity
import SwiftCLIKitAuthSSH

@Suite("SSHPublicKeyCredential")
struct SSHPublicKeyCredentialTests {

    /// A fixture file's first line.
    static func fixture(_ name: String) throws -> String {
        let url = try #require(Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures"))
        let text = try String(contentsOf: url, encoding: .utf8)
        return try #require(text.split(whereSeparator: \.isNewline).first.map(String.init))
    }

    /// The `SHA256:…` field of `ssh-keygen -l` output.
    static func oracleFingerprint(_ name: String) throws -> String {
        let fields = try fixture("\(name).fingerprint.txt").split(separator: " ")
        return try #require(fields.count > 1 ? String(fields[1]) : nil)
    }

    @Test("The fingerprint is the one ssh-keygen -l prints", arguments: [
        ("user_ed25519", "ssh-ed25519"), ("host_ed25519", "ssh-ed25519"), ("unknown_ecdsa", "ecdsa-sha2-nistp256"),
    ])
    func fingerprintMatchesOpenSSH(_ name: String, _ type: String) throws {
        let key = try #require(SSHPublicKeyCredential(openSSH: try Self.fixture("\(name).pub")))
        #expect(key.fingerprint == (try Self.oracleFingerprint(name)))
        #expect(key.keyType == type)
    }

    @Test("The comment is not part of the key")
    func commentIgnored() throws {
        let line = try Self.fixture("user_ed25519.pub")
        let fields = line.split(separator: " ")
        let bare = fields.prefix(2).joined(separator: " ")
        #expect(SSHPublicKeyCredential(openSSH: line) == SSHPublicKeyCredential(openSSH: bare + " another-comment"))
        #expect(SSHPublicKeyCredential(openSSH: line)?.openSSH == bare)
    }

    @Test("A line that isn't an OpenSSH public key is refused", arguments: [
        "", "ssh-ed25519", "ssh-ed25519 not-base64!", "ssh-ed25519 AAAA", "AAAAC3NzaC1lZDI1NTE5 ssh-ed25519",
    ])
    func malformed(_ line: String) {
        #expect(SSHPublicKeyCredential(openSSH: line) == nil)
    }

    @Test("A key whose type field disagrees with the type inside the key is refused")
    func typeMismatch() throws {
        let fields = try Self.fixture("user_ed25519.pub").split(separator: " ")
        #expect(SSHPublicKeyCredential(openSSH: "ecdsa-sha2-nistp256 \(fields[1])") == nil)
    }

    @Test("A connection's public-key evidence becomes the credential; other evidence doesn't")
    func fromIdentity() throws {
        let line = try Self.fixture("user_ed25519.pub")
        let bare = line.split(separator: " ").prefix(2).joined(separator: " ")
        let keyed = SSHClientIdentity(username: "ada", evidence: .publicKey(openSSH: bare))
        #expect(SSHPublicKeyCredential(keyed)?.openSSH == bare)
        #expect(SSHPublicKeyCredential(SSHClientIdentity(username: "ada", evidence: .password)) == nil)
        #expect(SSHPublicKeyCredential(SSHClientIdentity(username: "ada", evidence: .none)) == nil)
    }

    @Test("It is a possession factor of its own kind")
    func kind() {
        #expect(SSHPublicKeyCredential.kind == "ssh-public-key")
        #expect(SSHPublicKeyCredential.factorClass == .possession)
    }
}
