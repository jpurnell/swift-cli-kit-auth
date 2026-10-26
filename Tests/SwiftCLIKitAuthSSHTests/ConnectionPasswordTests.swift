// ConnectionPasswordTests.swift
// SwiftCLIKitAuthSSHTests
// Created by Justin Purnell on 2026-10-25.

import Testing
import Foundation
import SwiftCLIKitSSH
import SwiftIdentity
import SwiftCLIKitAuthSSH

/// What an admission closure was asked about.
private actor Asked {
    private(set) var subjects: [String] = []

    func record(_ authentication: Authentication) {
        subjects.append(authentication.subject.id)
    }
}

/// `ConnectionPassword` against a real `FileCredentialStore`: SwiftIdentity decides who someone
/// is, the closure decides whether the app admits them, and only both together admit.
@Suite("ConnectionPassword")
struct ConnectionPasswordTests {

    private static func attempt(_ username: String, _ password: String) -> SSHAuthenticationAttempt {
        SSHAuthenticationAttempt(username: username, evidence: .password, password: password)
    }

    @Test("It offers passwords, and only passwords")
    func methods() throws {
        let fixture = try PassphraseStoreFixture()
        defer { fixture.remove() }
        #expect(ConnectionPassword(authenticator: fixture.authenticator).methods == .password)
    }

    @Test("The right password admits, attaching an Authentication for the username's subject")
    func rightPasswordAdmits() async throws {
        let fixture = try PassphraseStoreFixture()
        defer { fixture.remove() }
        let verifier = ConnectionPassword(authenticator: fixture.authenticator)

        let verdict = await verifier.verify(Self.attempt("ada", PassphraseStoreFixture.secret))

        #expect(verdict.admits)
        let authentication = try #require(verdict.attachment as? Authentication)
        #expect(authentication.subject.id == "ada")
        #expect(authentication.factors.map(\.kind) == [Passphrase.kind])
        #expect(authentication.assurance == .singleFactor)
    }

    @Test("A wrong password is refused, with nothing attached")
    func wrongPasswordRefused() async throws {
        let fixture = try PassphraseStoreFixture()
        defer { fixture.remove() }
        let verifier = ConnectionPassword(authenticator: fixture.authenticator)

        let verdict = await verifier.verify(Self.attempt("ada", PassphraseStoreFixture.secret + "x"))

        #expect(!verdict.admits)
        #expect(verdict.attachment == nil)
    }

    @Test("A user the store doesn't know is refused, even with a known user's password")
    func unknownUserRefused() async throws {
        let fixture = try PassphraseStoreFixture()
        defer { fixture.remove() }
        let verifier = ConnectionPassword(authenticator: fixture.authenticator)

        #expect(!(await verifier.verify(Self.attempt("mallory", PassphraseStoreFixture.secret))).admits)
        // On the roster, with no passphrase of her own.
        #expect(!(await verifier.verify(Self.attempt("grace", PassphraseStoreFixture.secret))).admits)
    }

    @Test("The username is passed through unchanged: a different case is a different user")
    func usernameIsCaseSensitive() async throws {
        let fixture = try PassphraseStoreFixture()
        defer { fixture.remove() }
        let verifier = ConnectionPassword(authenticator: fixture.authenticator)

        #expect(!(await verifier.verify(Self.attempt("Ada", PassphraseStoreFixture.secret))).admits)
        #expect(!(await verifier.verify(Self.attempt(" ada", PassphraseStoreFixture.secret))).admits)
    }

    @Test("A proven subject the app doesn't admit is refused, and the closure saw who it was")
    func admissionCanRefuse() async throws {
        let fixture = try PassphraseStoreFixture()
        defer { fixture.remove() }
        let asked = Asked()
        let verifier = ConnectionPassword(authenticator: fixture.authenticator) { authentication in
            await asked.record(authentication)
            return false
        }

        let verdict = await verifier.verify(Self.attempt("ada", PassphraseStoreFixture.secret))

        #expect(!verdict.admits)
        #expect(verdict.attachment == nil)
        #expect(await asked.subjects == ["ada"])
    }

    @Test("Admission is asked only about a subject SwiftIdentity proved")
    func admissionNotAskedOnRefusal() async throws {
        let fixture = try PassphraseStoreFixture()
        defer { fixture.remove() }
        let asked = Asked()
        let verifier = ConnectionPassword(authenticator: fixture.authenticator) { authentication in
            await asked.record(authentication)
            return true
        }

        #expect(!(await verifier.verify(Self.attempt("ada", "wrong"))).admits)
        #expect(await asked.subjects.isEmpty)
    }

    @Test("Anything but a password attempt is refused")
    func nonPasswordRefused() async throws {
        let fixture = try PassphraseStoreFixture()
        defer { fixture.remove() }
        let verifier = ConnectionPassword(authenticator: fixture.authenticator)
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnly"

        let keyAttempt = SSHAuthenticationAttempt(username: "ada", evidence: .publicKey(openSSH: key))
        #expect(!(await verifier.verify(keyAttempt)).admits)
        // Key evidence that somehow also carries the right password is still not a password attempt.
        let mixed = SSHAuthenticationAttempt(
            username: "ada", evidence: .publicKey(openSSH: key), password: PassphraseStoreFixture.secret
        )
        #expect(!(await verifier.verify(mixed)).admits)
        // Password evidence with no password has nothing to check.
        let empty = SSHAuthenticationAttempt(username: "ada", evidence: .password)
        #expect(!(await verifier.verify(empty)).admits)
    }

    @Test("The verifier's description, debug description and mirror never show a secret")
    func noSecretInDescriptions() async throws {
        let fixture = try PassphraseStoreFixture()
        defer { fixture.remove() }
        let verifier = ConnectionPassword(authenticator: fixture.authenticator)
        _ = await verifier.verify(Self.attempt("ada", PassphraseStoreFixture.secret))

        var dumped = ""
        dump(verifier, to: &dumped)
        for text in [String(describing: verifier), String(reflecting: verifier), dumped] {
            #expect(!text.contains(PassphraseStoreFixture.secret))
        }
    }
}
