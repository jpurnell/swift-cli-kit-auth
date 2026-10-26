// CLISignInTests.swift
// SwiftCLIKitAuthTests
// Created by Justin Purnell on 2026-10-25.

import Testing
import Foundation
import SwiftIdentity
import SwiftCLIKitAuth

/// Records audit events, so a test can see that a refusal's reason went there and nowhere else.
private actor AuditLog: IdentityAudit {
    private(set) var outcomes: [IdentityEvent.Outcome] = []
    func record(_ event: IdentityEvent) async { outcomes.append(event.outcome) }
}

/// A source that counts its calls and returns fixed credentials, or nil.
private struct Counted: CredentialSource {
    let counter: CallCounter
    let result: [any Credential]?
    var requirements: SourceRequirements { [] }
    func credentials(_ context: SignInContext) async throws -> [any Credential]? {
        await counter.record(context.subjectID)
        return result
    }
}

@Suite("CLISignIn")
struct CLISignInTests {

    private static func sessions() -> SessionStore {
        SessionStore(subjects: { id in [Fixture.ada, Fixture.grace].first { $0.id == id } }, now: { Fixture.instant })
    }

    private static func signIn(
        _ sources: [any CredentialSource],
        admission: Admission = .anyone,
        presenter: ScriptedPresenter = ScriptedPresenter(),
        authenticator: Authenticator = Fixture.authenticator
    ) async throws -> AccessLease {
        var generator = SplitMix64(seed: 7)
        return try await CLISignIn.signIn(
            sources: sources, authenticator: authenticator, admission: admission, presenter: presenter,
            sessions: Self.sessions(), lifetime: 3600, reresolveEvery: .seconds(300),
            now: { Fixture.instant }, generator: &generator
        )
    }

    @Test("A source whose credentials resolve and are admitted signs in")
    func signsIn() async throws {
        let presenter = ScriptedPresenter([.text("ada"), .text("right")])
        let lease = try await Self.signIn([PromptedPassword()], presenter: presenter)
        #expect(await lease.authentication.subject.id == "ada")
        #expect(await lease.isActive)
        #expect(await presenter.shown.isEmpty)
        await lease.end()
    }

    @Test("A source that doesn't apply passes to the next")
    func notApplicable() async throws {
        let skipped = CallCounter()
        let lease = try await Self.signIn([
            Counted(counter: skipped, result: nil),
            Counted(counter: CallCounter(), result: [BearerKey("ada-key")]),
        ])
        #expect(await skipped.calls == 1)
        #expect(await lease.authentication.subject.id == "ada")
        await lease.end()
    }

    @Test("Credentials that don't resolve pass to the next source, as an unknown key would to a device sign-in")
    func unresolvedFallsThrough() async throws {
        let lease = try await Self.signIn([
            Counted(counter: CallCounter(), result: [BearerKey("nobody-knows-this")]),
            Counted(counter: CallCounter(), result: [BearerKey("ada-key")]),
        ])
        #expect(await lease.authentication.subject.id == "ada")
        await lease.end()
    }

    @Test("A source that throws stops the sign-in: no later source is asked")
    func throwNeverFallsThrough() async throws {
        let later = CallCounter()
        let presenter = ScriptedPresenter([.text("ada"), .fail(.cancelled)])
        await #expect(throws: SignInError.cancelled) {
            _ = try await Self.signIn([PromptedPassword(), Counted(counter: later, result: [BearerKey("ada-key")])], presenter: presenter)
        }
        #expect(await later.calls == 0)
        #expect(await presenter.shown.isEmpty, "a cancellation isn't a failure to report")
    }

    @Test("A subject that resolves but isn't admitted fails at once, without trying further sources")
    func notAdmitted() async throws {
        let later = CallCounter()
        let presenter = ScriptedPresenter()
        await #expect(throws: SignInError.failed) {
            _ = try await Self.signIn(
                [Counted(counter: CallCounter(), result: [BearerKey("grace-key")]),
                 Counted(counter: later, result: [BearerKey("ada-key")])],
                admission: .subjects(["ada"]), presenter: presenter
            )
        }
        #expect(await later.calls == 0)
        #expect(await presenter.shown == [.failed])
    }

    @Test("When nothing resolves, the person sees only that sign-in failed; the reason is in the audit")
    func refusalIsPrivate() async throws {
        let audit = AuditLog()
        let authenticator = Authenticator(stores: [Fixture.store], audit: audit, now: { Fixture.instant })
        let presenter = ScriptedPresenter([.text("ada"), .text("wrong"), .text("ada"), .text("right")])
        await #expect(throws: SignInError.failed) {
            _ = try await Self.signIn(
                [PromptedPassword(), Together(PromptedPassword(), BearerSource())],
                presenter: presenter, authenticator: authenticator
            )
        }
        #expect(await presenter.shown == [.failed])
        #expect(await presenter.progressMessages.isEmpty)
        #expect(await audit.outcomes.contains(.subjectMismatch))
    }

    @Test("A source failing for a reason that isn't a SignInError fails the sign-in, saying nothing more")
    func foreignError() async throws {
        struct Broken: CredentialSource {
            struct Oops: Error {}
            var requirements: SourceRequirements { [] }
            func credentials(_ context: SignInContext) async throws -> [any Credential]? { throw Oops() }
        }
        let presenter = ScriptedPresenter()
        await #expect(throws: SignInError.failed) {
            _ = try await Self.signIn([Broken()], presenter: presenter)
        }
        #expect(await presenter.shown == [.failed])
    }

    @Test("No sources fails")
    func noSources() async throws {
        await #expect(throws: SignInError.failed) {
            _ = try await Self.signIn([])
        }
    }
}

/// Grace's bearer key: with Ada's password, a subject mismatch.
private struct BearerSource: CredentialSource {
    var requirements: SourceRequirements { [] }
    func credentials(_ context: SignInContext) async throws -> [any Credential]? {
        [BearerKey("grace-key")]
    }
}
