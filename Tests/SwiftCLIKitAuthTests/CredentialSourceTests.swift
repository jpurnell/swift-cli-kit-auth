// CredentialSourceTests.swift
// SwiftCLIKitAuthTests
// Created by Justin Purnell on 2026-10-25.

import Testing
import Foundation
import SwiftIdentity
import SwiftCLIKitAuth

@Suite("Credential sources")
struct CredentialSourceTests {

    private static func context(_ presenter: ScriptedPresenter, subjectID: String? = nil) -> SignInContext {
        SignInContext(presenter: presenter, subjectID: subjectID)
    }

    // MARK: - PromptedPassword

    @Test("PromptedPassword asks for a username, then the password as a secret")
    func passwordAsksBoth() async throws {
        let presenter = ScriptedPresenter([.text("ada"), .text("right")])
        let credentials = try await PromptedPassword().credentials(Self.context(presenter))
        #expect(credentials?.first as? Passphrase == Passphrase(subjectID: "ada", secret: "right"))
        #expect(await presenter.asked == ["text:Username", "secret:Password"])
    }

    @Test("PromptedPassword doesn't ask for a username the sign-in already has")
    func passwordUsesContextSubject() async throws {
        let presenter = ScriptedPresenter([.text("right")])
        let credentials = try await PromptedPassword(subjectHint: "grace").credentials(Self.context(presenter, subjectID: "ada"))
        #expect(credentials?.first as? Passphrase == Passphrase(subjectID: "ada", secret: "right"))
        #expect(await presenter.asked == ["secret:Password"])
    }

    @Test("PromptedPassword uses its hint when the sign-in names no one yet")
    func passwordUsesHint() async throws {
        let presenter = ScriptedPresenter([.text("right")])
        let credentials = try await PromptedPassword(subjectHint: "ada").credentials(Self.context(presenter))
        #expect((credentials?.first as? Passphrase)?.subjectID == "ada")
    }

    @Test("A cancelled prompt stops the source")
    func passwordCancelled() async {
        let presenter = ScriptedPresenter([.text("ada"), .fail(.cancelled)])
        await #expect(throws: SignInError.cancelled) {
            _ = try await PromptedPassword().credentials(Self.context(presenter))
        }
    }

    @Test("A password is passed on exactly as typed, untrimmed")
    func passwordUntrimmed() async throws {
        let presenter = ScriptedPresenter([.text("ada"), .text("  spaced out  ")])
        let credentials = try await PromptedPassword().credentials(Self.context(presenter))
        #expect((credentials?.first as? Passphrase)?.secret == "  spaced out  ")
    }

    // MARK: - PromptedCode

    @Test("PromptedCode reads the code in the clear, without the spaces people type in it")
    func code() async throws {
        let presenter = ScriptedPresenter([.text(" 123 456 ")])
        let credentials = try await PromptedCode().credentials(Self.context(presenter, subjectID: "ada"))
        #expect(credentials?.first as? OneTimeCode == OneTimeCode(subjectID: "ada", code: "123456"))
        #expect(await presenter.asked == ["text:One-time code"])
    }

    @Test("PromptedCode asks for a username when nothing names one")
    func codeAsksUsername() async throws {
        let presenter = ScriptedPresenter([.text("ada"), .text("123456")])
        let credentials = try await PromptedCode().credentials(Self.context(presenter))
        #expect((credentials?.first as? OneTimeCode)?.subjectID == "ada")
        #expect(await presenter.asked == ["text:Username", "text:One-time code"])
    }

    // MARK: - DeviceSignIn

    @Test("DeviceSignIn shows the code and URL, then returns the flow's credential")
    func device() async throws {
        let presenter = ScriptedPresenter()
        let uri = try #require(URL(string: "https://example.com/device"))
        let complete = try #require(URL(string: "https://example.com/device?user_code=WDJB-MJHT"))
        let source = DeviceSignIn { present in
            try await present(DevicePrompt(userCode: "WDJB-MJHT", verificationURI: uri, verificationURIComplete: complete))
            return BearerKey("ada-key")
        }
        let credentials = try await source.credentials(Self.context(presenter))
        #expect(credentials?.first as? BearerKey == BearerKey("ada-key"))
        #expect(await presenter.shown == [.visit(userCode: "WDJB-MJHT", verificationURI: uri, verificationURIComplete: complete)])
        #expect(source.requirements.contains([.showsURL, .network]))
    }

    @Test("A device flow that fails for any reason the person didn't choose fails the sign-in, saying nothing more")
    func deviceFailure() async {
        struct Denied: Error {}
        let source = DeviceSignIn { _ in throw Denied() }
        await #expect(throws: SignInError.failed) {
            _ = try await source.credentials(Self.context(ScriptedPresenter()))
        }
    }

    @Test("A device flow the person cancelled stays cancelled")
    func deviceCancelled() async {
        let source = DeviceSignIn { _ in throw SignInError.cancelled }
        await #expect(throws: SignInError.cancelled) {
            _ = try await source.credentials(Self.context(ScriptedPresenter()))
        }
    }

    // MARK: - Together

    @Test("Together gathers every source's credentials, naming the subject once")
    func together() async throws {
        let presenter = ScriptedPresenter([.text("ada"), .text("right"), .text("123456")])
        let source = Together(PromptedPassword(), PromptedCode())
        let credentials = try #require(try await source.credentials(Self.context(presenter)))
        #expect(credentials.count == 2)
        #expect(credentials.first as? Passphrase == Passphrase(subjectID: "ada", secret: "right"))
        #expect(credentials.last as? OneTimeCode == OneTimeCode(subjectID: "ada", code: "123456"))
        #expect(await presenter.asked == ["text:Username", "secret:Password", "text:One-time code"])
        #expect(source.requirements == [.interaction, .readsSecret])
    }

    @Test("Together doesn't apply when any of its sources doesn't")
    func togetherNotApplicable() async throws {
        struct NotHere: CredentialSource {
            var requirements: SourceRequirements { [] }
            func credentials(_ context: SignInContext) async throws -> [any Credential]? { nil }
        }
        let presenter = ScriptedPresenter([.text("ada"), .text("right")])
        #expect(try await Together(PromptedPassword(), NotHere()).credentials(Self.context(presenter)) == nil)
    }

    @Test("Together stops at the first source that throws")
    func togetherThrows() async {
        let presenter = ScriptedPresenter([.text("ada"), .fail(.cancelled), .text("123456")])
        await #expect(throws: SignInError.cancelled) {
            _ = try await Together(PromptedPassword(), PromptedCode()).credentials(Self.context(presenter))
        }
        #expect(await presenter.asked == ["text:Username", "secret:Password"])
    }

    @Test("Together's multi-factor credentials authenticate as multi-factor")
    func togetherIsMultiFactor() async throws {
        let presenter = ScriptedPresenter([.text("ada"), .text("right"), .text("123456")])
        let credentials = try #require(try await Together(PromptedPassword(), PromptedCode()).credentials(Self.context(presenter)))
        let authentication = try await Fixture.authentication(credentials)
        #expect(authentication.assurance == .multiFactor)
    }
}
