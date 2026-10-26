// TerminalPresenterTests.swift
// SwiftCLIKitAuthTests
// Created by Justin Purnell on 2026-10-25.

import Foundation
import Testing
import SwiftCLIKit
import SwiftCLIKitAuth

@Suite("TerminalPresenter")
struct TerminalPresenterTests {

    // MARK: - Helpers

    private func makeBackend(width: Int = 200) -> TestBackend {
        TestBackend(width: width, height: 24)
    }

    private func type(_ text: String, into backend: TestBackend) async {
        await backend.injectSequence(text.map { .key(.character($0)) })
    }

    private func output(_ backend: TestBackend) -> String {
        backend.allWrittenOutput.joined()
    }

    // MARK: - readText

    @Test("Typed text is echoed and returned on Enter")
    func textEntry() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        await type("alice", into: backend)
        await backend.inject(.key(.enter))

        let value = try await presenter.readText("Username")

        #expect(value == "alice")
        let written = output(backend)
        #expect(written.contains("Username: "))
        #expect(written.contains("alice"))
        #expect(written.hasSuffix("\r\n"))
    }

    @Test("Backspace removes the last character")
    func textBackspace() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        await type("alicx", into: backend)
        await backend.inject(.key(.backspace))
        await type("e", into: backend)
        await backend.inject(.key(.enter))

        let value = try await presenter.readText("Username")

        #expect(value == "alice")
    }

    @Test("Backspace on an empty field does nothing")
    func textBackspaceEmpty() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        await backend.inject(.key(.backspace))
        await type("a", into: backend)
        await backend.inject(.key(.enter))

        #expect(try await presenter.readText("Code") == "a")
    }

    @Test("A paste is inserted whole")
    func textPaste() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        await type("ab", into: backend)
        await backend.inject(.key(.paste("123 456")))
        await backend.inject(.key(.enter))

        #expect(try await presenter.readText("Code") == "ab123 456")
    }

    @Test("A pasted line break neither submits nor enters the value")
    func textPasteLineBreak() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        await backend.inject(.key(.paste("12\r\n34\n")))
        await type("5", into: backend)
        await backend.inject(.key(.enter))

        #expect(try await presenter.readText("Code") == "12345")
    }

    @Test("Echoed text is neutralised")
    func textEchoNeutralised() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        await backend.inject(.key(.paste("a\u{1B}[2Jb\u{202E}c")))
        await backend.inject(.key(.enter))

        let value = try await presenter.readText("Code")

        #expect(!value.contains("\u{1B}"))
        let written = output(backend)
        #expect(!written.contains("\u{1B}[2J"))
        #expect(!written.unicodeScalars.contains("\u{202E}"))
    }

    // MARK: - readSecret

    @Test("A secret is masked and never written")
    func secretMasked() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        let typed = "hunter2-correct-horse"
        await type(typed, into: backend)
        await backend.inject(.key(.enter))

        let value = try await presenter.readSecret("Password")

        #expect(value == typed)
        let written = output(backend)
        #expect(!written.contains(typed))
        #expect(!written.contains("hunter"))
        #expect(!written.contains("horse"))
        #expect(written.contains(String(repeating: "•", count: typed.count)))
        #expect(written.contains("Password: "))
        #expect(written.hasSuffix("\r\n"))
    }

    @Test("A pasted 64-code-point Unicode password arrives whole")
    func secretUnicodePaste() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        // Latin with diacritics, CJK, emoji with a variation selector, a combining mark, Cyrillic
        // and Greek: 64 scalars.
        let padded = "pässwörd-日本語のパスワード-🔐🗝\u{FE0F}-e\u{0301}-Пароль-ÆØÅ-çñü-ß-🙂🙃-абв-漢字かな-Ωμέγα-λφψ"
        #expect(padded.unicodeScalars.count == 64)
        await backend.inject(.key(.paste(padded)))
        await backend.inject(.key(.enter))

        let value = try await presenter.readSecret("Password")

        #expect(value == padded)
        #expect(value.unicodeScalars.count == 64)
        #expect(!output(backend).contains("日本語"))
    }

    @Test("The reveal key shows the secret, and Enter masks it again")
    func secretReveal() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        await type("opensesame", into: backend)
        await backend.inject(.key(.functionKey(2)))
        await backend.inject(.key(.enter))

        let value = try await presenter.readSecret("Password")

        #expect(value == "opensesame")
        let writes = backend.allWrittenOutput
        #expect(writes.joined().contains("opensesame"))
        // The last draw of the field, the one left in scrollback, is masked.
        let lastDraw = writes.last { $0.contains("Password: ") }
        #expect(lastDraw?.contains("opensesame") == false)
        #expect(lastDraw?.contains("••••••••••") == true)
    }

    @Test("Without a reveal key, F2 reveals nothing")
    func secretNoRevealKey() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend, revealKey: nil)
        await type("opensesame", into: backend)
        await backend.inject(.key(.functionKey(2)))
        await backend.inject(.key(.enter))

        #expect(try await presenter.readSecret("Password") == "opensesame")
        #expect(!output(backend).contains("opensesame"))
    }

    @Test("A revealed secret is neutralised")
    func secretRevealNeutralised() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        await backend.inject(.key(.paste("pw\u{1B}[2J\u{202E}")))
        await backend.inject(.key(.functionKey(2)))
        await backend.inject(.key(.enter))

        let value = try await presenter.readSecret("Password")

        #expect(value == "pw\u{1B}[2J\u{202E}")
        let written = output(backend)
        #expect(!written.contains("\u{1B}[2J"))
        #expect(!written.unicodeScalars.contains("\u{202E}"))
    }

    @Test("A long secret on a narrow terminal is still returned whole")
    func secretNarrowTerminal() async throws {
        let backend = makeBackend(width: 20)
        let presenter = TerminalPresenter(backend: backend)
        let secret = String(repeating: "s3cr3t", count: 10)
        await backend.inject(.key(.paste(secret)))
        await backend.inject(.key(.enter))

        #expect(try await presenter.readSecret("Password") == secret)
        #expect(!output(backend).contains("s3cr3t"))
    }

    // MARK: - Cancelling and ending

    @Test("Ctrl-C cancels a text prompt")
    func textCtrlC() async {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        await type("al", into: backend)
        await backend.inject(.key(.ctrlC))

        await #expect(throws: SignInError.cancelled) {
            try await presenter.readText("Username")
        }
    }

    @Test("Escape cancels a text prompt")
    func textEscape() async {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        await backend.inject(.key(.escape))

        await #expect(throws: SignInError.cancelled) {
            try await presenter.readText("Username")
        }
    }

    @Test("Ctrl-C cancels a secret prompt")
    func secretCtrlC() async {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        await type("pw", into: backend)
        await backend.inject(.key(.ctrlC))

        await #expect(throws: SignInError.cancelled) {
            try await presenter.readSecret("Password")
        }
    }

    @Test("Escape cancels a secret prompt")
    func secretEscape() async {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        await type("pw", into: backend)
        await backend.inject(.key(.escape))

        await #expect(throws: SignInError.cancelled) {
            try await presenter.readSecret("Password")
        }
    }

    @Test("End of input ends a text prompt")
    func textInputEnded() async {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        await type("al", into: backend)
        backend.endInput()

        await #expect(throws: SignInError.inputEnded) {
            try await presenter.readText("Username")
        }
    }

    @Test("End of input ends a secret prompt")
    func secretInputEnded() async {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        backend.endInput()

        await #expect(throws: SignInError.inputEnded) {
            try await presenter.readSecret("Password")
        }
    }

    @Test("Input ending while a prompt waits ends it")
    func inputEndsWhileWaiting() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        let reading = Task { try await presenter.readSecret("Password") }
        while !backend.isAwaitingKey {
            await Task.yield()
        }
        backend.endInput()

        await #expect(throws: SignInError.inputEnded) {
            try await reading.value
        }
    }

    // MARK: - show and progress

    @Test("A device prompt names the URL and the code")
    func showVisit() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        let uri = try #require(URL(string: "https://example.com/device"))

        await presenter.show(.visit(userCode: "WDJB-MJHT", verificationURI: uri, verificationURIComplete: nil))

        #expect(output(backend) == "To sign in, visit https://example.com/device and enter the code: WDJB-MJHT\r\n")
    }

    @Test("A device prompt offers the complete URL when there is one")
    func showVisitComplete() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        let uri = try #require(URL(string: "https://example.com/device"))
        let complete = try #require(URL(string: "https://example.com/device?user_code=WDJB-MJHT"))

        await presenter.show(.visit(userCode: "WDJB-MJHT", verificationURI: uri, verificationURIComplete: complete))

        #expect(output(backend) == """
            To sign in, visit https://example.com/device and enter the code: WDJB-MJHT\r
            Or open: https://example.com/device?user_code=WDJB-MJHT\r

            """)
    }

    @Test("A malicious user code is neutralised")
    func showVisitNeutralised() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        let uri = try #require(URL(string: "https://example.com/device"))
        let code = "AB\u{1B}[2J\u{202E}CD\u{200B}\u{9B}31m\u{07}"

        await presenter.show(.visit(userCode: code, verificationURI: uri, verificationURIComplete: nil))

        let written = output(backend)
        #expect(!written.unicodeScalars.contains("\u{1B}"))
        #expect(!written.unicodeScalars.contains("\u{9B}"))
        #expect(!written.unicodeScalars.contains("\u{07}"))
        #expect(!written.unicodeScalars.contains("\u{202E}"))
        #expect(!written.unicodeScalars.contains("\u{200B}"))
        #expect(written.contains("AB"))
        #expect(written.contains("CD"))
        #expect(written.hasSuffix("\r\n"))
    }

    @Test("A failed sign-in says only that it failed")
    func showFailed() async {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)

        await presenter.show(.failed)

        #expect(output(backend) == "Sign-in failed.\r\n")
    }

    @Test("Progress writes the status line, neutralised")
    func progress() async {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)

        await presenter.progress("Waiting for approval\u{1B}[2J…")

        let written = output(backend)
        #expect(written.hasPrefix("Waiting for approval"))
        #expect(written.hasSuffix("…\r\n"))
        #expect(!written.unicodeScalars.contains("\u{1B}"))
    }

    // MARK: - Line endings and screen

    @Test("Every line ends CRLF, and the alternate screen is never used")
    func crlfOnly() async throws {
        let backend = makeBackend()
        let presenter = TerminalPresenter(backend: backend)
        let uri = try #require(URL(string: "https://example.com/device"))
        await type("a", into: backend)
        await backend.inject(.key(.enter))
        await type("b", into: backend)
        await backend.inject(.key(.enter))

        _ = try await presenter.readText("Username")
        _ = try await presenter.readSecret("Password")
        await presenter.progress("Working")
        await presenter.show(.visit(userCode: "X", verificationURI: uri, verificationURIComplete: uri))
        await presenter.show(.failed)

        let scalars = Array(output(backend).unicodeScalars)
        for (index, scalar) in scalars.enumerated() where scalar == "\n" {
            #expect(index > 0 && scalars[index - 1] == "\r")
        }
        #expect(!backend.isAlternateScreen)
    }
}
