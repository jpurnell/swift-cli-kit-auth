// TerminalPresenter.swift
// SwiftCLIKitAuth
// Created by Justin Purnell on 2026-10-25.

import Foundation
import SwiftCLIKit

/// A line-oriented ``SignInPresenter`` over a SwiftCLIKit terminal, in the manner of
/// `gh auth login`.
///
/// It writes lines with `TerminalBackend.write(_:)` and reads keys with
/// `TerminalBackend.nextKey()`, the only way to read keys over SSH. It never enters the alternate
/// screen, so what it asked and what was answered stay in the person's scrollback, and it ends
/// every line with `"\r\n"`, because a raw terminal (an SSH session's, say) doesn't turn `"\n"`
/// into a carriage return.
///
/// - A secret is read with SwiftCLIKit's `SecureField`: masked with `•`, pasted whole, shown
///   only while the reveal key is toggled on, and masked again when the person presses Enter,
///   so a revealed secret is never left in scrollback.
/// - Ctrl-C or Escape at any prompt throws ``SignInError/cancelled``; input ending (the terminal
///   closing, or the SSH client disconnecting) throws ``SignInError/inputEnded``.
/// - Everything shown is neutralised first: control characters (C0, C1, DEL, and so ESC),
///   Unicode format characters (bidirectional overrides, zero-width characters) and line and
///   paragraph separators are each replaced with U+FFFD, so text from outside, such as a device
///   sign-in's user code, can't clear the screen, move the cursor or reorder what the person
///   reads. This changes only what is displayed, never what a prompt returns.
///
/// ```swift
/// import SwiftCLIKit
/// import SwiftCLIKitAuth
///
/// func askForPassword(over backend: any TerminalBackend) async throws -> String {
///     let presenter = TerminalPresenter(backend: backend)
///     return try await presenter.readSecret("Password")
/// }
/// ```
public struct TerminalPresenter: SignInPresenter {
    private let backend: any TerminalBackend
    private let revealKey: Key?

    /// Erases the whole line the cursor is on (ECMA-48 EL 2), leaving the cursor where it is.
    private static let eraseLine = "\u{1B}[2K"
    /// What ends a line on a raw terminal.
    private static let newline = "\r\n"
    /// The width to assume when the terminal reports none.
    private static let fallbackColumns = 80

    /// Creates a presenter.
    /// - Parameters:
    ///   - backend: The terminal to write to and read keys from.
    ///   - revealKey: The key that shows or hides a secret as it is typed, or `nil` for a secret
    ///     that is never shown. F2 by default.
    public init(backend: any TerminalBackend, revealKey: Key? = .functionKey(2)) {
        self.backend = backend
        self.revealKey = revealKey
    }

    // MARK: - SignInPresenter

    /// Shows a prompt that needs no answer.
    ///
    /// A device prompt reads "To sign in, visit <URI> and enter the code: <CODE>", with a second
    /// line offering the complete URI when there is one. A refusal reads "Sign-in failed." and
    /// nothing more.
    /// - Parameter prompt: What to show.
    public func show(_ prompt: SignInPrompt) async {
        switch prompt {
        case .visit(let userCode, let verificationURI, let verificationURIComplete):
            let uri = Self.neutralised(verificationURI.absoluteString)
            let code = Self.neutralised(userCode)
            var text = "To sign in, visit \(uri) and enter the code: \(code)" + Self.newline
            if let verificationURIComplete {
                text += "Or open: \(Self.neutralised(verificationURIComplete.absoluteString))" + Self.newline
            }
            backend.write(text)
        case .failed:
            backend.write("Sign-in failed." + Self.newline)
        }
    }

    /// Reads a line the person sees as they type.
    ///
    /// Backspace deletes the last character and Enter submits. A paste is inserted whole, except
    /// for its control characters: this is a single-line field, so a pasted line break neither
    /// submits nor becomes part of the value, and is dropped along with tabs and escapes.
    /// - Parameter label: What is being asked for.
    /// - Returns: What they entered.
    /// - Throws: ``SignInError/cancelled`` on Ctrl-C or Escape; ``SignInError/inputEnded`` if
    ///   input ends first.
    public func readText(_ label: String) async throws -> String {
        let prefix = Self.prefix(for: label)
        var text = ""
        drawText(text, prefix: prefix)
        while let key = await backend.nextKey() {
            switch key {
            case .ctrlC, .escape:
                backend.write(Self.newline)
                throw SignInError.cancelled
            case .enter:
                backend.write(Self.newline)
                return text
            case .backspace:
                guard !text.isEmpty else { continue }
                text.removeLast()
            case .character(let character):
                let kept = Self.withoutControls(String(character))
                guard !kept.isEmpty else { continue }
                text += kept
            case .paste(let pasted):
                let kept = Self.withoutControls(pasted)
                guard !kept.isEmpty else { continue }
                text += kept
            default:
                continue
            }
            drawText(text, prefix: prefix)
        }
        throw SignInError.inputEnded
    }

    /// Reads a secret with SwiftCLIKit's `SecureField`: masked, pasted whole, shown only while
    /// the reveal key is toggled on.
    ///
    /// The field is redrawn on its own line after every key. When the person presses Enter it
    /// is drawn masked once more, so a revealed secret doesn't stay in scrollback.
    /// - Parameter label: What is being asked for.
    /// - Returns: The secret, which the caller hands on and does not keep.
    /// - Throws: ``SignInError/cancelled`` on Ctrl-C or Escape; ``SignInError/inputEnded`` if
    ///   input ends first.
    public func readSecret(_ label: String) async throws -> String {
        let prefix = Self.prefix(for: label)
        var field = SecureField()
        field.revealKey = revealKey
        drawSecret(field, prefix: prefix)
        while let key = await backend.nextKey() {
            if key == .ctrlC {
                try cancel(&field, prefix: prefix)
            }
            switch field.handleKey(key) {
            case .submitted:
                field.setRevealed(false)
                drawSecret(field, prefix: prefix)
                backend.write(Self.newline)
                return field.consume()
            case .cancelled:
                try cancel(&field, prefix: prefix)
            case .changed, .revealChanged:
                drawSecret(field, prefix: prefix)
            case .unhandled:
                continue
            }
        }
        field.clear()
        throw SignInError.inputEnded
    }

    /// Says what is happening, on a line of its own.
    /// - Parameter message: The status, such as "Waiting for approval…".
    public func progress(_ message: String) async {
        backend.write(Self.neutralised(message) + Self.newline)
    }

    // MARK: - Drawing

    /// Redraws a text prompt's line, showing as much of the end of the text as fits.
    private func drawText(_ text: String, prefix: String) {
        let room = max(columns() - UnicodeWidth.displayWidth(prefix) - 1, 1)
        var shown: [Character] = []
        var used = 0
        for character in text.reversed() {
            let width = max(UnicodeWidth.width(of: character), 1)
            guard used + width <= room else { break }
            used += width
            shown.append(character)
        }
        redraw(prefix + Self.neutralised(String(shown.reversed())))
    }

    /// Redraws a secret prompt's line: the field rendered into a frame, and its content row
    /// written as plain text.
    private func drawSecret(_ field: SecureField, prefix: String) {
        // SecureField draws a box, so its content is the middle row, inside the borders.
        let width = max(columns() - UnicodeWidth.displayWidth(prefix) + 1, 4)
        var frame = Frame(buffer: CellBuffer(width: width, height: 3), rect: Rect(x: 0, y: 0, width: width, height: 3))
        field.render(into: &frame, focused: true)
        let buffer = frame.cellBuffer
        var row = ""
        var x = 1
        while x < width - 1 {
            let character = buffer[x, 1].character
            row.append(character)
            x += max(UnicodeWidth.width(of: character), 1)
        }
        while row.last == " " {
            row.removeLast()
        }
        redraw(prefix + Self.neutralised(row))
    }

    /// Returns to the start of the line, erases it, and writes `line`.
    private func redraw(_ line: String) {
        backend.write("\r" + Self.eraseLine + line)
    }

    /// Masks and ends a secret prompt the person cancelled.
    private func cancel(_ field: inout SecureField, prefix: String) throws -> Never {
        field.setRevealed(false)
        drawSecret(field, prefix: prefix)
        field.clear()
        backend.write(Self.newline)
        throw SignInError.cancelled
    }

    /// The terminal's width, or a sensible one if it reports none.
    private func columns() -> Int {
        let reported = backend.terminalSize().columns
        return reported > 0 ? reported : Self.fallbackColumns
    }

    // MARK: - Neutralising

    /// What precedes the answer on a prompt's line.
    private static func prefix(for label: String) -> String {
        neutralised(label) + ": "
    }

    /// `text` with every scalar a terminal might act on replaced by U+FFFD.
    private static func neutralised(_ text: String) -> String {
        var result = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            result.append(isInert(scalar) ? scalar : "\u{FFFD}")
        }
        return String(result)
    }

    /// `text` without its control characters, for a single-line field's value.
    private static func withoutControls(_ text: String) -> String {
        var result = String.UnicodeScalarView()
        for scalar in text.unicodeScalars where scalar.properties.generalCategory != .control {
            result.append(scalar)
        }
        return String(result)
    }

    /// Whether `scalar` is safe to write: not a control character, a format character (such as
    /// a bidirectional override or a zero-width space), or a line or paragraph separator.
    private static func isInert(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator:
            return false
        default:
            return true
        }
    }
}
