// SignInPresenter.swift
// SwiftCLIKitAuth
// Created by Justin Purnell on 2026-10-25.

import Foundation

/// Why a sign-in didn't produce a session.
///
/// Deliberately coarse. A refusal is ``failed`` whatever the reason: the reason goes to
/// SwiftIdentity's audit trail and never to the person signing in, so a guesser learns nothing
/// about which part was wrong.
public enum SignInError: Error, Sendable, Equatable {
    /// The credentials didn't prove a subject the app admits. Shown as "Sign-in failed".
    case failed
    /// The person cancelled: Ctrl-C or Escape at a prompt, or dismissing a device sign-in.
    case cancelled
    /// Input ended before the sign-in did: the terminal closed or the SSH client disconnected.
    case inputEnded
}

/// Something a sign-in shows the person that isn't a question.
public enum SignInPrompt: Sendable, Equatable {
    /// Visit a URL and enter a code: RFC 8628 device sign-in.
    /// - Parameters:
    ///   - userCode: The code to enter.
    ///   - verificationURI: Where to enter it.
    ///   - verificationURIComplete: A URL that carries the code, for a person who'd rather follow
    ///     a link than type.
    case visit(userCode: String, verificationURI: URL, verificationURIComplete: URL?)
    /// Sign-in failed. Never with a reason: see ``SignInError/failed``.
    case failed
}

/// How a sign-in talks to the person.
///
/// Sources ask through this and never draw for themselves, so the same source works in a local
/// terminal, over SSH, or in a test. Every method that reads throws ``SignInError/cancelled`` when
/// the person cancels and ``SignInError/inputEnded`` when input ends.
public protocol SignInPresenter: Sendable {
    /// Shows a prompt that needs no answer.
    /// - Parameter prompt: What to show.
    func show(_ prompt: SignInPrompt) async

    /// Reads a line the person may see as they type, such as a username or a one-time code.
    /// - Parameter label: What is being asked for.
    /// - Returns: What they entered.
    func readText(_ label: String) async throws -> String

    /// Reads a secret without echoing it: masked, pasted whole, revealed only on request.
    /// - Parameter label: What is being asked for.
    /// - Returns: The secret, which the caller hands on and does not keep.
    func readSecret(_ label: String) async throws -> String

    /// Says what is happening, such as "Waiting for approval…".
    /// - Parameter message: The status.
    func progress(_ message: String) async
}
