// Admission.swift
// SwiftCLIKitAuth
// Created by Justin Purnell on 2026-10-25.

import Foundation
import SwiftIdentity

/// Who the app admits, once SwiftIdentity has said who someone is.
///
/// Entitlement is the app's, so this is a small predicate rather than a framework. Rules combine
/// with ``all(_:)``:
///
/// ```swift
/// import SwiftCLIKitAuth
///
/// let opsWithTwoFactors = Admission.all([
///     .attribute("team", equals: "ops"),
///     .minimumAssurance(.multiFactor),
/// ])
/// ```
///
/// A rule only decides; it never asks for more. An app that needs a second factor presents both
/// together (``Together``), because SwiftIdentity computes assurance from the credentials
/// presented in one authentication. Raising it after admission is `AccessLease.reverify`.
public struct Admission: Sendable {
    private let decide: @Sendable (Authentication) async -> Bool

    private init(_ decide: @escaping @Sendable (Authentication) async -> Bool) {
        self.decide = decide
    }

    /// Whether the app admits this authentication.
    /// - Parameter authentication: What SwiftIdentity's `Authenticator` produced.
    /// - Returns: `true` to admit.
    public func admits(_ authentication: Authentication) async -> Bool {
        await decide(authentication)
    }

    /// Every subject SwiftIdentity authenticates. Revoked and honeypot subjects never get this
    /// far: they don't authenticate.
    public static let anyone = Admission { _ in true }

    /// Only these subjects.
    /// - Parameter ids: Local subject ids, as SwiftIdentity records them.
    /// - Returns: The rule.
    public static func subjects(_ ids: Set<String>) -> Admission {
        Admission { ids.contains($0.subject.id) }
    }

    /// Subjects whose attribute has exactly this value.
    /// - Parameters:
    ///   - name: The attribute, as the roster records it.
    ///   - value: The value it must have, compared exactly.
    /// - Returns: The rule.
    public static func attribute(_ name: String, equals value: String) -> Admission {
        Admission { $0.subject.attributes[name] == value }
    }

    /// At least this assurance, as SwiftIdentity computed it.
    /// - Parameter level: The weakest level admitted.
    /// - Returns: The rule.
    public static func minimumAssurance(_ level: Assurance) -> Admission {
        Admission { $0.assurance >= level }
    }

    /// Every factor's recorded algorithm passes `accept`, such as "no ES256 after 2035". A factor
    /// whose store recorded no algorithm fails the rule, so an unknown algorithm is never
    /// admitted by accident.
    /// - Parameter accept: Decides one factor, which is guaranteed to name an algorithm.
    /// - Returns: The rule.
    public static func factors(_ accept: @escaping @Sendable (VerifiedFactor) -> Bool) -> Admission {
        Admission { authentication in
            !authentication.factors.isEmpty
                && authentication.factors.allSatisfy { $0.algorithm != nil && accept($0) }
        }
    }

    /// The app's own decision.
    /// - Parameter decide: Returns `true` to admit.
    /// - Returns: The rule.
    public static func custom(_ decide: @escaping @Sendable (Authentication) async -> Bool) -> Admission {
        Admission(decide)
    }

    /// Every rule admits. An empty list admits no one: a missing rule should never mean "open".
    /// - Parameter rules: The rules, checked in order until one refuses.
    /// - Returns: The rule.
    public static func all(_ rules: [Admission]) -> Admission {
        Admission { authentication in
            guard !rules.isEmpty else { return false }
            for rule in rules where await !rule.admits(authentication) {
                return false
            }
            return true
        }
    }
}
