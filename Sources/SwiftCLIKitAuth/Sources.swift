// Sources.swift
// SwiftCLIKitAuth
// Created by Justin Purnell on 2026-10-25.

import Foundation
import SwiftIdentity
#if canImport(os)
import os
#endif

/// A username and password, typed or pasted: a SwiftIdentity `Passphrase`.
///
/// The password is read as a secret (masked, pasted whole, revealed only on request) and passed
/// on exactly as entered. SwiftIdentity canonicalises it, as NIST SP 800-63B-4 requires, so
/// nothing is trimmed or normalised here.
///
/// ```swift
/// import SwiftCLIKitAuth
///
/// let source = PromptedPassword()             // asks "Username", then "Password"
/// let forAda = PromptedPassword(subjectHint: "ada")   // asks only "Password"
/// ```
public struct PromptedPassword: CredentialSource {
    /// Who to sign in when the sign-in hasn't named anyone yet; `nil` asks.
    public let subjectHint: String?

    /// Creates the source.
    /// - Parameter subjectHint: The subject to sign in, if known; otherwise the person is asked.
    public init(subjectHint: String? = nil) {
        self.subjectHint = subjectHint
    }

    /// It asks, and reads a secret.
    public var requirements: SourceRequirements { [.interaction, .readsSecret] }

    /// Asks for the username if needed, then the password.
    /// - Parameter context: Where it runs.
    /// - Returns: One `Passphrase`.
    /// - Throws: Whatever the presenter throws: ``SignInError/cancelled`` or ``SignInError/inputEnded``.
    public func credentials(_ context: SignInContext) async throws -> [any Credential]? {
        let subjectID = try await SubjectPrompt.subjectID(context, hint: subjectHint)
        let secret = try await context.presenter.readSecret("Password")
        return [Passphrase(subjectID: subjectID, secret: secret)]
    }
}

/// A one-time code from an authenticator app: a SwiftIdentity `OneTimeCode`.
///
/// The code is read in the clear (it's good for one step, and SwiftIdentity refuses it once
/// used), with spaces removed, since people type "123 456". As the second factor after a
/// password, present both with ``Together`` so they authenticate together:
///
/// ```swift
/// import SwiftCLIKitAuth
///
/// let twoFactor = Together(PromptedPassword(), PromptedCode())
/// ```
public struct PromptedCode: CredentialSource {
    /// Who to sign in when the sign-in hasn't named anyone yet; `nil` asks.
    public let subjectHint: String?

    /// Creates the source.
    /// - Parameter subjectHint: The subject to sign in, if known; otherwise the person is asked.
    public init(subjectHint: String? = nil) {
        self.subjectHint = subjectHint
    }

    /// It asks.
    public var requirements: SourceRequirements { [.interaction] }

    /// Asks for the username if needed, then the code.
    /// - Parameter context: Where it runs.
    /// - Returns: One `OneTimeCode`.
    /// - Throws: Whatever the presenter throws: ``SignInError/cancelled`` or ``SignInError/inputEnded``.
    public func credentials(_ context: SignInContext) async throws -> [any Credential]? {
        let subjectID = try await SubjectPrompt.subjectID(context, hint: subjectHint)
        let typed = try await context.presenter.readText("One-time code")
        let code = String(typed.filter { !$0.isWhitespace })
        return [OneTimeCode(subjectID: subjectID, code: code)]
    }
}

/// What a device sign-in shows the person: RFC 8628's user code and verification URIs.
public struct DevicePrompt: Sendable, Equatable {
    /// The code to enter.
    public let userCode: String
    /// Where to enter it.
    public let verificationURI: URL
    /// A URL carrying the code, for a person who'd rather follow a link.
    public let verificationURIComplete: URL?

    /// Creates a prompt.
    /// - Parameters:
    ///   - userCode: The code to enter.
    ///   - verificationURI: Where to enter it.
    ///   - verificationURIComplete: A URL carrying the code, if the server gave one.
    public init(userCode: String, verificationURI: URL, verificationURIComplete: URL? = nil) {
        self.userCode = userCode
        self.verificationURI = verificationURI
        self.verificationURIComplete = verificationURIComplete
    }
}

/// An OAuth device sign-in (RFC 8628), run by the app's own flow.
///
/// This package doesn't depend on an OAuth library: the app's closure runs the flow, calls
/// `present` once with the code and URL, and returns the credential the flow produced. With
/// swift-oauth, that is a few lines:
///
/// ```swift
/// import SwiftCLIKitAuth
/// import SwiftIdentity
///
/// // `requestToken` stands in for the app's OAuth client, such as swift-oauth's
/// // DeviceAuthorizationClient.signIn(present:), which hands back an access token.
/// func requestToken(_ present: @Sendable (DevicePrompt) async throws -> Void) async throws -> String {
///     guard let uri = URL(string: "https://example.com/device") else { return "" }
///     try await present(DevicePrompt(userCode: "WDJB-MJHT", verificationURI: uri))
///     return "access-token"
/// }
///
/// let device = DeviceSignIn { present in
///     BearerKey(try await requestToken(present))   // SwiftOAuthIdentity's OAuthAccessToken, in practice
/// }
///
/// // Or remember the token for later runs, which RememberedToken presents:
/// let cache = FileTokenCache(url: URL(fileURLWithPath: "/home/ada/.config/mytool/token"))
/// let remembered = DeviceSignIn(remembering: cache, credential: BearerKey.init) { present in
///     try await requestToken(present)
/// }
/// ```
///
/// A flow that throws for any reason the person didn't choose (denied, expired, a network
/// failure) fails the sign-in as ``SignInError/failed``, saying nothing more; one that throws
/// ``SignInError`` keeps it.
public struct DeviceSignIn: CredentialSource, OutcomeObservingSource {
    /// Runs a device sign-in: shows `present`'s prompt once, then returns the credential.
    public typealias Flow = @Sendable (_ present: @escaping @Sendable (DevicePrompt) async throws -> Void) async throws -> any Credential

    /// Runs a device sign-in: shows `present`'s prompt once, then returns the token string, which
    /// is what gets remembered.
    public typealias TokenFlow = @Sendable (_ present: @escaping @Sendable (DevicePrompt) async throws -> Void) async throws -> String

    #if canImport(os)
    private static let logger = Logger(subsystem: "com.swiftclikitauth", category: "DeviceSignIn")
    #endif

    private enum Kind: Sendable {
        case plain(Flow)
        case remembering(any TokenCache, TokenFlow, @Sendable (String) -> any Credential)
    }

    private let kind: Kind

    /// Creates the source.
    /// - Parameter flow: The app's device flow.
    public init(_ flow: @escaping Flow) {
        self.kind = .plain(flow)
    }

    /// Creates the source, remembering the token once the sign-in it makes is admitted.
    ///
    /// The token is saved only when its subject is admitted: not when it doesn't resolve, nor
    /// when the app turns them away, nor when the source is asked for a step-up. A save that
    /// fails is logged and the sign-in stands; the next run asks again.
    ///
    /// To keep a sign-in going past an access token's hour, return a refresh token from `flow`
    /// and exchange it in `credential`: refresh stays in the app, which owns the OAuth client.
    /// - Parameters:
    ///   - cache: Where the token is remembered, such as a ``FileTokenCache``.
    ///   - credential: Makes the credential SwiftIdentity resolves from the token.
    ///   - flow: The app's device flow, returning the token string.
    public init(
        remembering cache: any TokenCache,
        credential: @escaping @Sendable (String) -> any Credential,
        _ flow: @escaping TokenFlow
    ) {
        self.kind = .remembering(cache, flow, credential)
    }

    /// It shows a URL and reaches a server.
    public var requirements: SourceRequirements { [.interaction, .showsURL, .network] }

    /// Runs the flow, showing its prompt through the presenter.
    /// - Parameter context: Where it runs.
    /// - Returns: The flow's credential.
    /// - Throws: ``SignInError/cancelled`` or ``SignInError/inputEnded`` as the flow threw them;
    ///   ``SignInError/failed`` for anything else.
    public func credentials(_ context: SignInContext) async throws -> [any Credential]? {
        try await gather(context)?.credentials
    }

    /// Runs the flow, and remembers its token if the sign-in is admitted.
    func gather(_ context: SignInContext) async throws -> ObservedCredentials? {
        let presenter = context.presenter
        let present: @Sendable (DevicePrompt) async throws -> Void = { prompt in
            await presenter.show(.visit(
                userCode: prompt.userCode,
                verificationURI: prompt.verificationURI,
                verificationURIComplete: prompt.verificationURIComplete
            ))
            await presenter.progress("Waiting for approval…")
        }
        do {
            switch kind {
            case .plain(let flow):
                return .unobserved([try await flow(present)])
            case .remembering(let cache, let flow, let credential):
                let token = try await flow(present)
                return ObservedCredentials(credentials: [credential(token)]) { outcome in
                    guard outcome == .admitted else { return }
                    await Self.save(token, in: cache)
                }
            }
        } catch let error as SignInError {
            throw error
        } catch {
            throw SignInError.failed
        }
    }

    /// Saves an admitted token; a failure leaves the sign-in standing.
    private static func save(_ token: String, in cache: any TokenCache) async {
        do {
            try await cache.save(token)
        } catch {
            // The person is signed in; only remembering failed, so the next run asks again.
            #if canImport(os)
            logger.error("couldn't remember the sign-in: \(String(describing: error), privacy: .private)")
            #endif
        }
    }
}

/// A token remembered from an earlier sign-in, presented again.
///
/// Put it first, before the ``DeviceSignIn`` that remembers into the same cache: a token that
/// still resolves signs the person in with no prompt; one that doesn't (it expired, was revoked
/// at the identity provider, or its subject was revoked here) is forgotten, and the device
/// sign-in runs.
///
/// ```swift
/// import Foundation
/// import SwiftCLIKitAuth
/// import SwiftIdentity
///
/// func sources(_ flow: @escaping DeviceSignIn.TokenFlow) -> [any CredentialSource] {
///     let cache = FileTokenCache(url: URL(fileURLWithPath: "/home/ada/.config/mytool/token"))
///     return [
///         RememberedToken(cache: cache, credential: BearerKey.init),
///         DeviceSignIn(remembering: cache, credential: BearerKey.init, flow),
///     ]
/// }
/// ```
///
/// Signing out is the app's call: `try await cache.clear()`.
///
/// A cache that can't be loaded, such as a token file others can read, stops the sign-in: the
/// person sees "Sign-in failed.", the reason goes to the log, and nothing later is tried, since
/// replacing a token that may be exposed would hide that it is.
public struct RememberedToken: CredentialSource, OutcomeObservingSource {
    #if canImport(os)
    private static let logger = Logger(subsystem: "com.swiftclikitauth", category: "RememberedToken")
    #endif

    private let cache: any TokenCache
    private let credential: @Sendable (String) -> any Credential

    /// Creates the source.
    /// - Parameters:
    ///   - cache: Where the token was remembered.
    ///   - credential: Makes the credential SwiftIdentity resolves from the token: the same one
    ///     the remembering ``DeviceSignIn`` uses.
    public init(cache: any TokenCache, credential: @escaping @Sendable (String) -> any Credential) {
        self.cache = cache
        self.credential = credential
    }

    /// It asks nothing of the person.
    public var requirements: SourceRequirements { [] }

    /// The remembered token, as a credential.
    /// - Parameter context: Unused: the token comes from the cache.
    /// - Returns: One credential, or `nil` when nothing is remembered.
    /// - Throws: ``SignInError/failed`` when the cache can't be loaded.
    public func credentials(_ context: SignInContext) async throws -> [any Credential]? {
        try await gather(context)?.credentials
    }

    /// The remembered token, forgotten unless it signs the person in.
    func gather(_ context: SignInContext) async throws -> ObservedCredentials? {
        let token: String?
        do {
            token = try await cache.load()
        } catch {
            #if canImport(os)
            Self.logger.error("the remembered sign-in couldn't be loaded: \(String(describing: error), privacy: .private)")
            #endif
            throw SignInError.failed
        }
        guard let token else { return nil }
        let cache = self.cache
        return ObservedCredentials(credentials: [credential(token)]) { outcome in
            guard outcome != .admitted else { return }
            await Self.forget(cache)
        }
    }

    /// Forgets a token that no longer signs the person in.
    private static func forget(_ cache: any TokenCache) async {
        do {
            try await cache.clear()
        } catch {
            // The token is refused either way; it is only left on disk.
            #if canImport(os)
            logger.error("couldn't forget a remembered sign-in: \(String(describing: error), privacy: .private)")
            #endif
        }
    }
}

/// Several sources whose credentials are presented together, so SwiftIdentity authenticates them
/// as one: a password and a one-time code, say, for multi-factor.
///
/// Sources run in order. The subject the first names is handed to the rest, so the person is
/// asked for a username once. If any source doesn't apply, neither does this; if any throws, the
/// rest are never run.
public struct Together: CredentialSource {
    private let sources: [any CredentialSource]

    /// Creates the combination.
    /// - Parameter sources: The sources, in the order they run.
    public init(_ sources: any CredentialSource...) {
        self.sources = sources
    }

    /// Everything its sources need.
    public var requirements: SourceRequirements {
        sources.reduce(into: []) { $0.formUnion($1.requirements) }
    }

    /// Runs each source in order.
    /// - Parameter context: Where it runs.
    /// - Returns: Every source's credentials, or `nil` if any source doesn't apply.
    /// - Throws: The first error a source throws.
    public func credentials(_ context: SignInContext) async throws -> [any Credential]? {
        var gathered: [any Credential] = []
        var subjectID = context.subjectID
        for source in sources {
            let next = SignInContext(presenter: context.presenter, subjectID: subjectID)
            guard let credentials = try await source.credentials(next) else { return nil }
            gathered += credentials
            subjectID = subjectID ?? credentials.lazy.compactMap(SubjectPrompt.namedSubject).first
        }
        return gathered
    }
}

/// Who a credential source signs in.
enum SubjectPrompt {
    /// The subject already named, the hint, or what the person types.
    static func subjectID(_ context: SignInContext, hint: String?) async throws -> String {
        if let named = context.subjectID ?? hint { return named }
        return try await context.presenter.readText("Username")
    }

    /// The subject a credential names, for a credential that names one.
    static func namedSubject(_ credential: any Credential) -> String? {
        switch credential {
        case let passphrase as Passphrase: passphrase.subjectID
        case let code as OneTimeCode: code.subjectID
        default: nil
        }
    }
}
