# swift-cli-kit-auth 0.1 — experiences A and C

**Design:** `SwiftCLIKit/project/plans/proposals/2026-10-20_SwiftCLIKitAuth.md` §4.3–4.4, rev 9.
Started 2026-10-25.

## Scope decisions made while planning (to confirm with the user)
- **Signed in per process.** Experience A's "later runs are signed in" needs a credential kept
  between runs, which the approved design doesn't place: `SessionStore` is in memory, and a
  cached bearer credential on disk is its own security decision. Designed in 0.2, next to
  `SSHKeyStore`, which solves the same problem for SSH keys.
- **No QR code yet.** The device prompt shows the code and URL. A QR encoder of our own (we build
  our own implementations) is a project in itself; tracked for later.
- **`Admission.minimumAssurance` decides, it doesn't challenge.** An app wanting MFA presents
  `Together(PromptedPassword(), PromptedCode())`, because SwiftIdentity computes assurance from
  one set of credentials presented together. Step-up after admission is `AccessLease.reverify`.

## API (0.1)

```swift
public enum SignInError: Error, Sendable, Equatable { case failed, cancelled, inputEnded }

public enum SignInPrompt: Sendable, Equatable {
    case visit(userCode: String, verificationURI: URL, verificationURIComplete: URL?)
    case failed                                   // "Sign-in failed"; never a reason
}
public protocol SignInPresenter: Sendable {
    func show(_ prompt: SignInPrompt) async
    func readText(_ label: String) async throws -> String     // echoed
    func readSecret(_ label: String) async throws -> String   // SecureField: masked, paste, reveal
    func progress(_ message: String) async
}
public struct TerminalPresenter: SignInPresenter { init(backend: any TerminalBackend, revealKey: Key? = .functionKey(2)) }

public struct SignInContext: Sendable { presenter; subjectID: String? }
public struct SourceRequirements: OptionSet, Sendable { interaction, showsURL, readsSecret, network }
public protocol CredentialSource: Sendable {
    var requirements: SourceRequirements { get }
    func credentials(_ context: SignInContext) async throws -> [any Credential]?
}
PromptedPassword(subjectHint:) · PromptedCode(subjectHint:) · DeviceSignIn(_ flow:) · Together(_:)

public struct Admission: Sendable {
    static func subjects(_:), attribute(_:equals:), minimumAssurance(_:), factors(_:), custom(_:), all(_:)
    func admits(_ authentication: Authentication) async -> Bool
}

public actor AccessLease { authentication; ended: AsyncStream<LeaseEnd>; reverify(minimum:maximumAge:); end() }
public enum CLISignIn { static func signIn(...) async throws -> AccessLease }

// SwiftCLIKitAuthSSH
public struct ConnectionPassword: SSHClientVerifier { init(authenticator:admission:) }
extension SSHSession { var authentication: Authentication? }
```

## Phases
- [x] Core types: `SignInError`, `SignInPrompt`, `SignInPresenter`, `SignInContext`,
      `SourceRequirements`, `CredentialSource`.
- [x] `TerminalPresenter` over `TestBackend`: masked secret, paste whole, reveal key, Ctrl-C and
      Escape cancel, end of input, control characters in shown text neutralised, no secret in
      output.
- [x] Sources: `PromptedPassword`, `PromptedCode`, `DeviceSignIn`, `Together` (subject threaded).
- [x] `Admission`, each rule and `all`.
- [x] `AccessLease`: revocation ends it within `reresolveEvery` (injected clock); expiry; `end()`
      revokes the token; `reverify` within `maximumAge` doesn't prompt; step-up to multi-factor
      for the same subject; a different subject fails.
- [x] `CLISignIn`: first source that applies wins; **a source that throws never falls through**;
      refusal shows "Sign-in failed" with the reason in audit only; admission false fails.
- [x] `ConnectionPassword`: wrong password never gets a session; admitted session carries the
      `Authentication`; over the wire. (Takes `admits:` as a closure for now; the `Admission`
      convenience init lands when `Admission` does.)
- [x] Real SwiftIdentity stores as fixtures: `FileCredentialStore` in the lease and SSH tests; a table store (SwiftIdentity's own construction) where a test is about admission, not identity. `ConformanceSuite` applies to `SSHKeyStore` in 0.2.
- [x] Docs: DocC, `AccountSignInGuide.md`, README, CHANGELOG; gate 0/0 locally. CI needs the GitHub repo.
