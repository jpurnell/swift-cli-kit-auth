# swift-cli-kit-auth

Account sign-in for [SwiftCLIKit](https://github.com/jpurnell/swift-cli-kit) apps, on
[SwiftIdentity](https://github.com/jpurnell/swift-identity).

**Status: 0.2.0.** Command-line sign-in (a password, a one-time code, or an OAuth device
sign-in), SSH password sign-in, and SSH apps with accounts: remembered SSH keys and an SSH
sign-in gate. Unreleased: staying signed in
between command-line runs (0.3).

```swift
dependencies: [
    .package(url: "https://github.com/jpurnell/swift-cli-kit-auth.git", from: "0.2.0"),
]
```

## What it does

- **SwiftIdentity decides who someone is** and how strongly that was proven. This package
  gathers the credentials, asks your app whether it admits them, and holds the session.
- **A refusal never says why.** Every refusal reads "Sign-in failed"; the reason goes to
  SwiftIdentity's audit trail only.
- **It depends on swift-cli-kit and swift-identity only.** A sign-in method's own package, such
  as swift-oauth for device sign-in, is your app's dependency, never this one's.

## What 0.1 includes

- `CLISignIn.signIn` with `PromptedPassword`, `PromptedCode`, `DeviceSignIn` (your app runs the
  OAuth flow) and `Together` for two factors; `TerminalPresenter` draws over any SwiftCLIKit
  `TerminalBackend`, local or SSH.
- `ConnectionPassword`: an SSH password checked during SSH authentication, so a wrong one never
  gets a session.
- `Admission` rules and `AccessLease`, which re-checks a session token, never the credentials,
  so a revoked subject is signed out within one interval.

## What 0.2 adds

- `SSHKeyStore` and `SignInGate`: an SSH key used once alongside another sign-in is remembered,
  so the next connection goes straight in. Revoking the person stops their keys at once.

## Since 0.2 (unreleased)

- `RememberedToken`, `DeviceSignIn(remembering:)` and `FileTokenCache`: after `mytool login`, later
  runs are signed in until the token stops resolving. Only device sign-in tokens are remembered.

See **[AccountSignInGuide.md](AccountSignInGuide.md)**.

## Requirements

- Swift 6.2+
- macOS 14+, iOS 17+ or visionOS 1+, or Linux

## License

Proprietary. Copyright (c) 2026 Justin Purnell. All rights reserved. See [LICENSE](LICENSE).
