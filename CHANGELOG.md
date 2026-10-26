# Changelog

All notable changes to swift-cli-kit-auth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `TerminalPresenter.readSecret` drops a paste's one trailing line break (`\n`, `\r\n` or
  `\r`): a copied line usually ends in one, and Enter can never type one into a secret. Line
  breaks inside a paste, and anything typed, are kept.
- Licence: proprietary (`LICENSE`).
- `CLISignIn.signIn`: runs sources in order. One that doesn't apply, or whose credentials don't
  resolve, passes to the next; one that throws stops the sign-in; a resolved subject the app
  doesn't admit fails at once. Every failure shows "Sign-in failed" and nothing more. The lease
  it returns can step up through the same sources.
- The package: `SwiftCLIKitAuth` and `SwiftCLIKitAuthSSH`, on swift-cli-kit 2.3.0 and
  swift-identity 0.7.1.
- `SignInPresenter`, `SignInPrompt` and `SignInError`; `CredentialSource`, `SignInContext` and
  `SourceRequirements`; `SSHSession.authentication`.
- Credential sources: `PromptedPassword` (passed on untrimmed; SwiftIdentity canonicalises),
  `PromptedCode` (spaces removed), `DeviceSignIn` (the app's closure runs the flow, so this
  package never depends on an OAuth library; any failure the person didn't choose is `.failed`),
  and `Together`, which presents several sources' credentials as one authentication and names
  the subject once.
- `Admission`: `anyone`, `subjects`, `attribute(_:equals:)`, `minimumAssurance`, `factors` (a
  factor with no recorded algorithm fails), `custom`, and `all` (an empty list admits no one).
- `ConnectionPassword`, an `SSHClientVerifier`: an SSH password becomes a SwiftIdentity
  `Passphrase` for the username, resolved through `Authenticator.authentication(for:)` and then
  the app's `admits` rule. A wrong password, an unknown user or an unadmitted subject gets no
  session; an admitted one's sessions carry the `Authentication`.
- `TerminalPresenter`, a line-oriented `SignInPresenter` over any `TerminalBackend`, SSH
  included: secrets through `SecureField` (masked, pasted whole, F2 to reveal, masked again on
  Enter), Ctrl-C and Escape cancel, end of input ends, CRLF line endings, no alternate screen,
  and control, format and separator characters in anything shown replaced with U+FFFD.
- `AccessLease`, `LeaseEnd` and `StepUp`: an admitted session's lifetime. The lease mints a
  `SessionStore` token and re-resolves it every `reresolveEvery`, so revoking the subject ends it
  within one interval; it never keeps the sign-in credentials. `reverify(minimum:maximumAge:)`
  steps up for the same subject only.
