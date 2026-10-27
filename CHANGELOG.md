# Changelog

All notable changes to swift-cli-kit-auth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Cancelling a device sign-in while it waits.** Ctrl-C or Escape while a `DeviceSignIn` polls
  for approval cancels the sign-in and the flow's task; input ending ends it. When approval comes
  first, the watch stops without taking the app's next key.
  - `SignInPresenter.watchForCancel()`, with a default that never reports a cancellation, so
    existing presenters compile unchanged. `TerminalPresenter` watches for Ctrl-C and Escape.
  - A flow that throws `CancellationError` now ends the sign-in as `SignInError.cancelled`
    rather than `.failed`.

### Changed

- Requires swift-cli-kit 2.5.0, whose local-terminal `nextKey()` can be cancelled; before it, the
  watch would have held a local sign-in open after approval until a key was pressed.
- `TerminalPresenter` uses swift-cli-kit's `ANSICodes.eraseLine` in place of its own.
- The SSH over-the-wire tests use swift-cli-kit 2.4.0's public `SSHServer.listen`, and no longer
  import SwiftCLIKitSSH with `@testable`.

## [0.3.0] - 2026-10-26

### Added

- Staying signed in between command-line runs (design:
  `project/plans/proposals/2026-10-26_RememberedSignIn.md`).
  - `TokenCache`, and `FileTokenCache`: a token in an owner-only file the app places. Written 0600
    and renamed into place; a missing directory is created 0700. A file others can read, a
    symlink, a directory others can write, and a file larger than any token are refused.
  - `RememberedToken`: presents the remembered token, and forgets it when it no longer signs the
    person in. A cache that can't be loaded stops the sign-in.
  - `DeviceSignIn(remembering:credential:_:)`: saves the flow's token once its subject is
    admitted, and never otherwise. Only device sign-in tokens are remembered; refresh stays in the
    app's `credential` closure.

## [0.2.0] - 2026-10-26

### Added

- `SSHPublicKeyCredential`: an SSH public key the client proved it holds, from a connection's
  `SSHClientIdentity` (a plain key only, never a certificate) or an OpenSSH line. Its
  `fingerprint` is the one `ssh-keygen -l -E sha256` prints, checked against OpenSSH's own output
  for Ed25519 and ECDSA keys.
- `SSHKeyStore`: remembered keys, a `CredentialStore` that **passes SwiftIdentity's
  `ConformanceSuite` unchanged**, claiming revocation, honeypot, expiry and algorithm records.
  - Each subject's status is read from the roster on every resolution, so revoking a subject
    stops their keys at once, and a key bound to a honeypot subject is a tripwire.
  - It reports the key type it recorded when the key was bound, never the connection's claim.
  - The file is owner-only; a shared file or a malformed line stops it at startup. Writes are
    atomic and never readable by others, even mid-write.
- `ConnectionKey`: the connection's key as a credential source.
- `SignInGate.wrap`, experience B.
  - A password verified at connect is the sign-in.
  - Otherwise the sources run in order, so an unremembered key falls through to a device sign-in.
  - A key used with another credential is then remembered for `rememberFor`.
  - The app runs with a lease, and is cancelled when the lease ends.

## [0.1.0] - 2026-10-25

First release: command-line sign-in (experience A) and passwords done to standard, at the
terminal or at SSH connect (experience C). Remembered SSH keys and the SSH sign-in gate are 0.2.

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
