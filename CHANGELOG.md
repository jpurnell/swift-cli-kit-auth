# Changelog

All notable changes to swift-cli-kit-auth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The package: `SwiftCLIKitAuth` and `SwiftCLIKitAuthSSH`, on swift-cli-kit 2.3.0 and
  swift-identity 0.7.1.
- `SignInPresenter`, `SignInPrompt` and `SignInError`; `CredentialSource`, `SignInContext` and
  `SourceRequirements`; `SSHSession.authentication`.
- `TerminalPresenter`, a line-oriented `SignInPresenter` over any `TerminalBackend`, SSH
  included: secrets through `SecureField` (masked, pasted whole, F2 to reveal, masked again on
  Enter), Ctrl-C and Escape cancel, end of input ends, CRLF line endings, no alternate screen,
  and control, format and separator characters in anything shown replaced with U+FFFD.
