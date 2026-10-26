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
- `AccessLease`, `LeaseEnd` and `StepUp`: an admitted session's lifetime. The lease mints a
  `SessionStore` token and re-resolves it every `reresolveEvery`, so revoking the subject ends it
  within one interval; it never keeps the sign-in credentials. `reverify(minimum:maximumAge:)`
  steps up for the same subject only.
