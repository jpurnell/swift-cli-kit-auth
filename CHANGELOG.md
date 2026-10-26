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
- `ConnectionPassword`, an `SSHClientVerifier`: an SSH password becomes a SwiftIdentity
  `Passphrase` for the username, resolved through `Authenticator.authentication(for:)` and then
  the app's `admits` rule. A wrong password, an unknown user or an unadmitted subject gets no
  session; an admitted one's sessions carry the `Authentication`.
