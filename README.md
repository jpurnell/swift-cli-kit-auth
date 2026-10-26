# swift-cli-kit-auth

Account sign-in for [SwiftCLIKit](https://github.com/jpurnell/swift-cli-kit) apps, on
[SwiftIdentity](https://github.com/jpurnell/swift-identity).

**Status: in development, not yet released.** 0.1 will cover command-line sign-in (a password,
a one-time code, or an OAuth device sign-in) and SSH password sign-in. 0.2 adds remembered SSH
keys.

## What it does

- **SwiftIdentity decides who someone is** and how strongly that was proven. This package
  gathers the credentials, asks your app whether it admits them, and holds the session.
- **A refusal never says why.** Every refusal reads "Sign-in failed"; the reason goes to
  SwiftIdentity's audit trail only.
- **It depends on swift-cli-kit and swift-identity only.** A sign-in method's own package, such
  as swift-oauth for device sign-in, is your app's dependency, never this one's.

## Requirements

- Swift 6.2+
- macOS 14+, iOS 17+ or visionOS 1+, or Linux

## License

Not yet chosen.
