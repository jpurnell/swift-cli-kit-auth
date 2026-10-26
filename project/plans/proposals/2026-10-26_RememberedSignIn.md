# Design Proposal: Remembered command-line sign-in

**Date:** 2026-10-26
**Status:** Approved 2026-10-26 — all three open questions answered as proposed (§16)
**Author:** Claude (session with Justin Purnell)
**Parent:** SwiftCLIKit `project/plans/proposals/2026-10-20_SwiftCLIKitAuth.md`, experience A
("later runs are signed in"), deferred from 0.1 (rev 9 scope note).

## 1. Objective

After `mytool login`, later runs of `mytool` are signed in without asking, until the remembered
credential stops resolving, and `mytool logout` forgets it. As `gh auth login` and
`aws sso login` do.

## 2. Motivation

0.1 signs in once per process. `AccessLease` holds a `SessionStore` token, and `SessionStore` is
in memory by design (SwiftIdentity: "sessions do not survive a restart"). So nothing survives
between runs, and every command asks again.

## 3. Proposed Architecture

**Only a bearer credential from a device sign-in is ever remembered.** Never a password and
never a one-time code: those prove something only when the person presents them. An OAuth
access token is already designed to be held by the client between uses, which is what RFC 8628
issues it for.

```
mytool login:   DeviceSignIn ──token──▶ Authenticator ──▶ Admission ──▶ lease
                       └── saves the token string ──▶ TokenCache (0600 file / Keychain later)

mytool deploy:  RememberedToken ◀── TokenCache
                       │ resolves? ── yes ──▶ lease, no prompt
                       └── no ──▶ the cache is cleared; CLISignIn falls through to the next source
```

This uses 0.1's fall-through rule unchanged: a source whose credentials don't resolve passes to
the next. The person sees a prompt only when the remembered token has stopped working, because
it expired, was revoked at the IdP, or its subject was revoked locally.

## 4. API Surface

```swift
/// Where a remembered token lives between runs.
public protocol TokenCache: Sendable {
    func load() async throws -> String?
    func save(_ token: String) async throws
    func clear() async throws
}

/// An owner-only file: written 0600 in a 0700 directory, refused (startup-fatal, as
/// SwiftIdentity's key files are) if anyone but the owner can read it.
public struct FileTokenCache: TokenCache { public init(url: URL) }

/// Presents the remembered token, if there is one; clears it if it doesn't resolve.
public struct RememberedToken: CredentialSource {
    public init(cache: any TokenCache, credential: @escaping @Sendable (String) -> any Credential)
}

extension DeviceSignIn {
    /// The same flow, saving the token it returns once the sign-in is admitted.
    public init(remembering cache: any TokenCache,
                _ flow: @escaping @Sendable (_ present: …) async throws -> String,
                credential: @escaping @Sendable (String) -> any Credential)
}
```

The usage is a source list:

```swift
sources: [RememberedToken(cache: cache, credential: OAuthAccessToken.init),
          DeviceSignIn(remembering: cache, flow, credential: OAuthAccessToken.init)]
```

`CLISignIn` needs one change. A source can learn whether its credentials were admitted, so it
saves only an admitted token, and `RememberedToken` clears a token that didn't resolve. The
hook is internal (`CredentialSource` stays as it is), via an optional
`SignInOutcomeObserving` protocol.

## 5. MCP Schema

N/A.

## 6. Constraints & Compliance

- **At rest.** The token is a bearer secret.
  - **File:** written 0600 in a 0700 directory, never logged. A file someone else can read is
    refused, not repaired.
  - **Keychain:** a Keychain-backed cache on Apple platforms is the better home (proposal §14).
    It's a later `TokenCache`, with no API change.
- **NIST SP 800-63B-4.** A remembered token is a session secret, not an authenticator.
  Reauthentication follows the IdP's token lifetime. The app can force it by clearing the
  cache, which is what `logout` does.
- **Fail closed.** A cache that can't be read is treated as empty. The person is asked again,
  and the error never reaches them as a reason.

## 7. Source & API Compatibility

Additive: new types and a new `DeviceSignIn` initializer.

## 10. Dependencies

None new.

## 11. Test Strategy

- **The cache:** file mode refusal (0644 is refused); round-trip; `clear` removes the file.
- **The sign-in:**
  - a remembered token that resolves signs in with no prompt;
  - one that doesn't is cleared, and the device sign-in runs;
  - a device sign-in that resolves but isn't admitted saves nothing;
  - a password never reaches a cache (no API for it; asserted by the types).

## 13. Adversarial Review

- **"A token on disk is worse than asking every time."** Sometimes. That's why it's opt-in, and
  only for device-issued bearer tokens. Today the alternative people use is a token pasted into
  an environment variable, which is worse.
- **Where this is most likely wrong:** refresh tokens. An access token lasts about an hour, so
  without refresh the "remembered" sign-in lapses hourly. Proposed: the cache stores whatever
  string the app's flow returns, so an app can store a refresh token and exchange it inside its
  `credential` closure. That puts refresh logic in the app, which it already owns (it runs the
  flow). Should this package instead model access and refresh tokens explicitly?

## 16. Open Questions

1. ~~Approve "device-issued bearer tokens only, never passwords or codes"?~~ **Yes** — "only
   remember tokens, that's safer."
2. ~~Refresh: leave it in the app's closure (proposed), or model it here?~~ **In the app's
   closure** — "that's cleaner."
3. ~~Default location: `~/.config/<app>/token`, left for the app to choose (proposed), or
   chosen here?~~ **The app chooses.** `FileTokenCache(url:)` has no default.

## 17. Decided while building

- **The outcome hook.** A source learns how its credentials fared through an internal
  `OutcomeObservingSource` protocol whose `gather` returns the credentials with a callback
  carrying the outcome (`unresolved`, `notAdmitted`, `admitted`), so the token string a
  `DeviceSignIn` produced stays with that one run instead of being stored on a shared value.
  `SignInRun` calls it; `CredentialSource` is unchanged.
- **Not inside `Together`, not on step-up.** A remembering source nested in `Together`, or asked by
  `AccessLease.reverify`, presents its credentials but saves and clears nothing: the hook is
  called only by the sign-in loop.
- **A cache readable by others is refused, not treated as empty.** §6 said a cache that can't be
  read is empty. That holds for a file that can't be opened; but a token file others can read may
  already be exposed, and quietly replacing it would hide that. So `load` and `save` throw
  `readableByOthers`, the sign-in fails ("Sign-in failed." to the person, the path to the log),
  and the person fixes or deletes the file.
- **The directory.** Created 0700 if missing. An existing directory others can *write* is refused
  (another user could swap the file between write and rename); one others can merely read is
  allowed, since the file itself is 0600. A symlink at the token path is refused.
