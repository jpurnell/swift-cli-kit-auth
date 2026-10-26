# Account Sign-In Guide

swift-cli-kit-auth signs people in to SwiftCLIKit apps, from a local terminal or over SSH, on
[SwiftIdentity](https://github.com/jpurnell/swift-identity). It covers command-line
sign-in (experience A), SSH apps with accounts and remembered keys (experience B, from 0.2), and
passwords done to standard (experience C).

## What lives where

| Concern | Where | Why |
|---|---|---|
| Who someone is; how strongly that was proven | SwiftIdentity's `Authenticator` | Its core. Assurance is computed, never declared. |
| Refusal reasons | SwiftIdentity's audit, only | A guesser learns nothing from the screen. |
| Asking for credentials, showing prompts | `CredentialSource`s through a `SignInPresenter` | The same source works in a terminal, over SSH, and in a test. |
| Whether the app admits someone | `Admission` | Entitlement is the app's. |
| How long a session lasts; revocation mid-session | `AccessLease` | A long SSH session has no "next verification" of its own. |
| Running an OAuth device flow | **Your app**, with swift-oauth | So this package never makes your app download an OAuth library it doesn't use. |

## Experience A: `mytool login`

```swift
import SwiftCLIKit
import SwiftCLIKitAuth
import SwiftIdentity

let people = try FileCredentialStore(directory: identityDirectory)
let sessions = SessionStore(subjects: { id in people.subject(id: id) })
var generator = SystemRandomNumberGenerator()

let lease = try await CLISignIn.signIn(
    sources: [Together(PromptedPassword(), PromptedCode())],
    authenticator: Authenticator(stores: [people], audit: audit, now: { Date() }),
    admission: .minimumAssurance(.multiFactor),
    presenter: TerminalPresenter(backend: RealBackend()),
    sessions: sessions,
    lifetime: 8 * 3600,
    reresolveEvery: .seconds(300),
    generator: &generator
)
```

`CLISignIn.signIn` tries the sources in order:

- **A source that doesn't apply, or whose credentials don't resolve, passes to the next.** In
  0.2 this is how an unrecognised SSH key falls through to a device sign-in.
- **A source that throws stops the sign-in.** No later source is asked. A cancellation (Ctrl-C or
  Escape) is rethrown as `SignInError.cancelled`; anything else fails the sign-in.
- **A subject who resolves but isn't admitted fails at once.**
- Every failure shows "Sign-in failed." and nothing more.

### Passwords

`PromptedPassword` reads the password with SwiftCLIKit's `SecureField`: masked, pasted whole (the
route a password manager uses), revealed with F2, any Unicode. It passes the password on exactly
as entered; SwiftIdentity canonicalises it as NIST SP 800-63B-4 requires.

### Two factors

SwiftIdentity computes assurance from the credentials presented **together**, so a password and
a one-time code are gathered by one source:

```swift
Together(PromptedPassword(), PromptedCode())   // asks Username once, then Password, then the code
```

Asking for a code after a password has already been verified on its own doesn't raise the
assurance of that first authentication. To raise it later, use `AccessLease.reverify`.

### Device sign-in (OAuth, RFC 8628)

Your app runs the flow; `DeviceSignIn` shows the code and URL through the presenter. With
swift-oauth's `DeviceAuthorizationClient` and `SwiftOAuthIdentity`:

```swift
import SwiftOAuthClient
import SwiftOAuthIdentity

let device = DeviceSignIn { present in
    let tokens = try await client.signIn { authorization in
        try await present(DevicePrompt(
            userCode: authorization.userCode,
            verificationURI: authorization.verificationURI,
            verificationURIComplete: authorization.verificationURIComplete
        ))
    }
    return OAuthAccessToken(tokens.accessToken)
}
```

Put an `OAuthIdentityStore` in the `Authenticator`'s stores so the token resolves to a local
subject. A flow that fails for any reason the person didn't choose (denied, expired, a network
error) fails the sign-in without saying which.

### Staying signed in between runs

After `mytool login`, later runs can be signed in without asking, as `gh` and the AWS CLI are.
Only a token from a device sign-in is ever remembered: never a password or a one-time code, which
prove something only when the person presents them.

```swift
let cache = FileTokenCache(url: home.appendingPathComponent(".config/mytool/token"))

let sources: [any CredentialSource] = [
    RememberedToken(cache: cache, credential: OAuthAccessToken.init),
    DeviceSignIn(remembering: cache, credential: OAuthAccessToken.init) { present in
        try await client.signIn { authorization in
            try await present(DevicePrompt(
                userCode: authorization.userCode,
                verificationURI: authorization.verificationURI,
                verificationURIComplete: authorization.verificationURIComplete
            ))
        }.accessToken
    },
]
```

- **A remembered token that still resolves signs the person in with no prompt.** One that
  doesn't (it expired, was revoked at the identity provider, or its subject was revoked here) is
  forgotten, and the device sign-in runs.
- **A new token is saved only once its subject is admitted.** Not when it doesn't resolve, nor
  when your app turns the person away. A save that fails is logged and the sign-in stands.
- **Your app chooses where the token lives.** `FileTokenCache` has no default path. It writes the
  file 0600 (a new file renamed into place), creates a missing directory 0700, and refuses a
  directory others can write and a symlink at the path.
- **A token file others can read is refused, not repaired.** The sign-in fails, the path goes to
  the log, and the person deletes the file: the token in it may already be exposed, and quietly
  replacing it would hide that.
- **Signing out** is `try await cache.clear()`, plus `await lease.end()` for the current run.
- **Refresh stays in your app.** An access token lasts about an hour. To stay signed in longer,
  return a refresh token from the flow and exchange it inside `credential`; this package stores
  whatever string the flow returns and doesn't model OAuth's tokens.
- Outcomes reach a source only through the sign-in loop: nested inside `Together`, or asked for a
  step-up by `AccessLease.reverify`, a remembering source presents its token and saves or clears
  nothing.

## Experience C over SSH: the password at connect

`ConnectionPassword` is an `SSHClientVerifier`, so the password is checked during SSH
authentication and a wrong one never gets a session:

```swift
import SwiftCLIKitAuth
import SwiftCLIKitAuthSSH
import SwiftCLIKitSSH

let server = SSHServer(
    host: "0.0.0.0",
    port: 2222,
    hostKeySource: .filePath("/etc/myapp/ssh_host_ed25519_key"),
    configuration: SSHConfiguration(authMode: .verifier(
        ConnectionPassword(authenticator: authenticator, admission: .attribute("team", equals: "ops"))
    ))
)
try await server.start { backend, session in
    guard let who = session.authentication else { return }
    try await MyApp(subject: who.subject).run(on: backend)
}
```

**SSH here is not post-quantum.** A session recorded today, password included, could be
decrypted by a future quantum computer. See SwiftCLIKit's README; if that matters, put the app
behind OpenSSH or TLS.

## Experience B: SSH apps with accounts

`ssh dash.example.com` asks the person to visit a URL and enter a code. After approval their
key is remembered, and the next connection goes straight in.

```swift
let keys = try SSHKeyStore(url: keysURL, subjects: { id in people.subject(id: id) })
let gate = SignInGate(
    sources: [ConnectionKey(), device],              // device: a DeviceSignIn, as above
    authenticator: Authenticator(stores: [keys, corp, people], audit: audit, now: { Date() }),
    admission: .attribute("team", equals: "ops"),
    keys: keys,
    rememberFor: .seconds(30 * 24 * 3600),           // no default: your security decision
    sessions: sessions, sessionLifetime: 8 * 3600, reresolveEvery: .seconds(300),
    generator: { SystemRandomNumberGenerator() }
)
try await SSHServer(host: "0.0.0.0", hostKeySource: .filePath(hostKeyPath),
                    configuration: SSHConfiguration(authMode: .publicKey))
    .start(sessionHandler: gate.wrap { backend, session, lease in
        try await DashboardApp(lease: lease).run(on: backend)
    })
```

1. **`ConnectionKey` offers the key.** If `keys` remembers it, the app runs with no prompt.
2. **Otherwise the device sign-in runs.** The token resolves to the same local subject through
   SwiftIdentity's external-identity mapping.
3. **The key is bound** to that subject until `rememberFor` runs out.
4. **The app runs with a lease.** When the lease ends (revoked, or expired), the app is
   cancelled.

`SSHKeyStore` passes SwiftIdentity's `ConformanceSuite`. It reads each subject's status on every
resolution, so revoking someone stops their keys at once. A key bound to a honeypot subject is a
tripwire: it is refused, and audited as a honeypot.

## The lease

`AccessLease` is what an admitted session holds:

- It **never keeps the credentials.** It mints a token in your `SessionStore` and re-resolves
  that every `reresolveEvery`. The store reads the subject's status each time, so revoking the
  subject, or `sessions.revokeAll(forSubject:)`, ends the lease within one interval.
- `ended` yields once: `.signedOut`, `.revoked` or `.expired`.
- `reverify(minimum:maximumAge:)` steps up before something sensitive: it returns the current
  authentication if it's strong and recent enough, otherwise runs the sources again and accepts
  only the same subject at the required assurance.
- Revocation **at an identity provider** is seen at the next sign-in, not mid-session: the lease
  asks your local roster, not the IdP, so the IdP isn't called every few minutes.

## Not yet

- **A Keychain-backed `TokenCache`.** `FileTokenCache` is the only one so far; a Keychain cache
  is a later conformance with no API change.
- **A QR code** for the device URL.
