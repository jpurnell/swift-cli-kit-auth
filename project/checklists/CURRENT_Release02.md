# swift-cli-kit-auth 0.2 — experience B: remembered SSH keys

**Design:** SwiftCLIKit's sign-in proposal §4.2 and §4.4 (approved), rev 6 (algorithm records).
Remembered command-line sign-in is a separate proposal,
`project/plans/proposals/2026-10-26_RememberedSignIn.md`, **awaiting approval**.

## Decided while planning
- **The key file records the key type** (`fingerprint<TAB>type<TAB>subject<TAB>until`). Rev 6
  says the store reports the bound key's type from its own record, and a fingerprint hashes the
  whole key, so its type can't be recovered from it.
- **`ConnectionKey()` finds the connection through a task-local value the gate sets**, because
  `SignInContext` lives in `SwiftCLIKitAuth`, which doesn't depend on SwiftCLIKitSSH.
- **Honeypot keys: claimed after all.** §10 planned `notClaimed`, but the store reads each subject's
  status from the roster on every resolution (as SwiftIdentity's `SessionStore` does), so a key
  bound to a honeypot subject is a tripwire with no extra machinery.

## Phases
- [x] `SSHPublicKeyCredential`: from `SSHClientIdentity` (nil unless key evidence) and from an
      OpenSSH line; `keyType`; `fingerprint` equal to `ssh-keygen -l -E sha256` (fixture oracle).
- [x] `SSHKeyStore`: owner-only file, startup-fatal refusals; `resolve` via the roster (revoked,
      unknown, expired); `resolveVerifying` reports the recorded type; `bind`/`unbind` atomic;
      **passes SwiftIdentity's `ConformanceSuite` unchanged**.
- [x] `ConnectionKey`.
- [x] `SignInGate.wrap`: remembered key admits with no prompt and the device flow is never
      called; unknown key → device flow → bind → admitted; a source that throws never falls
      through; admission false → "Sign-in failed"; the lease ending ends the session.
- [ ] Docs, CHANGELOG, guide; gate 0/0, CI green.
