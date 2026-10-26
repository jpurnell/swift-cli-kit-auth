# 2026-10-26 — 0.2 merged; 0.3 remembered sign-in built

## Done
- 0.2 (experience B) merged as PR #1 and released as 0.2.0 (tag pushed atomically with its release commit, as the release-readiness check requires); CI green.
- Remembered sign-in proposal approved: tokens only; refresh in the app's closure; the app
  places the file.
- 0.3 built TDD on `feature/0.3-remembered-sign-in`: `TokenCache`, `FileTokenCache`,
  `RememberedToken`, `DeviceSignIn(remembering:credential:_:)`, and an internal outcome hook in
  `SignInRun`. 132 tests; three planted mutants caught; gate 0/0.

## Decided (proposal §17)
- Any load error stops the sign-in (§6 had said "treated as empty"): an exposed token file must
  not be quietly replaced.
- Outcomes are reported only by the sign-in loop, not inside `Together` or on step-up.
- A directory others can write is refused; one they can read is allowed. Files over 64 KiB refused.

## Fixed along the way
- The master plan still showed 0.2 unticked; reconciled.
- Gate: a `catch CocoaError.fileReadNoSuchFile` that neither logged nor rethrew → `lstat`/`ENOENT`.

## Next
- User: merge the 0.3 PR (#2). Then a release: 0.3.0 commit on `main`, pushed atomically with the v0.3.0 tag; the user chose separate releases.
