# swift-cli-kit-auth 0.3 — remembered command-line sign-in

**Design:** `project/plans/proposals/2026-10-26_RememberedSignIn.md`, approved 2026-10-26
(tokens only; refresh in the app's closure; the app chooses the location). Decisions made while
building are its §17.

## Phases
- [x] `FileTokenCache`: round-trip; missing file is nil; empty file is nil; `clear` removes it and
      is a no-op when absent; written 0600; a file others can read is refused on load and save; a
      symlink is refused; a file over 64 KiB is refused; the directory is created 0700; a directory others can write is refused.
- [x] Outcome hook in `SignInRun`: `unresolved`, `notAdmitted`, `admitted`, each delivered once to
      the source whose credentials were tried.
- [x] `RememberedToken`: no cached token → doesn't apply; a token that resolves signs in with no
      prompt; one that doesn't resolve is cleared and the next source runs; one not admitted is
      cleared; a cache that can't be loaded stops the sign-in (§17).
- [x] `DeviceSignIn(remembering:)`: an admitted token is saved; a token not admitted is not; a
      token that doesn't resolve is not; a save that fails leaves the sign-in standing.
- [ ] Docs: guide section, README, CHANGELOG, master plan; gate 0/0, CI green.
