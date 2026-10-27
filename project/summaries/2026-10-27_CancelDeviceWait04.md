# 2026-10-27 — 0.4.0: cancelling a device sign-in while it waits

- **Shipped:** `SignInPresenter.watchForCancel()` (default: never reports a cancellation);
  `TerminalPresenter` ends the wait on Ctrl-C or Escape, and on end of input. `DeviceSignIn` races
  its flow against the watch in a task group: whichever ends first cancels the other, so approval
  never leaves a watch holding the app's next key. A flow's `CancellationError` is now
  `SignInError.cancelled`.
- **Upstream first:** SwiftCLIKit 2.4.0 (`SSHServer.listen`, `ANSICodes.eraseLine`) and 2.5.0
  (a local terminal's `nextKey()` that can be cancelled, and a lone Escape after 50 ms). Without
  2.5.0 the watch blocked a thread in `read(2)` after approval.
- **Tests:** 137 (5 new in `DeviceWaitTests`); quality gate 0/0.
- **Found:** a commit can pass the gate on cached test results while missing a file
  (`TerminalPresenter.swift` was left out of the first 0.4 commit); amended before pushing.
- **Next:** a Keychain `TokenCache`; the proposal §14 list.
