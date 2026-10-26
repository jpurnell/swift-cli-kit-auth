# SSH key fixtures

Public keys copied from SwiftCLIKit's `Tests/SwiftCLIKitSSHTests/Fixtures` (made there with
`ssh-keygen`, 2026-10-20 and 2026-10-24). Test-only keys, used for nothing else.

The `.fingerprint.txt` files are the oracle for `SSHPublicKeyCredential.fingerprint`, written
by OpenSSH itself, not by the code under test:

    ssh-keygen -l -E sha256 -f user_ed25519.pub > user_ed25519.fingerprint.txt

(OpenSSH 10.3p1, 2026-10-26.)

`revoked_ed25519.pub`, `honeypot_ed25519.pub`, `expired_ed25519.pub` (`ssh-keygen -t ed25519`)
and `unknown_ecdsa.pub` (`ssh-keygen -t ecdsa -b 256`) were made here on 2026-10-26 for the
conformance suite's refusals, which need a distinct key each. Their private halves were deleted
at once: only public keys are needed.
