# swift-cli-kit-auth Master Plan

**Purpose:** Source of truth for project vision, architecture, and goals.

---

## Project Overview

### Mission
Account sign-in for SwiftCLIKit apps, on SwiftIdentity: establish **who** someone is (a SwiftIdentity
`Subject`), **how strongly** that was proven, and **whether the app admits them**, from a local
terminal or over SSH. Apps that don't need accounts pay nothing; apps that do add only the packages
for the methods they use.

**Design:** `SwiftCLIKit/project/plans/proposals/2026-10-20_SwiftCLIKitAuth.md`, approved
2026-10-24 (rev 7), with revs 8 and 9 decided by the user. That proposal is the authority; this
plan tracks delivery.

### Target Users
- Authors of command-line tools that call an account-bound service (`mytool login`, experience A).
- Authors of SSH apps that need accounts (experiences B and C), built on `SwiftCLIKitSSH`.

### Key Differentiators
- **It decides nothing about identity.** Verifying who someone is stays in SwiftIdentity's
  `Authenticator`; this package gathers credentials, shows prompts, admits, and holds the session.
- **Refusals stay private.** It consumes `Authenticator.authentication(for:)`, the statically
  dispatched form, so no layer here can print a reason. Every refusal reads "Sign-in failed".
- **No method's package is a dependency.** Device sign-in takes the app's closure, so swift-oauth is
  the app's dependency, not ours (rev 9).

---

## Architecture

### Technology Stack
- **Language:** Swift 6.2+
- **Build System:** Swift Package Manager
- **Testing:** Swift Testing framework
- **Concurrency:** Swift 6 strict concurrency throughout
- **Dependencies:** `swift-cli-kit` ≥ 2.3.0 (`SwiftCLIKit`, `SwiftCLIKitSSH`), `swift-identity`
  ≥ 0.7.1. No other library dependency, by design. The SSH tests also name swift-nio and
  swift-nio-ssh, already resolved through swift-cli-kit, to drive a real NIOSSH client.

### Module Structure

```
Sources/SwiftCLIKitAuth/      presenting, credential sources, admission, the lease, CLI sign-in
Sources/SwiftCLIKitAuthSSH/   ConnectionPassword (0.1); SignInGate, SSHKeyStore (0.2)
```

### Key Types

| Type | Purpose |
|------|---------|
| `SignInPresenter` / `TerminalPresenter` | How a sign-in talks to the person; the terminal one draws over any `TerminalBackend`, reading keys with `nextKey()` |
| `CredentialSource` | One way to obtain credentials: `PromptedPassword`, `PromptedCode`, `DeviceSignIn`, `Together` |
| `Admission` | Who the app admits: subjects, attributes, minimum assurance, factor algorithms, custom |
| `AccessLease` | An admitted session's lifetime: re-resolves a `SessionStore` token on an interval; step-up via `reverify` |
| `CLISignIn` | Experience A: run sources, authenticate, admit, and return a lease |
| `SSHKeyStore` / `ConnectionKey` / `SignInGate` | Experience B: remembered SSH keys, and the gate that signs each SSH connection in |
| `ConnectionPassword` | An `SSHClientVerifier`: the SSH password, resolved through the `Authenticator` and admitted, attached as the session's `Authentication` |

### Data Flow

```
CredentialSource(s) ──credentials──▶ Authenticator (SwiftIdentity) ──Authentication?──▶ Admission
        ▲ prompts                                                                       │ admitted
SignInPresenter ◀────────────────────── "Sign-in failed" ◀──── refused ─────────────────┤
                                                                                        ▼
                                           SessionStore.mint ──token──▶ AccessLease (re-resolves)
```

---

## Core Architectural Decisions

1. **A companion package, not a SwiftCLIKit product** (proposal ADR 1): SwiftCLIKit exposes seams
   and never takes the dependency.
2. **Built on SwiftIdentity; defines no identity** (proposal ADR 2).
3. **Fail closed:** a source that throws stops the attempt and never falls through to the next;
   a lease whose re-resolution fails ends the session.
4. **The lease re-resolves a session token, never the credentials** (rev 9): no secret is kept,
   no KDF re-runs; revocation at an IdP takes effect at the next sign-in.
5. **Device sign-in takes a closure** (rev 9), so this package never depends on swift-oauth.

---

## Current Status

### What's Working
- [x] Repository scaffolded from development-guidelines v2.5.0 (2026-10-25).
- [x] Prerequisites shipped: SwiftCLIKit 2.2.0 (identity seam, `AuthMode.verifier`), 2.3.0 (SSH
      key input); SwiftIdentity 0.7.1; swift-oauth 1.0.0-beta.9 (device grant, `SwiftOAuthIdentity`).

### What's Next
- [x] 0.1.0 released 2026-10-25: public repository `jpurnell/swift-cli-kit-auth`, proprietary licence (the user's decisions), CI green.
- [x] 0.2.0 released 2026-10-26 (PR #1), CI on `main` green.
- [ ] 0.3: staying signed in between runs (see Roadmap).

---

## Quality Standards

### Code Quality
- All code follows `coding_rules.md`
- TDD: failing tests before implementation
- Documentation for all public APIs
- No warnings in build output
- Quality gate: 0 errors, 0 warnings before every commit

### Documentation Quality
- DocC comments for all public functions
- Usage examples in documentation
- Articles for complex topics

---

## Collaboration Principles

### AI as Sparring Partner, Not Oracle

AI proposes; the human interrogates. High AI confidence triggers harder questions, not faster acceptance.

- **Interrogate confident outputs.** When the AI states something with certainty, ask for the counterargument before accepting.
- **Demand counterarguments.** Before locking in an approach, require an explicit case for the strongest alternative.
- **Sit with discomfort.** Resist the pull to take the first plausible answer.

This principle is operationalized in the **Adversarial Review** step of `design_proposal.md`.

---

## Roadmap

### 0.1: experiences A and C (released as 0.1.0, 2026-10-25)
- [x] `TerminalPresenter`, `PromptedPassword`, `PromptedCode`, `DeviceSignIn`, `Together`
- [x] `Admission`, `AccessLease`, `CLISignIn`
- [x] `ConnectionPassword` (SSH password at connect, through `AuthMode.verifier`)
- [x] `AccountSignInGuide.md`

### 0.2: experience B (released as 0.2.0, 2026-10-26)
- [x] `SSHPublicKeyCredential`, `SSHKeyStore` (passes SwiftIdentity's `ConformanceSuite`), `ConnectionKey`
- [x] `SignInGate`

### Future
- Proposal §14: SSH certificates (blocked upstream), biometric unlock, a SwiftUI presenter,
  authorization-code + loopback for desktop CLIs, Keychain-backed stores.

---

**Last Updated:** 2026-10-26 (0.2.0 released: its roadmap items ticked, which the 0.2 PR left open, and its types added to Key Types. Before that: 0.1.0 released 2026-10-25 after its first green CI run.)
