// AccessLeaseTests.swift
// SwiftCLIKitAuthTests
// Created by Justin Purnell on 2026-10-25.

import Foundation
import SwiftCLIKitAuth
import SwiftIdentity
import Testing

@Suite("AccessLease")
struct AccessLeaseTests {

    static let interval = Duration.seconds(30)

    /// A lease over ada's single-factor authentication. `sleeps(atLeast: 1)` returns once the
    /// lease's re-resolution loop is asleep, so the first advance can't race it.
    static func lease(
        _ fixture: IdentityFixture,
        clock: ManualClock,
        lifetime: TimeInterval = 3_600,
        stepUp: StepUp? = nil,
        authentication: Authentication? = nil,
        seed: UInt64 = 1
    ) async throws -> AccessLease {
        let admitted: Authentication
        if let authentication {
            admitted = authentication
        } else {
            admitted = try await fixture.authenticate([IdentityFixture.adaPassphrase])
        }
        var generator = SplitMix64(seed: seed)
        let date = fixture.date
        return await AccessLease(
            authentication: admitted, sessions: fixture.sessions, lifetime: lifetime,
            reresolveEvery: interval, stepUp: stepUp, now: { date.instant }, clock: clock,
            generator: &generator
        )
    }

    /// The first value the lease's `ended` stream yields.
    static func firstEnd(_ lease: AccessLease) async -> LeaseEnd? {
        var iterator = lease.ended.makeAsyncIterator()
        return await iterator.next()
    }

    // MARK: - Re-resolution

    @Test("a lease stays active while its subject does, interval after interval")
    func staysActive() async throws {
        let fixture = try IdentityFixture()
        let clock = ManualClock()
        let lease = try await Self.lease(fixture, clock: clock)
        await clock.sleeps(atLeast: 1)
        for round in 2...4 {
            clock.advance(by: Self.interval)
            await clock.sleeps(atLeast: round)
        }
        #expect(await lease.isActive)
    }

    @Test("revoking the subject mid-lease ends it as .revoked within one interval")
    func revocationEndsLease() async throws {
        let fixture = try IdentityFixture()
        let clock = ManualClock()
        let lease = try await Self.lease(fixture, clock: clock)
        await clock.sleeps(atLeast: 1)

        try await fixture.roster.rewriteSubjects("""
            ada    person  revoked
            grace  person  active
            """)
        // Still active until the interval elapses: the lease checks on its interval, not on
        // the roster's change.
        #expect(await lease.isActive)
        clock.advance(by: Self.interval)

        #expect(await Self.firstEnd(lease) == .revoked)
        #expect(await lease.isActive == false)
    }

    @Test("revokeAll(forSubject:) ends the lease as .revoked within one interval")
    func revokeAllEndsLease() async throws {
        let fixture = try IdentityFixture()
        let clock = ManualClock()
        let lease = try await Self.lease(fixture, clock: clock)
        await clock.sleeps(atLeast: 1)

        await fixture.sessions.revokeAll(forSubject: "ada")
        clock.advance(by: Self.interval)

        #expect(await Self.firstEnd(lease) == .revoked)
        #expect(await lease.isActive == false)
    }

    @Test("a session past its lifetime ends the lease as .expired, not .revoked")
    func expiryEndsLease() async throws {
        let fixture = try IdentityFixture()
        let clock = ManualClock()
        let lease = try await Self.lease(fixture, clock: clock, lifetime: 60)
        await clock.sleeps(atLeast: 1)

        fixture.date.advance(61)
        clock.advance(by: Self.interval)

        #expect(await Self.firstEnd(lease) == .expired)
        #expect(await lease.isActive == false)
    }

    // MARK: - Ending

    @Test("end() yields .signedOut and revokes the token in the store")
    func endSignsOut() async throws {
        let fixture = try IdentityFixture()
        let clock = ManualClock()
        // Distinct seeds, so the two leases hold distinct tokens.
        let ended = try await Self.lease(fixture, clock: clock, lifetime: 60, seed: 1)
        let kept = try await Self.lease(fixture, clock: clock, lifetime: 60, seed: 2)

        await ended.end()
        #expect(await Self.firstEnd(ended) == .signedOut)
        #expect(await ended.isActive == false)

        // The oracle: past both sessions' lifetime, the store sweeps what it still holds. Only
        // the kept lease's session is there; the ended one's token was revoked, so it no longer
        // resolves.
        fixture.date.advance(61)
        #expect(await fixture.sessions.removeExpired() == 1)
        #expect(await kept.isActive)
    }

    @Test("ended yields exactly once, then finishes, however many ways the lease ends")
    func endedYieldsOnce() async throws {
        let fixture = try IdentityFixture()
        let clock = ManualClock()
        let lease = try await Self.lease(fixture, clock: clock)
        await clock.sleeps(atLeast: 1)

        await lease.end()
        await lease.end()
        await fixture.sessions.revokeAll(forSubject: "ada")
        clock.advance(by: Self.interval)

        var values: [LeaseEnd] = []
        for await value in lease.ended { values.append(value) }
        #expect(values == [.signedOut])
    }

    // MARK: - Reverify

    @Test("reverify within maximumAge returns the current authentication and asks no source")
    func reverifyWithinAgeAsksNothing() async throws {
        let fixture = try IdentityFixture()
        let clock = ManualClock()
        let source = FixedSource(credentials: [IdentityFixture.adaPassphrase, IdentityFixture.adaKey])
        let presenter = RecordingPresenter()
        let stepUp = StepUp(sources: [source], authenticator: fixture.authenticator, presenter: presenter)
        let lease = try await Self.lease(fixture, clock: clock, stepUp: stepUp)
        let original = await lease.authentication

        fixture.date.advance(30)
        let result = try await lease.reverify(minimum: .singleFactor, maximumAge: .seconds(60))

        #expect(result == original)
        #expect(await source.counter.calls == 0)
        #expect(await presenter.log.shown.isEmpty)
    }

    @Test("reverify past maximumAge asks again, even when assurance already suffices")
    func reverifyPastAgeAsks() async throws {
        let fixture = try IdentityFixture()
        let clock = ManualClock()
        let source = FixedSource(credentials: [IdentityFixture.adaPassphrase])
        let stepUp = StepUp(sources: [source], authenticator: fixture.authenticator, presenter: RecordingPresenter())
        let lease = try await Self.lease(fixture, clock: clock, stepUp: stepUp)
        let original = await lease.authentication

        fixture.date.advance(120)
        let result = try await lease.reverify(minimum: .singleFactor, maximumAge: .seconds(60))

        #expect(await source.counter.calls == 1)
        #expect(result.subject.id == "ada")
        #expect(result.at > original.at)
        #expect(await lease.authentication == result)
    }

    @Test("step-up from single- to multi-factor for the same subject succeeds and updates authentication")
    func stepUpToMultiFactor() async throws {
        let fixture = try IdentityFixture()
        let clock = ManualClock()
        let none = FixedSource(credentials: nil)
        let both = FixedSource(credentials: [IdentityFixture.adaPassphrase, IdentityFixture.adaKey])
        let stepUp = StepUp(sources: [none, both], authenticator: fixture.authenticator, presenter: RecordingPresenter())
        let lease = try await Self.lease(fixture, clock: clock, stepUp: stepUp)
        #expect(await lease.authentication.assurance == .singleFactor)

        let result = try await lease.reverify(minimum: .multiFactor, maximumAge: nil)

        #expect(result.subject.id == "ada")
        #expect(result.assurance == .multiFactor)
        #expect(await lease.authentication == result)
        // A source that doesn't apply passes to the next; each is told who is signed in.
        #expect(await none.counter.subjectIDs == ["ada"])
        #expect(await both.counter.subjectIDs == ["ada"])
    }

    @Test("step-up proving a different subject fails, shows Sign-in failed, and keeps the old authentication")
    func stepUpDifferentSubjectFails() async throws {
        let fixture = try IdentityFixture()
        let clock = ManualClock()
        let grace = FixedSource(credentials: [IdentityFixture.gracePassphrase, IdentityFixture.graceKey])
        let presenter = RecordingPresenter()
        let stepUp = StepUp(sources: [grace], authenticator: fixture.authenticator, presenter: presenter)
        let lease = try await Self.lease(fixture, clock: clock, stepUp: stepUp)
        let original = await lease.authentication

        await #expect(throws: SignInError.failed) {
            try await lease.reverify(minimum: .multiFactor, maximumAge: nil)
        }
        #expect(await presenter.log.shown == [.failed])
        #expect(await lease.authentication == original)
    }

    @Test("step-up that proves the subject below the minimum fails")
    func stepUpBelowMinimumFails() async throws {
        let fixture = try IdentityFixture()
        let clock = ManualClock()
        let single = FixedSource(credentials: [IdentityFixture.adaPassphrase])
        let presenter = RecordingPresenter()
        let stepUp = StepUp(sources: [single], authenticator: fixture.authenticator, presenter: presenter)
        let lease = try await Self.lease(fixture, clock: clock, stepUp: stepUp)

        await #expect(throws: SignInError.failed) {
            try await lease.reverify(minimum: .multiFactor, maximumAge: nil)
        }
        #expect(await presenter.log.shown == [.failed])
    }

    @Test("a source that throws during step-up propagates, and the next source is never asked")
    func throwingSourceNeverFallsThrough() async throws {
        let fixture = try IdentityFixture()
        let clock = ManualClock()
        let throwing = ThrowingSource()
        let next = FixedSource(credentials: [IdentityFixture.adaPassphrase, IdentityFixture.adaKey])
        let stepUp = StepUp(sources: [throwing, next], authenticator: fixture.authenticator, presenter: RecordingPresenter())
        let lease = try await Self.lease(fixture, clock: clock, stepUp: stepUp)

        await #expect(throws: SignInError.cancelled) {
            try await lease.reverify(minimum: .multiFactor, maximumAge: nil)
        }
        #expect(await throwing.counter.calls == 1)
        #expect(await next.counter.calls == 0)
        #expect(await lease.isActive)
    }

    @Test("when no source applies, step-up fails")
    func noSourceApplies() async throws {
        let fixture = try IdentityFixture()
        let clock = ManualClock()
        let stepUp = StepUp(sources: [FixedSource(credentials: nil)], authenticator: fixture.authenticator, presenter: RecordingPresenter())
        let lease = try await Self.lease(fixture, clock: clock, stepUp: stepUp)

        await #expect(throws: SignInError.failed) {
            try await lease.reverify(minimum: .multiFactor, maximumAge: nil)
        }
    }

    @Test("with no step-up configured, a reverify that needs one fails")
    func noStepUpFails() async throws {
        let fixture = try IdentityFixture()
        let lease = try await Self.lease(fixture, clock: ManualClock())

        await #expect(throws: SignInError.failed) {
            try await lease.reverify(minimum: .multiFactor, maximumAge: nil)
        }
    }

    @Test("an ended lease refuses reverify, even one that would need no prompt")
    func endedLeaseRefusesReverify() async throws {
        let fixture = try IdentityFixture()
        let source = FixedSource(credentials: [IdentityFixture.adaPassphrase, IdentityFixture.adaKey])
        let stepUp = StepUp(sources: [source], authenticator: fixture.authenticator, presenter: RecordingPresenter())
        let lease = try await Self.lease(fixture, clock: ManualClock(), stepUp: stepUp)

        await lease.end()

        await #expect(throws: SignInError.failed) {
            try await lease.reverify(minimum: .singleFactor, maximumAge: nil)
        }
        #expect(await source.counter.calls == 0)
    }

    @Test("reverify re-resolves first: a revoked subject is refused before the next interval")
    func reverifyReresolves() async throws {
        let fixture = try IdentityFixture()
        let lease = try await Self.lease(fixture, clock: ManualClock())

        await fixture.sessions.revokeAll(forSubject: "ada")

        await #expect(throws: SignInError.failed) {
            try await lease.reverify(minimum: .singleFactor, maximumAge: nil)
        }
        #expect(await Self.firstEnd(lease) == .revoked)
    }
}
