// ManualClock.swift
// SwiftCLIKitAuthTests
// Created by Justin Purnell on 2026-10-25.

import Foundation
import os

/// A clock that moves only when a test advances it, so an interval elapses without waiting.
///
/// A sleeper registers its deadline; ``advance(by:)`` moves the instant and wakes every sleeper
/// whose deadline has passed. ``sleeps(atLeast:)`` lets a test wait until a loop has gone back to
/// sleep, so an advance is never raced against the sleep it is meant to end.
struct ManualClock: Clock {
    /// A point on the manual timeline: the time since the clock was made.
    struct Instant: InstantProtocol {
        /// Time since the clock's origin.
        let offset: Duration

        func advanced(by duration: Duration) -> Instant {
            Instant(offset: offset + duration)
        }

        func duration(to other: Instant) -> Duration {
            other.offset - offset
        }

        static func < (lhs: Instant, rhs: Instant) -> Bool {
            lhs.offset < rhs.offset
        }
    }

    private struct Sleeper {
        let id: UInt64
        let deadline: Instant
        let continuation: CheckedContinuation<Void, any Error>
    }

    private struct Waiter {
        let count: Int
        let continuation: CheckedContinuation<Void, Never>
    }

    private struct State {
        var now = Instant(offset: .zero)
        var nextID: UInt64 = 0
        var sleepers: [Sleeper] = []
        var sleepCount = 0
        var waiters: [Waiter] = []
        var cancelled: Set<UInt64> = []
    }

    private let state = OSAllocatedUnfairLock(initialState: State())

    var now: Instant {
        state.withLock { $0.now }
    }

    var minimumResolution: Duration {
        .nanoseconds(1)
    }

    func sleep(until deadline: Instant, tolerance: Duration?) async throws {
        let id = state.withLock { state -> UInt64 in
            state.nextID += 1
            return state.nextID
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let (resume, waiters) = state.withLock { state -> (Result<Void, any Error>?, [Waiter]) in
                    state.sleepCount += 1
                    let ready = state.waiters.filter { $0.count <= state.sleepCount }
                    state.waiters.removeAll { $0.count <= state.sleepCount }
                    if state.cancelled.remove(id) != nil {
                        return (.failure(CancellationError()), ready)
                    }
                    if deadline <= state.now {
                        return (.success(()), ready)
                    }
                    state.sleepers.append(Sleeper(id: id, deadline: deadline, continuation: continuation))
                    return (nil, ready)
                }
                for waiter in waiters { waiter.continuation.resume() }
                if let resume { continuation.resume(with: resume) }
            }
        } onCancel: {
            let sleeper = state.withLock { state -> Sleeper? in
                guard let index = state.sleepers.firstIndex(where: { $0.id == id }) else {
                    state.cancelled.insert(id)
                    return nil
                }
                return state.sleepers.remove(at: index)
            }
            sleeper?.continuation.resume(throwing: CancellationError())
        }
    }

    /// Moves the clock forward and wakes every sleeper whose deadline has now passed.
    /// - Parameter duration: How far to move.
    func advance(by duration: Duration) {
        let due = state.withLock { state -> [Sleeper] in
            state.now = state.now.advanced(by: duration)
            let instant = state.now
            let due = state.sleepers.filter { $0.deadline <= instant }
            state.sleepers.removeAll { $0.deadline <= instant }
            return due
        }
        for sleeper in due { sleeper.continuation.resume() }
    }

    /// Returns once `count` sleeps have begun on this clock, in total.
    /// - Parameter count: The total to wait for.
    func sleeps(atLeast count: Int) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let ready = state.withLock { state -> Bool in
                guard state.sleepCount < count else { return true }
                state.waiters.append(Waiter(count: count, continuation: continuation))
                return false
            }
            if ready { continuation.resume() }
        }
    }
}
