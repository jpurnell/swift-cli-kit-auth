// PassphraseStoreFixture.swift
// SwiftCLIKitAuthSSHTests
// Created by Justin Purnell on 2026-10-25.

import Foundation
import SwiftIdentity
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A seeded generator, so every salt a fixture draws is the same on every run.
///
/// SplitMix64 (Steele, Lea and Flood 2014), the generator SwiftIdentity's own tests seed salts
/// with.
struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var mixed = state
        mixed = (mixed ^ (mixed >> 30)) &* 0xBF58_476D_1CE4_E5B9
        mixed = (mixed ^ (mixed >> 27)) &* 0x94D0_49BB_1331_11EB
        return mixed ^ (mixed >> 31)
    }
}

/// A real SwiftIdentity `FileCredentialStore` in a fresh temporary directory, holding one
/// passphrase for `ada` and a roster entry for `grace`, who has none.
///
/// The verifier is derived at `PassphraseVerifier.roundFloor`, the fewest rounds swift-crypto
/// will derive with: the same code path as production at a third of the default's cost.
struct PassphraseStoreFixture {
    /// The subject holding a passphrase.
    static let subjectID = "ada"
    /// Her passphrase: four words drawn from a seeded generator, so it is the same on every run
    /// and no credential is written into the source.
    static let secret: String = {
        var generator = SplitMix64(seed: 0x5EC2_E7)
        return (0..<4).map { _ in String(generator.next() % 1_000_000_007, radix: 36) }.joined(separator: " ")
    }()

    /// The directory holding `subjects` and `verifiers`.
    let directory: URL
    /// An authenticator over the store.
    let authenticator: Authenticator

    init() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("swift-cli-kit-auth-\(UUID().uuidString)")
            .standardized
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        guard chmod(directory.path, 0o700) == 0 else { throw FixtureError.permissions }

        var generator = SplitMix64(seed: 20_261_025)
        let verifier = try PassphraseVerifier(
            for: Passphrase(subjectID: Self.subjectID, secret: Self.secret),
            using: &generator, rounds: PassphraseVerifier.roundFloor
        )
        try Self.write("""
            ada     person   active
            grace   person   active
            """, to: directory.appendingPathComponent(FileCredentialStore.subjectsFile))
        try Self.write("""
            ada     passphrase  \(verifier.encoded)  -
            """, to: directory.appendingPathComponent(FileCredentialStore.verifiersFile))

        let store = try FileCredentialStore(directory: directory.path)
        self.directory = directory
        self.authenticator = Authenticator(stores: [store], audit: nil, now: { Date() })
    }

    /// Removes the directory.
    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }

    private static func write(_ text: String, to url: URL) throws {
        try Data(text.utf8).write(to: url)
        guard chmod(url.path, 0o600) == 0 else { throw FixtureError.permissions }
    }

    enum FixtureError: Error {
        case permissions
    }
}
