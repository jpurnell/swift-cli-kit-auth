// SSHKeyStore.swift
// SwiftCLIKitAuthSSH
// Created by Justin Purnell on 2026-10-26.

import Foundation
import SwiftIdentity
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Remembered SSH keys: a key fingerprint bound to a subject until a date.
///
/// What makes experience B's second connection skip the browser: once someone has signed in
/// another way, the gate binds the key they connected with, and next time the key alone resolves.
/// A `CredentialStore`, so SwiftIdentity's `Authenticator` asks it like any other, and it passes
/// SwiftIdentity's `ConformanceSuite` unchanged.
///
/// ## What a key proves
///
/// The binding says which subject a key stands for; the **roster** says whether that subject may
/// still sign in. It is read on every resolution, as SwiftIdentity's `SessionStore` reads it, so
/// revoking a subject stops their keys at once, and a key bound to a honeypot subject is a
/// tripwire: refused, and audited as a honeypot.
///
/// ## The file
///
/// One line per key: `SHA256 fingerprint<TAB>key type<TAB>subject id<TAB>until (Unix seconds)`.
/// It must be readable by its owner only, and a malformed line stops the store at startup rather
/// than being skipped, the rules SwiftIdentity's file store follows. Writes are atomic and never
/// leave the file readable by others, even for a moment.
///
/// ```swift
/// import Foundation
/// import SwiftIdentity
/// import SwiftCLIKitAuthSSH
///
/// func rememberedKeys(at url: URL, people: FileCredentialStore) throws -> SSHKeyStore {
///     try SSHKeyStore(url: url, subjects: { id in people.subject(id: id) })
/// }
/// ```
public actor SSHKeyStore: CredentialStore {

    /// Why the store wouldn't start, or wouldn't write.
    public enum Failure: Error, Equatable, Sendable {
        /// The keys file can be read by someone other than its owner.
        case readableByOthers(path: String)
        /// A line of the keys file isn't a binding; numbered from 1.
        case malformedLine(Int)
        /// A subject id that can't be written to the file: empty, or holding a tab or line break.
        case invalidSubjectID
        /// An expiry that isn't a finite date.
        case invalidExpiry
        /// The file couldn't be written.
        case writeFailed(path: String)
    }

    private struct Binding: Sendable {
        let fingerprint: String
        let keyType: String
        let subjectID: String
        let until: Int64
    }

    private let url: URL
    private let subjects: @Sendable (String) async -> Subject?
    private let now: @Sendable () -> Date
    private let audit: (any IdentityAudit)?
    private var bindings: [Binding]

    /// Opens the store, reading the keys file if it exists.
    ///
    /// - Parameters:
    ///   - url: The keys file. It needn't exist yet; the first ``bind(_:to:until:)`` creates it.
    ///   - subjects: Looks up the **current** subject for an id, such as
    ///     `FileCredentialStore.subject(id:)`. Called on every resolution.
    ///   - now: The clock, which decides expiry.
    ///   - audit: Told the outcome of every resolution of an SSH key.
    /// - Throws: ``Failure/readableByOthers(path:)`` or ``Failure/malformedLine(_:)``.
    public init(
        url: URL,
        subjects: @escaping @Sendable (String) async -> Subject?,
        now: @escaping @Sendable () -> Date = { Date() },
        audit: (any IdentityAudit)? = nil
    ) throws {
        self.url = url
        self.subjects = subjects
        self.now = now
        self.audit = audit
        self.bindings = try Self.read(url)
    }

    // MARK: - CredentialStore

    /// Resolves an SSH key to the subject it is bound to, if that subject may sign in.
    /// - Parameter credential: The proof presented; anything but an ``SSHPublicKeyCredential`` is
    ///   unknown, unaudited.
    /// - Returns: The subject, or why not.
    public func resolve(_ credential: any Credential) async -> Resolution {
        await resolveVerifying(credential).0
    }

    /// Resolves an SSH key, reporting the key type **this store recorded** when it was bound, never
    /// the connection's claim, as the algorithm.
    /// - Parameter credential: The proof presented.
    /// - Returns: The resolution, and the recorded key type when it resolved.
    public func resolveVerifying(_ credential: any Credential) async -> (Resolution, algorithm: String?) {
        guard let key = credential as? SSHPublicKeyCredential else { return (.refused(.unknown), nil) }
        let presented = Array(key.fingerprint.utf8)
        var matched: Binding?
        // Scanned rather than looked up, so the time taken doesn't depend on where a key sits:
        // SwiftIdentity's SessionStore reasons the same way.
        for binding in bindings where ConstantTime.equals(Array(binding.fingerprint.utf8), presented) {
            matched = binding
        }
        guard let binding = matched else { return (await report(.unknown, nil), nil) }
        guard Self.seconds(now()).map({ $0 < binding.until }) == true else {
            return (await report(.expired, binding.subjectID), nil)
        }
        guard let subject = await subjects(binding.subjectID) else {
            return (await report(.unknown, binding.subjectID), nil)
        }
        switch subject.status {
        case .revoked: return (await report(.revoked, subject.id), nil)
        case .honeypot: return (await report(.honeypot, subject.id), nil)
        case .active: return (await report(.verified, subject.id, verified: subject), binding.keyType)
        }
    }

    // MARK: - Remembering

    /// Binds a key to a subject until a date, replacing any binding the key had.
    ///
    /// Call it only after another credential proved who this is: binding is what lets the key
    /// alone sign them in next time.
    /// - Parameters:
    ///   - key: The key the person connected with.
    ///   - subjectID: Who another credential proved them to be.
    ///   - until: When the binding lapses.
    /// - Throws: ``Failure/invalidSubjectID``, ``Failure/invalidExpiry`` or
    ///   ``Failure/writeFailed(path:)``.
    public func bind(_ key: SSHPublicKeyCredential, to subjectID: String, until: Date) throws {
        guard !subjectID.isEmpty, !subjectID.contains(where: { $0 == "\t" || $0.isNewline }) else {
            throw Failure.invalidSubjectID
        }
        guard let seconds = Self.seconds(until) else { throw Failure.invalidExpiry }
        var next = bindings.filter { $0.fingerprint != key.fingerprint }
        next.append(Binding(fingerprint: key.fingerprint, keyType: key.keyType, subjectID: subjectID, until: seconds))
        try write(next)
        bindings = next
    }

    /// Forgets a key. Forgetting a key that isn't bound does nothing.
    /// - Parameter key: The key.
    /// - Throws: ``Failure/writeFailed(path:)``.
    public func unbind(_ key: SSHPublicKeyCredential) throws {
        let next = bindings.filter { $0.fingerprint != key.fingerprint }
        guard next.count != bindings.count else { return }
        try write(next)
        bindings = next
    }

    // MARK: - The file

    private static func read(_ url: URL) throws -> [Binding] {
        let path = url.path
        guard FileManager.default.fileExists(atPath: path) else { return [] }
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0o777
        guard mode & 0o077 == 0 else { throw Failure.readableByOthers(path: path) }
        let text = String(decoding: try Data(contentsOf: url), as: UTF8.self)
        var bindings: [Binding] = []
        for (index, line) in text.split(whereSeparator: \.isNewline).enumerated() {
            let fields = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard fields.count == 4, fields[0].hasPrefix("SHA256:"), !fields[1].isEmpty, !fields[2].isEmpty,
                  let until = Int64(fields[3])
            else { throw Failure.malformedLine(index + 1) }
            bindings.append(Binding(fingerprint: fields[0], keyType: fields[1], subjectID: fields[2], until: until))
        }
        return bindings
    }

    /// Writes every binding to a new owner-only file beside the keys file, then renames it into
    /// place, so a reader sees the old file or the new one, never half of either, and the file is
    /// never readable by others.
    private func write(_ next: [Binding]) throws {
        let body = next.map { "\($0.fingerprint)\t\($0.keyType)\t\($0.subjectID)\t\($0.until)\n" }.joined()
        let directory = url.deletingLastPathComponent().resolvingSymlinksInPath()
        let staging = directory.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        // The staging file must sit beside the keys file, for the rename to be atomic and for it
        // to land nowhere else.
        guard staging.pathComponents.starts(with: directory.pathComponents),
              staging.pathComponents.count == directory.pathComponents.count + 1
        else { throw Failure.writeFailed(path: url.path) }
        guard FileManager.default.createFile(
            atPath: staging.path, contents: Data(body.utf8), attributes: [.posixPermissions: 0o600]
        ) else { throw Failure.writeFailed(path: url.path) }
        guard rename(staging.path, url.path) == 0 else {
            try? FileManager.default.removeItem(at: staging) // silent: the staging file is ours, and the write has already failed
            throw Failure.writeFailed(path: url.path)
        }
    }

    /// Whole Unix seconds, or nil for a date that isn't finite or won't fit.
    private static func seconds(_ date: Date) -> Int64? {
        let value = date.timeIntervalSince1970.rounded(.down)
        guard value.isFinite, value > -9.2e18, value < 9.2e18 else { return nil }
        return Int64(value)
    }

    /// Records the outcome and returns the resolution, so the two can't disagree.
    private func report(_ outcome: IdentityEvent.Outcome, _ subjectID: String?, verified subject: Subject? = nil) async -> Resolution {
        await audit?.record(IdentityEvent(
            outcome: outcome, subjectID: subjectID, credentialKind: SSHPublicKeyCredential.kind, at: now()
        ))
        guard let subject else { return .refused(outcome) }
        return .verified(subject)
    }
}
