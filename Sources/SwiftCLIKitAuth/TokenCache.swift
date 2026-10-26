// TokenCache.swift
// SwiftCLIKitAuth
// Created by Justin Purnell on 2026-10-26.

import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Where a remembered token lives between runs of a command-line tool.
///
/// What it holds is a bearer secret: whoever reads it can sign in as the person until it lapses.
/// ``FileTokenCache`` keeps it in an owner-only file; a Keychain-backed cache is a later
/// conformance, with no change here.
public protocol TokenCache: Sendable {
    /// The remembered token, or `nil` if there is none.
    /// - Throws: When the cache can't be trusted, such as a file others can read.
    func load() async throws -> String?

    /// Remembers a token, replacing any before it.
    /// - Parameter token: The token, exactly as the sign-in flow returned it.
    /// - Throws: When it can't be kept safely.
    func save(_ token: String) async throws

    /// Forgets the token. Forgetting when there is none does nothing.
    /// - Throws: When the token couldn't be removed.
    func clear() async throws
}

/// A token in a file only its owner can read.
///
/// The app chooses where, as `gh` and the AWS CLI do; there is no default. A file others can read
/// is **refused, not repaired**: the token in it may already be exposed, and replacing it quietly
/// would hide that. The person deletes it, or signs out at the identity provider.
///
/// ```swift
/// import Foundation
/// import SwiftCLIKitAuth
///
/// let home = FileManager.default.homeDirectoryForCurrentUser
/// let cache = FileTokenCache(url: home.appendingPathComponent(".config/mytool/token"))
/// ```
///
/// - The file is written 0600, into a new file renamed into place, so it is never readable by
///   others and never half-written.
/// - A missing directory is created 0700. An existing one others can write is refused, since they
///   could swap the file; one they can only read is allowed, as the file itself is 0600.
/// - A symlink at the path is refused.
public struct FileTokenCache: TokenCache {

    /// Why the cache wouldn't load or save.
    public enum Failure: Error, Equatable, Sendable {
        /// The token file can be read by someone other than its owner.
        case readableByOthers(path: String)
        /// The token path is a symlink, directory or anything else that isn't a plain file.
        case notARegularFile(path: String)
        /// The directory the token file lives in can be written by someone other than its owner.
        case directoryWritableByOthers(path: String)
        /// The token file is larger than any token: it isn't one.
        case tooLarge(path: String)
        /// An empty token, which would read back as none.
        case emptyToken
        /// The file couldn't be written.
        case writeFailed(path: String)
    }

    /// The largest file read as a token. OAuth tokens, JWTs included, are far smaller.
    public static let maximumBytes = 64 * 1024

    /// The token file.
    public let url: URL

    /// Creates the cache. Nothing is read or written until it's used.
    /// - Parameter url: The token file. Its directory needn't exist yet.
    public init(url: URL) {
        self.url = url
    }

    /// The token in the file, or `nil` if there's no file or it's empty.
    /// - Returns: The file's contents.
    /// - Throws: ``Failure/readableByOthers(path:)``, ``Failure/notARegularFile(path:)`` or
    ///   ``Failure/tooLarge(path:)``, or the error reading the file.
    public func load() async throws -> String? {
        guard try checkExisting() else { return nil }
        let text = String(decoding: try Data(contentsOf: url), as: UTF8.self)
        return text.isEmpty ? nil : text
    }

    /// Writes the token to a new owner-only file and renames it into place.
    /// - Parameter token: The token.
    /// - Throws: ``Failure/emptyToken``, ``Failure/readableByOthers(path:)``,
    ///   ``Failure/notARegularFile(path:)``, ``Failure/directoryWritableByOthers(path:)`` or
    ///   ``Failure/writeFailed(path:)``.
    public func save(_ token: String) async throws {
        guard !token.isEmpty else { throw Failure.emptyToken }
        _ = try checkExisting()
        let directory = try ownerOnlyDirectory()
        let staging = directory.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        // The staging file must sit beside the token file, for the rename to be atomic and for it
        // to land nowhere else.
        guard staging.pathComponents.starts(with: directory.pathComponents),
              staging.pathComponents.count == directory.pathComponents.count + 1
        else { throw Failure.writeFailed(path: url.path) }
        guard FileManager.default.createFile(
            atPath: staging.path, contents: Data(token.utf8), attributes: [.posixPermissions: 0o600]
        ) else { throw Failure.writeFailed(path: url.path) }
        guard rename(staging.path, url.path) == 0 else {
            try? FileManager.default.removeItem(at: staging) // silent: the staging file is ours, and the write has already failed
            throw Failure.writeFailed(path: url.path)
        }
    }

    /// Removes the token file, if there is one.
    /// - Throws: ``Failure/notARegularFile(path:)``, or the error removing the file.
    public func clear() async throws {
        guard let type = try attributes()?[.type] as? FileAttributeType else { return }
        guard type == .typeRegular else { throw Failure.notARegularFile(path: url.path) }
        try FileManager.default.removeItem(at: url)
    }

    /// The token file's attributes, not following a symlink, or `nil` if there's nothing there.
    private func attributes() throws -> [FileAttributeKey: Any]? {
        var info = stat()
        if lstat(url.path, &info) != 0, errno == ENOENT { return nil }
        return try FileManager.default.attributesOfItem(atPath: url.path)
    }

    /// Whether there is a token file, refusing one that can't be trusted.
    private func checkExisting() throws -> Bool {
        guard let attributes = try attributes() else { return false }
        guard attributes[.type] as? FileAttributeType == .typeRegular else {
            throw Failure.notARegularFile(path: url.path)
        }
        let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0o777
        guard mode & 0o077 == 0 else { throw Failure.readableByOthers(path: url.path) }
        let size = (attributes[.size] as? NSNumber)?.intValue ?? Int.max
        guard size <= Self.maximumBytes else { throw Failure.tooLarge(path: url.path) }
        return true
    }

    /// The token file's directory, created 0700 if missing, refused if others can write it.
    private func ownerOnlyDirectory() throws -> URL {
        let directory = url.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
            )
        }
        let resolved = directory.resolvingSymlinksInPath()
        let attributes = try FileManager.default.attributesOfItem(atPath: resolved.path)
        let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0o777
        guard mode & 0o022 == 0 else { throw Failure.directoryWritableByOthers(path: directory.path) }
        return resolved
    }
}
