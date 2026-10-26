// FileTokenCacheTests.swift
// SwiftCLIKitAuthTests
// Created by Justin Purnell on 2026-10-26.

import Testing
import Foundation
import SwiftCLIKitAuth

@Suite("FileTokenCache")
struct FileTokenCacheTests {

    /// A fresh owner-only directory, and the token path inside it.
    private struct Place {
        let directory: URL
        var token: URL { directory.appendingPathComponent("token") }

        init() throws {
            directory = FileManager.default.temporaryDirectory.appendingPathComponent("tokens-\(UUID().uuidString)")
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
            )
        }

        func mode(_ url: URL) throws -> Int {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            return try #require(attributes[.posixPermissions] as? NSNumber).intValue & 0o777
        }

        func remove() {
            try? FileManager.default.removeItem(at: directory) // silent: best-effort cleanup of the test's own directory
        }
    }

    @Test("A saved token loads back exactly, and is written readable by its owner only")
    func roundTrip() async throws {
        let place = try Place()
        defer { place.remove() }
        let cache = FileTokenCache(url: place.token)

        try await cache.save("tok en\twith spaces")

        #expect(try await cache.load() == "tok en\twith spaces")
        #expect(try place.mode(place.token) == 0o600)
    }

    @Test("Saving again replaces the token")
    func replaces() async throws {
        let place = try Place()
        defer { place.remove() }
        let cache = FileTokenCache(url: place.token)

        try await cache.save("first")
        try await cache.save("second")

        #expect(try await cache.load() == "second")
    }

    @Test("No file, or an empty one, is no token")
    func missingOrEmpty() async throws {
        let place = try Place()
        defer { place.remove() }
        let cache = FileTokenCache(url: place.token)
        #expect(try await cache.load() == nil)

        #expect(FileManager.default.createFile(atPath: place.token.path, contents: Data(), attributes: [.posixPermissions: 0o600]))
        #expect(try await cache.load() == nil)
    }

    @Test("clear removes the file, and clearing nothing is no error")
    func clear() async throws {
        let place = try Place()
        defer { place.remove() }
        let cache = FileTokenCache(url: place.token)
        try await cache.clear()

        try await cache.save("tok")
        try await cache.clear()

        #expect(!FileManager.default.fileExists(atPath: place.token.path))
        #expect(try await cache.load() == nil)
    }

    @Test("A token file others can read is refused, on load and on save, and left as it is")
    func readableByOthers() async throws {
        let place = try Place()
        defer { place.remove() }
        #expect(FileManager.default.createFile(
            atPath: place.token.path, contents: Data("exposed".utf8), attributes: [.posixPermissions: 0o644]
        ))
        let cache = FileTokenCache(url: place.token)

        await #expect(throws: FileTokenCache.Failure.readableByOthers(path: place.token.path)) { try await cache.load() }
        await #expect(throws: FileTokenCache.Failure.readableByOthers(path: place.token.path)) { try await cache.save("new") }
        #expect(try String(contentsOf: place.token, encoding: .utf8) == "exposed")
    }

    @Test("A symlink at the token path is refused, on load and on save")
    func symlink() async throws {
        let place = try Place()
        defer { place.remove() }
        let elsewhere = place.directory.appendingPathComponent("elsewhere")
        #expect(FileManager.default.createFile(atPath: elsewhere.path, contents: Data("t".utf8), attributes: [.posixPermissions: 0o600]))
        try FileManager.default.createSymbolicLink(at: place.token, withDestinationURL: elsewhere)
        let cache = FileTokenCache(url: place.token)

        await #expect(throws: FileTokenCache.Failure.notARegularFile(path: place.token.path)) { try await cache.load() }
        await #expect(throws: FileTokenCache.Failure.notARegularFile(path: place.token.path)) { try await cache.save("new") }
        #expect(try String(contentsOf: elsewhere, encoding: .utf8) == "t")
    }

    @Test("A missing directory is created readable by its owner only")
    func createsDirectory() async throws {
        let place = try Place()
        defer { place.remove() }
        let nested = place.directory.appendingPathComponent("app")
        let cache = FileTokenCache(url: nested.appendingPathComponent("token"))

        try await cache.save("tok")

        #expect(try place.mode(nested) == 0o700)
        #expect(try await cache.load() == "tok")
    }

    @Test("A directory others can write is refused: they could swap the file")
    func sharedDirectory() async throws {
        let place = try Place()
        defer { place.remove() }
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: place.directory.path)
        let cache = FileTokenCache(url: place.token)

        await #expect(throws: FileTokenCache.Failure.directoryWritableByOthers(path: place.directory.path)) {
            try await cache.save("tok")
        }
        #expect(!FileManager.default.fileExists(atPath: place.token.path))
    }

    @Test("A file larger than any token is refused, not read")
    func tooLarge() async throws {
        let place = try Place()
        defer { place.remove() }
        let body = Data(repeating: 0x41, count: FileTokenCache.maximumBytes + 1)
        #expect(FileManager.default.createFile(atPath: place.token.path, contents: body, attributes: [.posixPermissions: 0o600]))
        let cache = FileTokenCache(url: place.token)

        await #expect(throws: FileTokenCache.Failure.tooLarge(path: place.token.path)) { try await cache.load() }

        #expect(FileManager.default.createFile(
            atPath: place.token.path, contents: body.dropLast(), attributes: [.posixPermissions: 0o600]
        ))
        #expect(try await cache.load()?.utf8.count == FileTokenCache.maximumBytes)
    }

    @Test("An empty token isn't saved: it would read back as none")
    func emptyToken() async throws {
        let place = try Place()
        defer { place.remove() }
        let cache = FileTokenCache(url: place.token)

        await #expect(throws: FileTokenCache.Failure.emptyToken) { try await cache.save("") }
    }
}
