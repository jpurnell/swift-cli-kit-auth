// SSHPublicKeyCredential.swift
// SwiftCLIKitAuthSSH
// Created by Justin Purnell on 2026-10-26.

import Crypto
import Foundation
import SwiftCLIKitSSH
import SwiftIdentity

/// An SSH public key the client proved it holds: a SwiftIdentity possession credential.
///
/// NIOSSH checks the client's signature before a session exists, so a key that reaches a
/// session is one the client holds. What a store keeps is its ``fingerprint``.
///
/// ```swift
/// import SwiftCLIKitAuthSSH
///
/// let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ada@laptop"
/// if let key = SSHPublicKeyCredential(openSSH: line) {
///     print(key.keyType)       // ssh-ed25519
///     print(key.fingerprint)   // SHA256:…, as ssh-keygen -l prints it
/// }
/// ```
public struct SSHPublicKeyCredential: Credential, Equatable, Hashable {
    /// The credential kind.
    public static let kind = "ssh-public-key"

    /// The key as OpenSSH writes it, `<type> <base64>`, without a comment.
    public let openSSH: String

    /// The key type, such as `ssh-ed25519`, as the key itself encodes it.
    public let keyType: String

    /// The SHA-256 fingerprint, `SHA256:` followed by unpadded base64, as `ssh-keygen -l` prints.
    public let fingerprint: String

    /// Reads an OpenSSH public key line, `<type> <base64> [comment]`.
    ///
    /// - Parameter openSSH: The line. A comment is ignored.
    /// - Returns: `nil` unless the base64 decodes to a key blob whose own type field matches the
    ///   line's.
    public init?(openSSH: String) {
        let fields = openSSH.split(separator: " ", omittingEmptySubsequences: true)
        guard fields.count >= 2, let blob = Data(base64Encoded: String(fields[1])),
              let encodedType = Self.leadingString(blob), encodedType == String(fields[0]),
              blob.count > 4 + encodedType.utf8.count
        else { return nil }
        self.keyType = encodedType
        self.openSSH = "\(fields[0]) \(fields[1])"
        let digest = Data(SHA256.hash(data: blob)).base64EncodedString()
        self.fingerprint = "SHA256:" + digest.replacingOccurrences(of: "=", with: "")
    }

    /// The key a connection was admitted with.
    ///
    /// - Parameter identity: The connection's `SSHClientIdentity`.
    /// - Returns: `nil` unless the evidence is a plain public key.
    public init?(_ identity: SSHClientIdentity) {
        // A plain key only: certificate evidence carries a key too, but trusting it is a CA's
        // question, which this credential doesn't answer.
        guard identity.evidence.kind == "public-key",
              let line = identity.evidence.openSSHPublicKey
        else { return nil }
        self.init(openSSH: line)
    }

    /// The SSH wire-format string a key blob starts with (RFC 4251 §5): a big-endian length,
    /// then that many bytes, which must be UTF-8.
    private static func leadingString(_ blob: Data) -> String? {
        let bytes = [UInt8](blob)
        guard bytes.count >= 4 else { return nil }
        let length = bytes[0..<4].reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0, bytes.count >= 4 + length else { return nil }
        return String(bytes: bytes[4..<(4 + length)], encoding: .utf8)
    }
}
