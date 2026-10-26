// SSHSession+Authentication.swift
// SwiftCLIKitAuthSSH
// Created by Justin Purnell on 2026-10-25.

import SwiftCLIKitSSH
import SwiftIdentity

extension SSHSession {
    /// The SwiftIdentity authentication the connection was admitted with, when its verifier
    /// attached one.
    public var authentication: Authentication? {
        verification as? Authentication
    }
}
