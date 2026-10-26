// SignInErrorTests.swift
// SwiftCLIKitAuthTests
// Created by Justin Purnell on 2026-10-25.

import Testing
import SwiftCLIKitAuth

@Suite("SignInError")
struct SignInErrorTests {

    @Test("A refusal carries no reason")
    func refusalIsCoarse() {
        #expect(String(describing: SignInError.failed) == "failed")
    }
}
