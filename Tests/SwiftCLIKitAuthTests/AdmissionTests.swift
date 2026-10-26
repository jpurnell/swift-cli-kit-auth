// AdmissionTests.swift
// SwiftCLIKitAuthTests
// Created by Justin Purnell on 2026-10-25.

import Testing
import Foundation
import SwiftIdentity
import SwiftCLIKitAuth

@Suite("Admission")
struct AdmissionTests {

    private static func adaByPassword() async throws -> Authentication {
        try await Fixture.authentication([Passphrase(subjectID: "ada", secret: "right")])
    }

    @Test("anyone admits every authenticated subject")
    func anyone() async throws {
        #expect(await Admission.anyone.admits(try await Self.adaByPassword()))
    }

    @Test("subjects admits only the listed ids")
    func subjects() async throws {
        let ada = try await Self.adaByPassword()
        let grace = try await Fixture.authentication([BearerKey("grace-key")])
        let rule = Admission.subjects(["ada"])
        #expect(await rule.admits(ada))
        #expect(await !rule.admits(grace))
    }

    @Test("attribute admits a subject whose attribute has the value, exactly")
    func attribute() async throws {
        let ada = try await Self.adaByPassword()
        #expect(await Admission.attribute("team", equals: "ops").admits(ada))
        #expect(await !Admission.attribute("team", equals: "Ops").admits(ada))
        #expect(await !Admission.attribute("missing", equals: "ops").admits(ada))
    }

    @Test("minimumAssurance compares the computed assurance")
    func minimumAssurance() async throws {
        let single = try await Self.adaByPassword()
        let multi = try await Fixture.authentication([
            Passphrase(subjectID: "ada", secret: "right"), OneTimeCode(subjectID: "ada", code: "123456"),
        ])
        #expect(multi.assurance == .multiFactor)
        #expect(await Admission.minimumAssurance(.singleFactor).admits(single))
        #expect(await !Admission.minimumAssurance(.multiFactor).admits(single))
        #expect(await Admission.minimumAssurance(.multiFactor).admits(multi))
        #expect(await !Admission.minimumAssurance(.phishingResistant).admits(multi))
    }

    @Test("factors requires every factor to name an algorithm the rule accepts")
    func factors() async throws {
        let password = try await Self.adaByPassword()
        let bearer = try await Fixture.authentication([BearerKey("ada-key")])   // no algorithm recorded
        let pbkdf2Only = Admission.factors { $0.algorithm?.hasPrefix("pbkdf2") == true }
        let acceptAll = Admission.factors { _ in true }
        #expect(await pbkdf2Only.admits(password))
        #expect(await !Admission.factors { $0.algorithm == "-7" }.admits(password))
        #expect(await !acceptAll.admits(bearer), "a factor with no recorded algorithm fails the rule")
    }

    @Test("custom runs the app's own decision")
    func custom() async throws {
        let ada = try await Self.adaByPassword()
        #expect(await Admission.custom { $0.subject.id.count == 3 }.admits(ada))
        #expect(await !Admission.custom { _ in false }.admits(ada))
    }

    @Test("all admits only when every rule does, and an empty list admits no one")
    func all() async throws {
        let ada = try await Self.adaByPassword()
        #expect(await Admission.all([.subjects(["ada"]), .attribute("team", equals: "ops")]).admits(ada))
        #expect(await !Admission.all([.subjects(["ada"]), .minimumAssurance(.multiFactor)]).admits(ada))
        #expect(await !Admission.all([]).admits(ada))
    }
}
