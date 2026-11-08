import Foundation
import XCTest
@testable import MacScope

final class OwnReturnAuthorityProductTests: XCTestCase {
    private typealias P = OwnReturnAuthority
    private typealias C = C2OwnReturnAuthority
    private let imageUUID = "11111111-2222-3333-4444-555555555555"

    private func row(_ start: String, _ type: String) -> P.Row {
        .init(start_hex: start, name: "_same_name", source_file_line: "synthetic.c:1",
              declared_return_as_written: type, precision_variant: "n/a",
              identity_method: "SYNTHETIC", identity_evidence: "user-supplied synthetic evidence",
              verdict: "BOUND", confidence_note: "synthetic only",
              return_type_for_override: type, value_class: type == "void" ? "void" : "integer")
    }
    private func envelope() -> P.Envelope {
        .init(schemaVersion: 1,
              source: .init(url: "synthetic", version: "1", sha256: "not-a-runtime-digest"),
              evidenceCensusHead: "synthetic",
              image: .init(uuid: imageUUID, installName: "synthetic", architecture: "arm64"),
              slot: "primary", functions: [row("0x1000", "void"), row("0x2000", "int")])
    }
    private func snapshot() -> WorkspaceSnapshot {
        var analysis = ImageAnalysis()
        for start in [UInt64(0x1000), UInt64(0x2000), UInt64(0x3000)] {
            analysis.functions.append(.init(id: UUID(), name: "_same_name",
                startAddress: start, endAddress: start + 8, confidence: 1))
        }
        var binary = BinaryImage(id: UUID(), name: "synthetic", path: "/synthetic",
                                 kind: "Mach-O", architecture: "arm64")
        binary.metadata.uuid = imageUUID
        return WorkspaceSnapshot(binaries: [binary], analysisBySlot: [.primary: analysis])
    }
    private func withPreferences<T>(_ body: (UserDefaults) throws -> T) throws -> T {
        let name = "OwnReturnAuthorityProductTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        return try body(defaults)
    }
    private func apply(_ file: P.Envelope, to snapshot: WorkspaceSnapshot) throws -> P.Result {
        try P.applyingUserEvidence(data: JSONEncoder().encode(file), to: snapshot,
                                   file: "/synthetic/authority.json")
    }
    private func assertUnchanged(_ actual: WorkspaceSnapshot, _ expected: WorkspaceSnapshot,
                                 file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(actual.addressOverrides, expected.addressOverrides, file: file, line: line)
        XCTAssertEqual(actual.importedPrototypes, expected.importedPrototypes, file: file, line: line)
        XCTAssertEqual(actual.binaries, expected.binaries, file: file, line: line)
        XCTAssertEqual(actual.functions, expected.functions, file: file, line: line)
    }
    private func assertReason(_ reason: String, _ body: () throws -> Void,
                              file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            XCTAssertEqual((error as? P.Rejection)?.description,
                           "own-return authority rejected: " + reason, file: file, line: line)
        }
    }

    func testOffNeverInvokesLoaderAndPreservesSnapshot() throws {
        var original = snapshot()
        original.addressOverrides[.primary(0x3000)] = .init(customComment: "keep")
        original.importedPrototypes[.primary(0x1000)] = .init(returnType: "double")
        try withPreferences { defaults in
            var opened = false
            for flag in [Optional<String>.none, "0", "true"] {
                var environment = [P.pathEnvironmentKey: "/must/not/be/opened"]
                environment[P.flagEnvironmentKey] = flag
                let result = try P.load(into: original, environment: environment,
                                        defaults: defaults, readFile: { _ in
                    opened = true
                    XCTFail("off must never invoke the loader")
                    return Data()
                })
                XCTAssertFalse(opened)
                XCTAssertNil(result.report)
                assertUnchanged(result.snapshot, original)
            }
        }
    }

    func testPreferenceAndExactEnvironmentFlagFollowExistingPattern() throws {
        try withPreferences { defaults in
            XCTAssertFalse(P.enabled(environment: [:], defaults: defaults))
            XCTAssertTrue(P.enabled(environment: [P.flagEnvironmentKey: "1"], defaults: defaults))
            XCTAssertFalse(P.enabled(environment: [P.flagEnvironmentKey: "true"], defaults: defaults))
            defaults.set(true, forKey: P.flagKey)
            XCTAssertTrue(P.enabled(environment: [:], defaults: defaults))
            // Like the SSA pattern, environment "0" does not override a true preference.
            XCTAssertTrue(P.enabled(environment: [P.flagEnvironmentKey: "0"], defaults: defaults))
        }
        if MacIRConfiguration.installedTestBaseline != nil {
            XCTAssertFalse(P.enabled(environment: [P.flagEnvironmentKey: "1"], defaults: .standard))
        }
    }

    func testEnabledMissingOrBlankPathRejectsBeforeLoading() throws {
        try withPreferences { defaults in
            for path in [Optional<String>.none, "", " \n"] {
                var environment = [P.flagEnvironmentKey: "1"]
                environment[P.pathEnvironmentKey] = path
                assertReason("empty authority path") {
                    _ = try P.load(into: snapshot(), environment: environment, defaults: defaults,
                                   readFile: { _ in XCTFail("blank path opened"); return Data() })
                }
            }
        }
    }

    func testUUIDArchitectureAndSlotMismatchRejectTransactionally() throws {
        let original = snapshot()
        let before = original
        for mutation in 0..<3 {
            var file = envelope()
            switch mutation {
            case 0: file.image.uuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
            case 1: file.image.architecture = "arm64e"
            default: file.slot = "secondary"
            }
            assertReason(mutation == 2 ? "slot" : "loaded image UUID/architecture/slot") {
                _ = try apply(file, to: original)
            }
            assertUnchanged(original, before)
        }
    }

    func testLaterBadRowOrAuthoredConflictCannotPublishPartialResult() throws {
        for conflict in [false, true] {
            var live = snapshot()
            live.importedPrototypes[.primary(0x1000)] = .init(returnType: "double")
            live.addressOverrides[.primary(0x3000)] = .init(customComment: "keep")
            var file = envelope()
            if conflict {
                // This is authored directly, not created by the authority route.
                live.addressOverrides[.primary(0x2000)] = .init(signature:
                    .init(returnType: "int", parameterList: .authoritative([]), variadicState: .fixed))
            } else {
                file.functions[1].name = "wrong_name"
            }
            let before = live
            var report: P.Report?
            assertReason(conflict ? "conflicting authored signature 0x2000"
                                  : "not an exact loaded function start/name 0x2000") {
                let result = try apply(file, to: live)
                live = result.snapshot
                report = result.report
            }
            assertUnchanged(live, before)
            XCTAssertNil(report)
            XCTAssertNil(live.addressOverrides[.primary(0x1000)]?.ownReturnAuthorityFile)
            XCTAssertNil(live.addressOverrides[.primary(0x1000)]?.signature)
        }
    }

    func testSuccessMarksNewRowsPreservesImportedAndConsumesOwnReturn() throws {
        var original = snapshot()
        let imported = FunctionSignatureOverride(returnType: "double",
            parameterList: .authoritative([ArgOverride(index: 0, name: "a", type: "int")]),
            variadicState: .variadic,
            quarantinedLegacyArgs: [LegacyArgOverride(originalIndex: 7, originalOrder: 0,
                                                       name: "legacy", type: "char *")],
            noReturnState: .noReturn)
        original.importedPrototypes[.primary(0x1000)] = imported
        let result = try withPreferences { defaults in
            try P.load(into: original,
                environment: [P.flagEnvironmentKey: "1", P.pathEnvironmentKey: "/synthetic/authority.json"],
                defaults: defaults, readFile: { _ in try JSONEncoder().encode(envelope()) })
        }
        let applied = try XCTUnwrap(result.snapshot.addressOverrides[.primary(0x1000)])
        XCTAssertEqual(applied.ownReturnAuthorityFile, "/synthetic/authority.json")
        XCTAssertEqual(applied.signature, FunctionSignatureOverride(returnType: "void"))
        XCTAssertEqual(result.snapshot.importedPrototypes, original.importedPrototypes)
        XCTAssertEqual(result.report?.displacedImported.first?.signature, imported)
        XCTAssertNil(result.snapshot.addressOverrides[.primary(0x3000)])
        XCTAssertTrue(result.snapshot.authoredCallSignaturesByTarget(in: .primary).isEmpty)
        let instructions = [InstructionRow(address: 0x1000, bytes: "c0 03 5f d6",
            mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil)]
        let function = MacIRConfiguration.$returnContractOverride.withValue(false) {
            PseudocodePrinter().buildFunction(functionName: "same_name", startAddress: 0x1000,
                signatureOverrides: result.snapshot.functionSignatureOverrides(in: .primary),
                explicitCFGEnabled: false, ssaEnabled: false, instructions: instructions)
        }
        var sawReturn = false
        for instruction in function.instructions {
            if case let .returnValue(value) = instruction.operation {
                sawReturn = true
                XCTAssertNil(value)
            }
        }
        XCTAssertTrue(sawReturn)
        let second = try apply(envelope(), to: result.snapshot)
        XCTAssertEqual(second.snapshot.addressOverrides, result.snapshot.addressOverrides)
    }

    func testEqualAuthoredRowIsNotRelabelledAndMarkerIsTransient() throws {
        var original = snapshot()
        let before = AddressOverride(customComment: "user", signature: .init(returnType: "void"))
        original.addressOverrides[.primary(0x1000)] = before
        let result = try apply(envelope(), to: original)
        XCTAssertEqual(result.snapshot.addressOverrides[.primary(0x1000)], before)
        var marked = try XCTUnwrap(result.snapshot.addressOverrides[.primary(0x2000)])
        XCTAssertNotNil(marked.ownReturnAuthorityFile)
        let decoded = try JSONDecoder().decode(AddressOverride.self, from: JSONEncoder().encode(marked))
        XCTAssertNil(decoded.ownReturnAuthorityFile)
        XCTAssertEqual(decoded.signature, marked.signature)
        marked.signature?.returnType = "double"
        XCTAssertNil(marked.ownReturnAuthorityFile)
        marked.ownReturnAuthorityFile = "test"
        marked.signature = nil
        XCTAssertNil(marked.ownReturnAuthorityFile)
        var markerOnly = AddressOverride()
        markerOnly.ownReturnAuthorityFile = "test"
        XCTAssertTrue(markerOnly.isEmpty)
    }

    func testProductBoundsAndDuplicateRowsRefuse() throws {
        let original = snapshot()
        assertReason("authority file too large") {
            _ = try P.applyingUserEvidence(data: Data(repeating: 0, count: P.maximumBytes + 1),
                                          to: original, file: "synthetic")
        }
        var file = envelope()
        file.functions = []
        assertReason("empty authority cohort") { _ = try apply(file, to: original) }
        file = envelope()
        file.functions.append(file.functions[0])
        assertReason("duplicate start 0x1000") { _ = try apply(file, to: original) }
    }

    func testWrapperStillRequiresIndependentReviewedCatalogAndOrder() throws {
        let original = snapshot(), file = envelope()
        let expected = C.Expectation(source: file.source, evidenceCensusHead: file.evidenceCensusHead,
                                    image: file.image, slot: file.slot, records: file.functions)
        var changed = file
        changed.source.version = "self-attested"
        // Product accepts metadata labels; the wrapper must not trust them.
        _ = try apply(changed, to: original)
        assertReason("reviewed source/image identity") {
            _ = try C.applying(data: JSONEncoder().encode(changed), to: original, expected: expected)
        }
        changed = file
        changed.functions[1] = changed.functions[0]
        assertReason("duplicate start 0x1000") {
            _ = try C.applying(data: JSONEncoder().encode(changed), to: original, expected: expected)
        }
        changed = file
        changed.functions[1].identity_evidence = "not reviewed"
        assertReason("noncohort or source/type/evidence mismatch 0x2000") {
            _ = try C.applying(data: JSONEncoder().encode(changed), to: original, expected: expected)
        }
    }
}
