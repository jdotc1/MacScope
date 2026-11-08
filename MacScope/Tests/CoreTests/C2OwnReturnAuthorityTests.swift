import Foundation
import XCTest
@testable import MacScope

final class C2OwnReturnAuthorityTests: XCTestCase {
    private typealias A = C2OwnReturnAuthority
    private let uuid = "11111111-2222-3333-4444-555555555555"
    private func row(_ start: String, _ type: String) -> A.Row {
        .init(start_hex: start, name: "_same_name", source_file_line: "synthetic.c:1",
              declared_return_as_written: "LOCAL(\(type)) -> static \(type)", precision_variant: "n/a",
              identity_method: "SYNTHETIC", identity_evidence: "synthetic reviewed identity",
              verdict: "BOUND", confidence_note: "synthetic only", return_type_for_override: type,
              value_class: type == "void" ? "void" : "integer")
    }
    private func expectation() -> A.Expectation {
        .init(source: .init(url: "synthetic", version: "1", sha256: "not-a-runtime-digest"),
              evidenceCensusHead: "synthetic", image: .init(uuid: uuid, installName: "synthetic", architecture: "arm64"),
              slot: "primary", records: [row("0x1000", "void"), row("0x2000", "int")])
    }
    private func envelope(_ expected: A.Expectation) -> A.Envelope {
        .init(schemaVersion: 1, source: expected.source, evidenceCensusHead: expected.evidenceCensusHead,
              image: expected.image, slot: expected.slot, functions: expected.records)
    }
    private func snapshot() -> WorkspaceSnapshot {
        var analysis = ImageAnalysis()
        for start in [UInt64(0x1000), UInt64(0x2000), UInt64(0x3000)] {
            analysis.functions.append(.init(id: UUID(), name: "_same_name", startAddress: start,
                                            endAddress: start + 8, confidence: 1))
        }
        var binary = BinaryImage(id: UUID(), name: "synthetic", path: "/synthetic", kind: "Mach-O", architecture: "arm64")
        binary.metadata.uuid = uuid
        return WorkspaceSnapshot(binaries: [binary], analysisBySlot: [.primary: analysis])
    }
    private func apply(_ envelope: A.Envelope, _ original: WorkspaceSnapshot,
                       expected: A.Expectation) throws -> A.Result {
        try A.applying(data: JSONEncoder().encode(envelope), to: original, expected: expected)
    }
    private func reject(_ envelope: A.Envelope, _ original: WorkspaceSnapshot,
                        expected: A.Expectation, file: StaticString = #filePath, line: UInt = #line) {
        let overrides = original.addressOverrides
        let imports = original.importedPrototypes
        XCTAssertThrowsError(try apply(envelope, original, expected: expected), file: file, line: line)
        XCTAssertEqual(original.addressOverrides, overrides, file: file, line: line)
        XCTAssertEqual(original.importedPrototypes, imports, file: file, line: line)
    }
    private func lifted(_ snapshot: WorkspaceSnapshot, start: UInt64, value: Bool = false) -> MacIRFunction {
        var rows: [InstructionRow] = []
        if value { rows.append(.init(address: start, bytes: "e0 00 80 52", mnemonic: "mov", operands: "w0, #7", hasBreakpoint: false, comment: nil)) }
        rows.append(.init(address: start + (value ? 4 : 0), bytes: "c0 03 5f d6", mnemonic: "ret", operands: "", hasBreakpoint: false, comment: nil))
        return MacIRConfiguration.$returnContractOverride.withValue(false) {
            PseudocodePrinter().buildFunction(functionName: "same_name", startAddress: start,
                signatureOverrides: snapshot.functionSignatureOverrides(in: .primary),
                explicitCFGEnabled: false, ssaEnabled: false, instructions: rows)
        }
    }
    private func returnOperand(_ function: MacIRFunction) throws -> MacIRValue? {
        for instruction in function.instructions {
            if case let .returnValue(value) = instruction.operation { return value }
        }
        XCTFail("synthetic ret must be lifted")
        throw A.Rejection("missing synthetic ret")
    }

    func testUnsetReturnsSnapshotUnchangedWithoutLoadingAFile() throws {
        var original = snapshot()
        original.addressOverrides[.primary(0x3000)] = AddressOverride(customComment: "untouched")
        original.importedPrototypes[.primary(0x1000)] = .init(returnType: "double")
        let result = try A.load(into: original, environment: [:])
        XCTAssertNil(result.report)
        XCTAssertEqual(result.snapshot.addressOverrides, original.addressOverrides)
        XCTAssertEqual(result.snapshot.importedPrototypes, original.importedPrototypes)
        XCTAssertEqual(result.snapshot.binaries, original.binaries)
        XCTAssertEqual(result.snapshot.functions, original.functions)
    }
    func testVoidRowActuallyConsumesOwnReturnToken() throws {
        let original = snapshot(), expected = expectation()
        XCTAssertEqual(try returnOperand(lifted(original, start: 0x1000)), .unknown("unresolved_return_contract"))
        let result = try apply(envelope(expected), original, expected: expected)
        XCTAssertNil(try returnOperand(lifted(result.snapshot, start: 0x1000)))
        let signature = try XCTUnwrap(result.snapshot.addressOverrides[.primary(0x1000)]?.signature)
        XCTAssertEqual(signature.parameterList, .unspecified)
        XCTAssertEqual(signature.variadicState, .unspecified)
        XCTAssertEqual(signature.noReturnState, .unspecified)
    }
    func testNonvoidRowConsumesTokenButDoesNotInventMissingReturnValue() throws {
        let original = snapshot(), expected = expectation()
        XCTAssertEqual(try returnOperand(lifted(original, start: 0x2000)), .unknown("unresolved_return_contract"))
        let result = try apply(envelope(expected), original, expected: expected)
        XCTAssertEqual(try returnOperand(lifted(result.snapshot, start: 0x2000)), .unknown("unbound_return_w0"))
        let available = try returnOperand(lifted(result.snapshot, start: 0x2000, value: true))
        XCTAssertNotNil(available)
        if case .unknown? = available { XCTFail("synthetic modeled w0 producer must remain a returned value") }
        let signature = try XCTUnwrap(result.snapshot.addressOverrides[.primary(0x2000)]?.signature)
        XCTAssertEqual(signature.returnType, "int")
        XCTAssertEqual(signature.parameterList, .unspecified)
        XCTAssertEqual(signature.variadicState, .unspecified)
        XCTAssertEqual(signature.noReturnState, .unspecified)
    }
    func testSameNameSiblingAtAnotherStartRemainsUnbound() throws {
        let original = snapshot(), expected = expectation()
        let result = try apply(envelope(expected), original, expected: expected)
        XCTAssertNil(result.snapshot.addressOverrides[.primary(0x3000)])
        XCTAssertEqual(try returnOperand(lifted(result.snapshot, start: 0x3000)), .unknown("unresolved_return_contract"))
    }
    func testRejectsVerdictEmptyTypeAndSelfAttestedSourceTypeTransactionally() {
        let original = snapshot(), expected = expectation()
        for mutation in 0..<5 {
            var file = envelope(expected)
            switch mutation {
            case 0: file.functions[1].verdict = "AMBIGUOUS"
            case 1: file.functions[1].return_type_for_override = ""
            case 2: file.functions[1].return_type_for_override = "void"; file.functions[1].declared_return_as_written = "LOCAL(void) -> static void"
            case 3: file.functions[1].source_file_line = "synthetic.c:99"
            default: file.functions[1].precision_variant = "12"
            }
            reject(file, original, expected: expected)
        }
    }
    func testRejectsDuplicateNoncohortMissingFunctionAndWrongName() {
        let original = snapshot(), expected = expectation()
        var file = envelope(expected)
        file.functions[1] = file.functions[0]
        reject(file, original, expected: expected)
        file = envelope(expected); file.functions[1].start_hex = "0x3000"
        reject(file, original, expected: expected)
        file = envelope(expected); file.functions[1].start_hex = "0X2000"
        reject(file, original, expected: expected)
        file = envelope(expected); file.functions.removeLast()
        reject(file, original, expected: expected)
        var missing = original
        missing.functions.removeAll { $0.startAddress == 0x2000 }
        reject(envelope(expected), missing, expected: expected)
        var wrongName = original
        wrongName.functions[1].name = "different"
        reject(envelope(expected), wrongName, expected: expected)
    }
    func testRejectsSlotUUIDArchitectureSourceAndSchemaMismatch() {
        let original = snapshot(), expected = expectation()
        for mutation in 0..<6 {
            var file = envelope(expected)
            switch mutation {
            case 0: file.slot = "secondary"
            case 1: file.image.uuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
            case 2: file.image.architecture = "x86_64"
            case 3: file.source.version = "different"
            case 4: file.schemaVersion = 2
            default: file.image.installName = "different"
            }
            reject(file, original, expected: expected)
        }
        var loadedWrongUUID = original
        loadedWrongUUID.binaries[0].metadata.uuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        reject(envelope(expected), loadedWrongUUID, expected: expected)
        var loadedWrongArch = original
        loadedWrongArch.binaries[0].architecture = "x86_64"
        reject(envelope(expected), loadedWrongArch, expected: expected)
    }
    func testAuthoredConflictAndFullImportedDisplacementPrecedence() throws {
        let expected = expectation()
        var original = snapshot()
        let imported = FunctionSignatureOverride(returnType: "double",
            parameterList: .authoritative([ArgOverride(index: 0, name: "argument", type: "int")]),
            variadicState: .variadic,
            quarantinedLegacyArgs: [LegacyArgOverride(originalIndex: 7, originalOrder: 0, name: "legacy", type: "char *")],
            noReturnState: .noReturn)
        original.importedPrototypes[.primary(0x1000)] = imported
        let result = try apply(envelope(expected), original, expected: expected)
        XCTAssertEqual(result.snapshot.importedPrototypes[.primary(0x1000)], imported)
        XCTAssertEqual(result.snapshot.functionSignatureOverrides(in: .primary)[0x1000], .init(returnType: "void"))
        XCTAssertEqual(result.report?.displacedImported.count, 1)
        XCTAssertEqual(result.report?.displacedImported.first?.signature, imported)
        let encodedReport = try JSONEncoder().encode(XCTUnwrap(result.report))
        let decodedReport = try JSONDecoder().decode(A.Report.self, from: encodedReport)
        XCTAssertEqual(decodedReport.displacedImported.first?.signature, imported)
        original.addressOverrides[.primary(0x2000)] = AddressOverride(signature: .init(returnType: "void"))
        reject(envelope(expected), original, expected: expected)
    }
    func testPreservesUnrelatedAddressOverrideFieldsAndEqualAuthoredRow() throws {
        let expected = expectation()
        var original = snapshot()
        let before = AddressOverride(customName: "my_name", customComment: "my_comment", tag: "my_tag",
            signature: .init(returnType: "void"), appliedTypeName: "my_type", markAsProcedure: true,
            registerNames: ["x19": "saved"], localLabel: "my_label")
        original.addressOverrides[.primary(0x1000)] = before
        let sibling = AddressOverride(customComment: "sibling", signature: .init(returnType: "double"))
        original.addressOverrides[.primary(0x3000)] = sibling
        let result = try apply(envelope(expected), original, expected: expected)
        XCTAssertEqual(result.snapshot.addressOverrides[.primary(0x1000)], before)
        XCTAssertEqual(result.snapshot.addressOverrides[.primary(0x3000)], sibling)
        XCTAssertEqual(original.addressOverrides[.primary(0x1000)], before)
    }

    private func invariant(_ original: A.Row) -> A.Row {
        var result = original
        result.verdict = "RETURN_INVARIANT"
        result.identity_class = "RETURN_INVARIANT"
        result.candidate_set_complete = true
        result.candidate_definitions = ["first.c:10", "second.c:20"].map { definition in
            A.Candidate(definition: definition, translationUnit: definition,
                precision: "n/a", symbol: "same_name", returnType: original.return_type_for_override,
                expandedReturnType: original.return_type_for_override,
                returnDependsOnPrecision: false, evidence: "synthetic complete candidate manifest")
        }
        return result
    }
    private func invariantExpectation() -> A.Expectation {
        var result = expectation()
        result.records = result.records.map { invariant($0) }
        return result
    }

    func testLegacyBoundRowsDecodeWithoutCandidateMetadata() throws {
        let expected = expectation(), original = snapshot()
        let data = try JSONEncoder().encode(envelope(expected))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        var records = try XCTUnwrap(object["functions"] as? [[String: Any]])
        for index in records.indices {
            records[index].removeValue(forKey: "identity_class")
            records[index].removeValue(forKey: "candidate_definitions")
            records[index].removeValue(forKey: "candidate_set_complete")
        }
        object["functions"] = records
        let decoded = try JSONDecoder().decode(A.Envelope.self,
            from: JSONSerialization.data(withJSONObject: object))
        XCTAssertEqual(decoded.functions, expected.records)
        let result = try apply(decoded, original, expected: expected)
        XCTAssertEqual(result.report?.appliedStartsByAuthorityClass["BOUND"], ["0x1000", "0x2000"])
        XCTAssertNil(result.report?.appliedStartsByAuthorityClass["RETURN_INVARIANT"])
    }
    func testReturnInvariantVoidConsumesOnlyOwnReturnToken() throws {
        let expected = invariantExpectation(), original = snapshot()
        XCTAssertEqual(try returnOperand(lifted(original, start: 0x1000)), .unknown("unresolved_return_contract"))
        let result = try apply(envelope(expected), original, expected: expected)
        XCTAssertNil(try returnOperand(lifted(result.snapshot, start: 0x1000)))
        let signature = try XCTUnwrap(result.snapshot.addressOverrides[.primary(0x1000)]?.signature)
        XCTAssertEqual(signature, FunctionSignatureOverride(returnType: "void"))
        XCTAssertEqual(signature.parameterList, .unspecified)
        XCTAssertEqual(signature.variadicState, .unspecified)
        XCTAssertEqual(signature.noReturnState, .unspecified)
        XCTAssertEqual(result.report?.appliedStartsByAuthorityClass["RETURN_INVARIANT"], ["0x1000", "0x2000"])
    }
    func testReturnInvariantNonvoidDoesNotInventCarrier() throws {
        let expected = invariantExpectation(), original = snapshot()
        XCTAssertEqual(try returnOperand(lifted(original, start: 0x2000)), .unknown("unresolved_return_contract"))
        let result = try apply(envelope(expected), original, expected: expected)
        XCTAssertEqual(try returnOperand(lifted(result.snapshot, start: 0x2000)), .unknown("unbound_return_w0"))
        let available = try returnOperand(lifted(result.snapshot, start: 0x2000, value: true))
        XCTAssertNotNil(available)
        if case .unknown? = available { XCTFail("Modeled return carrier must remain a value") }
        XCTAssertEqual(result.snapshot.addressOverrides[.primary(0x2000)]?.signature,
                       FunctionSignatureOverride(returnType: "int"))
    }
    func testReturnInvariantMixedCandidateSetIsRejectedEvenWhenCatalogMatches() {
        let original = snapshot()
        var expected = invariantExpectation()
        expected.records[1].candidate_definitions?[0].returnType = "void"
        expected.records[1].candidate_definitions?[0].expandedReturnType = "void"
        // Equality to a bad manifest is insufficient: the validator must check uniformity itself.
        reject(envelope(expected), original, expected: expected)
    }
    func testReturnInvariantOmittedCandidateIsRejectedTransactionally() {
        let expected = invariantExpectation(), original = snapshot()
        var file = envelope(expected)
        file.functions[1].candidate_definitions?.removeLast()
        reject(file, original, expected: expected)
    }
    func testReturnInvariantAddedCandidateIsRejectedTransactionally() {
        let expected = invariantExpectation(), original = snapshot()
        var file = envelope(expected)
        file.functions[1].candidate_definitions?.append(.init(definition: "extra.c:30",
            translationUnit: "extra.c", precision: "n/a", symbol: "same_name",
            returnType: "int", expandedReturnType: "int", returnDependsOnPrecision: false,
            evidence: "not in compiled catalog"))
        reject(file, original, expected: expected)
    }
    func testAuthorityClassesCannotBeInterchanged() {
        let original = snapshot()
        let invariantExpected = invariantExpectation()
        var file = envelope(invariantExpected)
        file.functions[1].identity_class = "BOUND"
        reject(file, original, expected: invariantExpected)
        file.functions[1].verdict = "BOUND"
        file.functions[1].candidate_definitions = nil
        file.functions[1].candidate_set_complete = nil
        reject(file, original, expected: invariantExpected)
        let boundExpected = expectation()
        file = envelope(boundExpected)
        file.functions[1] = invariant(file.functions[1])
        reject(file, original, expected: boundExpected)
    }
    func testDuplicateStartAcrossAuthorityClassesIsRejected() {
        let original = snapshot()
        var expected = expectation()
        expected.records[1] = invariant(expected.records[1])
        var file = envelope(expected)
        file.functions[1].start_hex = file.functions[0].start_hex
        reject(file, original, expected: expected)
    }
    func testReturnInvariantLeavesSameNameUnlistedSiblingUnchanged() throws {
        let expected = invariantExpectation(), original = snapshot()
        let result = try apply(envelope(expected), original, expected: expected)
        XCTAssertNil(result.snapshot.addressOverrides[.primary(0x3000)])
        XCTAssertEqual(try returnOperand(lifted(result.snapshot, start: 0x3000)), .unknown("unresolved_return_contract"))
    }
    func testUnsetAuthorityStillReturnsIdentityAfterClassExtension() throws {
        var original = snapshot()
        original.addressOverrides[.primary(0x3000)] = AddressOverride(customComment: "preserved")
        original.importedPrototypes[.primary(0x1000)] = .init(returnType: "double")
        let result = try A.load(into: original, environment: [:])
        XCTAssertNil(result.report)
        XCTAssertEqual(result.snapshot.addressOverrides, original.addressOverrides)
        XCTAssertEqual(result.snapshot.importedPrototypes, original.importedPrototypes)
        XCTAssertEqual(result.snapshot.binaries, original.binaries)
        XCTAssertEqual(result.snapshot.functions, original.functions)
    }
    func testReturnInvariantRequiresCompletePrecisionIndependentCandidates() {
        let original = snapshot()
        for mutation in 0..<5 {
            var expected = invariantExpectation()
            switch mutation {
            case 0: expected.records[1].candidate_set_complete = false
            case 1: expected.records[1].candidate_definitions = []
            case 2: expected.records[1].candidate_definitions?[0].returnDependsOnPrecision = true
            case 3: expected.records[1].candidate_definitions?[0].expandedReturnType = "unsigned int"
            default: expected.records[1].candidate_definitions?[0].symbol = "another_name"
            }
            reject(envelope(expected), original, expected: expected)
        }
    }

    private func guardIsolationSnapshot() -> WorkspaceSnapshot {
        var original = snapshot()
        original.addressOverrides[.primary(0x3000)] = AddressOverride(customComment: "guard sentinel")
        original.importedPrototypes[.primary(0x1000)] = .init(returnType: "double")
        return original
    }

    private func reviewedGuardIsolationSnapshot() throws -> WorkspaceSnapshot {
        let expected = A.Expectation.reviewed
        var original = guardIsolationSnapshot()
        original.binaries[0].metadata.uuid = expected.image.uuid
        original.binaries[0].architecture = expected.image.architecture
        original.functions = []
        for item in expected.records {
            let start = try XCTUnwrap(UInt64(item.start_hex.dropFirst(2), radix: 16))
            original.functions.append(.init(id: UUID(), name: item.name, startAddress: start,
                                            endAddress: start + 8, confidence: 1))
        }
        return original
    }

    private func rejectGuard(_ fileEnvelope: A.Envelope, _ original: WorkspaceSnapshot,
                             expected: A.Expectation, reason: String,
                             file: StaticString = #filePath, line: UInt = #line) {
        assertGuardRejection(original, reason: reason, file: file, line: line) {
            try apply(fileEnvelope, original, expected: expected)
        }
    }

    private func assertGuardRejection(_ original: WorkspaceSnapshot, reason: String,
                                      file: StaticString = #filePath, line: UInt = #line,
                                      operation: () throws -> A.Result) {
        let overrides = original.addressOverrides, imports = original.importedPrototypes
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            guard let rejection = error as? A.Rejection else {
                return XCTFail("Expected A.Rejection, got \(type(of: error)): \(error)", file: file, line: line)
            }
            XCTAssertEqual(rejection.description, "own-return authority rejected: " + reason,
                           file: file, line: line)
        }
        XCTAssertEqual(original.addressOverrides, overrides, file: file, line: line)
        XCTAssertEqual(original.importedPrototypes, imports, file: file, line: line)
    }

    private func assertGuardSystemError(_ original: WorkspaceSnapshot,
                                        isExpected: (Error) -> Bool,
                                        file: StaticString = #filePath, line: UInt = #line,
                                        operation: () throws -> A.Result) {
        let overrides = original.addressOverrides, imports = original.importedPrototypes
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            XCTAssertFalse(error is A.Rejection, "Expected a system/decoding error", file: file, line: line)
            XCTAssertTrue(isExpected(error), "Unexpected error type: \(type(of: error)): \(error)",
                          file: file, line: line)
        }
        XCTAssertEqual(original.addressOverrides, overrides, file: file, line: line)
        XCTAssertEqual(original.importedPrototypes, imports, file: file, line: line)
    }

    func testGuardIsolationBlankPath() throws {
        let original = guardIsolationSnapshot()
        for path in ["", " \t\n"] {
            assertGuardRejection(original, reason: "empty authority path") {
                try A.load(into: original, environment: [A.environmentKey: path])
            }
        }
    }

    func testGuardIsolationFileReadError() throws {
        let original = try reviewedGuardIsolationSnapshot()
        assertGuardSystemError(original, isExpected: { ($0 as NSError).domain == NSCocoaErrorDomain }) {
            try A.load(into: original, environment: [A.environmentKey: "/dev/null/authority.json"])
        }
    }

    func testGuardIsolationDecodeError() throws {
        let original = guardIsolationSnapshot(), expected = expectation()
        assertGuardSystemError(original, isExpected: { $0 is DecodingError }) {
            try A.applying(data: Data("{}".utf8), to: original, expected: expected)
        }
    }

    func testGuardIsolationExpectedSlot() throws {
        let original = guardIsolationSnapshot()
        var expected = expectation()
        expected.slot = "secondary"
        var file = envelope(expected)
        file.slot = "primary"
        rejectGuard(file, original, expected: expected, reason: "slot")
    }

    func testGuardIsolationSnapshotPrimarySlot() throws {
        var original = guardIsolationSnapshot()
        var secondary = original.binaries[0]
        secondary.slot = ImageSlot(rawValue: 1)
        original.binaries.insert(secondary, at: 0)
        let expected = expectation()
        rejectGuard(envelope(expected), original, expected: expected, reason: "slot")
    }

    func testGuardIsolationCensusHead() throws {
        let original = guardIsolationSnapshot(), expected = expectation()
        var file = envelope(expected)
        file.evidenceCensusHead = "different"
        rejectGuard(file, original, expected: expected, reason: "reviewed source/image identity")
    }

    func testGuardIsolationSinglePrimary() throws {
        var original = guardIsolationSnapshot()
        let duplicate = original.binaries[0]
        original.binaries.append(duplicate)
        let expected = expectation()
        rejectGuard(envelope(expected), original, expected: expected,
                    reason: "loaded image UUID/architecture/slot")
    }

    func testGuardIsolationUUIDPresence() throws {
        var original = guardIsolationSnapshot()
        original.binaries[0].metadata.uuid = nil
        let expected = expectation()
        rejectGuard(envelope(expected), original, expected: expected,
                    reason: "loaded image UUID/architecture/slot")
    }

    func testGuardIsolationUUIDSyntax() throws {
        var original = guardIsolationSnapshot()
        var expected = expectation()
        expected.image.uuid = "not-a-uuid"
        original.binaries[0].metadata.uuid = "not-a-uuid"
        rejectGuard(envelope(expected), original, expected: expected,
                    reason: "loaded image UUID/architecture/slot")
    }

    func testGuardIsolationAnalysisPresence() throws {
        let seeded = guardIsolationSnapshot()
        var original = WorkspaceSnapshot(binaries: seeded.binaries, analysisBySlot: [:])
        original.addressOverrides = seeded.addressOverrides
        original.importedPrototypes = seeded.importedPrototypes
        let expected = expectation()
        rejectGuard(envelope(expected), original, expected: expected,
                    reason: "loaded image UUID/architecture/slot")
    }

    func testGuardIsolationCompiledClassGate() throws {
        let original = guardIsolationSnapshot()
        var expected = expectation()
        expected.records[1].identity_class = "OTHER"
        expected.records[1].verdict = "OTHER"
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationCompiledEmptyType() throws {
        let original = guardIsolationSnapshot()
        var expected = expectation()
        expected.records[1].return_type_for_override = ""
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationCompiledDuplicate() throws {
        let original = guardIsolationSnapshot()
        var expected = expectation()
        expected.records[1] = expected.records[0]
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationEmptyCatalog() throws {
        let original = guardIsolationSnapshot()
        var expected = expectation()
        expected.records = []
        rejectGuard(envelope(expected), original, expected: expected, reason: "complete reviewed cohort required")
    }

    func testGuardIsolationFileCohortCount() throws {
        let original = guardIsolationSnapshot(), expected = expectation()
        var file = envelope(expected)
        file.functions = []
        rejectGuard(file, original, expected: expected, reason: "complete reviewed cohort required")
    }

    func testGuardIsolationDuplicateFileStart() throws {
        let original = guardIsolationSnapshot(), expected = expectation()
        var file = envelope(expected)
        file.functions[1] = file.functions[0]
        rejectGuard(file, original, expected: expected, reason: "duplicate start 0x1000")
    }

    func testGuardIsolationWhitespaceType() throws {
        let original = guardIsolationSnapshot()
        var expected = expectation()
        expected.records[1].return_type_for_override = " \t\n"
        rejectGuard(envelope(expected), original, expected: expected, reason: "noncohort or source/type/evidence mismatch 0x2000")
    }

    func testGuardIsolationCatalogMembership() throws {
        let original = guardIsolationSnapshot(), expected = expectation()
        var file = envelope(expected)
        file.functions[1].start_hex = "0x3000"
        rejectGuard(file, original, expected: expected,
                    reason: "noncohort or source/type/evidence mismatch 0x3000")
    }

    func testGuardIsolationDuplicateLoadedStart() throws {
        var original = guardIsolationSnapshot()
        let duplicate = original.functions[0]
        original.functions.append(duplicate)
        let expected = expectation()
        rejectGuard(envelope(expected), original, expected: expected,
                    reason: "not an exact loaded function start/name 0x1000")
    }

    func testGuardIsolationVerdictMatchesClass() throws {
        let original = guardIsolationSnapshot()
        var expected = expectation()
        expected.records[1].verdict = "OTHER"
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationBoundCandidateDefinitions() throws {
        let original = guardIsolationSnapshot()
        var expected = expectation()
        expected.records[1].candidate_definitions = []
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationBoundCompletenessField() throws {
        let original = guardIsolationSnapshot()
        var expected = expectation()
        expected.records[1].candidate_set_complete = false
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationCandidateListPresence() throws {
        let original = guardIsolationSnapshot()
        var expected = invariantExpectation()
        expected.records[1].candidate_definitions = nil
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationRowReturnExpansion() throws {
        let original = guardIsolationSnapshot()
        var expected = invariantExpectation()
        expected.records[1].return_type_for_override = "float"
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationInvariantValueClass() throws {
        let original = guardIsolationSnapshot()
        var expected = invariantExpectation()
        expected.records[1].value_class = "void"
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationCandidateDefinition() throws {
        let original = guardIsolationSnapshot()
        var expected = invariantExpectation()
        expected.records[1].candidate_definitions?[0].definition = ""
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationCandidateTranslationUnit() throws {
        let original = guardIsolationSnapshot()
        var expected = invariantExpectation()
        expected.records[1].candidate_definitions?[0].translationUnit = ""
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationCandidatePrecision() throws {
        let original = guardIsolationSnapshot()
        var expected = invariantExpectation()
        expected.records[1].candidate_definitions?[0].precision = ""
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationCandidateEvidence() throws {
        let original = guardIsolationSnapshot()
        var expected = invariantExpectation()
        expected.records[1].candidate_definitions?[0].evidence = ""
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationCandidateDeclaredReturn() throws {
        let original = guardIsolationSnapshot()
        var expected = invariantExpectation()
        expected.records[1].candidate_definitions?[0].returnType = "void"
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationCandidateInstanceUnique() throws {
        let original = guardIsolationSnapshot()
        var expected = invariantExpectation()
        let first = expected.records[1].candidate_definitions![0]
        expected.records[1].candidate_definitions = [first, first]
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationUnknownIdentityClass() throws {
        let original = guardIsolationSnapshot()
        var expected = expectation()
        expected.records[1].identity_class = "OTHER"
        expected.records[1].verdict = "OTHER"
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }

    func testGuardIsolationCanonicalStartRoundTrip() throws {
        let original = guardIsolationSnapshot()
        var expected = expectation()
        expected.records[1].start_hex = "0x02000"
        rejectGuard(envelope(expected), original, expected: expected, reason: "noncanonical start 0x02000")
    }

    func testGuardIsolationMixedClassReport() throws {
        let original = guardIsolationSnapshot()
        var expected = expectation()
        expected.records = [row("0x3000", "void"), invariant(row("0x2000", "int")), row("0x1000", "void")]
        let overrides = original.addressOverrides, imports = original.importedPrototypes
        let result = try apply(envelope(expected), original, expected: expected)
        let report = try XCTUnwrap(result.report)
        XCTAssertEqual(report.appliedStartsByAuthorityClass,
                       ["BOUND": ["0x1000", "0x3000"], "RETURN_INVARIANT": ["0x2000"]])
        XCTAssertEqual(report.appliedStarts, ["0x1000", "0x2000", "0x3000"])
        XCTAssertEqual(original.addressOverrides, overrides)
        XCTAssertEqual(original.importedPrototypes, imports)
    }

    func testGuardIsolationUnsupportedReturnWhitelist() throws {
        let original = guardIsolationSnapshot()
        var expected = invariantExpectation()
        expected.records[1].return_type_for_override = "float"
        rejectGuard(envelope(expected), original, expected: expected, reason: "invalid compiled expected catalog")
    }
}
