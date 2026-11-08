import CryptoKit
import Foundation
import XCTest
@testable import MacScope

/// Bytes pass through the real structured reader and service. The original
/// tracked fixtures remain unchanged; authored in-memory variants get new hashes.
final class UnwindAuditCFIControlIntegrationTests: XCTestCase {
    // First FDE in AIRSCFARegister has 19 program bytes and range [0x338, 0x34c).
    // The call observation is 0x340. Advances reach +4, +8 and the exact +20 end.
    private let allControls: [UInt8] = [
        0x02, 4, 0x0e, 16, 0x9d, 2, 0x9e, 1,
        0x03, 4, 0, 0x0a, 0x0b, 0x04, 12, 0, 0, 0
    ]
    private let restoredRule: [UInt8] = [
        0x02, 4, 0x0e, 16, 0x9d, 2, 0x9e, 1,
        0x0a, 0x07, 19, 0x0b, 0x03, 4, 0, 0x0d, 29
    ]

    func testReaderDecodesUnsignedFixedWidthsInLittleEndianOrder() throws {
        let cases: [([UInt8], UInt64)] = [
            ([0x02, 0x80], 128), ([0x03, 0, 1], 256),
            ([0x04, 0, 0, 1, 0], 65_536), ([0x03, 0xfc, 0xff], 65_532),
            ([0x04, 0xfc, 0xff, 0xff, 0xff], 4_294_967_292)
        ]
        for (encoded, delta) in cases {
            let table = try read(program: encoded + [0x0e, 8], size: delta + 4)
            let source = try XCTUnwrap(table.fdes.first)
            XCTAssertEqual(source.program.status, .complete)
            XCTAssertEqual(source.program.operations.first?.operands, [.unsigned(delta)])
            XCTAssertEqual(source.program.operations.first?.rawBytes, encoded)
            XCTAssertEqual(source.program.operations.map(\.sectionOffset), [45, 45 + encoded.count])
            let evaluator = try UnwindAuditCFI(table: table, enableCFIControls: true)
            let fde = try evaluator.select(offset: 20, start: 0x1000, end: 0x1000 + delta + 4)
            XCTAssertEqual(fde.rows.map(\.pc), [0x1000, 0x1000 + delta])
            XCTAssertEqual(try fde.row(at: 0x1000 + delta).offset, 8)
        }
    }

    func testReaderControlsHaveNoOperandsAndPreserveCurrentPCOnRestore() throws {
        let bytes: [UInt8] = [0x0a, 0x0e, 16, 0x02, 4, 0x0b, 0x03, 4, 0]
        let table = try read(program: bytes)
        let source = try XCTUnwrap(table.fdes.first)
        XCTAssertEqual(source.program.status, .complete)
        XCTAssertEqual(source.program.operations.map(\.opcode), [10, 14, 2, 11, 3])
        XCTAssertEqual(source.program.operations.map(\.operands), [
            [], [.unsigned(16)], [.unsigned(4)], [], [.unsigned(4)]
        ])
        XCTAssertEqual(source.program.operations.flatMap(\.rawBytes), bytes)
        let fde = try UnwindAuditCFI(table: table, enableCFIControls: true)
            .select(offset: 20, start: 0x1000, end: 0x1040)
        XCTAssertEqual(fde.rows.map(\.pc), [0x1000, 0x1004, 0x1008])
        XCTAssertEqual(fde.rows.map(\.offset), [16, 0, 0])
    }

    func testEveryFixedOperandTruncationIsMalformedAndRejectsThePrefix() throws {
        for (opcode, width) in [(UInt8(2), 1), (3, 2), (4, 4)] {
            for present in 0..<width {
                let table = try read(program: [0x0a, 0x0b, opcode] + Array(repeating: 0, count: present))
                let source = try XCTUnwrap(table.fdes.first)
                XCTAssertEqual(source.program.status, .malformed(offset: 47))
                XCTAssertEqual(source.program.operations.map(\.opcode), [10, 11])
                XCTAssertThrowsError(try UnwindAuditCFI(table: table, enableCFIControls: true))
            }
        }
    }

    func testReaderUnsupportedTailCannotBecomeACompleteControlProgram() throws {
        let table = try read(program: [0x02, 4, 0x0a, 0x0b, 0x3f, 0])
        let source = try XCTUnwrap(table.fdes.first)
        XCTAssertEqual(source.program.status, .unsupported(opcode: 0x3f))
        XCTAssertEqual(source.program.rawBytes, [0x02, 4, 0x0a, 0x0b, 0x3f, 0])
        XCTAssertThrowsError(try UnwindAuditCFI(table: table, enableCFIControls: true))
    }

    func testRealReaderCIEControlsAreDecodedButNeverAdmitted() throws {
        let controls: [[UInt8]] = [[0x44], [2, 4], [3, 4, 0], [4, 4, 0, 0, 0], [10], [11], [10, 11]]
        for control in controls {
            let table = try read(program: [], initialProgram: [0x0c, 31, 0] + control)
            XCTAssertEqual(table.cies.first?.initialProgram.status, .complete)
            XCTAssertThrowsError(try UnwindAuditCFI(table: table, enableCFIControls: true))
        }
    }

    func testServiceOptsIntoAllFixedAdvancesAndReportsOriginalCallPC() throws {
        let binary = try loadFixture(firstProgram: allControls)
        let report = try UnwindAuditService.audit(binary: binary, model: .boundedCFIControls)
        XCTAssertEqual(report.analysisModelVersion, "arm64-bounded-cfi-controls-v4")
        XCTAssertEqual(report.identity, binary.artifactIdentity)
        XCTAssertEqual(report.findings.count, 3)
        let finding = try firstFinding(report)
        XCTAssertEqual(finding.function.address, 0x338)
        XCTAssertEqual(finding.endAddress, 0x34c)
        XCTAssertEqual(finding.verdict, "agreement")
        XCTAssertEqual(finding.coverage, "dwarf_evaluated")
        XCTAssertEqual(finding.mode, "dwarf")
        XCTAssertEqual(finding.scope, "synchronous_call_sites")
        XCTAssertEqual(finding.instructionCount, 5)
        XCTAssertEqual(finding.checkedPCs, [0x340])
        XCTAssertEqual(finding.reasonCodes, ["supported_model_agreement"])
        XCTAssertTrue(finding.evidence.contains {
            $0.code == "dwarf_cfi_row" && $0.address == 0x340
                && $0.message.contains("row 0x340") && $0.message.contains("register 31+16")
        })
        let decoded = try JSONDecoder().decode(UnwindAuditReport.self, from: JSONEncoder().encode(report))
        XCTAssertEqual(decoded, report)
    }

    func testServiceRestoresRequiredRuleAndCFARetainsItsRegisterUpdate() throws {
        let binary = try loadFixture(firstProgram: restoredRule)
        let finding = try firstFinding(UnwindAuditService.audit(binary: binary, model: .boundedCFIControls))
        XCTAssertEqual(finding.verdict, "agreement")
        XCTAssertEqual(finding.checkedPCs, [0x340])
        XCTAssertTrue(finding.evidence.contains { $0.code == "dwarf_cfi_row" && $0.message.contains("register 29+16") })
    }

    func testIdenticalControlInputModelAndLimitsProduceIdenticalReports() throws {
        let binary = try loadFixture(firstProgram: allControls)
        var limits = UnwindAuditLimits()
        limits.maxInstructions = 32
        limits.maxSteps = 128
        let first = try UnwindAuditService.audit(binary: binary, limits: limits, model: .boundedCFIControls)
        let repeated = try UnwindAuditService.audit(binary: binary, limits: limits, model: .boundedCFIControls)
        XCTAssertEqual(repeated, first)
    }

    func testServicePreservesKnownReachableMismatchUnderControlModel() throws {
        var wrongLR = restoredRule
        wrongLR[7] = 2 // LR is recovered from saved FP, a concrete wrong caller value.
        let binary = try loadFixture(firstProgram: wrongLR)
        let finding = try firstFinding(UnwindAuditService.audit(binary: binary, model: .boundedCFIControls))
        XCTAssertEqual(finding.verdict, "inconsistency")
        XCTAssertEqual(finding.coverage, "dwarf_evaluated")
        XCTAssertEqual(finding.checkedPCs, [0x340])
        XCTAssertEqual(finding.reasonCodes, ["caller_state_mismatch"])
        XCTAssertTrue(finding.evidence.contains {
            $0.address == 0x340 && $0.expected == "original x30" && $0.observed == "original x29"
        })
    }

    func testRestoredUnknownStillDominatesAConcreteMismatch() throws {
        let bytes: [UInt8] = [
            0x02, 4, 0x0e, 16, 0x9d, 2, 0x9e, 2,
            0x07, 19, 0x0a, 0x08, 19, 0x0b, 0x03, 4, 0
        ]
        let binary = try loadFixture(firstProgram: bytes)
        let finding = try firstFinding(UnwindAuditService.audit(binary: binary, model: .boundedCFIControls))
        XCTAssertEqual(finding.verdict, "unresolved")
        XCTAssertEqual(finding.coverage, "dwarf_evaluated")
        XCTAssertEqual(finding.reasonCodes, ["unknown_recovery_value"])
        XCTAssertEqual(finding.checkedPCs, [])
        XCTAssertFalse(finding.evidence.contains { $0.code == "caller_state_mismatch" })
    }

    func testDefaultV1AndBothHistoricalOptInsKeepControlTableUnresolved() throws {
        let binary = try loadFixture(firstProgram: allControls)
        let defaultReport = try UnwindAuditService.audit(binary: binary)
        XCTAssertEqual(defaultReport.analysisModelVersion, UnwindAuditModel.boundedLoops.rawValue)
        try assertTableRefused(defaultReport)
        for model in [UnwindAuditModel.boundedLoops, .boundedLoopCalls, .boundedLoopCallsMOVK] {
            let report = try UnwindAuditService.audit(binary: binary, model: model)
            XCTAssertEqual(report.analysisModelVersion, model.rawValue)
            try assertTableRefused(report)
        }
    }

    func testLateUnderflowAfterExactEndRejectsEveryDWARFFindingWithoutPrefixEvidence() throws {
        let binary = try loadFixture(firstProgram: allControls + [0x0b])
        let report = try UnwindAuditService.audit(binary: binary, model: .boundedCFIControls)
        try assertTableRefused(report)
    }

    func testUnselectedFDEControlFaultsRetainMacScopeWholeTableRefusal() throws {
        let tails: [[UInt8]] = [
            Array(repeating: 0, count: 14) + [0x0b], // restore underflow
            Array(repeating: 0, count: 14) + [0x3f], // unknown opcode
            Array(repeating: 0, count: 14) + [0x04]  // missing fixed-width operand
        ]
        for second in tails {
            let binary = try loadFixture(firstProgram: allControls, secondProgram: second)
            let report = try UnwindAuditService.audit(binary: binary, model: .boundedCFIControls)
            try assertTableRefused(report)
        }
    }

    func testUnmodifiedOwnedFixturesPreserveV1ResultsAndV4StillRefusesLoopCalls() throws {
        for name in ["AIRSCFARegister.dylib", "AIRSUnwindLoops.dylib"] {
            let binary = try loadFixture(name)
            let baseline = try UnwindAuditService.audit(binary: binary)
            let control = try UnwindAuditService.audit(binary: binary, model: .boundedCFIControls)
            XCTAssertEqual(control.findings, baseline.findings, name)
            XCTAssertEqual(control.identity, baseline.identity)
            XCTAssertEqual(control.configuration, baseline.configuration)
            XCTAssertEqual(baseline.analysisModelVersion, UnwindAuditModel.boundedLoops.rawValue)
            XCTAssertEqual(control.analysisModelVersion, UnwindAuditModel.boundedCFIControls.rawValue)
            if name == "AIRSUnwindLoops.dylib" {
                let loop = try XCTUnwrap(control.findings.first { $0.function.symbolName == "_loop_call_inside" })
                XCTAssertEqual(loop.verdict, "unresolved")
                XCTAssertEqual(loop.reasonCodes, ["cfg_loop_call_not_modeled"])
                XCTAssertEqual(loop.checkedPCs, [])
            }
        }
    }

    func testControlModelRetainsServiceInstructionLimitAndExactConfiguration() throws {
        let binary = try loadFixture(firstProgram: allControls)
        var limits = UnwindAuditLimits()
        limits.maxInstructions = 1
        let report = try UnwindAuditService.audit(binary: binary, limits: limits, model: .boundedCFIControls)
        XCTAssertEqual(report.configuration, limits)
        XCTAssertEqual(report.analysisModelVersion, UnwindAuditModel.boundedCFIControls.rawValue)
        let finding = try firstFinding(report)
        XCTAssertEqual(finding.verdict, "unresolved")
        XCTAssertEqual(finding.reasonCodes, ["function_instruction_limit"])
        XCTAssertEqual(finding.checkedPCs, [])
    }

    private func firstFinding(_ report: UnwindAuditReport) throws -> UnwindAuditFinding {
        try XCTUnwrap(report.findings.first { $0.function.symbolName == "_cfa_register_agree" })
    }

    private func assertTableRefused(_ report: UnwindAuditReport,
                                    file: StaticString = #filePath, line: UInt = #line) throws {
        let findings = report.findings.filter { $0.mode == "dwarf" }
        XCTAssertEqual(findings.count, 2, file: file, line: line)
        for finding in findings {
            XCTAssertEqual(finding.verdict, "unresolved", file: file, line: line)
            XCTAssertEqual(finding.coverage, "dwarf_reference", file: file, line: line)
            XCTAssertEqual(finding.scope, "metadata_only", file: file, line: line)
            XCTAssertEqual(finding.reasonCodes, ["dwarf_cfi_unsupported"], file: file, line: line)
            XCTAssertEqual(finding.checkedPCs, [], file: file, line: line)
            XCTAssertEqual(finding.instructionCount, 0, file: file, line: line)
            XCTAssertFalse(finding.evidence.contains { $0.code == "dwarf_cfi_row" || $0.code == "caller_state_recovered" },
                           file: file, line: line)
        }
    }

    private func read(program: [UInt8], initialProgram: [UInt8] = [0x0c, 31, 0],
                       size: UInt64 = 0x40) throws -> DWARFStructuredCallFrameTable {
        // A real CIEv1 zR/code1/data-8/RA30/pcrel64 envelope, with no production encoder.
        let cie = littleEndian(0, width: 4) + [1, 0x7a, 0x52, 0, 1, 0x78, 30, 1, 0x10] + initialProgram
        var bytes = littleEndian(UInt64(cie.count), width: 4) + cie
        let offset = bytes.count
        let displacement = UInt64(bitPattern: Int64(0x1000) - Int64(0x800 + offset + 8))
        let fde = littleEndian(UInt64(offset + 4), width: 4) + littleEndian(displacement, width: 8)
            + littleEndian(size, width: 8) + [0] + program
        bytes += littleEndian(UInt64(fde.count), width: 4) + fde
        return try DWARFReader(sections: .init(ehFrame: Data(bytes)))
            .recoverStructuredCallFrameInfo(sectionAddress: 0x800)
    }

    private func littleEndian(_ value: UInt64, width: Int) -> [UInt8] {
        (0..<width).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
    }

    private enum FixtureError: Error { case oversizedProgram }

    /// Same parser-to-LoadedBinary projection as UnwindAuditOracleTests. Mutations
    /// touch only equal-size CFI program bytes, preserving all code and boundaries.
    private func loadFixture(_ name: String = "AIRSCFARegister.dylib",
                             firstProgram: [UInt8]? = nil, secondProgram: [UInt8]? = nil) throws -> LoadedBinary {
        let original: (digest: String, byteCount: UInt64, uuid: String)
        if name == "AIRSCFARegister.dylib" {
            original = ("e3ef10557917add67fd62dcebc9ea7f0893339a362325e3511ed4c5f7e9e9a93",
                        16904, "eada8dec-ff01-3904-b0b8-2365df568169")
        } else {
            original = ("e4957a86d91eb3722f975b48aee12bace61211e7a737a56a9249dad9b598d8d1",
                        17480, "9f20e834-0ec1-31f0-aa9c-6153bbab70c6")
        }
        let url = TestSourceRoot.fileURL(#filePath).deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Fixtures").appendingPathComponent(name)
        var bytes = try Data(contentsOf: url)
        XCTAssertEqual(UInt64(bytes.count), original.byteCount)
        func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
        XCTAssertEqual(digest(bytes), original.digest)
        let parsed = try MachOParser().parse(bytes, options: MachOParseOptions(
            recoverStringLiterals: false, recoverObjectiveCMetadata: false,
            recoverSwiftMetadata: false, parseCodeSignature: false))
        if firstProgram != nil || secondProgram != nil {
            XCTAssertEqual(name, "AIRSCFARegister.dylib")
            let eh = try XCTUnwrap(parsed.sections.first { $0.segmentName == "__TEXT" && $0.sectionName == "__eh_frame" })
            XCTAssertEqual(eh.size, 104)
            for (replacement, offset, width) in [(firstProgram, 45, 19), (secondProgram, 89, 15)] {
                if let replacement {
                    guard replacement.count <= width else { throw FixtureError.oversizedProgram }
                    let start = Int(eh.fileOffset) + offset
                    bytes.replaceSubrange(start..<(start + width),
                        with: replacement + Array(repeating: 0, count: width - replacement.count))
                }
            }
            XCTAssertNotEqual(digest(bytes), original.digest)
        }
        let identity = try MachOSliceArtifactIdentity(uuid: UUID(uuidString: original.uuid),
            rawCPUType: 0x0100000c, rawCPUSubtype: 0,
            selectedSliceSHA256: digest(bytes), selectedSliceByteCount: UInt64(bytes.count))
        let layout = try MachOPreferredSegmentLayout(records: parsed.segments.map {
            MachOPreferredSegmentLayout.Record(name: $0.name, preferredVMStart: $0.vmAddress,
                preferredVMSize: $0.vmSize, sliceRelativeFileOffset: $0.fileOffset,
                fileSize: $0.fileSize, initialProtections: $0.initialProtection)
        }, selectedSliceByteCount: UInt64(bytes.count))
        func section(_ source: MachOSection) -> BinarySection {
            BinarySection(name: "\(source.segmentName),\(source.sectionName)", address: source.address,
                size: source.size, fileOffset: UInt64(source.fileOffset),
                isExecutable: source.isExecutableInstructions, isZeroFill: source.isZeroFill)
        }
        return LoadedBinary(name: name, path: url.path, isBundle: false,
            cpuType: parsed.header.cpuType, cpuSubtype: parsed.header.cpuSubtype,
            fileTypeName: parsed.fileTypeName, architectureDisplayName: parsed.architectureDisplayName,
            metadata: BinaryMetadataSummary(uuid: parsed.uuid?.stringValue),
            artifactIdentity: identity, preferredSegmentLayout: layout, artifactIntegrityState: .verified,
            bytes: bytes, sliceOffset: parsed.selectedSliceOffset, sliceSize: UInt64(bytes.count),
            sections: parsed.sections.map(section), executableTextSection: parsed.executableTextSection.map(section),
            entryPointAddress: parsed.entryPointAddress,
            symbols: parsed.symbols.map {
                SymbolSummary(id: UUID(), name: $0.name, address: $0.address, kind: $0.kind.rawValue,
                    libraryName: $0.libraryName, rawLinkageName: $0.name)
            }, imports: [], indirectSymbols: [], exports: [], stringLiterals: [],
            functionStarts: parsed.functionStarts.map(\.address), objcSelectors: [:])
    }
}
