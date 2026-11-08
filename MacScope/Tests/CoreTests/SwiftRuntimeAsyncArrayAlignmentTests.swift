import Foundation
import XCTest
@testable import MacScope

// New definitions. All bytes are constructed here; no retained fixture is loaded.
final class SwiftRuntimeAsyncArrayAlignmentTests: XCTestCase {
    private enum ArrayKind: String, CaseIterable {
        case entries = "__swift_as_entry"
        case resumes = "__swift_as_ret"
        case continuations = "__swift_as_cont"

        var address: UInt64 {
            switch self {
            case .entries: return 0x1100
            case .resumes: return 0x1120
            case .continuations: return 0x1140
            }
        }

        func targets(in metadata: SwiftAsyncMetadata) -> [UInt64] {
            switch self {
            case .entries: return metadata.entries.map(\.entryAddress)
            case .resumes: return metadata.resumePartialAddresses
            case .continuations: return metadata.continuationPartialAddresses
            }
        }
    }

    private struct Fixture {
        var data: Data
        var sections: [SwiftMetadataParser.Section]

        var parser: SwiftMetadataParser {
            SwiftMetadataParser(data: data, sections: sections)
        }
    }

    // Each array has room for eight words; __const has room for eight records.
    private func fixture(_ arrays: [ArrayKind: [UInt64]],
                         pointers: [(target: UInt64, context: UInt32)] = []) -> Fixture {
        var data = Data(repeating: 0, count: 0x200)
        var sections: [SwiftMetadataParser.Section] = [
            .init(name: "__text", address: 0x1000, fileOffset: 0, size: 0x100,
                  isExecutable: true, segmentName: "__TEXT")
        ]
        for kind in ArrayKind.allCases {
            let targets = arrays[kind] ?? []
            let offset = Int(kind.address - 0x1000)
            sections.append(.init(name: kind.rawValue, address: kind.address,
                                  fileOffset: UInt64(offset), size: UInt64(targets.count * 4),
                                  segmentName: "__TEXT"))
            for (index, target) in targets.enumerated() {
                writeRelative(target, from: kind.address + UInt64(index * 4),
                              at: offset + index * 4, in: &data)
            }
        }
        if !pointers.isEmpty {
            sections.append(.init(name: "__const", address: 0x1180, fileOffset: 0x180,
                                  size: UInt64(pointers.count * 8), segmentName: "__TEXT"))
            for (index, pointer) in pointers.enumerated() {
                writeRelative(pointer.target, from: 0x1180 + UInt64(index * 8),
                              at: 0x180 + index * 8, in: &data)
                writeWord(pointer.context, at: 0x184 + index * 8, in: &data)
            }
        }
        return Fixture(data: data, sections: sections)
    }

    private func writeRelative(_ target: UInt64, from slot: UInt64,
                               at offset: Int, in data: inout Data) {
        // This helper is only used for the small, non-wrapping fixture addresses.
        writeWord(UInt32(bitPattern: Int32(Int64(target) - Int64(slot))), at: offset, in: &data)
    }

    private func writeWord(_ word: UInt32, at offset: Int, in data: inout Data) {
        for index in 0..<4 {
            data[offset + index] = UInt8(truncatingIfNeeded: word >> (index * 8))
        }
    }

    private func misalignment(_ kind: ArrayKind, slot: UInt64) -> MetadataParseDiagnostic {
        .init(grade: .skippedItem, address: slot,
              message: "\(kind.rawValue) target is not a 4-byte instruction address")
    }

    private func unreadable(_ kind: ArrayKind, slot: UInt64) -> MetadataParseDiagnostic {
        .init(grade: .skippedItem, address: slot,
              message: "Unreadable \(kind.rawValue) entry or target outside __text")
    }

    private func arrayDiagnostics(_ diagnostics: [MetadataParseDiagnostic],
                                  for kind: ArrayKind) -> [MetadataParseDiagnostic] {
        diagnostics.filter { $0.message.contains(kind.rawValue) }
    }

    func testEachArrayOmitsMisalignedTargetAndReportsSourcePointerSlot() {
        for kind in ArrayKind.allCases {
            let report = fixture([kind: [0x1062]]).parser.parseAsyncFunctionsReport()
            XCTAssertTrue(report.records.entries.isEmpty)
            XCTAssertTrue(report.records.resumePartialAddresses.isEmpty)
            XCTAssertTrue(report.records.continuationPartialAddresses.isEmpty)
            XCTAssertEqual(report.diagnostics, [misalignment(kind, slot: kind.address)])
            XCTAssertNotEqual(report.diagnostics.first?.address, 0x1062)
        }
    }

    func testOffsetsOneTwoThreeRefuseAndFourIsAcceptedInEachArray() {
        for kind in ArrayKind.allCases {
            let report = fixture([kind: [0x1061, 0x1062, 0x1063, 0x1064]],
                                 pointers: [(0x1064, 32)]).parser.parseAsyncFunctionsReport()
            XCTAssertEqual(kind.targets(in: report.records), [0x1064])
            XCTAssertEqual(report.diagnostics, [
                misalignment(kind, slot: kind.address),
                misalignment(kind, slot: kind.address + 4),
                misalignment(kind, slot: kind.address + 8)
            ])
        }
    }

    func testMixedNeighborsSurviveInOriginalOrderForAllThreeArrays() {
        let targets: [UInt64] = [0x1080, 0x1061, 0x1000, 0x1063, 0x1040, 0x1062, 0x1060]
        let report = fixture([.entries: targets, .resumes: targets, .continuations: targets],
                             pointers: [(0x1080, 16), (0x1000, 32), (0x1040, 48), (0x1060, 64)])
            .parser.parseAsyncFunctionsReport()
        var expectedDiagnostics: [MetadataParseDiagnostic] = []
        for kind in ArrayKind.allCases {
            XCTAssertEqual(kind.targets(in: report.records), [0x1080, 0x1000, 0x1040, 0x1060])
            expectedDiagnostics += [
                misalignment(kind, slot: kind.address + 4),
                misalignment(kind, slot: kind.address + 12),
                misalignment(kind, slot: kind.address + 20)
            ]
        }
        XCTAssertEqual(report.diagnostics, expectedDiagnostics)
        XCTAssertEqual(report.records.entries.map { $0.pointerRecords.map(\.address) },
                       [[0x1180], [0x1188], [0x1190], [0x1198]])
    }

    func testAlignedDuplicatesKeepMultiplicityAndUnresolvedOwnership() {
        let report = fixture([.entries: [0x1040, 0x1062, 0x1040]], pointers: [(0x1040, 32)])
            .parser.parseAsyncFunctionsReport()
        let candidates = [SwiftAsyncFunctionPointerRecord(address: 0x1180, expectedContextSize: 32)]
        XCTAssertEqual(report.records.entries, [
            .init(entryAddress: 0x1040, pointerRecords: candidates),
            .init(entryAddress: 0x1040, pointerRecords: candidates)
        ])
        XCTAssertEqual(report.records.entryGroups, [
            .init(entryAddress: 0x1040, entryCount: 2, pointerRecords: candidates)
        ])
        XCTAssertEqual(report.diagnostics, [
            misalignment(.entries, slot: 0x1104),
            .init(grade: .skippedItem, address: 0x1040,
                  message: "Async target has 1 candidate pointer records for 2 array entries; ownership unresolved")
        ])
    }

    func testMatchingPointerCountDoesNotAssignDuplicateEntryOwnership() {
        let report = fixture([.entries: [0x1040, 0x1040]],
                             pointers: [(0x1040, 32), (0x1040, 48)]).parser.parseAsyncFunctionsReport()
        let candidates = [SwiftAsyncFunctionPointerRecord(address: 0x1180, expectedContextSize: 32),
                          SwiftAsyncFunctionPointerRecord(address: 0x1188, expectedContextSize: 48)]
        XCTAssertEqual(report.records.entries, [
            .init(entryAddress: 0x1040, pointerRecords: candidates),
            .init(entryAddress: 0x1040, pointerRecords: candidates)
        ])
        XCTAssertEqual(report.records.entryGroups, [
            .init(entryAddress: 0x1040, entryCount: 2, pointerRecords: candidates)
        ])
        XCTAssertTrue(report.diagnostics.isEmpty)
    }

    func testFilteredEntryDoesNotCreatePointerOrOwnershipDiagnostics() {
        let report = fixture([.entries: [0x1062]], pointers: [(0x1062, 0)])
            .parser.parseAsyncFunctionsReport()
        XCTAssertTrue(report.records.entries.isEmpty)
        XCTAssertTrue(report.records.entryGroups.isEmpty)
        XCTAssertEqual(report.diagnostics, [misalignment(.entries, slot: 0x1100)])
    }

    func testAlignedPositivePointerAssociationsDoNotPairIndependentArrays() {
        var f = fixture([.entries: [0x1080, 0x1000], .resumes: [0x1060, 0x1040, 0x1060],
                         .continuations: [0x10c0, 0x1080]], pointers: [(0x1000, 32), (0x1080, 48)])
        // Physical section enumeration differs from the order of the three result properties.
        f.sections.swapAt(1, 3)
        let report = f.parser.parseAsyncFunctionsReport()
        XCTAssertEqual(report.records.entries, [
            .init(entryAddress: 0x1080, pointerRecords: [.init(address: 0x1188, expectedContextSize: 48)]),
            .init(entryAddress: 0x1000, pointerRecords: [.init(address: 0x1180, expectedContextSize: 32)])
        ])
        XCTAssertEqual(report.records.resumePartialAddresses, [0x1060, 0x1040, 0x1060])
        XCTAssertEqual(report.records.continuationPartialAddresses, [0x10c0, 0x1080])
        XCTAssertTrue(report.diagnostics.isEmpty)
        // No proof API is invoked; membership/alignment is not a continuation certificate.
    }

    func testArraySectionOrderIsNotSortedByAddressOrCoalesced() {
        for kind in ArrayKind.allCases {
            // Back the complete requested instruction spans without changing array order.
            var data = Data(repeating: 0, count: 0x100)
            writeRelative(0x1080, from: 0x2100, at: 0, in: &data)
            writeRelative(0x1000, from: 0x2000, at: 4, in: &data)
            writeRelative(0x1080, from: 0x2004, at: 8, in: &data)
            let parser = SwiftMetadataParser(data: data, sections: [
                .init(name: "__text", address: 0x1000, fileOffset: 0, size: 0x100, segmentName: "__TEXT"),
                .init(name: kind.rawValue, address: 0x2100, fileOffset: 0, size: 4),
                .init(name: kind.rawValue, address: 0x2000, fileOffset: 4, size: 8)
            ])
            let report = parser.parseAsyncFunctionsReport()
            XCTAssertEqual(kind.targets(in: report.records), [0x1080, 0x1000, 0x1080])
            XCTAssertTrue(arrayDiagnostics(report.diagnostics, for: kind).isEmpty)
        }
    }

    func testTextEndAndOutsideTargetsRetainExistingDiagnosticPrecedence() {
        for kind in ArrayKind.allCases {
            var f = fixture([kind: [0x107c, 0x107f, 0x1080, 0x0ffc]], pointers: [(0x107c, 32)])
            f.sections[0].size = 0x80
            let report = f.parser.parseAsyncFunctionsReport()
            XCTAssertEqual(kind.targets(in: report.records), [0x107c])
            XCTAssertEqual(report.diagnostics, [
                misalignment(kind, slot: kind.address + 4),
                unreadable(kind, slot: kind.address + 8),
                unreadable(kind, slot: kind.address + 12)
            ])
        }
    }

    func testCompleteInstructionSpanPreservesNonExecutableAndNilSegmentAdmission() {
        for kind in ArrayKind.allCases {
            var f = fixture([kind: [0x1060]], pointers: [(0x1060, 32)])
            f.sections[0].size = 0x64 // Four target bytes are present; executable flag remains unnecessary.
            f.sections[0].isExecutable = false
            f.sections[0].segmentName = nil
            let report = f.parser.parseAsyncFunctionsReport()
            XCTAssertEqual(kind.targets(in: report.records), [0x1060])
            XCTAssertTrue(report.diagnostics.isEmpty)
        }
    }

    func testTextZeroFillWrongSegmentAndWrongNameStillRefuse() {
        for kind in ArrayKind.allCases {
            for variant in 0..<3 {
                var f = fixture([kind: [0x1060, 0x1062]])
                switch variant {
                case 0: f.sections[0].isZeroFill = true
                case 1: f.sections[0].segmentName = "__DATA"
                default: f.sections[0].name = "__stubs"
                }
                let report = f.parser.parseAsyncFunctionsReport()
                XCTAssertTrue(kind.targets(in: report.records).isEmpty)
                XCTAssertEqual(report.diagnostics, [unreadable(kind, slot: kind.address),
                                                     unreadable(kind, slot: kind.address + 4)])
            }
        }
    }

    func testZeroFillArrayCannotSupplyAnOtherwiseAlignedTarget() {
        for kind in ArrayKind.allCases {
            var f = fixture([kind: [0x1060]])
            for index in f.sections.indices where f.sections[index].name == kind.rawValue {
                f.sections[index].isZeroFill = true
            }
            let report = f.parser.parseAsyncFunctionsReport()
            XCTAssertTrue(kind.targets(in: report.records).isEmpty)
            XCTAssertEqual(report.diagnostics, [unreadable(kind, slot: kind.address)])
        }
    }

    func testPartialTrailingPointerKeepsTruncationAndCompleteNeighbor() {
        for kind in ArrayKind.allCases {
            var f = fixture([kind: [0x1060, 0x1062]], pointers: [(0x1060, 32)])
            for index in f.sections.indices where f.sections[index].name == kind.rawValue {
                f.sections[index].size = 7
            }
            let report = f.parser.parseAsyncFunctionsReport()
            XCTAssertEqual(kind.targets(in: report.records), [0x1060])
            XCTAssertEqual(report.diagnostics, [
                .init(grade: .skippedItem, address: kind.address,
                      message: "Truncated \(kind.rawValue) relative-pointer array")
            ])
        }
    }

    func testFileTruncatedPointerAndNullPointerKeepExistingRefusals() {
        for kind in ArrayKind.allCases {
            var truncated = fixture([kind: [0x1060, 0x1062]])
            truncated.data = Data(truncated.data.prefix(Int(kind.address - 0x1000) + 6))
            let truncatedReport = truncated.parser.parseAsyncFunctionsReport()
            XCTAssertEqual(kind.targets(in: truncatedReport.records), [0x1060])
            XCTAssertEqual(arrayDiagnostics(truncatedReport.diagnostics, for: kind),
                           [unreadable(kind, slot: kind.address + 4)])

            var null = fixture([kind: [0x1060]])
            writeWord(0, at: Int(kind.address - 0x1000), in: &null.data)
            let nullReport = null.parser.parseAsyncFunctionsReport()
            XCTAssertTrue(kind.targets(in: nullReport.records).isEmpty)
            XCTAssertEqual(nullReport.diagnostics, [unreadable(kind, slot: kind.address)])
        }
    }

    func testSlotWidthAndAdditionOverflowPreserveFallbackSourceDiagnostic() {
        for kind in ArrayKind.allCases {
            let base = UInt64.max - 2
            let parser = SwiftMetadataParser(data: Data(repeating: 0, count: 8), sections: [
                .init(name: kind.rawValue, address: base, fileOffset: 0, size: 8)
            ])
            let report = parser.parseAsyncFunctionsReport()
            XCTAssertTrue(kind.targets(in: report.records).isEmpty)
            XCTAssertEqual(report.diagnostics, [unreadable(kind, slot: base), unreadable(kind, slot: base)])
        }
    }

    func testFileOffsetAdditionOverflowKeepsExistingRefusal() {
        for kind in ArrayKind.allCases {
            let parser = SwiftMetadataParser(data: Data(repeating: 0, count: 8), sections: [
                .init(name: kind.rawValue, address: kind.address, fileOffset: UInt64.max - 1, size: 8)
            ])
            let report = parser.parseAsyncFunctionsReport()
            XCTAssertTrue(kind.targets(in: report.records).isEmpty)
            XCTAssertEqual(report.diagnostics, [unreadable(kind, slot: kind.address),
                                                 unreadable(kind, slot: kind.address + 4)])
        }
    }

    func testWrappedRelativeTargetOutsideTextKeepsExistingRefusal() {
        for kind in ArrayKind.allCases {
            var data = Data(repeating: 0, count: 4)
            writeWord(16, at: 0, in: &data)
            let slot = UInt64.max - 7 // Existing relative resolver wraps this target to 8.
            let parser = SwiftMetadataParser(data: data, sections: [
                .init(name: kind.rawValue, address: slot, fileOffset: 0, size: 4),
                .init(name: "__text", address: 0x1000, fileOffset: 0, size: 0x100, segmentName: "__TEXT")
            ])
            let report = parser.parseAsyncFunctionsReport()
            XCTAssertTrue(kind.targets(in: report.records).isEmpty)
            XCTAssertEqual(report.diagnostics, [unreadable(kind, slot: slot)])
        }
    }

    func testAlignedWrappedRelativeTargetIsRefusedBeforeTextAdmission() {
        var data = Data(repeating: 0, count: 4)
        writeWord(24, at: 0, in: &data)
        let parser = SwiftMetadataParser(data: data, sections: [
            .init(name: "__swift_as_ret", address: UInt64.max - 7, fileOffset: 0, size: 4),
            .init(name: "__text", address: 0, fileOffset: 0, size: 0x40, segmentName: "__TEXT")
        ])
        let report = parser.parseAsyncFunctionsReport()
        XCTAssertTrue(report.records.resumePartialAddresses.isEmpty)
        XCTAssertEqual(report.diagnostics, [unreadable(.resumes, slot: UInt64.max - 7)])
        XCTAssertNil(parser.resolveRelativePointer(at: UInt64.max - 7))
        // Checked relative arithmetic refuses the wrapped target before text or alignment admission.
    }

    func testRecordCapRemainsPerArrayWithoutLargeFixtureData() {
        for kind in ArrayKind.allCases {
            let cap = SwiftMetadataParser.Limits.maxTypes
            let slot: UInt64 = 0x200000
            // Back target 0x1060 through 0x1063; later array words remain null.
            // This cap-sized method remains UNRUN and excluded from focused execution.
            var data = Data(repeating: 0, count: 100)
            writeRelative(0x1060, from: slot, at: 0, in: &data)
            let parser = SwiftMetadataParser(data: data, sections: [
                .init(name: kind.rawValue, address: slot, fileOffset: 0, size: UInt64(cap + 1) * 4),
                .init(name: "__text", address: 0x1000, fileOffset: 0, size: 0x100, segmentName: "__TEXT")
            ])
            let report = parser.parseAsyncFunctionsReport()
            let diagnostics = arrayDiagnostics(report.diagnostics, for: kind)
            XCTAssertEqual(kind.targets(in: report.records), [0x1060])
            XCTAssertEqual(diagnostics.count, cap)
            let capDiagnostic = MetadataParseDiagnostic(grade: .skippedItem, address: slot,
                                                        message: "\(kind.rawValue) reached record cap")
            XCTAssertEqual(diagnostics.first, capDiagnostic)
            XCTAssertEqual(diagnostics.dropFirst().first, unreadable(kind, slot: slot + 4))
            XCTAssertEqual(diagnostics.last, unreadable(kind, slot: slot + UInt64(cap - 1) * 4))
            XCTAssertFalse(diagnostics.contains { $0.address == slot + UInt64(cap) * 4 })
        }
    }
}
