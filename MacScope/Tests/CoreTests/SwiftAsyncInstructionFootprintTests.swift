import Foundation
import XCTest
@testable import MacScope

// Self-contained bytes, no retained binary or prior test replay.
final class SwiftAsyncInstructionFootprintTests: XCTestCase {
    private let names = ["__swift_as_entry", "__swift_as_ret", "__swift_as_cont"]
    private func parser(_ name: String, targets: [UInt64] = [0x1000],
                        sections: [SwiftMetadataParser.Section], count: Int = 64) -> SwiftMetadataParser {
        var data = Data(repeating: 0, count: count)
        for (index, target) in targets.enumerated() {
            let word = UInt32(bitPattern: Int32(Int64(target) - Int64(0x2000 + index * 4)))
            for byte in 0..<4 { data[index * 4 + byte] = UInt8(truncatingIfNeeded: word >> (8 * byte)) }
        }
        let array = SwiftMetadataParser.Section(name: name, address: 0x2000,
            fileOffset: 0, size: UInt64(targets.count * 4), segmentName: "__TEXT")
        return SwiftMetadataParser(data: data, sections: [array] + sections)
    }
    private func text(_ size: UInt64, at address: UInt64 = 0x1000,
                      file: UInt64 = 32, zero: Bool = false,
                      segment: String? = "__TEXT") -> SwiftMetadataParser.Section {
        .init(name: "__text", address: address, fileOffset: file, size: size,
              isExecutable: true, isZeroFill: zero, segmentName: segment)
    }
    private func values(_ metadata: SwiftAsyncMetadata, _ name: String) -> [UInt64] {
        switch name {
        case "__swift_as_entry": return metadata.entries.map(\.entryAddress)
        case "__swift_as_ret": return metadata.resumePartialAddresses
        default: return metadata.continuationPartialAddresses
        }
    }
    private func spanMessage(_ name: String) -> String {
        "\(name) target lacks a unique file-backed 4-byte __text span"
    }
    func testOneTwoThreeRemainingVMBytesRefuseInEveryArray() {
        for name in names { for remaining in 1...3 {
            let report = parser(name, sections: [text(UInt64(remaining))]).parseAsyncFunctionsReport()
            XCTAssertTrue(values(report.records, name).isEmpty)
            XCTAssertTrue(report.diagnostics.contains { $0.address == 0x2000 && $0.message == spanMessage(name) })
        } }
    }
    func testOneTwoThreeRemainingFileBytesRefuse() {
        for remaining in 1...3 {
            let report = parser(names[1], sections: [text(4)], count: 32 + remaining).parseAsyncFunctionsReport()
            XCTAssertTrue(report.records.resumePartialAddresses.isEmpty)
            XCTAssertEqual(report.diagnostics.map(\.address), [0x2000])
            XCTAssertEqual(report.diagnostics.map(\.message), [spanMessage(names[1])])
        }
    }
    func testExactFourBytesAndNilSegmentRetainTargets() {
        for name in names { for segment in [nil, "__TEXT"] as [String?] {
            let report = parser(name, sections: [text(4, segment: segment)], count: 36).parseAsyncFunctionsReport()
            XCTAssertEqual(values(report.records, name), [0x1000])
            XCTAssertFalse(report.diagnostics.contains { $0.message.contains(name) })
        } }
    }
    func testSplitAdjacentMappingsCannotSupplyAnInstruction() {
        let sections = [text(2), text(2, at: 0x1002, file: 34)]
        for ordered in [sections, Array(sections.reversed())] {
            let report = parser(names[2], sections: ordered).parseAsyncFunctionsReport()
            XCTAssertTrue(report.records.continuationPartialAddresses.isEmpty)
            XCTAssertEqual(report.diagnostics.map(\.message), [spanMessage(names[2])])
        }
    }
    func testInteriorCompetitorAndIdenticalMapsRefuseIndependentOfOrder() {
        let complete = text(8)
        let middle = SwiftMetadataParser.Section(name: "__data", address: 0x1001,
            fileOffset: 48, size: 1, segmentName: "__DATA")
        for competitor in [middle, complete, text(1, at: 0x1001, zero: true)] {
            for ordered in [[complete, competitor], [competitor, complete]] {
                let report = parser(names[1], sections: ordered).parseAsyncFunctionsReport()
                XCTAssertTrue(report.records.resumePartialAddresses.isEmpty)
                XCTAssertEqual(report.diagnostics.map(\.message), [spanMessage(names[1])])
            }
        }
    }
    func testZeroFillAndOutsideTextKeepExistingEarlyRefusal() {
        for sections in [[text(8, zero: true)], [text(8, at: 0x1004)], [text(8, segment: "__DATA")]] {
            let report = parser(names[1], sections: sections).parseAsyncFunctionsReport()
            XCTAssertTrue(report.records.resumePartialAddresses.isEmpty)
            XCTAssertEqual(report.diagnostics.map(\.message), ["Unreadable \(names[1]) entry or target outside __text"])
        }
    }
    func testValidNeighborsAndDuplicatesSurviveShortTail() {
        for name in names {
            let report = parser(name, targets: [0x1000, 0x1004, 0x1008, 0x1000],
                sections: [text(10)]).parseAsyncFunctionsReport()
            XCTAssertEqual(values(report.records, name), [0x1000, 0x1004, 0x1000])
            let local = report.diagnostics.filter { $0.message.contains(name) }
            XCTAssertEqual(local.map(\.address), [0x2008])
            XCTAssertEqual(local.map(\.message), [spanMessage(name)])
        }
    }
    func testUnalignedTargetKeepsAlignmentDiagnosticPrecedence() {
        let report = parser(names[1], targets: [0x1001], sections: [text(2)]).parseAsyncFunctionsReport()
        XCTAssertTrue(report.records.resumePartialAddresses.isEmpty)
        XCTAssertEqual(report.diagnostics.map(\.message), ["\(names[1]) target is not a 4-byte instruction address"])
    }
    func testCheckedFileOffsetRefusesWithoutReadingPayload() {
        let report = parser(names[1], sections: [text(4, file: UInt64.max - 1)]).parseAsyncFunctionsReport()
        XCTAssertTrue(report.records.resumePartialAddresses.isEmpty)
        XCTAssertEqual(report.diagnostics.map(\.message), [spanMessage(names[1])])
    }
    func testAdjacentNonoverlappingMappingDoesNotRejectExactEnd() {
        let next = SwiftMetadataParser.Section(name: "__data", address: 0x1004,
            fileOffset: 48, size: 4, segmentName: "__DATA")
        let report = parser(names[1], sections: [text(4), next]).parseAsyncFunctionsReport()
        XCTAssertEqual(report.records.resumePartialAddresses, [0x1000])
        XCTAssertTrue(report.diagnostics.isEmpty)
    }
}
