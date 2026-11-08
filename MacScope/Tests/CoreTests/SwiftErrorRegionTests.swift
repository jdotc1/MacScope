import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope
#else
@testable import SwiftErrorFlow
#endif

final class SwiftErrorRegionTests: XCTestCase {
    func testOwnedShapeRetainsIntervalRawWordsAndOpaqueCall() throws {
        let report = analyze([0xb4000095, 0xaa1503e0, 0x94000005, 0x92800000])
        let region = try XCTUnwrap(report.regions.first)
        XCTAssertEqual(region.status, .candidate)
        XCTAssertEqual(region.startAddress, 0x1008)
        XCTAssertEqual(region.endExclusive, 0x1014)
        XCTAssertEqual(region.joinAddress, 0x1014)
        XCTAssertEqual(region.instructions.map(\.kind), ["mov", "bl", "movn"])
        XCTAssertEqual(region.instructions.map(\.word), [0xaa1503e0, 0x94000005, 0x92800000])
        XCTAssertEqual(region.instructions[1].address, 0x100c)
        XCTAssertEqual(region.instructions[1].targetAddress, 0x1020)
        XCTAssertTrue(region.instructions[1].opaqueCall)
        XCTAssertEqual(region.opaqueCallCount, 1)
        XCTAssertEqual(region.incomingEntries?.status, .noUnexpected)
        XCTAssertEqual(region.postcallWindow.status, .noUnexpected)
        XCTAssertEqual(report.callerScanCount, 1)
        XCTAssertEqual(report.scannedWordCount, 32)
    }

    func testOpaqueCallCanTargetItselfOrOutsideTheCallerWithoutMeaning() throws {
        for call: UInt32 in [0x94000000, 0x94000100] {
            let region = try XCTUnwrap(analyze([0xb4000095, 0xaa1503e0, call, 0x92800000]).regions.first)
            XCTAssertEqual(region.status, .candidate)
            XCTAssertTrue(region.instructions[1].opaqueCall)
            XCTAssertFalse(region.callReturnProven)
            XCTAssertFalse(region.joinReachabilityProven)
            XCTAssertFalse(region.sourceReconstructionAllowed)
        }
    }

    func testFinalBranchMustBeExactlyAtTheIntervalEndAndTargetJoin() throws {
        let region = try XCTUnwrap(analyze([0xb4000095, 0xaa1503e0, 0xd503201f, 0x14000001]).regions.first)
        XCTAssertEqual(region.status, .candidate)
        XCTAssertEqual(region.instructions.last?.targetAddress, 0x1014)
        for window: [UInt32] in [[0xb4000095, 0x14000003, 0xd503201f, 0x92800000],
                                  [0xb4000095, 0xaa1503e0, 0xd503201f, 0x14000002]] {
            XCTAssertEqual(analyze(window).regions.first?.reason, .unmodeledControlFlow)
        }
    }

    func testUnsupportedRegionInstructionsKeepEdgeAndRefusalWord() throws {
        for word: UInt32 in [0xb4000040, 0xd61f0000, 0xd65f03c0, 0xf9400000, 0xffffffff,
                             0x2a1503e0, 0xf2800000, 0x91000400] {
            let report = analyze([0xb4000095, word, 0xd503201f, 0x92800000])
            let region = try XCTUnwrap(report.regions.first)
            XCTAssertEqual(report.edgeReport.edges.count, 1)
            XCTAssertEqual(region.status, .declined)
            XCTAssertEqual(region.reason, .unmodeledInstruction)
            XCTAssertEqual(region.instructions.first?.word, word)
            XCTAssertNil(region.incomingEntries)
            XCTAssertNil(region.startAddress)
        }
    }

    func testForwardErrorLayoutsRemainDeclined() {
        XCTAssertEqual(analyze([0xb5000095, 0xaa1503e0, 0xd503201f, 0x92800000]).regions.first?.reason,
                       .unsupportedLayout)
        XCTAssertEqual(analyze([0xf10002bf, 0x54000081, 0xaa1503e0, 0xd503201f, 0x92800000]).regions.first?.reason,
                       .unsupportedLayout)
    }

    func testOneAndSixteenWordsAcceptedButSeventeenDeclined() throws {
        for count in [1, 16, 17] {
            let branch = UInt32(0xb4000015) | UInt32(count + 1) << 5
            let region = try XCTUnwrap(analyze([branch] + Array(repeating: 0xd503201f, count: count)).regions.first)
            XCTAssertEqual(region.status, count <= 16 ? .candidate : .declined)
            if count <= 16 { XCTAssertEqual(region.instructions.count, count) }
            else { XCTAssertEqual(region.reason, .wordBudgetExceeded) }
        }
    }

    func testCompareAliasRegionRequiresClearWindowAndRetainsBothChecks() throws {
        let region = try XCTUnwrap(analyze([0xaa1503f3, 0xf100027f, 0x54000080,
                                           0xaa1303e0, 0xd503201f, 0x92800000]).regions.first)
        XCTAssertEqual(region.status, .candidate)
        XCTAssertEqual(region.startAddress, 0x1010)
        XCTAssertEqual(region.joinAddress, 0x101c)
        XCTAssertEqual(region.postcallWindow.scope, .postcallWindow)
        XCTAssertEqual(region.postcallWindow.protectedStartAddress, 0x1004)
        XCTAssertEqual(region.postcallWindow.protectedEndExclusive, 0x1010)
        XCTAssertEqual(region.incomingEntries?.scope, .region)
    }

    func testCompareWindowConflictOrUnknownWithholdsRegionButPreservesEdge() throws {
        let window: [UInt32] = [0xf10002bf, 0x54000080, 0xaa1503e0, 0xd503201f, 0x92800000]
        // At +24, B -16 enters CMP at +4? Delta -20 gives +4.
        for (word, status) in [(UInt32(0x17fffffb), SwiftErrorEntryStatus.unexpected),
                               (UInt32(0xffffffff), SwiftErrorEntryStatus.unresolved)] {
            let report = analyze(window, extras: [6: word])
            let region = try XCTUnwrap(report.regions.first)
            XCTAssertEqual(report.edgeReport.edges.count, 1)
            XCTAssertEqual(region.reason, .postcallEntriesNotClear)
            XCTAssertEqual(region.postcallWindow.status, status)
            XCTAssertNil(region.incomingEntries)
        }
    }

    func testCBWindowConflictDoesNotEraseRawRegion() throws {
        let region = try XCTUnwrap(analyze(extras: [5: 0x17fffffc]).regions.first) // +20 -> test at +4.
        XCTAssertEqual(region.status, .candidate)
        XCTAssertEqual(region.postcallWindow.status, .unexpected)
        XCTAssertEqual(region.incomingEntries?.status, .noUnexpected)
        XCTAssertFalse(region.postcallWindow.exclusiveEntryProven)
        XCTAssertFalse(region.postcallWindow.flagStateProven)
    }

    func testEveryDirectFamilyDetectsRegionSideEntries() throws {
        // All words at +20 target +8, a signed displacement of -12.
        let words: [UInt32] = [0x17fffffd, 0x97fffffd, 0x54ffffa0,
                                0xb4ffffa0, 0xb5ffffa0, 0x34ffffa0, 0x35ffffa0,
                                0x3607ffa0, 0x3707ffa0, 0xb607ffa0, 0xb707ffa0]
        for word in words {
            let entry = try XCTUnwrap(analyze(extras: [5: word]).regions.first?.incomingEntries)
            XCTAssertEqual(entry.status, .unexpected, String(word, radix: 16))
            XCTAssertEqual(entry.unexpectedEntryCount, 1)
            XCTAssertEqual(entry.unexpectedEntries.first?.address, 0x1014)
            XCTAssertEqual(entry.unexpectedEntries.first?.targetAddress, 0x1008)
        }
    }

    func testRegionStartAndInteriorConflictButJoinAndOutsideDoNot() throws {
        for (word, count) in [(UInt32(0x17fffffd), 1), (UInt32(0x17fffffe), 1),
                               (UInt32(0x14000000), 0), (UInt32(0x14000001), 0)] {
            let entry = try XCTUnwrap(analyze(extras: [5: word]).regions.first?.incomingEntries)
            XCTAssertEqual(entry.unexpectedEntryCount, count)
            XCTAssertEqual(entry.status, count == 0 ? .noUnexpected : .unexpected)
        }
    }

    func testInternalOpaqueCallIsNotSideEntryButCanConflictWithWindow() throws {
        let selfCall = try XCTUnwrap(analyze([0xb4000095, 0xaa1503e0, 0x94000000, 0x92800000]).regions.first)
        XCTAssertEqual(selfCall.incomingEntries?.unexpectedEntryCount, 0)
        // At +12, BL -8 enters the original test at +4.
        let windowCall = try XCTUnwrap(analyze([0xb4000095, 0xaa1503e0, 0x97fffffe, 0x92800000]).regions.first)
        XCTAssertEqual(windowCall.status, .candidate)
        XCTAssertEqual(windowCall.incomingEntries?.unexpectedEntryCount, 0)
        XCTAssertEqual(windowCall.postcallWindow.unexpectedEntryCount, 1)
    }

    func testWindowIncludesCopyCompareAndTestButExcludesCallAndEnd() throws {
        let window: [UInt32] = [0xaa1503f3, 0xf100027f, 0x54000080, 0xaa1303e0, 0xd503201f, 0x92800000]
        for (target, expected) in [(0, 0), (4, 1), (8, 1), (12, 1), (16, 0)] {
            let region = try XCTUnwrap(analyze(window, extras: [7: branch(from: 28, to: target)]).regions.first)
            XCTAssertEqual(region.postcallWindow.unexpectedEntryCount, expected)
            XCTAssertEqual(region.postcallWindow.protectedEndExclusive, 0x1010)
        }
    }

    func testUnknownIndirectAndNoncanonicalBranchesLeaveAbsenceUnresolved() throws {
        for word: UInt32 in [0xffffffff, 0xd61f0000, 0xd63f0000, 0xd65f0000,
                             0x54000010, 0x55000000, 0x5400000e, 0x5400000f] {
            let entry = try XCTUnwrap(analyze(extras: [5: word]).regions.first?.incomingEntries)
            XCTAssertEqual(entry.status, .unresolved)
            XCTAssertEqual(entry.unclassifiedWordCount, 1)
            XCTAssertEqual(entry.unclassifiedWords.first?.address, 0x1014)
            XCTAssertEqual(entry.unclassifiedWords.first?.word, word)
        }
        let terminal = try XCTUnwrap(analyze(extras: [5: 0xd65f03c0]).regions.first?.incomingEntries)
        XCTAssertEqual(terminal.status, .noUnexpected)
        XCTAssertFalse(terminal.exclusiveEntryProven)
    }

    func testPartialCallerNeverClaimsAbsenceAndDoesNotReadSuffix() throws {
        let entry = try XCTUnwrap(analyze(extras: [4096: 0xffffffff], callerWords: 4097).regions.first?.incomingEntries)
        XCTAssertEqual(entry.status, .unresolved)
        XCTAssertFalse(entry.callerScanComplete)
        XCTAssertEqual(entry.scannedWordCount, 4096)
        XCTAssertEqual(entry.callerWordCount, 4097)
        XCTAssertEqual(entry.unclassifiedWordCount, 0)
    }

    func testObservedConflictTakesPrecedenceOverPartialAndUnknown() throws {
        let entry = try XCTUnwrap(analyze(extras: [5: 0x17fffffd, 6: 0xffffffff], callerWords: 4097).regions.first?.incomingEntries)
        XCTAssertEqual(entry.status, .unexpected)
        XCTAssertEqual(entry.unexpectedEntryCount, 1)
        XCTAssertEqual(entry.unclassifiedWordCount, 1)
        XCTAssertFalse(entry.callerScanComplete)
    }

    func testConflictDetailsAreCappedWithoutLosingInspectedTotals() throws {
        let extras = Dictionary(uniqueKeysWithValues: (5..<25).map { ($0, branch(from: $0 * 4, to: 8)) })
        let entry = try XCTUnwrap(analyze(extras: extras).regions.first?.incomingEntries)
        XCTAssertEqual(entry.unexpectedEntryCount, 20)
        XCTAssertEqual(entry.unexpectedEntries.count, 16)
        XCTAssertFalse(entry.entryDetailsComplete)
        XCTAssertEqual(entry.unexpectedEntries.last?.address, 0x1050)
        XCTAssertTrue(entry.callerScanComplete)
    }

    func testUnknownDetailsHaveIndependentCapAndExactInspectedTotal() throws {
        let extras = Dictionary(uniqueKeysWithValues: (5..<25).map { ($0, UInt32(0xffffffff)) })
        let entry = try XCTUnwrap(analyze(extras: extras).regions.first?.incomingEntries)
        XCTAssertEqual(entry.unclassifiedWordCount, 20)
        XCTAssertEqual(entry.unclassifiedWords.count, 16)
        XCTAssertFalse(entry.unclassifiedDetailsComplete)
        XCTAssertTrue(entry.entryDetailsComplete)
        XCTAssertEqual(entry.status, .unresolved)
    }

    func testInvalidDirectTargetsAreUnknownAndInvalidRegionCallsDecline() throws {
        let underflow = try XCTUnwrap(analyze(extras: [5: 0x17fffff0], base: 0).regions.first?.incomingEntries)
        XCTAssertEqual(underflow.status, .unresolved)
        XCTAssertEqual(underflow.unclassifiedWordCount, 1)
        for (base, call) in [(UInt64(0), UInt32(0x96000000)), (UInt64.max - 0x103, UInt32(0x95ffffff))] {
            let region = try XCTUnwrap(analyze([0xb4000095, 0xaa1503e0, call, 0x92800000], base: base).regions.first)
            XCTAssertEqual(region.reason, .invalidCallTarget)
            XCTAssertEqual(region.instructions.last?.word, call)
            XCTAssertNil(region.instructions.last?.targetAddress)
        }
    }

    func testRegionBeyondCallerScanPrefixIsDeclinedWithoutInspection() throws {
        var input = request(callerWords: 4100)
        input.code.words[0] = 0xd503201f
        input.code.words[4094] = 0x94000006 // Calls the declared function at word 4100.
        input.code.words[4095] = 0xb4000055 // Success at word 4097; error at 4096.
        input.code.words[4096] = 0xd503201f
        let report = SwiftErrorRegionAnalyzer.analyze(input)
        let region = try XCTUnwrap(report.regions.first)
        XCTAssertEqual(report.edgeReport.edges.count, 1)
        XCTAssertEqual(region.reason, .outsideCallerScan)
        XCTAssertTrue(region.instructions.isEmpty)
        XCTAssertFalse(region.postcallWindow.callerScanComplete)
    }

    func testTwoCallsShareOneScanButRetainDifferentEntryChecks() throws {
        // Second call at +24; second interval [+32,+44). At +48, B enters first interval only.
        let extras: [Int: UInt32] = [6: 0x9400001a, 7: 0xb4000095, 8: 0xd503201f,
                                     9: 0xd503201f, 10: 0xd503201f, 12: 0x17fffff6]
        let report = analyze(extras: extras)
        XCTAssertEqual(report.regions.count, 2)
        XCTAssertEqual(report.callerScanCount, 1)
        XCTAssertEqual(report.scannedWordCount, 32)
        XCTAssertEqual(report.regions[0].incomingEntries?.unexpectedEntryCount, 1)
        XCTAssertEqual(report.regions[1].incomingEntries?.unexpectedEntryCount, 0)
        XCTAssertEqual(report.regions[1].startAddress, 0x1020)
    }

    func testAttemptCapIncludesDeclinesAndPreservesExactOmissionCount() {
        var input = request()
        let callerCount = 257, calleeIndex = callerCount * 4
        input.code.words = []
        input.functions = []
        for index in 0..<callerCount {
            let start = UInt64(0x1000 + index * 16)
            input.functions.append(.init(start: start, endExclusive: start + 16, boundarySource: "lc_function_starts"))
            input.code.words += [0x94000000 | UInt32(calleeIndex - index * 4), 0xb5000055, 0xd503201f, 0xd65f03c0]
        }
        let callee = UInt64(0x1000 + calleeIndex * 4)
        input.code.words.append(0xd65f03c0)
        input.functions.append(.init(start: callee, endExclusive: callee + 4, boundarySource: "lc_function_starts"))
        input.symbols[0].address = callee
        let report = SwiftErrorRegionAnalyzer.analyze(input)
        XCTAssertEqual(report.recoveredEdgeCount, 257)
        XCTAssertEqual(report.regions.count, 256)
        XCTAssertEqual(report.omittedRegionCount, 1)
        XCTAssertFalse(report.regionDetailsComplete)
        XCTAssertTrue(report.regions.allSatisfy { $0.reason == .unsupportedLayout })
        XCTAssertEqual(report.regions.last?.edge.callAddress, 0x1ff0)
        XCTAssertEqual(report.callerScanCount, 256)
        XCTAssertEqual(report.scannedWordCount, 1024)
    }

    func testRejectedInputCannotProduceRegionsOrCallerScans() {
        var input = request()
        input.code.hasEmbeddedData = true
        let report = SwiftErrorRegionAnalyzer.analyze(input)
        XCTAssertEqual(report.edgeReport.status, .rejected)
        XCTAssertEqual(report.edgeReport.abstentions.first?.code, "tainted_code_mapping")
        XCTAssertTrue(report.regions.isEmpty)
        XCTAssertEqual(report.callerScanCount, 0)
        XCTAssertEqual(report.scannedWordCount, 0)
    }

    func testEncodingSeparatesModelsAndKeepsProofFlagsFalse() throws {
        let report = analyze()
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any])
        XCTAssertEqual(json["model"] as? String, "macscope-swift-error-region-native-v1")
        XCTAssertEqual(json["entryModel"] as? String, "macscope-swift-region-direct-entries-native-v1")
        XCTAssertEqual(report.edgeReport.model, "macscope-swift-error-flow-native-v2-register-copies")
        XCTAssertEqual(json["sourceReconstructionAllowed"] as? Bool, false)
        XCTAssertEqual(json["runtimeReachabilityProven"] as? Bool, false)
        XCTAssertEqual(report.omittedRegionCount, 0)
        XCTAssertTrue(report.regionDetailsComplete)
        let region = try XCTUnwrap(report.regions.first)
        XCTAssertFalse(region.runtimeReachabilityProven)
        XCTAssertFalse(region.joinReachabilityProven)
        XCTAssertFalse(region.callReturnProven)
        XCTAssertFalse(try XCTUnwrap(region.incomingEntries).exclusiveEntryProven)
    }

    private func analyze(_ window: [UInt32] = [0xb4000095, 0xaa1503e0, 0xd503201f, 0x92800000],
                         extras: [Int: UInt32] = [:], callerWords: Int = 32, base: UInt64 = 0x1000) -> SwiftErrorRegionReport {
        SwiftErrorRegionAnalyzer.analyze(request(window, extras: extras, callerWords: callerWords, base: base))
    }

    private func request(_ window: [UInt32] = [0xb4000095, 0xaa1503e0, 0xd503201f, 0x92800000],
                         extras: [Int: UInt32] = [:], callerWords: Int = 32, base: UInt64 = 0x1000) -> SwiftErrorFlowRequest {
        var words = [UInt32(0x94000000) | UInt32(callerWords)] + window
        words += Array(repeating: UInt32(0xd65f03c0), count: callerWords + 1 - words.count)
        for (index, word) in extras { words[index] = word }
        let callee = base + UInt64(callerWords) * 4
        return .init(
            slice: .init(artifactSHA256: String(repeating: "a", count: 64), sliceOffset: 0,
                         sliceByteCount: 1_048_576, cpuType: 0x0100000c, cpuSubtype: 0, littleEndian: true),
            code: .init(baseAddress: base, sliceRelativeFileOffset: 256, sectionOrdinal: 1,
                        hasEmbeddedData: false, hasRelocations: false, words: words),
            functions: [.init(start: base, endExclusive: callee, boundarySource: "lc_function_starts"),
                        .init(start: callee, endExclusive: callee + 4, boundarySource: "lc_function_starts")],
            symbols: [.init(address: callee, name: "_$s4Demo5parseyS2iKF", nType: 0x0f, nDesc: 0, sectionOrdinal: 1)])
    }

    private func branch(from: Int, to: Int) -> UInt32 {
        0x14000000 | (UInt32(truncatingIfNeeded: (to - from) / 4) & 0x03ffffff)
    }
}
