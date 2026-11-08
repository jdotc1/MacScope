import Foundation
import XCTest
@testable import MacScope

/// Wire version 5 framed analysis reply (candidate K2). The emitter is OFF by default; the decoder
/// recognizes a frame by its magic. Fixture F is the cancelled failure envelope; frame B wraps it.
final class FramedAnalysisReplyTests: XCTestCase {
    private let cancelled = Array(#"{"version":5,"failure":{"cancelled":{}}}"#.utf8)

    // MARK: Frame builders

    private func le32(_ value: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: value >> UInt32(8 * $0)) } }
    private func le64(_ value: UInt64) -> [UInt8] { (0..<8).map { UInt8(truncatingIfNeeded: value >> UInt64(8 * $0)) } }

    private func section(_ tag: UInt32, _ body: [UInt8], rows: UInt64, length: UInt64? = nil) -> [UInt8] {
        le32(tag) + le64(length ?? UInt64(body.count)) + le64(rows) + body
    }

    private func header(version: UInt32 = 5, outcome: UInt8 = 1, count: UInt32 = 1) -> [UInt8] {
        Array("MSAREPLY".utf8) + le32(version) + [outcome] + le32(count)
    }

    private func failureFrame(_ json: [UInt8]? = nil, version: UInt32 = 5) -> Data {
        Data(header(version: version) + section(8, json ?? cancelled, rows: 1))
    }

    private func codec(_ edit: (inout PayloadWireCodec.Limits) -> Void = { _ in }) -> PayloadWireCodec {
        var limits = PayloadWireCodec.Limits.production
        edit(&limits)
        return PayloadWireCodec(limits: limits)
    }

    private func assertLimit(_ expected: String, file: StaticString = #filePath, line: UInt = #line,
                             _ operation: () throws -> Void) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            guard case DecodingError.dataCorrupted(let context) = error else {
                return XCTFail("Expected a budget or framing rejection, got \(error)", file: file, line: line)
            }
            XCTAssertTrue(context.debugDescription.contains(expected), context.debugDescription, file: file, line: line)
        }
    }

    private func assertMalformed(_ data: Data, file: StaticString = #filePath, line: UInt = #line) {
        assertLimit("malformed", file: file, line: line) { _ = try codec().decodeReply(data) }
    }

    private func assertCancelled(_ data: Data, _ codec: PayloadWireCodec, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try codec.decodeReply(data), file: file, line: line) {
            XCTAssertTrue($0 is AnalysisCancelled, "Unexpected error: \($0)", file: file, line: line)
        }
    }

    // MARK: TC02/TC03 raw byte limit

    func testFrameRawByteLimitIsInclusive() {
        let data = failureFrame()
        XCTAssertEqual(data.count, 17 + 20 + cancelled.count)
        assertCancelled(data, codec { $0.maximumReplyBytes = data.count })
        assertLimit("raw byte") { _ = try codec { $0.maximumReplyBytes = data.count - 1 }.decodeReply(data) }
    }

    // MARK: TC04/TC05/TC07 ledgers

    func testFrameValueLedgerMatchesLegacyJSON() {
        let data = failureFrame()
        assertCancelled(data, codec { $0.maximumReplyValues = 7 })
        assertLimit("values=7, limit=6") { _ = try codec { $0.maximumReplyValues = 6 }.decodeReply(data) }
    }

    func testFrameStringLedgerMatchesLegacyJSON() {
        let data = failureFrame()
        assertCancelled(data, codec { $0.maximumReplyStringBytes = 23; $0.maximumReplySingleStringBytes = 9 })
        assertLimit("string byte") { _ = try codec { $0.maximumReplyStringBytes = 22; $0.maximumReplySingleStringBytes = 9 }.decodeReply(data) }
        assertLimit("string byte") { _ = try codec { $0.maximumReplyStringBytes = 23; $0.maximumReplySingleStringBytes = 8 }.decodeReply(data) }
    }

    func testFrameDepthLedgerMatchesLegacyJSON() {
        let data = failureFrame()
        assertCancelled(data, codec { $0.maximumNestingDepth = 3 })
        assertLimit("nesting depth") { _ = try codec { $0.maximumNestingDepth = 2 }.decodeReply(data) }
    }

    // MARK: TC06 canonical string charging

    func testCanonicalStringChargeCountsEscapedBytes() throws {
        func symbolFrame(_ name: String) throws -> (Data, Int) {
            var snapshot = WorkspaceSnapshot(binaries: [], functions: [], instructions: [], xrefs: [], hexBytes: Data())
            snapshot.symbols = [SymbolSummary(id: UUID(), name: name, address: nil, kind: "k", libraryName: nil)]
            var limits = PayloadWireCodec.Limits.production
            limits.framedReplies = true
            return (PayloadWireCodec(limits: limits).encodeReply(.success(snapshot)), name.utf8.count)
        }
        // The smallest string budget that admits the reply is the charge; a quote costs two, a C0 control six.
        func minimumBudget(_ name: String) throws -> Int {
            let (data, _) = try symbolFrame(name)
            var low = 1, high = 4096
            while low < high {
                let mid = (low + high) / 2
                var limits = PayloadWireCodec.Limits.production
                limits.maximumReplyStringBytes = mid
                limits.maximumReplySingleStringBytes = mid
                if (try? PayloadWireCodec(limits: limits).decodeReply(data)) != nil { high = mid } else { low = mid + 1 }
            }
            return low
        }
        let plain = try minimumBudget("aaa")
        XCTAssertEqual(try minimumBudget("a\"a"), plain + 1)
        XCTAssertEqual(try minimumBudget("a\\a"), plain + 1)
        XCTAssertEqual(try minimumBudget("a/a"), plain + 1)
        XCTAssertEqual(try minimumBudget("a\u{01}a"), plain + 5)
        XCTAssertEqual(try minimumBudget("a\u{00E9}a"), plain + 1)
    }

    // MARK: TC08 framing rejections

    func testFramingRejections() {
        let good = Array(failureFrame())
        // Declared length one byte too long, truncated, and an extra trailing byte.
        assertMalformed(Data(header() + section(8, cancelled, rows: 1, length: UInt64(cancelled.count + 1))))
        assertMalformed(Data(good.dropLast()))
        assertMalformed(Data(good + [0]))
        // Header faults.
        assertMalformed(Data(Array("MSAREPLY".utf8) + [5, 0]))
        assertMalformed(Data(header(outcome: 2) + section(8, cancelled, rows: 1)))
        assertMalformed(Data(header(count: 2) + section(8, cancelled, rows: 1)))
        // Section faults: unknown tag, wrong tag, UInt64.max length, residual row count, empty residual.
        assertMalformed(Data(header() + section(99, cancelled, rows: 1)))
        assertMalformed(Data(header() + section(1, cancelled, rows: 1)))
        assertMalformed(Data(header() + section(8, cancelled, rows: 1, length: UInt64.max)))
        assertMalformed(Data(header() + section(8, cancelled, rows: 2)))
        assertMalformed(Data(header() + section(8, [], rows: 1)))
        // A success frame with a missing section.
        assertMalformed(Data(header(outcome: 0, count: 8) + section(1, [], rows: 0)))
    }

    func testRowCountAndEmptySectionRules() {
        var parts = header(outcome: 0, count: 8)
        parts += section(1, [], rows: 1)
        assertMalformed(Data(parts))
        parts = header(outcome: 0, count: 8) + section(1, [UInt8](repeating: 0, count: 28), rows: 1)
        assertMalformed(Data(parts))
        parts = header(outcome: 0, count: 8) + section(1, [], rows: UInt64.max)
        assertMalformed(Data(parts))
    }

    func testBranchesAreExclusiveAndVersionsMustAgree() {
        let both = Array(#"{"version":5,"failure":{"cancelled":{}},"payload":null}"#.utf8)
        assertCancelled(failureFrame(both), codec())
        assertMalformed(failureFrame(Array(#"{"version":5}"#.utf8)))
        assertMalformed(failureFrame(Array(#"{"version":4,"failure":{"cancelled":{}}}"#.utf8)))
        // A success header over a failure residual is ambiguous.
        var data = header(outcome: 0, count: 8)
        for tag in UInt32(1)...7 { data += section(tag, [], rows: 0) }
        data += section(8, cancelled, rows: 1)
        assertMalformed(Data(data))
    }

    // MARK: TC10 versions

    func testVersionMismatchIsReportedForLegacyAndFramedReplies() {
        let legacy = Data(#"{"version":4,"failure":{"cancelled":{}}}"#.utf8)
        for data in [legacy, failureFrame(version: 4)] {
            XCTAssertThrowsError(try codec().decodeReply(data)) {
                guard case AnalysisWorkerError.versionMismatch(let expected, let got)? = $0 as? AnalysisWorkerError else {
                    return XCTFail("Expected versionMismatch, got \($0)")
                }
                XCTAssertEqual(expected, 5)
                XCTAssertEqual(got, 4)
            }
        }
    }

    // MARK: TC01 round trip

    private func populated() -> WorkspaceSnapshot {
        let function = UUID(), block = UUID()
        var snapshot = WorkspaceSnapshot(binaries: [], functions: [], instructions: [], xrefs: [],
                                         hexBytes: Data([1, 2, 3]))
        snapshot.imageBytes = Data([9, 8, 7])
        snapshot.functions = [
            FunctionSummary(id: function, name: "_main \"q\" \u{00E9}", startAddress: 0x1000, endAddress: 0x1040,
                            confidence: 0.75, noReturnProvenance: .catalog),
            FunctionSummary(id: UUID(), name: "_f", startAddress: 0x2000, endAddress: 0x2010, confidence: 1),
        ]
        snapshot.symbols = [
            SymbolSummary(id: UUID(), name: "_a", address: 0x10, kind: "func", libraryName: "libSystem", rawLinkageName: "_a"),
            SymbolSummary(id: UUID(), name: "b", address: nil, kind: "data", libraryName: nil),
        ]
        snapshot.stringLiterals = [
            StringLiteralSummary(id: UUID(), value: "hi\n\"there\"/\\", address: 0x3000, sourceSection: "__cstring", byteLength: 12),
        ]
        snapshot.basicBlocks = [
            BasicBlockSummary(id: block, functionID: function, startAddress: 0x1000, endAddress: 0x1010, instructionCount: 4),
        ]
        snapshot.instructions = [
            InstructionRow(address: 0x1000, bytes: "1f 20", mnemonic: "nop", operands: "", hasBreakpoint: false, comment: nil),
            InstructionRow(address: 0x1004, bytes: "c0 03", mnemonic: "ret", operands: "x0", hasBreakpoint: true,
                           comment: "done \u{00E9}",
                           structuredOperands: InstructionOperands(coverage: .partial, opcodeClass: "partial",
                                                                   operands: [.opaque("unknown")])),
        ]
        snapshot.xrefs = [XRef(id: UUID(), from: 1, to: 2, kind: "call")]
        snapshot.controlFlowEdges = [ControlFlowEdge(id: UUID(), from: 0x1000, to: 0x1004, kind: "fallthrough")]
        return snapshot
    }

    func testFramedRoundTripEqualsLegacyDecode() throws {
        let snapshot = populated()
        var framedLimits = PayloadWireCodec.Limits.production
        framedLimits.framedReplies = true
        let framed = PayloadWireCodec(limits: framedLimits).encodeReply(.success(snapshot))
        XCTAssertEqual(Array(framed.prefix(8)), Array("MSAREPLY".utf8))
        let viaFrame = try PayloadWireCodec().decodeReply(framed)
        let viaJSON = try PayloadWireCodec().decodeReply(PayloadWireCodec().encodeReply(.success(snapshot)))
        XCTAssertEqual(viaFrame.functions, viaJSON.functions)
        XCTAssertEqual(viaFrame.symbols, viaJSON.symbols)
        XCTAssertEqual(viaFrame.stringLiterals, viaJSON.stringLiterals)
        XCTAssertEqual(viaFrame.basicBlocks, viaJSON.basicBlocks)
        XCTAssertEqual(viaFrame.instructions, viaJSON.instructions)
        XCTAssertEqual(viaFrame.xrefs, viaJSON.xrefs)
        XCTAssertEqual(viaFrame.controlFlowEdges, viaJSON.controlFlowEdges)
        XCTAssertEqual(viaFrame.imageBytes, snapshot.imageBytes)
        XCTAssertEqual(viaFrame.functions.count, 2)
    }

    func testFramedRowLedgerMatchesLegacyValueCount() throws {
        let snapshot = populated()
        let legacy = PayloadWireCodec().encodeReply(.success(snapshot))
        var framedLimits = PayloadWireCodec.Limits.production
        framedLimits.framedReplies = true
        let framed = PayloadWireCodec(limits: framedLimits).encodeReply(.success(snapshot))
        var low = 1, high = 100_000
        while low < high {
            let mid = (low + high) / 2
            if (try? codec { $0.maximumReplyValues = mid }.decodeReply(legacy)) != nil { high = mid } else { low = mid + 1 }
        }
        let legacyValues = low
        XCTAssertNoThrow(try codec { $0.maximumReplyValues = legacyValues }.decodeReply(framed))
        assertLimit("aggregate model value") { _ = try codec { $0.maximumReplyValues = legacyValues - 1 }.decodeReply(framed) }
    }

    func testFramedRowBytesCorruptionIsRejected() throws {
        var framedLimits = PayloadWireCodec.Limits.production
        framedLimits.framedReplies = true
        var bytes = Array(PayloadWireCodec(limits: framedLimits).encodeReply(.success(populated())))
        // First section is the instructions; its first row's breakpoint flag sits at header + 20 + 8.
        bytes[17 + 20 + 8] = 2
        assertMalformed(Data(bytes))
    }

    // MARK: Emitter

    func testEmitterIsOffByDefault() {
        XCTAssertFalse(PayloadWireCodec.Limits.production.framedReplies)
        let data = PayloadWireCodec().encodeReply(.success(populated()))
        XCTAssertEqual(data.first, UInt8(ascii: "{"))
    }

    func testEmitterRefusalIsALegacyUnexpectedFailure() {
        var limits = PayloadWireCodec.Limits.production
        limits.framedReplies = true
        limits.maximumReplyBytes = 100
        let data = PayloadWireCodec(limits: limits).encodeReply(.success(populated()))
        XCTAssertEqual(data.first, UInt8(ascii: "{"))
        XCTAssertLessThanOrEqual(data.count, 1_000)
        XCTAssertThrowsError(try PayloadWireCodec().decodeReply(data)) {
            guard let failure = $0 as? RemoteAnalysisFailure else { return XCTFail("Got \($0)") }
            XCTAssertTrue(failure.message.contains("raw byte limit"), failure.message)
        }
    }

    func testEmitterRefusesNonFiniteConfidence() {
        var snapshot = populated()
        snapshot.functions[0].confidence = .nan
        var limits = PayloadWireCodec.Limits.production
        limits.framedReplies = true
        let data = PayloadWireCodec(limits: limits).encodeReply(.success(snapshot))
        XCTAssertThrowsError(try PayloadWireCodec().decodeReply(data)) {
            XCTAssertTrue($0 is RemoteAnalysisFailure, "Got \($0)")
        }
    }

    // MARK: TC11 pinned range composition

    func testFramedReplyKeepsPinnedImageBytesRule() {
        var snapshot = populated()
        snapshot.imageBytes = Data([1, 2, 3, 4])
        let range = AnalysisPinnedImageByteRange(offset: 0, byteCount: 4, sha256: "unused")
        var limits = PayloadWireCodec.Limits.production
        limits.framedReplies = true
        let data = PayloadWireCodec(limits: limits).encodeReply(.success(snapshot), pinnedImageBytes: range)
        XCTAssertThrowsError(try PayloadWireCodec().decodeReply(data)) {
            XCTAssertEqual($0 as? AnalysisPinnedImageBytesError, .pinnedSourceMissing)
        }
        limits.maximumPinnedImageBytes = 3
        assertLimit("pinned image byte") { _ = try PayloadWireCodec(limits: limits).decodeReply(data) }
    }
}
