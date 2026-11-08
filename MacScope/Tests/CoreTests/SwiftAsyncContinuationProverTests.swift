import Foundation
import XCTest
@testable import MacScope

final class SwiftAsyncContinuationProverTests: XCTestCase {
    private struct Truth: Decodable {
        var negative: Bool
        var source: UInt64
        var callee: UInt64
        var resume: UInt64
        var transfer: UInt64
        var entryMetadataCount: Int
        var resumeMetadataCount: Int
    }

    private struct Fixture {
        var data: Data
        var truth: Truth
        var parser: SwiftMetadataParser
        var metadata: SwiftAsyncMetadata
    }

    private var fixtures: URL {
        TestSourceRoot.url.appendingPathComponent("MacScope/Tests/Fixtures/SwiftAsyncContinuations")
    }

    private func fixture(_ name: String) throws -> Fixture {
        let data = try Data(contentsOf: fixtures.appendingPathComponent(name + ".bin"))
        let truth = try JSONDecoder().decode(Truth.self,
            from: Data(contentsOf: fixtures.appendingPathComponent(name + ".truth.json")))
        let parser = makeParser(data: data, entries: truth.entryMetadataCount,
                                resumes: truth.resumeMetadataCount)
        return Fixture(data: data, truth: truth, parser: parser, metadata: parser.parseAsyncFunctions())
    }

    private func makeParser(data: Data, entries: Int = 2, resumes: Int = 1,
                            allocator: String = "_swift_task_alloc", additionalBinds: [UInt64: String] = [:],
                            rebases: [UInt64: UInt64] = [:]) -> SwiftMetadataParser {
        var binds: [UInt64: String] = [0x1180: allocator, 0x1188: "_untrusted_mutator"]
        binds.merge(additionalBinds) { _, replacement in replacement }
        return SwiftMetadataParser(data: data, sections: [
            .init(name: "__text", address: 0x1000, fileOffset: 0, size: 0x100,
                  isExecutable: true, segmentName: "__TEXT"),
            .init(name: "__stubs", address: 0x1100, fileOffset: 0x100, size: 0x20,
                  isExecutable: true, segmentName: "__TEXT"),
            .init(name: "__got", address: 0x1180, fileOffset: 0x180, size: 0x20,
                  segmentName: "__DATA"),
            .init(name: "__swift_as_entry", address: 0x11a0, fileOffset: 0x1a0,
                  size: UInt64(entries * 4), segmentName: "__TEXT"),
            .init(name: "__swift_as_ret", address: 0x11b0, fileOffset: 0x1b0,
                  size: UInt64(resumes * 4), segmentName: "__TEXT"),
            .init(name: "__const", address: 0x11c0, fileOffset: 0x1c0, size: 16,
                  segmentName: "__TEXT")
        ], rebaseTargets: rebases, bindNames: binds)
    }

    private func assertPositive(_ name: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let f = try fixture(name)
        XCTAssertFalse(f.truth.negative, file: file, line: line)
        let report = SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata)
        XCTAssertEqual(report.edges.count, 1, file: file, line: line)
        let edge = try XCTUnwrap(report.edges.first, file: file, line: line)
        XCTAssertEqual(edge.source, f.truth.source, file: file, line: line)
        XCTAssertEqual(edge.resume, f.truth.resume, file: file, line: line)
        XCTAssertEqual(edge.kind, .calleeReturn, file: file, line: line)
        XCTAssertEqual(edge.certificate.callee, f.truth.callee, file: file, line: line)
        XCTAssertEqual(edge.certificate.transfer, f.truth.transfer, file: file, line: line)
        XCTAssertTrue(SwiftAsyncContinuationCertificateVerifier.verify(edge.certificate,
            parser: f.parser, metadata: f.metadata), file: file, line: line)
        XCTAssertEqual(report.chains.first(where: { $0.entry == f.truth.source })?.partials,
                       [f.truth.resume], file: file, line: line)
    }

    private func assertNegative(_ name: String, reason: String,
                                file: StaticString = #filePath, line: UInt = #line) throws {
        let f = try fixture(name)
        XCTAssertTrue(f.truth.negative, file: file, line: line)
        let report = SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata)
        XCTAssertTrue(report.edges.isEmpty, file: file, line: line)
        XCTAssertTrue(report.abstentions.contains { $0.source == f.truth.source && $0.reason == reason },
                      "Expected \(reason), got \(report.abstentions)", file: file, line: line)
    }

    func testPositiveContextStoresProveOneEdge() throws { try assertPositive("positive") }
    func testCallBeforeStoresAllowsFreshProof() throws { try assertPositive("call_before_stores") }
    func testRematerializedStoresAfterCallAllowFreshProof() throws { try assertPositive("restore_after_call") }

    func testContextRegisterImpostorRefuses() throws {
        try assertNegative("x22_impostor", reason: "unprovedAsyncContext")
    }
    func testAliasClobberKillsStores() throws {
        try assertNegative("alias_clobber", reason: "missing or clobbered live context stores")
    }
    func testWrongCalleeRefuses() throws {
        try assertNegative("wrong_callee", reason: "nonAsyncTransfer")
    }
    func testUnknownWriteKillsStores() throws {
        try assertNegative("unknown_write", reason: "missing or clobbered live context stores")
    }
    func testCompetingResumeRefuses() throws {
        try assertNegative("competing_resume", reason: "competingResume")
    }
    func testDistinctAllocationStoresCannotCombine() throws {
        try assertNegative("two_alloc_mismatch", reason: "missing or clobbered live context stores")
    }
    func testMissingResumeMetadataRefuses() throws {
        try assertNegative("no_resume_metadata", reason: "unproved or conflicting resume/parent provenance")
    }
    func testConditionalBranchRefuses() throws {
        try assertNegative("unsupported_branch", reason: "unsupportedBranch")
    }
    func testOrdinaryTailTransferRefuses() throws {
        try assertNegative("tail_impostor", reason: "nonAsyncTransfer")
    }
    func testStaleRegisterRestorationCannotProveResume() throws {
        try assertNegative("stale_restore_after_call", reason: "unproved or conflicting resume/parent provenance")
    }

    func testForgedCertificateWordOffsetAndDigestAreRejected() throws {
        let f = try fixture("positive")
        let report = SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata)
        let certificate = try XCTUnwrap(report.edges.first?.certificate)
        var forgedWord = certificate
        forgedWord.steps[0].word = 0xd503201f
        forgedWord = forgedWord.withDigest()
        var forgedOffset = certificate
        forgedOffset.resumeOffset = 16
        forgedOffset = forgedOffset.withDigest()
        var forgedDigest = certificate
        forgedDigest.digest = String(repeating: "0", count: 64)
        for forged in [forgedWord, forgedOffset, forgedDigest] {
            XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verify(forged,
                parser: f.parser, metadata: f.metadata))
        }
    }

    func testForgedEpochCannotBeHiddenByRecomputedDigest() throws {
        let f = try fixture("positive")
        let report = SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata)
        var forged = try XCTUnwrap(report.edges.first?.certificate)
        forged.steps[forged.steps.count - 1].epoch += 1
        forged = forged.withDigest()
        XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verify(forged,
            parser: f.parser, metadata: f.metadata))
    }

    func testPairedStoreProvesBothContextFields() throws {
        let f = try fixture("positive")
        var data = f.data
        writeWord(0xd503201f, at: 0x0c, in: &data)
        writeWord(0xa9000000 | (9 << 10) | (23 << 5) | 19, at: 0x14, in: &data)
        let parser = makeParser(data: data)
        let metadata = parser.parseAsyncFunctions()
        let report = SwiftAsyncContinuationProver.analyze(parser: parser, metadata: metadata)
        XCTAssertEqual(report.edges.count, 1)
        let certificate = try XCTUnwrap(report.edges.first?.certificate)
        XCTAssertEqual(certificate.parentStore, 0x1014)
        XCTAssertEqual(certificate.resumeStore, 0x1014)
        XCTAssertTrue(SwiftAsyncContinuationCertificateVerifier.verify(certificate, parser: parser, metadata: metadata))
    }

    func testSharedPartialProducesConflictWithoutMergingChains() throws {
        let f = try fixture("positive")
        var data = f.data
        let words: [UInt32] = [
            0xaa1603f3,
            branch(from: 0x1084, to: 0x1100, call: true),
            0xaa0003f7,
            0xf90002f3,
            addressInstruction(register: 9, from: 0x1090, to: 0x1060),
            0xf90006e9,
            0xaa1703f6,
            branch(from: 0x109c, to: 0x1040, call: false)
        ]
        for (index, word) in words.enumerated() { writeWord(word, at: 0x80 + index * 4, in: &data) }
        writeWord(UInt32(bitPattern: Int32(0x1080 - 0x11a8)), at: 0x1a8, in: &data)
        let parser = makeParser(data: data, entries: 3)
        let report = SwiftAsyncContinuationProver.analyze(parser: parser, metadata: parser.parseAsyncFunctions())
        XCTAssertEqual(report.edges.count, 2)
        for entry in [UInt64(0x1000), UInt64(0x1080)] {
            let chain = try XCTUnwrap(report.chains.first { $0.entry == entry })
            XCTAssertTrue(chain.partials.isEmpty)
            XCTAssertEqual(chain.conflicts, [0x1060])
        }
    }

    func testReservedStackStoresPreserveLaterStubLoad() throws {
        let f = try fixture("positive")
        var data = f.data
        let words: [UInt32] = [
            0xb24403bd, 0xd10083ff, 0xa9017bfd, 0xf90007f6, 0x910043fd,
            branch(from: 0x1014, to: 0x1100, call: true),
            addressInstruction(register: 8, from: 0x1018, to: 0x1060),
            0xa9002016, 0xaa0003f6, 0xa9417bfd, 0x9243fbbd, 0x910083ff,
            branch(from: 0x1030, to: 0x1040, call: false)
        ]
        for (index, word) in words.enumerated() { writeWord(word, at: index * 4, in: &data) }
        let parser = makeParser(data: data)
        try assertVerifiedProgram(parser)
    }

    func testUnprovedStackFootprintsRemainImageTainted() throws {
        let prefixes: [[UInt32]] = [
            [0xf90003ff],                         // no reservation: STR XZR,[SP]
            [0xd10043ff, 0xf9000bff],             // STR beyond a 16-byte frame
            [0xd10043ff, 0xa900fbfd],             // second STP lane crosses entry SP
            [0xd10083ff, 0x910043ff, 0xa900fbfd], // shrinking a frame drops the released interval
            [0xd10083ff, 0x910083ff, 0xf90003ff], // reservation already released
            [0xd10083ff, 0x9100c3ff, 0xf90003ff], // SP moved above entry; provenance cannot recover
            [0xd10023ff, 0xf90003ff],             // misaligned reservation is not admitted
            [0xd10083ff, 0xa9bf7bfd],             // unmodeled pre-indexed SP write
            [0xd10083ff, 0x9100015f, 0xf90003ff], // arbitrary ADD SP,X10,#0
            [0xd10083ff, 0x927befff, 0xf90003ff], // AND SP,XZR,#... loses provenance
            [0xd10083ff, 0xf9000adf],             // incoming context is not stack
        ]
        for prefix in prefixes {
            let words = stackProgram(prefix: prefix)
            assertProgramRefusal(try programParser(words), reason: "mutableImageLoad",
                                 at: 0x1000 + UInt64(prefix.count * 4))
        }
    }

    func testStackReservationCannotClearUnknownCallTaint() throws {
        let prefix: [UInt32] = [branch(from: 0x1000, to: 0x1110, call: true), 0xd10083ff, 0xf90003ff]
        assertProgramRefusal(try programParser(stackProgram(prefix: prefix)),
                             reason: "mutableImageLoad", at: 0x100c)
    }

    func testReservedStackStorePreservesLiveContextFields() throws {
        let words = stackProgram(prefix: [0xd10083ff], afterFields: [0xf90003ff, 0x910083ff])
        try assertVerifiedProgram(try programParser(words, binds: [0x1188: "_$s4Test3fooyyYaF"]))
    }

    func testAllocatedStoreOutsideHeaderCannotExemptImageReads() throws {
        // Restore the valid fields after each unsafe write. This must not clear
        // image taint merely because the base was returned by the allocator.
        for store in [UInt32(0xf900081f), 0xa900a016, 0xf81f801f, 0xb900001f] {
            let words = stackProgram(prefix: [], afterAllocation: [store])
            let parser = try programParser(words, binds: [0x1188: "_$s4Test3fooyyYaF"])
            assertProgramRefusal(parser, reason: "mutableImageLoad", at: 0x1000 + UInt64((words.count - 1) * 4))
        }
    }

    func testReplayDerivesStackBoundsDespiteRecomputedDigest() throws {
        let original = stackProgram(prefix: [0xd10083ff, 0xf9000fff]) // 8 bytes at SP+24 in 32-byte frame
        let binds: [UInt64: String] = [0x1188: "_$s4Test3fooyyYaF"]
        let certificate = try assertVerifiedProgram(try programParser(original, binds: binds))
        var changed = original
        changed[0] = 0xd10043ff // only reserve 16; same store now escapes
        let parser = try programParser(changed, binds: binds)
        var forged = certificate
        forged.steps[0].word = changed[0]
        // Also update the epoch story; rejection must survive a self-consistent
        // digest/epoch forgery rather than rely on a trivial trace mismatch.
        for index in 2..<forged.steps.count { forged.steps[index].epoch += 1 }
        forged = forged.withDigest()
        XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verify(forged,
            parser: parser, metadata: parser.parseAsyncFunctions()))
    }

    private func stackProgram(prefix: [UInt32], afterAllocation: [UInt32] = [],
                              afterFields: [UInt32] = []) -> [UInt32] {
        var words = prefix
        words.append(branch(from: 0x1000 + Int64(words.count * 4), to: 0x1100, call: true))
        words += afterAllocation
        words.append(addressInstruction(register: 8, from: 0x1000 + Int64(words.count * 4), to: 0x1060))
        words += [0xa9002016, 0xaa0003f6]
        words += afterFields
        words.append(branch(from: 0x1000 + Int64(words.count * 4), to: 0x1110, call: false))
        return words
    }

    private func incomingParser(_ words: [UInt32], size: UInt32 = 32,
                                symbols: [UInt64: [String]] = [0x11c0: ["_$s4Test3fooyyYaFTu"]]) throws -> SwiftMetadataParser {
        var data = try fixture("positive").data
        for (index, word) in words.enumerated() { writeWord(word, at: index * 4, in: &data) }
        writeWord(UInt32(bitPattern: Int32(0x1000 - 0x11c0)), at: 0x1c0, in: &data)
        writeWord(size, at: 0x1c4, in: &data)
        let base = makeParser(data: data, additionalBinds: [0x1188: "_$s4Test3fooyyYaF"])
        return SwiftMetadataParser(data: data, sections: base.sections, bindNames: base.bindNames,
                                   asyncFunctionPointerSymbols: symbols)
    }

    func testSymbolBoundIncomingPayloadStoresPreserveImageAndChildFacts() throws {
        // Writes at +16 before allocation and +24 after allocation mirror the
        // measured frontier without re-running that fixture or using its oracle.
        let words = stackProgram(prefix: [0xf9000adf], afterAllocation: [0xf9000ec0])
        let certificate = try assertVerifiedProgram(try incomingParser(words))
        XCTAssertEqual(certificate.incomingContext?.size, 32)
        XCTAssertEqual(certificate.incomingContext?.record, 0x11c0)
        // A MOV identity alias can still address the incoming payload after x22
        // is switched to the newly allocated child; neither child field is lost.
        let alias = stackProgram(prefix: [0xaa1603f3], afterFields: [0xf9000a7f])
        try assertVerifiedProgram(try incomingParser(alias))
        try assertVerifiedProgram(try incomingParser(stackProgram(prefix: [0xa9017edf]))) // STP XZR,XZR,[X22,#16]
    }

    func testIncomingBoundsRejectHeuristicInvalidAndConflictingRecords() throws {
        let words = stackProgram(prefix: [0xf9000edf])
        for size in [UInt32(0), 16, 24, UInt32.max] {
            assertProgramRefusal(try incomingParser(words, size: size), reason: "mutableImageLoad", at: 0x1004)
        }
        let symbolCases: [[UInt64: [String]]] = [[:], [0x11c0: ["_$s4Test3fooyyYaF"]],
            [0x11c8: ["_$s4Test3fooyyYaFTu"]],
            [0x11c0: ["_$s4Test3fooyyYaFTu", "_$s4Test3baryyYaFTu"]]]
        for symbols in symbolCases {
            assertProgramRefusal(try incomingParser(words, symbols: symbols), reason: "mutableImageLoad", at: 0x1004)
        }
        let parser = try incomingParser(words)
        var metadata = parser.parseAsyncFunctions()
        metadata.entries[0].pointerRecords.append(.init(address: 0x11c8, expectedContextSize: 64))
        XCTAssertNil(SwiftAsyncContinuationImage(parser: parser, metadata: metadata).incomingContextBound(at: 0x1000))
        metadata = parser.parseAsyncFunctions()
        metadata.entries.append(metadata.entries[0])
        XCTAssertNil(SwiftAsyncContinuationImage(parser: parser, metadata: metadata).incomingContextBound(at: 0x1000))
        metadata = parser.parseAsyncFunctions()
        metadata.entries[0].pointerRecords[0].expectedContextSize = 64
        XCTAssertNil(SwiftAsyncContinuationImage(parser: parser, metadata: metadata).incomingContextBound(at: 0x1000))
        metadata = parser.parseAsyncFunctions()
        metadata.entries[0].pointerRecords[0].address = UInt64.max - 3
        XCTAssertNil(SwiftAsyncContinuationImage(parser: parser, metadata: metadata).incomingContextBound(at: 0x1000))
        var bytes = Data(parser.bytes)
        writeWord(UInt32(bitPattern: Int32(0x1040 - 0x11c0)), at: 0x1c0, in: &bytes)
        let wrongTarget = SwiftMetadataParser(data: bytes, sections: parser.sections,
            bindNames: parser.bindNames, asyncFunctionPointerSymbols: parser.asyncFunctionPointerSymbols)
        XCTAssertNil(SwiftAsyncContinuationImage(parser: wrongTarget,
            metadata: parser.parseAsyncFunctions()).incomingContextBound(at: 0x1000))
    }

    func testIncomingBoundsRejectEscapingHeaderAndUnprovedAliasWrites() throws {
        let prefixes: [[UInt32]] = [
            [0xf90012df], // +32 escapes
            [0xa901fedf], // STP at +24: second lane escapes
            [0xf90006df], // header +8 is outside admitted payload
            [0xf81f82df], // negative offset
            [0xb90012df], // unmodeled 32-bit store
            [0xf8010edf], // pre-indexed STR, writeback
            [0x910002d3, 0xf9000a7f], // ADD alias lacks identity proof
            [0xaa1f03f3, 0xf9000a7f], // impostor base
            [0xaa1603f3, 0xd2800013, 0xf9000a7f] // clobbered MOV alias
        ]
        for prefix in prefixes {
            assertProgramRefusal(try incomingParser(stackProgram(prefix: prefix)),
                                 reason: "mutableImageLoad", at: 0x1000 + UInt64(prefix.count * 4))
        }
    }

    func testIncomingPayloadCannotClearUnknownCallTaint() throws {
        let prefix = [branch(from: 0x1000, to: 0x1110, call: true), UInt32(0xf9000adf)]
        assertProgramRefusal(try incomingParser(stackProgram(prefix: prefix)), reason: "mutableImageLoad", at: 0x1008)
    }

    func testIncomingExtentNeverPropagatesToResumePartial() throws {
        let parser = try incomingParser(stackProgram(prefix: [0xf9000adf]))
        var metadata = parser.parseAsyncFunctions()
        let image = SwiftAsyncContinuationImage(parser: parser, metadata: metadata)
        XCTAssertNotNil(image.incomingContextBound(at: 0x1000))
        XCTAssertNil(image.incomingContextBound(at: 0x1060))
        metadata.resumePartialAddresses.append(0x1000)
        XCTAssertNil(SwiftAsyncContinuationImage(parser: parser, metadata: metadata).incomingContextBound(at: 0x1000))
    }

    func testReplayRechecksIncomingRecordAndFootprintDespiteForgedDigest() throws {
        let words = stackProgram(prefix: [0xf9000edf])
        let parser = try incomingParser(words)
        let certificate = try assertVerifiedProgram(parser)
        for changed in [try incomingParser(words, size: 16), try incomingParser(words, symbols: [:])] {
            var forged = certificate
            forged.incomingContext = SwiftAsyncContinuationImage(parser: changed,
                metadata: changed.parseAsyncFunctions()).incomingContextBound(at: 0x1000)
            forged = forged.withDigest()
            XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verify(forged,
                parser: changed, metadata: changed.parseAsyncFunctions()))
        }
        var forged = certificate
        forged.incomingContext?.size = 64
        forged = forged.withDigest()
        XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verify(forged, parser: parser,
            metadata: parser.parseAsyncFunctions()))
        var alteredWords = words
        alteredWords[0] = 0xf90012df
        let changed = try incomingParser(alteredWords)
        forged = certificate
        forged.steps[0].word = alteredWords[0]
        for index in 1..<forged.steps.count { forged.steps[index].epoch += 1 }
        forged = forged.withDigest()
        XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verify(forged, parser: changed,
            metadata: changed.parseAsyncFunctions()))
    }

    func testOverwrittenImageSlotCannotSupplyOriginalResumePointer() throws {
        let f = try fixture("positive")
        var data = f.data
        writeWord(0x1060, at: 0x190, in: &data)
        writeWord(0, at: 0x194, in: &data)
        let words: [UInt32] = [
            0xaa1603f3,
            branch(from: 0x1004, to: 0x1100, call: true),
            0xaa0003f7,
            addressInstruction(register: 10, from: 0x100c, to: 0x1190),
            0xf900015f,
            0x58000009 | (UInt32((0x1190 - 0x1014) / 4) << 5),
            0xf90002f3, 0xf90006e9, 0xaa1703f6,
            branch(from: 0x1024, to: 0x1040, call: false)
        ]
        for (index, word) in words.enumerated() { writeWord(word, at: index * 4, in: &data) }
        let parser = makeParser(data: data)
        let report = SwiftAsyncContinuationProver.analyze(parser: parser, metadata: parser.parseAsyncFunctions())
        XCTAssertTrue(report.edges.isEmpty)
        XCTAssertTrue(report.abstentions.contains {
            $0.source == 0x1000 && $0.instruction == 0x1024
                && $0.reason == "unproved or conflicting resume/parent provenance"
        })
    }

    func testUnknownDestinationLoadAllowsLaterFreshResumeMaterialization() throws {
        let words: [UInt32] = [
            0xaa1603f3, branch(from: 0x1004, to: 0x1100, call: true), 0xaa0003f7,
            addressInstruction(register: 10, from: 0x100c, to: 0x1190), 0xf900015f,
            0x58000009 | (UInt32((0x1190 - 0x1014) / 4) << 5),
            0xf90002f3, addressInstruction(register: 9, from: 0x101c, to: 0x1060),
            0xf90006e9, 0xaa1703f6, branch(from: 0x1028, to: 0x1040, call: false)
        ]
        let parser = try programParser(words)
        let certificate = try assertVerifiedProgram(parser)
        XCTAssertEqual(certificate.steps.first { $0.address == 0x1014 }?.effect, "unknownImageLoad")
    }

    func testRebasedImageSlotSuppliesResumePointer() throws {
        let words = imageLoadProgram()
        let parser = try programParser(words, rebases: [0x1190: 0x1060])
        try assertVerifiedProgram(parser)
    }

    func testRebasedImageSlotOutsideResumeMetadataRefuses() throws {
        let parser = try programParser(imageLoadProgram(), rebases: [0x1190: 0x1080])
        assertProgramRefusal(parser, reason: "unproved or conflicting resume/parent provenance", at: 0x1020)
    }

    private func imageLoadProgram() -> [UInt32] {
        [0xaa1603f3, branch(from: 0x1004, to: 0x1100, call: true), 0xaa0003f7, 0xf90002f3,
         addressInstruction(register: 10, from: 0x1010, to: 0x1190), 0xf9400149,
         0xf90006e9, 0xaa1703f6, branch(from: 0x1020, to: 0x1040, call: false)]
    }

    func testBoundImageSlotTransfersToDemangledAsyncFunction() throws {
        let parser = try programParser(boundTransferProgram(), binds: [0x1190: "_$s4Test3fooyyYaF"])
        try assertVerifiedProgram(parser)
    }

    func testBoundImageSlotSynchronousFunctionRefuses() throws {
        let parser = try programParser(boundTransferProgram(), binds: [0x1190: "_$s4Test3fooyyF"])
        assertProgramRefusal(parser, reason: "nonAsyncTransfer", at: 0x1024)
    }

    private func boundTransferProgram() -> [UInt32] {
        [0xaa1603f3, branch(from: 0x1004, to: 0x1100, call: true), 0xaa0003f7, 0xf90002f3,
         addressInstruction(register: 9, from: 0x1010, to: 0x1060), 0xf90006e9,
         addressInstruction(register: 10, from: 0x1018, to: 0x1190), 0xf9400151,
         0xaa1703f6, 0xd61f0220]
    }

    func testStubTransferResolvesDemangledAsyncImport() throws {
        var data = try fixture("positive").data
        writeWord(branch(from: 0x101c, to: 0x1110, call: false), at: 0x1c, in: &data)
        let parser = makeParser(data: data, additionalBinds: [0x1188: "_$s4Test3fooyyYaF"])
        try assertVerifiedProgram(parser)
    }

    func testStubCannotResolveThroughUnreachableOrRejectedInstructions() throws {
        var data = try fixture("positive").data
        writeWord(branch(from: 0x101c, to: 0x1110, call: false), at: 0x1c, in: &data)
        writeWord(0xd503201f, at: 0x110, in: &data)
        writeWord(0x580003b1, at: 0x114, in: &data)
        writeWord(0xd61f0220, at: 0x118, in: &data)
        let binds: [UInt64: String] = [0x1188: "_$s4Test3fooyyYaF"]
        let valid = makeParser(data: data, additionalBinds: binds)
        let certificate = try assertVerifiedProgram(valid)
        for firstWord in [branch(from: 0x1110, to: 0x1040, call: false), 0xb2800000] {
            var changed = data
            writeWord(firstWord, at: 0x110, in: &changed)
            let invalid = makeParser(data: changed, additionalBinds: binds)
            assertProgramRefusal(invalid, reason: "nonAsyncTransfer", at: 0x101c)
            XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verify(certificate,
                parser: invalid, metadata: invalid.parseAsyncFunctions()))
        }
    }

    func testStubTransferToSynchronousImportRefuses() throws {
        var data = try fixture("positive").data
        writeWord(branch(from: 0x101c, to: 0x1110, call: false), at: 0x1c, in: &data)
        let parser = makeParser(data: data, additionalBinds: [0x1188: "_$s4Test3fooyyF"])
        assertProgramRefusal(parser, reason: "nonAsyncTransfer", at: 0x101c)
    }

    func testLogicalImmediateSubtractionAndNonliteralLoadsPreserveOtherRegisters() throws {
        for effect in [UInt32(0xb24403bd), 0x9243fbbd, 0xd10007bd, 0xf840015d] {
            try assertVerifiedProgram(programParser(registerEffectProgram(effect)))
        }
    }

    func testLogicalImmediateSubtractionAndNonliteralLoadsCannotPreserveTheirDestination() throws {
        for effect in [UInt32(0xb24403b3), 0x9243fbb3, 0xd1000673, 0xf8400153] {
            let parser = try programParser(registerEffectProgram(effect))
            assertProgramRefusal(parser, reason: "unproved or conflicting resume/parent provenance", at: 0x1020)
        }
    }

    private func registerEffectProgram(_ effect: UInt32) -> [UInt32] {
        [0xaa1603f3, branch(from: 0x1004, to: 0x1100, call: true), 0xaa0003f7, effect,
         0xf90002f3, addressInstruction(register: 9, from: 0x1014, to: 0x1060),
         0xf90006e9, 0xaa1703f6, branch(from: 0x1020, to: 0x1040, call: false)]
    }

    func testUnknownIndirectBranchRefusesAsUnsupportedBranch() throws {
        var data = try fixture("positive").data
        writeWord(0xd61f0220, at: 0x1c, in: &data)
        assertProgramRefusal(makeParser(data: data), reason: "unsupportedBranch", at: 0x101c)
    }

    func testUnsupportedInstructionIsReportedBeforeLaterABISite() throws {
        let parser = try programParser([0x9b0b7d49, branch(from: 0x1004, to: 0x1110, call: false)],
                                       binds: [0x1188: "_swift_task_switch"])
        let report = SwiftAsyncContinuationProver.analyze(parser: parser, metadata: parser.parseAsyncFunctions())
        XCTAssertTrue(report.edges.isEmpty)
        let refusal = try XCTUnwrap(report.abstentions.first { $0.source == 0x1000 })
        XCTAssertEqual(refusal.reason, "unsupportedInstruction")
        XCTAssertEqual(refusal.instruction, 0x1000)
        XCTAssertEqual(refusal.mnemonic, "mul")
    }

    func testDecoderRejectedMoveWideCannotEnterProofOrReplay() throws {
        let valid = try programParser(registerEffectProgram(0xd503201f))
        var forged = try assertVerifiedProgram(valid)
        let invalid = try programParser(registerEffectProgram(0xb2800000))
        assertProgramRefusal(invalid, reason: "unsupportedInstruction", at: 0x100c)
        forged.steps[3].word = 0xb2800000
        forged = forged.withDigest()
        XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verify(forged,
            parser: invalid, metadata: invalid.parseAsyncFunctions()))
    }

    private func programParser(_ words: [UInt32], binds: [UInt64: String] = [:],
                               rebases: [UInt64: UInt64] = [:]) throws -> SwiftMetadataParser {
        var data = try fixture("positive").data
        for (index, word) in words.enumerated() { writeWord(word, at: index * 4, in: &data) }
        return makeParser(data: data, additionalBinds: binds, rebases: rebases)
    }

    @discardableResult
    private func assertVerifiedProgram(_ parser: SwiftMetadataParser,
                                       file: StaticString = #filePath, line: UInt = #line) throws -> SwiftAsyncContinuationCertificate {
        let metadata = parser.parseAsyncFunctions()
        let report = SwiftAsyncContinuationProver.analyze(parser: parser, metadata: metadata)
        XCTAssertEqual(report.edges.count, 1, "\(report.abstentions)", file: file, line: line)
        let certificate = try XCTUnwrap(report.edges.first?.certificate, file: file, line: line)
        XCTAssertEqual(certificate.resume, 0x1060, file: file, line: line)
        XCTAssertTrue(SwiftAsyncContinuationCertificateVerifier.verify(certificate, parser: parser, metadata: metadata),
                      file: file, line: line)
        return certificate
    }

    private func assertProgramRefusal(_ parser: SwiftMetadataParser, reason: String, at instruction: UInt64,
                                      file: StaticString = #filePath, line: UInt = #line) {
        let report = SwiftAsyncContinuationProver.analyze(parser: parser, metadata: parser.parseAsyncFunctions())
        XCTAssertTrue(report.edges.isEmpty, file: file, line: line)
        XCTAssertTrue(report.abstentions.contains { $0.source == 0x1000 && $0.reason == reason && $0.instruction == instruction },
                      "\(report.abstentions)", file: file, line: line)
    }

    func testProjectionEmitsVerifiedFactAndCertificateProvenance() throws {
        let f = try fixture("positive")
        let report = SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata)
        let certificate = try XCTUnwrap(report.edges.first?.certificate)
        let output = SwiftMetadataFactProjection.projectAsyncContinuations(report,
            parser: f.parser, metadata: f.metadata, image: "Fixture", toolchain: "test")
        XCTAssertTrue(output.refused.isEmpty)
        XCTAssertTrue(output.frontier.isEmpty)
        XCTAssertEqual(output.facts.count, 1)
        let fact = try XCTUnwrap(output.facts.first)
        XCTAssertEqual(fact.subject, NavigatorSubject(kind: "function", ref: "0x1060", image: "Fixture"))
        XCTAssertEqual(fact.predicate, "asyncContinuationOf")
        XCTAssertEqual(fact.value, .string("0x1000"))
        XCTAssertEqual(fact.status, "proven")
        XCTAssertEqual(fact.provenance, [.init(kind: "proofCertificate", ref: "sha256:" + certificate.digest,
                                             rule: "macscope.swift-async-continuation", ruleVersion: "1")])
        let state = NavigatorEngineState(toolchain: "test", facts: output.facts, frontier: output.frontier)
        XCTAssertEqual(NavigatorContractValidator.validateState(state.json), [])
    }

    func testProjectionKeepsUnlinkedPartialReasonOnFrontier() throws {
        let f = try fixture("positive")
        var data = f.data
        writeWord(UInt32(bitPattern: Int32(0x1080 - 0x11b4)), at: 0x1b4, in: &data)
        let parser = makeParser(data: data, resumes: 2)
        let metadata = parser.parseAsyncFunctions()
        let report = SwiftAsyncContinuationProver.analyze(parser: parser, metadata: metadata)
        let output = SwiftMetadataFactProjection.projectAsyncContinuations(report,
            parser: parser, metadata: metadata, image: "Fixture", toolchain: "test")
        XCTAssertTrue(output.refused.isEmpty)
        XCTAssertEqual(output.facts.count, 1)
        XCTAssertEqual(output.frontier.count, 1)
        let gap = try XCTUnwrap(output.frontier.first)
        XCTAssertEqual(gap.subject.ref, "0x1080")
        XCTAssertEqual(gap.gap, "unlinkedAsyncContinuation")
        XCTAssertEqual(gap.detail, "noContinuationTransfer")
    }

    func testProjectionRefusesTamperedCertificateAndLeavesPartialUnlinked() throws {
        let f = try fixture("positive")
        var report = SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata)
        XCTAssertEqual(report.edges.count, 1)
        guard !report.edges.isEmpty else { return }
        report.edges[0].certificate.steps[0].word = 0xd503201f
        report.edges[0].certificate = report.edges[0].certificate.withDigest()
        let output = SwiftMetadataFactProjection.projectAsyncContinuations(report,
            parser: f.parser, metadata: f.metadata, image: "Fixture", toolchain: "test")
        XCTAssertTrue(output.facts.isEmpty)
        XCTAssertEqual(output.refused, ["async continuation certificate refused"])
        XCTAssertEqual(output.frontier.map(\.subject.ref), ["0x1060"])
        XCTAssertEqual(output.frontier.map(\.gap), ["unlinkedAsyncContinuation"])
    }

    private func invocationFixture(size: UInt32 = 32, loaded: Bool = false,
                                   betweenArgumentAndCall: [UInt32] = [],
                                   prefix: [UInt32] = [], afterAllocation: [UInt32] = []) throws -> Fixture {
        var f = try fixture("positive")
        for offset in stride(from: 0, to: 0x100, by: 4) {
            writeWord(0xd503201f, at: offset, in: &f.data)
        }
        var caller: [UInt32] = [0xaa1603f3] + prefix // MOV X19,X22 saves incoming context.
        if loaded {
            caller.append(addressInstruction(register: 8, from: 0x1000 + Int64(caller.count * 4), to: 0x11c0))
            caller.append(0xb9400500) // LDR W0,[X8,#4], numeric record size, no Tu symbol.
        } else {
            caller.append(0x52800000 | (size << 5)) // MOVZ W0,#size
        }
        caller += betweenArgumentAndCall
        caller.append(branch(from: 0x1000 + Int64(caller.count * 4), to: 0x1100, call: true))
        caller += [0xaa0003f7] + afterAllocation + [0xf90002f3] // Save allocation in X23, then restore parent field.
        caller.append(addressInstruction(register: 9, from: 0x1000 + Int64(caller.count * 4), to: 0x1060))
        caller += [0xf90006e9, 0xaa1703f6] // STR X9,[X23,#8]; MOV X22,X23
        caller.append(branch(from: 0x1000 + Int64(caller.count * 4), to: 0x1040, call: false))
        XCTAssertLessThanOrEqual(caller.count, 16)
        let callee: [UInt32] = [
            0xaa1603f3, 0xf9000a7f, // MOV X19,X22; STR XZR,[X19,#16]
            branch(from: 0x1048, to: 0x1100, call: true),
            addressInstruction(register: 9, from: 0x104c, to: 0x1070),
            0xa9002413, 0xf9000e60, // STP X19,X9,[X0]; STR X0,[X19,#24]
            0xaa0003f6, branch(from: 0x105c, to: 0x1080, call: false)
        ]
        for (index, word) in caller.enumerated() { writeWord(word, at: index * 4, in: &f.data) }
        for (index, word) in callee.enumerated() { writeWord(word, at: 0x40 + index * 4, in: &f.data) }
        for address in [0x1060, 0x1070, 0x1080] { writeWord(0xd65f03c0, at: address - 0x1000, in: &f.data) }
        for (index, address) in [0x1000, 0x1040, 0x1080].enumerated() {
            writeWord(UInt32(bitPattern: Int32(address - (0x11a0 + index * 4))), at: 0x1a0 + index * 4, in: &f.data)
        }
        for (index, address) in [0x1060, 0x1070].enumerated() {
            writeWord(UInt32(bitPattern: Int32(address - (0x11b0 + index * 4))), at: 0x1b0 + index * 4, in: &f.data)
        }
        writeWord(UInt32(bitPattern: Int32(0x1040 - 0x11c0)), at: 0x1c0, in: &f.data)
        writeWord(size, at: 0x1c4, in: &f.data)
        f.parser = makeParser(data: f.data, entries: 3, resumes: 2)
        f.metadata = f.parser.parseAsyncFunctions()
        return f
    }

    private func invocationCaller(_ f: Fixture) throws -> SwiftAsyncContinuationCertificate {
        try XCTUnwrap(SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata)
            .edges.first(where: { $0.source == 0x1000 })?.certificate)
    }

    func testInvocationStrippedNumericLoadAndMOVZProveCallerBound() throws {
        for loaded in [false, true] {
            let f = try invocationFixture(loaded: loaded)
            let caller = try invocationCaller(f)
            XCTAssertEqual(caller.outgoingAllocation?.size, 32)
            XCTAssertEqual(caller.outgoingAllocation?.sizeInstruction, loaded ? 0x1008 : 0x1004)
            XCTAssertEqual(caller.outgoingAllocation?.loadAddress, loaded ? 0x11c4 : nil)
            let result = SwiftAsyncContinuationProver.analyzeInvocation(parser: f.parser, metadata: f.metadata, caller: caller)
            let certificate = try XCTUnwrap(result.certificate)
            XCTAssertNil(result.abstention)
            XCTAssertNil(certificate.continuation.incomingContext)
            XCTAssertEqual(certificate.continuation.incomingCallerDigest, caller.digest)
            XCTAssertEqual(certificate.continuation.source, 0x1040)
            XCTAssertEqual(certificate.continuation.resume, 0x1070)
            XCTAssertTrue(SwiftAsyncContinuationCertificateVerifier.verifyInvocation(certificate, parser: f.parser, metadata: f.metadata))
        }
    }

    func testInvocationSizeStaysCallerScopedWithoutGlobalPromotion() throws {
        for size in [UInt32(16), 32, 48] {
            let f = try invocationFixture(size: size, loaded: true)
            let caller = try invocationCaller(f)
            let contextual = SwiftAsyncContinuationProver.analyzeInvocation(parser: f.parser, metadata: f.metadata, caller: caller)
            XCTAssertEqual(contextual.certificate != nil, size >= 32)
            let global = SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata)
            XCTAssertFalse(global.edges.contains { $0.source == 0x1040 })
            XCTAssertTrue(global.abstentions.contains { $0.source == 0x1040 })
        }
        for size in [UInt32(0), 8, 24, 1_048_592] {
            let f = try invocationFixture(size: size, loaded: true)
            let caller = try invocationCaller(f)
            XCTAssertNil(caller.outgoingAllocation)
            XCTAssertNil(SwiftAsyncContinuationProver.analyzeInvocation(parser: f.parser, metadata: f.metadata, caller: caller).certificate)
        }
    }

    func testInvocationNonadjacentSizeAndClobber() throws {
        for separator in [UInt32(0xd503201f), 0xd2800000] { // NOP; MOVZ X0,#0 (not a W0 size argument)
            let f = try invocationFixture(betweenArgumentAndCall: [separator])
            let caller = try invocationCaller(f)
            XCTAssertEqual(caller.outgoingAllocation?.size, separator == 0xd503201f ? 32 : nil)
            XCTAssertEqual(SwiftAsyncContinuationProver.analyzeInvocation(parser: f.parser, metadata: f.metadata, caller: caller).certificate != nil,
                           separator == 0xd503201f)
        }
    }

    func testInvocationAllocatorStubClobberCannotClaimCallerSize() throws {
        var f = try invocationFixture()
        writeWord(0x52800200, at: 0x100, in: &f.data) // MOVZ W0,#16 replaces the caller's 32.
        writeWord(0x580003f0, at: 0x104, in: &f.data) // LDR X16,0x1180 from PC 0x1104.
        writeWord(0xd61f0200, at: 0x108, in: &f.data) // BR X16
        f.parser = makeParser(data: f.data, entries: 3, resumes: 2)
        f.metadata = f.parser.parseAsyncFunctions()
        let caller = try invocationCaller(f)
        XCTAssertTrue(SwiftAsyncContinuationCertificateVerifier.verify(caller, parser: f.parser, metadata: f.metadata))
        XCTAssertNil(caller.outgoingAllocation)
        XCTAssertNil(SwiftAsyncContinuationProver.analyzeInvocation(parser: f.parser, metadata: f.metadata, caller: caller).certificate)
        var forged = caller
        forged.outgoingAllocation = .init(size: 32, sizeInstruction: 0x1004, loadAddress: nil)
        XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verify(forged.withDigest(), parser: f.parser, metadata: f.metadata))
    }

    func testInvocationUnknownCallsUnsafeWritesAndRelocationsRefuse() throws {
        for prefix in [[branch(from: 0x1004, to: 0x1110, call: true)], [UInt32(0xf900015f)]] { // unknown call; STR XZR,[X10]
            let f = try invocationFixture(loaded: true, prefix: prefix)
            let report = SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata)
            XCTAssertFalse(report.edges.contains { $0.source == 0x1000 && $0.certificate.outgoingAllocation != nil })
        }
        for lateInstruction in [branch(from: 0x1010, to: 0x1110, call: true), UInt32(0xf900015f)] {
            // X23 preserves the allocation across the late call/write; fresh
            // header stores recover an ordinary edge, never the erased extent.
            let f = try invocationFixture(afterAllocation: [lateInstruction])
            let caller = try invocationCaller(f)
            XCTAssertNil(caller.outgoingAllocation)
            XCTAssertTrue(SwiftAsyncContinuationCertificateVerifier.verify(caller, parser: f.parser, metadata: f.metadata))
            XCTAssertNil(SwiftAsyncContinuationProver.analyzeInvocation(parser: f.parser, metadata: f.metadata, caller: caller).certificate)
        }
        let f = try invocationFixture(loaded: true)
        for address in [UInt64(0x11c0), 0x11c4] {
            for parser in [makeParser(data: f.data, entries: 3, resumes: 2, additionalBinds: [address: "_size_impostor"]),
                           makeParser(data: f.data, entries: 3, resumes: 2, rebases: [address: 32])] {
                let report = SwiftAsyncContinuationProver.analyze(parser: parser, metadata: parser.parseAsyncFunctions())
                XCTAssertFalse(report.edges.contains { $0.source == 0x1000 && $0.certificate.outgoingAllocation != nil })
            }
        }
    }

    func testInvocationWrongAllocationAndTargetCannotBorrowBound() throws {
        let f = try invocationFixture()
        let caller = try invocationCaller(f)
        var wrongAllocation = caller
        wrongAllocation.allocation += 4
        var wrongTarget = caller
        wrongTarget.callee = 0x1080
        for forged in [wrongAllocation.withDigest(), wrongTarget.withDigest()] {
            XCTAssertNil(SwiftAsyncContinuationProver.analyzeInvocation(parser: f.parser, metadata: f.metadata, caller: forged).certificate)
        }
        var data = f.data
        writeWord(0xaa1303f6, at: 0x1c, in: &data) // Transfer the incoming object instead of the allocated X23.
        let parser = makeParser(data: data, entries: 3, resumes: 2)
        XCTAssertFalse(SwiftAsyncContinuationProver.analyze(parser: parser, metadata: parser.parseAsyncFunctions())
            .edges.contains { $0.source == 0x1000 })
    }

    func testInvocationLoadedBytesAndRecomputedCertificateForgeriesRefuse() throws {
        let f = try invocationFixture(loaded: true)
        let caller = try invocationCaller(f)
        let certificate = try XCTUnwrap(SwiftAsyncContinuationProver.analyzeInvocation(parser: f.parser, metadata: f.metadata, caller: caller).certificate)
        var data = f.data
        writeWord(16, at: 0x1c4, in: &data)
        let changed = makeParser(data: data, entries: 3, resumes: 2)
        XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verifyInvocation(certificate, parser: changed, metadata: changed.parseAsyncFunctions()))
        var size = certificate
        size.caller.outgoingAllocation?.size = 48
        size.caller = size.caller.withDigest()
        size.continuation.incomingCallerDigest = size.caller.digest
        size.continuation = size.continuation.withDigest()
        var trace = certificate
        trace.continuation.steps[1].word = 0xd503201f
        trace.continuation = trace.continuation.withDigest()
        var callerBinding = certificate
        callerBinding.continuation.incomingCallerDigest = String(repeating: "0", count: 64)
        callerBinding.continuation = callerBinding.continuation.withDigest()
        for forged in [size.withDigest(), trace.withDigest(), callerBinding.withDigest()] {
            XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verifyInvocation(forged, parser: f.parser, metadata: f.metadata))
        }
    }

    func testInvocationExtractionProjectionOneHopAndPartialRefuse() throws {
        let f = try invocationFixture()
        let caller = try invocationCaller(f)
        let certificate = try XCTUnwrap(SwiftAsyncContinuationProver.analyzeInvocation(parser: f.parser, metadata: f.metadata, caller: caller).certificate)
        XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verify(certificate.continuation, parser: f.parser, metadata: f.metadata))
        XCTAssertNil(SwiftAsyncContinuationProver.analyzeInvocation(parser: f.parser, metadata: f.metadata, caller: certificate.continuation).certificate)
        var report = SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata)
        report.edges.append(.init(source: 0x1040, resume: 0x1070, kind: .calleeReturn, certificate: certificate.continuation))
        let projection = SwiftMetadataFactProjection.projectAsyncContinuations(report,
            parser: f.parser, metadata: f.metadata, image: "Fixture", toolchain: "test")
        XCTAssertTrue(projection.refused.contains("async continuation certificate refused"))
        XCTAssertFalse(projection.facts.contains { $0.subject.ref == "0x1070" })
        XCTAssertTrue(projection.frontier.contains { $0.subject.ref == "0x1070" })
        var partialData = f.data
        writeWord(UInt32(bitPattern: Int32(0x1040 - 0x11b4)), at: 0x1b4, in: &partialData)
        let partialParser = makeParser(data: partialData, entries: 3, resumes: 2)
        XCTAssertNil(SwiftAsyncContinuationProver.analyzeInvocation(parser: partialParser,
            metadata: partialParser.parseAsyncFunctions(), caller: caller).certificate)
    }

    func testInvocationGeneralSizeExpressionsPreserveWidthAndLastDefinition() throws {
        let expressions: [[UInt32]] = [
            [0xd2800200, 0x91004000], // MOVZ X0,#16; ADD X0,X0,#16
            [0x52800201, 0x2a0103e0, 0x11004000], // W1=16; MOV W0,W1; ADD W0,#16
            [0x129fffe0, 0x72a00000, 0x72800400], // MOVN W0,#ffff; MOVK upper=0; MOVK lower=32
            [0x52800201, 0x0b010420], // W1=16; ADD W0,W1,W1,LSL #1 =>48
            [0xd2800601, 0xd2800202, 0xcb020020], // X1=48; X2=16; SUB X0,X1,X2
            [0x12800000, 0x52800400], // W0=all ones; W MOVZ clears the entire prior value
        ]
        for (index, words) in expressions.enumerated() {
            let f = try invocationFixture(betweenArgumentAndCall: words)
            let caller = try invocationCaller(f)
            XCTAssertEqual(caller.outgoingAllocation?.size, index == 3 ? 48 : 32)
            XCTAssertEqual(caller.outgoingAllocation?.sizeInstruction, 0x1004 + UInt64(words.count * 4))
            XCTAssertNotNil(SwiftAsyncContinuationProver.analyzeInvocation(parser: f.parser, metadata: f.metadata, caller: caller).certificate)
        }
    }

    func testInvocationGeneralNumericLoadsAndRegisterMoves() throws {
        let variants: [[UInt32]] = [
            [addressInstruction(register: 8, from: 0x1008, to: 0x11c0), 0xb9400501, 0x2a0103e0], // W load through W1
            [addressInstruction(register: 8, from: 0x1008, to: 0x11c0), 0xf9400500], // LDR X0,[X8,#8]
            [0x58000e00], // LDR X0,0x11c8 from 0x1008 (0x1c0 /4 <<5)
        ]
        for words in variants {
            var f = try invocationFixture(betweenArgumentAndCall: words)
            writeWord(32, at: 0x1c8, in: &f.data)
            writeWord(0, at: 0x1cc, in: &f.data)
            f.parser = makeParser(data: f.data, entries: 3, resumes: 2)
            f.metadata = f.parser.parseAsyncFunctions()
            let caller = try invocationCaller(f)
            XCTAssertEqual(caller.outgoingAllocation?.size, 32)
            XCTAssertNotNil(SwiftAsyncContinuationProver.analyzeInvocation(parser: f.parser, metadata: f.metadata, caller: caller).certificate)
        }
    }

    func testInvocationExpressionOverflowUnknownOperandsAndCallsRefuse() throws {
        let expressions: [[UInt32]] = [
            [0x12800000, 0x11008400], // UINT32_MAX +33 would wrap to32; reject overflow.
            [0x92800000, 0x91008400], // UINT64_MAX +33 would wrap to32.
            [0xd2800000, 0xd1000400], // zero minus1 underflows.
            [0x8b0a0000], // ADD X0,X0,X10, unknown X10.
            [0x92400000], // AND X0,X0,#1: unsupported numeric destination kills old32.
            [branch(from: 0x1008, to: 0x1110, call: true)], // unknown call resets scalar arguments.
        ]
        for words in expressions {
            let f = try invocationFixture(betweenArgumentAndCall: words)
            let report = SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata)
            XCTAssertFalse(report.edges.contains { $0.source == 0x1000 && $0.certificate.outgoingAllocation != nil })
        }
    }

    private func invocationChainFixture(recursive: Bool = false) throws -> Fixture {
        var f = try invocationFixture()
        writeWord(addressInstruction(register: 9, from: 0x1014, to: 0x10c0), at: 0x14, in: &f.data)
        for (source, resume, sized, target) in [(Int64(0x1040), Int64(0x10d0), true, Int64(0x1080)),
                                               (Int64(0x1080), Int64(0x10e0), recursive, Int64(0x1080))] {
            var words: [UInt32] = [0xaa1603f3, 0xf9000a7f]
            if sized { words.append(0x52800400) } // outgoing allocation32 permits another contextual frame.
            words.append(branch(from: source + Int64(words.count * 4), to: 0x1100, call: true))
            words.append(addressInstruction(register: 9, from: source + Int64(words.count * 4), to: resume))
            words += [0xa9002413, 0xf9000e60, 0xaa0003f6]
            words.append(branch(from: source + Int64(words.count * 4), to: target, call: false))
            for (index, word) in words.enumerated() { writeWord(word, at: Int(source - 0x1000) + index * 4, in: &f.data) }
        }
        for (index, address) in [0x10c0, 0x10d0, 0x10e0].enumerated() {
            writeWord(0xd65f03c0, at: address - 0x1000, in: &f.data)
            writeWord(UInt32(bitPattern: Int32(address - (0x11b0 + index * 4))), at: 0x1b0 + index * 4, in: &f.data)
        }
        f.parser = makeParser(data: f.data, entries: 3, resumes: 3)
        f.metadata = f.parser.parseAsyncFunctions()
        return f
    }

    func testInvocationDiscoveryAutomaticallyStitchesThreeContextualFrames() throws {
        let f = try invocationChainFixture()
        let discovery = SwiftAsyncContinuationProver.discoverInvocations(parser: f.parser, metadata: f.metadata)
        let chain = try XCTUnwrap(discovery.chains.first { $0.frames.first?.source == 0x1000 })
        XCTAssertEqual(chain.frames.map(\.source), [0x1000, 0x1040, 0x1080])
        XCTAssertNil(chain.frames[0].incomingCallerDigest)
        XCTAssertEqual(chain.frames[1].incomingCallerDigest, chain.frames[0].digest)
        XCTAssertEqual(chain.frames[2].incomingCallerDigest, chain.frames[1].digest)
        XCTAssertTrue(SwiftAsyncContinuationCertificateVerifier.verifyInvocationChain(chain, parser: f.parser, metadata: f.metadata))
        XCTAssertFalse(SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata).edges.contains { $0.source == 0x1040 || $0.source == 0x1080 })
    }

    func testInvocationDiscoveryKeepsTwoCallerContextsSeparate() throws {
        var f = try invocationFixture()
        let callerBytes = Array(f.data[0..<0x24])
        for (index, byte) in callerBytes.enumerated() { f.data[0x80 + index] = byte }
        writeWord(0x52800600, at: 0x84, in: &f.data) // independent caller supplies48
        writeWord(branch(from: 0x1088, to: 0x1100, call: true), at: 0x88, in: &f.data)
        writeWord(addressInstruction(register: 9, from: 0x1094, to: 0x1070), at: 0x94, in: &f.data)
        writeWord(branch(from: 0x10a0, to: 0x1040, call: false), at: 0xa0, in: &f.data)
        f.parser = makeParser(data: f.data, entries: 3, resumes: 2)
        f.metadata = f.parser.parseAsyncFunctions()
        let discovery = SwiftAsyncContinuationProver.discoverInvocations(parser: f.parser, metadata: f.metadata)
        let first = try XCTUnwrap(discovery.chains.first { $0.frames.first?.source == 0x1000 })
        let second = try XCTUnwrap(discovery.chains.first { $0.frames.first?.source == 0x1080 })
        XCTAssertEqual(first.frames.count, 2)
        XCTAssertEqual(second.frames.count, 2)
        XCTAssertEqual(first.frames[0].outgoingAllocation?.size, 32)
        XCTAssertEqual(second.frames[0].outgoingAllocation?.size, 48)
        XCTAssertEqual(first.frames[1].source, second.frames[1].source)
        XCTAssertNotEqual(first.frames[1].incomingCallerDigest, second.frames[1].incomingCallerDigest)
        XCTAssertNotEqual(first.digest, second.digest)
    }

    func testInvocationChainForgeryAndContextExtractionRefuse() throws {
        let f = try invocationChainFixture()
        let chain = try XCTUnwrap(SwiftAsyncContinuationProver.discoverInvocations(parser: f.parser, metadata: f.metadata)
            .chains.first { $0.frames.count == 3 })
        var reordered = chain
        reordered.frames.swapAt(1, 2)
        var rebound = chain
        rebound.frames[2].incomingCallerDigest = rebound.frames[0].digest
        rebound.frames[2] = rebound.frames[2].withDigest()
        for forged in [reordered.withDigest(), rebound.withDigest()] {
            XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verifyInvocationChain(forged, parser: f.parser, metadata: f.metadata))
        }
        for frame in chain.frames.dropFirst() {
            XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verify(frame, parser: f.parser, metadata: f.metadata))
        }
    }

    func testInvocationDiscoveryCapsDeadlineAndRecursionKeepFrontier() throws {
        let f = try invocationChainFixture(recursive: true)
        let empty = SwiftAsyncContinuationProver.discoverInvocations(parser: f.parser, metadata: f.metadata, maxSources: 0)
        XCTAssertEqual(empty.examinedSources, 0)
        XCTAssertTrue(empty.chains.isEmpty)
        XCTAssertTrue(empty.frontier.contains { $0.reason == "callerDiscoveryLimit" })
        let expired = SwiftAsyncContinuationProver.discoverInvocations(parser: f.parser, metadata: f.metadata, deadline: .distantPast)
        XCTAssertEqual(expired.examinedSources, 0)
        XCTAssertTrue(expired.frontier.contains { $0.reason == "invocationTimeLimit" })
        let shallow = SwiftAsyncContinuationProver.discoverInvocations(parser: f.parser, metadata: f.metadata, maxSources: 1, maxDepth: 2)
        XCTAssertEqual(shallow.examinedSources, 1)
        XCTAssertEqual(shallow.chains.first?.frames.count, 2)
        XCTAssertTrue(shallow.frontier.contains { $0.reason == "invocationDepthLimit" && $0.callerDigest != nil })
        let recursive = SwiftAsyncContinuationProver.discoverInvocations(parser: f.parser, metadata: f.metadata)
        XCTAssertTrue(recursive.frontier.contains { $0.reason == "recursiveInvocationContext" && $0.callerDigest != nil })
        XCTAssertTrue(recursive.chains.contains { $0.frames.first?.source == 0x1000 && $0.frames.count == 3 })
    }

    private func returnStateFixture(parentSize: UInt32? = 32, payloadStore: Bool = true,
                                    restoreParent: Bool = true, deallocate: Bool = false,
                                    nested: Bool = false, mutations: [Int: UInt32] = [:]) -> (SwiftMetadataParser, SwiftAsyncMetadata) {
        var data = Data(repeating: 0, count: 0x400)
        for offset in stride(from: 0, to: 0x300, by: 4) { writeWord(0xd503201f, at: offset, in: &data) }
        func put(_ address: Int, _ words: [UInt32]) {
            for (index, word) in words.enumerated() { writeWord(word, at: address - 0x1000 + index * 4, in: &data) }
        }
        func suspension(_ source: Int64, resume: Int64, target: Int64, prefix: [UInt32] = [], size: UInt32 = 48) -> [UInt32] {
            var words = prefix + [0xaa1603f3, 0x52800000 | (size << 5)]
            words.append(branch(from: source + Int64(words.count * 4), to: 0x1300, call: true))
            words.append(addressInstruction(register: 9, from: source + Int64(words.count * 4), to: resume))
            words += [0xa9002413, 0xaa0003f6]
            words.append(branch(from: source + Int64(words.count * 4), to: target, call: false))
            return words
        }
        put(0x1000, suspension(0x1000, resume: 0x1100, target: 0x1040))
        put(0x1080, [0xf94006c8, 0xd61f0100])
        if nested {
            put(0x1040, suspension(0x1040, resume: 0x1140, target: 0x1080, size: 32))
            put(0x1140, [0xf94002d6, 0xf94006c8, 0xd61f0100])
            put(0x1100, [0xf94002d6, 0xd65f03c0])
        } else {
            put(0x1040, [0xf94006c8, 0xd61f0100])
            var prefix: [UInt32] = [0xaa1603f7]
            if restoreParent { prefix.append(0xf94002d6) }
            if deallocate {
                prefix.append(0xaa1703e0)
                prefix.append(branch(from: 0x1100 + Int64(prefix.count * 4), to: 0x1310, call: true))
            }
            if payloadStore { prefix.append(0xf9000adf) }
            put(0x1100, suspension(0x1100, resume: 0x1180, target: 0x1080, prefix: prefix, size: 32))
            put(0x1180, [0xf94002d6, 0xd65f03c0])
        }
        put(0x1300, [0x58000410, 0xd61f0200])
        put(0x1310, [0x580003d0, 0xd61f0200])
        for (index, address) in [0x1000, 0x1040, 0x1080].enumerated() {
            writeWord(UInt32(bitPattern: Int32(address - (0x13a0 + index * 4))), at: 0x3a0 + index * 4, in: &data)
        }
        for (index, address) in [0x1100, 0x1140, 0x1180].enumerated() {
            writeWord(UInt32(bitPattern: Int32(address - (0x13b0 + index * 4))), at: 0x3b0 + index * 4, in: &data)
        }
        if let parentSize {
            writeWord(UInt32(bitPattern: Int32(0x1000 - 0x13c0)), at: 0x3c0, in: &data)
            writeWord(parentSize, at: 0x3c4, in: &data)
        }
        for (offset, word) in mutations { writeWord(word, at: offset, in: &data) }
        let parser = SwiftMetadataParser(data: data, sections: [
            .init(name: "__text", address: 0x1000, fileOffset: 0, size: 0x300, isExecutable: true, segmentName: "__TEXT"),
            .init(name: "__stubs", address: 0x1300, fileOffset: 0x300, size: 0x20, isExecutable: true, segmentName: "__TEXT"),
            .init(name: "__got", address: 0x1380, fileOffset: 0x380, size: 0x20, segmentName: "__DATA"),
            .init(name: "__swift_as_entry", address: 0x13a0, fileOffset: 0x3a0, size: 12, segmentName: "__TEXT"),
            .init(name: "__swift_as_ret", address: 0x13b0, fileOffset: 0x3b0, size: 12, segmentName: "__TEXT"),
            .init(name: "__const", address: 0x13c0, fileOffset: 0x3c0, size: 8, segmentName: "__TEXT")
        ], bindNames: [0x1380: "_swift_task_alloc", 0x1388: "_swift_task_dealloc"],
           asyncFunctionPointerSymbols: parentSize == nil ? [:] : [0x13c0: ["_$s4Test3fooyyYaFTu"]])
        return (parser, parser.parseAsyncFunctions())
    }

    private func returnChain(_ parser: SwiftMetadataParser, _ metadata: SwiftAsyncMetadata) throws -> SwiftAsyncInvocationChainCertificate {
        try XCTUnwrap(SwiftAsyncContinuationProver.discoverInvocations(parser: parser, metadata: metadata)
            .chains.first { $0.frames.first?.source == 0x1000 })
    }

    private func returns(_ chain: SwiftAsyncInvocationChainCertificate) -> [SwiftAsyncReturnCertificate] {
        (chain.transitions ?? []).compactMap { if case let .returnToCaller(value) = $0 { return value }; return nil }
    }

    func testReturnStateRestoresParentBoundAndProvesSecondAwait() throws {
        let (parser, metadata) = returnStateFixture()
        let chain = try returnChain(parser, metadata)
        XCTAssertEqual(chain.frames.map(\.source), [0x1000, 0x1100])
        let witnesses = returns(chain)
        XCTAssertEqual(witnesses.map(\.source), [0x1040, 0x1080])
        XCTAssertEqual(witnesses.map(\.resume), [0x1100, 0x1180])
        XCTAssertEqual(chain.frames.last?.incomingCallerDigest, witnesses.first?.digest)
        XCTAssertTrue(SwiftAsyncContinuationCertificateVerifier.verifyInvocationChain(chain, parser: parser, metadata: metadata))
        if let partial = chain.frames.last, partial.source == 0x1100 {
            XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verify(partial, parser: parser, metadata: metadata))
        }
    }

    func testReturnStateCannotBorrowChildExtentOrSkipParentLoad() throws {
        for (parentSize, restore) in [(UInt32?.none, true), (UInt32?(16), true), (UInt32?(32), false)] {
            let (parser, metadata) = returnStateFixture(parentSize: parentSize, restoreParent: restore)
            let chain = try returnChain(parser, metadata)
            XCTAssertEqual(chain.frames.count, 1)
            XCTAssertEqual(returns(chain).count, 1)
        }
        let (parser, metadata) = returnStateFixture(parentSize: nil, payloadStore: false)
        XCTAssertEqual(try returnChain(parser, metadata).frames.map(\.source), [0x1000, 0x1100])
    }

    func testReturnStateNestedReturnsPopExactInvocation() throws {
        let (parser, metadata) = returnStateFixture(nested: true)
        let chain = try returnChain(parser, metadata)
        XCTAssertEqual(chain.frames.map(\.source), [0x1000, 0x1040])
        XCTAssertEqual(returns(chain).map(\.source), [0x1080, 0x1140])
        XCTAssertEqual(returns(chain).map(\.resume), [0x1140, 0x1100])
        XCTAssertTrue(SwiftAsyncContinuationCertificateVerifier.verifyInvocationChain(chain, parser: parser, metadata: metadata))
        var forged = chain
        var events = try XCTUnwrap(forged.transitions)
        guard events.count >= 3 else { return XCTFail("missing nested returns") }
        events.swapAt(1, 2)
        forged.transitions = events
        XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verifyInvocationChain(forged.withDigest(), parser: parser, metadata: metadata))
    }

    func testReturnStateHeaderClobberWrongTargetAndUnknownCallsRefuse() throws {
        let cases: [[Int: UInt32]] = [
            [0x40: 0xf94002c8],
            [0x40: 0xf94002d6, 0x44: 0xf94006c8, 0x48: 0xd61f0100],
            [0x40: 0x390002df, 0x44: 0xf94006c8, 0x48: 0xd61f0100],
            [0x40: 0xf900015f, 0x44: 0xf94006c8, 0x48: 0xd61f0100],
            [0x40: branch(from: 0x1040, to: 0x1320, call: true), 0x44: 0xf94006c8, 0x48: 0xd61f0100],
            [0x40: addressInstruction(register: 8, from: 0x1040, to: 0x1100)],
        ]
        for changes in cases {
            let (parser, metadata) = returnStateFixture(mutations: changes)
            XCTAssertTrue(returns(try returnChain(parser, metadata)).isEmpty)
        }
    }

    func testReturnStateDigestAndTraceForgeriesRefuse() throws {
        let (parser, metadata) = returnStateFixture()
        let chain = try returnChain(parser, metadata)
        let witness = try XCTUnwrap(returns(chain).first)
        for mutation in 0..<4 {
            var returned = witness
            switch mutation {
            case 0: returned.steps[0].word = 0xd503201f
            case 1: returned.callerDigest = String(repeating: "0", count: 64)
            case 2: returned.resume = 0x1180
            default: returned.previousReturnDigest = witness.digest
            }
            var forged = chain
            forged.transitions?[0] = .returnToCaller(returned.withDigest())
            XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verifyInvocationChain(forged.withDigest(), parser: parser, metadata: metadata))
        }
        let (changed, changedMetadata) = returnStateFixture(mutations: [0x40: 0xf94002c8])
        XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verifyInvocationChain(chain, parser: changed, metadata: changedMetadata))
    }

    func testReturnStateExactDeallocationRetiresOnlyReturnedChild() throws {
        let (parser, metadata) = returnStateFixture(deallocate: true)
        let chain = try returnChain(parser, metadata)
        XCTAssertEqual(chain.frames.map(\.source), [0x1000, 0x1100])
        XCTAssertEqual(returns(chain).count, 2)
        XCTAssertTrue(SwiftAsyncContinuationCertificateVerifier.verifyInvocationChain(chain, parser: parser, metadata: metadata))
        let (early, earlyMetadata) = returnStateFixture(restoreParent: false, deallocate: true)
        XCTAssertEqual(try returnChain(early, earlyMetadata).frames.count, 1)
        let (clobbered, clobberedMetadata) = returnStateFixture(deallocate: true,
            mutations: [0x310: 0xd2800000, 0x314: 0x580003b0, 0x318: 0xd61f0200])
        XCTAssertEqual(try returnChain(clobbered, clobberedMetadata).frames.count, 1)
    }

    func testReturnStateProjectionRetainsTransitionsAndLegacyDescent() throws {
        let old = try invocationChainFixture()
        var legacy = try XCTUnwrap(SwiftAsyncContinuationProver.discoverInvocations(parser: old.parser, metadata: old.metadata)
            .chains.first { $0.frames.count == 3 })
        legacy.transitions = nil
        XCTAssertTrue(SwiftAsyncContinuationCertificateVerifier.verifyInvocationChain(legacy.withDigest(), parser: old.parser, metadata: old.metadata))
        let (parser, metadata) = returnStateFixture(nested: true)
        let chain = try returnChain(parser, metadata)
        let report = SwiftAsyncInvocationDiscoveryReport(chains: [chain], frontier: [], examinedSources: 1)
        let output = SwiftMetadataFactProjection.projectAsyncInvocations(report, parser: parser, metadata: metadata,
            image: "Fixture", toolchain: "test")
        XCTAssertTrue(output.refused.isEmpty)
        XCTAssertEqual(output.facts.count, 1)
        let fact = try XCTUnwrap(output.facts.first)
        let text = try XCTUnwrap(fact.value["certificateJSON"]?.stringValue)
        let decoded = try JSONDecoder().decode(SwiftAsyncInvocationChainCertificate.self, from: Data(text.utf8))
        XCTAssertEqual(decoded, chain)
        XCTAssertEqual(returns(decoded).count, 2)
        let certificate = try XCTUnwrap(output.certificates.first)
        XCTAssertNil(NavigatorContractValidator.certificateRefusal(for: fact) { $0 == certificate.hash ? certificate : nil })
        XCTAssertFalse(output.facts.contains { $0.predicate == "asyncContinuationOf" })
        let paired = returnStateFixture(mutations: [0x40: 0xa94022d3]) // LDP X19,X8,[X22], x22 retains child.
        XCTAssertEqual(returns(try returnChain(paired.0, paired.1)).count, 2)
    }

    func testReturnStateAllocatorStubCannotClobberContext() throws {
        for clobber in [UInt32(0xaa1f03f3), 0xaa1f03f6, 0xd10043ff] { // X19, X22, SP
            let (parser, metadata) = returnStateFixture(mutations: [
                0x300: clobber, 0x304: 0x580003f0, 0x308: 0xd61f0200,
            ])
            let report = SwiftAsyncContinuationProver.discoverInvocations(parser: parser, metadata: metadata)
            XCTAssertFalse(report.chains.contains { $0.frames.first?.source == 0x1000 })
            XCTAssertTrue(report.frontier.contains { $0.source == 0x1000 && $0.reason == "allocatorContextClobber" })
        }
        // A stub may replace W0 without changing the parent identity, but the
        // caller's requested extent must not survive that replacement.
        let f = try invocationFixture()
        var bytes = f.data
        writeWord(0x52800200, at: 0x100, in: &bytes)
        writeWord(0x580003f0, at: 0x104, in: &bytes)
        writeWord(0xd61f0200, at: 0x108, in: &bytes)
        let parser = makeParser(data: bytes, entries: 3, resumes: 2)
        let report = SwiftAsyncContinuationProver.analyze(parser: parser, metadata: parser.parseAsyncFunctions())
        let root = try XCTUnwrap(report.edges.first { $0.source == 0x1000 })
        XCTAssertNil(root.certificate.outgoingAllocation)
    }

    private func writeWord(_ word: UInt32, at offset: Int, in data: inout Data) {
        for index in 0..<4 { data[offset + index] = UInt8(truncatingIfNeeded: word >> (index * 8)) }
    }

    private func branch(from source: Int64, to target: Int64, call: Bool) -> UInt32 {
        (call ? 0x94000000 : 0x14000000) | (UInt32(truncatingIfNeeded: (target - source) / 4) & 0x03ffffff)
    }

    private func addressInstruction(register: UInt32, from source: Int64, to target: Int64) -> UInt32 {
        let immediate = UInt32(truncatingIfNeeded: target - source) & 0x1fffff
        return 0x10000000 | ((immediate & 3) << 29) | ((immediate >> 2) << 5) | register
    }

    func testTaskSwitchAbstainsWithoutEstablishedABI() throws {
        try assertRuntimeABIAbstention("_swift_task_switch", call: false)
    }

    func testContinuationAwaitAbstainsWithoutEstablishedABI() throws {
        try assertRuntimeABIAbstention("_swift_continuation_await", call: false)
    }

    func testContinuationInitializationAbstainsWithoutEstablishedABI() throws {
        try assertRuntimeABIAbstention("_swift_continuation_init", call: true)
    }

    private func assertRuntimeABIAbstention(_ name: String, call: Bool) throws {
        let f = try fixture("positive")
        var data = f.data
        let word: UInt32 = (call ? 0x94000000 : 0x14000000) | 0x40
        for index in 0..<4 { data[index] = UInt8(truncatingIfNeeded: word >> (index * 8)) }
        let parser = makeParser(data: data, allocator: name)
        let report = SwiftAsyncContinuationProver.analyze(parser: parser, metadata: parser.parseAsyncFunctions())
        XCTAssertTrue(report.edges.isEmpty)
        XCTAssertTrue(report.abstentions.contains { $0.source == 0x1000 && $0.reason == "abiUnestablished" })
    }
}
