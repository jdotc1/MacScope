import Foundation
import XCTest
@testable import MacScope

/// New, source-only fixture definitions; no retained binary fixture is loaded.
final class SwiftAsyncContinuationAlignmentTests: XCTestCase {
    private let externalName = "_$s4Test3fooyyYaF"

    private struct Fixture {
        var parser: SwiftMetadataParser
        var metadata: SwiftAsyncMetadata
        var source: UInt64
        var resume: UInt64
        var callee: UInt64?
        var boundCallee: String?
        var words: [UInt32]
        var transfer: UInt64 { source + UInt64((words.count - 1) * 4) }
    }

    func testAlignedDirectMetadataPreservesEdgeCertificateAndChain() throws {
        for continuationArray in [false, true] {
            let f = fixture(continuationArray: continuationArray)
            let certificate = try assertPositive(f)
            XCTAssertEqual(certificate.callee, 0x1040)
            XCTAssertNil(certificate.boundCallee)
            XCTAssertEqual(certificate.calleeEvidence, "asyncEntryMetadata")
        }
    }

    func testEveryMisalignedSourceRefusesDirectMetadataAndResealedCertificate() throws {
        let baseline = try assertPositive(fixture())
        for remainder in 1...3 {
            let f = fixture(sourceRemainder: remainder)
            let image = SwiftAsyncContinuationImage(parser: f.parser, metadata: f.metadata)
            XCTAssertFalse(image.executable(f.source))
            XCTAssertNil(image.instruction(f.source))
            assertRefused(f, reason: "unreadableInstruction", at: f.source)
            assertIndependentRefusal(reseal(baseline, for: f), in: f)
        }
    }

    func testEveryMisalignedResumeRefusesDirectMetadataAndResealedCertificate() throws {
        let baseline = try assertPositive(fixture())
        for continuationArray in [false, true] {
            for remainder in 1...3 {
                let f = fixture(resume: 0x1060 + UInt64(remainder), continuationArray: continuationArray)
                assertRefused(f, reason: "unproved or conflicting resume/parent provenance", at: f.transfer)
                assertIndependentRefusal(reseal(baseline, for: f), in: f)
            }
        }
    }

    func testEveryMisalignedConcreteCalleeRefusesWithoutRoundingOrParserFiltering() throws {
        let baseline = try assertPositive(fixture())
        for remainder in 1...3 {
            let f = fixture(callee: 0x1040 + UInt64(remainder))
            XCTAssertTrue(f.metadata.entries.contains { $0.entryAddress == f.callee })
            // ADR + BR carries all low bits; a direct B immediate would round the test target.
            assertRefused(f, reason: "nonAsyncTransfer", at: f.transfer)
            assertIndependentRefusal(reseal(baseline, for: f), in: f)
        }
    }

    func testAlignedBoundExternalCalleeKeepsAbsentConcreteAddress() throws {
        let f = fixture(external: true)
        let certificate = try assertPositive(f)
        XCTAssertNil(certificate.callee)
        XCTAssertEqual(certificate.boundCallee, externalName)
        XCTAssertEqual(certificate.calleeEvidence, "demangledAsyncImport")
        var inventedAddress = certificate
        inventedAddress.callee = 0x1040
        assertIndependentRefusal(inventedAddress.withDigest(), in: f)
    }

    func testAlignedInvalidContextStillRefusesConcreteAndBoundTransfers() throws {
        for external in [false, true] {
            let baseline = try assertPositive(fixture(external: external))
            let f = fixture(external: external, invalidContext: true)
            assertRefused(f, reason: "unprovedAsyncContext", at: f.transfer)
            assertIndependentRefusal(reseal(baseline, for: f), in: f)
        }
    }

    func testImageAlignmentPreservesSectionWidthAndOwnershipChecks() {
        let empty = SwiftAsyncMetadata(entries: [], resumePartialAddresses: [], continuationPartialAddresses: [])
        func image(_ address: UInt64, _ size: UInt64, executable: Bool = true,
                   zeroFill: Bool = false) -> SwiftAsyncContinuationImage {
            let parser = SwiftMetadataParser(data: Data(repeating: 0, count: 16), sections: [
                .init(name: "__text", address: address, fileOffset: 0, size: size,
                      isExecutable: executable, isZeroFill: zeroFill, segmentName: "__TEXT")
            ])
            return .init(parser: parser, metadata: empty)
        }
        let ordinary = image(0x1000, 16)
        XCTAssertTrue(ordinary.executable(0x1000))
        XCTAssertTrue(ordinary.executable(0x100c))
        for address in [UInt64(0x0ffc), 0x1001, 0x1002, 0x1003, 0x100d, 0x100e, 0x100f, 0x1010] {
            XCTAssertFalse(ordinary.executable(address))
        }
        XCTAssertFalse(image(0x1000, 3).executable(0x1000))
        XCTAssertFalse(image(0x1000, 0).executable(0x1000))
        XCTAssertFalse(image(0x1000, 16, executable: false).executable(0x1000))
        XCTAssertFalse(image(0x1000, 16, zeroFill: true).executable(0x1000))
        // Alignment is absolute, not relative to an adversarial section base.
        XCTAssertFalse(image(0x1001, 7).executable(0x1001))
        XCTAssertTrue(image(0x1001, 7).executable(0x1004))
        // Preserve subtraction-based bounds at the top of the address space.
        let high = image(UInt64.max - 15, 12)
        XCTAssertTrue(high.executable(UInt64.max - 7))
        XCTAssertFalse(high.executable(UInt64.max - 6))
        XCTAssertFalse(high.executable(UInt64.max - 3))
        XCTAssertFalse(high.executable(UInt64.max))
    }

    @discardableResult
    private func assertPositive(_ f: Fixture, file: StaticString = #filePath,
                                line: UInt = #line) throws -> SwiftAsyncContinuationCertificate {
        let report = SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata)
        XCTAssertEqual(report.edges.count, 1, "\(report.abstentions)", file: file, line: line)
        let edge = try XCTUnwrap(report.edges.first, file: file, line: line)
        XCTAssertEqual(edge.source, f.source, file: file, line: line)
        XCTAssertEqual(edge.resume, f.resume, file: file, line: line)
        XCTAssertEqual(edge.kind, .calleeReturn, file: file, line: line)
        XCTAssertEqual(edge.certificate.transfer, f.transfer, file: file, line: line)
        XCTAssertTrue(SwiftAsyncContinuationCertificateVerifier.verify(edge.certificate,
            parser: f.parser, metadata: f.metadata), file: file, line: line)
        XCTAssertEqual(report.chains.first { $0.entry == f.source }?.partials,
                       [f.resume], file: file, line: line)
        XCTAssertEqual(report.chains.first { $0.entry == f.source }?.conflicts,
                       [], file: file, line: line)
        XCTAssertTrue(report.unlinkedPartials.isEmpty, file: file, line: line)
        return edge.certificate
    }

    private func assertRefused(_ f: Fixture, reason: String, at instruction: UInt64,
                               file: StaticString = #filePath, line: UInt = #line) {
        let report = SwiftAsyncContinuationProver.analyze(parser: f.parser, metadata: f.metadata)
        XCTAssertTrue(report.edges.isEmpty, file: file, line: line)
        // An exact producer refusal, rather than verificationFailed, exercises producer admission.
        XCTAssertTrue(report.abstentions.contains {
            $0.source == f.source && $0.instruction == instruction && $0.reason == reason
        }, "\(report.abstentions)", file: file, line: line)
        XCTAssertTrue(report.chains.allSatisfy { $0.partials.isEmpty }, file: file, line: line)
        XCTAssertEqual(report.unlinkedPartials, [f.resume], file: file, line: line)
    }

    private func assertIndependentRefusal(_ certificate: SwiftAsyncContinuationCertificate,
                                          in f: Fixture, file: StaticString = #filePath,
                                          line: UInt = #line) {
        // No producer call here: the forged trace, addresses and digest are supplied directly.
        XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verify(certificate,
            parser: f.parser, metadata: f.metadata), file: file, line: line)
        XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verifyPreservingFrame(certificate,
            parser: f.parser, metadata: f.metadata, incomingSize: nil), file: file, line: line)
        let chain = SwiftAsyncInvocationChainCertificate(digest: "", frames: [certificate]).withDigest()
        XCTAssertFalse(SwiftAsyncContinuationCertificateVerifier.verifyInvocationChain(chain,
            parser: f.parser, metadata: f.metadata), file: file, line: line)
    }

    private func reseal(_ baseline: SwiftAsyncContinuationCertificate,
                        for f: Fixture) -> SwiftAsyncContinuationCertificate {
        var forged = baseline
        forged.source = f.source
        forged.allocation = f.source + 4
        forged.parentStore = f.source + 12
        forged.resumeStore = f.source + 20
        forged.transfer = f.transfer
        forged.resume = f.resume
        forged.callee = f.callee
        forged.boundCallee = f.boundCallee
        // Preserve the valid chronology; change every relocated address and actual encoded word.
        for index in forged.steps.indices {
            forged.steps[index].address = f.source + UInt64(index * 4)
            forged.steps[index].word = f.words[index]
        }
        return forged.withDigest()
    }

    private func fixture(sourceRemainder: Int = 0, resume: UInt64 = 0x1060,
                         callee: UInt64 = 0x1040, continuationArray: Bool = false,
                         external: Bool = false, invalidContext: Bool = false) -> Fixture {
        let source = UInt64(0x1000 + sourceRemainder)
        let stub = UInt64(0x1100 + sourceRemainder)
        let allocatorSlot = UInt64(0x1180 + sourceRemainder)
        var words: [UInt32] = [
            0xaa1603f3,                                  // MOV X19,X22: incoming parent.
            branch(from: source + 4, to: stub),          // BL preserving allocator stub.
            0xaa0003f7, 0xf90002f3,                      // MOV X23,X0; STR X19,[X23].
            addressInstruction(register: 9, from: source + 16, to: resume),
            0xf90006e9                                  // STR X9,[X23,#8].
        ]
        if external {
            words += [addressInstruction(register: 10, from: source + 24, to: 0x1188),
                      0xf9400151]                       // LDR X17,[X10]: bound name, no code VA.
        } else {
            words.append(addressInstruction(register: 17, from: source + 24, to: callee))
        }
        words += [invalidContext ? 0xaa1303f6 : 0xaa1703f6, 0xd61f0220] // MOV X22,X19/X23; BR X17.
        var data = Data(repeating: 0, count: 0x194)
        for (index, word) in words.enumerated() { writeWord(word, at: sourceRemainder + index * 4, in: &data) }
        writeWord(0xd65f03c0, at: Int(callee - 0x1000), in: &data)
        writeWord(0xd65f03c0, at: Int(resume - 0x1000), in: &data)
        // Use fully modeled address/load instructions so allocator-context proof reaches alignment admission.
        writeWord(addressInstruction(register: 16, from: stub, to: allocatorSlot),
                  at: 0x100 + sourceRemainder, in: &data)
        writeWord(0xf9400210, at: 0x104 + sourceRemainder, in: &data) // LDR X16,[X16].
        writeWord(0xd61f0200, at: 0x108 + sourceRemainder, in: &data)
        var binds = [allocatorSlot: "_swift_task_alloc"]
        if external { binds[0x1188] = externalName }
        let parser = SwiftMetadataParser(data: data, sections: [
            .init(name: "__text", address: 0x1000, fileOffset: 0, size: 0x100,
                  isExecutable: true, segmentName: "__TEXT"),
            .init(name: "__stubs", address: stub, fileOffset: UInt64(0x100 + sourceRemainder), size: 12,
                  isExecutable: true, segmentName: "__TEXT"),
            .init(name: "__got", address: allocatorSlot, fileOffset: UInt64(0x180 + sourceRemainder), size: 16,
                  segmentName: "__DATA")
        ], bindNames: binds)
        // Deliberately do not call parseAsyncFunctions: parser filtering cannot hide these adversarial inputs.
        let entries: [SwiftAsyncFunctionRecord] = [.init(entryAddress: source, pointerRecords: [])]
            + (external ? [] : [.init(entryAddress: callee, pointerRecords: [])])
        let metadata = SwiftAsyncMetadata(entries: entries,
            resumePartialAddresses: continuationArray ? [] : [resume],
            continuationPartialAddresses: continuationArray ? [resume] : [])
        return .init(parser: parser, metadata: metadata, source: source, resume: resume,
                     callee: external ? nil : callee, boundCallee: external ? externalName : nil, words: words)
    }

    private func writeWord(_ word: UInt32, at offset: Int, in data: inout Data) {
        for index in 0..<4 { data[offset + index] = UInt8(truncatingIfNeeded: word >> (index * 8)) }
    }

    private func branch(from source: UInt64, to target: UInt64) -> UInt32 {
        0x94000000 | (UInt32(truncatingIfNeeded: (Int64(target) - Int64(source)) / 4) & 0x03ffffff)
    }

    private func addressInstruction(register: UInt32, from source: UInt64, to target: UInt64) -> UInt32 {
        let immediate = UInt32(truncatingIfNeeded: Int64(target) - Int64(source)) & 0x1fffff
        return 0x10000000 | ((immediate & 3) << 29) | ((immediate >> 2) << 5) | register
    }
}
