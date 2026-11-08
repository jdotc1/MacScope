import XCTest
@testable import MacScope

/// Crafted-input regression tests for the binary-parser security hardening (external audit
/// F2/F3 + the consumer-inventory finding F4). A hostile thin Mach-O whose segment table carries
/// adversarial 64-bit range fields must produce a TYPED error or nil — never a process trap, an
/// out-of-bounds read, or a section-count resource-amplification DoS.
///
/// Note: finding F1 (parser-level rejection of an out-of-slice segment file range) was DEFERRED —
/// the dyld shared-cache loader legitimately parses images with cache-relative `fileOffset`s, so a
/// `fileOffset <= data.count` check would reject valid input. The two concrete trap consumers are
/// instead hardened independently (F2 in the writer, F4 in `MachOFile.virtualAddress`), which is
/// why these fixtures parse successfully and then exercise the hardened consumers.
final class MachOParserSecurityTests: XCTestCase {

    /// A minimal thin arm64 Mach-O with ONE `LC_SEGMENT_64` (no sections, no other commands)
    /// whose vm/file range fields are caller-controlled — the lever for the hostile fixtures.
    private func craftedThinMachO(
        vmAddress: UInt64, vmSize: UInt64, fileOffset: UInt64, fileSize: UInt64,
        trailingBytes: Int = 64
    ) -> Data {
        let segmentCommandSize = 72
        var bytes = Data()
        bytes.appendUInt32LE(0xfeedfacf)                                       // magic (MH_MAGIC_64)
        bytes.appendUInt32LE(UInt32(bitPattern: MachOConstants.cpuTypeARM64))  // cputype
        bytes.appendUInt32LE(0)                                                // cpusubtype
        bytes.appendUInt32LE(MachOConstants.fileTypeExecute)                   // filetype
        bytes.appendUInt32LE(1)                                                // ncmds
        bytes.appendUInt32LE(UInt32(segmentCommandSize))                       // sizeofcmds
        bytes.appendUInt32LE(0)                                                // flags
        bytes.appendUInt32LE(0)                                                // reserved
        bytes.appendUInt32LE(MachOConstants.loadCommandSegment64)
        bytes.appendUInt32LE(UInt32(segmentCommandSize))
        bytes.appendFixedCString("__HOSTILE", length: 16)
        bytes.appendUInt64LE(vmAddress)
        bytes.appendUInt64LE(vmSize)
        bytes.appendUInt64LE(fileOffset)
        bytes.appendUInt64LE(fileSize)
        bytes.appendUInt32LE(5)                                                // maxprot
        bytes.appendUInt32LE(5)                                                // initprot
        bytes.appendUInt32LE(0)                                                // nsects
        bytes.appendUInt32LE(0)                                                // flags
        if trailingBytes > 0 { bytes.append(Data(count: trailingBytes)) }
        return bytes
    }

    // MARK: - LC_FUNCTION_STARTS has an independent large-image budget

    private let functionStartOptions = MachOParseOptions(recoverStringLiterals: false,
        recoverObjectiveCMetadata: false, recoverSwiftMetadata: false, parseCodeSignature: false)

    private func craftedFunctionStarts(entryCount: Int) -> Data {
        let payloadOffset = 32 + 72 + 16
        let fileSize = UInt64(payloadOffset + entryCount + 1)
        var bytes = craftedThinMachO(vmAddress: 0x1_0000_0000, vmSize: fileSize,
            fileOffset: 0, fileSize: fileSize, trailingBytes: 0)
        var commandHeader = Data()
        commandHeader.appendUInt32LE(2)
        commandHeader.appendUInt32LE(72 + 16)
        bytes.replaceSubrange(16..<24, with: commandHeader)
        var segmentName = Data()
        segmentName.appendFixedCString("__TEXT", length: 16)
        bytes.replaceSubrange(40..<56, with: segmentName)
        bytes.appendUInt32LE(MachOConstants.loadCommandFunctionStarts)
        bytes.appendUInt32LE(16)
        bytes.appendUInt32LE(UInt32(payloadOffset))
        bytes.appendUInt32LE(UInt32(entryCount + 1))
        // Bulk construction avoids a per-entry Swift encoding loop, including at the cap.
        bytes.append(Data(repeating: 1, count: entryCount))
        bytes.append(0)
        return bytes
    }

    func testFunctionStartsParsesSixtyThousandEntries() throws {
        let file = try MachOParser().parse(craftedFunctionStarts(entryCount: 60_000),
            options: functionStartOptions)
        XCTAssertEqual(file.functionStarts.count, 60_000)
        XCTAssertEqual(file.functionStarts.last?.address, 0x1_0000_EA60)
    }

    func testFunctionStartsInventoryAcceptsSixtyThousandEntries() throws {
        let parsed = try MachOParser().parseWithFixupCoverage(
            craftedFunctionStarts(entryCount: 60_000), options: functionStartOptions)
        XCTAssertTrue(parsed.coverage.functionStartsInventoryIsComplete,
            "layout: \(parsed.coverage.refusalReasons); starts: \(parsed.coverage.functionStartsInventoryRefusalReasons)")
        XCTAssertEqual(parsed.coverage.decodedFunctionStartCount, 60_000)
    }

    func testFunctionStartsCrossCheckReportsMissingStartAboveOldLimit() throws {
        let file = try MachOParser().parse(craftedFunctionStarts(entryCount: 60_000),
            options: functionStartOptions)
        XCTAssertEqual(file.functionStarts.count, 60_000)
        let findings = MachOUnwindFunctionStarts.crossCheck(functionStarts: file.functionStarts,
            unwindOffsets: [60_000, 60_001], imageBase: 0x1_0000_0000,
            functionStartsParseOutcome: file.functionStartsParseOutcome)
        XCTAssertEqual(findings.count, 1)
        let finding = try XCTUnwrap(findings.first)
        XCTAssertEqual(finding.kind, .unwindFunctionStartNotInFunctionStarts)
        XCTAssertEqual(finding.value, 60_001)
        XCTAssertEqual(finding.address, 0x1_0000_EA61)
    }

    func testFunctionStartsStillTruncatesAtRecoveryLimit() throws {
        let limit = MachORecoveryLimits.maximumFunctionStarts
        // One parse, no inventory rescan or expected million-element array.
        let file = try MachOParser().parse(craftedFunctionStarts(entryCount: limit + 1),
            options: functionStartOptions)
        XCTAssertEqual(file.functionStarts.count, limit)
        XCTAssertEqual(file.functionStarts.last?.offsetFromImageBase, UInt64(limit))
        XCTAssertEqual(file.functionStarts.last?.address, 0x1_0000_0000 + UInt64(limit))
        XCTAssertEqual(file.functionStartsParseOutcome, .entryLimitReached)
    }

    // MARK: - Explicit LC_FUNCTION_STARTS completeness

    /// A self-contained image with a UUID and an optional regular unwind page listing offsets
    /// 4 and 8. nil payload omits LC_FUNCTION_STARTS; empty Data declares an empty payload.
    /// New test definitions are source-only and have not been run.
    private func functionStartsImage(
        payload: Data?, imageBase: UInt64 = 0x1_0000_0000,
        includeSegment: Bool = true, includeUnwind: Bool = false
    ) -> Data {
        let segmentSize = includeSegment ? (includeUnwind ? 152 : 72) : 0
        let commandSize = segmentSize + 24 + (payload == nil ? 0 : 16)
        let payloadOffset = 32 + commandSize
        let payloadEnd = payloadOffset + (payload?.count ?? 0)
        let unwindOffset = (payloadEnd + 3) & ~3
        let fileSize = includeUnwind ? unwindOffset + 76 : payloadEnd
        var bytes = Data()
        bytes.appendUInt32LE(0xfeedfacf)
        bytes.appendUInt32LE(UInt32(bitPattern: MachOConstants.cpuTypeARM64))
        bytes.appendUInt32LE(0)
        bytes.appendUInt32LE(MachOConstants.fileTypeExecute)
        bytes.appendUInt32LE(UInt32((includeSegment ? 1 : 0) + 1 + (payload == nil ? 0 : 1)))
        bytes.appendUInt32LE(UInt32(commandSize))
        bytes.appendUInt32LE(0)
        bytes.appendUInt32LE(0)
        if includeSegment {
            bytes.appendUInt32LE(MachOConstants.loadCommandSegment64)
            bytes.appendUInt32LE(UInt32(segmentSize))
            bytes.appendFixedCString("__TEXT", length: 16)
            bytes.appendUInt64LE(imageBase)
            bytes.appendUInt64LE(UInt64(fileSize))
            bytes.appendUInt64LE(0)
            bytes.appendUInt64LE(UInt64(fileSize))
            bytes.appendUInt32LE(5)
            bytes.appendUInt32LE(5)
            bytes.appendUInt32LE(includeUnwind ? 1 : 0)
            bytes.appendUInt32LE(0)
            if includeUnwind {
                bytes.appendFixedCString("__unwind_info", length: 16)
                bytes.appendFixedCString("__TEXT", length: 16)
                bytes.appendUInt64LE(imageBase + UInt64(unwindOffset))
                bytes.appendUInt64LE(76)
                bytes.appendUInt32LE(UInt32(unwindOffset))
                bytes.appendUInt32LE(2)
                for _ in 0..<6 { bytes.appendUInt32LE(0) }
            }
        }
        bytes.appendUInt32LE(MachOConstants.loadCommandUUID)
        bytes.appendUInt32LE(24)
        bytes.append(contentsOf: (1...16).map(UInt8.init))
        if let payload {
            bytes.appendUInt32LE(MachOConstants.loadCommandFunctionStarts)
            bytes.appendUInt32LE(16)
            bytes.appendUInt32LE(UInt32(payloadOffset))
            bytes.appendUInt32LE(UInt32(payload.count))
            bytes.append(payload)
        }
        if includeUnwind {
            bytes.append(Data(count: unwindOffset - bytes.count))
            // Header, regular-page index plus sentinel, page header, and two entries.
            let words: [UInt32] = [1, 0, 0, 0, 0, 28, 2, 4, 52, 0, 12, 0, 0, 2,
                                   0x0002_0008, 4, 0, 8, 0]
            for word in words {
                bytes.appendUInt32LE(word)
            }
        }
        return bytes
    }

    func testFunctionStartsTerminatedBelowCapPreservesAddressesAndInventory() throws {
        let parsed = try MachOParser().parseWithFixupCoverage(
            functionStartsImage(payload: Data([1, 2, 0])), options: functionStartOptions)
        XCTAssertEqual(parsed.file.functionStartsParseOutcome, .terminated)
        XCTAssertEqual(parsed.file.functionStarts.map(\.offsetFromImageBase), [1, 3])
        XCTAssertEqual(parsed.file.functionStarts.map(\.address), [0x1_0000_0001, 0x1_0000_0003])
        XCTAssertTrue(parsed.coverage.functionStartsInventoryIsComplete)
        XCTAssertEqual(parsed.coverage.decodedFunctionStartCount, 2)
    }

    func testFunctionStartsExactlyAtCapTerminatorEnablesComparisonAndInventory() throws {
        let limit = MachORecoveryLimits.maximumFunctionStarts
        let parsed = try MachOParser().parseWithFixupCoverage(
            craftedFunctionStarts(entryCount: limit), options: functionStartOptions)
        XCTAssertEqual(parsed.file.functionStarts.count, limit)
        XCTAssertEqual(parsed.file.functionStarts.last?.offsetFromImageBase, UInt64(limit))
        XCTAssertEqual(parsed.file.functionStartsParseOutcome, .terminated)
        XCTAssertTrue(parsed.coverage.functionStartsInventoryIsComplete)
        let findings = MachOUnwindFunctionStarts.crossCheck(functionStarts: parsed.file.functionStarts,
            unwindOffsets: [UInt32(limit), UInt32(limit + 1)], imageBase: 0x1_0000_0000,
            functionStartsParseOutcome: parsed.file.functionStartsParseOutcome)
        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.value, UInt64(limit + 1))
    }

    func testFunctionStartsCapLookaheadOnlyRecognizesBoundedZeroEncoding() throws {
        let limit = MachORecoveryLimits.maximumFunctionStarts
        let tails: [(Data, FunctionStartsParseOutcome)] = [
            (Data(repeating: 0x80, count: 9) + Data([0]), .terminated),
            (Data(), .unterminatedPayload),
            (Data([1, 0]), .entryLimitReached),
            (Data([0x80]), .entryLimitReached),
            (Data(repeating: 0x80, count: 10) + Data([0]), .entryLimitReached),
            (Data(repeating: 0x80, count: 9) + Data([2]), .entryLimitReached)
        ]
        for (tail, expected) in tails {
            // Only the compact payload is built in bulk; no million-element expected array.
            let payload = Data(repeating: 1, count: limit) + tail
            let file = try MachOParser().parse(functionStartsImage(payload: payload),
                options: functionStartOptions)
            XCTAssertEqual(file.functionStarts.count, limit)
            XCTAssertEqual(file.functionStarts.last?.offsetFromImageBase, UInt64(limit))
            XCTAssertEqual(file.functionStartsParseOutcome, expected)
        }
    }

    func testFunctionStartsPayloadExhaustionRetainsPrefixWithoutNegativeEvidence() throws {
        let parsed = try MachOParser().parseWithFixupCoverage(
            functionStartsImage(payload: Data([4]), includeUnwind: true), options: functionStartOptions)
        XCTAssertEqual(parsed.file.functionStarts.map(\.offsetFromImageBase), [4])
        XCTAssertEqual(parsed.file.functionStartsParseOutcome, .unterminatedPayload)
        XCTAssertTrue(parsed.file.functionStartsDiagnostics.isEmpty)
        XCTAssertFalse(parsed.coverage.functionStartsInventoryIsComplete)
        XCTAssertTrue(parsed.coverage.functionStartsInventoryRefusalReasons.contains(.incompleteFunctionStarts))
    }

    func testFunctionStartsAbsentEmptyAndTerminatedEmptyRemainDistinct() throws {
        let cases: [(Data?, FunctionStartsParseOutcome, Int)] = [
            (nil, .absentCommand, 0), (Data(), .emptyPayload, 0), (Data([0]), .terminated, 2)
        ]
        for (payload, expected, disagreementCount) in cases {
            let parsed = try MachOParser().parseWithFixupCoverage(
                functionStartsImage(payload: payload, includeUnwind: true), options: functionStartOptions)
            XCTAssertTrue(parsed.file.functionStarts.isEmpty)
            XCTAssertEqual(parsed.file.functionStartsParseOutcome, expected)
            XCTAssertEqual(parsed.file.functionStartsDiagnostics.count, disagreementCount)
            XCTAssertEqual(parsed.coverage.functionStartsInventoryIsComplete, expected == .terminated)
            if expected == .absentCommand {
                XCTAssertTrue(parsed.coverage.functionStartsInventoryRefusalReasons.contains(.missingDeclaration))
            } else if expected == .emptyPayload {
                XCTAssertTrue(parsed.coverage.functionStartsInventoryRefusalReasons.contains(.incompleteFunctionStarts))
            }
        }
    }

    func testFunctionStartsWithoutImageBaseDoesNotClaimTermination() throws {
        let file = try MachOParser().parse(
            functionStartsImage(payload: Data([0]), includeSegment: false), options: functionStartOptions)
        XCTAssertTrue(file.functionStarts.isEmpty)
        XCTAssertEqual(file.functionStartsParseOutcome, .unavailableImageBase)
        XCTAssertTrue(file.functionStartsDiagnostics.isEmpty)
    }

    func testFunctionStartsActualFindingsPathRequiresExplicitCompleteEvidence() throws {
        let bytes = functionStartsImage(payload: Data([4, 0]), includeUnwind: true)
        let file = try MachOParser().parse(bytes, options: functionStartOptions)
        XCTAssertEqual(file.functionStartsDiagnostics.count, 1)
        XCTAssertEqual(file.functionStartsDiagnostics.first?.value, 8)
        XCTAssertEqual(file.functionStartsDiagnostics.first?.address, 0x1_0000_0008)
        let incomplete: [FunctionStartsParseOutcome] = [.unknown, .absentCommand, .emptyPayload,
            .unterminatedPayload, .entryLimitReached, .unavailableImageBase]
        for outcome in incomplete {
            XCTAssertTrue(MachOUnwindFunctionStarts.crossCheck(functionStarts: file.functionStarts,
                unwindOffsets: [4, 8], imageBase: 0x1_0000_0000,
                functionStartsParseOutcome: outcome).isEmpty)
            XCTAssertTrue(MachOUnwindFunctionStarts.findings(in: bytes, sections: file.sections,
                segments: file.segments, functionStarts: file.functionStarts, hasFunctionStartsCommand: true,
                functionStartsParseOutcome: outcome).isEmpty)
        }
        // Defaulted legacy callers and explicit command absence never infer complete evidence.
        XCTAssertTrue(MachOUnwindFunctionStarts.crossCheck(functionStarts: file.functionStarts,
            unwindOffsets: [4, 8], imageBase: 0x1_0000_0000).isEmpty)
        XCTAssertTrue(MachOUnwindFunctionStarts.findings(in: bytes, sections: file.sections,
            segments: file.segments, functionStarts: file.functionStarts,
            hasFunctionStartsCommand: true).isEmpty)
        XCTAssertTrue(MachOUnwindFunctionStarts.findings(in: bytes, sections: file.sections,
            segments: file.segments, functionStarts: file.functionStarts, hasFunctionStartsCommand: false,
            functionStartsParseOutcome: .terminated).isEmpty)
    }

    func testFunctionStartsTerminatorDoesNotBypassIndependentPaddingAudit() throws {
        for payload in [Data([1, 0, 0]), Data([1, 0, 2])] {
            let parsed = try MachOParser().parseWithFixupCoverage(
                functionStartsImage(payload: payload), options: functionStartOptions)
            XCTAssertEqual(parsed.file.functionStartsParseOutcome, .terminated)
            XCTAssertEqual(parsed.file.functionStarts.map(\.offsetFromImageBase), [1])
            XCTAssertEqual(parsed.coverage.functionStartsInventoryIsComplete, payload.last == 0)
        }
    }

    func testFunctionStartsInventoryStillRejectsDecodedCountMismatch() throws {
        // The byte inventory contains one entry, but the parser cannot project it without a
        // segment/image base. The independent audit must still compare the exact decoded count.
        let parsed = try MachOParser().parseWithFixupCoverage(
            functionStartsImage(payload: Data([1, 0]), includeSegment: false), options: functionStartOptions)
        XCTAssertEqual(parsed.file.functionStartsParseOutcome, .unavailableImageBase)
        XCTAssertTrue(parsed.file.functionStarts.isEmpty)
        XCTAssertFalse(parsed.coverage.functionStartsInventoryIsComplete)
        XCTAssertTrue(parsed.coverage.functionStartsInventoryRefusalReasons.contains(.incompleteFunctionStarts))
    }

    func testFunctionStartsLegacyModelInitializersKeepEvidenceUnknown() throws {
        let bytes = functionStartsImage(payload: Data([4, 0]), includeUnwind: true)
        let parsed = try MachOParser().parse(bytes, options: functionStartOptions)
        // Intentionally omit the new label, as existing array-only producers do.
        let legacy = MachOFile(header: parsed.header, loadCommands: parsed.loadCommands,
            segments: parsed.segments, sections: parsed.sections, dylibs: parsed.dylibs,
            rpaths: parsed.rpaths, symbols: parsed.symbols, imports: parsed.imports,
            indirectSymbols: parsed.indirectSymbols, relocations: parsed.relocations,
            exports: parsed.exports, stringLiterals: parsed.stringLiterals,
            objectiveCMetadata: parsed.objectiveCMetadata, swiftMetadataSections: parsed.swiftMetadataSections,
            exceptionMetadata: parsed.exceptionMetadata, functionStarts: parsed.functionStarts,
            dataInCodeEntries: parsed.dataInCodeEntries, uuid: parsed.uuid, buildVersion: parsed.buildVersion,
            sourceVersion: parsed.sourceVersion, legacyMinimumOSVersion: parsed.legacyMinimumOSVersion,
            codeSignature: parsed.codeSignature, dyldChainedFixups: parsed.dyldChainedFixups,
            entryPointOffset: parsed.entryPointOffset, entryPointVirtualAddress: parsed.entryPointVirtualAddress,
            selectedSliceOffset: parsed.selectedSliceOffset, universalBinary: parsed.universalBinary)
        XCTAssertEqual(legacy.functionStarts.map(\.address), parsed.functionStarts.map(\.address))
        XCTAssertEqual(legacy.functionStartsParseOutcome, .unknown)
        XCTAssertTrue(MachOUnwindFunctionStarts.findings(in: bytes, sections: legacy.sections,
            segments: legacy.segments, functionStarts: legacy.functionStarts, hasFunctionStartsCommand: true,
            functionStartsParseOutcome: legacy.functionStartsParseOutcome).isEmpty)
        XCTAssertEqual(parsed.functionStartsDiagnostics.count, 1)

        let loaded = LoadedBinary(name: "legacy", path: "/legacy", isBundle: false,
            cpuType: parsed.header.cpuType, fileTypeName: parsed.fileTypeName,
            architectureDisplayName: parsed.architectureDisplayName,
            metadata: BinaryMetadataSummary(uuid: nil, platformName: nil, minimumOSVersion: nil,
                sdkVersion: nil, buildTools: []),
            bytes: bytes, sliceOffset: 0, sections: [], executableTextSection: nil, entryPointAddress: nil,
            symbols: [], imports: [], indirectSymbols: [], exports: [], stringLiterals: [],
            functionStarts: legacy.functionStarts.map(\.address), objcSelectors: [:])
        XCTAssertEqual(loaded.functionStarts, [0x1_0000_0004])
        XCTAssertEqual(loaded.functionStartsParseOutcome, .unknown)
        XCTAssertFalse(loaded.functionStartsParseOutcome.isComplete)
    }

    func testFunctionStartsLoaderProjectsOutcomeAndExistingAddressArray() throws {
        let cases: [(Data?, FunctionStartsParseOutcome, [UInt64], Int)] = [
            (nil, .absentCommand, [], 0),
            (Data(), .emptyPayload, [], 0),
            (Data([0]), .terminated, [], 2),
            (Data([4]), .unterminatedPayload, [0x1_0000_0004], 0),
            (Data([4, 0]), .terminated, [0x1_0000_0004], 1)
        ]
        for (payload, expectedOutcome, expectedAddresses, expectedDisagreements) in cases {
            // The bytes overload parses and projects the actual image; it does not reopen this
            // descriptive path. Exact command sizes and a contained named segment satisfy the
            // supplied reconstruction guards; the optional UUID is populated, not required.
            let loaded = try MachOBinaryLoader().load(
                bytes: functionStartsImage(payload: payload, includeUnwind: true),
                sourceURL: URL(fileURLWithPath: "/function-starts-completeness-fixture"))
            XCTAssertEqual(loaded.functionStarts, expectedAddresses)
            XCTAssertEqual(loaded.functionStartsParseOutcome, expectedOutcome)
            XCTAssertEqual(loaded.loaderFindings.filter { $0.category == .functionStartsDisagreement }.count,
                expectedDisagreements)
        }
    }

    func testFunctionStartsMalformedULEBsStillThrowInsteadOfReturningComplete() {
        let malformed = [Data([0x80]), Data([4, 0x80]), Data(repeating: 0x80, count: 10),
            Data(repeating: 0x80, count: 9) + Data([2]),
            Data(repeating: 0x80, count: 9) + Data([0x81, 0])]
        for payload in malformed {
            XCTAssertThrowsError(try MachOParser().parse(functionStartsImage(payload: payload),
                options: functionStartOptions)) { error in
                guard case MachOParserError.truncated(let context) = error else {
                    return XCTFail("expected LC ULEB truncation error, got \(error)")
                }
                XCTAssertEqual(context, "LC_FUNCTION_STARTS delta")
            }
        }
    }

    func testFunctionStartsCheckedOffsetAndAddressOverflowStillThrow() {
        let maximumDelta = Data(repeating: 0xff, count: 9) + Data([1])
        let cases: [(Data, UInt64, String)] = [
            (maximumDelta + Data([1, 0]), 0, "LC_FUNCTION_STARTS delta overflows image offset"),
            (Data([1, 0]), UInt64.max, "LC_FUNCTION_STARTS address overflows image base")
        ]
        for (payload, base, expectedReason) in cases {
            XCTAssertThrowsError(try MachOParser().parse(functionStartsImage(payload: payload, imageBase: base),
                options: functionStartOptions)) { error in
                guard case MachOParserError.invalidLoadCommand(_, let reason) = error else {
                    return XCTFail("expected checked LC address arithmetic error, got \(error)")
                }
                XCTAssertEqual(reason, expectedReason)
            }
        }
    }

    // MARK: - F2: MachOPatchWriter must not trap on hostile segment arithmetic

    /// Variant A — `Int(fileOffset)` would trap when the mapped offset exceeds Int.max.
    func testPatchWriterFileOffsetAboveIntMaxYieldsTypedErrorNotTrap() throws {
        let data = craftedThinMachO(vmAddress: 0x1000, vmSize: 0x10, fileOffset: .max, fileSize: 0x10)
        let patches: [UInt64: BytePatch] = [0x1000: BytePatch(bytes: [0xAA])]
        XCTAssertThrowsError(try MachOPatchWriter().makePatchedData(originalData: data, patches: patches)) { error in
            guard case MachOPatchWriter.PatchWriteError.fileOffsetOutOfRange = error else {
                return XCTFail("expected fileOffsetOutOfRange, got \(error)")
            }
        }
    }

    /// Variant B — `segment.fileOffset + offsetIntoSegment` would trap on UInt64 overflow.
    func testPatchWriterWrappingFileOffsetAdditionYieldsTypedErrorNotTrap() throws {
        let data = craftedThinMachO(vmAddress: 0x1000, vmSize: 0x10, fileOffset: .max, fileSize: 0x10)
        let patches: [UInt64: BytePatch] = [0x1001: BytePatch(bytes: [0xAA])] // offsetIntoSegment = 1
        // The overflowed mapping returns nil; the writer re-classifies it as a typed error.
        XCTAssertThrowsError(try MachOPatchWriter().makePatchedData(originalData: data, patches: patches)) { error in
            XCTAssertTrue(error is MachOPatchWriter.PatchWriteError, "expected a typed PatchWriteError, got \(error)")
        }
    }

    /// Variant C — `segment.vmAddress + segment.fileSize` would trap during the containment search.
    func testPatchWriterWrappingSegmentVMRangeYieldsTypedErrorNotTrap() throws {
        let data = craftedThinMachO(vmAddress: .max - 3, vmSize: 8, fileOffset: 0, fileSize: 8)
        let patches: [UInt64: BytePatch] = [UInt64.max - 3: BytePatch(bytes: [0xAA])]
        // The wrapping VM range is skipped, so the address maps to no segment.
        XCTAssertThrowsError(try MachOPatchWriter().makePatchedData(originalData: data, patches: patches)) { error in
            guard case MachOPatchWriter.PatchWriteError.addressNotMapped = error else {
                return XCTFail("expected addressNotMapped, got \(error)")
            }
        }
    }

    /// A valid patch through the normal fixture still applies byte-exact (no regression).
    func testPatchWriterStillAppliesValidPatchByteExact() throws {
        let fixture = MachOFixture.makeExecutable()
        let patched = try MachOPatchWriter().makePatchedData(
            originalData: fixture.bytes,
            patches: [fixture.baseAddress: BytePatch(bytes: [0x1f, 0x20, 0x03, 0xd5])]
        )
        XCTAssertEqual(patched.count, fixture.bytes.count)
        XCTAssertEqual(Array(patched[fixture.codeOffset..<(fixture.codeOffset + 4)]), [0x1f, 0x20, 0x03, 0xd5])
    }

    // MARK: - F4: MachOFile.virtualAddress(forFileOffset:) must not trap on hostile segments

    func testVirtualAddressForFileOffsetDoesNotTrapOnWrappingSegmentFileRange() throws {
        // fileOffset + fileSize wraps UInt64 → the read-side mapping must skip the segment, not trap.
        let data = craftedThinMachO(vmAddress: 0x4000, vmSize: 2, fileOffset: .max, fileSize: 2)
        let machO = try MachOParser().parse(data)
        XCTAssertNil(machO.virtualAddress(forFileOffset: 0), "a wrapping segment file range must map to nil, never trap")
        XCTAssertNil(machO.virtualAddress(forFileOffset: .max))
    }

    func testVirtualAddressForFileOffsetDoesNotTrapOnWrappingVMBase() throws {
        // A valid file range but vmAddress + delta wraps UInt64 → must return nil, not trap.
        let data = craftedThinMachO(vmAddress: .max, vmSize: 16, fileOffset: 0, fileSize: 16)
        let machO = try MachOParser().parse(data)
        XCTAssertNil(machO.virtualAddress(forFileOffset: 8), "a wrapping vmAddress mapping must return nil, never trap")
    }

    // MARK: - F3: section-count resource-amplification DoS is bounded

    func testParserRejectsOverBudgetSectionCountBeforeAllocating() {
        // A STRUCTURALLY-VALID LC_SEGMENT_64 (cmdsize admits every declared section record) that
        // declares ONE section over the budget. The structural size check therefore PASSES, so only
        // the per-segment section-count cap can reject it — isolating the new guard. (The previous
        // 10M/cmdsize=72 fixture was ALSO caught by the pre-existing structural check, so it did not
        // prove the cap; this asserts the cap's specific error.)
        let overBudget = 65_537   // MachORecoveryLimits.maximumSections (64Ki, file-private) + 1
        let sectionRecordsBytes = overBudget * 80
        let cmdsize = UInt32(72 + sectionRecordsBytes)
        var bytes = Data()
        bytes.appendUInt32LE(0xfeedfacf)
        bytes.appendUInt32LE(UInt32(bitPattern: MachOConstants.cpuTypeARM64))
        bytes.appendUInt32LE(0)
        bytes.appendUInt32LE(MachOConstants.fileTypeExecute)
        bytes.appendUInt32LE(1)                      // ncmds
        bytes.appendUInt32LE(cmdsize)                // sizeofcmds (admits all records → structural check passes)
        bytes.appendUInt32LE(0)
        bytes.appendUInt32LE(0)
        bytes.appendUInt32LE(MachOConstants.loadCommandSegment64)
        bytes.appendUInt32LE(cmdsize)                // cmdsize
        bytes.appendFixedCString("__DOS", length: 16)
        bytes.appendUInt64LE(0)                      // vmaddr
        bytes.appendUInt64LE(0)                      // vmsize
        bytes.appendUInt64LE(0)                      // fileoff
        bytes.appendUInt64LE(0)                      // filesize
        bytes.appendUInt32LE(5)
        bytes.appendUInt32LE(5)
        bytes.appendUInt32LE(UInt32(overBudget))     // nsects — one over the cap
        bytes.appendUInt32LE(0)
        bytes.append(Data(count: sectionRecordsBytes)) // the declared section records (zeroed)
        XCTAssertThrowsError(try MachOParser().parse(bytes)) { error in
            guard let parserError = error as? MachOParserError,
                  case .invalidLoadCommand(_, let reason) = parserError,
                  reason.contains("section count exceeds") else {
                return XCTFail("expected the section-count cap to fire (not the structural check), got \(error)")
            }
        }
    }
}

/// Self-contained little-endian byte builders for the crafted fixtures above (the equivalents in
/// MachOImportTests are `fileprivate` to that file).
private extension Data {
    mutating func appendUInt32LE(_ value: UInt32) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }
    mutating func appendUInt64LE(_ value: UInt64) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }
    mutating func appendFixedCString(_ string: String, length: Int) {
        var field = Array(string.utf8.prefix(length))
        if field.count < length { field.append(contentsOf: Array(repeating: 0, count: length - field.count)) }
        append(contentsOf: field.prefix(length))
    }
}
