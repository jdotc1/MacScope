import Foundation
import XCTest
@testable import MacScope

// Item 1309, pin 16da8e01dd5d2bbee339cc988b0d966003939029.
// BLOCKED-path baseline only. These tests deliberately have NO native-token dependency.
// They guard D1 and value-write behavior, not acceptance of the proposed narrower key.
// T-A1/T-A2 token/capture tests remain the plan in DESIGN.md section 6.
// Supplement 1 correction: concrete wire reconstruction is also covered below.
// Static authored; not compiled or run by this item. No external files or binaries.
final class NativeValidationTokenCoverageTests: XCTestCase {
    // Copied from input 12, ScriptingCaptureTests:8-11.
    private let functionID = UUID(uuidString: "30000000-0000-0000-0000-000000000003")!
    private let binaryID = UUID(uuidString: "10000000-0000-0000-0000-000000000001")!
    private let secondID = UUID(uuidString: "30000000-0000-0000-0000-000000000004")!
    private let thirdID = UUID(uuidString: "30000000-0000-0000-0000-000000000005")!

    private typealias Mutation = (name: String, apply: (inout WorkspaceSnapshot) -> Void)

    func testPublicGenerationStillRenewsForRepresentableAuthoringWrites() throws {
        let original = try makeScriptingFixture()
        let generation = original.analysisGenerationID
        let key = ImageAddress(slot: .primary, address: 0x1000)
        let cases: [Mutation] = [
            // Empty-map replacement is an observer case, not a nonempty rename test.
            ("addressOverrides assignment", { $0.addressOverrides = [:] }),
            // Constructor shape evidenced by WorkspaceSnapshot:2466.
            ("imported prototype", {
                $0.importedPrototypes[key] = FunctionSignatureOverride(returnType: "void")
            }),
            // A populated TypeDefinition initializer is not in the supplied fixtures.
            ("typeDefinitions assignment", { $0.typeDefinitions = [] }),
            ("header evidence empty input", { $0.recordHeaderImportEvidence([]) })
        ]
        for mutation in cases {
            var edited = original
            mutation.apply(&edited)
            XCTAssertNotEqual(edited.analysisGenerationID, generation, mutation.name)
            XCTAssertEqual(original.analysisGenerationID, generation, mutation.name)
            XCTAssertEqual(edited.binaries, original.binaries, mutation.name)
            XCTAssertEqual(edited.analysis(in: .primary)?.imageBytes,
                           original.analysis(in: .primary)?.imageBytes, mutation.name)
            XCTAssertEqual(edited.analysis(in: .primary)?.analysisInputFingerprint,
                           original.analysis(in: .primary)?.analysisInputFingerprint, mutation.name)
        }
    }

    func testPublicGenerationRenewsForBinaryWritesBeforeAnyFingerprintRefresh() throws {
        let original = try makeScriptingFixture()
        let generation = original.analysisGenerationID
        let cases: [Mutation] = [
            ("same binary array", { snapshot in
                let images = snapshot.binaries
                snapshot.binaries = images
            }),
            ("binary duplicate membership", { snapshot in
                let image = snapshot.binaries[0]
                snapshot.binaries.append(image)
            }),
            ("binary slot", { $0.binaries[0].slot = ImageSlot(rawValue: 7) }),
            ("integrity", { $0.binaries[0].artifactIntegrityState = .unavailable }),
            ("artifact identity", { $0.binaries[0].artifactIdentity = nil }),
            ("segment layout", { $0.binaries[0].preferredSegmentLayout = nil }),
            ("slice selection", { $0.binaries[0].selectedSliceIndex = 0 }),
            ("binary name", { $0.binaries[0].name = "changed image" }),
            ("binary path", { $0.binaries[0].path = "changed-synthetic-path" }),
            ("binary metadata", { $0.binaries[0].metadata.uuid = "changed" }),
            ("nested metadata array", { $0.binaries[0].metadata.buildTools.append("changed") }),
            ("same archive authority", { $0.binaries[0].elfArchiveMemberIdentity = nil }),
            ("unrelated bookmark", { $0.binaries[0].originalPathBookmark = Data([1]) })
        ]
        for mutation in cases {
            var edited = original
            mutation.apply(&edited)
            // Crucially no refreshFingerprint helper before this assertion.
            XCTAssertNotEqual(edited.analysisGenerationID, generation, mutation.name)
            XCTAssertEqual(original.analysisGenerationID, generation, mutation.name)
            XCTAssertEqual(edited.analysis(in: .primary)?.analysisInputFingerprint,
                           original.analysis(in: .primary)?.analysisInputFingerprint, mutation.name)
        }
    }

    func testPublicGenerationRenewsForAnalysisWritebackRoutes() throws {
        let original = try makeScriptingFixture()
        let generation = original.analysisGenerationID
        let cases: [Mutation] = [
            ("remove bucket", { $0.analysisBySlot[.primary] = nil }),
            ("same bucket", { snapshot in
                let bucket = snapshot.analysisBySlot[.primary]
                snapshot.analysisBySlot[.primary] = bucket
            }),
            ("replaceAnalysis", { snapshot in
                if let bucket = snapshot.analysis(in: .primary) {
                    snapshot.replaceAnalysis(bucket, in: .primary)
                }
            }),
            ("no-op mutateAnalysis", { snapshot in
                snapshot.mutateAnalysis(in: .primary) { _ in }
            }),
            ("flat setter same functions", { snapshot in
                let functions = snapshot.functions
                snapshot.functions = functions
            }),
            ("nested function name", {
                $0.analysisBySlot[.primary]?.functions[0].name = "changed function"
            }),
            ("function count", { $0.analysisBySlot[.primary]?.functions.removeLast() }),
            ("symbol count", { snapshot in
                snapshot.symbols = [SymbolSummary(id: UUID(), name: "symbol", address: 0x1000,
                                                  kind: "export", libraryName: nil,
                                                  rawLinkageName: "_symbol")]
            }),
            ("xref count", { snapshot in
                snapshot.xrefs = [XRef(id: UUID(), from: 0x1000, to: 0x1008, kind: XRefKind.call)]
            }),
            ("instruction count", { $0.analysisBySlot[.primary]?.instructions.removeLast() }),
            ("instruction element", {
                $0.analysisBySlot[.primary]?.instructions[0].mnemonic = "changed"
            }),
            // A semantic facet omits this bit; write-based generation must still advance.
            ("breakpoint bit with equal facet fields", {
                $0.analysisBySlot[.primary]?.instructions[0].hasBreakpoint = true
            }),
            ("selected slice byte", { $0.analysisBySlot[.primary]?.imageBytes[0] = 1 }),
            ("stored fingerprint", { $0.analysisBySlot[.primary]?.analysisInputFingerprint = nil }),
            ("same stored fingerprint", { snapshot in
                let fingerprint = snapshot.analysis(in: .primary)?.analysisInputFingerprint
                snapshot.analysisBySlot[.primary]?.analysisInputFingerprint = fingerprint
            }),
            ("attestations", { $0.identityEffectiveByteRanges = [] }),
            ("same relocations", { snapshot in
                let relocations = snapshot.relocations
                snapshot.relocations = relocations
            }),
            ("loader section", { $0.analysisBySlot[.primary]?.sections[0].name = "changed" }),
            ("code-data ranges", { snapshot in
                snapshot.codeDataRanges = [CodeDataRangeSummary(id: UUID(), address: 0x1000,
                                                                size: 4, kind: "data")]
            }),
            ("control flow", { snapshot in
                snapshot.controlFlowEdges = [ControlFlowEdge(id: UUID(), from: 0x1000,
                                                             to: 0x1004, kind: "flow")]
            }),
            ("source lines", { snapshot in
                snapshot.sourceLines = [SourceLineEntry(address: 0x1000, file: "synthetic.c",
                                                        line: 1, column: 1, endSequence: false)]
            }),
            ("same load metadata", { $0.machOMetadata = nil }),
            ("unrelated diagnostics", { $0.diagnostics = [] })
        ]
        for mutation in cases {
            var edited = original
            mutation.apply(&edited)
            XCTAssertNotEqual(edited.analysisGenerationID, generation, mutation.name)
            XCTAssertEqual(original.analysisGenerationID, generation, mutation.name)
            XCTAssertEqual(original.analysis(in: .primary)?.functions.first?.name, "entry", mutation.name)
            XCTAssertEqual(original.analysis(in: .primary)?.imageBytes.first, 0, mutation.name)
        }
    }

    func testFreshConstructionWithReusedAnalysisAndPlainCopyHaveDifferentRoles() throws {
        let original = try makeScriptingFixture()
        let plainCopy = original
        let reconstructed = WorkspaceSnapshot(binaries: original.binaries,
                                               analysisBySlot: original.analysisBySlot)
        XCTAssertEqual(plainCopy.analysisGenerationID, original.analysisGenerationID)
        XCTAssertNotEqual(reconstructed.analysisGenerationID, original.analysisGenerationID)
        XCTAssertEqual(reconstructed.analysis(in: .primary)?.analysisInputFingerprint,
                       original.analysis(in: .primary)?.analysisInputFingerprint)
        var edited = original
        edited.analysisBySlot[.primary]?.imageBytes[0] = 1
        XCTAssertNotEqual(edited.analysisGenerationID, original.analysisGenerationID)
        XCTAssertEqual(plainCopy.analysisGenerationID, original.analysisGenerationID)
        XCTAssertEqual(plainCopy.analysis(in: .primary)?.imageBytes.first, 0)
    }

    func testOldFingerprintTextDoesNotAuthorizeChangedSelectedSliceBytes() throws {
        let original = try makeScriptingFixture()
        _ = try NativeDecompilerSnapshotBuilder.validateImage(from: original, imageSlot: .primary)
        var edited = original
        edited.analysisBySlot[.primary]?.imageBytes[0] = 1
        XCTAssertEqual(edited.analysis(in: .primary)?.analysisInputFingerprint,
                       original.analysis(in: .primary)?.analysisInputFingerprint)
        XCTAssertThrowsError(try NativeDecompilerSnapshotBuilder.validateImage(
            from: edited, imageSlot: .primary
        )) { error in
            XCTAssertEqual(error as? NativeDecompilerSnapshotProjectionError, .selectedSliceMismatch)
        }
    }

    func testWireDecodeCreatesFreshPublicGenerationForEachReconstruction() throws {
        let original = try makeScriptingFixture()
        // APIs supplied whole by supplement 1: WireCodec:220,433-465,471-486.
        let codec = PayloadWireCodec()
        let encoded = codec.encodeReply(.success(original))
        let first = try codec.decodeReply(encoded)
        let second = try codec.decodeReply(encoded, pinnedSource: nil)
        XCTAssertNotEqual(first.analysisGenerationID, original.analysisGenerationID)
        XCTAssertNotEqual(second.analysisGenerationID, original.analysisGenerationID)
        XCTAssertNotEqual(first.analysisGenerationID, second.analysisGenerationID)
        XCTAssertEqual(first.analysis(in: .primary)?.imageBytes,
                       original.analysis(in: .primary)?.imageBytes)
        XCTAssertEqual(second.analysis(in: .primary)?.imageBytes,
                       original.analysis(in: .primary)?.imageBytes)
    }

    // Exact copied fixture body: input 12, ScriptingCaptureTests:509-612.
    // File-private source helper is not called across files.
    private func makeScriptingFixture(byteCount: Int = 128, xrefCount: Int = 0) throws -> WorkspaceSnapshot {
        let bytes = Data(repeating: 0, count: byteCount)
        let artifact = try MachOSliceArtifactIdentity(
            uuid: UUID(uuidString: "30000000-0000-0000-0000-000000000003")!,
            rawCPUType: MachOConstants.cpuTypeARM64,
            rawCPUSubtype: 0,
            selectedSliceSHA256: AnalysisFingerprintBuilder.sha256Hex(bytes),
            selectedSliceByteCount: UInt64(bytes.count)
        )
        let layout = try MachOPreferredSegmentLayout(
            records: [
                .init(
                    name: "__TEXT",
                    preferredVMStart: 0x1000,
                    preferredVMSize: UInt64(bytes.count),
                    sliceRelativeFileOffset: 0,
                    fileSize: UInt64(bytes.count),
                    initialProtections: 5
                ),
            ],
            selectedSliceByteCount: UInt64(bytes.count)
        )
        let binary = BinaryImage(
            id: binaryID,
            name: "fixture",
            path: "synthetic-fixture",
            kind: "Mach-O 64-bit",
            architecture: "arm64",
            artifactIdentity: artifact,
            preferredSegmentLayout: layout,
            artifactIntegrityState: .verified,
            slot: .primary
        )
        var analysis = ImageAnalysis(
            functions: [
                FunctionSummary(
                    id: functionID,
                    name: "entry",
                    startAddress: 0x1000,
                    endAddress: 0x1008,
                    confidence: 1
                ),
            ],
            basicBlocks: [
                BasicBlockSummary(
                    id: UUID(),
                    functionID: functionID,
                    startAddress: 0x1000,
                    endAddress: 0x1008,
                    instructionCount: 2
                ),
            ],
            instructions: [
                InstructionRow(
                    address: 0x1000,
                    bytes: "1f 20 03 d5",
                    mnemonic: "nop",
                    operands: "",
                    hasBreakpoint: false,
                    comment: nil
                ),
                InstructionRow(
                    address: 0x1004,
                    bytes: "c0 03 5f d6",
                    mnemonic: "ret",
                    operands: "",
                    hasBreakpoint: false,
                    comment: nil
                ),
            ],
            sections: [
                SectionSummary(
                    id: UUID(uuidString: "50000000-0000-0000-0000-000000000005")!,
                    name: "__TEXT,__text",
                    address: 0x1000,
                    size: UInt64(bytes.count),
                    fileOffset: 0,
                    isExecutable: true
                ),
            ],
            identityEffectiveByteRanges: [try IdentityEffectiveByteRangeAttestation(
                artifactIdentity: artifact,
                segmentName: "__TEXT",
                startAddress: 0x1000,
                endAddressExclusive: 0x1000 + UInt64(bytes.count),
                sliceRelativeFileOffset: 0,
                byteCount: UInt64(bytes.count),
                initialProtections: 5,
                rawBytesSHA256: AnalysisFingerprintBuilder.sha256Hex(bytes)
            )],
            imageBytes: bytes
        )
        analysis.functions += [
            .init(id: secondID, name: "second", startAddress: 0x1008, endAddress: 0x1010, confidence: 1),
            .init(id: thirdID, name: "third", startAddress: 0x1010, endAddress: 0x1018, confidence: 1)]
        analysis.xrefs = (0..<xrefCount).map { _ in
            .init(id: UUID(), from: 0xf0000000, to: 0xf0000004, kind: XRefKind.call)
        }
        analysis.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(
            binary: binary,
            analysis: analysis
        )
        return WorkspaceSnapshot(binaries: [binary], analysisBySlot: [.primary: analysis])
    }
}
