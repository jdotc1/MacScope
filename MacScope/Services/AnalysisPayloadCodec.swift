import CryptoKit
import Foundation
import os

/// The derived products emitted by the analysis engine and safe to transfer across
/// the analysis-worker boundary. User-authored workspace state deliberately has no
/// representation here; the main-actor store remains its source of truth.
struct AnalysisResultPayload: Codable, Equatable, Sendable {
    private static let logger = Logger(subsystem: "com.jeffcooney.MacScope", category: "AnalysisPayload")
    var binaries: [BinaryImage]
    var functions: [FunctionSummary]
    var symbols: [SymbolSummary]
    var imports: [ImportSummary]
    var indirectSymbols: [IndirectSymbolSummary]
    var exports: [ExportSummary]
    var stringLiterals: [StringLiteralSummary]
    var stringLiteralCoverage: StringLiteralCoverage? = nil
    var basicBlocks: [BasicBlockSummary]
    var instructions: [InstructionRow]
    var xrefs: [XRef]
    var controlFlowEdges: [ControlFlowEdge]
    var hexBytes: Data
    var jumpTables: [UInt64: [UInt64]]
    var objcSelectors: [UInt64: String]
    /// HOP-5c: `__cfstring` object address → contents. Only the CFString part of the image's
    /// constant-string map crosses the wire; the C-string part is rebuilt from `stringLiterals`.
    var constantCFStrings: [UInt64: String]
    /// Retained CFString object -> backing address table; nil for legacy replies.
    var cfStringBackings: ImageConstantStringProvider.CFStringBackingTable?
    /// RX-02a: `__objc_classrefs` slot → class. Legacy replies carry none.
    var objcClassReferences: [UInt64: ObjCClassReferenceTarget]
    var objcClasses: [ObjCClass]
    var objcProtocols: [ObjCProtocol]
    var objcCategories: [ObjCCategory]
    var swiftTypes: [SwiftTypeDescriptor]
    var swiftConformances: [SwiftConformance]
    var sections: [SectionSummary]
    var codeDataRanges: [CodeDataRangeSummary]
    var relocations: [RelocationSummary]
    var identityEffectiveByteRanges: [IdentityEffectiveByteRangeAttestation]
    var sourceLines: [SourceLineEntry]
    var imageBytes: Data
    var diagnostics: [AnalysisDiagnostic]
    var machOMetadata: MachOLoadMetadata?
    var analysisInputFingerprint: AnalysisInputFingerprint?
    /// Same-build worker reply only. BinaryImage's saved encoding excludes this.
    var containerAdmissionWitness: MachOContainerAdmissionWitness?

    private enum CodingKeys: String, CodingKey {
        case binaries
        case functions
        case symbols
        case imports
        case indirectSymbols
        case exports
        case stringLiterals
        case stringLiteralCoverage
        case basicBlocks
        case instructions
        case xrefs
        case controlFlowEdges
        case hexBytes
        case jumpTables
        case objcSelectors
        case constantCFStrings
        case cfStringBackings
        case objcClassReferences
        case objcClasses
        case objcProtocols
        case objcCategories
        case swiftTypes
        case swiftConformances
        case sections
        case codeDataRanges
        case relocations
        case identityEffectiveByteRanges
        case sourceLines
        case imageBytes
        case diagnostics
        case machOMetadata
        case analysisInputFingerprint
        case containerAdmissionWitness
    }

    /// JSON objects cannot preserve UInt64 keys without string coercion. Pair arrays
    /// retain the numeric key and are sorted before encoding for deterministic output.
    private struct UInt64Pair<Value: Codable & Equatable>: Codable, Equatable {
        var address: UInt64
        var value: Value
    }

    init(
        binaries: [BinaryImage],
        functions: [FunctionSummary],
        symbols: [SymbolSummary],
        imports: [ImportSummary],
        indirectSymbols: [IndirectSymbolSummary],
        exports: [ExportSummary],
        stringLiterals: [StringLiteralSummary],
        stringLiteralCoverage: StringLiteralCoverage? = nil,
        basicBlocks: [BasicBlockSummary],
        instructions: [InstructionRow],
        xrefs: [XRef],
        controlFlowEdges: [ControlFlowEdge],
        hexBytes: Data,
        jumpTables: [UInt64: [UInt64]],
        objcSelectors: [UInt64: String],
        objcClasses: [ObjCClass],
        objcCategories: [ObjCCategory],
        objcProtocols: [ObjCProtocol] = [],
        swiftTypes: [SwiftTypeDescriptor],
        swiftConformances: [SwiftConformance],
        sections: [SectionSummary],
        codeDataRanges: [CodeDataRangeSummary],
        relocations: [RelocationSummary],
        sourceLines: [SourceLineEntry],
        imageBytes: Data,
        diagnostics: [AnalysisDiagnostic],
        machOMetadata: MachOLoadMetadata?,
        analysisInputFingerprint: AnalysisInputFingerprint? = nil,
        containerAdmissionWitness: MachOContainerAdmissionWitness? = nil,
        identityEffectiveByteRanges: [IdentityEffectiveByteRangeAttestation] = [],
        constantCFStrings: [UInt64: String] = [:],
        cfStringBackings: ImageConstantStringProvider.CFStringBackingTable? = nil,
        objcClassReferences: [UInt64: ObjCClassReferenceTarget] = [:]
    ) {
        self.binaries = binaries
        self.functions = functions
        self.symbols = symbols
        self.imports = imports
        self.indirectSymbols = indirectSymbols
        self.exports = exports
        self.stringLiterals = stringLiterals
        self.stringLiteralCoverage = stringLiteralCoverage
        self.basicBlocks = basicBlocks
        self.instructions = instructions
        self.xrefs = xrefs
        self.controlFlowEdges = controlFlowEdges
        self.hexBytes = hexBytes
        self.jumpTables = jumpTables
        self.objcSelectors = objcSelectors
        self.constantCFStrings = constantCFStrings
        self.cfStringBackings = cfStringBackings
        self.objcClassReferences = objcClassReferences
        self.objcClasses = objcClasses
        self.objcCategories = objcCategories
        self.objcProtocols = objcProtocols
        self.swiftTypes = swiftTypes
        self.swiftConformances = swiftConformances
        self.sections = sections
        self.codeDataRanges = codeDataRanges
        self.relocations = relocations
        self.identityEffectiveByteRanges = identityEffectiveByteRanges
        self.sourceLines = sourceLines
        self.imageBytes = imageBytes
        self.diagnostics = diagnostics
        self.machOMetadata = machOMetadata
        self.analysisInputFingerprint = analysisInputFingerprint
        self.containerAdmissionWitness = containerAdmissionWitness
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        binaries = try container.decode([BinaryImage].self, forKey: .binaries)
        functions = try container.decode([FunctionSummary].self, forKey: .functions)
        symbols = try container.decode([SymbolSummary].self, forKey: .symbols)
        imports = try container.decode([ImportSummary].self, forKey: .imports)
        indirectSymbols = try container.decode([IndirectSymbolSummary].self, forKey: .indirectSymbols)
        exports = try container.decode([ExportSummary].self, forKey: .exports)
        stringLiterals = try container.decode([StringLiteralSummary].self, forKey: .stringLiterals)
        stringLiteralCoverage = try container.decodeIfPresent(StringLiteralCoverage.self, forKey: .stringLiteralCoverage)
        basicBlocks = try container.decode([BasicBlockSummary].self, forKey: .basicBlocks)
        instructions = try container.decode([InstructionRow].self, forKey: .instructions)
        xrefs = try container.decode([XRef].self, forKey: .xrefs)
        controlFlowEdges = try container.decode([ControlFlowEdge].self, forKey: .controlFlowEdges)
        hexBytes = try container.decode(Data.self, forKey: .hexBytes)
        jumpTables = try Self.decodeMap(
            [UInt64].self,
            from: container,
            forKey: .jumpTables
        )
        objcSelectors = try Self.decodeMap(
            String.self,
            from: container,
            forKey: .objcSelectors
        )
        // Legacy replies predate HOP-5c constant CFStrings.
        constantCFStrings = container.contains(.constantCFStrings)
            ? try Self.decodeMap(String.self, from: container, forKey: .constantCFStrings)
            : [:]
        cfStringBackings = try container.decodeIfPresent(
            ImageConstantStringProvider.CFStringBackingTable.self, forKey: .cfStringBackings
        ).map(ImageConstantStringProvider.validated)
        objcClassReferences = container.contains(.objcClassReferences)
            ? try Self.decodeMap(ObjCClassReferenceTarget.self, from: container, forKey: .objcClassReferences)
            : [:]
        objcClasses = try container.decode([ObjCClass].self, forKey: .objcClasses)
        objcProtocols = try container.decodeIfPresent([ObjCProtocol].self, forKey: .objcProtocols) ?? []
        objcCategories = try container.decode([ObjCCategory].self, forKey: .objcCategories)
        swiftTypes = try container.decode([SwiftTypeDescriptor].self, forKey: .swiftTypes)
        swiftConformances = try container.decode([SwiftConformance].self, forKey: .swiftConformances)
        sections = try container.decode([SectionSummary].self, forKey: .sections)
        codeDataRanges = try container.decodeIfPresent([CodeDataRangeSummary].self, forKey: .codeDataRanges) ?? []
        relocations = try container.decode([RelocationSummary].self, forKey: .relocations)
        // Legacy replies carry no effective-byte authority; do not derive or invent it.
        identityEffectiveByteRanges = try (container.decodeIfPresent(
            [EffectiveByteRangePayload].self, forKey: .identityEffectiveByteRanges) ?? [])
            .map { try $0.validatedAttestation() }
        sourceLines = try container.decode([SourceLineEntry].self, forKey: .sourceLines)
        imageBytes = try container.decode(Data.self, forKey: .imageBytes)
        // One diagnostic this build can't read (a kind added later) is dropped, never the payload.
        let entries = try container.decode([LossyDiagnostic].self, forKey: .diagnostics)
        diagnostics = entries.compactMap(\.value)
        let dropped = entries.count - diagnostics.count
        if dropped > 0 {
            // Visible when debugging, so a real codec bug doesn't hide behind the tolerance.
            Self.logger.debug("Dropped \(dropped, privacy: .public) undecodable diagnostics from an analysis payload")
        }
        machOMetadata = try container.decodeIfPresent(MachOLoadMetadata.self, forKey: .machOMetadata)
        analysisInputFingerprint = try container.decodeIfPresent(
            AnalysisInputFingerprint.self,
            forKey: .analysisInputFingerprint
        )
        containerAdmissionWitness = try container.decodeIfPresent(
            MachOContainerAdmissionWitness.self, forKey: .containerAdmissionWitness)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(binaries, forKey: .binaries)
        try container.encode(functions, forKey: .functions)
        try container.encode(symbols, forKey: .symbols)
        try container.encode(imports, forKey: .imports)
        try container.encode(indirectSymbols, forKey: .indirectSymbols)
        try container.encode(exports, forKey: .exports)
        try container.encode(stringLiterals, forKey: .stringLiterals)
        try container.encodeIfPresent(stringLiteralCoverage, forKey: .stringLiteralCoverage)
        try container.encode(basicBlocks, forKey: .basicBlocks)
        try container.encode(instructions, forKey: .instructions)
        try container.encode(xrefs, forKey: .xrefs)
        try container.encode(controlFlowEdges, forKey: .controlFlowEdges)
        try container.encode(hexBytes, forKey: .hexBytes)
        try Self.encodeMap(jumpTables, to: &container, forKey: .jumpTables)
        try Self.encodeMap(objcSelectors, to: &container, forKey: .objcSelectors)
        try Self.encodeMap(constantCFStrings, to: &container, forKey: .constantCFStrings)
        if let cfStringBackings {
            try container.encode(ImageConstantStringProvider.validated(cfStringBackings), forKey: .cfStringBackings)
        }
        try Self.encodeMap(objcClassReferences, to: &container, forKey: .objcClassReferences)
        try container.encode(objcClasses, forKey: .objcClasses)
        try container.encode(objcProtocols, forKey: .objcProtocols)
        try container.encode(objcCategories, forKey: .objcCategories)
        try container.encode(swiftTypes, forKey: .swiftTypes)
        try container.encode(swiftConformances, forKey: .swiftConformances)
        try container.encode(sections, forKey: .sections)
        try container.encode(codeDataRanges, forKey: .codeDataRanges)
        try container.encode(relocations, forKey: .relocations)
        try container.encode(identityEffectiveByteRanges.map(EffectiveByteRangePayload.init),
            forKey: .identityEffectiveByteRanges)
        try container.encode(sourceLines, forKey: .sourceLines)
        try container.encode(imageBytes, forKey: .imageBytes)
        try container.encode(diagnostics, forKey: .diagnostics)
        try container.encodeIfPresent(machOMetadata, forKey: .machOMetadata)
        try container.encodeIfPresent(analysisInputFingerprint, forKey: .analysisInputFingerprint)
        try container.encodeIfPresent(containerAdmissionWitness, forKey: .containerAdmissionWitness)
    }

    /// Wire representation only. Decode must re-enter the loader evidence invariants.
    private struct EffectiveByteRangePayload: Codable {
        let artifactIdentity: MachOSliceArtifactIdentity
        let segmentName: String
        let startAddress: UInt64
        let endAddressExclusive: UInt64
        let sliceRelativeFileOffset: UInt64
        let byteCount: UInt64
        let initialProtections: Int32
        let rawBytesSHA256: String

        init(_ value: IdentityEffectiveByteRangeAttestation) {
            artifactIdentity = value.artifactIdentity
            segmentName = value.segmentName
            startAddress = value.startAddress
            endAddressExclusive = value.endAddressExclusive
            sliceRelativeFileOffset = value.sliceRelativeFileOffset
            byteCount = value.byteCount
            initialProtections = value.initialProtections
            rawBytesSHA256 = value.rawBytesSHA256
        }

        func validatedAttestation() throws -> IdentityEffectiveByteRangeAttestation {
            try .init(artifactIdentity: artifactIdentity, segmentName: segmentName,
                startAddress: startAddress, endAddressExclusive: endAddressExclusive,
                sliceRelativeFileOffset: sliceRelativeFileOffset, byteCount: byteCount,
                initialProtections: initialProtections, rawBytesSHA256: rawBytesSHA256)
        }
    }

    private static func decodeMap<Value: Codable & Equatable>(
        _ valueType: Value.Type,
        from container: KeyedDecodingContainer<CodingKeys>,
        forKey key: CodingKeys
    ) throws -> [UInt64: Value] {
        let pairs = try container.decode([UInt64Pair<Value>].self, forKey: key)
        var result: [UInt64: Value] = [:]
        result.reserveCapacity(pairs.count)
        for pair in pairs {
            guard result.updateValue(pair.value, forKey: pair.address) == nil else {
                throw DecodingError.dataCorruptedError(
                    forKey: key,
                    in: container,
                    debugDescription: "Duplicate UInt64 map key \(pair.address)"
                )
            }
        }
        return result
    }

    private static func encodeMap<Value: Codable & Equatable>(
        _ map: [UInt64: Value],
        to container: inout KeyedEncodingContainer<CodingKeys>,
        forKey key: CodingKeys
    ) throws {
        let pairs = map.sorted { $0.key < $1.key }.map {
            UInt64Pair(address: $0.key, value: $0.value)
        }
        try container.encode(pairs, forKey: key)
    }
}

enum AnalysisPayloadCodec {
    static func payload(from snapshot: WorkspaceSnapshot) -> AnalysisResultPayload {
        AnalysisResultPayload(
            binaries: snapshot.binaries,
            functions: snapshot.functions,
            symbols: snapshot.symbols,
            imports: snapshot.imports,
            indirectSymbols: snapshot.indirectSymbols,
            exports: snapshot.exports,
            stringLiterals: snapshot.stringLiterals,
            stringLiteralCoverage: snapshot.stringLiteralCoverage,
            basicBlocks: snapshot.basicBlocks,
            instructions: snapshot.instructions,
            xrefs: snapshot.xrefs,
            controlFlowEdges: snapshot.controlFlowEdges,
            hexBytes: snapshot.hexBytes,
            jumpTables: snapshot.jumpTables,
            objcSelectors: snapshot.objcSelectors,
            objcClasses: snapshot.objcClasses,
            objcCategories: snapshot.objcCategories,
            objcProtocols: snapshot.objcProtocols,
            swiftTypes: snapshot.swiftTypes,
            swiftConformances: snapshot.swiftConformances,
            sections: snapshot.sections,
            codeDataRanges: snapshot.codeDataRanges,
            relocations: snapshot.relocations,
            sourceLines: snapshot.sourceLines,
            imageBytes: snapshot.imageBytes,
            diagnostics: snapshot.diagnostics,
            machOMetadata: snapshot.machOMetadata,
            analysisInputFingerprint: snapshot.analysisInputFingerprint,
            containerAdmissionWitness: snapshot.binaries.count == 1
                ? snapshot.binaries.first?.containerAdmissionWitness : nil,
            identityEffectiveByteRanges: snapshot.identityEffectiveByteRanges,
            constantCFStrings: ImageConstantStringProvider.cfStrings(in: snapshot.constantStrings),
            cfStringBackings: snapshot.analysis(in: snapshot.primarySlot)?.cfStringBackings,
            objcClassReferences: snapshot.analysis(in: snapshot.primarySlot)?.objcClassReferences ?? [:]
        )
    }

    static func snapshot(from payload: AnalysisResultPayload) -> WorkspaceSnapshot {
        var binaries = payload.binaries
        for index in binaries.indices { binaries[index].containerAdmissionWitness = nil }
        if let witness = payload.containerAdmissionWitness,
           binaries.count == 1,
           binaries[0].artifactIntegrityState == .verified,
           binaries[0].artifactIdentity == witness.selectedSliceIdentity,
           UInt64(payload.imageBytes.count) == witness.sliceSize {
            let digest = SHA256.hash(data: payload.imageBytes)
                .map { String(format: "%02x", $0) }.joined()
            if digest == witness.selectedSliceIdentity.selectedSliceSHA256 {
                binaries[0].containerAdmissionWitness = witness
            }
        }
        return WorkspaceSnapshot(
            binaries: binaries,
            functions: payload.functions,
            symbols: payload.symbols,
            imports: payload.imports,
            indirectSymbols: payload.indirectSymbols,
            exports: payload.exports,
            stringLiterals: payload.stringLiterals,
            stringLiteralCoverage: payload.stringLiteralCoverage,
            basicBlocks: payload.basicBlocks,
            instructions: payload.instructions,
            xrefs: payload.xrefs,
            controlFlowEdges: payload.controlFlowEdges,
            hexBytes: payload.hexBytes,
            jumpTables: payload.jumpTables,
            objcSelectors: payload.objcSelectors,
            objcClassReferences: payload.objcClassReferences,
            constantStrings: ImageConstantStringProvider.build(
                stringLiterals: payload.stringLiterals, cfStrings: payload.constantCFStrings
            ),
            cfStringBackings: payload.cfStringBackings,
            objcClasses: payload.objcClasses,
            objcCategories: payload.objcCategories,
            objcProtocols: payload.objcProtocols,
            swiftTypes: payload.swiftTypes,
            swiftConformances: payload.swiftConformances,
            sections: payload.sections,
            codeDataRanges: payload.codeDataRanges,
            relocations: payload.relocations,
            identityEffectiveByteRanges: payload.identityEffectiveByteRanges,
            sourceLines: payload.sourceLines,
            imageBytes: payload.imageBytes,
            diagnostics: payload.diagnostics,
            machOMetadata: payload.machOMetadata,
            analysisInputFingerprint: payload.analysisInputFingerprint
        )
    }
}

/// Decodes one diagnostic, or nil when it doesn't decode (an unknown kind or provenance).
private struct LossyDiagnostic: Decodable {
    let value: AnalysisDiagnostic?

    init(from decoder: Decoder) throws {
        value = try? AnalysisDiagnostic(from: decoder)
    }
}

// MARK: - Framed analysis reply (wire version 5, candidate K2)

/// A single framed binary reply: a fixed header, then eight ordered sections. Seven carry the large
/// row classes as fixed-width binary rows; the eighth is the residual JSON, a legacy-shaped reply
/// envelope whose seven relocated arrays are empty. Every length, count and flag is untrusted and is
/// admitted by `decode` before any model object is built. The model types keep their own Codable
/// conformances; this is a wire-only adapter. The emitter is OFF unless a codec's
/// `Limits.framedReplies` is set; decoding a frame is always recognized by its magic.
///
/// Layout (all integers little-endian): magic `MSAREPLY` (8), UInt32 wire version, UInt8 outcome
/// (0 success, 1 failure), UInt32 section count (8 or 1). Each section is UInt32 tag, UInt64 body
/// length, UInt64 row count, then the body. Success has tags 1...8 in order; failure has one residual
/// section (tag 8, one row) holding a legacy-shaped failure envelope.
enum AnalysisFramedReply {
    static let magic: [UInt8] = Array("MSAREPLY".utf8)
    static let headerByteCount = 17
    static let sectionHeaderByteCount = 20
    /// Length sentinel for an absent optional string or JSON field. Required fields cannot use it.
    static let absentLength = UInt32.max
    /// Message of the existing `unexpected` failure the emitter sends when the frame would exceed the cap.
    static let refusalMessage = "Analysis reply exceeds its raw byte limit."

    enum Outcome: UInt8 { case success = 0, failure = 1 }

    enum Section: UInt32, CaseIterable {
        case instructions = 1, xrefs, controlFlowEdges, basicBlocks, stringLiterals, symbols, functions, residual

        /// Fixed row width before variable contents.
        var minimumRowBytes: UInt64 {
            switch self {
            case .instructions: 29
            case .xrefs, .controlFlowEdges: 36
            case .basicBlocks: 56
            case .stringLiterals: 40
            case .symbols: 33
            case .functions: 48
            case .residual: 0
            }
        }
    }

    /// The legacy-JSON failure a refused emission sends (decodes to `RemoteAnalysisFailure`).
    private struct RefusalEnvelope: Encodable {
        struct Unexpected: Encodable { let _0: String }
        struct Failure: Encodable { let unexpected: Unexpected }
        let version: Int
        let failure: Failure
    }

    /// A parsed and fully admitted frame. `envelopeJSON` is the residual JSON (a legacy-shaped
    /// envelope); `restore` fills the seven relocated arrays of the decoded payload.
    struct Decoded {
        let envelopeJSON: Data
        fileprivate let data: Data
        fileprivate let outcome: Outcome
        fileprivate let entries: [Entry]
        fileprivate let limits: PayloadWireCodec.Limits

        func restore(into payload: inout AnalysisResultPayload) throws {
            guard outcome == .success else { throw AnalysisFramedReply.malformed("a failure frame carries a payload") }
            guard payload.instructions.isEmpty, payload.xrefs.isEmpty, payload.controlFlowEdges.isEmpty,
                  payload.basicBlocks.isEmpty, payload.stringLiterals.isEmpty, payload.symbols.isEmpty,
                  payload.functions.isEmpty else {
                throw AnalysisFramedReply.malformed("the residual repeats a relocated section")
            }
            var ledger = Ledger(limits: limits)
            let sets = try data.withUnsafeBytes {
                try AnalysisFramedReply.parseAll(entries, $0, &ledger, build: true)
            }
            payload.instructions = sets.instructions
            payload.xrefs = sets.xrefs
            payload.controlFlowEdges = sets.controlFlowEdges
            payload.basicBlocks = sets.basicBlocks
            payload.stringLiterals = sets.stringLiterals
            payload.symbols = sets.symbols
            payload.functions = sets.functions
        }
    }

    struct Refusal: Error { let message: String }

    fileprivate struct Entry {
        let section: Section
        let offset: Int
        let length: Int
        let rows: Int
    }

    fileprivate struct RowSets {
        var instructions: [InstructionRow] = []
        var xrefs: [XRef] = []
        var controlFlowEdges: [ControlFlowEdge] = []
        var basicBlocks: [BasicBlockSummary] = []
        var stringLiterals: [StringLiteralSummary] = []
        var symbols: [SymbolSummary] = []
        var functions: [FunctionSummary] = []
    }

    static func malformed(_ reason: String) -> DecodingError {
        .dataCorrupted(.init(codingPath: [], debugDescription: "Analysis reply frame is malformed: \(reason)."))
    }

    static func limitError(_ budget: String, detail: String? = nil) -> DecodingError {
        let suffix = detail.map { " (\($0))" } ?? ""
        return .dataCorrupted(.init(
            codingPath: [], debugDescription: "Analysis reply exceeds its \(budget) limit\(suffix)."
        ))
    }

    // MARK: Ledger

    /// Whole-reply logical ledgers, charged identically for binary rows and embedded JSON, so
    /// nothing resets between a row and its nested JSON. Strings are charged by the canonical rule:
    /// quote, backslash and slash cost 2; C0 controls cost 6; other scalars their UTF-8 width.
    fileprivate struct Ledger {
        let limits: PayloadWireCodec.Limits
        var values = 0
        var stringBytes = 0

        init(limits: PayloadWireCodec.Limits) { self.limits = limits }

        mutating func add(values count: Int) {
            let (sum, overflow) = values.addingReportingOverflow(count)
            values = overflow ? Int.max : sum
        }

        /// One string value or key: one model value plus its charged bytes.
        mutating func string(_ charge: Int) throws {
            add(values: 1)
            guard charge <= limits.maximumReplySingleStringBytes else { throw AnalysisFramedReply.limitError("string byte") }
            let (sum, overflow) = stringBytes.addingReportingOverflow(charge)
            guard !overflow, sum <= limits.maximumReplyStringBytes else { throw AnalysisFramedReply.limitError("string byte") }
            stringBytes = sum
        }

        mutating func scalar() { add(values: 1) }
        mutating func container() { add(values: 1) }

        mutating func finish() throws {
            guard values <= limits.maximumReplyValues else {
                throw AnalysisFramedReply.limitError(
                    "aggregate model value", detail: "values=\(values), limit=\(limits.maximumReplyValues)")
            }
        }

        /// The legacy lexical scan, applied to JSON text embedded in the frame, starting at the
        /// virtual depth of its enclosing frame containers.
        mutating func scan(_ bytes: UnsafeRawBufferPointer, baseDepth: Int) throws {
            var depth = baseDepth
            var current = 0
            var inString = false
            var escaped = false
            var inScalar = false
            for byte in bytes {
                guard byte != 0 else { throw AnalysisFramedReply.malformed("embedded JSON must be UTF-8") }
                if inString {
                    if byte == 0x22 && !escaped {
                        inString = false
                        continue
                    }
                    guard current < limits.maximumReplySingleStringBytes,
                          stringBytes < limits.maximumReplyStringBytes else {
                        throw AnalysisFramedReply.limitError("string byte")
                    }
                    current += 1
                    stringBytes += 1
                    if escaped { escaped = false } else { escaped = byte == 0x5c }
                    continue
                }
                switch byte {
                case 0x22:
                    inString = true
                    escaped = false
                    current = 0
                    inScalar = false
                case 0x7b, 0x5b:
                    guard depth < limits.maximumNestingDepth else { throw AnalysisFramedReply.limitError("nesting depth") }
                    depth += 1
                    inScalar = false
                case 0x7d, 0x5d:
                    depth = max(0, depth - 1)
                    inScalar = false
                    continue
                case 0x20, 0x09, 0x0a, 0x0d, 0x2c, 0x3a:
                    inScalar = false
                    continue
                default:
                    if inScalar { continue }
                    inScalar = true
                }
                add(values: 1)
            }
        }
    }

    // MARK: Reader

    fileprivate struct Reader {
        let bytes: UnsafeRawBufferPointer
        var position: Int
        let end: Int
        var remaining: Int { end - position }

        mutating func u8() throws -> UInt8 {
            guard remaining >= 1 else { throw AnalysisFramedReply.malformed("truncated field") }
            defer { position += 1 }
            return bytes[position]
        }

        mutating func u32() throws -> UInt32 {
            guard remaining >= 4 else { throw AnalysisFramedReply.malformed("truncated field") }
            var value: UInt32 = 0
            for index in 0..<4 { value |= UInt32(bytes[position + index]) << UInt32(8 * index) }
            position += 4
            return value
        }

        mutating func u64() throws -> UInt64 {
            guard remaining >= 8 else { throw AnalysisFramedReply.malformed("truncated field") }
            var value: UInt64 = 0
            for index in 0..<8 { value |= UInt64(bytes[position + index]) << UInt64(8 * index) }
            position += 8
            return value
        }

        mutating func take(_ count: Int) throws -> UnsafeRawBufferPointer {
            guard count >= 0, count <= remaining else { throw AnalysisFramedReply.malformed("length exceeds the section") }
            let slice = UnsafeRawBufferPointer(rebasing: bytes[position ..< position + count])
            position += count
            return slice
        }

        mutating func uuid() throws -> UUID {
            let slice = try take(16)
            var value: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            withUnsafeMutableBytes(of: &value) { $0.copyMemory(from: slice) }
            return UUID(uuid: value)
        }

        mutating func flag() throws -> Bool {
            switch try u8() {
            case 0: return false
            case 1: return true
            default: throw AnalysisFramedReply.malformed("invalid Boolean byte")
            }
        }
    }

    // MARK: Decode

    /// Returns nil when `data` does not begin with the frame magic (it is the JSON form). Throws a
    /// budget or framing `DecodingError` (the provider maps these to a malformed reply), or
    /// `versionMismatch` for a valid header of another version.
    static func decode(_ data: Data, version expected: Int, limits: PayloadWireCodec.Limits) throws -> Decoded? {
        guard data.count >= magic.count, data.prefix(magic.count).elementsEqual(magic) else { return nil }
        guard data.count <= limits.maximumReplyBytes else { throw limitError("raw byte") }
        return try data.withUnsafeBytes { try admit(data, $0, expected, limits) }
    }

    private struct Probe: Decodable {
        let version: Int
        let hasPayload: Bool
        let hasFailure: Bool

        private enum Keys: String, CodingKey { case version, payload, failure }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: Keys.self)
            version = try container.decode(Int.self, forKey: .version)
            hasPayload = try Self.present(container, .payload)
            hasFailure = try Self.present(container, .failure)
        }

        private static func present(_ container: KeyedDecodingContainer<Keys>, _ key: Keys) throws -> Bool {
            try container.contains(key) && !container.decodeNil(forKey: key)
        }
    }

    private static func admit(
        _ data: Data, _ raw: UnsafeRawBufferPointer, _ expected: Int, _ limits: PayloadWireCodec.Limits
    ) throws -> Decoded {
        var reader = Reader(bytes: raw, position: magic.count, end: raw.count)
        guard reader.remaining >= headerByteCount - magic.count else { throw malformed("truncated header") }
        let got = try reader.u32()
        guard let outcome = Outcome(rawValue: try reader.u8()) else { throw malformed("unknown outcome") }
        let count = try reader.u32()
        guard count == (outcome == .success ? 8 : 1) else { throw malformed("unexpected section count") }
        guard Int(got) == expected else { throw AnalysisWorkerError.versionMismatch(expected: expected, got: Int(got)) }

        let order: [Section] = outcome == .success ? Section.allCases : [.residual]
        var entries: [Entry] = []
        for section in order {
            guard reader.remaining >= sectionHeaderByteCount else { throw malformed("truncated section header") }
            let tag = try reader.u32()
            guard tag == section.rawValue else {
                throw malformed(Section(rawValue: tag) == nil ? "unknown section tag" : "repeated or out-of-order section")
            }
            let length = try reader.u64()
            let rows = try reader.u64()
            guard length <= UInt64(reader.remaining) else { throw malformed("section length exceeds the reply") }
            if section == .residual {
                guard rows == 1, length > 0 else { throw malformed("residual section must hold one non-empty value") }
            } else if length == 0 {
                guard rows == 0 else { throw malformed("empty section declares rows") }
            } else {
                guard rows > 0, rows <= length / section.minimumRowBytes else { throw malformed("row count exceeds the section") }
            }
            entries.append(Entry(section: section, offset: reader.position, length: Int(length), rows: Int(rows)))
            reader.position += Int(length)
        }
        guard reader.remaining == 0 else { throw malformed("trailing bytes") }

        var ledger = Ledger(limits: limits)
        if entries.contains(where: { $0.section != .residual && $0.rows > 0 }) {
            // Rows sit inside the virtual envelope, payload and array containers (depth 3).
            guard 3 < limits.maximumNestingDepth else { throw limitError("nesting depth") }
        }
        _ = try parseAll(entries, raw, &ledger, build: false)
        guard let residual = entries.last else { throw malformed("missing residual section") }
        let json = Data(UnsafeRawBufferPointer(rebasing: raw[residual.offset ..< residual.offset + residual.length]))
        try json.withUnsafeBytes { try ledger.scan($0, baseDepth: 0) }
        try ledger.finish()

        let probe = try JSONDecoder().decode(Probe.self, from: json)
        guard probe.version == Int(got) else { throw malformed("residual version disagrees with the header") }
        switch outcome {
        case .success: guard probe.hasPayload, !probe.hasFailure else { throw malformed("ambiguous success reply") }
        case .failure: guard probe.hasFailure, !probe.hasPayload else { throw malformed("ambiguous failure reply") }
        }
        return Decoded(envelopeJSON: json, data: data, outcome: outcome, entries: entries, limits: limits)
    }

    fileprivate static func parseAll(
        _ entries: [Entry], _ raw: UnsafeRawBufferPointer, _ ledger: inout Ledger, build: Bool
    ) throws -> RowSets {
        var sets = RowSets()
        for entry in entries {
            switch entry.section {
            case .instructions: sets.instructions = try scanRows(entry, raw, &ledger, build, instruction)
            case .xrefs: sets.xrefs = try scanRows(entry, raw, &ledger, build, xref)
            case .controlFlowEdges: sets.controlFlowEdges = try scanRows(entry, raw, &ledger, build, edge)
            case .basicBlocks: sets.basicBlocks = try scanRows(entry, raw, &ledger, build, block)
            case .stringLiterals: sets.stringLiterals = try scanRows(entry, raw, &ledger, build, stringLiteral)
            case .symbols: sets.symbols = try scanRows(entry, raw, &ledger, build, symbol)
            case .functions: sets.functions = try scanRows(entry, raw, &ledger, build, function)
            case .residual: break
            }
        }
        return sets
    }

    private static func scanRows<T>(
        _ entry: Entry, _ raw: UnsafeRawBufferPointer, _ ledger: inout Ledger, _ build: Bool,
        _ row: (inout Reader, inout Ledger, Bool) throws -> T?
    ) throws -> [T] {
        var reader = Reader(bytes: raw, position: entry.offset, end: entry.offset + entry.length)
        var rows: [T] = []
        if build { rows.reserveCapacity(entry.rows) }
        for _ in 0..<entry.rows {
            if let value = try row(&reader, &ledger, build) { rows.append(value) }
        }
        guard reader.remaining == 0 else { throw malformed("section has trailing bytes") }
        return rows
    }

    // MARK: Row readers (each charges the same ledger as the equivalent legacy JSON object)

    private static func canonicalCharge(_ buffer: UnsafeRawBufferPointer) throws -> Int {
        var index = 0
        var charge = 0
        let count = buffer.count
        while index < count {
            let byte = buffer[index]
            if byte < 0x80 {
                charge += (byte == 0x22 || byte == 0x5c || byte == 0x2f) ? 2 : (byte < 0x20 ? 6 : 1)
                index += 1
                continue
            }
            var width = 0
            var lower: UInt8 = 0x80
            var upper: UInt8 = 0xbf
            switch byte {
            case 0xc2 ... 0xdf: width = 2
            case 0xe0: width = 3; lower = 0xa0
            case 0xe1 ... 0xec, 0xee ... 0xef: width = 3
            case 0xed: width = 3; upper = 0x9f
            case 0xf0: width = 4; lower = 0x90
            case 0xf1 ... 0xf3: width = 4
            case 0xf4: width = 4; upper = 0x8f
            default: throw malformed("invalid UTF-8")
            }
            guard index + width <= count else { throw malformed("invalid UTF-8") }
            let second = buffer[index + 1]
            guard second >= lower, second <= upper else { throw malformed("invalid UTF-8") }
            for offset in 2..<max(width, 2) where buffer[index + offset] & 0xc0 != 0x80 {
                throw malformed("invalid UTF-8")
            }
            charge += width
            index += width
        }
        return charge
    }

    private static func text(
        _ reader: inout Reader, _ length: UInt32, _ ledger: inout Ledger, _ build: Bool
    ) throws -> String {
        let slice = try reader.take(Int(length))
        try ledger.string(try canonicalCharge(slice))
        return build ? String(decoding: slice, as: UTF8.self) : ""
    }

    private static func optionalText(
        _ reader: inout Reader, _ length: UInt32, _ ledger: inout Ledger, _ build: Bool
    ) throws -> String? {
        length == absentLength ? nil : try text(&reader, length, &ledger, build)
    }

    private static func embeddedJSON(
        _ reader: inout Reader, _ length: UInt32, _ ledger: inout Ledger, _ build: Bool
    ) throws -> Data {
        let slice = try reader.take(Int(length))
        try ledger.scan(slice, baseDepth: 4)
        return build ? Data(slice) : Data()
    }

    private static func key(_ ledger: inout Ledger, _ length: Int) throws { try ledger.string(length) }

    private static func instruction(_ r: inout Reader, _ l: inout Ledger, _ build: Bool) throws -> InstructionRow? {
        let address = try r.u64()
        let breakpoint = try r.flag()
        let bytesLength = try r.u32(), mnemonicLength = try r.u32(), operandsLength = try r.u32()
        let commentLength = try r.u32(), operandJSONLength = try r.u32()
        l.container()
        try key(&l, 7); l.scalar()
        try key(&l, 5); let bytes = try text(&r, bytesLength, &l, build)
        try key(&l, 8); let mnemonic = try text(&r, mnemonicLength, &l, build)
        try key(&l, 8); let operands = try text(&r, operandsLength, &l, build)
        try key(&l, 13); l.scalar()
        var comment: String?
        if commentLength != absentLength { try key(&l, 7); comment = try text(&r, commentLength, &l, build) }
        var structured: InstructionOperands?
        if operandJSONLength != absentLength {
            try key(&l, 18)
            let json = try embeddedJSON(&r, operandJSONLength, &l, build)
            if build { structured = try JSONDecoder().decode(InstructionOperands.self, from: json) }
        }
        guard build else { return nil }
        return InstructionRow(address: address, bytes: bytes, mnemonic: mnemonic, operands: operands,
                              hasBreakpoint: breakpoint, comment: comment, structuredOperands: structured)
    }

    private static func xref(_ r: inout Reader, _ l: inout Ledger, _ build: Bool) throws -> XRef? {
        let id = try r.uuid(), from = try r.u64(), to = try r.u64(), kindLength = try r.u32()
        l.container()
        try key(&l, 2); try l.string(36)
        try key(&l, 4); l.scalar()
        try key(&l, 2); l.scalar()
        try key(&l, 4); let kind = try text(&r, kindLength, &l, build)
        return build ? XRef(id: id, from: from, to: to, kind: kind) : nil
    }

    private static func edge(_ r: inout Reader, _ l: inout Ledger, _ build: Bool) throws -> ControlFlowEdge? {
        let id = try r.uuid(), from = try r.u64(), to = try r.u64(), kindLength = try r.u32()
        l.container()
        try key(&l, 2); try l.string(36)
        try key(&l, 4); l.scalar()
        try key(&l, 2); l.scalar()
        try key(&l, 4); let kind = try text(&r, kindLength, &l, build)
        return build ? ControlFlowEdge(id: id, from: from, to: to, kind: kind) : nil
    }

    private static func block(_ r: inout Reader, _ l: inout Ledger, _ build: Bool) throws -> BasicBlockSummary? {
        let id = try r.uuid(), functionID = try r.uuid()
        let start = try r.u64(), end = try r.u64()
        guard let count = Int(exactly: Int64(bitPattern: try r.u64())) else { throw malformed("count out of range") }
        l.container()
        try key(&l, 2); try l.string(36)
        try key(&l, 10); try l.string(36)
        try key(&l, 12); l.scalar()
        try key(&l, 10); l.scalar()
        try key(&l, 16); l.scalar()
        return build ? BasicBlockSummary(id: id, functionID: functionID, startAddress: start, endAddress: end,
                                         instructionCount: count) : nil
    }

    private static func stringLiteral(_ r: inout Reader, _ l: inout Ledger, _ build: Bool) throws -> StringLiteralSummary? {
        let id = try r.uuid(), address = try r.u64()
        guard let byteLength = Int(exactly: Int64(bitPattern: try r.u64())) else { throw malformed("count out of range") }
        let valueLength = try r.u32(), sectionLength = try r.u32()
        l.container()
        try key(&l, 2); try l.string(36)
        try key(&l, 5); let value = try text(&r, valueLength, &l, build)
        try key(&l, 7); l.scalar()
        try key(&l, 13); let section = try text(&r, sectionLength, &l, build)
        try key(&l, 10); l.scalar()
        return build ? StringLiteralSummary(id: id, value: value, address: address, sourceSection: section,
                                            byteLength: byteLength) : nil
    }

    private static func symbol(_ r: inout Reader, _ l: inout Ledger, _ build: Bool) throws -> SymbolSummary? {
        let id = try r.uuid()
        let nameLength = try r.u32(), kindLength = try r.u32(), libraryLength = try r.u32(), rawLength = try r.u32()
        let hasAddress = try r.flag()
        let address = hasAddress ? try r.u64() : nil
        l.container()
        try key(&l, 2); try l.string(36)
        try key(&l, 4); let name = try text(&r, nameLength, &l, build)
        try key(&l, 4); let kind = try text(&r, kindLength, &l, build)
        if hasAddress { try key(&l, 7); l.scalar() }
        var library: String?
        if libraryLength != absentLength { try key(&l, 11); library = try text(&r, libraryLength, &l, build) }
        var raw: String?
        if rawLength != absentLength { try key(&l, 14); raw = try text(&r, rawLength, &l, build) }
        return build ? SymbolSummary(id: id, name: name, address: address, kind: kind, libraryName: library,
                                     rawLinkageName: raw) : nil
    }

    private static func function(_ r: inout Reader, _ l: inout Ledger, _ build: Bool) throws -> FunctionSummary? {
        let id = try r.uuid()
        let nameLength = try r.u32()
        let start = try r.u64(), end = try r.u64()
        let confidence = Double(bitPattern: try r.u64())
        guard confidence.isFinite else { throw malformed("non-finite confidence") }
        let provenanceLength = try r.u32()
        l.container()
        try key(&l, 2); try l.string(36)
        try key(&l, 4); let name = try text(&r, nameLength, &l, build)
        try key(&l, 12); l.scalar()
        try key(&l, 10); l.scalar()
        try key(&l, 10); l.scalar()
        var provenance: AnalysisNoReturnProvenance?
        if provenanceLength != absentLength {
            try key(&l, 18)
            let json = try embeddedJSON(&r, provenanceLength, &l, build)
            if build { provenance = try JSONDecoder().decode(AnalysisNoReturnProvenance.self, from: json) }
        }
        return build ? FunctionSummary(id: id, name: name, startAddress: start, endAddress: end,
                                       confidence: confidence, noReturnProvenance: provenance) : nil
    }

    // MARK: Encode (bounded writer)

    private struct Residual: Encodable {
        var version: Int
        var payload: AnalysisResultPayload
        var imageBytesInPinnedSource: AnalysisPinnedImageByteRange?
    }

    fileprivate struct Writer {
        var data = Data()
        let cap: Int

        mutating func need(_ count: Int) throws {
            guard count <= cap - data.count else { throw Refusal(message: AnalysisFramedReply.refusalMessage) }
        }

        mutating func u8(_ value: UInt8) throws { try need(1); data.append(value) }

        mutating func u32(_ value: UInt32) throws {
            try need(4)
            for index in 0..<4 { data.append(UInt8(truncatingIfNeeded: value >> UInt32(8 * index))) }
        }

        mutating func u64(_ value: UInt64) throws {
            try need(8)
            for index in 0..<8 { data.append(UInt8(truncatingIfNeeded: value >> UInt64(8 * index))) }
        }

        mutating func uuid(_ value: UUID) throws {
            try need(16)
            withUnsafeBytes(of: value.uuid) { data.append(contentsOf: $0) }
        }

        mutating func text(_ value: String) throws {
            try need(value.utf8.count)
            data.append(contentsOf: value.utf8)
        }

        mutating func blob(_ value: Data) throws {
            try need(value.count)
            data.append(value)
        }

        /// Length prefix of a string field: the sentinel is reserved for absent optionals.
        func length(_ count: Int) throws -> UInt32 {
            guard let length = UInt32(exactly: count), length != AnalysisFramedReply.absentLength else {
                throw Refusal(message: "Analysis reply contains a field too long for its frame.")
            }
            return length
        }

        mutating func patch(at offset: Int, _ value: UInt64) {
            for index in 0..<8 { data[offset + index] = UInt8(truncatingIfNeeded: value >> UInt64(8 * index)) }
        }
    }

    /// The bounded writer never grows past `limits.maximumReplyBytes`. A refusal is returned as a
    /// legacy-JSON `unexpected` failure reply; nothing partial escapes.
    static func encode(
        _ payload: AnalysisResultPayload,
        range: AnalysisPinnedImageByteRange?,
        version: Int,
        limits: PayloadWireCodec.Limits
    ) -> Data {
        let message: String
        do {
            return try frame(payload, range, version, limits)
        } catch let refusal as Refusal {
            message = refusal.message
        } catch {
            message = "Analysis reply encoding failed."
        }
        let envelope = RefusalEnvelope(version: version, failure: .init(unexpected: .init(_0: message)))
        return (try? JSONEncoder().encode(envelope)) ?? Data()
    }

    private static func frame(
        _ payload: AnalysisResultPayload, _ range: AnalysisPinnedImageByteRange?, _ version: Int,
        _ limits: PayloadWireCodec.Limits
    ) throws -> Data {
        guard let wireVersion = UInt32(exactly: version) else { throw Refusal(message: "Analysis reply version is invalid.") }
        var residualPayload = payload
        residualPayload.instructions = []
        residualPayload.xrefs = []
        residualPayload.controlFlowEdges = []
        residualPayload.basicBlocks = []
        residualPayload.stringLiterals = []
        residualPayload.symbols = []
        residualPayload.functions = []
        let residual = try JSONEncoder().encode(
            Residual(version: version, payload: residualPayload, imageBytesInPinnedSource: range))
        var writer = Writer(cap: limits.maximumReplyBytes)
        let floor = 177 + residual.count + payload.instructions.count * 29 + payload.xrefs.count * 36
            + payload.controlFlowEdges.count * 36 + payload.basicBlocks.count * 56
            + payload.stringLiterals.count * 40 + payload.symbols.count * 33 + payload.functions.count * 48
        writer.data.reserveCapacity(min(floor, limits.maximumReplyBytes))
        try writer.blob(Data(magic))
        try writer.u32(wireVersion)
        try writer.u8(Outcome.success.rawValue)
        try writer.u32(UInt32(Section.allCases.count))

        try section(&writer, .instructions, payload.instructions.count) { w in
            for row in payload.instructions {
                try w.u64(row.address)
                try w.u8(row.hasBreakpoint ? 1 : 0)
                let structured = try row.structuredOperands.map { try JSONEncoder().encode($0) }
                try w.u32(try w.length(row.bytes.utf8.count))
                try w.u32(try w.length(row.mnemonic.utf8.count))
                try w.u32(try w.length(row.operands.utf8.count))
                try w.u32(try row.comment.map { try w.length($0.utf8.count) } ?? absentLength)
                try w.u32(try structured.map { try w.length($0.count) } ?? absentLength)
                try w.text(row.bytes); try w.text(row.mnemonic); try w.text(row.operands)
                if let comment = row.comment { try w.text(comment) }
                if let structured { try w.blob(structured) }
            }
        }
        try section(&writer, .xrefs, payload.xrefs.count) { w in
            for row in payload.xrefs {
                try w.uuid(row.id); try w.u64(row.from); try w.u64(row.to)
                try w.u32(try w.length(row.kind.utf8.count)); try w.text(row.kind)
            }
        }
        try section(&writer, .controlFlowEdges, payload.controlFlowEdges.count) { w in
            for row in payload.controlFlowEdges {
                try w.uuid(row.id); try w.u64(row.from); try w.u64(row.to)
                try w.u32(try w.length(row.kind.utf8.count)); try w.text(row.kind)
            }
        }
        try section(&writer, .basicBlocks, payload.basicBlocks.count) { w in
            for row in payload.basicBlocks {
                try w.uuid(row.id); try w.uuid(row.functionID)
                try w.u64(row.startAddress); try w.u64(row.endAddress)
                try w.u64(UInt64(bitPattern: Int64(row.instructionCount)))
            }
        }
        try section(&writer, .stringLiterals, payload.stringLiterals.count) { w in
            for row in payload.stringLiterals {
                try w.uuid(row.id); try w.u64(row.address)
                try w.u64(UInt64(bitPattern: Int64(row.byteLength)))
                try w.u32(try w.length(row.value.utf8.count))
                try w.u32(try w.length(row.sourceSection.utf8.count))
                try w.text(row.value); try w.text(row.sourceSection)
            }
        }
        try section(&writer, .symbols, payload.symbols.count) { w in
            for row in payload.symbols {
                try w.uuid(row.id)
                try w.u32(try w.length(row.name.utf8.count))
                try w.u32(try w.length(row.kind.utf8.count))
                try w.u32(try row.libraryName.map { try w.length($0.utf8.count) } ?? absentLength)
                try w.u32(try row.rawLinkageName.map { try w.length($0.utf8.count) } ?? absentLength)
                try w.u8(row.address == nil ? 0 : 1)
                if let address = row.address { try w.u64(address) }
                try w.text(row.name); try w.text(row.kind)
                if let library = row.libraryName { try w.text(library) }
                if let rawName = row.rawLinkageName { try w.text(rawName) }
            }
        }
        try section(&writer, .functions, payload.functions.count) { w in
            for row in payload.functions {
                guard row.confidence.isFinite else {
                    throw Refusal(message: "Analysis reply contains a non-finite function confidence.")
                }
                let provenance = try row.noReturnProvenance.map { try JSONEncoder().encode($0) }
                try w.uuid(row.id)
                try w.u32(try w.length(row.name.utf8.count))
                try w.u64(row.startAddress); try w.u64(row.endAddress)
                try w.u64(row.confidence.bitPattern)
                try w.u32(try provenance.map { try w.length($0.count) } ?? absentLength)
                try w.text(row.name)
                if let provenance { try w.blob(provenance) }
            }
        }
        try section(&writer, .residual, 1) { try $0.blob(residual) }
        return writer.data
    }

    private static func section(
        _ writer: inout Writer, _ tag: Section, _ rows: Int, _ body: (inout Writer) throws -> Void
    ) throws {
        try writer.u32(tag.rawValue)
        let lengthOffset = writer.data.count
        try writer.u64(0)
        try writer.u64(UInt64(rows))
        let start = writer.data.count
        try body(&writer)
        writer.patch(at: lengthOffset, UInt64(writer.data.count - start))
    }
}
