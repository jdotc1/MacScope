import Foundation
import XCTest
@testable import MacScope

// Authored, unrun. 1284-UUID: fresh document IDs normalize; input/stable IDs do not.
// Traversal: declaration order for structs; array order; sorted canonical dictionary
// keys and set elements. Document ordinals follow first value appearance, references included.
struct AnalysisSnapshotCanonicalizer {
    enum Failure: Error, Equatable {
        case undeclaredUUID(String)
        case unsupported(String)
        case conflictingIdentity(String)
        case unknownField(String)
        case fingerprintMismatch(String)
    }
    private var identities: [UUID: String] = [:]
    private var normalizedFingerprints: [UUID: AnalysisInputFingerprint] = [:]
    private var goldenValues: [String: String] = [:]
    mutating func declareFresh(_ ids: [UUID], kind: String) throws {
        var next = identities.values.filter { $0.hasPrefix("fresh:\(kind):") }.count
        for id in ids {
            if let existing = identities[id] {
                guard existing.hasPrefix("fresh:\(kind):") else {
                    throw Failure.conflictingIdentity(kind)
                }
                continue
            }
            identities[id] = "fresh:\(kind):\(next)"
            next += 1
        }
    }
    mutating func declareStable(_ ids: [UUID]) throws {
        for id in ids {
            let token = "stable:\(id.uuidString)"
            if let existing = identities[id], existing != token {
                throw Failure.conflictingIdentity(token)
            }
            identities[id] = token
        }
    }
    init() {}
    init(snapshot: WorkspaceSnapshot, inputUUIDs: Set<UUID> = []) throws {
        try declareStable(Array(inputUUIDs))
        for binary in snapshot.binaries {
            guard let analysis = snapshot.analysisBySlot[binary.slot] else { continue }
            try declareStable(analysis.functions.map(\.id))
            try declareStable(analysis.symbols.map(\.id))
        }
        try declareDocument(snapshot)
        for binary in snapshot.binaries {
            guard let analysis = snapshot.analysisBySlot[binary.slot],
                  let stored = analysis.analysisInputFingerprint else { continue }
            let rebuilt = try AnalysisFingerprintBuilder.fingerprint(binary: binary, analysis: analysis)
            guard try canonical(stored) == canonical(rebuilt) else {
                throw Failure.fingerprintMismatch("analysisBySlot.analysisInputFingerprint")
            }
            guard let token = identities[binary.id], token.hasPrefix("fresh:document:") else { continue }
            let ordinal = try XCTUnwrap(Int(token.split(separator: ":").last!))
            let pinnedID = UUID(uuidString: String(format: "00000000-0000-4000-8000-%012llx", UInt64(ordinal + 1)))!
            guard identities[pinnedID] == nil else { throw Failure.conflictingIdentity("pinned binary ID") }
            identities[pinnedID] = token
            let pinned = BinaryImage(id: pinnedID, name: binary.name, path: binary.path,
                kind: binary.kind, architecture: binary.architecture,
                originalPathBookmark: binary.originalPathBookmark, metadata: binary.metadata,
                selectedSliceIndex: binary.selectedSliceIndex, machOSelectedSliceFact: binary.machOSelectedSliceFact,
                elfArchiveMemberIdentity: binary.elfArchiveMemberIdentity, artifactIdentity: binary.artifactIdentity,
                preferredSegmentLayout: binary.preferredSegmentLayout, artifactIntegrityState: binary.artifactIntegrityState,
                containerAdmissionWitness: binary.containerAdmissionWitness, resolvedExecutablePath: binary.resolvedExecutablePath,
                slot: binary.slot)
            normalizedFingerprints[binary.id] = try AnalysisFingerprintBuilder.fingerprint(binary: pinned, analysis: analysis)
        }
    }
    static let goldenName = "ready-golden-input"
    static let goldenPath = "/__macscope_ready_goldens__/input"

    static func goldenBinary(_ binary: BinaryImage, id: UUID) -> BinaryImage {
        BinaryImage(id: id, name: goldenName, path: goldenPath,
            kind: binary.kind, architecture: binary.architecture,
            originalPathBookmark: binary.originalPathBookmark, metadata: binary.metadata,
            selectedSliceIndex: binary.selectedSliceIndex, machOSelectedSliceFact: binary.machOSelectedSliceFact,
            elfArchiveMemberIdentity: binary.elfArchiveMemberIdentity, artifactIdentity: binary.artifactIdentity,
            preferredSegmentLayout: binary.preferredSegmentLayout, artifactIntegrityState: binary.artifactIntegrityState,
            containerAdmissionWitness: binary.containerAdmissionWitness,
            resolvedExecutablePath: goldenPath, slot: binary.slot)
    }

    static func canonicalGoldenSnapshot(_ snapshot: WorkspaceSnapshot,
        sourceURL: URL?, inputUUIDs: Set<UUID> = []) throws -> String {
        var comparator = try AnalysisSnapshotCanonicalizer(snapshot: snapshot, inputUUIDs: inputUUIDs)
        let raw = try comparator.canonical(snapshot)
        guard let sourceURL else { return raw }
        guard snapshot.binaries.count == 1 else {
            throw Failure.unsupported("golden disk fixture must contain exactly one binary")
        }
        let binary = snapshot.binaries[0]
        let canonicalSourcePath = URL(fileURLWithPath: sourceURL.path).resolvingSymlinksInPath().path
        guard sourceURL.isFileURL,
              binary.name == sourceURL.lastPathComponent,
              binary.path == sourceURL.path,
              let resolvedPath = binary.resolvedExecutablePath,
              resolvedPath == sourceURL.path,
              URL(fileURLWithPath: resolvedPath).resolvingSymlinksInPath().path == canonicalSourcePath,
              binary.originalPathBookmark == nil,
              let witness = binary.containerAdmissionWitness,
              let stamp = witness.sourceFileStamp,
              let captured = NativeExecutionFileStamp.capture(path: sourceURL.path),
              stamp.canonicalPath == canonicalSourcePath,
              stamp == captured,
              stamp.byteCount == witness.containerByteCount,
              let analysis = snapshot.analysisBySlot[binary.slot],
              analysis.analysisInputFingerprint != nil,
              let pinnedID = comparator.normalizedFingerprints[binary.id]?.binaryID else {
            throw Failure.unsupported("golden source binding: $root.binaries.0")
        }
        let root = "$root.binaries.0"
        let stampRoot = root + ".containerAdmissionWitness.some.sourceFileStamp.some"
        var values: [String: String] = [:]
        values[root + ".name"] = try comparator.canonical(goldenName)
        values[root + ".path"] = try comparator.canonical(goldenPath)
        values[root + ".resolvedExecutablePath"] = try comparator.canonical(goldenPath)
        values[stampRoot + ".canonicalPath"] = try comparator.canonical(goldenPath)
        values[stampRoot + ".device"] = try comparator.canonical(UInt64(0))
        values[stampRoot + ".inode"] = try comparator.canonical(UInt64(0))
        values[stampRoot + ".byteCount"] = try comparator.canonical(UInt64(0))
        values[stampRoot + ".modifiedSeconds"] = try comparator.canonical(Int64(0))
        values[stampRoot + ".modifiedNanoseconds"] = try comparator.canonical(Int64(0))
        values[stampRoot + ".changedSeconds"] = try comparator.canonical(Int64(0))
        values[stampRoot + ".changedNanoseconds"] = try comparator.canonical(Int64(0))
        let pinned = goldenBinary(binary, id: pinnedID)
        let fingerprint = try AnalysisFingerprintBuilder.fingerprint(binary: pinned, analysis: analysis)
        let analysisRoot = "$root.analysisBySlot[" + (try comparator.canonical(binary.slot)) + "]"
        values[analysisRoot + ".analysisInputFingerprint"] = try comparator.canonical(fingerprint)
        comparator.goldenValues = values
        return try comparator.canonical(snapshot)
    }

    static func canonicalSnapshot(_ snapshot: WorkspaceSnapshot, inputUUIDs: Set<UUID> = []) throws -> String {
        try AnalysisSnapshotCanonicalizer(snapshot: snapshot, inputUUIDs: inputUUIDs).canonical(snapshot)
    }
    static func canonicalDocument(_ value: Any, inputUUIDs: Set<UUID> = []) throws -> String {
        var comparator = AnalysisSnapshotCanonicalizer()
        try comparator.declareStable(Array(inputUUIDs))
        try comparator.declareDocument(value)
        return try comparator.canonical(value)
    }
    static func canonicalImage(_ analysis: ImageAnalysis, inputUUIDs: Set<UUID>) throws -> String {
        var comparator = AnalysisSnapshotCanonicalizer()
        try comparator.declareStable(Array(inputUUIDs))
        try comparator.declareStable(analysis.functions.map(\.id))
        try comparator.declareStable(analysis.symbols.map(\.id))
        try comparator.declareDocument(analysis)
        return try comparator.canonical(analysis)
    }
    static func inputUUIDs(in value: Any) throws -> Set<UUID> {
        var result = Set<UUID>()
        try walk(value, path: "$input", ordered: false) { child, _ in
            if let id = child as? UUID { result.insert(id) }
        }
        return result
    }
    private mutating func declareDocument(_ value: Any) throws {
        var fresh = Set<UUID>()
        try Self.walk(value, path: "$root", ordered: false) { node, path in
            let type = String(describing: Swift.type(of: node))
            let freshFields = Self.freshFields[type] ?? []
            for child in Mirror(reflecting: node).children where freshFields.contains(child.label ?? "") {
                guard let id = child.value as? UUID else { throw Failure.unsupported(path) }
                fresh.insert(id)
            }
        }
        var ordered: [UUID] = []
        var seen = Set<UUID>()
        try Self.walk(value, path: "$root", literalIDs: Set(identities.keys)) { child, path in
            guard let id = child as? UUID else { return }
            if identities[id] != nil { return }
            guard fresh.contains(id) else { throw Failure.undeclaredUUID(path) }
            if seen.insert(id).inserted { ordered.append(id) }
        }
        try declareFresh(ordered, kind: "document")
    }
    // Confirmed mint fields, not a rule that all properties named id are fresh.
    // Engine:568,794,813,816,857,2331,2359; loader:124,136,153,165,730.
    private static let freshFields: [String: Set<String>] = [
        "WorkspaceSnapshot": ["indirectCallSnapshotID", "stringDiscoveryKey"],
        "BinaryImage": ["id"], "XRef": ["id"], "SectionSummary": ["id"],
        "CodeDataRangeSummary": ["id"], "BasicBlockSummary": ["id"], "ControlFlowEdge": ["id"],
        "ImportSummary": ["id"], "IndirectSymbolSummary": ["id"], "ExportSummary": ["id"],
        "StringLiteralSummary": ["id"], "RelocationSummary": ["id"],
        // Supplement catalog pristine factories mint these fields only (:717 and :329).
        "DebuggerLogicalBreakpointCatalog": ["catalogID"], "DebuggerLaunchProfileCatalog": ["catalogID"]
    ]
    // Whole snapshot file:10-51,197-250. Private headerLayoutEvidence IS semantic.
    private static let snapshotFields: Set<String> = [
        "indirectCallSnapshotID", "indirectCallMemo", "indirectSelectorMemo", "slotPrototypeMemo",
        "stringDiscoveryKey", "headerLayoutEvidence", "binaries", "analysisBySlot", "codeExclusionMemo",
        "crossImageXrefs", "addressOverrides", "importedPrototypes", "typeDefinitions", "manualXRefs",
        "manualXRefEndpointMemo", "bookmarks", "segmentOverrides", "logicalBreakpointCatalog",
        "launchProfileCatalog", "savedWatchCatalog", "sourceLinkState"
    ]
    private static let binaryFields: Set<String> = [
        "id", "name", "path", "kind", "architecture", "originalPathBookmark", "metadata",
        "selectedSliceIndex", "machOSelectedSliceFact", "elfArchiveMemberIdentity", "artifactIdentity",
        "preferredSegmentLayout", "artifactIntegrityState", "containerAdmissionWitness", "resolvedExecutablePath", "slot"
    ]
    private static let catalogFields: [String: Set<String>] = [
        "DebuggerLogicalBreakpointCatalog": ["catalogID", "revision", "specifications"],
        "DebuggerLaunchProfileCatalog": ["catalogID", "revision", "profiles", "selectedProfileID"]
    ]
    // AnalysisModels.swift whole1207-1301 (part3): all stored fields, including typeCatalog.
    private static let imageFields: Set<String> = [
        "nativeFunctionPrototypes", "functions", "symbols", "graphNames", "callOwnerAdjacencyMemo", "imports", "indirectSymbols",
        "exports", "stringLiterals", "stringLiteralCoverage", "basicBlocks", "instructions",
        "exportInstructionMemo", "instructionFingerprintMemo", "xrefEndpointMemo", "controlFlowFingerprintMemo",
        "xrefs", "controlFlowEdges", "hexBytes", "jumpTables", "objcSelectors", "constantStrings",
        "objcClasses", "objcCategories", "objcProtocols", "swiftTypes", "swiftConformances", "sections",
        "codeDataRanges", "relocations", "identityEffectiveByteRanges", "sourceLines", "imageBytes",
        "diagnostics", "machOMetadata", "analysisInputFingerprint", "objcClassReferences", "typeCatalog", "cfStringBackings"
    ]
    // Only these exact object fields are runtime caches/locks, never arbitrary classes.
    // Snapshot:11-13,45,234; ImageAnalysis:1212,1225-1228 (part3).
    private static let memoTypes: [String: [String: String]] = [
        "WorkspaceSnapshot": ["indirectCallMemo": "IndirectCallResolutionMemo",
            "indirectSelectorMemo": "IndirectSelectorMemo", "slotPrototypeMemo": "SlotPrototypeMemo",
            "codeExclusionMemo": "ExportCodeExclusionMemo", "manualXRefEndpointMemo": "ManualXRefEndpointMemo"],
        "ImageAnalysis": ["graphNames": "GraphNameMemo", "callOwnerAdjacencyMemo": "CallOwnerAdjacencyMemo", "exportInstructionMemo": "ExportInstructionMemo",
            "instructionFingerprintMemo": "AnalysisFacetDigestMemo", "xrefEndpointMemo": "XRefEndpointMemo",
            "controlFlowFingerprintMemo": "AnalysisFacetDigestMemo"]
    ]
    static func requireFieldSet(_ type: String, actual: Set<String>, path: String) throws {
        let expected = type == "WorkspaceSnapshot" ? snapshotFields : type == "ImageAnalysis" ? imageFields :
            type == "BinaryImage" ? binaryFields : catalogFields[type]
        if let expected {
            guard actual == expected else {
                throw Failure.unknownField(path + "." + actual.symmetricDifference(expected).sorted().joined(separator: ","))
            }
        }
    }

    private static func semanticChildren(_ value: Any, path: String) throws -> [Mirror.Child] {
        let type = String(describing: Swift.type(of: value))
        let children = Array(Mirror(reflecting: value).children)
        try requireFieldSet(type, actual: Set(children.compactMap(\.label)), path: path)
        return try children.filter { child in
            guard let name = child.label, let expectedType = memoTypes[type]?[name] else { return true }
            guard String(describing: Swift.type(of: child.value)) == expectedType else {
                throw Failure.unsupported(path + "." + name)
            }
            return false
        }
    }
    private static func walk(_ value: Any, path: String, ordered: Bool = true,
                             literalIDs: Set<UUID> = [], visit: (Any, String) throws -> Void) throws {
        try visit(value, path)
        if value is UUID || value is Data || value is String { return }
        let mirror = Mirror(reflecting: value)
        if mirror.displayStyle == .class { throw Failure.unsupported(path) }
        var children = try semanticChildren(value, path: path)
        var keyComparator = AnalysisSnapshotCanonicalizer()
        try keyComparator.declareStable(Array(literalIDs))
        if ordered && mirror.displayStyle == .dictionary {
            children = try children.map { child -> (String, Mirror.Child) in
                let pair = Array(Mirror(reflecting: child.value).children)
                guard pair.count == 2 else { throw Failure.unsupported(path) }
                return (try keyComparator.canonical(pair[0].value, path: path + ".key"), child)
            }.sorted { $0.0 < $1.0 }.map(\.1)
        }
        if ordered && mirror.displayStyle == .set {
            children = try children.map { (try keyComparator.canonical($0.value), $0) }
                .sorted { $0.0 < $1.0 }.map(\.1)
        }
        for (index, child) in children.enumerated() {
            try walk(child.value, path: path + "." + (child.label ?? String(index)),
                ordered: ordered, literalIDs: literalIDs, visit: visit)
        }
    }
    func canonical(_ value: Any, path: String = "$root") throws -> String {
        if let replacement = goldenValues[path] { return replacement }
        if let original = value as? AnalysisInputFingerprint, let pinned = normalizedFingerprints[original.binaryID] {
            return try canonical(pinned, path: path)
        }
        if let id = value as? UUID {
            guard let token = identities[id] else { throw Failure.undeclaredUUID(path) }
            return frame("UUID", token)
        }
        if let data = value as? Data { return frame("Data", data.base64EncodedString()) }
        if let text = value as? String { return frame("String", text) }
        if let number = value as? UInt64 { return frame("UInt64", String(number)) }
        if let number = value as? Int { return frame("Int", String(number)) }
        if let number = value as? UInt32 { return frame("UInt32", String(number)) }
        if let number = value as? Int32 { return frame("Int32", String(number)) }
        if let number = value as? UInt8 { return frame("UInt8", String(number)) }
        if let number = value as? UInt16 { return frame("UInt16", String(number)) }
        if let number = value as? Int64 { return frame("Int64", String(number)) }
        if let number = value as? Int16 { return frame("Int16", String(number)) }
        if let number = value as? Int8 { return frame("Int8", String(number)) }
        if let number = value as? UInt { return frame("UInt", String(number)) }
        if let number = value as? Float { return frame("FloatBits", String(number.bitPattern)) }
        if let number = value as? Double { return frame("DoubleBits", String(number.bitPattern)) }
        if let flag = value as? Bool { return frame("Bool", flag ? "true" : "false") }
        let mirror = Mirror(reflecting: value)
        let type = String(reflecting: Swift.type(of: value))
        if mirror.displayStyle == .class { throw Failure.unsupported(path + ":" + type) }
        if mirror.displayStyle == .dictionary {
            let entries = try mirror.children.map { child -> String in
                let pair = Array(Mirror(reflecting: child.value).children)
                guard pair.count == 2 else { throw Failure.unsupported(path) }
                let key = try canonical(pair[0].value, path: path + ".key")
                let val = try canonical(pair[1].value, path: path + "[" + key + "]")
                return frame(key, val)
            }
            return frame(type, entries.sorted().joined())
        }
        if mirror.displayStyle == .set {
            let values = try mirror.children.map { try canonical($0.value, path: path + ".element") }
            return frame(type, values.sorted().joined())
        }
        let children = try Self.semanticChildren(value, path: path).enumerated().map { index, child in
            try frame(child.label ?? String(index), canonical(child.value,
                path: path + "." + (child.label ?? String(index))))
        }
        if !children.isEmpty { return frame(type, children.joined()) }
        if mirror.displayStyle == .optional { return frame(type, "nil") }
        if mirror.displayStyle == .collection || mirror.displayStyle == .dictionary
            || mirror.displayStyle == .set { return frame(type, "") }
        // Only payload-free enums use their case spelling. Opaque values never fall back
        // to description, which could omit hidden fields or contain unstable addresses.
        if mirror.displayStyle == .enum { return frame(type, String(describing: value)) }
        if mirror.displayStyle == .struct { return frame(type, "") }
        throw Failure.unsupported(path + ":" + type)
    }
    private func frame(_ tag: String, _ body: String) -> String {
        "\(tag.utf8.count):\(tag)\(body.utf8.count):\(body)"
    }
}

enum ReadyFixture {
    static func instructions(count: Int) -> [DecodedInstruction] {
        (0..<count).map { index in
            DecodedInstruction(address: 0x1000 + UInt64(index * 4),
                bytes: [0xc0, 0x03, 0x5f, 0xd6], mnemonic: "ret", operands: "",
                branchTarget: nil, comment: nil, flow: .return)
        }
    }
    static func binary(instructions: [DecodedInstruction],
                       ranges: [BinaryCodeDataRange] = []) -> LoadedBinary {
        let end = instructions.map { $0.address + UInt64($0.bytes.count) }.max() ?? 0x1000
        let bytes = Data(repeating: 0, count: Int(end - 0x1000))
        let section = BinarySection(name: ".text", address: 0x1000,
            size: UInt64(bytes.count), fileOffset: 0, isExecutable: true)
        var result = LoadedBinary(name: "ready-fixture", path: "/tmp/ready-fixture",
            isBundle: false, cpuType: MachOConstants.cpuTypeARM64,
            fileTypeName: "fixture", architectureDisplayName: "arm64", metadata: .empty,
            bytes: bytes, sliceOffset: 0, sections: [section], executableTextSection: section,
            entryPointAddress: 0x1000, symbols: [], imports: [], indirectSymbols: [],
            exports: [], stringLiterals: [], functionStarts: [0x1000], objcSelectors: [:])
        result.codeDataRanges = ranges
        return result
    }
    struct Loader: BinaryLoader {
        let binary: LoadedBinary
        func load(at url: URL) throws -> LoadedBinary { binary }
    }
    struct Decoder: Disassembler {
        let rows: [DecodedInstruction]
        func decode(_ bytes: Data, baseAddress: UInt64, maxInstructionCount: Int) -> [DecodedInstruction] {
            Array(rows.filter { $0.address >= baseAddress && $0.address < baseAddress + UInt64(bytes.count) }
                .prefix(maxInstructionCount))
        }
    }
}
