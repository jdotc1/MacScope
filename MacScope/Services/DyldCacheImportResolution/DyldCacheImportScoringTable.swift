import Foundation

/// DC1 acceptance scoring: one row per import entry, with outcome counts that must sum to the
/// import total. Pure value logic over a finished `ImportResolutionBatch`; nothing here reads a
/// cache or a binary. Every `resolved` row states its address domain; nothing is normalized.
struct DyldCacheImportScoringTable: Codable, Equatable, Sendable {
    struct Row: Codable, Equatable, Sendable {
        var index: Int
        var symbol: String
        /// Exact install name of the importing image's dependency for this origin, when it has one.
        var originImage: String?
        /// Namespace decided from the ordinal encoding, for example `dependency(2)` or `flatLookup`.
        var namespace: String
        var originEncoding: String?
        var originRawOrdinal: Int?
        var originTableIndex: Int?
        var isWeakImport: Bool?
        var outcome: String
        var subreason: String?
        var detail: String?
        var resolvedImage: String?
        /// `0x`-prefixed hex of the cache unslid VM address; nil unless `resolved`.
        var resolvedAddress: String?
        var addressDomain: String?
        var resolvedImageLoadAddress: String?
        var terminalKind: String?
        /// `0x`-prefixed hex of the resolver function's cache unslid VM address for a stub-and-resolver
        /// row; `resolvedAddress` stays the exported stub. nil for every other row.
        var resolverAddress: String?
        var isFinalTarget: Bool?
        var candidates: [String]?
    }

    var importer: String
    var architecture: String
    var cacheUUID: String?
    var isPartial: Bool
    var importTotal: Int
    /// Counts per outcome name; the values sum to `importTotal`.
    var outcomeCounts: [String: Int]
    var rows: [Row]

    static let outcomeNames = ["resolved", "notExported", "reexportChain", "ambiguous", "cacheUnavailable", "notCacheResident"]

    var countsSumToTotal: Bool { outcomeCounts.values.reduce(0, +) == importTotal && rows.count == importTotal }

    static func build(
        importer: String, architecture: String,
        entries: [ImportResolutionEntry], batch: ImportResolutionBatch,
        dependencies: [MachOLoadMetadata.DependentDylib]
    ) -> DyldCacheImportScoringTable {
        var byOrdinal: [Int: String] = [:]
        for dylib in dependencies where byOrdinal[dylib.ordinal] == nil { byOrdinal[dylib.ordinal] = dylib.path }
        var counts = Dictionary(uniqueKeysWithValues: outcomeNames.map { ($0, 0) })
        var rows: [Row] = []
        for batchRow in batch.rows {
            let entry = entries.indices.contains(batchRow.entryIndex) ? entries[batchRow.entryIndex] : nil
            var row = Row(
                index: batchRow.entryIndex, symbol: batchRow.symbolName, originImage: nil,
                namespace: "noOrigin", originEncoding: nil, originRawOrdinal: nil, originTableIndex: nil,
                isWeakImport: nil, outcome: "", subreason: nil, detail: nil, resolvedImage: nil,
                resolvedAddress: nil, addressDomain: nil, resolvedImageLoadAddress: nil, terminalKind: nil,
                isFinalTarget: nil, candidates: nil)
            if let origin = batchRow.origin {
                let namespace = ImportNamespace.classify(origin)
                row.namespace = describe(namespace)
                row.originEncoding = origin.encoding.rawValue
                row.originRawOrdinal = origin.rawOrdinal
                row.originTableIndex = origin.tableIndex
                row.isWeakImport = origin.isWeak
                if case .dependency(let ordinal) = namespace { row.originImage = byOrdinal[ordinal] }
            }
            if let entry, case .request(let request) = entry.outcome { row.originImage = request.installName }
            fill(&row, outcome: batchRow.outcome)
            counts[row.outcome, default: 0] += 1
            rows.append(row)
        }
        return DyldCacheImportScoringTable(
            importer: importer, architecture: architecture,
            cacheUUID: batch.cacheUUID.map(hex), isPartial: batch.isPartial,
            importTotal: rows.count, outcomeCounts: counts, rows: rows)
    }

    private static func fill(_ row: inout Row, outcome: ImportResolutionOutcome) {
        switch outcome {
        case .resolved(let value):
            row.outcome = "resolved"
            row.resolvedImage = text(value.symbol.imagePath)
            row.resolvedAddress = hex(value.symbol.address)
            row.addressDomain = value.symbol.domain.rawValue
            row.resolvedImageLoadAddress = hex(value.symbol.imageLoadAddress)
            row.isFinalTarget = value.isFinalTarget
            switch value.symbol.terminalKind {
            case .regular: row.terminalKind = "regular"
            case .absolute: row.terminalKind = "absolute"
            case .threadLocal: row.terminalKind = "threadLocal"
            case .stubAndResolver(let resolver): row.terminalKind = "stubAndResolver(resolverOffset: \(hex(resolver)))"
            }
            row.resolverAddress = value.symbol.resolverAddress.map(hex)
            row.subreason = value.symbol.isWeakDefinition ? "weakDefinition" : nil
            row.detail = "viaPath=" + value.viaPath.map(text).joined(separator: " -> ")
                + " duplicates=\(value.duplicateTerminalCount) incompleteBranches=\(value.incompleteBranches)"
        case .notExported(let searched):
            row.outcome = "notExported"
            row.detail = "searched=" + searched.map(text).joined(separator: ", ")
        case .reexportChain(let failure, let viaPath):
            row.outcome = "reexportChain"
            row.subreason = failure.rawValue
            row.detail = "viaPath=" + viaPath.map(text).joined(separator: " -> ")
        case .ambiguous(let candidates, let more):
            row.outcome = "ambiguous"
            row.subreason = more ? "moreCandidates" : nil
            row.candidates = candidates.map { "\(text($0.imagePath)) @ \(hex($0.address))" }
        case .cacheUnavailable(let reason, let detail):
            row.outcome = "cacheUnavailable"
            row.subreason = reason.rawValue
            row.detail = detail
        case .notCacheResident(let reason):
            row.outcome = "notCacheResident"
            switch reason {
            case .preLookup(let miss): row.subreason = describe(miss)
            case .installNameNotInCache(let name):
                row.subreason = "installNameNotInCache"
                row.detail = name
            }
        }
    }

    private static func describe(_ namespace: ImportNamespace) -> String {
        switch namespace {
        case .dependency(let ordinal): "dependency(\(ordinal))"
        case .selfImage: "selfImage"
        case .mainExecutable: "mainExecutable"
        case .flatLookup: "flatLookup"
        case .weakLookup: "weakLookup"
        case .unknown(let raw): "unknown(\(raw))"
        }
    }

    private static func describe(_ miss: ImportResolutionPreLookupMiss) -> String {
        switch miss {
        case .noOriginRecorded: "noOriginRecorded"
        case .selfImage: "selfImage"
        case .mainExecutable: "mainExecutable"
        case .flatLookup: "flatLookup"
        case .weakLookup: "weakLookup"
        case .unknownOrdinal(let raw): "unknownOrdinal(\(raw))"
        case .ordinalOutOfRange(let ordinal, let count): "ordinalOutOfRange(\(ordinal) of \(count))"
        case .unresolvedPathVariable(let name): "unresolvedPathVariable(\(name))"
        case .nonAbsoluteInstallName(let name): "nonAbsoluteInstallName(\(name))"
        case .emptySymbolName: "emptySymbolName"
        }
    }

    private static func hex(_ value: UInt64) -> String { "0x" + String(value, radix: 16) }
    private static func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    private static func text(_ bytes: [UInt8]) -> String { String(decoding: bytes, as: UTF8.self) }

    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }
}
