import Foundation

/// Which namespace an import ordinal selects. Decided from the ordinal ENCODING, never from the
/// bare integer: a chained-fixup ordinal 254/255 is a genuine dependency, while an nlist n_desc
/// ordinal 0xfe/0xff is a special. Pure value logic; no cache or file access.
enum ImportNamespace: Hashable, Sendable {
    case dependency(ordinal: Int)
    case selfImage
    case mainExecutable
    case flatLookup
    case weakLookup
    case unknown(raw: Int)

    /// Range checking of a dependency ordinal happens in the builder so the miss can name the count.
    static func classify(_ origin: ImportOrigin) -> ImportNamespace {
        switch origin.encoding {
        case .nlistDesc:
            switch origin.rawOrdinal {
            case 0: return .selfImage
            case MachOConstants.dynamicLookupLibraryOrdinal: return .flatLookup
            case MachOConstants.executableLibraryOrdinal: return .mainExecutable
            case 1...: return .dependency(ordinal: origin.rawOrdinal)
            default: return .unknown(raw: origin.rawOrdinal)
            }
        case .chainedFixup:
            switch origin.rawOrdinal {
            case 0: return .selfImage
            case -1: return .mainExecutable
            case -2: return .flatLookup
            case -3: return .weakLookup
            case 1...: return .dependency(ordinal: origin.rawOrdinal)
            default: return .unknown(raw: origin.rawOrdinal)
            }
        }
    }
}

/// A lookup the later cache walker can run: exact symbol spelling in one named dependency.
struct ImportResolutionRequest: Hashable, Sendable {
    var symbolName: String
    var origin: ImportOrigin
    /// 1-based ordinal into the importing image's dependency table.
    var dependencyOrdinal: Int
    /// Exact install name from the importing image's own dependency table (an absolute path).
    var installName: String
    /// Load-command kind of the dependency (required, weak, reexport, upward, lazy).
    var dependencyKind: String
    /// Weak import flag from this origin (nil never occurs here: origins always record it).
    var isWeakImport: Bool
}

/// Reasons no lookup can even be attempted. These are decided from the importer's own metadata
/// before any cache is consulted, and are never repaired into a guess.
enum ImportResolutionPreLookupMiss: Hashable, Sendable {
    /// Legacy or non-Mach-O row with no recorded origin; the ordinal encoding is unknown.
    case noOriginRecorded
    case selfImage
    case mainExecutable
    case flatLookup
    case weakLookup
    case unknownOrdinal(raw: Int)
    case ordinalOutOfRange(ordinal: Int, dependencyCount: Int)
    /// `@rpath/`, `@loader_path/`, `@executable_path/`: not nameable as a cache image without a runtime.
    case unresolvedPathVariable(installName: String)
    /// Install name is not an absolute path.
    case nonAbsoluteInstallName(installName: String)
    case emptySymbolName
}

struct ImportResolutionEntry: Hashable, Sendable {
    enum Outcome: Hashable, Sendable {
        case request(ImportResolutionRequest)
        case miss(ImportResolutionPreLookupMiss)
    }
    var symbolName: String
    /// Nil only for the `noOriginRecorded` miss.
    var origin: ImportOrigin?
    var outcome: Outcome
}

/// Builds one entry per (imported symbol, distinct origin) in input order. Duplicate names that
/// come from distinct origins stay separate; nothing is collapsed or reordered.
enum ImportResolutionRequestBuilder {
    private static let pathVariablePrefixes = ["@rpath/", "@loader_path/", "@executable_path/"]

    static func build(from metadata: MachOLoadMetadata) -> [ImportResolutionEntry] {
        var entries: [ImportResolutionEntry] = []
        var dependencies: [Int: MachOLoadMetadata.DependentDylib] = [:]
        for dylib in metadata.dependentDylibs where dependencies[dylib.ordinal] == nil {
            dependencies[dylib.ordinal] = dylib
        }
        for symbol in metadata.importedSymbols {
            guard !symbol.origins.isEmpty else {
                entries.append(ImportResolutionEntry(
                    symbolName: symbol.name, origin: nil, outcome: .miss(.noOriginRecorded)))
                continue
            }
            var seen = Set<ImportOrigin>()
            for origin in symbol.origins where seen.insert(origin).inserted {
                entries.append(ImportResolutionEntry(
                    symbolName: symbol.name, origin: origin,
                    outcome: outcome(symbol: symbol.name, origin: origin, dependencies: dependencies,
                                     dependencyCount: metadata.dependentDylibs.count)))
            }
        }
        return entries
    }

    private static func outcome(
        symbol: String, origin: ImportOrigin, dependencies: [Int: MachOLoadMetadata.DependentDylib],
        dependencyCount: Int
    ) -> ImportResolutionEntry.Outcome {
        if symbol.isEmpty { return .miss(.emptySymbolName) }
        switch ImportNamespace.classify(origin) {
        case .selfImage: return .miss(.selfImage)
        case .mainExecutable: return .miss(.mainExecutable)
        case .flatLookup: return .miss(.flatLookup)
        case .weakLookup: return .miss(.weakLookup)
        case .unknown(let raw): return .miss(.unknownOrdinal(raw: raw))
        case .dependency(let ordinal):
            guard let dylib = dependencies[ordinal] else {
                return .miss(.ordinalOutOfRange(ordinal: ordinal, dependencyCount: dependencyCount))
            }
            if pathVariablePrefixes.contains(where: { dylib.path.hasPrefix($0) }) {
                return .miss(.unresolvedPathVariable(installName: dylib.path))
            }
            guard dylib.path.hasPrefix("/") else {
                return .miss(.nonAbsoluteInstallName(installName: dylib.path))
            }
            return .request(ImportResolutionRequest(
                symbolName: symbol, origin: origin, dependencyOrdinal: ordinal,
                installName: dylib.path, dependencyKind: dylib.kind, isWeakImport: origin.isWeak))
        }
    }
}
