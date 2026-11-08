import Foundation

// DC1 slice B: typed results and limits for resolving a Mach-O import against the host dyld
// shared cache. Pure value types. Install names, symbol names and image paths are carried as
// raw bytes wherever the resolver compares them, so no Unicode normalization or lossy decoding
// can change which image or symbol is meant.

/// The address space a resolved address lives in. File offsets and runtime (slid) addresses are
/// never mixed into `ResolvedSystemSymbol.address`.
enum CacheAddressDomain: String, Hashable, Sendable {
    case cacheUnslidVM
}

enum CacheUnavailableReason: String, Hashable, Sendable {
    case notPresent
    case unreadable
    case identityMismatch
    case changedDuringResolution
    case unsupportedFormat
    case architectureMismatch
    case budgetExceeded
    case cancelled
}

/// Thrown while admitting the cache or an image. Always maps to `cacheUnavailable` on the row.
struct CacheUnavailableError: Error, Equatable, Sendable {
    var reason: CacheUnavailableReason
    var detail: String
    init(_ reason: CacheUnavailableReason, _ detail: String) {
        self.reason = reason
        self.detail = detail
    }
}

enum ResolvedTerminalKind: Hashable, Sendable {
    case regular
    case absolute
    case threadLocal
    /// EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: `address` is the stub; the real target is only known
    /// after the resolver function runs, so the row is flagged non-final.
    case stubAndResolver(resolverOffset: UInt64)
}

/// The DC2 seam (design section 7): a symbol proven against one cache snapshot and one image.
struct ResolvedSystemSymbol: Hashable, Sendable {
    var cacheUUID: [UInt8]
    var imageUUID: [UInt8]
    var imagePath: [UInt8]
    var imageLoadAddress: UInt64
    /// Cache unslid VM address (for `absolute` terminals, the absolute value itself).
    var address: UInt64
    /// `address - imageLoadAddress`; nil for absolute terminals, which are not image-relative.
    var imageOffset: UInt64?
    var symbolName: [UInt8]
    var terminalKind: ResolvedTerminalKind
    var isWeakDefinition: Bool
    var domain: CacheAddressDomain = .cacheUnslidVM
    /// Cache unslid VM address of the resolver function for a stub-and-resolver terminal; nil
    /// otherwise. `address` is always the exported stub, never this value.
    var resolverAddress: UInt64?
}

struct ResolvedImport: Hashable, Sendable {
    var symbol: ResolvedSystemSymbol
    /// Image paths traversed, importer's named dependency first, the exporting image last.
    var viaPath: [[UInt8]]
    /// The importing image marked this import weak (Q6: resolved and flagged).
    var isWeakImport: Bool
    /// False for stub-and-resolver terminals (Q6: resolved, non-final).
    var isFinalTarget: Bool
    /// Extra terminals that reached the same (image, address) (Q6 duplicate policy).
    var duplicateTerminalCount: Int
    /// Reexport branches that failed or were cut while another branch resolved. Nonzero means the
    /// answer is the unique terminal found, but not every branch was proven.
    var incompleteBranches: Int
}

enum ReexportChainFailure: String, Hashable, Sendable {
    case depthLimit
    case stateLimit
    case cycle
    case edgeTargetNotInCache
    case edgeOrdinalOutOfRange
    /// The reexport renamed the symbol and the renamed target (with its own reexports) lacks it.
    case renamedTargetMissing
    /// The reexport kept the spelling and the target (with its own reexports) lacks it.
    case targetSymbolMissing
    case unsupportedFlags
}

struct AmbiguousCandidate: Hashable, Sendable, Comparable {
    var imagePath: [UInt8]
    var imageLoadAddress: UInt64
    var address: UInt64

    static func < (lhs: AmbiguousCandidate, rhs: AmbiguousCandidate) -> Bool {
        if lhs.imageLoadAddress != rhs.imageLoadAddress { return lhs.imageLoadAddress < rhs.imageLoadAddress }
        if lhs.address != rhs.address { return lhs.address < rhs.address }
        return lhs.imagePath.lexicographicallyPrecedes(rhs.imagePath)
    }
}

enum NotCacheResidentReason: Hashable, Sendable {
    /// Decided from the importer's own metadata before any cache was consulted (slice A).
    case preLookup(ImportResolutionPreLookupMiss)
    /// The exact install-name bytes are not in the cache's image catalog.
    case installNameNotInCache(installName: String)
}

enum ImportResolutionOutcome: Hashable, Sendable {
    case resolved(ResolvedImport)
    case notExported(searchedImages: [[UInt8]])
    case reexportChain(ReexportChainFailure, viaPath: [[UInt8]])
    case ambiguous(candidates: [AmbiguousCandidate], moreCandidates: Bool)
    case cacheUnavailable(CacheUnavailableReason, detail: String)
    case notCacheResident(NotCacheResidentReason)
}

struct ImportResolutionRow: Hashable, Sendable {
    /// Index of the entry in the input array; rows are returned in input order.
    var entryIndex: Int
    var symbolName: String
    var origin: ImportOrigin?
    var outcome: ImportResolutionOutcome
}

struct ImportResolutionBatch: Sendable {
    var rows: [ImportResolutionRow]
    /// UUID of the main cache file the rows were proven against; nil if no snapshot was admitted.
    var cacheUUID: [UInt8]?
    /// True when budget exhaustion or cancellation left unfinished rows typed as unavailable.
    var isPartial: Bool
    var workUnitsUsed: UInt64
}

struct DyldCacheImportResolutionLimits: Sendable, Equatable {
    var maximumRequestsPerBatch = 100_000
    var maximumSymbolBytes = 4_096
    var maximumDependencies = 256
    var maximumLoadCommands = 4_096
    var maximumLoadCommandBytes = 1_048_576
    var descriptorCacheCapacity = 64
    var maximumReexportDepth = 8
    /// Design proposed 64. libSystem.B alone fans out to 40 children plus itself, and a missing
    /// name must visit all of them, so 64 leaves almost no room for a nested umbrella. 256 keeps
    /// the bound while making `notExported` reachable for real umbrella frameworks.
    var maximumVisitedStates = 256
    var maximumReportedCandidates = 16
    var maximumSubCaches = 128
    var maximumCacheFileBytes: UInt64 = 32 * 1024 * 1024 * 1024
    var maximumCatalogPathBytes = 4_096
    /// Abstract work units: bytes inspected plus node visits plus descriptor loads.
    var workBudget: UInt64 = 200_000_000
    var cancellationCheckInterval: UInt64 = 4_096

    static let production = DyldCacheImportResolutionLimits()
}
