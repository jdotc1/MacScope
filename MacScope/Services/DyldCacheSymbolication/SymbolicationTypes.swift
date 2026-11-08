import Foundation

// DC2-2: typed results and limits for naming crash-report frames that sit in dyld shared cache
// images. Names are raw bytes with a decoded display string; an address is only ever a cache
// unslid VM address (`CacheAddressDomain.cacheUnslidVM`), never a runtime (slid) address.

/// Record-only defaults (orchestrator ruling Q11): none of these were measured on a real image.
/// Exhausting one is a typed incompleteness, never a silent empty result.
struct DyldCacheSymbolicationLimits: Sendable, Equatable {
    var maximumTrieBytes = 32 * 1024 * 1024
    var maximumTrieNodes = 4_000_000
    var maximumExportNameBytes = 4_096
    var maximumRetainedNameBytes = 64 * 1024 * 1024
    var maximumExportEntries = 2_000_000
    var maximumFunctionStarts = 4_000_000
    var maximumMemoImages = 16
    var maximumMemoBytes = 256 * 1024 * 1024
    var maximumReportFrames = 100_000
    var maximumReportImages = 20_000
    var maximumReportedCandidates = 16
    var cancellationCheckInterval = 4_096
    /// Limits for the shared DC1 descriptor loads (load-command count and size).
    var descriptorLimits = DyldCacheImportResolutionLimits.production

    static let production = DyldCacheSymbolicationLimits()
}

enum SymbolicationBound: String, Hashable, Sendable {
    case trieBytes, trieNodes, retainedNameBytes, exportEntries
}

enum SymbolNameSource: String, Hashable, Sendable {
    case exportTrieExact
    /// Reserved: local symbols are not read on this host (see `LocalSymbolsUnavailableReason`),
    /// so nothing produces it yet.
    case localSymbolExact
}

struct SymbolName: Hashable, Sendable {
    var bytes: [UInt8]
    var display: String
    var source: SymbolNameSource
}

enum FunctionBoundsFailure: String, Hashable, Sendable {
    /// No LC_FUNCTION_STARTS command.
    case absentCommand
    /// The command exists but its payload is empty.
    case emptyPayload
    /// The start list stopped at `maximumFunctionStarts`.
    case truncatedByCap
    /// The payload ended without a zero terminator.
    case unterminated
}

enum NoSymbolReason: Hashable, Sendable {
    /// A function start exists but no admitted source has a name at exactly that address.
    case startUnnamed(UInt64)
    case noFunctionBounds(FunctionBoundsFailure)
    case stubSection(String)
    case notExecutableCode
    /// Address-only entry point: the address is in no catalogued image's segments.
    case outsideAnyImage
    case beforeFirstFunction
    case pastLastFunction
    case exportsIncomplete(SymbolicationBound)
    /// An export lies strictly inside the function but nothing is at its start.
    case interiorSymbolOnly(UInt64)
}

/// DC2-3 (design D21): why no local-symbol names were attempted for this cache. Attached as
/// evidence beside a `noSymbolCovering(.startUnnamed | .interiorSymbolOnly)` answer, so a consumer
/// can tell that unexported names were not even tried. It never changes the outcome itself.
enum LocalSymbolsUnavailableReason: Hashable, Sendable {
    /// The main header's symbolFileUUID (0x190..0x1A0) is zero or absent: the cache declares no
    /// local-symbol companion, and localSymbolsOffset/Size (0x48/0x50) are zero. Probe result for
    /// this host (lane-dc2c/PROBE.md).
    case noDeclaredCompanion
    /// The header declares a companion, but this slice reads none (the snapshot admits only the
    /// sub-caches the header lists).
    case declaredCompanionNotRead(uuid: [UInt8])
    /// The main header could not be re-read.
    case headerUnreadable
}

enum CacheMismatchReason: Hashable, Sendable {
    case osBuildDiffers(report: String, host: String)
    case hostBuildUnavailable
    /// SystemVersion.plist and kern.osversion disagree (orchestrator ruling Q3).
    case hostBuildSourcesDisagree(systemVersion: String, kernel: String)
    case slideInconsistent
    /// The catalog's text-info UUID, the image's LC_UUID or its LC_ID_DYLIB disagree.
    case catalogHeaderDisagree(String)
    case snapshotUnavailable(CacheUnavailableReason, String)
    /// The UUID was not found, but this many catalog images could not be scanned.
    case catalogScanIncomplete(unreadableImages: Int)
}

enum AmbiguousSymbolReason: Hashable, Sendable {
    case duplicateImageUUID(paths: [[UInt8]], moreCandidates: Bool)
    case overlappingImageExtents(paths: [[UInt8]], moreCandidates: Bool)
}

enum MalformedSymbolReason: Hashable, Sendable {
    case missingImageIndex, imageIndexOutOfRange, missingOffset, invalidReportUUID, addressOverflow
    case traversalBound(String)
    case nameNotUTF8
    case invalidLoadCommands(String)
}

struct NamedFrame: Hashable, Sendable {
    /// At least one, sorted bytewise, no primary (orchestrator ruling Q4).
    var names: [SymbolName]
    var functionStart: UInt64
    /// nil only when the image has no function-start list and the address was an exact export.
    var functionEnd: UInt64?
    var offsetWithinSymbol: UInt64
    var imagePath: [UInt8]
    var imageUUID: [UInt8]
    /// `imageLoadAddress + imageOffset`, cache unslid VM.
    var address: UInt64
    var imageOffset: UInt64
    /// The report carried no OS build, so only the image UUID proved the cache.
    var buildUnchecked: Bool
}

struct ImageNotInCache: Hashable, Sendable {
    var reportImageName: String?
    var reportUUID: String?
    var catalogCount: Int
    /// The report's own `source` tag for the image, kept as evidence only. It never selects or skips a
    /// lookup: the catalog UUID is the only authority (design 3.1 step 6).
    var skippedSource: CrashReportImageSource?
}

enum FrameSymbolOutcome: Hashable, Sendable {
    case named(NamedFrame)
    case imageNotInCache(ImageNotInCache)
    case cacheMismatch(CacheMismatchReason)
    case noSymbolCovering(NoSymbolReason)
    case ambiguous(AmbiguousSymbolReason)
    case malformed(MalformedSymbolReason)
    /// The caller's cancellation closure fired before this frame was answered.
    case cancelled
}

/// Every frame in a report gets exactly one of these.
struct FrameSymbolication: Hashable, Sendable {
    var threadIndex: Int
    var frameID: Int
    var reportImageIndex: Int?
    /// 0 for a thread's top frame, 1 for deeper frames (lookup at address - 1; orchestrator Q5).
    var coverAdjustment: UInt8
    var cacheUUID: [UInt8]
    var domain: CacheAddressDomain = .cacheUnslidVM
    var outcome: FrameSymbolOutcome
    /// Set only beside `noSymbolCovering(.startUnnamed | .interiorSymbolOnly)`, where a local
    /// name could have helped. Does not alter `outcome`.
    var localSymbolsEvidence: LocalSymbolsUnavailableReason? = nil
}

enum SymbolicationRefusal: Hashable, Sendable {
    case tooManyFrames(count: Int, limit: Int)
    case tooManyImages(count: Int, limit: Int)
}

struct CrashSymbolication: Sendable {
    var cacheUUID: [UInt8]
    var frames: [FrameSymbolication]
    /// False when the report carried no OS build (every named frame is `buildUnchecked`).
    var buildChecked: Bool
    var refusal: SymbolicationRefusal?
    var wasCancelled: Bool
}

/// Host OS build evidence (orchestrator ruling Q3): both sources must agree.
struct HostBuildEvidence: Sendable, Equatable {
    var systemVersionBuild: String?
    var kernelOSVersion: String?

    /// Production reader. Not exercised by tests, which inject values.
    static func current() -> HostBuildEvidence {
        var plistBuild: String?
        if let data = try? Data(contentsOf: URL(fileURLWithPath: "/System/Library/CoreServices/SystemVersion.plist")),
           let object = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            plistBuild = object["ProductBuildVersion"] as? String
        }
        var size = 0
        var kernel: String?
        if sysctlbyname("kern.osversion", nil, &size, nil, 0) == 0, size > 1, size <= 256 {
            var buffer = [CChar](repeating: 0, count: size)
            if sysctlbyname("kern.osversion", &buffer, &size, nil, 0) == 0 {
                kernel = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            }
        }
        return HostBuildEvidence(systemVersionBuild: plistBuild, kernelOSVersion: kernel)
    }
}
