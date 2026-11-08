import Darwin
import Foundation

/// Finds the host's dyld shared cache main file for an importer architecture. A stable path is a
/// place to look, never an identity: the snapshot proves identity from the opened descriptors.
struct HostCacheLocator: Sendable {
    static let defaultCandidateDirectories: [URL] = [
        "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
        "/System/Cryptexes/OS/System/Library/dyld",
        "/System/Library/dyld",
        "/var/db/dyld",
    ].map { URL(fileURLWithPath: $0, isDirectory: true) }

    var candidateDirectories: [URL] = HostCacheLocator.defaultCandidateDirectories

    /// Cache file-name tokens for an importer architecture, in preference order. arm64 and arm64e
    /// importers run against the arm64e cache on Apple silicon.
    static func cacheArchitectureTokens(forImporterArchitecture architecture: String) -> [String] {
        switch architecture {
        case "arm64", "arm64e": ["arm64e"]
        case "x86_64", "x86_64h": ["x86_64h", "x86_64"]
        default: []
        }
    }

    /// The first existing main file, with the architecture token it was found under.
    func locate(importerArchitecture: String) throws -> (url: URL, architecture: String) {
        let tokens = Self.cacheArchitectureTokens(forImporterArchitecture: importerArchitecture)
        guard !tokens.isEmpty else {
            throw CacheUnavailableError(.architectureMismatch, "no cache architecture for \(importerArchitecture)")
        }
        for directory in candidateDirectories {
            for token in tokens {
                let url = directory.appendingPathComponent("dyld_shared_cache_\(token)")
                var metadata = stat()
                if url.path.withCString({ lstat($0, &metadata) }) == 0 {
                    return (url, token)
                }
            }
        }
        throw CacheUnavailableError(.notPresent, "no dyld shared cache main file in the candidate directories")
    }
}

/// The immutable authority record for one admitted host cache: the main file plus every declared
/// sub-cache, each mapped read-only through a descriptor whose identity was captured, with header
/// UUIDs matched to the declaring entries, mappings checked for overlap, and the image catalog
/// read as raw path bytes. Pure `Data` views over mmap; nothing is copied or hashed.
///
/// This is the shared seam for DC2 (crash-frame symbolication): it exposes the catalog, the
/// address-to-bytes mapping and the identity recheck without any import-specific logic.
struct HostCacheSnapshot: Sendable {
    struct CacheFile: Sendable {
        var suffix: String
        var url: URL
        var identity: DyldCacheFileIdentity
        var data: Data
        var uuid: [UInt8]
        var mappings: [DyldCacheMapping]
    }

    struct CatalogImage: Sendable, Hashable {
        var path: [UInt8]
        var loadAddress: UInt64
    }

    let mainURL: URL
    let architecture: String
    /// UUID of the main cache file.
    let cacheUUID: [UInt8]
    /// Main file first, then declared sub-caches in entry order.
    let files: [CacheFile]
    let catalog: [CatalogImage]
    private let catalogIndexByPath: [[UInt8]: Int]

    // MARK: Admission

    static func open(
        mainURL: URL,
        expectedArchitecture: String,
        limits: DyldCacheImportResolutionLimits = .production,
        isCancelled: () -> Bool = { false }
    ) throws -> HostCacheSnapshot {
        let parser = DyldSharedCacheParser()
        let main = try mapFile(url: mainURL, suffix: "", limits: limits)
        let mainHeader = try parseHeader(parser, main.data, label: "main")
        guard mainHeader.architecture == expectedArchitecture else {
            throw CacheUnavailableError(.architectureMismatch,
                "cache is \(mainHeader.architecture), expected \(expectedArchitecture)")
        }
        guard !mainHeader.uuid.isEmpty, mainHeader.uuid.contains(where: { $0 != 0 }) else {
            throw CacheUnavailableError(.unsupportedFormat, "main header carries no UUID")
        }
        guard mainHeader.mappings.count <= 16_384 else {
            throw CacheUnavailableError(.unsupportedFormat, "mapping count exceeds bound")
        }
        guard mainHeader.subCacheEntries.count <= limits.maximumSubCaches else {
            throw CacheUnavailableError(.unsupportedFormat, "sub-cache count exceeds bound")
        }

        var files = [CacheFile(
            suffix: "", url: mainURL.standardizedFileURL, identity: main.identity, data: main.data,
            uuid: mainHeader.uuid, mappings: mainHeader.mappings)]
        var seenSuffixes = Set<String>()
        for entry in mainHeader.subCacheEntries {
            if isCancelled() { throw CacheUnavailableError(.cancelled, "cancelled while admitting sub-caches") }
            let siblingURL: URL
            do {
                siblingURL = try DyldCacheSourceIdentityReader.safeSiblingURL(mainURL: mainURL, suffix: entry.fileSuffix)
            } catch {
                throw CacheUnavailableError(.identityMismatch, "unsafe sub-cache suffix")
            }
            guard seenSuffixes.insert(entry.fileSuffix).inserted else {
                throw CacheUnavailableError(.identityMismatch, "duplicate sub-cache suffix \(entry.fileSuffix)")
            }
            let sub: (data: Data, identity: DyldCacheFileIdentity)
            do {
                sub = try mapFile(url: siblingURL, suffix: entry.fileSuffix, limits: limits)
            } catch let error as CacheUnavailableError where error.reason == .notPresent {
                throw CacheUnavailableError(.identityMismatch, "declared sub-cache \(entry.fileSuffix) is missing")
            }
            let header = try parseHeader(parser, sub.data, label: entry.fileSuffix)
            guard header.uuid == entry.uuid else {
                throw CacheUnavailableError(.identityMismatch, "sub-cache \(entry.fileSuffix) UUID differs from its entry")
            }
            guard header.architecture == mainHeader.architecture else {
                throw CacheUnavailableError(.architectureMismatch, "sub-cache \(entry.fileSuffix) architecture differs")
            }
            guard header.mappings.count <= 16_384 else {
                throw CacheUnavailableError(.unsupportedFormat, "sub-cache mapping count exceeds bound")
            }
            files.append(CacheFile(
                suffix: entry.fileSuffix, url: siblingURL, identity: sub.identity, data: sub.data,
                uuid: header.uuid, mappings: header.mappings))
        }
        if MultiFileCacheReader.mappingError(files.flatMap(\.mappings)) != nil {
            throw CacheUnavailableError(.identityMismatch, "mappings overlap across cache files")
        }

        // Catalog: raw path bytes, exact. Header-level image paths are already range-checked by the
        // parser; bytes are re-read here so no lossy UTF-8 repair can alias two distinct names.
        guard mainHeader.images.count <= DyldSharedCacheParser.maximumArrayCount else {
            throw CacheUnavailableError(.unsupportedFormat, "image count exceeds bound")
        }
        var catalog: [CatalogImage] = []
        catalog.reserveCapacity(mainHeader.images.count)
        var index: [[UInt8]: Int] = [:]
        index.reserveCapacity(mainHeader.images.count)
        for image in mainHeader.images {
            if catalog.count & 0xfff == 0, isCancelled() {
                throw CacheUnavailableError(.cancelled, "cancelled while reading the catalog")
            }
            guard let path = rawCString(main.data, offset: image.pathFileOffset, maximum: limits.maximumCatalogPathBytes),
                  !path.isEmpty else {
                throw CacheUnavailableError(.unsupportedFormat, "catalog image path is empty, unterminated or too long")
            }
            guard index[path] == nil else {
                throw CacheUnavailableError(.unsupportedFormat, "catalog lists one install name twice")
            }
            index[path] = catalog.count
            catalog.append(CatalogImage(path: path, loadAddress: image.address))
        }

        return HostCacheSnapshot(
            mainURL: mainURL.standardizedFileURL, architecture: mainHeader.architecture,
            cacheUUID: mainHeader.uuid, files: files, catalog: catalog, catalogIndexByPath: index)
    }

    private static func mapFile(
        url: URL, suffix: String, limits: DyldCacheImportResolutionLimits
    ) throws -> (data: Data, identity: DyldCacheFileIdentity) {
        var metadata = stat()
        if url.path.withCString({ lstat($0, &metadata) }) != 0 {
            if errno == ENOENT || errno == ENOTDIR {
                throw CacheUnavailableError(.notPresent, "cache file \(suffix.isEmpty ? "main" : suffix) is not present")
            }
            throw CacheUnavailableError(.unreadable, "cache file \(suffix.isEmpty ? "main" : suffix) cannot be examined")
        }
        do {
            return try DyldCacheSourceIdentityReader.identityBoundMappedData(
                for: url, expectedIdentity: nil, maximumBytes: limits.maximumCacheFileBytes)
        } catch DyldCacheAnalysisProviderError.sourceChangedDuringInspection {
            throw CacheUnavailableError(.changedDuringResolution, "cache file changed while it was admitted")
        } catch DyldCacheAnalysisProviderError.outputLimitExceeded {
            throw CacheUnavailableError(.unsupportedFormat, "cache file exceeds the size bound")
        } catch {
            throw CacheUnavailableError(.unreadable, "cache file \(suffix.isEmpty ? "main" : suffix) cannot be read")
        }
    }

    private static func parseHeader(
        _ parser: DyldSharedCacheParser, _ data: Data, label: String
    ) throws -> DyldSharedCacheHeader {
        do {
            return try parser.parseHeader(data)
        } catch DyldSharedCacheError.overlappingMappings {
            throw CacheUnavailableError(.identityMismatch, "\(label): mappings overlap")
        } catch DyldSharedCacheError.notADyldCache {
            throw CacheUnavailableError(.unsupportedFormat, "\(label): bad cache magic")
        } catch {
            throw CacheUnavailableError(.unsupportedFormat, "\(label): header is malformed")
        }
    }

    private static func rawCString(_ data: Data, offset: UInt64, maximum: Int) -> [UInt8]? {
        guard offset < UInt64(data.count) else { return nil }
        let start = data.startIndex + Int(offset)
        var bytes: [UInt8] = []
        var cursor = start
        while cursor < data.endIndex {
            let byte = data[cursor]
            if byte == 0 { return bytes }
            guard bytes.count < maximum else { return nil }
            bytes.append(byte)
            cursor += 1
        }
        return nil
    }

    private init(
        mainURL: URL, architecture: String, cacheUUID: [UInt8], files: [CacheFile],
        catalog: [CatalogImage], catalogIndexByPath: [[UInt8]: Int]
    ) {
        self.mainURL = mainURL
        self.architecture = architecture
        self.cacheUUID = cacheUUID
        self.files = files
        self.catalog = catalog
        self.catalogIndexByPath = catalogIndexByPath
    }

    // MARK: Queries

    /// Exact byte match on the install name: no suffix, basename, case-fold or normalization.
    func catalogIndex(forInstallName bytes: [UInt8]) -> Int? { catalogIndexByPath[bytes] }

    /// Reads exactly `length` bytes at a cache VM address. The run must lie inside ONE mapping of
    /// one file; returns a slice of the mapped file (no copy), or nil.
    func bytes(at address: UInt64, length: UInt64) -> Data? {
        guard length > 0 else { return Data() }
        for file in files {
            for mapping in file.mappings where mapping.contains(address) {
                let delta = address - mapping.address
                guard length <= mapping.size - delta else { return nil }
                let (fileStart, overflow) = mapping.fileOffset.addingReportingOverflow(delta)
                guard !overflow,
                      let range = LittleEndianReader(file.data).range(fileStart, length) else { return nil }
                let base = file.data.startIndex
                return file.data[(base + range.lowerBound)..<(base + range.upperBound)]
            }
        }
        return nil
    }

    /// True when every admitted file still has the identity captured at admission.
    func verifyIdentitiesUnchanged() throws {
        for file in files {
            let current: DyldCacheFileIdentity
            do {
                current = try DyldCacheSourceIdentityReader.identity(for: file.url)
            } catch {
                throw CacheUnavailableError(.changedDuringResolution, "cache file \(file.suffix) can no longer be opened")
            }
            guard current == file.identity else {
                throw CacheUnavailableError(.changedDuringResolution, "cache file \(file.suffix) changed identity")
            }
        }
    }
}
