import Foundation

/// DC2-2: names crash-report frames that sit in dyld shared cache images, against one admitted
/// `HostCacheSnapshot`. Authority chain per frame (design 3.1): report OS build against the host
/// build, the image UUID proven unique in the catalog and agreeing with the image's own `LC_UUID`
/// (and the header's imagesText UUID when present), and a consistent slide across the report's
/// cache images. Naming (design 2.0/2.1): the frame address is mapped to a function bounded by
/// `LC_FUNCTION_STARTS`, and only a name exported at exactly that function's start is claimed.
/// Nothing is ever named past the end of its function; every frame gets exactly one typed outcome.
struct CrashFrameSymbolicator: Sendable {
    let snapshot: HostCacheSnapshot
    let hostBuild: HostBuildEvidence
    let limits: DyldCacheSymbolicationLimits
    let memo: SymbolicationMemo

    init(
        snapshot: HostCacheSnapshot, hostBuild: HostBuildEvidence,
        limits: DyldCacheSymbolicationLimits = .production,
        memo: SymbolicationMemo? = nil
    ) {
        self.snapshot = snapshot
        self.hostBuild = hostBuild
        self.limits = limits
        self.memo = memo ?? SymbolicationMemo(limits: limits)
    }

    // MARK: Report entry point

    private enum ImageResolution {
        case proven(catalogIndex: Int, uuid: [UInt8])
        case failed(FrameSymbolOutcome)
    }

    func symbolicate(_ report: CrashReport, isCancelled: () -> Bool = { false }) -> CrashSymbolication {
        var result = CrashSymbolication(
            cacheUUID: snapshot.cacheUUID, frames: [], buildChecked: report.osVersion?.build != nil,
            refusal: nil, wasCancelled: false)
        let frameCount = report.threads.reduce(0) { $0 + $1.frames.count }
        guard frameCount <= limits.maximumReportFrames else {
            result.refusal = .tooManyFrames(count: frameCount, limit: limits.maximumReportFrames)
            return result
        }
        guard report.images.count <= limits.maximumReportImages else {
            result.refusal = .tooManyImages(count: report.images.count, limit: limits.maximumReportImages)
            return result
        }
        result.frames.reserveCapacity(frameCount)

        var snapshotFailure: CacheMismatchReason?
        do {
            try snapshot.verifyIdentitiesUnchanged()
        } catch let error as CacheUnavailableError {
            snapshotFailure = .snapshotUnavailable(error.reason, error.detail)
        } catch {
            snapshotFailure = .snapshotUnavailable(.unreadable, "identity recheck failed")
        }
        let buildRefusal = buildGate(report)
        let buildUnchecked = report.osVersion?.build == nil

        var resolutions: [ImageResolution] = []
        var cancelled = false
        if report.threads.contains(where: { !$0.frames.isEmpty }) {
            do {
                resolutions = try resolveImages(
                    report, snapshotFailure: snapshotFailure, buildRefusal: buildRefusal,
                    isCancelled: isCancelled)
            } catch {
                cancelled = true
            }
        }

        var localIndexes: [Int: Result<ImageSymbolIndex, MappedFailure>] = [:]
        for thread in report.threads {
            for (position, frame) in thread.frames.enumerated() {
                let isTop = position == 0
                var record = FrameSymbolication(
                    threadIndex: thread.id, frameID: frame.id, reportImageIndex: frame.imageIndex,
                    coverAdjustment: isTop ? 0 : 1, cacheUUID: snapshot.cacheUUID, outcome: .cancelled)
                if !cancelled, isCancelled() { cancelled = true }
                if !cancelled {
                    do {
                        record.outcome = try outcome(
                            for: frame, isTop: isTop, report: report, resolutions: resolutions,
                            buildUnchecked: buildUnchecked, localIndexes: &localIndexes, isCancelled: isCancelled)
                        record.localSymbolsEvidence = localSymbolsEvidence(for: record.outcome)
                    } catch {
                        cancelled = true
                    }
                }
                result.frames.append(record)
            }
        }
        result.wasCancelled = cancelled
        return result
    }

    /// Address-only entry point (no crash frame): names a cache unslid VM address. The owner is
    /// proven by the address lying in one image's own segments, never by "the image below".
    func symbolicate(cacheAddress: UInt64, isTopFrame: Bool = true, isCancelled: () -> Bool = { false }) -> FrameSymbolication {
        var record = FrameSymbolication(
            threadIndex: -1, frameID: 0, reportImageIndex: nil, coverAdjustment: isTopFrame ? 0 : 1,
            cacheUUID: snapshot.cacheUUID, outcome: .cancelled)
        let cover = isTopFrame ? cacheAddress : cacheAddress &- 1
        do {
            try snapshot.verifyIdentitiesUnchanged()
            let scan = try memo.scan(cacheUUID: snapshot.cacheUUID) {
                try CatalogScan.build(snapshot: snapshot, limits: limits, isCancelled: isCancelled)
            }
            var owners = Set<Int>()
            for extent in scan.extents where extent.start <= cover && cover < extent.end { owners.insert(extent.catalogIndex) }
            guard !owners.isEmpty else {
                record.outcome = .noSymbolCovering(.outsideAnyImage)
                return record
            }
            guard owners.count == 1, let owner = owners.first, let uuid = scan.uuidByCatalogIndex[owner] else {
                let paths = owners.sorted().prefix(limits.maximumReportedCandidates).map { snapshot.catalog[$0].path }
                record.outcome = .ambiguous(.overlappingImageExtents(
                    paths: paths, moreCandidates: owners.count > limits.maximumReportedCandidates))
                return record
            }
            var localIndexes: [Int: Result<ImageSymbolIndex, MappedFailure>] = [:]
            switch try symbolIndex(catalogIndex: owner, uuid: uuid, local: &localIndexes, isCancelled: isCancelled) {
            case .failure(let failure):
                record.outcome = failure.outcome
            case .success(let index):
                let (offset, underflow) = cacheAddress.subtractingReportingOverflow(index.loadAddress)
                record.outcome = underflow ? .malformed(.addressOverflow)
                    : Self.lookup(index, imageOffset: offset, isTopFrame: isTopFrame, buildUnchecked: true)
                record.localSymbolsEvidence = localSymbolsEvidence(for: record.outcome)
            }
        } catch let error as CacheUnavailableError {
            record.outcome = .cacheMismatch(.snapshotUnavailable(error.reason, error.detail))
        } catch {
            record.outcome = .cancelled
        }
        return record
    }

    // MARK: Local-symbol availability (DC2-3, design D21)

    /// Evidence only where a local name could have helped: a function start with no export name,
    /// or an export strictly inside the function. Other answers carry none, and `named` is untouched.
    private func localSymbolsEvidence(for outcome: FrameSymbolOutcome) -> LocalSymbolsUnavailableReason? {
        guard case .noSymbolCovering(let reason) = outcome else { return nil }
        switch reason {
        case .startUnnamed, .interiorSymbolOnly: break
        default: return nil
        }
        return memo.localSymbolsStatus(cacheUUID: snapshot.cacheUUID) { Self.localSymbolsStatus(of: snapshot) }
    }

    /// Reads only the already-mapped main header through the existing parser (symbolFileUUID,
    /// DyldSharedCacheParser.swift:313). No companion file is opened or read.
    static func localSymbolsStatus(of snapshot: HostCacheSnapshot) -> LocalSymbolsUnavailableReason {
        guard let main = snapshot.files.first,
              let header = try? DyldSharedCacheParser().parseHeader(main.data) else { return .headerUnreadable }
        guard let declared = header.symbolFileUUID else { return .noDeclaredCompanion }
        return .declaredCompanionNotRead(uuid: declared)
    }

    // MARK: Authority

    private func buildGate(_ report: CrashReport) -> CacheMismatchReason? {
        guard let reportBuild = report.osVersion?.build else { return nil }
        guard let plist = hostBuild.systemVersionBuild, let kernel = hostBuild.kernelOSVersion else {
            return .hostBuildUnavailable
        }
        guard plist == kernel else { return .hostBuildSourcesDisagree(systemVersion: plist, kernel: kernel) }
        guard reportBuild == plist else { return .osBuildDiffers(report: reportBuild, host: plist) }
        return nil
    }

    private static func uuidBytes(_ value: String?) -> [UInt8]? {
        guard let value else { return nil }
        let compact = Array(value.replacingOccurrences(of: "-", with: "").lowercased().utf8)
        guard compact.count == 32 else { return nil }
        var bytes: [UInt8] = []
        func nibble(_ c: UInt8) -> UInt8? {
            switch c {
            case 48...57: return c - 48
            case 97...102: return c - 87
            default: return nil
            }
        }
        for pair in stride(from: 0, to: 32, by: 2) {
            guard let high = nibble(compact[pair]), let low = nibble(compact[pair + 1]) else { return nil }
            bytes.append(high << 4 | low)
        }
        return bytes
    }

    private func resolveImages(
        _ report: CrashReport, snapshotFailure: CacheMismatchReason?, buildRefusal: CacheMismatchReason?,
        isCancelled: () -> Bool
    ) throws -> [ImageResolution] {
        var scan: CatalogScan?
        var resolutions: [ImageResolution] = []
        resolutions.reserveCapacity(report.images.count)
        for image in report.images {
            guard let uuid = Self.uuidBytes(image.uuid) else {
                resolutions.append(.failed(.malformed(.invalidReportUUID)))
                continue
            }
            if let snapshotFailure {
                resolutions.append(.failed(.cacheMismatch(snapshotFailure)))
                continue
            }
            if let buildRefusal {
                resolutions.append(.failed(.cacheMismatch(buildRefusal)))
                continue
            }
            let table: CatalogScan
            if let existing = scan {
                table = existing
            } else {
                table = try memo.scan(cacheUUID: snapshot.cacheUUID) {
                    try CatalogScan.build(snapshot: snapshot, limits: limits, isCancelled: isCancelled)
                }
                scan = table
            }
            let candidates = table.uuidToCatalogIndices[uuid] ?? []
            if candidates.isEmpty {
                resolutions.append(.failed(table.unreadableImages > 0
                    ? .cacheMismatch(.catalogScanIncomplete(unreadableImages: table.unreadableImages))
                    : .imageNotInCache(ImageNotInCache(
                        reportImageName: image.name, reportUUID: image.uuid, catalogCount: snapshot.catalog.count,
                        skippedSource: image.source))))
            } else if candidates.count > 1 {
                let paths = candidates.sorted().prefix(limits.maximumReportedCandidates).map { snapshot.catalog[$0].path }
                resolutions.append(.failed(.ambiguous(.duplicateImageUUID(
                    paths: paths, moreCandidates: candidates.count > limits.maximumReportedCandidates))))
            } else {
                let index = candidates[0]
                if let textInfo = table.textInfoUUIDs,
                   textInfo[snapshot.catalog[index].loadAddress] != uuid {
                    resolutions.append(.failed(.cacheMismatch(.catalogHeaderDisagree(
                        "the imagesText UUID differs from the image's LC_UUID"))))
                } else {
                    resolutions.append(.proven(catalogIndex: index, uuid: uuid))
                }
            }
        }
        applySlideConsistency(report, &resolutions)
        return resolutions
    }

    /// slide_i = report base_i - catalog load address_i must be one value across the report's
    /// proven cache images, a non-negative multiple of the 16 KiB page granule. The reference is
    /// the value a strict majority shares; without one, every proven image is inconsistent.
    private func applySlideConsistency(_ report: CrashReport, _ resolutions: inout [ImageResolution]) {
        var slides: [(position: Int, slide: UInt64?)] = []
        for (position, resolution) in resolutions.enumerated() {
            guard case .proven(let catalogIndex, _) = resolution else { continue }
            let base = report.images[position].base
            let load = snapshot.catalog[catalogIndex].loadAddress
            slides.append((position, base >= load ? base - load : nil))
        }
        guard !slides.isEmpty else { return }
        var counts: [UInt64: Int] = [:]
        for entry in slides { if let slide = entry.slide { counts[slide, default: 0] += 1 } }
        var reference: UInt64?
        if let best = counts.max(by: { $0.value < $1.value }), best.value * 2 > slides.count, best.key % 0x4000 == 0 {
            reference = best.key
        }
        for entry in slides where entry.slide == nil || entry.slide != reference {
            resolutions[entry.position] = .failed(.cacheMismatch(.slideInconsistent))
        }
    }

    // MARK: Per-frame

    private struct MappedFailure: Error {
        var outcome: FrameSymbolOutcome
    }

    private func outcome(
        for frame: CrashReportFrame, isTop: Bool, report: CrashReport, resolutions: [ImageResolution],
        buildUnchecked: Bool, localIndexes: inout [Int: Result<ImageSymbolIndex, MappedFailure>],
        isCancelled: () -> Bool
    ) throws -> FrameSymbolOutcome {
        guard let imageIndex = frame.imageIndex else { return .malformed(.missingImageIndex) }
        guard report.images.indices.contains(imageIndex), resolutions.indices.contains(imageIndex) else {
            return .malformed(.imageIndexOutOfRange)
        }
        guard let offset = frame.imageOffset else { return .malformed(.missingOffset) }
        switch resolutions[imageIndex] {
        case .failed(let outcome):
            return outcome
        case .proven(let catalogIndex, let uuid):
            switch try symbolIndex(catalogIndex: catalogIndex, uuid: uuid, local: &localIndexes, isCancelled: isCancelled) {
            case .failure(let failure): return failure.outcome
            case .success(let index):
                return Self.lookup(index, imageOffset: offset, isTopFrame: isTop, buildUnchecked: buildUnchecked)
            }
        }
    }

    private func symbolIndex(
        catalogIndex: Int, uuid: [UInt8], local: inout [Int: Result<ImageSymbolIndex, MappedFailure>],
        isCancelled: () -> Bool
    ) throws -> Result<ImageSymbolIndex, MappedFailure> {
        if let hit = local[catalogIndex] { return hit }
        let result: Result<ImageSymbolIndex, MappedFailure>
        do {
            let index = try memo.index(for: SymbolicationMemo.Key(cacheUUID: snapshot.cacheUUID, imageUUID: uuid)) {
                let descriptor = try ImageDescriptor.load(
                    catalogIndex: catalogIndex, in: snapshot, limits: limits.descriptorLimits)
                guard descriptor.uuid == uuid else {
                    throw CacheUnavailableError(.identityMismatch, "the image's LC_UUID differs from the report")
                }
                let facts = try ImageSymbolFacts.load(catalogIndex: catalogIndex, in: snapshot, limits: limits)
                let exports = try ExportTrieEnumerator.enumerate(
                    tries: descriptor.exportTries, loadAddress: descriptor.loadAddress, limits: limits,
                    isCancelled: isCancelled)
                return ImageSymbolIndex(
                    catalogIndex: catalogIndex, path: descriptor.path, uuid: descriptor.uuid,
                    loadAddress: descriptor.loadAddress, facts: facts, exports: exports)
            }
            result = .success(index)
        } catch let error as CacheUnavailableError {
            let outcome: FrameSymbolOutcome
            switch error.reason {
            case .unsupportedFormat: outcome = .malformed(.invalidLoadCommands(error.detail))
            case .identityMismatch: outcome = .cacheMismatch(.catalogHeaderDisagree(error.detail))
            default: outcome = .cacheMismatch(.snapshotUnavailable(error.reason, error.detail))
            }
            result = .failure(MappedFailure(outcome: outcome))
        }
        // ExportTrieEnumerator.Cancelled propagates to the caller; only definite results are kept.
        local[catalogIndex] = result
        return result
    }

    // MARK: Address to function to name

    static func lookup(
        _ index: ImageSymbolIndex, imageOffset: UInt64, isTopFrame: Bool, buildUnchecked: Bool
    ) -> FrameSymbolOutcome {
        let (address, overflow) = index.loadAddress.addingReportingOverflow(imageOffset)
        guard !overflow, isTopFrame || address > 0 else { return .malformed(.addressOverflow) }
        let cover = isTopFrame ? address : address - 1
        let facts = index.facts
        guard let segment = facts.segment(containing: cover), segment.isExecutable,
              let section = segment.sections.first(where: { $0.address <= cover && cover < $0.end }) else {
            return .noSymbolCovering(.notExecutableCode)
        }
        if section.isStub { return .noSymbolCovering(.stubSection(section.name)) }
        guard section.isInstructions else { return .noSymbolCovering(.notExecutableCode) }

        func named(start: UInt64, end: UInt64?) -> FrameSymbolOutcome {
            guard case .entries(let exported) = index.exports else {
                if case .incomplete(let bound) = index.exports { return .noSymbolCovering(.exportsIncomplete(bound)) }
                if case .malformed(let detail) = index.exports { return .malformed(.traversalBound(detail)) }
                return .malformed(.traversalBound("export enumeration unavailable"))
            }
            let found = exported.names(at: start)
            if found.isEmpty {
                if let end, let interior = exported.firstAddress(after: start, before: end) {
                    return .noSymbolCovering(.interiorSymbolOnly(interior))
                }
                return .noSymbolCovering(end == nil ? .noFunctionBounds(.absentCommand) : .startUnnamed(start))
            }
            var names: [SymbolName] = []
            for bytes in found {
                guard let text = String(bytes: bytes, encoding: .utf8) else { return .malformed(.nameNotUTF8) }
                names.append(SymbolName(bytes: bytes, display: text, source: .exportTrieExact))
            }
            return .named(NamedFrame(
                names: names, functionStart: start, functionEnd: end, offsetWithinSymbol: address - start,
                imagePath: index.path, imageUUID: index.uuid, address: address, imageOffset: imageOffset,
                buildUnchecked: buildUnchecked))
        }

        func exportsFailure() -> FrameSymbolOutcome? {
            switch index.exports {
            case .entries: return nil
            case .incomplete(let bound): return .noSymbolCovering(.exportsIncomplete(bound))
            case .malformed(let detail): return .malformed(.traversalBound(detail))
            }
        }

        if facts.functionStarts.isEmpty, case .failure(let reason) = facts.startsStatus {
            // No usable function bounds: only an exact export at a top frame address can be claimed.
            if let failure = exportsFailure() { return failure }
            guard isTopFrame, case .entries(let exported) = index.exports, !exported.names(at: address).isEmpty else {
                return .noSymbolCovering(.noFunctionBounds(reason))
            }
            return named(start: address, end: nil)
        }
        guard let (position, start) = facts.start(atOrBelow: cover) else { return .noSymbolCovering(.beforeFirstFunction) }
        let next = position + 1 < facts.functionStarts.count ? facts.functionStarts[position + 1] : nil
        if next == nil, case .failure(let reason) = facts.startsStatus {
            return .noSymbolCovering(.noFunctionBounds(reason))
        }
        guard start >= section.address else { return .noSymbolCovering(.pastLastFunction) }
        let end = min(next ?? section.end, section.end, segment.end)
        guard cover < end else { return .noSymbolCovering(.pastLastFunction) }
        if let failure = exportsFailure() { return failure }
        return named(start: start, end: end)
    }
}
