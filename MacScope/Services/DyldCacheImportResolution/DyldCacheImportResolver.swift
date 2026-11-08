import Foundation

/// DC1 slice B. Resolves the slice-A `ImportResolutionEntry` rows against an admitted host cache
/// snapshot, one lazy exact-key walk per request. Policies (the maintainer's rulings Q3 to Q8):
///  - no whole-cache index: only the images a request touches are loaded (bounded LRU);
///  - weak imports resolve and are flagged; weak-definition terminals resolve and are flagged;
///    stub-and-resolver terminals resolve with `isFinalTarget == false`;
///  - the same (image, address) reached twice is ONE resolved row with the duplicate counted;
///    distinct (image, address) terminals are `ambiguous`, never first-wins;
///  - an image's own export wins; only when its tries have no terminal does the walk continue into
///    its `LC_REEXPORT_DYLIB` children in load-command order (dyld semantics, mach-o/loader.h);
///  - budget exhaustion or cancellation keeps finished rows and types the rest.
/// There is no recursion: the walk uses an explicit stack with depth, state and work bounds.
final class DyldCacheImportResolver {
    let snapshot: HostCacheSnapshot
    let limits: DyldCacheImportResolutionLimits
    private var descriptors: ImageDescriptorCache
    private var workUnits: UInt64 = 0
    private var lastCancellationCheck: UInt64 = 0

    init(snapshot: HostCacheSnapshot, limits: DyldCacheImportResolutionLimits = .production) {
        self.snapshot = snapshot
        self.limits = limits
        self.descriptors = ImageDescriptorCache(capacity: limits.descriptorCacheCapacity)
    }

    // MARK: Convenience: locate, admit, resolve, recheck

    /// Locates and admits the host cache for `importerArchitecture`, resolves `entries`, then
    /// rechecks every cache file's identity. A change during the batch turns every cache-dependent
    /// row into `cacheUnavailable(changedDuringResolution)`; no stale resolved row is published.
    static func resolve(
        entries: [ImportResolutionEntry],
        importerArchitecture: String,
        locator: HostCacheLocator = HostCacheLocator(),
        limits: DyldCacheImportResolutionLimits = .production,
        isCancelled: @escaping () -> Bool = { false },
        rowObserver: ((Int) -> Void)? = nil
    ) -> ImportResolutionBatch {
        let snapshot: HostCacheSnapshot
        do {
            let located = try locator.locate(importerArchitecture: importerArchitecture)
            snapshot = try HostCacheSnapshot.open(
                mainURL: located.url, expectedArchitecture: located.architecture,
                limits: limits, isCancelled: isCancelled)
        } catch let error as CacheUnavailableError {
            return unavailable(entries: entries, error: error)
        } catch {
            return unavailable(entries: entries, error: CacheUnavailableError(.unreadable, "cache admission failed"))
        }
        let resolver = DyldCacheImportResolver(snapshot: snapshot, limits: limits)
        var batch = resolver.resolve(entries: entries, isCancelled: isCancelled, rowObserver: rowObserver)
        do {
            try snapshot.verifyIdentitiesUnchanged()
        } catch let error as CacheUnavailableError {
            batch.rows = batch.rows.map { row in
                guard row.isCacheDependent else { return row }
                var changed = row
                changed.outcome = .cacheUnavailable(error.reason, detail: error.detail)
                return changed
            }
            batch.isPartial = true
        } catch {}
        return batch
    }

    private static func unavailable(entries: [ImportResolutionEntry], error: CacheUnavailableError) -> ImportResolutionBatch {
        let rows = entries.enumerated().map { index, entry -> ImportResolutionRow in
            switch entry.outcome {
            case .miss(let miss):
                return ImportResolutionRow(entryIndex: index, symbolName: entry.symbolName, origin: entry.origin,
                                           outcome: .notCacheResident(.preLookup(miss)))
            case .request:
                return ImportResolutionRow(entryIndex: index, symbolName: entry.symbolName, origin: entry.origin,
                                           outcome: .cacheUnavailable(error.reason, detail: error.detail))
            }
        }
        return ImportResolutionBatch(rows: rows, cacheUUID: nil, isPartial: false, workUnitsUsed: 0)
    }

    // MARK: Batch

    func resolve(
        entries: [ImportResolutionEntry],
        isCancelled: () -> Bool = { false },
        rowObserver: ((Int) -> Void)? = nil
    ) -> ImportResolutionBatch {
        var rows: [ImportResolutionRow] = []
        rows.reserveCapacity(entries.count)
        var stop: CacheUnavailableError?
        var isPartial = false

        let requestCount = entries.reduce(0) { count, entry in
            if case .request = entry.outcome { return count + 1 }
            return count
        }
        if requestCount > limits.maximumRequestsPerBatch {
            stop = CacheUnavailableError(.budgetExceeded, "request count \(requestCount) is over the batch bound")
        } else {
            var distinctInstallNames = Set<String>()
            for case .request(let request) in entries.map(\.outcome) { distinctInstallNames.insert(request.installName) }
            if distinctInstallNames.count > limits.maximumDependencies {
                stop = CacheUnavailableError(.budgetExceeded,
                    "\(distinctInstallNames.count) distinct dependencies is over the bound")
            }
        }

        for (index, entry) in entries.enumerated() {
            let outcome: ImportResolutionOutcome
            switch entry.outcome {
            case .miss(let miss):
                outcome = .notCacheResident(.preLookup(miss))
            case .request(let request):
                if stop == nil, isCancelled() {
                    stop = CacheUnavailableError(.cancelled, "cancelled between requests")
                }
                if let stop {
                    outcome = .cacheUnavailable(stop.reason, detail: stop.detail)
                    isPartial = true
                } else {
                    do {
                        outcome = try resolveOne(request, isCancelled: isCancelled)
                    } catch let error as CacheUnavailableError {
                        outcome = .cacheUnavailable(error.reason, detail: error.detail)
                        // Only shared budgets end the batch; a too-long symbol is that row's own problem.
                        if (error.reason == .budgetExceeded && error.detail == Self.workBudgetDetail)
                            || error.reason == .cancelled {
                            stop = error
                            isPartial = true
                        }
                    } catch {
                        outcome = .cacheUnavailable(.unreadable, detail: "unexpected failure")
                    }
                }
            }
            rows.append(ImportResolutionRow(entryIndex: index, symbolName: entry.symbolName,
                                            origin: entry.origin, outcome: outcome))
            rowObserver?(index)
        }
        return ImportResolutionBatch(rows: rows, cacheUUID: snapshot.cacheUUID,
                                     isPartial: isPartial, workUnitsUsed: workUnits)
    }

    private static let workBudgetDetail = "work budget exhausted"

    // MARK: One request

    private struct PathNode {
        var id: Int
        var image: Int
        var name: [UInt8]
    }

    private struct Frame {
        enum Edge { case root, explicit(renamed: Bool), implicit }
        var id: Int
        var image: Int
        var name: [UInt8]
        var path: [PathNode]
        var edge: Edge
    }

    private struct Candidate {
        var symbol: ResolvedSystemSymbol
        var viaImages: [Int]
        var duplicates: Int
    }

    private func chargeAndCheck(_ units: UInt64, isCancelled: () -> Bool) throws {
        workUnits &+= units
        if workUnits > limits.workBudget {
            throw CacheUnavailableError(.budgetExceeded, Self.workBudgetDetail)
        }
        if workUnits &- lastCancellationCheck >= limits.cancellationCheckInterval {
            lastCancellationCheck = workUnits
            if isCancelled() { throw CacheUnavailableError(.cancelled, "cancelled during a lookup") }
        }
    }

    private func resolveOne(
        _ request: ImportResolutionRequest, isCancelled: () -> Bool
    ) throws -> ImportResolutionOutcome {
        let symbol = Array(request.symbolName.utf8)
        guard !symbol.isEmpty else { return .notCacheResident(.preLookup(.emptySymbolName)) }
        guard symbol.count <= limits.maximumSymbolBytes else {
            throw CacheUnavailableError(.budgetExceeded, "symbol length \(symbol.count) is over the bound")
        }
        guard let rootImage = snapshot.catalogIndex(forInstallName: Array(request.installName.utf8)) else {
            return .notCacheResident(.installNameNotInCache(installName: request.installName))
        }

        var nextID = 1
        var stack = [Frame(id: 0, image: rootImage, name: symbol,
                           path: [PathNode(id: 0, image: rootImage, name: symbol)], edge: .root)]
        var candidates: [Candidate] = []
        var failures: [(ReexportChainFailure, [Int])] = []
        var hitIDs = Set<Int>()
        var failedIDs = Set<Int>()
        var explicitFrames: [(id: Int, renamed: Bool, path: [Int])] = []
        var searched: [Int] = []
        var states = 0

        func record(_ failure: ReexportChainFailure, path: [PathNode]) {
            failures.append((failure, path.map(\.image)))
            for node in path { failedIDs.insert(node.id) }
        }

        while let frame = stack.popLast() {
            states += 1
            if states > limits.maximumVisitedStates {
                record(.stateLimit, path: frame.path)
                break
            }
            try chargeAndCheck(1, isCancelled: isCancelled)
            var loaded = 0
            let descriptor = try descriptors.descriptor(
                for: frame.image, in: snapshot, limits: limits, loaded: &loaded)
            if loaded > 0 { try chargeAndCheck(1_024, isCancelled: isCancelled) }
            if !searched.contains(frame.image) { searched.append(frame.image) }

            var terminals: [ExportTerminal] = []
            var unsupportedTerminal = false
            for trie in descriptor.exportTries {
                var units: UInt64 = 0
                let result = ExportTrieWalker.walk(trie: trie, symbol: frame.name, workUnits: &units)
                try chargeAndCheck(units, isCancelled: isCancelled)
                switch result {
                case .terminal(let terminal): terminals.append(terminal)
                case .noEdge: break
                case .malformed(let detail):
                    throw CacheUnavailableError(.unsupportedFormat,
                        "\(String(decoding: descriptor.path, as: UTF8.self)): \(detail)")
                case .unsupportedFlags: unsupportedTerminal = true
                }
            }
            if unsupportedTerminal {
                record(.unsupportedFlags, path: frame.path)
                continue
            }

            if terminals.isEmpty {
                // Implicit reexport: continue into LC_REEXPORT_DYLIB children in load-command order.
                var children: [Frame] = []
                for ordinal in descriptor.reexportedDependencyOrdinals {
                    let dependency = descriptor.dependencies[ordinal - 1]
                    guard let childImage = snapshot.catalogIndex(forInstallName: dependency.installName) else {
                        record(.edgeTargetNotInCache, path: frame.path)
                        continue
                    }
                    if frame.path.count > limits.maximumReexportDepth {
                        record(.depthLimit, path: frame.path)
                        continue
                    }
                    if frame.path.contains(where: { $0.image == childImage && $0.name == frame.name }) {
                        record(.cycle, path: frame.path + [PathNode(id: -1, image: childImage, name: frame.name)])
                        continue
                    }
                    let id = nextID
                    nextID += 1
                    children.append(Frame(
                        id: id, image: childImage, name: frame.name,
                        path: frame.path + [PathNode(id: id, image: childImage, name: frame.name)], edge: .implicit))
                }
                stack.append(contentsOf: children.reversed())
                continue
            }

            for terminal in terminals {
                switch terminal.payload {
                case .reexport(let ordinal, let importedName):
                    guard ordinal >= 1, ordinal <= UInt64(descriptor.dependencies.count) else {
                        record(.edgeOrdinalOutOfRange, path: frame.path)
                        continue
                    }
                    let dependency = descriptor.dependencies[Int(ordinal) - 1]
                    guard let childImage = snapshot.catalogIndex(forInstallName: dependency.installName) else {
                        record(.edgeTargetNotInCache, path: frame.path)
                        continue
                    }
                    let newName = importedName.isEmpty ? frame.name : importedName
                    guard newName.count <= limits.maximumSymbolBytes else {
                        throw CacheUnavailableError(.budgetExceeded, "reexported symbol length is over the bound")
                    }
                    if frame.path.count > limits.maximumReexportDepth {
                        record(.depthLimit, path: frame.path)
                        continue
                    }
                    if frame.path.contains(where: { $0.image == childImage && $0.name == newName }) {
                        record(.cycle, path: frame.path + [PathNode(id: -1, image: childImage, name: newName)])
                        continue
                    }
                    let id = nextID
                    nextID += 1
                    let path = frame.path + [PathNode(id: id, image: childImage, name: newName)]
                    explicitFrames.append((id, !importedName.isEmpty, path.map(\.image)))
                    stack.append(Frame(id: id, image: childImage, name: newName, path: path,
                                       edge: .explicit(renamed: !importedName.isEmpty)))
                case .address, .stubAndResolver:
                    let symbolValue = try makeSymbol(terminal, descriptor: descriptor, name: frame.name)
                    let viaImages = frame.path.map(\.image)
                    for node in frame.path { hitIDs.insert(node.id) }
                    if let existing = candidates.firstIndex(where: {
                        $0.symbol.imageLoadAddress == symbolValue.imageLoadAddress && $0.symbol.address == symbolValue.address
                    }) {
                        candidates[existing].duplicates += 1
                    } else {
                        candidates.append(Candidate(symbol: symbolValue, viaImages: viaImages, duplicates: 0))
                    }
                }
            }
        }

        // Explicit reexport edges whose target branch found nothing and recorded no failure.
        for edge in explicitFrames where !hitIDs.contains(edge.id) && !failedIDs.contains(edge.id) {
            failures.append((edge.renamed ? .renamedTargetMissing : .targetSymbolMissing, edge.path))
        }

        let unresolvedBranches = failures.count
        if candidates.count >= 2 {
            let sorted = candidates.map {
                AmbiguousCandidate(imagePath: $0.symbol.imagePath, imageLoadAddress: $0.symbol.imageLoadAddress,
                                   address: $0.symbol.address)
            }.sorted()
            return .ambiguous(candidates: Array(sorted.prefix(limits.maximumReportedCandidates)),
                              moreCandidates: sorted.count > limits.maximumReportedCandidates)
        }
        if let only = candidates.first {
            var kindFinal = true
            if case .stubAndResolver = only.symbol.terminalKind { kindFinal = false }
            return .resolved(ResolvedImport(
                symbol: only.symbol,
                viaPath: only.viaImages.map { snapshot.catalog[$0].path },
                isWeakImport: request.isWeakImport,
                isFinalTarget: kindFinal,
                duplicateTerminalCount: only.duplicates,
                incompleteBranches: unresolvedBranches))
        }
        if let first = failures.first {
            return .reexportChain(first.0, viaPath: first.1.map { snapshot.catalog[$0].path })
        }
        return .notExported(searchedImages: searched.map { snapshot.catalog[$0].path })
    }

    private func makeSymbol(
        _ terminal: ExportTerminal, descriptor: ImageDescriptor, name: [UInt8]
    ) throws -> ResolvedSystemSymbol {
        func overflow() -> CacheUnavailableError {
            CacheUnavailableError(.unsupportedFormat,
                "\(String(decoding: descriptor.path, as: UTF8.self)): terminal address overflows")
        }
        let value: UInt64
        let kind: ResolvedTerminalKind
        var resolverOffset: UInt64?
        switch terminal.payload {
        case .address(let v):
            value = v
            kind = terminal.kind == .absolute ? .absolute : terminal.kind == .threadLocal ? .threadLocal : .regular
        case .stubAndResolver(let stub, let resolver):
            value = stub
            kind = .stubAndResolver(resolverOffset: resolver)
            resolverOffset = resolver
        case .reexport:
            throw CacheUnavailableError(.unsupportedFormat, "a reexport terminal carries no address")
        }
        let address: UInt64
        let imageOffset: UInt64?
        if terminal.kind == .absolute, case .address = terminal.payload {
            address = value
            imageOffset = nil
        } else {
            let (sum, didOverflow) = descriptor.loadAddress.addingReportingOverflow(value)
            if didOverflow { throw overflow() }
            address = sum
            imageOffset = value
        }
        var resolverAddress: UInt64?
        if let resolverOffset {
            let (sum, didOverflow) = descriptor.loadAddress.addingReportingOverflow(resolverOffset)
            if didOverflow { throw overflow() }
            resolverAddress = sum
        }
        return ResolvedSystemSymbol(
            cacheUUID: snapshot.cacheUUID, imageUUID: descriptor.uuid, imagePath: descriptor.path,
            imageLoadAddress: descriptor.loadAddress, address: address, imageOffset: imageOffset,
            symbolName: name, terminalKind: kind, isWeakDefinition: terminal.isWeakDefinition,
            resolverAddress: resolverAddress)
    }
}

extension ImportResolutionRow {
    /// Rows decided without consulting the cache never depend on its identity.
    fileprivate var isCacheDependent: Bool {
        if case .notCacheResident(.preLookup) = outcome { return false }
        return true
    }
}
