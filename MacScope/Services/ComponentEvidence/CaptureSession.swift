// Adapted from the AIRS component evidence core at donor commit fa5a2f3128da9134969055cebea145e2ca144214.
// Original relative paths: native/Sources/AIRSCore/BundleDiscovery.swift (descriptor helpers openChild, openRelative,
// metadata, prefix, same) and native/Sources/AIRSCore/ComponentInventory.swift (ComponentInventoryBuilder.capture).
// License: MIT, Copyright (c) 2026 Jeffrey D. Cooney; the notice is in ThirdParty/AIRS/LICENSE.
// Adaptations: one pathname open, then descriptor-relative calls only; the root descriptor is a lexical local of one
// synchronous call; no descriptor, pointer or callable reader is ever stored in or returned from a value.

import Darwin
import Foundation

extension ComponentEvidence {
    /// Test fault seam: consulted at each descriptor operation; a nonnil result is the errno that call fails with.
    typealias FaultInjector = (Operation, PathRange) -> Int32?

    /// Identifies one synchronous capture call. A copied value is powerless once the call has returned.
    struct SessionID: Hashable, Sendable {
        let rawValue: UUID
    }

    /// One shared read ledger for discovery header probes, metadata reads and repeated load captures.
    struct ReadLedger: Sendable, Equatable {
        let limit: Int
        private(set) var used: Int
        init(limit: Int) { self.limit = limit; used = 0 }
        var remaining: Int { limit - used }
        /// Charges the requested bytes conservatively before the attempt. False means the budget is exhausted.
        mutating func charge(_ count: Int) -> Bool {
            guard count >= 0, count <= remaining else { return false }
            used += count
            return true
        }
    }

    /// Lexical syscall wrapper. Constructed inside one capture call; never stored in a published value.
    struct DescriptorOps {
        let fault: FaultInjector

        func failure(_ operation: Operation, _ code: Int32, _ range: PathRange) -> EvidenceError {
            .io(operation, errno: code, range)
        }

        /// The only pathname open of a capture operation.
        func openRoot(_ path: String) throws -> Int32 {
            if let code = fault(.openRoot, .wholeRoot) { throw failure(.openRoot, code, .wholeRoot) }
            let descriptor = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { throw failure(.openRoot, errno, .wholeRoot) }
            return descriptor
        }

        func stat(_ descriptor: Int32, _ range: PathRange) throws -> stat {
            if let code = fault(.statDescriptor, range) { throw failure(.statDescriptor, code, range) }
            var info = Darwin.stat()
            guard Darwin.fstat(descriptor, &info) == 0 else { throw failure(.statDescriptor, errno, range) }
            return info
        }

        func statEntry(_ directory: Int32, _ name: ExactUTF8Key, _ range: PathRange) throws -> stat {
            if let code = fault(.statEntry, range) { throw failure(.statEntry, code, range) }
            var info = Darwin.stat()
            let result = withCName(name) { Darwin.fstatat(directory, $0, &info, AT_SYMLINK_NOFOLLOW) }
            guard result == 0 else { throw failure(.statEntry, errno, range) }
            return info
        }

        func openChild(_ directory: Int32, _ name: ExactUTF8Key, isDirectory: Bool, _ range: PathRange) throws -> Int32 {
            guard RelativePath.isSafe(name.bytes) else { throw EvidenceError.unsafePath(range) }
            let operation: Operation = isDirectory ? .openDirectory : .openFile
            if let code = fault(operation, range) { throw failure(operation, code, range) }
            let flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (isDirectory ? O_DIRECTORY : O_NONBLOCK)
            let descriptor = withCName(name) { Darwin.openat(directory, $0, flags) }
            guard descriptor >= 0 else { throw failure(operation, errno, range) }
            return descriptor
        }

        /// Opens every component from the retained root with no-follow semantics; intermediates close immediately.
        func openRelative(_ root: Int32, _ path: RelativePath, directory: Bool) throws -> Int32 {
            var current = Darwin.dup(root)
            guard current >= 0 else { throw failure(.duplicateDirectory, errno, .leaf(path)) }
            let last = path.components.count - 1
            for (index, component) in path.components.enumerated() {
                let partial = path.prefix(index + 1)
                do {
                    let child = try openChild(current, component, isDirectory: index < last || directory, .leaf(partial))
                    Darwin.close(current)
                    current = child
                } catch {
                    Darwin.close(current)
                    throw error
                }
            }
            return current
        }

        /// Raw entry names of a directory descriptor plus an enumeration errno if readdir failed (nil means EOF).
        func listDirectory(_ directory: Int32, _ range: PathRange) throws -> (names: [ExactUTF8Key], enumerationError: Int32?) {
            if let code = fault(.duplicateDirectory, range) { throw failure(.duplicateDirectory, code, range) }
            let duplicate = Darwin.dup(directory)
            guard duplicate >= 0 else { throw failure(.duplicateDirectory, errno, range) }
            guard let stream = Darwin.fdopendir(duplicate) else {
                let code = errno
                Darwin.close(duplicate)
                throw failure(.openDirectory, code, range)
            }
            defer { Darwin.closedir(stream) }
            var names: [ExactUTF8Key] = []
            let offset = MemoryLayout<dirent>.offset(of: \.d_name) ?? 21
            while true {
                if let code = fault(.enumerate, range) { return (names, code) }
                errno = 0
                guard let entry = Darwin.readdir(stream) else {
                    let code = errno
                    return (names, code == 0 ? nil : code)
                }
                let length = Int(entry.pointee.d_namlen)
                let base = UnsafeRawPointer(entry).advanced(by: offset).assumingMemoryBound(to: UInt8.self)
                let bytes = Array(UnsafeBufferPointer(start: base, count: length))
                if bytes == [0x2e] || bytes == [0x2e, 0x2e] { continue }
                names.append(ExactUTF8Key(rawBytes: bytes))
            }
        }

        /// Exact-count positional read. A short result is a typed shortRead, never padded.
        func read(_ descriptor: Int32, offset: UInt64, count: Int, _ range: PathRange) throws -> [UInt8] {
            guard count >= 0, offset <= UInt64(Int64.max) else { throw EvidenceError.budgetExceeded(.headerBytes, range) }
            if count == 0 { return [] }
            if let code = fault(.read, range) { throw failure(.read, code, range) }
            var bytes = [UInt8](repeating: 0, count: count)
            let amount = bytes.withUnsafeMutableBytes { Darwin.pread(descriptor, $0.baseAddress, count, off_t(offset)) }
            guard amount >= 0 else { throw failure(.read, errno, range) }
            guard amount == count else { throw EvidenceError.shortRead(range, expected: count, actual: amount) }
            return bytes
        }

        func close(_ descriptor: Int32) { Darwin.close(descriptor) }

        private func withCName<T>(_ name: ExactUTF8Key, _ body: (UnsafePointer<CChar>) -> T) -> T {
            var bytes = name.bytes.map { CChar(bitPattern: $0) }
            bytes.append(0)
            return bytes.withUnsafeBufferPointer { body($0.baseAddress!) }
        }

        /// Device, inode, mode, size and both timestamps must agree.
        static func same(_ lhs: stat, _ rhs: stat) -> Bool {
            lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_mode == rhs.st_mode
                && lhs.st_size == rhs.st_size
                && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
                && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
        }
        /// Directory identity only; a directory's size and times legitimately track its own content.
        static func sameObject(_ lhs: stat, _ rhs: stat) -> Bool {
            lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && (lhs.st_mode & S_IFMT) == (rhs.st_mode & S_IFMT)
        }
    }

    /// The live capability of one synchronous call. Passed down as a parameter, never stored or returned.
    struct ActiveSession {
        let id: SessionID
        let root: Int32
        let rootStat: stat
        let ops: DescriptorOps
    }

    // MARK: Capture entry point

    /// One requested observation. Bound to the call that offered it; a copy is powerless afterwards.
    struct CaptureRequest: Sendable, Equatable {
        let session: SessionID
        let inventoryID: UUID
        let componentID: UUID
        let category: DeclarationCategory
        let architecture: ExactUTF8Key?
    }

    struct CaptureResult: Sendable {
        let sessionID: SessionID
        let inventory: ComponentInventory
        let observations: [DeclarationObservation]
        let headerBytesUsed: Int
        let rootIdentity: CaptureRootIdentity?

        /// Retains the original construction shape; it conveys no root observation.
        init(sessionID: SessionID, inventory: ComponentInventory,
             observations: [DeclarationObservation], headerBytesUsed: Int) {
            self.init(sessionID: sessionID, inventory: inventory, observations: observations,
                      headerBytesUsed: headerBytesUsed, rootIdentity: nil)
        }

        init(sessionID: SessionID, inventory: ComponentInventory,
             observations: [DeclarationObservation], headerBytesUsed: Int,
             rootIdentity: CaptureRootIdentity?) {
            self.sessionID = sessionID
            self.inventory = inventory
            self.observations = observations
            self.headerBytesUsed = headerBytesUsed
            self.rootIdentity = rootIdentity
        }
    }

    private static func exclusionState(_ state: DiscoveryState) -> ExclusionState? {
        switch state {
        case .candidate, .malformedHeader, .unsupportedType: nil
        case .nonImage: .nonImage
        case .skippedLink: .skippedLink
        case .skippedSpecial: .skippedSpecial
        case .duplicateFile: .duplicateFile
        case .outsideCodeLocations: .outsideCodeLocations
        case .invalidName: .invalidName
        case .unreadable: .unreadable
        case .changed: .changed
        case .entryLimit: .entryLimit
        case .depthLimit: .depthLimit
        case .candidateLimit: .candidateLimit
        case .headerLimit: .headerLimit
        case .pathLimit: .pathLimit
        }
    }

    private static func scope(_ result: BundleDiscoveryResult, exclusions: [ExclusionRecord], limits: BundleDiscovery.Limits,
                              completion: InventoryCompletion, extraIssues: [EvidenceIssue], headerBytes: Int) -> InventoryScope {
        let keptExclusions = Array(exclusions.prefix(InventoryScope.maximumRecords))
        let allIssues = result.issues + extraIssues
        let keptIssues = Array(allIssues.prefix(InventoryScope.maximumRecords))
        return InventoryScope(
            searchedLocations: Array(result.searchedLocations.prefix(InventoryScope.maximumLocations)), completion: completion,
            exclusions: keptExclusions,
            exclusionOverflow: exclusions.count > InventoryScope.maximumRecords
                ? OverflowFact(observed: exclusions.count, retained: InventoryScope.maximumRecords) : nil,
            issues: keptIssues,
            issueOverflow: allIssues.count > InventoryScope.maximumRecords
                ? OverflowFact(observed: allIssues.count, retained: InventoryScope.maximumRecords) : nil,
            visited: result.visited, headerBytes: headerBytes, remainderUnknown: result.remainderUnknown,
            limitEntries: limits.entries, limitDepth: limits.depth, limitCandidates: limits.candidates,
            limitHeaderBytes: limits.headerBytes)
    }

    /// Opens the selected `.app` root once, discovers components, offers the live inventory to `choose`, then captures
    /// the requested observations. The root descriptor never leaves this call.
    static func capture(selection: URL, limits: BundleDiscovery.Limits = BundleDiscovery.Limits(),
                        fault: FaultInjector = { _, _ in nil }, signatureSink: SignatureSink? = nil,
                        choose: (LiveComponentInventory, SessionID) -> [CaptureRequest]) throws -> CaptureResult {
        try limits.validate()
        guard selection.isFileURL else { throw EvidenceError.invalidSelection }
        let path = selection.path
        let ext = (path as NSString).pathExtension
        guard ext.utf8.count == 3, ext.utf8.map({ $0 | 0x20 }).elementsEqual("app".utf8) else { throw EvidenceError.invalidSelection }
        let sessionID = SessionID(rawValue: UUID())
        let inventoryID = UUID()
        if Task.isCancelled {
            let empty = InventoryScope(searchedLocations: [], completion: .cancelled, exclusions: [], exclusionOverflow: nil,
                issues: [EvidenceIssue(.cancelled)], issueOverflow: nil, visited: 0, headerBytes: 0, remainderUnknown: true,
                limitEntries: limits.entries, limitDepth: limits.depth, limitCandidates: limits.candidates,
                limitHeaderBytes: limits.headerBytes)
            return CaptureResult(sessionID: sessionID, inventory: ComponentInventory(id: inventoryID, components: [], scope: empty),
                                 observations: [], headerBytesUsed: 0, rootIdentity: nil)
        }
        return try withoutActuallyEscaping(fault) { escaping in
            let ops = DescriptorOps(fault: escaping)
            let root = try ops.openRoot(path)
            defer { ops.close(root) }
            let rootStat = try ops.stat(root, .wholeRoot)
            guard (rootStat.st_mode & S_IFMT) == S_IFDIR else { throw EvidenceError.invalidSelection }
            let session = ActiveSession(id: sessionID, root: root, rootStat: rootStat, ops: ops)
            var ledger = ReadLedger(limit: limits.headerBytes)
            let discovery = try BundleDiscovery(limits: limits).discover(session, inventoryID: inventoryID, ledger: &ledger)

            // Components
            typealias Declared = (id: ExactUTF8Key?, version: ExactUTF8Key?, executable: ExactUTF8Key?, issue: EvidenceIssue?)
            var infoCache: [RelativePath: Declared] = [:]
            func declared(_ locations: CodeUnitDeclarationLocations) -> Declared {
                if let cached = infoCache[locations.infoPath] { return cached }
                var value: Declared = (nil, nil, nil, nil)
                do {
                    let bytes = try BundleDiscovery.readSmallFile(session, path: locations.infoPath)
                    let dictionary = try BundleDiscovery.decodePlist(bytes, source: locations.infoPath, category: .info)
                    value.id = (dictionary.object(forKey: "CFBundleIdentifier") as? String).map { ExactUTF8Key($0) }
                    value.version = ((dictionary.object(forKey: "CFBundleShortVersionString") as? String)
                        ?? (dictionary.object(forKey: "CFBundleVersion") as? String)).map { ExactUTF8Key($0) }
                    value.executable = try BundleDiscovery.declaredExecutable(dictionary, source: locations.infoPath)
                } catch let error as EvidenceError {
                    value.issue = EvidenceIssue(error, range: .leaf(locations.infoPath))
                } catch {}
                infoCache[locations.infoPath] = value
                return value
            }
            var records: [ComponentRecord] = []
            var boundByPrefix: [RelativePath: UUID] = [:]
            var provenance: [UUID: BundleImageProvenance] = [:]
            var cancelled = discovery.cancelled
            for entry in discovery.entries where entry.state == .candidate || entry.state == .malformedHeader || entry.state == .unsupportedType {
                guard let entryPath = entry.path, let locations = CodeUnitDeclarationLocations.locations(for: entryPath) else { continue }
                if records.count >= ComponentInventory.maximumComponents { break }
                var issues: [EvidenceIssue] = entry.issue.map { [$0] } ?? []
                var slices: [Slice] = []
                var available = false
                if entry.state == .candidate, let identity = entry.provenance {
                    if Task.isCancelled { cancelled = true; issues.append(EvidenceIssue(.cancelled, range: .leaf(entryPath))) }
                    else {
                        do {
                            try CodeUnitPreflight.revalidate(identity, session: session)
                            let handle = try ops.openRelative(root, entryPath, directory: false)
                            defer { ops.close(handle) }
                            let range = PathRange.leaf(entryPath)
                            let before = try ops.stat(handle, range)
                            let outcome = ComponentMetadataReader(captureLoadCommands: false).read(
                                size: UInt64(max(0, before.st_size)), range: range, ledger: &ledger) { offset, count in
                                try ops.read(handle, offset: offset, count: count, range)
                            }
                            if let failure = outcome.failure {
                                issues.append(EvidenceIssue(failure, range: range))
                                if case .cancelled = failure { cancelled = true }
                            } else if !DescriptorOps.same(before, try ops.stat(handle, range)) {
                                issues.append(EvidenceIssue(.changedInput(range), range: range))
                            } else {
                                slices = outcome.slices; available = true
                                if let signatureSink {
                                    signatureSink(entryPath, SignatureEvidenceReader.captureHeld(ops: ops, handle: handle, range: range, before: before, ledger: &ledger))
                                }
                            }
                            provenance[entry.id] = identity
                        } catch let error as EvidenceError {
                            issues.append(EvidenceIssue(error, range: .leaf(entryPath)))
                        } catch {}
                    }
                }
                let raw: Declared = entry.state == .candidate ? declared(locations) : (nil, nil, nil, nil)
                // Labels are only taken from the exact executable binding: same directory, same declared name.
                let bound = raw.executable != nil && entryPath.parent == locations.executablePrefix && entryPath.last == raw.executable
                if let issue = raw.issue { issues.append(issue) }
                else if entry.state == .candidate, raw.executable == nil, entryPath.parent == locations.executablePrefix {
                    issues.append(EvidenceIssue(.malformedMetadata(.info, .leaf(locations.infoPath), .executablePathMismatch), range: .leaf(entryPath)))
                }
                let info: (id: ExactUTF8Key?, version: ExactUTF8Key?) = bound ? (raw.id, raw.version) : (nil, nil)
                if bound { boundByPrefix[locations.executablePrefix] = entry.id }
                let kept = Array(issues.prefix(ComponentRecord.maximumIssues))
                records.append(ComponentRecord(
                    id: entry.id, parentID: nil, path: entryPath, kind: locations.kind, declaredBundleID: info.id,
                    declaredVersion: info.version, architectures: slices.map(\.architecture),
                    minimumOS: slices.compactMap { slice in slice.minimumOS.map { ArchitectureMinimum(architecture: slice.architecture, minimum: $0) } },
                    slices: slices, issues: kept,
                    issueOverflow: issues.count > ComponentRecord.maximumIssues
                        ? OverflowFact(observed: issues.count, retained: ComponentRecord.maximumIssues) : nil,
                    metadataAvailable: available, isDeclarationOnly: false))
            }
            var declarationOnlyPath: RelativePath?
            if case .unresolved = discovery.principal {
                declarationOnlyPath = BundleDiscovery.infoPath
                let info = CodeUnitDeclarationLocations.locations(for: RelativePath(unchecked: ["Contents", "MacOS", "x"].map { ExactUTF8Key($0) }))!
                let declaredInfo = declared(info)
                records.append(ComponentRecord(
                    id: UUID(), parentID: nil, path: BundleDiscovery.infoPath, kind: ExactUTF8Key("app"),
                    declaredBundleID: declaredInfo.id, declaredVersion: declaredInfo.version, architectures: [], minimumOS: [],
                    slices: [], issues: [], issueOverflow: nil, metadataAvailable: false, isDeclarationOnly: true))
            }
            records = records.map { record in
                guard let container = CodeUnitDeclarationLocations.locations(for: record.path)?.container,
                      let outer = CodeUnitDeclarationLocations.locations(for: container),
                      let parent = boundByPrefix[outer.executablePrefix], parent != record.id else { return record }
                return ComponentRecord(id: record.id, parentID: parent, path: record.path, kind: record.kind, declaredBundleID: record.declaredBundleID,
                    declaredVersion: record.declaredVersion, architectures: record.architectures, minimumOS: record.minimumOS, slices: record.slices,
                    issues: record.issues, issueOverflow: record.issueOverflow, metadataAvailable: record.metadataAvailable, isDeclarationOnly: record.isDeclarationOnly)
            }
            records.sort { $0.path < $1.path }

            var exclusions: [ExclusionRecord] = []
            for entry in discovery.entries {
                guard let state = exclusionState(entry.state) else { continue }
                if state == .outsideCodeLocations, entry.path == declarationOnlyPath { continue }
                exclusions.append(ExclusionRecord(range: entry.range, rawPath: entry.rawPath, state: state,
                                                  canonicalPath: entry.canonicalPath, omittedCount: entry.omittedCount))
            }
            var completion: InventoryCompletion = cancelled ? .cancelled : (discovery.partial ? .partial : .complete)
            if completion == .complete, exclusions.count > InventoryScope.maximumRecords || discovery.issues.count > InventoryScope.maximumRecords { completion = .partial }
            if records.contains(where: { !$0.metadataAvailable && !$0.isDeclarationOnly }) && completion == .complete { completion = .partial }
            let preliminary = ComponentInventory(id: inventoryID, components: records, scope: scope(
                discovery, exclusions: exclusions, limits: limits, completion: completion, extraIssues: [], headerBytes: ledger.used))
            try preliminary.validate()
            let live = LiveComponentInventory(inventory: preliminary, provenance: provenance,
                                              resourceDeclarations: discovery.resourceDeclarations, session: sessionID)

            // Requests
            let requests = choose(live, sessionID)
            guard requests.count <= maximumObservations else { throw EvidenceError.budgetExceeded(.observations, .wholeRoot) }
            var seen = Set<String>()
            for request in requests {
                guard request.session == sessionID else { throw EvidenceError.staleCapability }
                guard request.inventoryID == inventoryID else { throw EvidenceError.invalidObservation(.inventoryMismatch) }
                guard preliminary.component(request.componentID) != nil else { throw EvidenceError.unknownComponent }
                let architectureOK = request.category == .loadCommands ? request.architecture != nil : request.architecture == nil
                guard architectureOK else { throw EvidenceError.invalidObservation(.wrongArchitectureField) }
                let key = "\(request.componentID.uuidString)|\(request.category.rawValue)|\(request.architecture?.display ?? "")"
                guard seen.insert(key).inserted else { throw EvidenceError.invalidObservation(.duplicateObservation) }
            }
            var observations: [DeclarationObservation] = []
            var cancelledDuringRequests = false
            for request in requests {
                let component = preliminary.component(request.componentID)!
                if Task.isCancelled || cancelledDuringRequests {
                    cancelledDuringRequests = true
                    observations.append(try DeclarationObservation(
                        inventoryID: inventoryID, componentID: component.id, category: request.category, architecture: request.architecture,
                        state: .unavailable, issue: EvidenceIssue(.cancelled, range: .leaf(component.path))))
                    continue
                }
                switch request.category {
                case .info: observations.append(try InfoDeclarations.capture(session, inventoryID: inventoryID, component: component))
                case .privacy: observations.append(try PrivacyDeclarations.capture(session, inventoryID: inventoryID, component: component))
                case .loadCommands:
                    observations.append(try LoaderDeclarations.capture(session, inventoryID: inventoryID, component: component,
                                                                       architecture: request.architecture!, provenance: provenance[component.id], ledger: &ledger))
                }
            }
            let finalCompletion: InventoryCompletion = (cancelled || cancelledDuringRequests) ? .cancelled : completion
            let final = ComponentInventory(id: inventoryID, components: records, scope: scope(
                discovery, exclusions: exclusions, limits: limits, completion: finalCompletion,
                extraIssues: cancelledDuringRequests ? [EvidenceIssue(.cancelled)] : [], headerBytes: ledger.used))
            try final.validate()
            return CaptureResult(sessionID: sessionID, inventory: final, observations: observations, headerBytesUsed: ledger.used,
                                 rootIdentity: CaptureRootIdentity(device: discovery.rootDevice, inode: discovery.rootInode))
        }
    }
}
