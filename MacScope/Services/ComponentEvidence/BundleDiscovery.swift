// Adapted from the AIRS component evidence core at donor commit fa5a2f3128da9134969055cebea145e2ca144214.
// Original relative path: native/Sources/AIRSCore/BundleDiscovery.swift.
// License: MIT, Copyright (c) 2026 Jeffrey D. Cooney; the notice is in ThirdParty/AIRS/LICENSE.
// Adaptations: whole-root descriptor-relative walk with typed exclusions instead of a six-location scan; raw
// directory-entry bytes; no pathname reopening, canonical URL resolution or free-text states; per-call session
// descriptors; numeric inode policy with deterministic canonical names; typed failures instead of ReportError.

import Darwin
import Foundation

extension ComponentEvidence {
    enum DiscoveryState: String, Sendable, Hashable {
        case candidate, malformedHeader, unsupportedType, nonImage, skippedLink, skippedSpecial, duplicateFile
        case outsideCodeLocations, invalidName, unreadable, changed
        case entryLimit, depthLimit, candidateLimit, headerLimit, pathLimit
    }

    /// Captured identity of one admitted candidate, bound to the call that discovered it. No descriptor, no URL.
    struct BundleImageProvenance: Sendable, Equatable {
        let session: SessionID
        let inventoryID: UUID
        let path: RelativePath
        let rootDevice: UInt64
        let rootInode: UInt64
        let fileIdentity: ResumeFileIdentity
    }

    struct BundleDiscoveryEntry: Sendable, Identifiable {
        let id: UUID
        /// Exact raw path bytes, kept even when a retained RelativePath cannot name the observation.
        let rawPath: ExactUTF8Key
        let path: RelativePath?
        let state: DiscoveryState
        let range: PathRange
        let issue: EvidenceIssue?
        let provenance: BundleImageProvenance?
        let physical: PhysicalFileKey?
        /// For duplicateFile: the entry that holds the physical file's one canonical name.
        let canonicalEntryID: UUID?
        let canonicalPath: RelativePath?
        let isPrincipal: Bool
        let omittedCount: Int
        var selectable: Bool { provenance != nil }
    }

    enum PrincipalStatus: Sendable, Equatable {
        case declared(RelativePath)
        case unresolved
    }

    /// Captured declaration bytes confer no executable or code-unit capability.
    struct BundleResourceDeclarations: Sendable, Equatable {
        let info: [UInt8]
        let privacyState: DeclarationState
        let privacy: [UInt8]?
        let privacyIssue: EvidenceIssue?
    }

    struct BundleDiscoveryResult: Sendable, Identifiable {
        let id: UUID
        let entries: [BundleDiscoveryEntry]
        let partial: Bool
        let cancelled: Bool
        let visited: Int
        let headerBytes: Int
        let searchedLocations: [SearchLocation]
        let issues: [EvidenceIssue]
        let remainderUnknown: Bool
        let principal: PrincipalStatus
        let resourceDeclarations: BundleResourceDeclarations?
        let rootDevice: UInt64
        let rootInode: UInt64
    }

    struct BundleDiscovery: Sendable {
        struct Limits: Sendable, Equatable {
            let entries: Int
            let depth: Int
            let candidates: Int
            let headerBytes: Int
            init(entries: Int = 4096, depth: Int = 12, candidates: Int = 128, headerBytes: Int = 1_048_576) {
                self.entries = entries; self.depth = depth; self.candidates = candidates; self.headerBytes = headerBytes
            }
            func validate() throws {
                guard entries > 0, entries <= 4096 else { throw EvidenceError.invalidLimits(.entries) }
                guard depth > 0, depth <= 12 else { throw EvidenceError.invalidLimits(.depth) }
                guard candidates > 0, candidates <= 128 else { throw EvidenceError.invalidLimits(.candidates) }
                guard headerBytes >= 4096, headerBytes <= 1_048_576 else { throw EvidenceError.invalidLimits(.headerBytes) }
            }
        }

        static let codeLocations: [RelativePath] = [
            ["Contents", "MacOS"], ["Contents", "Frameworks"], ["Contents", "PlugIns"],
            ["Contents", "XPCServices"], ["Contents", "Helpers"], ["Contents", "Library", "LoginItems"],
        ].map { RelativePath(unchecked: $0.map { ExactUTF8Key($0) }) }
        static let infoPath = RelativePath(unchecked: [ExactUTF8Key("Contents"), ExactUTF8Key("Info.plist")])
        static let privacyPath = RelativePath(unchecked: ["Contents", "Resources", "PrivacyInfo.xcprivacy"].map { ExactUTF8Key($0) })
        static let maximumPlistBytes = 65_536
        static let headerProbeBytes = 4096

        let limits: Limits
        init(limits: Limits = Limits()) { self.limits = limits }

        // MARK: Plist helpers shared with the code-unit preflight

        static func decodePlist(_ bytes: [UInt8], source: RelativePath, category: DeclarationCategory) throws -> NSDictionary {
            let range = PathRange.leaf(source)
            guard !bytes.isEmpty, bytes.count <= maximumPlistBytes else {
                throw EvidenceError.malformedMetadata(category, range, bytes.isEmpty ? .badPlist : .oversize)
            }
            // Only XML and binary property lists count; lenient old-style text would turn blank bytes into an empty dictionary.
            var format = PropertyListSerialization.PropertyListFormat.openStep
            guard let object = try? PropertyListSerialization.propertyList(from: Data(bytes), format: &format), format != .openStep else {
                throw EvidenceError.malformedMetadata(category, range, .badPlist)
            }
            guard let dictionary = object as? NSDictionary else { throw EvidenceError.malformedMetadata(category, range, .notDictionary) }
            return dictionary
        }

        /// The declared executable name, nil when the key is absent; a present but unsafe value throws.
        static func declaredExecutable(_ dictionary: NSDictionary, source: RelativePath) throws -> ExactUTF8Key? {
            guard let declared = dictionary.object(forKey: "CFBundleExecutable") else { return nil }
            guard let name = declared as? String, !name.isEmpty, name != ".", name != "..", name.utf8.count <= 255,
                  !name.contains("/"), !name.contains("\\"), !name.contains("\0") else {
                throw EvidenceError.malformedMetadata(.info, .leaf(source), .invalidExecutable)
            }
            return ExactUTF8Key(name)
        }

        /// A bounded regular file read in full through the retained session, bracketed by stability checks.
        static func readSmallFile(_ session: ActiveSession, path: RelativePath) throws -> [UInt8] {
            let range = PathRange.leaf(path)
            let ops = session.ops
            let file = try ops.openRelative(session.root, path, directory: false)
            defer { ops.close(file) }
            let before = try ops.stat(file, range)
            guard (before.st_mode & S_IFMT) == S_IFREG else { throw EvidenceError.malformedMetadata(nil, range, .notRegularFile) }
            guard before.st_size > 0, before.st_size <= Int64(maximumPlistBytes) else {
                throw EvidenceError.malformedMetadata(nil, range, before.st_size == 0 ? .badPlist : .oversize)
            }
            let bytes = try ops.read(file, offset: 0, count: Int(before.st_size), range)
            guard DescriptorOps.same(before, try ops.stat(file, range)) else { throw EvidenceError.changedInput(range) }
            return bytes
        }

        // MARK: Discovery

        func discover(_ session: ActiveSession, inventoryID: UUID, ledger: inout ReadLedger) throws -> BundleDiscoveryResult {
            try limits.validate()
            let ops = session.ops
            let rootStat = session.rootStat
            let contents = try ops.openChild(session.root, ExactUTF8Key("Contents"), isDirectory: true, .leaf(RelativePath(unchecked: [ExactUTF8Key("Contents")])))
            ops.close(contents)
            // Required root Info.plist: bounded, regular, stable, a dictionary with a safe principal declaration.
            let infoRange = PathRange.leaf(Self.infoPath)
            let plistFD = try ops.openRelative(session.root, Self.infoPath, directory: false)
            defer { ops.close(plistFD) }
            let plistStat = try ops.stat(plistFD, infoRange)
            guard (plistStat.st_mode & S_IFMT) == S_IFREG else { throw EvidenceError.malformedMetadata(.info, infoRange, .notRegularFile) }
            guard plistStat.st_size > 0, plistStat.st_size <= Int64(Self.maximumPlistBytes) else {
                throw EvidenceError.malformedMetadata(.info, infoRange, plistStat.st_size == 0 ? .badPlist : .oversize)
            }
            let plistBytes = try ops.read(plistFD, offset: 0, count: Int(plistStat.st_size), infoRange)
            let dictionary = try Self.decodePlist(plistBytes, source: Self.infoPath, category: .info)
            let executable = try Self.declaredExecutable(dictionary, source: Self.infoPath)
            let principalPath = try executable.map { try Self.infoPath.parent!.appending(ExactUTF8Key("MacOS")).appending($0) }

            var walker = Walker(session: session, limits: limits, inventoryID: inventoryID, ledger: ledger)
            walker.walk(directory: session.root, path: [], depth: 0)
            ledger = walker.ledger
            if Task.isCancelled { walker.cancelled = true; walker.partial = true }
            let searched = walker.searchedLocations()
            let entries = walker.resolve(principalPath: principalPath, rootStat: rootStat)

            var issues = walker.issues
            var partial = walker.partial
            var declarations: BundleResourceDeclarations?
            let principal: PrincipalStatus
            if let principalPath {
                principal = .declared(principalPath)
                if !entries.contains(where: { $0.path == principalPath && $0.selectable }) {
                    partial = true
                    issues.append(EvidenceIssue(.principalUnavailable(.leaf(principalPath)), range: .leaf(principalPath)))
                }
            } else {
                principal = .unresolved
                partial = true
                issues.append(EvidenceIssue(.principalUnresolved, range: .wholeRoot))
                declarations = capturePrivacy(session, plist: plistBytes, cancelled: &walker.cancelled)
            }
            // Root and Info.plist must still be the same objects after the walk.
            let finalPlist = try? ops.stat(plistFD, infoRange)
            let finalRoot = try? ops.stat(session.root, .wholeRoot)
            if finalPlist.map({ !DescriptorOps.same(plistStat, $0) }) ?? true || finalRoot.map({ !DescriptorOps.same(rootStat, $0) }) ?? true {
                declarations = nil
                partial = true
                issues.append(EvidenceIssue(.changedInput(.wholeRoot), range: .wholeRoot))
            }
            if walker.cancelled { partial = true }
            return BundleDiscoveryResult(
                id: inventoryID, entries: entries, partial: partial, cancelled: walker.cancelled, visited: walker.visited,
                headerBytes: walker.ledger.used, searchedLocations: searched, issues: issues,
                remainderUnknown: walker.remainderUnknown, principal: principal, resourceDeclarations: declarations,
                rootDevice: UInt64(UInt32(bitPattern: rootStat.st_dev)), rootInode: rootStat.st_ino)
        }

        private func capturePrivacy(_ session: ActiveSession, plist: [UInt8], cancelled: inout Bool) -> BundleResourceDeclarations {
            if Task.isCancelled {
                cancelled = true
                return .init(info: plist, privacyState: .unavailable, privacy: nil,
                             privacyIssue: EvidenceIssue(.cancelled, range: .leaf(Self.privacyPath)))
            }
            do {
                let bytes = try Self.readSmallFile(session, path: Self.privacyPath)
                _ = try Self.decodePlist(bytes, source: Self.privacyPath, category: .privacy)
                return .init(info: plist, privacyState: .present, privacy: bytes, privacyIssue: nil)
            } catch EvidenceError.io(_, let code, _) where code == ENOENT {
                return .init(info: plist, privacyState: .notPresent, privacy: nil, privacyIssue: nil)
            } catch let error as EvidenceError {
                return .init(info: plist, privacyState: .unavailable, privacy: nil,
                             privacyIssue: EvidenceIssue(error, range: .leaf(Self.privacyPath)))
            } catch {
                return .init(info: plist, privacyState: .unavailable, privacy: nil,
                             privacyIssue: EvidenceIssue(.malformedMetadata(.privacy, .leaf(Self.privacyPath), .badPlist), range: .leaf(Self.privacyPath)))
            }
        }

        // MARK: Header classification (hints only; the metadata reader is the authority on valid slices)

        enum HeaderClass: Equatable {
            case image, nonImage, malformed(MetadataReason), unsupported
        }

        static func classify(_ bytes: [UInt8], size: UInt64) -> HeaderClass {
            guard bytes.count >= 4 else { return .nonImage }
            let magic = Array(bytes.prefix(4))
            func number(_ start: Int, little: Bool) -> UInt32 {
                (0..<4).reduce(UInt32(0)) { $0 | UInt32(bytes[start + $1]) << UInt32((little ? $1 : 3 - $1) * 8) }
            }
            let thin: [[UInt8]] = [[0xcf, 0xfa, 0xed, 0xfe], [0xfe, 0xed, 0xfa, 0xcf], [0xce, 0xfa, 0xed, 0xfe], [0xfe, 0xed, 0xfa, 0xce]]
            if thin.contains(magic) {
                guard bytes.count >= (magic.contains(0xcf) ? 32 : 28) else { return .malformed(.truncated) }
                let little = magic[0] == 0xcf || magic[0] == 0xce
                let type = number(12, little: little)
                guard [2, 6, 8].contains(type) else { return .unsupported }
                return .image
            }
            let fat: [[UInt8]] = [[0xca, 0xfe, 0xba, 0xbe], [0xbe, 0xba, 0xfe, 0xca], [0xca, 0xfe, 0xba, 0xbf], [0xbf, 0xba, 0xfe, 0xca]]
            if fat.contains(magic) {
                guard bytes.count >= 8 else { return .malformed(.truncated) }
                let little = magic[0] == 0xbe || magic[0] == 0xbf
                let count = number(4, little: little), stride = magic.contains(0xbf) ? 32 : 20
                guard count > 0, count <= 64, UInt64(8 + Int(count) * stride) <= size, 8 + Int(count) * stride <= bytes.count else {
                    return .malformed(.badUniversalLayout)
                }
                return .image
            }
            return .nonImage
        }

        // MARK: Walker (function-local mutable state; never stored or published)

        private struct Fact {
            let path: RelativePath?
            let raw: ExactUTF8Key
            let state: DiscoveryState
            let range: PathRange
            let issue: EvidenceIssue?
            let physical: PhysicalFileKey?
            let inCode: Bool
            let identity: ResumeFileIdentity?
            let omitted: Int
        }

        private struct Walker {
            let session: ActiveSession
            let limits: Limits
            let inventoryID: UUID
            var ledger: ReadLedger
            var visited = 0
            var stopped = false
            var cancelled = false
            var partial = false
            var remainderUnknown = false
            var candidates = 0
            var facts: [Fact] = []
            var issues: [EvidenceIssue] = []
            var seenCandidates = Set<PhysicalFileKey>()
            var listings: [ExactUTF8Key: Set<ExactUTF8Key>] = [:]
            var nonDirectories = Set<ExactUTF8Key>()

            init(session: ActiveSession, limits: Limits, inventoryID: UUID, ledger: ReadLedger) {
                self.session = session; self.limits = limits; self.inventoryID = inventoryID
                self.ledger = ReadLedger(limit: min(ledger.limit, limits.headerBytes))
                _ = self.ledger.charge(ledger.used)
            }

            static func key(_ path: [ExactUTF8Key]) -> ExactUTF8Key {
                ExactUTF8Key(rawBytes: RelativePath.joined(path))
            }

            static func inCode(_ path: [ExactUTF8Key]) -> Bool {
                BundleDiscovery.codeLocations.contains { location in
                    path.count > location.components.count && Array(path.prefix(location.components.count)) == location.components
                }
            }

            mutating func record(_ path: [ExactUTF8Key], raw: ExactUTF8Key? = nil, _ state: DiscoveryState, _ range: PathRange,
                                 issue: EvidenceIssue? = nil, physical: PhysicalFileKey? = nil, identity: ResumeFileIdentity? = nil,
                                 omitted: Int = 0, partial isPartial: Bool = true) {
                let relative: RelativePath? = path.isEmpty ? nil : RelativePath(unchecked: path)
                facts.append(Fact(path: relative, raw: raw ?? ExactUTF8Key(rawBytes: RelativePath.joined(path)), state: state, range: range,
                                  issue: issue, physical: physical, inCode: Walker.inCode(path), identity: identity, omitted: omitted))
                if isPartial { partial = true }
            }

            mutating func stop(_ limit: LimitKind, _ state: DiscoveryState, path: [ExactUTF8Key], range: PathRange) {
                record(path, state, range, issue: EvidenceIssue(.budgetExceeded(limit, range), range: range))
                issues.append(EvidenceIssue(.budgetExceeded(limit, range), range: range))
                stopped = true
                remainderUnknown = true
            }

            mutating func checkCancelled(_ range: PathRange) -> Bool {
                guard Task.isCancelled else { return false }
                if !cancelled { issues.append(EvidenceIssue(.cancelled, range: range)) }
                cancelled = true; partial = true; stopped = true; remainderUnknown = true
                return true
            }

            mutating func ioFailure(_ path: [ExactUTF8Key], _ error: Error, _ range: PathRange) {
                let typed = (error as? EvidenceError) ?? .io(.read, errno: EIO, range)
                record(path, .unreadable, range, issue: EvidenceIssue(typed, range: range))
            }

            mutating func walk(directory: Int32, path: [ExactUTF8Key], depth: Int) {
                let range: PathRange = path.isEmpty ? .wholeRoot : .subtree(RelativePath(unchecked: path))
                if checkCancelled(range) || stopped { return }
                guard depth <= limits.depth else {
                    record(path, .depthLimit, range, issue: EvidenceIssue(.budgetExceeded(.depth, range), range: range))
                    issues.append(EvidenceIssue(.budgetExceeded(.depth, range), range: range))
                    return
                }
                let ops = session.ops
                let before: stat
                let listing: (names: [ExactUTF8Key], enumerationError: Int32?)
                do {
                    before = try ops.stat(directory, range)
                    listing = try ops.listDirectory(directory, range)
                } catch {
                    ioFailure(path, error, range)
                    return
                }
                var accepted: [ExactUTF8Key] = []
                for name in listing.names {
                    if checkCancelled(range) { return }
                    guard visited < limits.entries else {
                        stop(.entries, .entryLimit, path: path, range: range)
                        return
                    }
                    // Every captured entry is charged, including invalid names.
                    visited += 1
                    accepted.append(name)
                }
                if let code = listing.enumerationError {
                    let error = EvidenceError.io(.enumerate, errno: code, range)
                    record(path, .unreadable, range, issue: EvidenceIssue(error, range: range))
                } else {
                    listings[Walker.key(path)] = Set(accepted)
                }
                var pathLimited = 0
                for name in accepted.sorted() {
                    if checkCancelled(range) || stopped { return }
                    let child = path + [name]
                    if RelativePath.joined(child).count > RelativePath.maximumBytes {
                        pathLimited += 1
                        continue
                    }
                    let childRange = PathRange.subtree(RelativePath(unchecked: child))
                    guard name.text != nil, !name.bytes.contains(0x5c) else {
                        record(child, .invalidName, childRange, issue: EvidenceIssue(.unsafePath(childRange), range: childRange))
                        continue
                    }
                    let entry: stat
                    do { entry = try ops.statEntry(directory, name, .leaf(RelativePath(unchecked: child))) }
                    catch { ioFailure(child, error, .leaf(RelativePath(unchecked: child))); continue }
                    let leaf = PathRange.leaf(RelativePath(unchecked: child))
                    switch entry.st_mode & S_IFMT {
                    case S_IFLNK:
                        nonDirectories.insert(Walker.key(child))
                        record(child, .skippedLink, childRange, partial: false)
                    case S_IFDIR:
                        guard depth + 1 <= limits.depth else {
                            record(child, .depthLimit, childRange, issue: EvidenceIssue(.budgetExceeded(.depth, childRange), range: childRange))
                            issues.append(EvidenceIssue(.budgetExceeded(.depth, childRange), range: childRange))
                            continue
                        }
                        do {
                            let handle = try ops.openChild(directory, name, isDirectory: true, childRange)
                            defer { ops.close(handle) }
                            let opened = try ops.stat(handle, childRange)
                            guard DescriptorOps.sameObject(entry, opened) else {
                                record(child, .changed, childRange, issue: EvidenceIssue(.changedInput(childRange), range: childRange))
                                continue
                            }
                            walk(directory: handle, path: child, depth: depth + 1)
                        } catch { ioFailure(child, error, childRange) }
                    case S_IFREG:
                        nonDirectories.insert(Walker.key(child))
                        file(directory: directory, name: name, path: child, entry: entry, leaf: leaf)
                    default:
                        nonDirectories.insert(Walker.key(child))
                        record(child, .skippedSpecial, leaf, partial: false)
                    }
                }
                if pathLimited > 0 {
                    let issue = EvidenceIssue(.budgetExceeded(.pathBytes, range), range: range)
                    record(path, .pathLimit, range, issue: issue, omitted: pathLimited)
                    issues.append(issue)
                    remainderUnknown = true
                }
                if let after = try? ops.stat(directory, range), !DescriptorOps.same(before, after) {
                    record(path, .changed, range, issue: EvidenceIssue(.changedInput(range), range: range))
                    listings[Walker.key(path)] = nil
                }
            }

            mutating func file(directory: Int32, name: ExactUTF8Key, path: [ExactUTF8Key], entry: stat, leaf: PathRange) {
                let ops = session.ops
                let relative = RelativePath(unchecked: path)
                let physical = PhysicalFileKey(entry)
                guard Walker.inCode(path) else {
                    record(path, .outsideCodeLocations, leaf, physical: physical, partial: false)
                    return
                }
                let handle: Int32
                do { handle = try ops.openChild(directory, name, isDirectory: false, leaf) }
                catch { ioFailure(path, error, leaf); return }
                defer { ops.close(handle) }
                do {
                    let before = try ops.stat(handle, leaf)
                    guard DescriptorOps.same(entry, before), (before.st_mode & S_IFMT) == S_IFREG else {
                        record(path, .changed, leaf, issue: EvidenceIssue(.changedInput(leaf), range: leaf)); return
                    }
                    let count = Int(min(before.st_size, Int64(BundleDiscovery.headerProbeBytes)))
                    guard ledger.charge(count) else {
                        stop(.headerBytes, .headerLimit, path: path, range: leaf)
                        return
                    }
                    let bytes = try ops.read(handle, offset: 0, count: count, leaf)
                    guard DescriptorOps.same(before, try ops.stat(handle, leaf)) else {
                        record(path, .changed, leaf, issue: EvidenceIssue(.changedInput(leaf), range: leaf)); return
                    }
                    let identity = ResumeFileIdentity(path: relative, stat: before)
                    switch BundleDiscovery.classify(bytes, size: UInt64(before.st_size)) {
                    case .nonImage:
                        record(path, .nonImage, leaf, physical: physical, identity: identity, partial: false)
                    case .malformed(let reason):
                        let issue = EvidenceIssue(.malformedHeader(leaf, reason), range: leaf)
                        record(path, .malformedHeader, leaf, issue: issue, physical: physical, identity: identity)
                    case .unsupported:
                        let issue = EvidenceIssue(.malformedHeader(leaf, .unsupportedFileType), range: leaf)
                        record(path, .unsupportedType, leaf, issue: issue, physical: physical, identity: identity)
                    case .image:
                        if seenCandidates.contains(physical) {
                            record(path, .candidate, leaf, physical: physical, identity: identity, partial: false)
                            return
                        }
                        guard candidates < limits.candidates else {
                            stop(.candidates, .candidateLimit, path: path, range: leaf)
                            return
                        }
                        candidates += 1
                        seenCandidates.insert(physical)
                        record(path, .candidate, leaf, physical: physical, identity: identity, partial: false)
                    }
                } catch { ioFailure(path, error, leaf) }
            }

            func searchedLocations() -> [SearchLocation] {
                var result: [SearchLocation] = []
                for location in BundleDiscovery.codeLocations {
                    var status = SearchLocation.Status.searched
                    var prefix: [ExactUTF8Key] = []
                    for component in location.components {
                        guard let listing = listings[Walker.key(prefix)] else { status = .incomplete; break }
                        if !listing.contains(component) { status = .absent; break }
                        prefix.append(component)
                        if nonDirectories.contains(Walker.key(prefix)) { status = .incomplete; break }
                    }
                    if status == .searched, listings[Walker.key(prefix)] == nil || stopped { status = .incomplete }
                    result.append(SearchLocation(range: .subtree(location), role: .codeRegion, status: status))
                }
                let whole = !stopped && !partial && !cancelled
                result.append(SearchLocation(range: .wholeRoot, role: .fullRoot, status: whole ? .searched : .incomplete))
                return result
            }

            /// Applies the inode policy and turns facts into stable, byte-ordered entries.
            func resolve(principalPath: RelativePath?, rootStat: stat) -> [BundleDiscoveryEntry] {
                func rank(_ fact: Fact) -> Int {
                    guard fact.inCode else { return 2 }
                    switch fact.state {
                    case .candidate, .malformedHeader, .unsupportedType: return 0
                    default: return 1
                    }
                }
                func order(_ lhs: Fact, _ rhs: Fact) -> Bool {
                    let (a, b) = (rank(lhs), rank(rhs))
                    return a != b ? a < b : lhs.raw < rhs.raw
                }
                var groups: [PhysicalFileKey: [Int]] = [:]
                for (index, fact) in facts.enumerated() {
                    guard let key = fact.physical else { continue }
                    groups[key, default: []].append(index)
                }
                let ids = facts.map { _ in UUID() }
                var canonical: [Int: Int] = [:]
                for (_, indices) in groups where indices.count > 1 {
                    let best = indices.min { order(facts[$0], facts[$1]) }!
                    for index in indices where index != best { canonical[index] = best }
                }
                // Stable ids by byte order keep results deterministic in shape (values themselves are fresh UUIDs).
                var entries: [BundleDiscoveryEntry] = []
                let rootDevice = UInt64(UInt32(bitPattern: rootStat.st_dev))
                for (index, fact) in facts.enumerated() {
                    if let target = canonical[index] {
                        entries.append(BundleDiscoveryEntry(
                            id: ids[index], rawPath: fact.raw, path: fact.path, state: .duplicateFile,
                            range: fact.path.map { PathRange.leaf($0) } ?? fact.range, issue: nil, provenance: nil,
                            physical: fact.physical, canonicalEntryID: ids[target], canonicalPath: facts[target].path,
                            isPrincipal: false, omittedCount: 0))
                        continue
                    }
                    var provenance: BundleImageProvenance?
                    if fact.state == .candidate, let path = fact.path, let identity = fact.identity {
                        provenance = BundleImageProvenance(session: session.id, inventoryID: inventoryID, path: path,
                            rootDevice: rootDevice, rootInode: rootStat.st_ino, fileIdentity: identity)
                    }
                    entries.append(BundleDiscoveryEntry(
                        id: ids[index], rawPath: fact.raw, path: fact.path, state: fact.state, range: fact.range, issue: fact.issue,
                        provenance: provenance, physical: fact.physical, canonicalEntryID: nil, canonicalPath: nil,
                        isPrincipal: provenance != nil && fact.path == principalPath, omittedCount: fact.omitted))
                }
                return entries.sorted { $0.rawPath < $1.rawPath }
            }
        }
    }
}
