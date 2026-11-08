import Foundation

struct RegenerationProgressFinding: Equatable, Sendable {
    /// `rule1`...`rule7` (the contracts README), `manifestV1` or `reportIdentity`.
    let code: String
    let message: String
}

struct RegenerationDependencyRow: Equatable, Sendable {
    let id: String
    let name: String
    let kind: RegenerationDependencyKind
    let version: String?
    let confidence: RegenerationDependencyConfidence
    /// Addresses listed by this dependency inside manifest images; 0 unless confirmed.
    let claimedFunctionCount: Int
}

struct RegenerationDependencyGroup: Equatable, Sendable {
    let confidence: RegenerationDependencyConfidence
    let dependencies: [RegenerationDependencyRow]
    var claimedFunctionCount: Int { dependencies.reduce(0) { $0 + $1.claimedFunctionCount } }
}

struct RegenerationStateLanguageCount: Hashable, Sendable {
    let state: RegenerationFunctionState
    let language: RegenerationLanguage
}

struct RegenerationProgressPage: Equatable, Sendable {
    let functions: [RegenerationProgressFunction]
    let pageIndex: Int
    let pageCount: Int
    /// Rows matching the filter, across all pages.
    let totalCount: Int
}

struct RegenerationNavigation: Equatable, Sendable {
    enum Status: Equatable, Sendable {
        case fullMatch, mismatch, uuidOnly, notOpen, unknownImage
    }

    let status: Status
    let reason: String
    /// The open image that matched on UUID, when there is one.
    let openImageName: String?

    var canNavigate: Bool { status == .fullMatch }
}

/// Pure, deterministic view of a regeneration export. It holds derived values only; findings are
/// listed and records are never repaired.
struct RegenerationProgressProjection: Equatable, Sendable {
    static let defaultPageSize = 500

    let files: [RegenerationExportFile]
    let appName: String?
    /// Sorted by image, numeric address, then function UUID.
    let functions: [RegenerationProgressFunction]
    let stateCounts: [RegenerationFunctionState: Int]
    let languageCounts: [RegenerationLanguage: Int]
    let resources: [RegenerationProgressResource]
    let resourceStatusCounts: [RegenerationResourceStatus: Int]
    let resourceEquivalenceCounts: [RegenerationResourceEquivalence: Int]
    let notAttemptedResourceCount: Int
    let dependencyGroups: [RegenerationDependencyGroup]
    let dimensions: [RegenerationDimensionResult]
    let functionStates: [String: Int]?
    let findings: [RegenerationProgressFinding]
    let manifestImages: [RegenerationProgressImage]
    let openImages: [RegenerationOpenImage]
    private let matrix: [RegenerationStateLanguageCount: Int]

    var emptyMessage: String? { files.contains { $0.state.isLoaded } ? nil : "No regeneration export loaded" }

    func count(state: RegenerationFunctionState, language: RegenerationLanguage) -> Int {
        matrix[RegenerationStateLanguageCount(state: state, language: language)] ?? 0
    }

    init(export: RegenerationLoadedExport, openImages: [RegenerationOpenImage] = []) {
        files = export.files
        self.openImages = openImages
        let manifest = export.manifest
        appName = manifest?.appName
        manifestImages = manifest?.images ?? []
        functions = (manifest?.functions ?? []).sorted(by: Self.functionOrder)
        resources = (manifest?.resources ?? []).sorted { ($0.compiledPath, $0.sourcePath ?? "") < ($1.compiledPath, $1.sourcePath ?? "") }

        var states = Dictionary(uniqueKeysWithValues: RegenerationFunctionState.allCases.map { ($0, 0) })
        var languages = Dictionary(uniqueKeysWithValues: RegenerationLanguage.allCases.map { ($0, 0) })
        var cells: [RegenerationStateLanguageCount: Int] = [:]
        for function in functions {
            states[function.state, default: 0] += 1
            languages[function.language, default: 0] += 1
            cells[RegenerationStateLanguageCount(state: function.state, language: function.language), default: 0] += 1
        }
        stateCounts = states
        languageCounts = languages
        matrix = cells

        var statuses = Dictionary(uniqueKeysWithValues: RegenerationResourceStatus.allCases.map { ($0, 0) })
        var equivalences = Dictionary(uniqueKeysWithValues: RegenerationResourceEquivalence.allCases.map { ($0, 0) })
        var notAttempted = 0
        for resource in resources {
            statuses[resource.status, default: 0] += 1
            if let result = resource.equivalence { equivalences[result, default: 0] += 1 } else { notAttempted += 1 }
        }
        resourceStatusCounts = statuses
        resourceEquivalenceCounts = equivalences
        notAttemptedResourceCount = notAttempted

        dimensions = (export.report?.dimensions ?? []).enumerated().sorted {
            let (left, right) = (RegenerationDimensionName.allCases.firstIndex(of: $0.element.dimension) ?? 0,
                                 RegenerationDimensionName.allCases.firstIndex(of: $1.element.dimension) ?? 0)
            return left != right ? left < right : $0.offset < $1.offset
        }.map(\.element)
        functionStates = export.report?.functionStates

        let insideImages = Set(manifestImages.map(\.imageName))
        let dependencies = (export.dependencies?.dependencies ?? []).sorted(by: Self.dependencyOrder)
        dependencyGroups = export.dependencies == nil ? [] : RegenerationDependencyConfidence.allCases.map { confidence in
            RegenerationDependencyGroup(
                confidence: confidence,
                dependencies: dependencies.filter { $0.confidence == confidence }.map { dependency in
                    let claimed = confidence == .confirmed
                        ? Set(dependency.functions.filter { insideImages.contains(RegenerationProgressFunction.imageName(ofAddress: $0)) }).count
                        : 0
                    return RegenerationDependencyRow(
                        id: dependency.id, name: dependency.name, kind: dependency.kind,
                        version: dependency.version, confidence: confidence, claimedFunctionCount: claimed
                    )
                }
            )
        }
        findings = Self.findings(export: export, functions: functions, dependencies: dependencies, insideImages: insideImages)
    }

    // MARK: Paging

    /// One page of the filtered function list. `search` matches name or address, case-insensitively.
    func page(
        pageIndex: Int = 0,
        state: RegenerationFunctionState? = nil,
        language: RegenerationLanguage? = nil,
        search: String = "",
        pageSize: Int = RegenerationProgressProjection.defaultPageSize
    ) -> RegenerationProgressPage {
        let needle = search.trimmingCharacters(in: .whitespacesAndNewlines)
        let size = max(1, pageSize)
        let matches = functions.filter { function in
            (state == nil || function.state == state)
                && (language == nil || function.language == language)
                && (needle.isEmpty
                    || function.imageQualifiedAddress.range(of: needle, options: .caseInsensitive) != nil
                    || function.name?.range(of: needle, options: .caseInsensitive) != nil)
        }
        let pageCount = max(1, (matches.count + size - 1) / size)
        let index = min(max(0, pageIndex), pageCount - 1)
        let start = index * size
        return RegenerationProgressPage(
            functions: Array(matches[start..<min(matches.count, start + size)]),
            pageIndex: index, pageCount: pageCount, totalCount: matches.count
        )
    }

    // MARK: Identity

    /// Navigation is offered only when the open image has the same UUID and the same slice SHA-256.
    func navigation(for function: RegenerationProgressFunction) -> RegenerationNavigation {
        let candidates = manifestImages.filter { $0.imageName == function.imageName }
        guard candidates.count == 1, let image = candidates.first else {
            return RegenerationNavigation(
                status: .unknownImage,
                reason: candidates.isEmpty
                    ? "The export does not describe image \(function.imageName); navigation refused."
                    : "The export describes image \(function.imageName) more than once; navigation refused.",
                openImageName: nil
            )
        }
        let uuid = image.uuid.lowercased()
        let sameUUID = openImages.filter { $0.uuid.lowercased() == uuid }
        guard !sameUUID.isEmpty else {
            return RegenerationNavigation(
                status: .notOpen,
                reason: openImages.isEmpty
                    ? "No analysed image is open; navigation refused."
                    : "No open image has UUID \(image.uuid); navigation refused.",
                openImageName: nil
            )
        }
        let digest = image.sha256.lowercased()
        if let match = sameUUID.first(where: { $0.sliceSha256?.lowercased() == digest }) {
            return RegenerationNavigation(
                status: .fullMatch,
                reason: "The open image matches the export's UUID and slice SHA-256.",
                openImageName: match.imageName
            )
        }
        if let unhashed = sameUUID.first(where: { $0.sliceSha256 == nil }) {
            return RegenerationNavigation(
                status: .uuidOnly,
                reason: "UUID-only match: the open image has no recorded slice SHA-256, so navigation is refused.",
                openImageName: unhashed.imageName
            )
        }
        return RegenerationNavigation(
            status: .mismatch,
            reason: "The open image has the same UUID but a different slice SHA-256; navigation refused.",
            openImageName: sameUUID.first?.imageName
        )
    }

    // MARK: Ordering

    private static func functionOrder(_ lhs: RegenerationProgressFunction, _ rhs: RegenerationProgressFunction) -> Bool {
        if lhs.imageName != rhs.imageName { return lhs.imageName < rhs.imageName }
        let (left, right) = (numericAddress(lhs.imageQualifiedAddress), numericAddress(rhs.imageQualifiedAddress))
        if left != right { return left < right }
        if lhs.imageQualifiedAddress != rhs.imageQualifiedAddress { return lhs.imageQualifiedAddress < rhs.imageQualifiedAddress }
        return lhs.functionUUID < rhs.functionUUID
    }

    private static func numericAddress(_ address: String) -> UInt64 {
        guard let colon = address.firstIndex(of: ":") else { return 0 }
        return UInt64(address[address.index(after: colon)...].dropFirst(2), radix: 16) ?? 0
    }

    private static func dependencyOrder(_ lhs: RegenerationProgressDependency, _ rhs: RegenerationProgressDependency) -> Bool {
        let rank = { (dependency: RegenerationProgressDependency) in
            RegenerationDependencyConfidence.allCases.firstIndex(of: dependency.confidence) ?? 0
        }
        if lhs.id != rhs.id { return lhs.id < rhs.id }
        if rank(lhs) != rank(rhs) { return rank(lhs) < rank(rhs) }
        if lhs.name != rhs.name { return lhs.name < rhs.name }
        return lhs.functions.joined(separator: ",") < rhs.functions.joined(separator: ",")
    }
}

// MARK: Consistency findings

extension RegenerationProgressProjection {
    /// The README's reader-checked rules. Rules that need a file that is not loaded are skipped.
    fileprivate static func findings(
        export: RegenerationLoadedExport,
        functions: [RegenerationProgressFunction],
        dependencies: [RegenerationProgressDependency],
        insideImages: Set<String>
    ) -> [RegenerationProgressFinding] {
        var result: [RegenerationProgressFinding] = []
        func add(_ code: String, _ message: String) { result.append(RegenerationProgressFinding(code: code, message: message)) }
        let external = functions.filter { $0.state == .external }

        if let manifest = export.manifest {
            if manifest.schemaVersion == 1 {
                for function in functions where function.state == .external || function.hasDependencyIdKey {
                    add("manifestV1", "\(function.imageQualifiedAddress): a version 1 manifest must not use state external or dependencyId.")
                }
            }
            // Rule 5.
            var seen = Set<String>()
            var repeated = Set<String>()
            for function in functions where !seen.insert(function.imageQualifiedAddress).inserted {
                repeated.insert(function.imageQualifiedAddress)
            }
            for address in repeated.sorted() { add("rule5", "\(address) appears more than once in the manifest.") }
        }

        if export.dependencies != nil {
            // Rule 7.
            var idCounts: [String: Int] = [:]
            for dependency in dependencies { idCounts[dependency.id, default: 0] += 1 }
            let duplicated = Set(idCounts.filter { $0.value > 1 }.keys)
            for id in duplicated.sorted() { add("rule7", "Dependency id \(id) is used by \(idCounts[id] ?? 0) entries.") }
            let unique = Dictionary(uniqueKeysWithValues: dependencies.filter { !duplicated.contains($0.id) }.map { ($0.id, $0) })

            if export.manifest != nil {
                // Rule 3.
                for function in external {
                    guard let id = function.dependencyId else {
                        add("rule3", "\(function.imageQualifiedAddress) is external without a dependencyId.")
                        continue
                    }
                    if duplicated.contains(id) {
                        add("rule3", "\(function.imageQualifiedAddress) names dependency \(id), which is unresolvable (duplicated id).")
                    } else if let dependency = unique[id] {
                        if dependency.confidence != .confirmed {
                            add("rule3", "\(function.imageQualifiedAddress) is external but dependency \(id) is \(dependency.confidence.rawValue).")
                        }
                    } else {
                        add("rule3", "\(function.imageQualifiedAddress) names dependency \(id), which is not in DEPENDENCIES.json.")
                    }
                }
                // Rule 6.
                for function in external {
                    guard let id = function.dependencyId else { continue }
                    if duplicated.contains(id) {
                        add("rule6", "\(function.imageQualifiedAddress) names dependency \(id), which is unresolvable (duplicated id).")
                    } else if let dependency = unique[id], !dependency.functions.contains(function.imageQualifiedAddress) {
                        add("rule6", "Dependency \(id) does not list \(function.imageQualifiedAddress).")
                    }
                }
                var owners: [String: Int] = [:]
                for dependency in dependencies { for address in Set(dependency.functions) { owners[address, default: 0] += 1 } }
                for address in owners.filter({ $0.value > 1 }).keys.sorted() {
                    add("rule6", "\(address) is listed by \(owners[address] ?? 0) dependencies.")
                }
                // Rule 4.
                let state = Dictionary(functions.map { ($0.imageQualifiedAddress, $0.state) }, uniquingKeysWith: { first, _ in first })
                for dependency in dependencies where dependency.confidence == .confirmed {
                    for address in Set(dependency.functions).sorted()
                    where insideImages.contains(RegenerationProgressFunction.imageName(ofAddress: address)) && state[address] != .external {
                        add("rule4", "Confirmed dependency \(dependency.id) lists \(address), which is not external in the manifest.")
                    }
                }
            }
        }

        if let report = export.report {
            for row in report.dimensions {
                let listed = row.listedMissing + row.listedExtra + row.listedDiffering
                if listed != row.missingInRebuilt + row.extraInRebuilt + row.differing
                    || row.listedMissing != row.missingInRebuilt || row.listedExtra != row.extraInRebuilt
                    || row.listedDiffering != row.differing {
                    add("rule1", "\(row.dimension.rawValue): listed items do not match the missing, extra and differing counts.")
                }
                let denominator = row.matched + row.missingInRebuilt + row.extraInRebuilt + row.differing
                let consistent = denominator == 0
                    ? row.score == nil
                    : row.score.map { abs($0 - Double(row.matched) / Double(denominator)) < 1e-9 } ?? false
                if !consistent { add("rule2", "\(row.dimension.rawValue): score is not matched / (matched + missing + extra + differing).") }
            }
            if let manifest = export.manifest {
                let original = report.original
                let found = manifest.images.contains {
                    $0.sha256 == original.sliceSha256 && $0.architecture == original.architecture
                        && $0.uuid.lowercased() == original.uuid.lowercased()
                }
                if !found { add("reportIdentity", "The report's original slice matches no image in the manifest.") }
            }
        }
        return result
    }
}

/// Window-local, single-entry memo. Main-thread-only: callers must serialize access on the
/// main thread. Intentionally not observable; filling it during body evaluation emits no change.
/// Full value equality includes export contents and open-image order, not just record counts.
final class RegenerationProjectionMemo {
    private var entry: (export: RegenerationLoadedExport, openImages: [RegenerationOpenImage],
                        projection: RegenerationProgressProjection)?
    private(set) var buildCount = 0

    func projection(
        export: RegenerationLoadedExport,
        openImages: [RegenerationOpenImage]
    ) -> RegenerationProgressProjection {
        if let entry, entry.export == export, entry.openImages == openImages {
            return entry.projection
        }
        let result = RegenerationProgressProjection(export: export, openImages: openImages)
        entry = (export, openImages, result)
        buildCount += 1
        return result
    }
}
