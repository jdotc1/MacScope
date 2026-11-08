// Adapted from the AIRS component evidence core at donor commit fa5a2f3128da9134969055cebea145e2ca144214.
// Original relative path: native/Sources/AIRSCore/ComponentInventory.swift.
// License: MIT, Copyright (c) 2026 Jeffrey D. Cooney; the notice is in ThirdParty/AIRS/LICENSE.
// Adaptations: byte-key identity, published values carry no descriptor or closure, scope with typed exclusions and
// overflow facts, three-valued completion, validating non-throwing initializer plus throwing validate().

import Foundation

extension ComponentEvidence {
    struct SearchLocation: Sendable, Equatable {
        enum Role: String, Sendable { case codeRegion, fullRoot }
        enum Status: String, Sendable { case searched, absent, incomplete }
        let range: PathRange
        let role: Role
        let status: Status
    }

    enum ExclusionState: String, Sendable, Hashable {
        case nonImage, skippedLink, skippedSpecial, duplicateFile, outsideCodeLocations, invalidName
        case unreadable, changed, entryLimit, depthLimit, candidateLimit, headerLimit, pathLimit
        /// True when the state conceals whatever could lie beneath its range (as opposed to naming a known non-component).
        var hides: Bool {
            switch self {
            case .nonImage, .outsideCodeLocations, .duplicateFile: false
            default: true
            }
        }
        /// States whose gaps leave the scope unable to prove a component absent.
        var isGap: Bool {
            switch self {
            case .unreadable, .changed, .entryLimit, .depthLimit, .candidateLimit, .headerLimit, .pathLimit, .invalidName: true
            default: false
            }
        }
    }

    struct ExclusionRecord: Sendable, Equatable {
        let range: PathRange
        let rawPath: ExactUTF8Key
        let state: ExclusionState
        let canonicalPath: RelativePath?
        let omittedCount: Int
    }

    /// Present when more exclusions or issues were observed than the 255 retained records.
    struct OverflowFact: Sendable, Equatable {
        let observed: Int
        let retained: Int
        var omitted: Int { max(0, observed - retained) }
    }

    enum InventoryCompletion: String, Sendable { case complete, partial, cancelled }

    struct InventoryScope: Sendable, Equatable {
        static let maximumLocations = 16
        static let maximumRecords = 255
        let searchedLocations: [SearchLocation]
        let completion: InventoryCompletion
        let exclusions: [ExclusionRecord]
        let exclusionOverflow: OverflowFact?
        let issues: [EvidenceIssue]
        let issueOverflow: OverflowFact?
        let visited: Int
        let headerBytes: Int
        let remainderUnknown: Bool
        let limitEntries: Int
        let limitDepth: Int
        let limitCandidates: Int
        let limitHeaderBytes: Int
    }

    struct ComponentRecord: Sendable, Equatable, Identifiable {
        static let maximumIssues = 64
        let id: UUID
        let parentID: UUID?
        let path: RelativePath
        let kind: ExactUTF8Key
        let declaredBundleID: ExactUTF8Key?
        let declaredVersion: ExactUTF8Key?
        let architectures: [ExactUTF8Key]
        let minimumOS: [ArchitectureMinimum]
        let slices: [Slice]
        let issues: [EvidenceIssue]
        let issueOverflow: OverflowFact?
        let metadataAvailable: Bool
        let isDeclarationOnly: Bool
    }

    struct ComponentInventory: Sendable, Identifiable {
        static let maximumComponents = 128
        let id: UUID
        let components: [ComponentRecord]
        let scope: InventoryScope

        init(id: UUID, components: [ComponentRecord], scope: InventoryScope) {
            self.id = id; self.components = components; self.scope = scope
        }

        var isComplete: Bool { scope.completion == .complete }

        /// Checks every structural invariant a consumer relies on.
        func validate() throws {
            guard components.count <= Self.maximumComponents else { throw EvidenceError.invalidInventory(.tooManyComponents) }
            guard scope.searchedLocations.count <= InventoryScope.maximumLocations,
                  scope.exclusions.count <= InventoryScope.maximumRecords, scope.issues.count <= InventoryScope.maximumRecords else {
                throw EvidenceError.invalidInventory(.scopeTooLarge)
            }
            if scope.completion == .complete, scope.exclusionOverflow != nil || scope.issueOverflow != nil || scope.remainderUnknown
                || scope.exclusions.contains(where: { $0.state.isGap }) {
                throw EvidenceError.invalidInventory(.completeWithGap)
            }
            let ids = Set(components.map(\.id))
            guard ids.count == components.count else { throw EvidenceError.invalidInventory(.duplicateID) }
            guard Set(components.map(\.path)).count == components.count else { throw EvidenceError.invalidInventory(.duplicatePath) }
            for component in components {
                guard RelativePath.isSafe(component.path.last.bytes) else { throw EvidenceError.invalidInventory(.badPath) }
                if let parent = component.parentID {
                    guard ids.contains(parent), parent != component.id else { throw EvidenceError.invalidInventory(.badParent) }
                }
                guard component.architectures.count <= ComponentMetadataReader.maximumSlices,
                      Set(component.architectures).count == component.architectures.count else {
                    throw EvidenceError.invalidInventory(component.architectures.count > ComponentMetadataReader.maximumSlices
                                                         ? .tooManyArchitectures : .duplicateArchitecture)
                }
                for minimum in component.minimumOS where !component.architectures.contains(minimum.architecture) {
                    throw EvidenceError.invalidInventory(.minimumWithoutArchitecture)
                }
                guard component.issues.count <= ComponentRecord.maximumIssues else { throw EvidenceError.invalidInventory(.scopeTooLarge) }
            }
            // Parent chains must terminate.
            let parents = Dictionary(uniqueKeysWithValues: components.map { ($0.id, $0.parentID) })
            for component in components {
                var seen = Set<UUID>([component.id])
                var cursor = component.parentID
                while let next = cursor {
                    guard seen.insert(next).inserted else { throw EvidenceError.invalidInventory(.cyclicParents) }
                    cursor = parents[next] ?? nil
                }
            }
        }

        func component(_ id: UUID) -> ComponentRecord? { components.first { $0.id == id } }

        /// True only when the scope is complete and no hiding exclusion could conceal a component at `path`.
        func covers(_ path: RelativePath) -> Bool {
            guard scope.completion == .complete, !scope.remainderUnknown, scope.exclusionOverflow == nil,
                  scope.issueOverflow == nil else { return false }
            // Any exclusion or issue whose range reaches this path, by component boundary, blocks the proof.
            return !scope.exclusions.contains { $0.range.blocks(path) } && !scope.issues.contains { $0.range.blocks(path) }
        }
    }

    /// Produced by one capture step; the retained provenance is immutable and holds no descriptor.
    struct LiveComponentInventory: Sendable {
        let inventory: ComponentInventory
        let provenance: [UUID: BundleImageProvenance]
        let resourceDeclarations: BundleResourceDeclarations?
        let session: SessionID
    }
}
