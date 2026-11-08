// Adapted from the AIRS component evidence core at donor commit fa5a2f3128da9134969055cebea145e2ca144214.
// Original relative path: native/Sources/AIRSCore/ComponentMatcher.swift.
// License: MIT, Copyright (c) 2026 Jeffrey D. Cooney; the notice is in ThirdParty/AIRS/LICENSE.
// Adaptations: byte-path identity, scope-aware unobserved results, deterministic match ids, no free-text states.

import CryptoKit
import Foundation

extension ComponentEvidence {
    enum MatchStatus: String, Sendable, Hashable {
        case sameLocation, uniqueIdentifierCandidate, ambiguous
        case unmatchedPrevious, unmatchedCurrent, unobservedInOtherScope
    }

    struct ComponentMatch: Sendable, Equatable, Identifiable {
        let id: String
        let status: MatchStatus
        let previousID: UUID?
        let currentID: UUID?
        let candidateIDs: [UUID]
    }

    struct ComponentMatcher: Sendable {
        init() {}

        static func matchID(_ status: MatchStatus, _ previous: UUID?, _ current: UUID?, _ extra: [UUID]) -> String {
            var data = Data()
            func frame(_ bytes: [UInt8]) {
                var length = UInt32(bytes.count).bigEndian
                withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
                data.append(contentsOf: bytes)
            }
            frame(Array(status.rawValue.utf8))
            frame(previous.map { Array($0.uuidString.utf8) } ?? [])
            frame(current.map { Array($0.uuidString.utf8) } ?? [])
            for id in extra { frame(Array(id.uuidString.utf8)) }
            return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        }

        /// Matches by exact path bytes first, then by a unique (kind, declared id) pair; duplicates are ambiguous.
        func match(previous: ComponentInventory, current: ComponentInventory) -> [ComponentMatch] {
            var results: [ComponentMatch] = []
            var takenPrevious = Set<UUID>(), takenCurrent = Set<UUID>()
            let currentByPath = Dictionary(uniqueKeysWithValues: current.components.map { ($0.path, $0) })
            for old in previous.components.sorted(by: { $0.path < $1.path }) {
                if let new = currentByPath[old.path] {
                    takenPrevious.insert(old.id); takenCurrent.insert(new.id)
                    results.append(ComponentMatch(id: Self.matchID(.sameLocation, old.id, new.id, []), status: .sameLocation,
                                                  previousID: old.id, currentID: new.id, candidateIDs: []))
                }
            }
            func identity(_ record: ComponentRecord) -> String? {
                record.declaredBundleID.map { "\($0.display)|\(record.kind.display)" }
            }
            let leftoverOld = previous.components.filter { !takenPrevious.contains($0.id) }
            let leftoverNew = current.components.filter { !takenCurrent.contains($0.id) }
            for old in leftoverOld.sorted(by: { $0.path < $1.path }) {
                guard let key = identity(old) else { continue }
                let sameOld = leftoverOld.filter { identity($0) == key }
                let candidates = leftoverNew.filter { identity($0) == key }.sorted { $0.path < $1.path }
                if candidates.isEmpty { continue }
                if sameOld.count == 1, candidates.count == 1 {
                    takenPrevious.insert(old.id); takenCurrent.insert(candidates[0].id)
                    results.append(ComponentMatch(id: Self.matchID(.uniqueIdentifierCandidate, old.id, candidates[0].id, []),
                        status: .uniqueIdentifierCandidate, previousID: old.id, currentID: candidates[0].id, candidateIDs: []))
                } else {
                    takenPrevious.insert(old.id)
                    let ids = candidates.map(\.id)
                    results.append(ComponentMatch(id: Self.matchID(.ambiguous, old.id, nil, ids), status: .ambiguous,
                                                  previousID: old.id, currentID: nil, candidateIDs: ids))
                }
            }
            for old in previous.components.sorted(by: { $0.path < $1.path }) where !takenPrevious.contains(old.id) {
                let observed = current.covers(old.path)
                let status: MatchStatus = observed ? .unmatchedPrevious : .unobservedInOtherScope
                results.append(ComponentMatch(id: Self.matchID(status, old.id, nil, []), status: status,
                                              previousID: old.id, currentID: nil, candidateIDs: []))
            }
            let ambiguousTargets = Set(results.filter { $0.status == .ambiguous }.flatMap(\.candidateIDs))
            for new in current.components.sorted(by: { $0.path < $1.path }) where !takenCurrent.contains(new.id) && !ambiguousTargets.contains(new.id) {
                let observed = previous.covers(new.path)
                let status: MatchStatus = observed ? .unmatchedCurrent : .unobservedInOtherScope
                results.append(ComponentMatch(id: Self.matchID(status, nil, new.id, []), status: status,
                                              previousID: nil, currentID: new.id, candidateIDs: []))
            }
            return results
        }
    }
}
