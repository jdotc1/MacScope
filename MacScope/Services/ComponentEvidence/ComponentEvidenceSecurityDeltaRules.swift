// Original to this item (AR3, NF07). Finding derivation over final observations, report assembly and coverage
// ledgers. A finding is whole or absent: it references retained rows only and never repeats their values. The
// related-components rule uses accepted same-location paths on both sides only; it never infers a relation from a
// candidate match. Related path nesting is by component boundary on the raw relative-path bytes.

import Foundation

extension ComponentEvidenceSecurityDelta {
    enum Rules {
        struct Plan {
            let kind: FindingKind
            let disposition: Disposition
            let title: String
            let explanation: String
            let ids: [RowID]
        }

        static let unresolvedReferenceCeiling = 256

        static func changed(_ row: Observation) -> Bool {
            row.disposition == .observedAddition || row.disposition == .observedRemoval || row.disposition == .observedChange
        }

        static func name(_ category: Category) -> String {
            switch category {
            case .componentInventory: "inventory"
            case .informationPropertyList: "info property list"
            case .loadCommands: "load commands"
            case .entitlements: "entitlements"
            case .privacyManifest: "privacy manifest"
            case .signatureEvidence: "signature evidence"
            }
        }

        static func text(_ key: ExactKey) -> String { String(data: key.utf8, encoding: .utf8) ?? "[non-text path]" }

        static func isAncestor(_ ancestor: ExactKey, of path: ExactKey) -> Bool {
            path.utf8.count > ancestor.utf8.count + 1 && path.utf8.starts(with: ancestor.utf8 + Data([0x2f]))
        }

        static func derive(_ rows: [Observation]) -> [Plan] {
            var plans: [Plan] = []
            let declarative: Set<Category> = [.informationPropertyList, .loadCommands, .entitlements, .privacyManifest]

            for row in rows where row.category == .componentInventory && row.subject == ExactKey(text: "component") {
                let isXPC = row.currentValue == .string(ExactKey(text: "xpc"))
                if row.disposition == .observedAddition {
                    plans.append(Plan(kind: isXPC ? .xpcAdded : .componentAdded, disposition: .observedAddition,
                                      title: isXPC ? "XPC service added" : "Component added",
                                      explanation: "\(text(row.componentPath)) is present only in the current inventory.", ids: [row.id]))
                } else if row.disposition == .observedRemoval {
                    plans.append(Plan(kind: .componentRemoved, disposition: .observedRemoval, title: "Component removed",
                                      explanation: "\(text(row.componentPath)) is present only in the previous inventory.", ids: [row.id]))
                }
            }

            struct Group: Hashable { let path: ExactKey; let category: Category }
            var byGroup: [Group: [RowID]] = [:]
            var order: [Group] = []
            for row in rows where changed(row) && row.category != .componentInventory {
                let group = Group(path: row.componentPath, category: row.category)
                if byGroup[group] == nil { order.append(group) }
                byGroup[group, default: []].append(row.id)
            }
            for group in order {
                let kind: FindingKind = group.category == .signatureEvidence ? .signatureEvidenceChanged : .declarationChanged
                plans.append(Plan(kind: kind, disposition: .observedChange, title: "Changed \(name(group.category))",
                                  explanation: "\(text(group.path)) has \(byGroup[group]?.count ?? 0) changed \(name(group.category)) rows.",
                                  ids: byGroup[group] ?? []))
            }

            var categoriesByPath: [ExactKey: [Category: RowID]] = [:]
            var paths: [ExactKey] = []
            for group in order where group.category != .componentInventory {
                if categoriesByPath[group.path] == nil { paths.append(group.path) }
                categoriesByPath[group.path, default: [:]][group.category] = byGroup[group]?.first
            }
            for path in paths {
                guard let found = categoriesByPath[path], found.count >= 2 else { continue }
                plans.append(Plan(kind: .componentMultiCategory, disposition: .observedChange, title: "Changes in several categories",
                                  explanation: "\(text(path)) changed in \(found.count) categories.",
                                  ids: found.sorted { $0.key < $1.key }.map(\.value)))
            }

            struct Repeat: Hashable {
                let category: Category; let subject: ExactKey; let disposition: Disposition
                let previous: Value?; let current: Value?
            }
            var repeats: [Repeat: [(ExactKey, RowID)]] = [:]
            var repeatOrder: [Repeat] = []
            for row in rows where changed(row) && declarative.contains(row.category) {
                let key = Repeat(category: row.category, subject: row.subject, disposition: row.disposition,
                                 previous: row.previousValue, current: row.currentValue)
                if repeats[key] == nil { repeatOrder.append(key) }
                repeats[key, default: []].append((row.componentPath, row.id))
            }
            for key in repeatOrder {
                guard let members = repeats[key], Set(members.map(\.0)).count >= 2 else { continue }
                plans.append(Plan(kind: .repeatedDeclaration, disposition: key.disposition, title: "Same change in several components",
                                  explanation: "\(text(key.subject)) changed identically in \(Set(members.map(\.0)).count) components.",
                                  ids: members.map(\.1)))
            }

            var firstRow: [ExactKey: RowID] = [:]
            for row in rows where changed(row) && firstRow[row.componentPath] == nil { firstRow[row.componentPath] = row.id }
            let changedPaths = firstRow.keys.sorted()
            for ancestor in changedPaths {
                for descendant in changedPaths where isAncestor(ancestor, of: descendant) {
                    guard let a = firstRow[ancestor], let d = firstRow[descendant] else { continue }
                    plans.append(Plan(kind: .relatedComponents, disposition: .observedChange, title: "Related components changed",
                                      explanation: "\(text(ancestor)) and nested \(text(descendant)) both changed.", ids: [a, d]))
                }
            }

            let unresolved = rows.filter { $0.disposition == .unresolved }
            if !unresolved.isEmpty {
                let conflicts = unresolved.filter {
                    $0.limitations.contains { $0.code == .xmlDerDisagreement || $0.code == .evidenceConflict }
                }
                plans.append(Plan(kind: .coverageIncomplete, disposition: .unresolved, title: "Some evidence is unresolved",
                                  explanation: "\(unresolved.count) rows could not be decided; none is reported as unchanged.",
                                  ids: Array(unresolved.prefix(unresolvedReferenceCeiling).map(\.id))))
                if !conflicts.isEmpty {
                    plans.append(Plan(kind: .evidenceConflict, disposition: .unresolved, title: "Evidence conflicts",
                                      explanation: "\(conflicts.count) rows have conflicting evidence.",
                                      ids: Array(conflicts.prefix(unresolvedReferenceCeiling).map(\.id))))
                }
            }
            return plans
        }
    }
}

extension ComponentEvidenceSecurityDelta.Analyzer.Run {
    typealias SD = ComponentEvidenceSecurityDelta

    private func classify(_ draft: SD.Analyzer.Draft) -> Int {
        if draft.disposition == .unresolved { return 3 }
        if draft.disposition == .declined || draft.previousState == .excluded || draft.currentState == .excluded { return 4 }
        if draft.disposition == .unchanged, draft.previousState == .unexamined, draft.currentState == .unexamined { return 2 }
        if draft.disposition == .unchanged, draft.previousState == .absent, draft.currentState == .absent { return 1 }
        return 0
    }

    func finish(options: SD.Options, evidenceBasisID: UUID) throws -> SD.Outcome {
        let identity = SD.ReviewIdentity(previousInventoryID: previous.inventory.id, currentInventoryID: current.inventory.id,
                                         architecture: "per-slice", evidenceBasisID: evidenceBasisID)
        var order = Array(drafts.indices)
        order.sort {
            let a = drafts[$0], b = drafts[$1]
            if a.category != b.category { return a.category < b.category }
            if a.path != b.path { return a.path < b.path }
            if a.subject != b.subject { return a.subject < b.subject }
            return $0 < $1
        }
        struct Slot: Hashable { let category: SD.Category; let path: SD.ExactKey; let subject: SD.ExactKey }
        var seen: [Slot: Int] = [:]
        var population: [SD.Analyzer.Draft] = []
        for index in order {
            var draft = drafts[index]
            let slot = Slot(category: draft.category, path: draft.path, subject: draft.subject)
            if let count = seen[slot] {
                seen[slot] = count + 1
                draft.subject = SD.ExactKey(text: (String(data: draft.subject.utf8, encoding: .utf8) ?? "[subject]") + "#\(count + 1)")
            } else {
                seen[slot] = 1
            }
            population.append(draft)
        }
        let kept = Array(population.prefix(options.maximumObservations))
        let dropped = population.count - kept.count
        var observations: [SD.Observation] = []
        for (ordinal, draft) in kept.enumerated() {
            observations.append(try SD.Observation(
                id: SD.RowID(reportID: evidenceBasisID, ordinal: ordinal), category: draft.category, componentPath: draft.path,
                subject: draft.subject, disposition: draft.disposition, previousState: draft.previousState,
                currentState: draft.currentState, previousValue: draft.previousValue, currentValue: draft.currentValue,
                evidence: draft.evidence, limitations: draft.limitations))
        }
        let plans = SD.Rules.derive(observations)
        let keptPlans = Array(plans.prefix(options.maximumFindings))
        let droppedFindings = plans.count - keptPlans.count
        let lookup = Dictionary(uniqueKeysWithValues: observations.map { ($0.id, $0) })
        var findings: [SD.Finding] = []
        for (ordinal, plan) in keptPlans.enumerated() {
            var evidence: [SD.EvidenceReference] = []
            for id in plan.ids {
                for item in lookup[id]?.evidence ?? [] where !evidence.contains(item) && evidence.count < SD.Observation.maximumReferences {
                    evidence.append(item)
                }
            }
            findings.append(try SD.Finding(id: SD.FindingID(reportID: evidenceBasisID, ordinal: ordinal), kind: plan.kind,
                                           disposition: plan.disposition, title: plan.title, explanation: plan.explanation,
                                           observationIDs: plan.ids, evidence: evidence, limitations: []))
        }

        var omissions: [SD.Omission] = []
        var details = previous.partialDetails + current.partialDetails + discovered
        if dropped > 0 {
            let why = SD.Analyzer.reason(.cap(.observationLimit), "observation limit reached")
            omissions.append(try SD.Omission(count: dropped, countIsExact: true, detailListComplete: false, reason: why,
                                             domain: .observations, cap: .observationLimit, boundedRange: nil,
                                             remainderUnknown: false, lowerBound: nil))
            details.append(try SD.PartialDetail(cap: .observationLimit, reason: why, side: nil, knownMismatchIDs: [],
                                                boundedRange: nil, omissionCount: dropped, remainderUnknown: false))
        }
        if droppedFindings > 0 {
            let why = SD.Analyzer.reason(.cap(.findingLimit), "finding limit reached")
            omissions.append(try SD.Omission(count: droppedFindings, countIsExact: true, detailListComplete: false, reason: why,
                                             domain: .findings, cap: .findingLimit, boundedRange: nil, remainderUnknown: false,
                                             lowerBound: nil))
            details.append(try SD.PartialDetail(cap: .findingLimit, reason: why, side: nil, knownMismatchIDs: [],
                                                boundedRange: nil, omissionCount: droppedFindings, remainderUnknown: false))
        }

        var counts = [0, 0, 0, 0, 0]
        for draft in population { counts[classify(draft)] += 1 }
        let accounted = population.count
        let categories = try SD.OpportunityCounts(accounted: accounted, compared: counts[0], provenAbsent: counts[1],
                                                  symmetricUnexamined: counts[2], unresolved: counts[3], excluded: counts[4],
                                                  total: details.contains { $0.remainderUnknown } ? nil : accounted)
        let slices = try SD.SliceCounts(observedKeys: tally.observed, uniquelyPaired: tally.paired, comparedSupported: tally.compared,
                                        unexaminedNotCompared: tally.unexamined, unmatched: tally.unmatched,
                                        ambiguous: tally.ambiguous, total: tally.observed)
        let denominators = try SD.Denominators(categories: categories, slices: slices, populationTotal: population.count)

        func scope(_ input: SD.Input) -> SD.ScopeState { input.inventory.isComplete ? .completeWithinScope : .partial }
        func exclusions(_ input: SD.Input) -> [SD.Reason] {
            input.inventory.scope.exclusions.filter(\.state.hides).prefix(32).map {
                SD.Analyzer.reason(.inventoryExcluded, "\($0.state.rawValue) \($0.rawPath.display)")
            }
        }
        func issues(_ input: SD.Input) -> [SD.Reason] {
            let count = input.inventory.scope.issues.count
            return count == 0 ? [] : [SD.Analyzer.reason(.inventoryIncomplete, "\(count) inventory issues")]
        }
        func locations(_ input: SD.Input) -> [SD.ExactKey] {
            input.inventory.scope.searchedLocations.map { SD.ExactKey(text: $0.range.display) }
        }
        let partial = scope(previous) != .completeWithinScope || scope(current) != .completeWithinScope || counts[3] > 0
            || !omissions.isEmpty || !details.isEmpty
        let coverage = try SD.Coverage(
            previousScope: scope(previous), currentScope: scope(current), previousLocations: locations(previous),
            currentLocations: locations(current), previousExclusions: exclusions(previous), currentExclusions: exclusions(current),
            previousIssues: issues(previous), currentIssues: issues(current),
            limitations: [SD.Analyzer.reason(.staticEvidenceOnly, "static evidence only; no runtime or trust claim")],
            omissions: omissions, denominators: denominators, status: partial ? .partial : .complete, partialDetails: details)
        let report = try SD.Report(identity: identity, options: options, observations: observations, findings: findings,
                                   coverage: coverage)
        return partial ? .partial(report) : .complete(report)
    }
}
