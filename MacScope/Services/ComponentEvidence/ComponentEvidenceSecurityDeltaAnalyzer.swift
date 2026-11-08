// Original to this item (AR3, NF05). Pure analysis of two validated sides into one report. No file is read here:
// every fact comes from the landed AR1 review and AR2 signature attachment. Two named gaps are surfaced as
// unresolved or PARTIAL states and never repaired: AR1/AR2 give no authority for resolving a duplicate numeric slice
// key, and the AR2 cross-check leaves digest correctness and lenient parsing uncovered, so a digest here is
// evidence of the captured bytes only. Unknown stays unknown: a failed or unexamined read never becomes absent.

import Foundation

extension ComponentEvidenceSecurityDelta {
    enum Analyzer {
        typealias CEv = ComponentEvidence

        /// Deterministic analysis. Cancellation and deadline throw a Refusal and publish no report.
        static func analyze(previous: Input, current: Input, options: Options? = nil, control: Control = .none,
                            evidenceBasisID: UUID = UUID()) throws -> Outcome {
            guard previous.side == .previous, current.side == .current else { throw Refusal.make(.invalidReview) }
            let options = try options ?? Options()
            var run = Run(previous: previous, current: current, control: control)
            try run.execute()
            return try run.finish(options: options, evidenceBasisID: evidenceBasisID)
        }

        struct Draft {
            var category: Category
            var path: ExactKey
            var subject: ExactKey
            var disposition: Disposition
            var previousState: SourceState
            var currentState: SourceState
            var previousValue: Value?
            var currentValue: Value?
            var evidence: [EvidenceReference]
            var limitations: [Reason]
        }

        /// A three-valued source fact.
        enum Probe {
            case present(Value)
            case absent
            case unavailable(ReasonCode)
        }

        struct SliceTally {
            var observed = 0, paired = 0, compared = 0, unexamined = 0, unmatched = 0, ambiguous = 0
        }

        // MARK: Small helpers

        static func exact(_ key: CEv.ExactUTF8Key) -> ExactKey {
            (try? ExactKey(utf8: Data(key.bytes))) ?? ExactKey(text: key.display)
        }

        static func hex32(_ value: UInt32) -> String { String(format: "%08x", value) }

        static func reason(_ code: ReasonCode, _ text: String = "") -> Reason {
            if let made = try? Reason(code: code, diagnostic: String(text.prefix(200))) { return made }
            return (try? Reason(code: code, diagnostic: ""))!
        }

        static func code(for problem: CEv.SignatureEvidenceProblem) -> ReasonCode {
            switch problem {
            case .unsupportedArchitecture: .unsupportedArchitecture
            case .readFailed: .readFailed
            case .capReached: .cap(.captureByteLimit)
            case .structureRefused, .codeDirectoryHeaderTruncated, .codeDirectoryTypeMagicMismatch: .signatureMalformed
            case .unsupportedDigestAlgorithm: .unsupportedHashType
            case .notExamined: .signatureUnexamined
            }
        }

        static func cap(for limit: CEv.CaptureLimit) -> Cap {
            switch limit {
            case .containerHashBytes, .headerBytes, .signatureBytes, .totalSignatureBytes: .captureByteLimit
            case .loadCommands, .slices, .slots: .sourceRecordLimit
            }
        }

        static func state(_ state: CEv.DeclarationState) -> SourceState {
            switch state {
            case .present: .observed
            case .notPresent: .absent
            case .unavailable: .unavailable
            }
        }

        // MARK: Run

        struct Run {
            let previous: Input
            let current: Input
            let control: Control
            var drafts: [Draft] = []
            var tally = SliceTally()
            var discovered: [PartialDetail] = []
            var usedXML = false

            init(previous: Input, current: Input, control: Control) {
                self.previous = previous; self.current = current; self.control = control
            }

            func input(_ side: Side) -> Input { side == .previous ? previous : current }

            func ref(_ side: Side, _ record: CEv.ComponentRecord, _ category: Category, source: ExactKey? = nil,
                     arch: String? = nil, key: String? = nil, slice: SliceIdentity? = nil) -> [EvidenceReference] {
                let owner = input(side)
                guard let made = try? EvidenceReference(
                    side: side, inventoryID: owner.inventory.id, componentID: record.id, category: category,
                    relativeSource: source ?? Analyzer.exact(record.path.key), architecture: arch,
                    evidenceKey: key.map { ExactKey(text: $0) }, slice: slice) else { return [] }
                return [made]
            }

            mutating func add(_ category: Category, _ path: ExactKey, _ subject: String, _ disposition: Disposition,
                              ps: SourceState, cs: SourceState, pv: Value? = nil, cv: Value? = nil,
                              evidence: [EvidenceReference] = [], limitations: [Reason] = []) {
                var notes = limitations
                if disposition == .unresolved, notes.isEmpty { notes = [Analyzer.reason(.evidenceConflict, "unresolved")] }
                drafts.append(Draft(category: category, path: path, subject: ExactKey(text: subject), disposition: disposition,
                                    previousState: ps, currentState: cs, previousValue: ps == .observed ? pv : nil,
                                    currentValue: cs == .observed ? cv : nil, evidence: evidence, limitations: notes))
            }

            /// Observed on both, one or neither side.
            mutating func change(_ category: Category, _ path: ExactKey, _ subject: String, _ pv: Value?, _ cv: Value?,
                                 evidence: [EvidenceReference], limitations: [Reason] = []) {
                switch (pv, cv) {
                case (nil, nil):
                    add(category, path, subject, .unchanged, ps: .absent, cs: .absent, evidence: evidence, limitations: limitations)
                case (nil, let b?):
                    add(category, path, subject, .observedAddition, ps: .absent, cs: .observed, cv: b, evidence: evidence,
                        limitations: limitations)
                case (let a?, nil):
                    add(category, path, subject, .observedRemoval, ps: .observed, cs: .absent, pv: a, evidence: evidence,
                        limitations: limitations)
                case (let a?, let b?):
                    add(category, path, subject, a == b ? .unchanged : .observedChange, ps: .observed, cs: .observed, pv: a,
                        cv: b, evidence: evidence, limitations: limitations)
                }
            }

            mutating func probeRow(_ category: Category, _ path: ExactKey, _ subject: String, _ p: Probe, _ c: Probe,
                                   evidence: [EvidenceReference]) {
                func parts(_ probe: Probe) -> (SourceState, Value?, Reason?) {
                    switch probe {
                    case .present(let value): (.observed, value, nil)
                    case .absent: (.absent, nil, nil)
                    case .unavailable(let code): (.unavailable, nil, Analyzer.reason(code))
                    }
                }
                let (ps, pv, pr) = parts(p), (cs, cv, cr) = parts(c)
                if ps == .unavailable || cs == .unavailable {
                    add(category, path, subject, .unresolved, ps: ps, cs: cs, pv: pv, cv: cv, evidence: evidence,
                        limitations: [pr, cr].compactMap { $0 })
                } else {
                    change(category, path, subject, pv, cv, evidence: evidence)
                }
            }

            mutating func execute() throws {
                let matches = CEv.ComponentMatcher().match(previous: previous.inventory, current: current.inventory)
                for match in matches {
                    try control.check()
                    try handle(match)
                }
            }

            // MARK: Matches

            mutating func handle(_ match: CEv.ComponentMatch) throws {
                let old = match.previousID.flatMap { previous.inventory.component($0) }
                let new = match.currentID.flatMap { current.inventory.component($0) }
                switch match.status {
                case .sameLocation:
                    guard let old, let new else { return }
                    inventory(old, new)
                    for category in [CEv.DeclarationCategory.info, .privacy] { declaration(old, new, category, nil) }
                    let architectures = Set(old.architectures).union(new.architectures).sorted()
                    for architecture in architectures { declaration(old, new, .loadCommands, architecture) }
                    try signatures(old, new)
                case .unmatchedPrevious:
                    guard let old else { return }
                    presence(old, .previous, other: current.inventory)
                case .unmatchedCurrent:
                    guard let new else { return }
                    presence(new, .current, other: previous.inventory)
                case .unobservedInOtherScope:
                    if let old { unresolvedComponent(old, .previous, .scopeUnsearched) }
                    if let new { unresolvedComponent(new, .current, .scopeUnsearched) }
                case .uniqueIdentifierCandidate, .ambiguous:
                    if let old { unresolvedComponent(old, .previous, .componentCorrespondenceUnaccepted) }
                    if let new { unresolvedComponent(new, .current, .componentCorrespondenceUnaccepted) }
                }
            }

            mutating func unresolvedComponent(_ record: CEv.ComponentRecord, _ side: Side, _ code: ReasonCode) {
                add(.componentInventory, Analyzer.exact(record.path.key), "component", .unresolved,
                    ps: side == .previous ? .observed : .unknown, cs: side == .current ? .observed : .unknown,
                    evidence: ref(side, record, .componentInventory), limitations: [Analyzer.reason(code, "component correspondence")])
            }

            /// Added or removed only when the other inventory was searched to completion.
            mutating func presence(_ record: CEv.ComponentRecord, _ side: Side, other: CEv.ComponentInventory) {
                let path = Analyzer.exact(record.path.key)
                let kind = Value.string(Analyzer.exact(record.kind))
                guard other.isComplete, other.covers(record.path) else {
                    unresolvedComponent(record, side, .inventoryIncomplete)
                    return
                }
                if side == .current {
                    add(.componentInventory, path, "component", .observedAddition, ps: .absent, cs: .observed, cv: kind,
                        evidence: ref(.current, record, .componentInventory))
                } else {
                    add(.componentInventory, path, "component", .observedRemoval, ps: .observed, cs: .absent, pv: kind,
                        evidence: ref(.previous, record, .componentInventory))
                }
            }

            mutating func inventory(_ old: CEv.ComponentRecord, _ new: CEv.ComponentRecord) {
                let path = Analyzer.exact(new.path.key)
                let evidence = ref(.previous, old, .componentInventory) + ref(.current, new, .componentInventory)
                func text(_ key: CEv.ExactUTF8Key?) -> Value? { key.map { .string(Analyzer.exact($0)) } }
                change(.componentInventory, path, "kind", text(old.kind), text(new.kind), evidence: evidence)
                change(.componentInventory, path, "declaredBundleID", text(old.declaredBundleID), text(new.declaredBundleID),
                       evidence: evidence)
                change(.componentInventory, path, "declaredVersion", text(old.declaredVersion), text(new.declaredVersion),
                       evidence: evidence)
                func architectures(_ record: CEv.ComponentRecord) -> Value {
                    .array(record.architectures.sorted().map { .string(Analyzer.exact($0)) })
                }
                change(.componentInventory, path, "architectures", architectures(old), architectures(new), evidence: evidence)
                if !old.metadataAvailable || !new.metadataAvailable {
                    add(.componentInventory, path, "metadata", .unresolved,
                        ps: old.metadataAvailable ? .observed : .unavailable, cs: new.metadataAvailable ? .observed : .unavailable,
                        evidence: evidence, limitations: [Analyzer.reason(.sourceUnavailable, "component metadata unavailable")])
                }
            }

            // MARK: Declarations

            mutating func declaration(_ old: CEv.ComponentRecord, _ new: CEv.ComponentRecord, _ kind: CEv.DeclarationCategory,
                                      _ architecture: CEv.ExactUTF8Key?) {
                let category: Category = switch kind {
                case .info: .informationPropertyList
                case .loadCommands: .loadCommands
                case .privacy: .privacyManifest
                }
                let path = Analyzer.exact(new.path.key)
                let label = architecture?.display
                let prefix = label.map { "arch=\($0)/" } ?? ""
                let p = previous.review.observation(component: old.id, category: kind, architecture: architecture)
                let c = current.review.observation(component: new.id, category: kind, architecture: architecture)
                func evidence(_ side: Side, _ record: CEv.ComponentRecord, _ observation: CEv.DeclarationObservation?) -> [EvidenceReference] {
                    ref(side, record, category, source: observation?.source.map { Analyzer.exact($0.path.key) }, arch: label)
                }
                guard p != nil || c != nil else {
                    add(category, path, prefix + "[declaration]", .unchanged, ps: .unexamined, cs: .unexamined,
                        limitations: [Analyzer.reason(.categoryUnexamined, "no observation on either side")])
                    return
                }
                guard let p, let c else {
                    add(category, path, prefix + "[declaration]", .unresolved,
                        ps: p.map { Analyzer.state($0.state) } ?? .unexamined, cs: c.map { Analyzer.state($0.state) } ?? .unexamined,
                        evidence: (p.map { evidence(.previous, old, $0) } ?? []) + (c.map { evidence(.current, new, $0) } ?? []),
                        limitations: [Analyzer.reason(.categoryUnexamined, "observation missing on one side")])
                    return
                }
                let both = evidence(.previous, old, p) + evidence(.current, new, c)
                guard let difference = try? CEv.DeclarationDifference(previous: p, current: c) else {
                    add(category, path, prefix + "[declaration]", .unresolved, ps: .unknown, cs: .unknown, evidence: both,
                        limitations: [Analyzer.reason(.evidenceConflict, "declaration pair does not correspond")])
                    return
                }
                switch difference.kind {
                case .comparedPresent:
                    let before = p.values ?? EntitlementDictionary(), after = c.values ?? EntitlementDictionary()
                    let rows = kind == .loadCommands
                        ? LoaderDelta.rows(previous: before, current: after)
                        : EntitlementDelta.diff(previous: before, current: after, previousTyped: false, currentTyped: false)
                    if rows.isEmpty {
                        add(category, path, prefix + "[empty]", .unchanged, ps: .observed, cs: .observed, evidence: both)
                    }
                    for row in rows { addRow(category, path, prefix, row, evidence: both) }
                case .becameAbsent:
                    add(category, path, prefix + "[declaration]", .observedRemoval, ps: .observed, cs: .absent, evidence: both)
                case .becamePresent:
                    add(category, path, prefix + "[declaration]", .observedAddition, ps: .absent, cs: .observed, evidence: both)
                case .bothAbsent:
                    add(category, path, prefix + "[declaration]", .unchanged, ps: .absent, cs: .absent, evidence: both)
                case .unavailable:
                    add(category, path, prefix + "[declaration]", .unresolved, ps: Analyzer.state(p.state),
                        cs: Analyzer.state(c.state), evidence: both,
                        limitations: [Analyzer.reason(.sourceUnavailable, "declaration unavailable")])
                }
            }

            mutating func addRow(_ category: Category, _ path: ExactKey, _ prefix: String, _ row: EntitlementDelta.Row,
                                 evidence: [EvidenceReference], extra: [Reason] = []) {
                let subject = prefix + (String(data: row.key.utf8, encoding: .utf8) ?? "[key]")
                switch row.kind {
                case .unchanged:
                    add(category, path, subject, .unchanged, ps: .observed, cs: .observed, pv: row.previous, cv: row.current,
                        evidence: evidence, limitations: extra)
                case .added:
                    add(category, path, subject, .observedAddition, ps: .absent, cs: .observed, cv: row.current,
                        evidence: evidence, limitations: extra)
                case .removed:
                    add(category, path, subject, .observedRemoval, ps: .observed, cs: .absent, pv: row.previous,
                        evidence: evidence, limitations: extra)
                case .changed:
                    add(category, path, subject, .observedChange, ps: .observed, cs: .observed, pv: row.previous, cv: row.current,
                        evidence: evidence, limitations: extra)
                case .unresolved:
                    add(category, path, subject, .unresolved, ps: row.previous == nil ? .unknown : .observed,
                        cs: row.current == nil ? .unknown : .observed, pv: row.previous, cv: row.current, evidence: evidence,
                        limitations: [Analyzer.reason(row.reason ?? .evidenceConflict, "value not decidable")] + extra)
                }
            }

            // MARK: Signatures and entitlements

            mutating func signatures(_ old: CEv.ComponentRecord, _ new: CEv.ComponentRecord) throws {
                let path = Analyzer.exact(new.path.key)
                let sides: [(Side, CEv.ComponentRecord)] = [(.previous, old), (.current, new)]
                var failed = false
                for (side, record) in sides {
                    guard let failure = input(side).signatures?.failures.first(where: { $0.componentID == record.path }) else { continue }
                    failed = true
                    var code = ReasonCode.readFailed
                    switch BoundaryTranslator.translate(failure.error) {
                    case .cancelled: throw Refusal.make(.cancelled, side: side, kind: .cancelled)
                    case .invalidReview(let refusal): throw Refusal.make(refusal, side: side)
                    case .unavailable(let kind): code = kind == .readFailed ? .readFailed : .upstreamUnknown(kind)
                    }
                    for category in [Category.signatureEvidence, .entitlements] {
                        add(category, path, "[capture]", .unresolved, ps: side == .previous ? .unavailable : .unknown,
                            cs: side == .current ? .unavailable : .unknown, evidence: ref(side, record, category),
                            limitations: [Analyzer.reason(code, "signature capture failed")])
                    }
                }
                if failed { return }
                let p = previous.signatures?.evidence(for: old.path), c = current.signatures?.evidence(for: new.path)
                guard let p, let c else {
                    let symmetric = p == nil && c == nil
                    for category in [Category.signatureEvidence, .entitlements] {
                        let evidence = ref(.previous, old, category) + ref(.current, new, category)
                        if symmetric {
                            add(category, path, "[signature]", .unchanged, ps: .unexamined, cs: .unexamined, evidence: evidence,
                                limitations: [Analyzer.reason(.signatureUnexamined, "no signature evidence on either side")])
                        } else {
                            add(category, path, "[signature]", .unresolved, ps: p == nil ? .unexamined : .observed,
                                cs: c == nil ? .unexamined : .observed, evidence: evidence,
                                limitations: [Analyzer.reason(.signatureUnexamined, "signature evidence on one side only")])
                        }
                    }
                    return
                }
                for (side, record, container) in [(Side.previous, old, p), (.current, new, c)] {
                    if case .partial(let capture) = container.completion {
                        let limit = capture.losses.first.map { Analyzer.cap(for: $0.limit) } ?? .upstream(.budget)
                        if let detail = try? PartialDetail(cap: limit, reason: Analyzer.reason(.signatureBudgetExceeded,
                                                           "signature capture partial: \(record.path.display)"),
                                                           side: side, knownMismatchIDs: [], boundedRange: nil,
                                                           omissionCount: capture.observedOmittedSliceCount,
                                                           remainderUnknown: capture.remainderUnknown) {
                            discovered.append(detail)
                        }
                    }
                }
                let containerEvidence = ref(.previous, old, .signatureEvidence) + ref(.current, new, .signatureEvidence)
                probeRow(.signatureEvidence, path, "containerSHA256", digest(p.containerSHA256), digest(c.containerSHA256),
                         evidence: containerEvidence)
                var left: [PairingKey: [CEv.SignatureSliceEvidence]] = [:], right = left
                for slice in p.slices { left[Self.pairing(slice.key), default: []].append(slice) }
                for slice in c.slices { right[Self.pairing(slice.key), default: []].append(slice) }
                let rightComplete = { if case .complete = c.completion { true } else { false } }()
                let leftComplete = { if case .complete = p.completion { true } else { false } }()
                for key in Set(left.keys).union(right.keys).sorted() {
                    try control.check()
                    tally.observed += 1
                    let a = left[key] ?? [], b = right[key] ?? []
                    let name = "slice[cpu=\(Analyzer.hex32(key.cpuType)),sub=\(Analyzer.hex32(key.cpuSubtype)),magic=\(Analyzer.hex32(key.headerMagic))]"
                    if a.count > 1 || b.count > 1 {
                        tally.ambiguous += 1
                        add(.signatureEvidence, path, name, .unresolved, ps: a.isEmpty ? .unknown : .observed,
                            cs: b.isEmpty ? .unknown : .observed, evidence: containerEvidence,
                            limitations: [Analyzer.reason(.sliceCorrespondenceUnresolved, "duplicate numeric slice key")])
                    } else if let x = a.first, let y = b.first {
                        tally.paired += 1
                        compareSlice(old, new, path, name, x, y)
                    } else if let x = a.first {
                        tally.unmatched += 1
                        sliceOnly(old, .previous, path, name, x, otherComplete: rightComplete)
                    } else if let y = b.first {
                        tally.unmatched += 1
                        sliceOnly(new, .current, path, name, y, otherComplete: leftComplete)
                    }
                }
            }

            static func pairing(_ key: CEv.SignatureSliceKey) -> PairingKey {
                PairingKey(cpuType: key.cpuType, cpuSubtype: key.cpuSubtype, headerMagic: key.headerMagic)
            }

            func identity(_ slice: CEv.SignatureSliceEvidence) -> SliceIdentity? {
                var recorded: Data?
                if case .complete(_, let bytes, _) = slice.sliceSHA256 { recorded = Data(bytes) }
                return try? SliceIdentity(cpuType: slice.key.cpuType, cpuSubtype: slice.key.cpuSubtype,
                                          headerMagic: slice.key.headerMagic, index: slice.key.index,
                                          offset: slice.key.sliceOffset, size: slice.key.sliceSize, recordedSHA256: recorded)
            }

            mutating func sliceOnly(_ record: CEv.ComponentRecord, _ side: Side, _ path: ExactKey, _ name: String,
                                    _ slice: CEv.SignatureSliceEvidence, otherComplete: Bool) {
                let evidence = ref(side, record, .signatureEvidence, key: name, slice: identity(slice))
                if otherComplete {
                    if side == .previous {
                        add(.signatureEvidence, path, name, .observedRemoval, ps: .observed, cs: .absent, evidence: evidence)
                    } else {
                        add(.signatureEvidence, path, name, .observedAddition, ps: .absent, cs: .observed, evidence: evidence)
                    }
                } else {
                    add(.signatureEvidence, path, name, .unresolved, ps: side == .previous ? .observed : .unknown,
                        cs: side == .current ? .observed : .unknown, evidence: evidence,
                        limitations: [Analyzer.reason(.inventoryIncomplete, "other side slice list is partial")])
                }
            }

            func digest(_ observation: CEv.DigestObservation) -> Probe {
                switch observation {
                case .complete(_, let bytes, _): .present(.data(Data(bytes)))
                case .unavailable(let problem): .unavailable(Analyzer.code(for: problem))
                case .prefix: .unavailable(.signatureBudgetExceeded)
                }
            }

            func presence<T: Sendable & Hashable>(_ value: CEv.EvidencePresence<T>, _ map: (T) -> Value) -> Probe {
                switch value {
                case .present(let inner): .present(map(inner))
                case .notPresent: .absent
                case .unavailable(let problem): .unavailable(Analyzer.code(for: problem))
                }
            }

            static func label(_ state: CEv.SignatureEvidenceState) -> (text: String, supported: Bool, benign: Bool) {
                switch state {
                case .collected: ("collected", true, false)
                case .signatureAbsent: ("signatureAbsent", true, false)
                case .entitlementsAbsent: ("entitlementsAbsent", true, false)
                case .unexamined(let problem):
                    switch problem {
                    case .notExamined: ("unexamined:notExamined", false, true)
                    case .unsupportedArchitecture: ("unexamined:unsupportedArchitecture", false, true)
                    default: ("unexamined:other", false, false)
                    }
                case .malformed: ("malformed", false, false)
                case .budgetExceeded: ("budgetExceeded", false, false)
                }
            }

            static func stateReason(_ state: CEv.SignatureEvidenceState) -> ReasonCode {
                switch state {
                case .malformed: .signatureMalformed
                case .budgetExceeded: .signatureBudgetExceeded
                case .unexamined: .signatureUnexamined
                default: .signatureStatesUnresolved
                }
            }

            mutating func compareSlice(_ old: CEv.ComponentRecord, _ new: CEv.ComponentRecord, _ path: ExactKey, _ name: String,
                                       _ p: CEv.SignatureSliceEvidence, _ c: CEv.SignatureSliceEvidence) {
                let evidence = ref(.previous, old, .signatureEvidence, key: name, slice: identity(p))
                    + ref(.current, new, .signatureEvidence, key: name, slice: identity(c))
                let entitlementEvidence = ref(.previous, old, .entitlements, key: name, slice: identity(p))
                    + ref(.current, new, .entitlements, key: name, slice: identity(c))
                let a = Self.label(p.state), b = Self.label(c.state)
                guard a.supported, b.supported else {
                    if !a.supported, !b.supported, a.text == b.text, a.benign {
                        tally.unexamined += 1
                        let note = [Analyzer.reason(.signatureUnexamined, "unexamined, not compared")]
                        add(.signatureEvidence, path, name + "/state", .unchanged, ps: .unexamined, cs: .unexamined,
                            evidence: evidence, limitations: note)
                        add(.entitlements, path, name + "/entitlements", .unchanged, ps: .unexamined, cs: .unexamined,
                            evidence: entitlementEvidence, limitations: note)
                        return
                    }
                    let why = !a.supported ? Self.stateReason(p.state) : Self.stateReason(c.state)
                    let note = [Analyzer.reason(why, "\(a.text) versus \(b.text)")]
                    add(.signatureEvidence, path, name + "/state", .unresolved, ps: a.supported ? .observed : .unexamined,
                        cs: b.supported ? .observed : .unexamined, evidence: evidence, limitations: note)
                    add(.entitlements, path, name + "/entitlements", .unresolved, ps: .unknown, cs: .unknown,
                        evidence: entitlementEvidence, limitations: note)
                    return
                }
                tally.compared += 1
                change(.signatureEvidence, path, name + "/state", .string(ExactKey(text: a.text)), .string(ExactKey(text: b.text)),
                       evidence: evidence)
                probeRow(.signatureEvidence, path, name + "/sliceSHA256", digest(p.sliceSHA256), digest(c.sliceSHA256), evidence: evidence)
                func slots(_ value: CEv.SlotInventoryObservation) -> Probe {
                    presence(value) { records in
                        .array(records.sorted { $0.slot < $1.slot }.map {
                            .string(ExactKey(text: "slot=\($0.slot),magic=\(Analyzer.hex32($0.magic)),length=\($0.length)"))
                        })
                    }
                }
                probeRow(.signatureEvidence, path, name + "/slots", slots(p.slots), slots(c.slots), evidence: evidence)
                func blob(_ value: CEv.EvidencePresence<CEv.SignatureBlobEvidence>) -> Probe {
                    presence(value) { .data(Data($0.sha256)) }
                }
                probeRow(.signatureEvidence, path, name + "/entitlementsXMLBlobSHA256", blob(p.entitlementsXML), blob(c.entitlementsXML),
                         evidence: evidence)
                probeRow(.signatureEvidence, path, name + "/entitlementsDERBlobSHA256", blob(p.entitlementsDER), blob(c.entitlementsDER),
                         evidence: evidence)
                codeDirectories(path, name, p.codeDirectories, c.codeDirectories, evidence)
                entitlements(old, new, path, name, p, c, entitlementEvidence)
            }

            // MARK: CodeDirectory correspondence by (slot, hashType)

            mutating func codeDirectories(_ path: ExactKey, _ name: String, _ p: CEv.EvidencePresence<[CEv.CodeDirectoryEvidence]>,
                                          _ c: CEv.EvidencePresence<[CEv.CodeDirectoryEvidence]>, _ evidence: [EvidenceReference]) {
                func table(_ value: CEv.EvidencePresence<[CEv.CodeDirectoryEvidence]>) -> (map: [String: [CEv.CodeDirectoryEvidence]]?, reason: ReasonCode?) {
                    switch value {
                    case .present(let list):
                        var map: [String: [CEv.CodeDirectoryEvidence]] = [:]
                        for item in list { map["slot=\(item.slot),hashType=\(item.hashType.map(String.init) ?? "none")", default: []].append(item) }
                        return (map, nil)
                    case .notPresent: return ([:], nil)
                    case .unavailable(let problem): return (nil, Analyzer.code(for: problem))
                    }
                }
                let (left, leftReason) = table(p), (right, rightReason) = table(c)
                guard let left, let right else {
                    add(.signatureEvidence, path, name + "/codeDirectories", .unresolved, ps: left == nil ? .unavailable : .observed,
                        cs: right == nil ? .unavailable : .observed, evidence: evidence,
                        limitations: [leftReason, rightReason].compactMap { $0 }.map { Analyzer.reason($0) })
                    return
                }
                for key in Set(left.keys).union(right.keys).sorted() {
                    let a = left[key] ?? [], b = right[key] ?? []
                    let subject = name + "/codeDirectory[\(key)]"
                    if a.count > 1 || b.count > 1 {
                        add(.signatureEvidence, path, subject, .unresolved, ps: a.isEmpty ? .absent : .observed,
                            cs: b.isEmpty ? .absent : .observed, evidence: evidence,
                            limitations: [Analyzer.reason(.codeDirectoryCorrespondenceUnresolved, "duplicate (slot, hashType)")])
                        continue
                    }
                    func digestProbe(_ item: CEv.CodeDirectoryEvidence?) -> Probe {
                        guard let item else { return .absent }
                        switch item.digest {
                        case .available(let value):
                            return .present(.array([.string(ExactKey(text: value.algorithm.rawValue)), .data(Data(value.fullBytes))]))
                        case .unavailable(let problem): return .unavailable(Analyzer.code(for: problem))
                        }
                    }
                    probeRow(.signatureEvidence, path, subject + "/digest", digestProbe(a.first), digestProbe(b.first), evidence: evidence)
                    probeRow(.signatureEvidence, path, subject + "/rawBlobSHA256",
                             a.first.map { .present(.data(Data($0.rawBlobSHA256))) } ?? .absent,
                             b.first.map { .present(.data(Data($0.rawBlobSHA256))) } ?? .absent, evidence: evidence)
                }
            }

            // MARK: Entitlements through the AR2 raw adapter

            private struct Side3 {
                var dictionary: EntitlementDictionary?
                var typed = false
                var xml = false
                var absent = false
                var reason: Reason?
                var note: Reason?
            }

            private func resolve(_ record: CEv.ComponentRecord, _ side: Side, _ slice: CEv.SignatureSliceEvidence) -> Side3 {
                guard let attachment = input(side).signatures else {
                    return Side3(reason: Analyzer.reason(.signatureUnexamined, "no attachment"))
                }
                let key = CEv.SignatureEvidenceKey(inventoryID: attachment.inventoryID, componentID: record.path, slice: slice.key)
                let result = CEv.RawEntitlementAdapter.convert(slice: slice, key: key)
                var out = Side3()
                switch result.agreement {
                case .nonePresent:
                    out.absent = true; out.dictionary = EntitlementDictionary()
                case .xmlOnly:
                    out.dictionary = result.xml?.dictionary; out.xml = true
                case .derOnly:
                    out.dictionary = result.der?.dictionary; out.typed = true
                case .bothEquivalent:
                    out.dictionary = result.der?.dictionary ?? result.xml?.dictionary; out.typed = result.der?.dictionary != nil
                case .bothDifferent:
                    out.reason = Analyzer.reason(.xmlDerDisagreement, "XML and DER entitlements disagree")
                case .oneUnavailable(let available, _):
                    let form = available == .xml ? result.xml : result.der
                    out.dictionary = form?.dictionary; out.typed = available == .der; out.xml = available == .xml
                    out.note = Analyzer.reason(.oneFormUnavailable, "one entitlement form unavailable")
                case .sliceUnavailable(let problem):
                    out.reason = Analyzer.reason(Analyzer.code(for: problem), "slice entitlements unavailable")
                default:
                    out.reason = Analyzer.reason(.oneFormUnavailable, "entitlement forms unavailable")
                }
                if out.dictionary == nil, out.reason == nil {
                    out.reason = Analyzer.reason(.oneFormUnavailable, "entitlement form not decoded")
                }
                return out
            }

            mutating func entitlements(_ old: CEv.ComponentRecord, _ new: CEv.ComponentRecord, _ path: ExactKey, _ name: String,
                                       _ p: CEv.SignatureSliceEvidence, _ c: CEv.SignatureSliceEvidence, _ evidence: [EvidenceReference]) {
                let a = resolve(old, .previous, p), b = resolve(new, .current, c)
                func state(_ side: Side3) -> SourceState { side.reason != nil ? .unavailable : (side.absent ? .absent : .observed) }
                guard let before = a.dictionary, let after = b.dictionary else {
                    add(.entitlements, path, name + "/entitlements", .unresolved, ps: state(a), cs: state(b), evidence: evidence,
                        limitations: [a.reason, b.reason].compactMap { $0 })
                    return
                }
                if a.absent, b.absent {
                    add(.entitlements, path, name + "/entitlements", .unchanged, ps: .absent, cs: .absent, evidence: evidence)
                    return
                }
                var notes = [a.note, b.note].compactMap { $0 }
                if a.xml || b.xml {
                    usedXML = true
                    notes.append(Analyzer.reason(.staticEvidenceOnly, "XML keys via Foundation; byte fidelity not proved"))
                }
                let rows = EntitlementDelta.diff(previous: before, current: after, previousTyped: a.typed, currentTyped: b.typed)
                if rows.isEmpty {
                    add(.entitlements, path, name + "/entitlements", .unchanged, ps: .observed, cs: .observed, evidence: evidence,
                        limitations: notes)
                }
                for row in rows { addRow(.entitlements, path, name + "/", row, evidence: evidence, extra: notes) }
            }
        }
    }
}
