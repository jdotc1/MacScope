import Foundation

/// Inert raw-record query, NOT a Type Atlas lookup or operation authorization. In particular,
/// a name-only external-adoption catalog row never establishes a recovered declaration.
struct ExactProtocolReadSelector: Sendable {
    let owner: Phase2ReadImageOwner
    let entryID: TypeAtlasEntryID
}

enum ExactProtocolReadFailure: Error, Equatable, Sendable {
    case unsupportedKind, invalidSelector, unresolvedOwner, analysisUnavailable
    case limitExceeded, deadlineExceeded, staleSource
}

/// Positive, tighten-only ceilings. Graph/encoding admission is deliberately conservative:
/// fixed wrapper reserves and formatter expansion may reject an otherwise small exact result.
struct ExactProtocolReadLimits: Sendable {
    var selectorUTF8Bytes = 1_024
    var imageRows = 256
    var rawRecords = 1_024
    var members = 4_096
    var textUTF8Bytes = 4_096
    var capturedUTF8Bytes = 1_048_576
    var rendererUTF8Bytes = 2_097_152
    var projectionNodes = 16_384
    var projectionDepth = 32
    var projectionUTF8Bytes = 262_144
    var encodedBytes = 1_048_576
    var duration: Duration = .seconds(10)

    fileprivate func validate() throws {
        let pairs = [(selectorUTF8Bytes, 1_024), (imageRows, 256), (rawRecords, 1_024),
            (members, 4_096), (textUTF8Bytes, 4_096), (capturedUTF8Bytes, 1_048_576),
            (rendererUTF8Bytes, 2_097_152), (projectionNodes, 16_384), (projectionDepth, 32),
            (projectionUTF8Bytes, 262_144), (encodedBytes, 1_048_576)]
        guard pairs.allSatisfy({ $0.0 > 0 && $0.0 <= $0.1 }),
              duration > .zero, duration <= .seconds(10) else {
            throw ExactProtocolReadFailure.limitExceeded
        }
    }
}

extension WorkspaceScriptingAPI {
    /// Snapshot membership is not live authority. Production delivery must use the controller.
    nonisolated static func exactProtocolRead(
        selector: ExactProtocolReadSelector, snapshot: WorkspaceSnapshot,
        limits: ExactProtocolReadLimits = .init(), checkpoint: () throws -> Void = {},
        now: () -> ContinuousClock.Instant = { ContinuousClock.now }
    ) throws -> ScriptValue {
        let started = now()
        try limits.validate()
        let deadline = started.advanced(by: limits.duration)
        return try exactProtocolProjection(selector: selector, snapshot: snapshot, limits: limits,
            deadline: deadline, checkpoint: checkpoint, now: now)
    }

    /// The controller passes its ORIGINAL deadline, including admission and snapshot capture.
    fileprivate nonisolated static func exactProtocolProjection(
        selector: ExactProtocolReadSelector, snapshot: WorkspaceSnapshot, limits: ExactProtocolReadLimits,
        deadline: ContinuousClock.Instant, checkpoint: () throws -> Void,
        now: () -> ContinuousClock.Instant
    ) throws -> ScriptValue {
        try limits.validate()
        func check() throws {
            try Task.checkCancellation()
            try checkpoint()
            guard now() < deadline else { throw ExactProtocolReadFailure.deadlineExceeded }
        }
        try check()
        guard selector.entryID.kind == .objcProtocol else { throw ExactProtocolReadFailure.unsupportedKind }
        guard selector.entryID.slot == selector.owner.slot,
              selector.owner.architecture.utf8.prefix(limits.selectorUTF8Bytes + 1).count <= limits.selectorUTF8Bytes else {
            throw ExactProtocolReadFailure.invalidSelector
        }
        if case .name(let name) = selector.entryID.key {
            guard !name.isEmpty, name.utf8.prefix(limits.selectorUTF8Bytes + 1).count <= limits.selectorUTF8Bytes,
                  !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                throw ExactProtocolReadFailure.invalidSelector
            }
        }
        guard snapshot.binaries.count <= limits.imageRows else { throw ExactProtocolReadFailure.limitExceeded }
        var slots = 0, owners = 0
        for binary in snapshot.binaries {
            try check()
            if binary.id == selector.owner.binaryID { owners += 1 }
            if binary.slot == selector.owner.slot {
                slots += 1
                guard binary.id == selector.owner.binaryID,
                      binary.architecture.utf8.elementsEqual(selector.owner.architecture.utf8),
                      binary.selectedSliceIndex == selector.owner.sliceIndex else {
                    throw ExactProtocolReadFailure.unresolvedOwner
                }
            }
        }
        guard slots == 1, owners == 1 else { throw ExactProtocolReadFailure.unresolvedOwner }
        guard let records = snapshot.analysis(in: selector.owner.slot)?.objcProtocols else {
            throw ExactProtocolReadFailure.analysisUnavailable
        }
        guard records.count <= limits.rawRecords else { throw ExactProtocolReadFailure.limitExceeded }

        // Complete raw-input admission before allocating match vectors, byte keys, result graphs,
        // or invoking the synchronous renderer. Every captured encoding/attribute is included.
        var memberCount = 0, capturedBytes = 0
        func charge(_ text: String) throws {
            try check()
            let count = text.utf8.prefix(limits.textUTF8Bytes + 1).count
            guard count <= limits.textUTF8Bytes, count <= limits.capturedUTF8Bytes - capturedBytes else {
                throw ExactProtocolReadFailure.limitExceeded
            }
            capturedBytes += count
        }
        for record in records {
            try check()
            for count in [record.adoptedProtocols.count, record.requiredMethods.count,
                          record.optionalMethods.count, record.properties.count] {
                guard count <= limits.members - memberCount else { throw ExactProtocolReadFailure.limitExceeded }
                memberCount += count
            }
            try charge(record.name)
            for name in record.adoptedProtocols { try charge(name) }
            for methods in [record.requiredMethods, record.optionalMethods] {
                for method in methods {
                    try charge(method.selector)
                    if let encoding = method.typeEncoding { try charge(encoding) }
                }
            }
            for property in record.properties { try charge(property.name); try charge(property.attributes) }
        }

        var direct: [Int] = []
        for index in records.indices {
            try check()
            let matches: Bool
            switch selector.entryID.key {
            case .address(let address): matches = records[index].address == address
            case .name(let name): matches = records[index].name.utf8.elementsEqual(name.utf8)
            }
            if matches { direct.append(index) }
        }
        // Do not hide a collision by filtering down to the single direct address/name hit.
        // Even identical repetitions are ambiguous. No canonical-equivalence String keys.
        var relevant: [Int] = []
        for index in records.indices {
            try check()
            var belongs = false
            for hit in direct {
                try check()
                if records[index].address == records[hit].address
                    || records[index].name.utf8.elementsEqual(records[hit].name.utf8) {
                    belongs = true
                    break
                }
            }
            if belongs { relevant.append(index) }
        }
        let found = direct.count == 1 && relevant.count == 1
        let chosen = found ? records[direct[0]] : nil

        // Checked/subtractive accounting; all terms are already hard-bounded above. Estimate
        // formatter work BEFORE render allocation. The existing decoder has a cumulative 8192
        // output budget, <=64 selector arguments, <=512 selector bytes; 32768/method also
        // covers fallback argument spelling. Diagnostic escaping <=10 bytes/scalar (160 max).
        var renderBound = 0
        if let record = chosen {
            renderBound = 8_192
            func reserveRender(_ count: Int, each: Int) throws {
                guard count <= (limits.rendererUTF8Bytes - renderBound) / each else {
                    throw ExactProtocolReadFailure.limitExceeded
                }
                renderBound += count * each
            }
            guard renderBound <= limits.rendererUTF8Bytes else { throw ExactProtocolReadFailure.limitExceeded }
            try reserveRender(record.requiredMethods.count, each: 32_768)
            try reserveRender(record.optionalMethods.count, each: 32_768)
            try reserveRender(record.properties.count, each: 4_096)
            try reserveRender(record.adoptedProtocols.count, each: 2_048)
        }
        // Full result graph preflight, not a post-allocation graph-only check. Conservatively
        // charge ALL raw members for the node reserve, including members not projected. Text
        // is charged per projected occurrence below. Depth reserve 8 covers the complete wrapper;
        // fixed nodes cover selector/owner/claim fields.
        let nodeBound = 128 + memberCount * 10 + relevant.count * 8
        guard nodeBound <= limits.projectionNodes, limits.projectionDepth >= 8 else {
            throw ExactProtocolReadFailure.limitExceeded
        }
        // Count EVERY projected key/string occurrence before result construction. Captured
        // input admission above is independent: one raw name can be projected more than once,
        // and generated hex/decimal/UUID strings do not occur in the captured text at all.
        var textBound = 0
        func reserveTextBytes(_ count: Int) throws {
            guard count >= 0, count <= limits.projectionUTF8Bytes - textBound else {
                throw ExactProtocolReadFailure.limitExceeded
            }
            textBound += count
        }
        func reserveText(_ text: String) throws {
            try check()
            // Every dynamic input here was individually admitted above; literals are fixed.
            try reserveTextBytes(text.utf8.count)
        }
        func reserveRepeatedText(_ count: Int, each: Int) throws {
            guard count >= 0, each > 0,
                  count <= (limits.projectionUTF8Bytes - textBound) / each else {
                throw ExactProtocolReadFailure.limitExceeded
            }
            textBound += count * each
        }
        func reserveKeys(_ keys: [String]) throws {
            for key in keys { try reserveText(key) }
        }
        // Complete wrapper and selector keys, including string-valued generated provenance.
        try reserveKeys(["imageSlot", "imageOwner", "selector", "ownerGeneration", "architecture",
            "sliceIndex", "status", "scope", "renderingClaim", "matches", "protocol", "rendered"])
        try reserveKeys(["slot", "kind"])
        try reserveText("objcProtocol")
        switch selector.entryID.key {
        case .address:
            try reserveText("address"); try reserveTextBytes(18) // 0x + <=16 UInt64 hex digits.
        case .name(let name):
            try reserveText("name"); try reserveText(name)
        }
        try reserveTextBytes(36) // Binary UUID spelling.
        try reserveTextBytes(20) // UInt64 owner generation decimal spelling.
        try reserveText(selector.owner.architecture)
        // Upper-bound the closed status vocabulary without allocating a selected status string.
        try reserveTextBytes(31) // absentInCurrentRecoveredRecords is the longest status.
        try reserveText("Retained selected-image records only; absence is not completeness.")
        try reserveText("Source-like display only; may contain diagnostics/refusals; not proof of a complete declaration, ABI, runtime behavior or callable body.")
        // Each match repeats its own name, address and all row keys. Do not substitute a
        // one-time captured-input total for this repeated projection accounting.
        try reserveRepeatedText(relevant.count, each: 18)
        for index in relevant {
            try check()
            try reserveKeys(["rawIndex", "name", "address"])
            try reserveText(records[index].name)
        }
        if let record = chosen {
            try reserveKeys(["name", "address", "inheritedUnresolvedNames", "requiredMethods",
                "optionalMethods", "propertiesRequirementUnknown"])
            try reserveText(record.name) // Additional occurrence, even though matches repeats it.
            try reserveTextBytes(18)
            for name in record.adoptedProtocols { try reserveText(name) }
            for methods in [record.requiredMethods, record.optionalMethods] {
                for method in methods {
                    try check()
                    try reserveKeys(["selector", "typeEncoding", "isClassMethod", "retainedIMP"])
                    try reserveText(method.selector)
                    if let encoding = method.typeEncoding { try reserveText(encoding) }
                    if method.implementation != nil { try reserveTextBytes(18) }
                }
            }
            for property in record.properties {
                try check()
                try reserveKeys(["name", "attributes"])
                try reserveText(property.name); try reserveText(property.attributes)
            }
            try reserveTextBytes(renderBound)
        }
        // Independent full-wrapper JSON cap: all keys/string values above get a conservative
        // six-byte UTF-8 escape expansion. The retained 96 bytes per graph node cover scalar digits
        // (<=20), string/key quotes, colon/comma and container delimiters. Keys are NOT hidden
        // in that structural reserve; their repeated text is charged explicitly above.
        guard nodeBound <= limits.encodedBytes / 96 else { throw ExactProtocolReadFailure.limitExceeded }
        let syntaxBound = nodeBound * 96
        guard textBound <= (limits.encodedBytes - syntaxBound) / 6 else {
            throw ExactProtocolReadFailure.limitExceeded
        }
        try check()

        var identity: [String: ScriptValue] = ["slot": .int(Int64(selector.owner.slot.rawValue)),
            "kind": .string("objcProtocol")]
        switch selector.entryID.key {
        case .address(let address): identity["address"] = .hex(address)
        case .name(let name): identity["name"] = .string(name)
        }
        var fields = imageProvenanceFields(slot: selector.owner.slot, snapshot: snapshot)
        fields["selector"] = .object(identity)
        fields["ownerGeneration"] = .string(String(selector.owner.ownerGeneration))
        fields["architecture"] = .string(selector.owner.architecture)
        fields["sliceIndex"] = selector.owner.sliceIndex.map { .int(Int64($0)) } ?? .null
        fields["status"] = .string(direct.isEmpty ? "absentInCurrentRecoveredRecords" : (found ? "found" : "multiple"))
        fields["scope"] = .string("Retained selected-image records only; absence is not completeness.")
        fields["renderingClaim"] = .string("Source-like display only; may contain diagnostics/refusals; not proof of a complete declaration, ABI, runtime behavior or callable body.")
        fields["matches"] = .array(try relevant.map { index in
            try check()
            return .object(["rawIndex": .int(Int64(index)), "name": .string(records[index].name),
                            "address": .hex(records[index].address)])
        })
        fields["protocol"] = .null
        fields["rendered"] = .null
        if let record = chosen {
            func method(_ value: ObjCMethod) throws -> ScriptValue {
                try check()
                return .object(["selector": .string(value.selector),
                    "typeEncoding": value.typeEncoding.map { .string($0) } ?? .null,
                    "isClassMethod": .bool(value.isClassMethod),
                    "retainedIMP": value.implementation.map { .hex($0) } ?? .null])
            }
            fields["protocol"] = .object(["name": .string(record.name), "address": .hex(record.address),
                "inheritedUnresolvedNames": .array(try record.adoptedProtocols.map { name in
                    try check(); return .string(name)
                }),
                "requiredMethods": .array(try record.requiredMethods.map(method)),
                "optionalMethods": .array(try record.optionalMethods.map(method)),
                "propertiesRequirementUnknown": .array(try record.properties.map { property in
                    try check(); return .object(["name": .string(property.name), "attributes": .string(property.attributes)])
                })])
            try check()
            // Existing bounded formatter is cooperative synchronous work, not hard-interruptible.
            let rendered = ObjectiveCProtocolRenderer.render(protocols: [record])
            try check()
            guard rendered.utf8.count <= renderBound, rendered.utf8.count <= limits.rendererUTF8Bytes else {
                throw ExactProtocolReadFailure.limitExceeded
            }
            fields["rendered"] = .string(rendered)
        }
        let result = ScriptValue.object(fields)
        try check()
        guard try result.jsonData().count <= limits.encodedBytes else { throw ExactProtocolReadFailure.limitExceeded }
        try check()
        return result
    }
}

/// Internal composition seam only: actual document-owned store/session, existing ledger/bridge,
/// no registry entry or transport grant. The clock closure is the sole deterministic timing seam.
@MainActor
final class ExactProtocolReadController {
    struct Prepared: Sendable {
        fileprivate let controllerID: UUID
        fileprivate let state: Phase2ReadCurrentState
        fileprivate let envelope: NEWFEATURESResultEnvelope<ScriptValue>
        fileprivate let deadline: ContinuousClock.Instant
    }
    private let id = UUID()
    private weak var store: WorkspaceStore?
    private let bridge: NEWFEATURESAdmissionBridge
    private let now: () -> ContinuousClock.Instant

    init(store: WorkspaceStore, session: WorkspaceDocumentSession,
         now: @escaping () -> ContinuousClock.Instant = { ContinuousClock.now }) {
        self.store = store
        self.bridge = NEWFEATURESAdmissionBridge(store: store, session: session)
        self.now = now
    }

    func prepare(selector: ExactProtocolReadSelector, limits: ExactProtocolReadLimits = .init()) throws -> Prepared {
        let started = now()
        try limits.validate()
        let deadline = started.advanced(by: limits.duration)
        try Task.checkCancellation()
        guard now() < deadline else { throw ExactProtocolReadFailure.deadlineExceeded }
        guard let store else { throw ExactProtocolReadFailure.staleSource }
        guard store.snapshot.binaries.count <= limits.imageRows else { throw ExactProtocolReadFailure.limitExceeded }
        let state = store.phase2ReadCurrentState(for: selector.owner.slot)
        guard state.image?.owner == selector.owner else { throw ExactProtocolReadFailure.unresolvedOwner }
        let admission = try bridge.admit(slot: selector.owner.slot) // Exactly one original admission.
        let snapshot = store.snapshot
        let value = try WorkspaceScriptingAPI.exactProtocolProjection(selector: selector, snapshot: snapshot,
            limits: limits, deadline: deadline, checkpoint: {}, now: now)
        return Prepared(controllerID: id, state: state, envelope: admission.retaining(value), deadline: deadline)
    }

    /// At ACTUAL synchronous delivery, including absent and ambiguous results. A deferred sink
    /// must retain Prepared and call publish again; a cached intermediate success is no authority.
    func publish(_ prepared: Prepared, to sink: (ScriptValue) throws -> Void) throws {
        func check() throws {
            try Task.checkCancellation()
            guard now() < prepared.deadline else { throw ExactProtocolReadFailure.deadlineExceeded }
            guard prepared.controllerID == id, let store,
                  store.phase2ReadCurrentState(for: prepared.state.image?.slot) == prepared.state else {
                throw ExactProtocolReadFailure.staleSource
            }
        }
        try check()
        try bridge.publish(prepared.envelope) { value in
            try check()
            try sink(value)
        }
    }
}
