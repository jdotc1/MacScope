import Foundation

/// VI3 slice B: the typed, read-only direct-callee inventory behind a future `open-claim`
/// (DESIGN 2.2). This is the LOCAL result shape; slice C maps it onto slice A's ledger model.
///
/// Scope, always: stored direct `call` xrefs of this one function. Indirect calls are typed
/// (resolved = advisory, unresolved = counted) but never expand into guessed callees.
///
/// Tail-call determination (Q8, code-cited):
/// - A direct tail call or any other direct branch (`b`, `b.cond`) is a `ControlFlowEdge` of kind
///   `"branch"` whenever the decoder produced a `branchTarget`
///   (`AnalysisEngine.buildControlFlowEdges`, AnalysisEngine.swift:2354-2361). `b` is not a
///   `call` xref (AnalysisEngine.swift:792-795 builds xrefs from `flow == .call` only), so
///   `callees` never sees it. Such edges leaving the function range ARE enumerable by a linear
///   scan of `ImageAnalysis.controlFlowEdges` (AnalysisModels.swift:1224); the endpoint index
///   covers xrefs only. They are listed as advisory `outOfFunctionBranches`, never as required
///   callees (a branch out of a function is not distinguishable from a shared-chunk jump).
/// - An indirect tail call (`br xN`, `InstructionFlow.indirectJump`, Disassembler.swift:15) has no
///   `branchTarget` (ARM64Decoder.swift:77 notes the same for authenticated variants) and so no
///   edge at all; only a resolved jump table yields in-function `switch` edges
///   (AnalysisEngine.swift:2364-2372). It cannot be enumerated: every inventory therefore carries
///   the permanent limitation `indirectTailCallsNotInventoried`.
struct CalleeClaimInventorySnapshot: Equatable, Sendable {
    enum CalleeKind: String, Sendable {
        /// The target is a function start.
        case function
        /// The target is inside a known function, not at its start.
        case interior
        /// An import/lazy stub symbol or an `_objc_msgSend$<selector>` stub.
        case stub
        /// A symbol or import with no function.
        case external
        /// No function and no symbol.
        case unnamed
    }

    struct Callee: Equatable, Sendable {
        var address: UInt64
        var kind: CalleeKind
        var name: String?
        /// Set for `interior` only.
        var containingFunction: UInt64?
        var offsetInContainingFunction: UInt64?
        var callSiteCount: Int
        /// First `calleeClaimCallSiteLimit` call sites, ascending.
        var callSites: [UInt64]
        var callSitesTruncated: Bool
    }

    /// A resolved indirect call: advisory, never required.
    struct ResolvedIndirect: Equatable, Sendable {
        var callSite: UInt64
        var target: UInt64
        var targetName: String?
        /// `function` or `type:<name>`.
        var scope: String
    }

    /// A direct `branch` edge leaving the function range: advisory, never required.
    struct OutOfFunctionBranch: Equatable, Sendable {
        var from: UInt64
        var target: UInt64
        var targetKind: CalleeKind
        var targetName: String?
    }

    enum Limitation {
        static let indirectTailCallsNotInventoried = "indirectTailCallsNotInventoried"
        static let unresolvedIndirectCallSites = "unresolvedIndirectCallSites"
        static let indirectCallTypingRefused = "indirectCallTypingRefused"
        static let controlFlowEdgesUnavailable = "controlFlowEdgesUnavailable"
        static let branchScanBudgetExceeded = "outOfFunctionBranchScanBudgetExceeded"
    }

    var imageSlot: Int
    var functionStart: UInt64
    var functionEnd: UInt64
    var functionName: String
    /// VI2 analysis generation at the read.
    var analysisGeneration: UUID
    /// Required set: distinct direct call targets, ascending by address.
    var callees: [Callee]
    var resolvedIndirect: [ResolvedIndirect]
    /// nil when indirect typing was refused (see the `indirectCallTypingRefused` limitation).
    var unresolvedIndirectCallSites: Int?
    var unresolvedIndirectReasons: [String: Int]
    var outOfFunctionBranches: [OutOfFunctionBranch]
    /// Sorted, unique.
    var limitations: [String]
    /// SHA-256 over sorted (call site, target) pairs, out-of-function branch pairs and limitations.
    /// Names, comments, overrides and generation do not enter it.
    var inventoryDigest: String
    /// Work-budget steps consumed by the xref scan.
    var scanSteps: Int
}

enum CalleeClaimInventoryError: Error, Equatable {
    /// The slot has no landed analysis; never reported as an empty callee list.
    case inventoryUnavailable(String)
    case digestUnavailable
}

extension WorkspaceScriptingAPI {
    nonisolated static let calleeClaimCallSiteLimit = 16
    nonisolated static let calleeClaimRequiredLimit = 8_192

    /// Builds the typed direct-callee inventory of one function. Read-only: no command is
    /// registered for it and no store is touched. Selectors are `function` or `address`, plus the
    /// optional `imageSlot` filter, exactly as `callees`.
    nonisolated static func calleeClaimInventory(
        arguments: ScriptValue, snapshot: WorkspaceSnapshot, checkpoint: () throws -> Void
    ) throws -> CalleeClaimInventorySnapshot {
        let command = "callee-claim-inventory"
        try checkpoint()
        let filter = try resolveImageSlotFilter(arguments, snapshot: snapshot)
        let view = filter.map { imageProjection(of: snapshot, in: $0) } ?? snapshot
        let slot = filter ?? view.primarySlot
        guard let analysis = view.analysis(in: slot) else {
            throw CalleeClaimInventoryError.inventoryUnavailable("no analysis has landed for image slot \(slot.rawValue)")
        }
        let function = try boundedSnapshotFunction(arguments, snapshot: view, checkpoint: checkpoint)

        // Direct callees: the shared S1 range scan, charged to the existing work budget.
        var work = 0
        func step() throws {
            guard work < maximumSnapshotSelectionWork else {
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                    detail: "\(command) exceeds the snapshot work budget",
                    budget: .init(unit: .workSteps, limit: Int64(maximumSnapshotSelectionWork)),
                    used: Int64(work + 1), narrowing: []))
            }
            if work % checkpointInterval == 0 { try checkpoint() }
            work += 1
        }
        var sitesByTarget: [UInt64: [UInt64]] = [:]
        try visitFunctionCallEdges(reverse: false, function: function, view: view, command: command,
            workUsed: work, checkpoint: checkpoint, step: step) { ref in
            sitesByTarget[ref.to, default: []].append(ref.from)
        }
        guard sitesByTarget.count <= calleeClaimRequiredLimit else {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                detail: "\(command) exceeds the required-callee budget",
                budget: .init(unit: .rows, limit: Int64(calleeClaimRequiredLimit)),
                used: Int64(sitesByTarget.count), narrowing: []))
        }
        let scanSteps = work

        // Control-flow edges that leave the function (direct branches / tail calls).
        let finalAddressOnly = function.startAddress == UInt64.max && function.endAddress <= function.startAddress
        let range = finalAddressOnly ? nil : view.functionRange(function)
        func inside(_ address: UInt64) -> Bool { range?.contains(address) ?? (address == UInt64.max) }
        var limitations: Set<String> = [CalleeClaimInventorySnapshot.Limitation.indirectTailCallsNotInventoried]
        var branchEdges: [(from: UInt64, to: UInt64)] = []
        if analysis.controlFlowEdges.isEmpty {
            limitations.insert(CalleeClaimInventorySnapshot.Limitation.controlFlowEdgesUnavailable)
        } else {
            var branchWork = 0
            var seenBranch = Set<[UInt64]>()
            scan: do {
                for edge in analysis.controlFlowEdges {
                    guard branchWork < maximumSnapshotSelectionWork else {
                        branchEdges = []
                        limitations.insert(CalleeClaimInventorySnapshot.Limitation.branchScanBudgetExceeded)
                        break scan
                    }
                    if branchWork % checkpointInterval == 0 { try checkpoint() }
                    branchWork += 1
                    guard edge.kind == "branch", inside(edge.from), !inside(edge.to),
                          seenBranch.insert([edge.from, edge.to]).inserted else { continue }
                    branchEdges.append((edge.from, edge.to))
                }
            }
        }

        // Typing: derived from the analysis tables (function index and symbol kinds).
        let targets = Set(sitesByTarget.keys).union(branchEdges.map(\.to))
        let nameIndex: GraphNameIndex
        do {
            nameIndex = try analysis.graphNames.index(functions: analysis.functions, symbols: analysis.symbols,
                                                      checkpoint: checkpoint)
        } catch let failure as GraphNameIndex.Limit { throw graphNameRefusal(failure) }
        var symbolKinds: [UInt64: Set<String>] = [:]
        for (position, symbol) in analysis.symbols.enumerated() {
            if position % checkpointInterval == 0 { try checkpoint() }
            if let address = symbol.address, targets.contains(address) {
                symbolKinds[address, default: []].insert(symbol.kind)
            }
        }
        let names = try boundedGraphTargetNames(targets.sorted(), snapshot: view, slot: slot, checkpoint: checkpoint)
        func classify(_ address: UInt64) -> (kind: CalleeClaimInventorySnapshot.CalleeKind, owner: UInt64?, offset: UInt64?) {
            let raw = nameIndex.rawName(address)
            let owner = nameIndex.owner(address)
            if symbolKinds[address]?.contains("stub") == true || raw?.hasPrefix("_objc_msgSend$") == true {
                return (.stub, nil, nil)
            }
            if let owner, owner.start == address { return (.function, nil, nil) }
            if let owner { return (.interior, owner.start, address - owner.start) }
            if raw != nil || !(symbolKinds[address]?.isEmpty ?? true) { return (.external, nil, nil) }
            return (.unnamed, nil, nil)
        }

        let callees = sitesByTarget.keys.sorted().map { target -> CalleeClaimInventorySnapshot.Callee in
            let sites = sitesByTarget[target, default: []].sorted()
            let typed = classify(target)
            return .init(address: target, kind: typed.kind, name: names[target].flatMap { $0.isEmpty ? nil : $0 },
                         containingFunction: typed.owner, offsetInContainingFunction: typed.offset,
                         callSiteCount: sites.count, callSites: Array(sites.prefix(calleeClaimCallSiteLimit)),
                         callSitesTruncated: sites.count > calleeClaimCallSiteLimit)
        }
        let branches = branchEdges.sorted { ($0.from, $0.to) < ($1.from, $1.to) }.map { edge in
            CalleeClaimInventorySnapshot.OutOfFunctionBranch(
                from: edge.from, target: edge.to, targetKind: classify(edge.to).kind,
                targetName: names[edge.to].flatMap { $0.isEmpty ? nil : $0 })
        }

        // Indirect calls: typed by the existing report. A refusal is a limitation, never "none".
        var resolved: [CalleeClaimInventorySnapshot.ResolvedIndirect] = []
        var unresolved: Int?
        var reasons: [String: Int] = [:]
        do {
            let report = try boundedIndirectCallTargets(
                arguments: .object(["address": .hex(function.startAddress)]), snapshot: view, checkpoint: checkpoint)
            for row in report["resolved"]?.arrayValue ?? [] {
                guard let call = row["call"]?.addressValue, let target = row["target"]?.addressValue else { continue }
                resolved.append(.init(callSite: call, target: target, targetName: row["targetName"]?.stringValue,
                                      scope: row["scope"]?.stringValue ?? "function"))
            }
            resolved.sort { ($0.callSite, $0.target) < ($1.callSite, $1.target) }
            var count = 0
            for row in report["refused"]?.arrayValue ?? [] {
                count += 1
                reasons[row["reason"]?.stringValue ?? "unknown", default: 0] += 1
            }
            unresolved = count
            if count > 0 { limitations.insert(CalleeClaimInventorySnapshot.Limitation.unresolvedIndirectCallSites) }
        } catch let error as ScriptingError {
            guard case .structuredRefusal(let refusal) = error, refusal.code == .budgetExceeded else { throw error }
            limitations.insert(CalleeClaimInventorySnapshot.Limitation.indirectCallTypingRefused)
        }

        let sortedLimitations = limitations.sorted()
        let digest = try calleeClaimInventoryDigest(
            slot: slot, function: function.startAddress,
            calls: sitesByTarget.flatMap { target, sites in sites.map { ($0, target) } },
            branches: branchEdges, limitations: sortedLimitations)
        try checkpoint()
        return CalleeClaimInventorySnapshot(
            imageSlot: slot.rawValue, functionStart: function.startAddress, functionEnd: function.endAddress,
            functionName: view.displayName(at: function.startAddress, in: slot, default: function.name),
            analysisGeneration: view.analysisGenerationID, callees: callees, resolvedIndirect: resolved,
            unresolvedIndirectCallSites: unresolved, unresolvedIndirectReasons: reasons,
            outOfFunctionBranches: branches, limitations: sortedLimitations,
            inventoryDigest: digest, scanSteps: scanSteps)
    }

    /// VI3 slice D: the digest of the body that backs one callee in this image, or nil when this image
    /// holds no body for it. `snapshot` is the image projection that holds the claim's function (the same
    /// view `calleeClaimInventory` reads); its primary slot is the image.
    ///
    /// The body is the function range of the callee: `function` and `stub` use the callee's own function,
    /// `interior` uses the owning function; `external`, `unnamed` and a stub with no function row have no
    /// body here and return nil. The digest is SHA-256 over the canonical JSON of (start, end, the sorted
    /// stored call xrefs whose site lies in the range, the basic block count of the range). Names,
    /// comments and overrides never enter it. Call sites reuse the inventory's own xref visitor, so
    /// the work budget applies and exhaustion is a typed `budgetExceeded`, never a partial digest.
    nonisolated static func calleeBodyDigest(
        callee: CalleeClaimInventorySnapshot.Callee, snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void = {}
    ) throws -> String? {
        let bodyStart: UInt64
        switch callee.kind {
        case .external, .unnamed: return nil
        case .function, .stub: bodyStart = callee.address
        case .interior:
            guard let owner = callee.containingFunction else { return nil }
            bodyStart = owner
        }
        let slot = snapshot.primarySlot
        guard let analysis = snapshot.analysis(in: slot),
              let function = analysis.functions.first(where: { $0.startAddress == bodyStart }) else { return nil }
        let command = "callee-body-digest"
        var work = 0
        func step() throws {
            guard work < maximumSnapshotSelectionWork else {
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                    detail: "\(command) exceeds the snapshot work budget",
                    budget: .init(unit: .workSteps, limit: Int64(maximumSnapshotSelectionWork)),
                    used: Int64(work + 1), narrowing: []))
            }
            if work % checkpointInterval == 0 { try checkpoint() }
            work += 1
        }
        var calls = Set<[UInt64]>()
        try visitFunctionCallEdges(reverse: false, function: function, view: snapshot, command: command,
                                   workUsed: work, checkpoint: checkpoint, step: step) { ref in
            calls.insert([ref.from, ref.to])
        }
        let range = snapshot.functionRange(function)
        var blocks = 0
        for (position, block) in analysis.basicBlocks.enumerated() {
            if position % checkpointInterval == 0 { try checkpoint() }
            if range.contains(block.startAddress) { blocks += 1 }
        }
        struct Payload: Encodable {
            var version: Int
            var start: String
            var end: String
            var calls: [[String]]
            var basicBlocks: Int
        }
        func hex(_ value: UInt64) -> String { "0x" + String(value, radix: 16) }
        let payload = Payload(
            version: 1, start: hex(function.startAddress), end: hex(function.endAddress),
            calls: calls.sorted { $0.lexicographicallyPrecedes($1) }.map { $0.map(hex) }, basicBlocks: blocks)
        do { return VASHA256Digest.hex(try VACanonicalJSON.encode(payload)) }
        catch { throw CalleeClaimInventoryError.digestUnavailable }
    }

    /// Canonical digest of stored analysis rows only: the pair lists are sorted, so xref order
    /// and ids do not matter; names, comments and overrides never enter it.
    nonisolated private static func calleeClaimInventoryDigest(
        slot: ImageSlot, function: UInt64, calls: [(UInt64, UInt64)],
        branches: [(from: UInt64, to: UInt64)], limitations: [String]
    ) throws -> String {
        struct Payload: Encodable {
            var version: Int
            var imageSlot: Int
            var function: String
            var calls: [[String]]
            var branches: [[String]]
            var limitations: [String]
        }
        func hex(_ value: UInt64) -> String { "0x" + String(value, radix: 16) }
        let payload = Payload(
            version: 1, imageSlot: slot.rawValue, function: hex(function),
            calls: Set(calls.map { [$0.0, $0.1] }).sorted { $0.lexicographicallyPrecedes($1) }
                .map { $0.map(hex) },
            branches: Set(branches.map { [$0.from, $0.to] }).sorted { $0.lexicographicallyPrecedes($1) }
                .map { $0.map(hex) },
            limitations: limitations)
        do { return VASHA256Digest.hex(try VACanonicalJSON.encode(payload)) }
        catch { throw CalleeClaimInventoryError.digestUnavailable }
    }
}
