import Foundation

/// Graph pages retain only bounded continuation state, not a captured workspace.
struct GraphPageRequest: Equatable, Sendable {
    let command: String
    let slot: ImageSlot
    let owner: UUID?
    let function: String?
    let address: UInt64
    let incoming: Bool
}

/// Page-level and per-row CFString disclosure carried by a graph cursor.
enum CFStringPageStorage: Sendable { case none, unavailable, retained, partial }

struct GraphPageState: Sendable {
    enum Phase: Sendable { case suppressions, recovered, additions, chained, done }
    struct Pair: Hashable, Sendable { let from: UInt64; let to: UInt64 }
    let request: GraphPageRequest
    let lower: UInt64
    let upper: UInt64
    let storage: CFStringPageStorage
    var phase: Phase
    var offset = 0
    var objects: [UInt64] = []
    var objectIndex = 0
    var skip = 0
    var emitted: Int64 = 0
    var suppressed = Set<XRefEndpointKey>()
    var authored = Set<XRefEndpointKey>()
    var present = Set<XRefEndpointKey>()
    var seen = Set<Pair>()
    var keyCount: Int { suppressed.count + authored.count + present.count + seen.count + objects.count }
}

struct GraphPageContext: Sendable {
    let session: GraphPageSession
    let epoch: UUID
    let workspace: UUID
    let document: UUID
}

/// Each store owns its cursor registry. Leases protect input states from concurrent
/// reuse; cancellation abandons a private transaction without consuming its cursor.
final class GraphPageSession: @unchecked Sendable {
    let boundedCalls = BoundedCallSession()
    static let maxKeys = 8_192
    static let maxRetainedKeys = 32_768
    static let maxStates = 8
    private struct Entry {
        let state: GraphPageState
        let workspace: UUID
        let document: UUID
        let created: TimeInterval
    }
    private let lock = NSLock()
    private var epoch = UUID()
    private var states: [UUID: Entry] = [:]
    private var order: [UUID] = []
    private var leases: [UUID: UUID?] = [:]
    private let clock: @Sendable () -> TimeInterval

    init(clock: @escaping @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.clock = clock
    }
    func capture(workspace: UUID, document: UUID) -> GraphPageContext {
        lock.lock(); defer { lock.unlock() }
        return GraphPageContext(session: self, epoch: epoch, workspace: workspace, document: document)
    }
    func invalidate() {
        lock.lock(); defer { lock.unlock() }
        epoch = UUID(); states.removeAll(); order.removeAll()
    }
    private func stale() -> ScriptingError {
        .invalidArgument("staleCursor: graph input changed, cursor expired or was evicted; restart without a cursor")
    }
    func requireCurrent(_ context: GraphPageContext) throws {
        lock.lock(); defer { lock.unlock() }
        guard context.epoch == epoch else { throw stale() }
    }
    func begin(_ context: GraphPageContext, cursor: ScriptValue?, request: GraphPageRequest)
        throws -> (lease: UUID, state: GraphPageState?) {
        var token: UUID?
        if let cursor, cursor != .null {
            guard case .string(let value) = cursor, value.utf8.prefix(40).count == 39,
                  value.hasPrefix("x2:"), let id = UUID(uuidString: String(value.dropFirst(3))),
                  value == "x2:" + id.uuidString else { throw ScriptingError.invalidArgument("malformed graph cursor; restart without a cursor") }
            token = id
        }
        let now = clock()
        lock.lock(); defer { lock.unlock() }
        guard context.epoch == epoch else { throw stale() }
        for id in order where now - (states[id]?.created ?? 0) >= 300 { states[id] = nil }
        order.removeAll { states[$0] == nil }
        guard leases.count < 2 else { throw ScriptingError.invalidArgument("graph pages are busy; retry the same cursor") }
        let state: GraphPageState?
        if let token {
            guard !leases.values.contains(where: { $0 == token }) else {
                throw ScriptingError.invalidArgument("graph cursor is busy; retry the same cursor")
            }
            guard let entry = states[token], entry.workspace == context.workspace,
                  entry.document == context.document, entry.state.request == request else { throw stale() }
            state = entry.state
        } else { state = nil }
        let lease = UUID()
        leases[lease] = .some(token)
        return (lease, state)
    }
    func abandon(_ lease: UUID) {
        lock.lock(); defer { lock.unlock() }; leases.removeValue(forKey: lease)
    }
    func commit(_ lease: UUID, context: GraphPageContext, state: GraphPageState?) throws -> String? {
        let now = clock()
        lock.lock(); defer { lock.unlock() }
        guard leases.keys.contains(lease), context.epoch == epoch else { throw stale() }
        guard let state else { leases.removeValue(forKey: lease); return nil }
        guard state.keyCount <= Self.maxKeys else {
            throw ScriptingError.invalidArgument("graph page deduplication state exceeds 8192 keys")
        }
        var retained = states.values.reduce(0) { $0 + $1.state.keyCount }
        while states.count >= Self.maxStates || retained + state.keyCount > Self.maxRetainedKeys {
            guard let victim = order.first(where: { id in !leases.values.contains(where: { $0 == id }) }) else {
                throw ScriptingError.invalidArgument("graph page state is busy; retry the same cursor")
            }
            retained -= states.removeValue(forKey: victim)?.state.keyCount ?? 0
            order.removeAll { $0 == victim }
        }
        let id = UUID()
        states[id] = Entry(state: state, workspace: context.workspace, document: context.document, created: now)
        order.append(id); leases.removeValue(forKey: lease)
        return "x2:" + id.uuidString
    }
}

// F3 uses raw explicit call-kind rows, never effectiveXRefs or crossImageXrefs.
// The session retains bounded traversal state only, not a workspace or source array.
struct BoundedCallRequest: Equatable, Sendable {
    let command: String
    let generation: UUID
    let slot: ImageSlot
    let owner: UUID?
    let root: UInt64
    let target: UInt64?
    let depth: Int
    let incoming: Bool
}

struct BoundedCallEdge: Hashable, Sendable {
    let from: UInt64
    let to: UInt64
    let caller: UInt64
    let callee: UInt64
}

struct BoundedCallState: Sendable {
    let request: BoundedCallRequest
    let backend: CallReadBackend
    var queue: [(address: UInt64, depth: Int)]
    var head = 0
    var scan = 0
    var pending: [BoundedCallEdge] = []
    var pendingKeys = Set<BoundedCallEdge>()
    var pendingIndex = 0
    var ready = false
    var seen: Set<UInt64>
    var edges = Set<BoundedCallEdge>()
    var parent: [UInt64: BoundedCallEdge] = [:]
    var done: Bool { head == queue.count }
}

final class BoundedCallSession: @unchecked Sendable {
    private struct Entry {
        let state: BoundedCallState
        let epoch: UUID
        let workspace: UUID
        let document: UUID
        let created: TimeInterval
    }
    private let lock = NSLock()
    private var entries: [UUID: Entry] = [:]
    private var order: [UUID] = []
    private var leases: [UUID: UUID?] = [:]
    private func stale() -> ScriptingError {
        .invalidArgument("staleCursor: bounded call input changed or cursor expired; restart without a cursor")
    }
    func begin(_ context: GraphPageContext, cursor: ScriptValue?, request: BoundedCallRequest)
        throws -> (lease: UUID, state: BoundedCallState?) {
        try context.session.requireCurrent(context)
        var token: UUID?
        if let cursor {
            guard case .string(let text) = cursor, text.utf8.prefix(40).count == 39,
                  text.hasPrefix("c1:"), let id = UUID(uuidString: String(text.dropFirst(3))),
                  text == "c1:" + id.uuidString else {
                throw ScriptingError.invalidArgument("malformed bounded call cursor")
            }
            token = id
        }
        let now = ProcessInfo.processInfo.systemUptime
        lock.lock(); defer { lock.unlock() }
        for id in order where now - (entries[id]?.created ?? 0) >= 300 { entries[id] = nil }
        order.removeAll { entries[$0] == nil }
        guard leases.count < 2, !leases.values.contains(where: { $0 == token && token != nil }) else {
            throw ScriptingError.invalidArgument("bounded call cursor is busy; retry the same cursor")
        }
        let state: BoundedCallState?
        if let token {
            guard let entry = entries[token], entry.epoch == context.epoch,
                  entry.workspace == context.workspace, entry.document == context.document,
                  entry.state.request == request else { throw stale() }
            state = entry.state
        } else { state = nil }
        let lease = UUID(); leases[lease] = .some(token)
        return (lease, state)
    }
    func abandon(_ lease: UUID) {
        lock.lock(); defer { lock.unlock() }; leases.removeValue(forKey: lease)
    }
    func commit(_ lease: UUID, context: GraphPageContext, state: BoundedCallState?) throws -> String? {
        try context.session.requireCurrent(context)
        lock.lock(); defer { lock.unlock() }
        guard leases.keys.contains(lease) else { throw stale() }
        guard let state else { leases.removeValue(forKey: lease); return nil }
        // Four entries, each <= 1024 nodes + 4096 edges + 4096 pending rows.
        // Old input cursors remain replayable until expiry/eviction, including after wire refusal.
        while entries.count >= 4 {
            guard let victim = order.first(where: { id in !leases.values.contains(where: { $0 == id }) }) else {
                throw ScriptingError.invalidArgument("bounded call state is busy; retry the same cursor")
            }
            entries[victim] = nil; order.removeAll { $0 == victim }
        }
        let id = UUID()
        entries[id] = Entry(state: state, epoch: context.epoch, workspace: context.workspace,
                            document: context.document, created: ProcessInfo.processInfo.systemUptime)
        order.append(id); leases.removeValue(forKey: lease)
        return "c1:" + id.uuidString
    }
}

extension WorkspaceScriptingAPI {
    nonisolated static let boundedCallCommands: Set<String> = ["call-graph", "call-path"]
    nonisolated static let boundedCallMaximumNodes = 1_024
    nonisolated static let boundedCallMaximumEdges = 4_096
    nonisolated static let boundedCallPageBytes = 131_072

    // Only the new commands use this parser. Null and coercions are rejected.
    nonisolated static func boundedCallOptions(_ command: String, _ args: ScriptValue)
        throws -> (root: UInt64, target: UInt64?, depth: Int, incoming: Bool, limit: Int) {
        guard boundedCallCommands.contains(command), case .object(let fields) = args else {
            throw ScriptingError.invalidArgument("bounded call arguments must be an object")
        }
        let allowed: Set<String> = command == "call-graph"
            ? ["root", "depth", "direction", "limit", "cursor", imageSlotFilterArgument]
            : ["from", "to", "maxDepth", "limit", "cursor", imageSlotFilterArgument]
        guard Set(fields.keys).isSubset(of: allowed) else {
            throw ScriptingError.invalidArgument("unknown bounded call argument")
        }
        func address(_ key: String) throws -> UInt64 {
            guard let value = fields[key] else { throw ScriptingError.missingArgument(key) }
            switch value {
            case .int(let n) where n >= 0: return UInt64(n)
            case .string(let text):
                guard text.utf8.prefix(19).count <= 18, text.hasPrefix("0x"), text.count > 2,
                      text.dropFirst(2).allSatisfy({ $0.isASCII && $0.isHexDigit }),
                      let value = UInt64(text.dropFirst(2), radix: 16) else {
                    throw ScriptingError.invalidArgument("\(key) must be a UInt64 hex address or non-negative integer")
                }
                return value
            default: throw ScriptingError.invalidArgument("\(key) must be a UInt64 hex address or non-negative integer")
            }
        }
        func integer(_ key: String, default fallback: Int, range: ClosedRange<Int>) throws -> Int {
            guard let value = fields[key] else { return fallback }
            guard case .int(let n) = value, n >= Int64(range.lowerBound), n <= Int64(range.upperBound) else {
                throw ScriptingError.invalidArgument("\(key) must be an integer from \(range.lowerBound) to \(range.upperBound)")
            }
            return Int(n)
        }
        let depth = try integer(command == "call-graph" ? "depth" : "maxDepth", default: 4, range: 0...16)
        let limit = try integer("limit", default: 100, range: 1...100)
        var incoming = false
        if command == "call-graph", let direction = fields["direction"] {
            guard direction == .string("callers") || direction == .string("callees") else {
                throw ScriptingError.invalidArgument("direction must be callers or callees")
            }
            incoming = direction == .string("callers")
        }
        if let cursor = fields["cursor"] {
            guard case .string(let text) = cursor, text.utf8.prefix(40).count == 39 else {
                throw ScriptingError.invalidArgument("cursor must be a bounded call cursor")
            }
        }
        return (try address(command == "call-graph" ? "root" : "from"),
                command == "call-path" ? try address("to") : nil, depth, incoming, limit)
    }

    nonisolated static func boundedCallRead(_ command: String, arguments: ScriptValue,
        snapshot: WorkspaceSnapshot, context: GraphPageContext?, visitLimit: Int = 100_000,
        autoContinueVisitLimit: Int = 4_000_000, checkpoint: () throws -> Void) throws -> ScriptValue {
        let options = try boundedCallOptions(command, arguments)
        try checkpoint()
        guard let context else { throw ScriptingError.invalidArgument("bounded calls require a store-owned read context") }
        func budget(_ detail: String, limit: Int, unit: MCPRefusalBudget.Unit = .workSteps) -> ScriptingError {
            .structuredRefusal(MCPToolRefusal(code: .budgetExceeded, detail: detail,
                budget: .init(unit: unit, limit: Int64(limit)), narrowing: ["depth", "maxDepth", "imageSlot", "limit"]))
        }
        guard snapshot.binaries.count <= 4_096 else { throw budget("bounded call image admission", limit: 4_096) }
        let slot = try resolveImageSlotFilter(arguments, snapshot: snapshot) ?? snapshot.primarySlot
        guard let analysis = snapshot.analysis(in: slot) else {
            throw ScriptingError.invalidArgument("bounded call image has no analysis")
        }
        let index: GraphNameIndex
        do {
            index = try analysis.graphNames.index(functions: analysis.functions, symbols: analysis.symbols,
                                                   checkpoint: checkpoint)
        } catch let failure as GraphNameIndex.Limit { throw graphNameRefusal(failure) }
        guard let root = index.owner(options.root)?.start else {
            throw ScriptingError.invalidArgument("root/from is outside every known function")
        }
        let target: UInt64?
        if let requested = options.target {
            guard let owner = index.owner(requested) else {
                throw ScriptingError.invalidArgument("to is outside every known function")
            }
            target = owner.start
        } else { target = nil }
        let request = BoundedCallRequest(command: command, generation: snapshot.analysisGenerationID,
            slot: slot, owner: snapshot.binary(in: slot)?.id, root: root, target: target,
            depth: options.depth, incoming: options.incoming)
        let transaction = try context.session.boundedCalls.begin(context, cursor: arguments["cursor"], request: request)
        defer { context.session.boundedCalls.abandon(transaction.lease) }
        let adjacency = try BoundedCallAdjacencyAdapter.select(
            analysis: analysis, retainedBackend: transaction.state?.backend)
        var state = transaction.state ?? BoundedCallState(request: request, backend: adjacency.backend,
            queue: [(root, 0)], seen: [root])
        let quantum = max(1, min(visitLimit, 100_000))
        var visits = 0, totalVisits = 0, page: [BoundedCallEdge] = []
        // Auto-continue: a page that spent its quantum scanning raw xrefs without emitting a row
        // runs further quanta (bounded by autoContinueVisitLimit) before replying empty.
        repeat {
            visits = 0
            while !state.done, visits < quantum, page.count < options.limit {
                try checkpoint()
                let current = state.queue[state.head]
                if current.depth >= request.depth {
                    state.head += 1; continue
                }
                if !state.ready {
                    // Never ask the endpoint memo to build an unbounded upstream index.
                    // Each raw candidate, even a non-call or duplicate, costs one visit.
                    guard try adjacency.scan(state: &state, currentAddress: current.address,
                        xrefs: analysis.xrefs, names: index, visits: &visits, quantum: quantum,
                        checkpoint: checkpoint) else { break }
                    // Complete each adjacency before BFS discovery. Ascending neighbour then
                    // raw callsite/target is the deterministic equal-hop tie policy.
                    state.pending.sort {
                        let a = request.incoming ? $0.caller : $0.callee
                        let b = request.incoming ? $1.caller : $1.callee
                        return a != b ? a < b : ($0.from != $1.from ? $0.from < $1.from : $0.to < $1.to)
                    }
                    state.ready = true
                    try checkpoint()
                }
                while state.pendingIndex < state.pending.count, visits < quantum, page.count < options.limit {
                    try checkpoint(); visits += 1
                    let edge = state.pending[state.pendingIndex]
                    state.pendingIndex += 1
                    guard !state.edges.contains(edge) else { continue }
                    guard state.edges.count < boundedCallMaximumEdges else {
                        throw budget("bounded call total edge cap", limit: boundedCallMaximumEdges, unit: .rows)
                    }
                    let next = request.incoming ? edge.caller : edge.callee
                    if !state.seen.contains(next) {
                        guard state.seen.count < boundedCallMaximumNodes else {
                            throw budget("bounded call node cap", limit: boundedCallMaximumNodes, unit: .rows)
                        }
                        state.seen.insert(next); state.queue.append((next, current.depth + 1))
                        state.parent[next] = edge
                    }
                    state.edges.insert(edge); page.append(edge)
                }
                if state.pendingIndex == state.pending.count {
                    state.head += 1; state.scan = 0; state.pending.removeAll(); state.pendingKeys.removeAll()
                    state.pendingIndex = 0; state.ready = false
                }
            }
            totalVisits += visits
        } while !state.done && totalVisits < autoContinueVisitLimit
            && (target.map { !state.seen.contains($0) && page.count < options.limit } ?? page.isEmpty)
        // Depth-boundary queue entries require no source read and do not consume a page.
        while !state.done, state.queue[state.head].depth >= request.depth { state.head += 1 }
        var path: [BoundedCallEdge] = []
        let witness = target.map { state.seen.contains($0) } ?? false
        if let target, witness {
            var current = target
            while current != root {
                try checkpoint()
                guard let edge = state.parent[current], path.count < 16 else {
                    throw ScriptingError.invalidArgument("bounded call parent invariant")
                }
                path.append(edge); current = edge.caller
            }
            path.reverse()
        }
        let selected = command == "call-path" ? path : page
        var addresses: Set<UInt64> = [root]
        for edge in selected { addresses.insert(edge.caller); addresses.insert(edge.callee) }
        let ordered = addresses.sorted()
        let names = try boundedGraphTargetNames(ordered, snapshot: snapshot, slot: slot, checkpoint: checkpoint)
        let nodes: [ScriptValue] = ordered.map { address in
            .object(["address": .hex(address), "name": names[address].map(ScriptValue.string) ?? .null,
                     "imageSlot": .int(Int64(slot.rawValue))])
        }
        let rows: [ScriptValue] = selected.map { edge in
            .object(["from": .hex(edge.from), "to": .hex(edge.to), "caller": .hex(edge.caller),
                     "callee": .hex(edge.callee), "imageSlot": .int(Int64(slot.rawValue))])
        }
        func envelope(_ cursor: String?) -> ScriptValue {
            .object(["nodes": .array(nodes), "edges": .array(rows), "edgePolicy": .string("rawExplicitCalls"),
                "generation": .string(request.generation.uuidString), "imageSlot": .int(Int64(slot.rawValue)),
                "imageOwner": request.owner.map { .string($0.uuidString) } ?? .null,
                // A found witness proves existence; absence is only provable once the search is done.
                "witnessExists": command == "call-path" ? (witness || state.done ? .bool(witness) : .null) : .null,
                "incompleteReason": state.done ? .null : .string("resumeNextCursor"),
                "sourceComplete": .null, // Recovery completeness is not represented by the supplied pin.
                "completeWithinScope": .bool(state.done), // Retained raw traversal only, never binary completeness.
                "shortestHopProven": command == "call-path" ? .bool(state.done && witness) : .null,
                "proofScope": .string("capturedRetainedRawCallsWithinDepth"),
                "isTruncated": .bool(!state.done), "nextCursor": cursor.map(ScriptValue.string) ?? .null])
        }
        let placeholder = state.done ? nil : "c1:00000000-0000-0000-0000-000000000000"
        guard try listPageWireBytes(envelope(placeholder)) <= boundedCallPageBytes else {
            throw budget(command == "call-graph"
                ? "bounded call page exceeds encoded bytes; retry the input cursor with a smaller limit"
                : "bounded path witness exceeds encoded bytes; limit does not shrink a witness; narrow depth/endpoints or retain this refusal",
                         limit: boundedCallPageBytes, unit: .bytes)
        }
        // Final validation is snapshot-local plus the store-owned epoch check in commit.
        // No live refresh is claimed or performed. Cancellation/name/bytes refusals win over prefixes.
        try checkpoint()
        let next = try context.session.boundedCalls.commit(transaction.lease, context: context,
                                                          state: state.done ? nil : state)
        return envelope(next)
    }
}


extension WorkspaceScriptingAPI {
    nonisolated static let graphPageCommands: Set<String> = ["xrefs", "callers", "callees"]
    nonisolated static let graphPageVisitLimit = 100_000
    nonisolated static let graphPageRowLimit = 500
    nonisolated static let graphPageByteLimit = 131_072

    nonisolated static func graphPageOptions(_ command: String, _ args: ScriptValue)
        throws -> (limit: Int, cursor: ScriptValue?)? {
        guard graphPageCommands.contains(command) else { return nil }
        let requested: Bool
        switch args["page"] {
        case .none, .some(.null), .some(.bool(false)): requested = false
        case .some(.bool(true)): requested = true
        default: throw ScriptingError.invalidArgument("page must be a boolean")
        }
        guard requested else {
            if let cursor = args["cursor"], cursor != .null { throw ScriptingError.invalidArgument("cursor requires page:true") }
            if let detail = args["detail"], detail != .null { throw ScriptingError.invalidArgument("detail requires page:true") }
            if command != "xrefs", let limit = args["limit"], limit != .null {
                throw ScriptingError.invalidArgument("limit requires page:true for callers and callees")
            }
            return nil
        }
        guard args["detail"] == .string("edges") else {
            throw ScriptingError.invalidArgument("graph pages require detail:edges; names are available on legacy nonpaged reads")
        }
        let limit: Int
        switch args["limit"] {
        case .none, .some(.null): limit = 100
        case .some(.int(let value)) where (1...Int64(graphPageRowLimit)).contains(value): limit = Int(value)
        default: throw ScriptingError.invalidArgument("graph page limit must be an integer from 1 to 500")
        }
        if let cursor = args["cursor"], cursor != .null {
            guard case .string(let text) = cursor, text.utf8.prefix(40).count == 39 else {
                throw ScriptingError.invalidArgument("malformed graph cursor")
            }
        }
        return (limit, args["cursor"])
    }

    private nonisolated static func graphBudget(_ detail: String, limit: Int,
        unit: MCPRefusalBudget.Unit = .workSteps) -> ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .budgetExceeded, detail: detail,
            budget: .init(unit: unit, limit: Int64(limit)), narrowing: []))
    }
    private nonisolated static func graphText(_ text: String, maxBytes: Int,
        checkpoint: () throws -> Void) throws -> String {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(min(maxBytes, 256))
        for byte in text.utf8 {
            if bytes.count % 256 == 0 { try checkpoint() }
            guard bytes.count < maxBytes else {
                throw graphBudget("graph page field exceeds UTF-8 admission", limit: maxBytes, unit: .bytes)
            }
            bytes.append(byte)
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private nonisolated static func cfStringStorageValue(_ storage: CFStringPageStorage) -> ScriptValue? {
        switch storage {
        case .none: return nil
        case .unavailable: return unavailableCFStringStorage()
        case .retained: return retainedCFStringStorage()
        case .partial: return partialCFStringStorage()
        }
    }

    private nonisolated static func initialGraphState(_ request: GraphPageRequest,
        arguments: ScriptValue, snapshot: WorkspaceSnapshot, checkpoint: () throws -> Void) throws -> GraphPageState {
        if request.command == "xrefs" {
            let table = request.incoming ? snapshot.cfStringBackings(in: request.slot) : nil
            let objects = try table.map {
                try cfStringObjects(backing: request.address, table: $0, checkpoint: checkpoint)
            } ?? []
            guard objects.count <= GraphPageSession.maxKeys else {
                throw graphBudget("graph page suppression/deduplication state exceeds 8192 keys",
                                  limit: GraphPageSession.maxKeys, unit: .rows)
            }
            var notice = !objects.isEmpty
            if !notice, request.incoming {
                notice = try requiresCFStringStorageNotice(
                    target: request.address, constants: snapshot.constantStrings(in: request.slot),
                    literals: snapshot.analysis(in: request.slot)?.stringLiterals ?? [],
                    maximumWork: graphPageVisitLimit, checkpoint: checkpoint)
            }
            let storage: CFStringPageStorage
            if !notice { storage = .none }
            else if let table { storage = table.complete ? .retained : .partial }
            else { storage = .unavailable }
            var state = GraphPageState(request: request, lower: request.address, upper: request.address,
                                       storage: storage, phase: .suppressions)
            state.objects = objects
            return state
        }
        let view = imageProjection(of: snapshot, in: request.slot)
        guard view.functions.count <= maximumSnapshotSelectionWork else {
            throw graphBudget("graph page function selection exceeds the function-entry budget", limit: maximumSnapshotSelectionWork)
        }
        if request.function != nil {
            var remaining = 1_048_576
            for function in view.functions {
                let raw = try graphText(function.name, maxBytes: min(4_096, remaining), checkpoint: checkpoint)
                remaining -= raw.utf8.count
                let display = try graphText(view.displayName(at: function.startAddress, default: function.name),
                                            maxBytes: min(4_096, remaining), checkpoint: checkpoint)
                remaining -= display.utf8.count
            }
        }
        let function = try boundedSnapshotFunction(arguments, snapshot: view, checkpoint: checkpoint)
        if request.command == "callers" { try requireCallersContainment(arguments, function: function) }
        return GraphPageState(request: request, lower: function.startAddress,
            upper: function.endAddress > function.startAddress ? function.endAddress - 1 : function.startAddress,
            storage: .none, phase: .recovered)
    }

    nonisolated static func snapshotGraphPage(_ command: String, arguments: ScriptValue,
        snapshot: WorkspaceSnapshot, context: GraphPageContext?, visitLimit: Int = graphPageVisitLimit,
        checkpoint: () throws -> Void) throws -> ScriptValue? {
        guard let options = try graphPageOptions(command, arguments) else { return nil }
        try checkpoint()
        guard let context else { throw ScriptingError.invalidArgument("graph pages require a store-owned read context") }
        guard snapshot.binaries.count <= 4_096 else {
            throw graphBudget("graph page image selection exceeds the image-entry budget", limit: 4_096)
        }
        let slot = try resolveImageSlotFilter(arguments, snapshot: snapshot) ?? snapshot.primarySlot
        let function: String?, address: UInt64, incoming: Bool
        if command == "xrefs" {
            function = nil
            if let to = arguments["to"]?.addressValue { address = to; incoming = true }
            else if let from = arguments["from"]?.addressValue { address = from; incoming = false }
            else { throw ScriptingError.missingArgument("to or from") }
        } else {
            if let selector = arguments["selector"], selector != .null {
                throw ScriptingError.invalidArgument("paged callers does not support selector queries; use the legacy selector read")
            }
            if let selectors = arguments["selectors"], selectors != .null {
                throw ScriptingError.invalidArgument("paged callers does not support selector queries; use the legacy selector read")
            }
            if let value = arguments["function"], value != .null {
                guard case .string(let name) = value else { throw ScriptingError.invalidArgument("function must be a string") }
                function = try graphText(name, maxBytes: 1_024, checkpoint: checkpoint)
            } else { function = nil }
            guard function != nil || arguments["address"]?.addressValue != nil else {
                throw ScriptingError.missingArgument("function or address")
            }
            address = function == nil ? (arguments["address"]?.addressValue ?? 0) : 0
            incoming = command == "callers"
        }
        let request = GraphPageRequest(command: command, slot: slot, owner: snapshot.binary(in: slot)?.id,
                                       function: function, address: address, incoming: incoming)
        let transaction = try context.session.begin(context, cursor: options.cursor, request: request)
        defer { context.session.abandon(transaction.lease) }
        var state = try transaction.state ?? initialGraphState(request, arguments: arguments,
                                                                snapshot: snapshot, checkpoint: checkpoint)
        let raw = snapshot.analysis(in: slot)?.xrefs ?? [], edits = snapshot.manualXRefs
        let effective = command == "xrefs"
        var visits = 0, rowBytes = 0
        var rows: [ScriptValue] = []
        let quantum = max(1, min(visitLimit, graphPageVisitLimit))
        func advance() {
            while state.phase != .done {
                if state.phase == .chained {
                    guard state.objectIndex >= state.objects.count else { return }
                    state.phase = .done
                    return
                }
                let count = state.phase == .recovered ? raw.count : edits.count
                guard state.offset >= count else { return }
                state.offset = 0
                switch state.phase {
                case .suppressions: state.phase = .recovered
                case .recovered: state.phase = effective ? .additions : .done
                case .additions: state.phase = state.objects.isEmpty ? .done : .chained
                case .chained, .done: break
                }
            }
        }
        func matches(_ from: UInt64, _ to: UInt64) -> Bool {
            let value = request.incoming ? to : from
            return value >= state.lower && value <= state.upper
        }
        func endpoint(_ from: UInt64, _ to: UInt64, _ kind: String) throws -> XRefEndpointKey {
            XRefEndpointKey(from: from, to: to, kind: try graphText(kind, maxBytes: 256, checkpoint: checkpoint))
        }
        func admit(_ alreadyPresent: Bool) throws {
            guard alreadyPresent || state.keyCount < GraphPageSession.maxKeys else {
                throw graphBudget("graph page suppression/deduplication state exceeds 8192 keys",
                                  limit: GraphPageSession.maxKeys, unit: .rows)
            }
        }
        advance()
        while state.phase != .done, visits < quantum, rows.count < options.limit {
            if visits % checkpointInterval == 0 { try checkpoint() }
            visits += 1
            if state.phase == .chained {
                let object = state.objects[state.objectIndex]
                let before = state.skip, capacity = options.limit - rows.count
                let target = request.address, suppressedNow = state.suppressed
                let found: [XRef]
                do {
                    found = try snapshot.boundedEffectiveXRefs(.to(object), in: slot, limit: before + capacity,
                        maximumRows: before + capacity, maximumWork: graphPageVisitLimit,
                        including: { !suppressedNow.contains(XRefEndpointKey(from: $0.from, to: target, kind: $0.kind)) },
                        checkpoint: checkpoint)
                } catch WorkspaceSnapshot.XRefQueryFailure.workBudget {
                    throw xrefWorkBudgetRefusal(limit: graphPageVisitLimit)
                } catch WorkspaceSnapshot.XRefQueryFailure.resultBudget {
                    throw xrefWorkBudgetRefusal(limit: graphPageVisitLimit)
                }
                visits += found.count
                var appended = 0, byteLimited = false
                for ref in found.dropFirst(before) {
                    var fields: [String: ScriptValue] = ["from": .hex(ref.from), "to": .hex(target),
                        "imageSlot": .int(Int64(slot.rawValue)),
                        "kind": .string(try graphText(ref.kind, maxBytes: 256, checkpoint: checkpoint)),
                        "via": .string("cfString"), "cfString": .hex(object)]
                    if let storage = cfStringStorageValue(state.storage) { fields["cfStringStorage"] = storage }
                    let row = ScriptValue.object(fields), size = try listPageWireBytes(row) + 1
                    if size > graphPageByteLimit - 2_048 - rowBytes { byteLimited = true; break }
                    guard state.emitted < Int64.max else { throw ScriptingError.invalidArgument("graph result count overflow") }
                    state.emitted += 1; rows.append(row); rowBytes += size; appended += 1
                }
                state.skip += appended
                if byteLimited { break }
                if found.count < before + capacity {
                    state.objectIndex += 1; state.skip = 0; advance()
                }
                continue
            }
            if state.phase == .suppressions {
                let edit = edits[state.offset]
                if edit.imageSlot == slot, matches(edit.from, edit.to) {
                    let key = try endpoint(edit.from, edit.to, edit.kind)
                    if edit.isSuppression { try admit(state.suppressed.contains(key)); state.suppressed.insert(key) }
                    else { try admit(state.authored.contains(key)); state.authored.insert(key) }
                }
                state.offset += 1; advance(); continue
            }
            let ref: XRef
            if state.phase == .recovered { ref = raw[state.offset] }
            else {
                let edit = edits[state.offset]
                guard edit.imageSlot == slot, !edit.isSuppression else { state.offset += 1; advance(); continue }
                ref = XRef(id: edit.id, from: edit.from, to: edit.to, kind: edit.kind)
            }
            guard matches(ref.from, ref.to), effective || ref.kind == XRefKind.call else {
                state.offset += 1; advance(); continue
            }
            let key = try endpoint(ref.from, ref.to, ref.kind)
            let pair = GraphPageState.Pair(from: ref.from, to: ref.to)
            if effective {
                guard !state.suppressed.contains(key), state.phase == .recovered || !state.present.contains(key) else {
                    state.offset += 1; advance(); continue
                }
                if state.authored.contains(key) { try admit(state.present.contains(key)) }
            } else {
                guard !state.seen.contains(pair) else { state.offset += 1; advance(); continue }
                try admit(false)
            }
            var fields: [String: ScriptValue] = ["from": .hex(ref.from), "to": .hex(ref.to),
                                                  "imageSlot": .int(Int64(slot.rawValue))]
            if effective { fields["kind"] = .string(key.kind) }
            if let storage = cfStringStorageValue(state.storage) { fields["cfStringStorage"] = storage }
            let row = ScriptValue.object(fields), size = try listPageWireBytes(row) + 1
            if size > graphPageByteLimit - 2_048 - rowBytes { break }
            if effective { if state.authored.contains(key) { state.present.insert(key) } }
            else { state.seen.insert(pair) }
            guard state.emitted < Int64.max else { throw ScriptingError.invalidArgument("graph result count overflow") }
            state.emitted += 1; rows.append(row); rowBytes += size; state.offset += 1; advance()
        }
        // A partial empty page is not evidence of absence. Refuse only once
        // the complete direct traversal has established that no row exists.
        if state.phase == .done, state.emitted == 0 {
            if state.storage == .unavailable { throw unavailableCFStringStorageRefusal() }
            if state.storage == .partial { throw partialCFStringStorageRefusal() }
        }
        func envelope(_ cursor: String?) -> ScriptValue {
            var fields: [String: ScriptValue] = ["rows": .array(rows), "projection": .string("edges"),
                     "total": state.phase == .done ? .int(state.emitted) : .null,
                     "lowerBound": .int(state.emitted), "isTruncated": .bool(state.phase != .done),
                     "coverage": .string(state.phase == .done ? "complete" : "partial"),
                     "sourceComplete": .null, "nextCursor": cursor.map(ScriptValue.string) ?? .null]
            if let storage = cfStringStorageValue(state.storage) { fields["cfStringStorage"] = storage }
            return .object(fields)
        }
        let placeholder = state.phase == .done ? nil : "x2:00000000-0000-0000-0000-000000000000"
        guard try listPageWireBytes(envelope(placeholder)) <= graphPageByteLimit else {
            throw graphBudget("graph page exceeds its encoded byte budget", limit: graphPageByteLimit, unit: .bytes)
        }
        try checkpoint()
        let next = try context.session.commit(transaction.lease, context: context,
                                              state: state.phase == .done ? nil : state)
        return envelope(next)
    }

    nonisolated static let defaultListPageLimit = 100
    nonisolated static let maximumListPageLimit = 1_000
    nonisolated static let maximumListPageBytes = 196_608
    nonisolated static let maximumListPageFieldBytes = 16_384
    nonisolated static let maximumListCursorBytes = 1_024
    nonisolated static let pagedListCommands: Set<String> = ["functions", "strings", "symbols"]

    struct StringListFilter: Equatable, Sendable {
        let section: String?
        let contains: String?
        nonisolated init(section: String?, contains: String?) {
            self.section = section
            self.contains = contains
        }
        nonisolated var isEmpty: Bool { section == nil && contains == nil }
        nonisolated func matches(_ literal: StringLiteralSummary) -> Bool {
            matches(value: literal.value, section: literal.sourceSection)
        }
        nonisolated func matches(value: String, section: String) -> Bool {
            if let wanted = self.section, section != wanted { return false }
            if let contains, value.range(of: contains, options: [.caseInsensitive, .literal],
                                                 locale: Locale(identifier: "en_US_POSIX")) == nil { return false }
            return true
        }
        nonisolated func cursorFilterBytes() throws -> Data {
            try JSONEncoder().encode([section,
                contains?.folding(options: .caseInsensitive, locale: Locale(identifier: "en_US_POSIX"))])
        }
        nonisolated var digest: String {
            func tagged(_ value: String?) -> String {
                guard let value else { return "0" }
                return "1" + value.replacingOccurrences(of: "\\", with: "\\\\")
                    .replacingOccurrences(of: "\0", with: "\\0")
            }
            let folded = contains?.folding(options: .caseInsensitive, locale: Locale(identifier: "en_US_POSIX"))
            let text = "s=\(tagged(section))\0c=\(tagged(folded))"
            var hash: UInt64 = 0xcbf29ce484222325
            for byte in text.utf8 { hash = (hash ^ UInt64(byte)) &* 0x100000001b3 }
            let hex = String(hash, radix: 16)
            return String(repeating: "0", count: 16 - hex.count) + hex
        }
    }

    nonisolated static func stringListFilter(_ arguments: ScriptValue) throws -> StringListFilter {
        func value(_ key: String) throws -> String? {
            guard let raw = arguments[key] else { return nil }
            guard case .string(let text) = raw, !text.isEmpty,
                  text.utf8.prefix(1_025).count <= 1_024 else {
                throw ScriptingError.invalidArgument("\(key) must be a non-empty string of at most 1024 UTF-8 bytes")
            }
            return text
        }
        return try StringListFilter(section: value("section"), contains: value("contains"))
    }

    /// Bounds filtered selection at the application boundary; source-byte provenance is separate.
    nonisolated static func admittedStringOffsets(_ literals: [StringLiteralSummary],
        filter: StringListFilter, limit: Int? = nil, checkpoint: () throws -> Void) throws -> [Int] {
        if limit == 0 { return [] }
        var visits = 0, bytes = 0
        func refusal(_ detail: String, _ unit: MCPRefusalBudget.Unit, _ limit: Int, _ used: Int) -> ScriptingError {
            .structuredRefusal(MCPToolRefusal(code: .budgetExceeded, detail: "strings filter \(detail)",
                budget: .init(unit: unit, limit: Int64(limit)), used: Int64(used), narrowing: []))
        }
        func admit(_ value: String) throws {
            try checkpoint()
            let view = value.utf8
            var cursor = view.startIndex, count = 0
            while cursor != view.endIndex {
                guard count < 4_096 else { throw refusal("field exceeds UTF-8 admission limit", .bytes, 4_096, count) }
                guard bytes < 1_048_576 else { throw refusal("requires another UTF-8 admission byte", .bytes, 1_048_576, bytes) }
                _ = view[cursor]
                view.formIndex(after: &cursor)
                count += 1; bytes += 1
                if count.isMultiple(of: 256) { try checkpoint() }
            }
            try checkpoint()
        }
        var selected: [Int] = []
        for index in literals.indices {
            try checkpoint()
            guard visits < 100_000 else { throw refusal("requires another candidate visit", .workSteps, 100_000, visits) }
            visits += 1
            let literal = literals[index]
            try admit(literal.sourceSection)
            try admit(literal.value)
            try checkpoint()
            if filter.matches(literal) {
                selected.append(index)
                if let limit, selected.count == limit { break }
            }
        }
        try checkpoint()
        return selected
    }


    nonisolated static func snapshotListPage(
        _ command: String,
        arguments: ScriptValue,
        snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void
    ) throws -> ScriptValue? {
        guard pagedListCommands.contains(command) else { return nil }
        let paged: Bool
        switch arguments["page"] {
        case .none, .some(.null), .some(.bool(false)): paged = false
        case .some(.bool(true)): paged = true
        default: throw ScriptingError.invalidArgument("page must be a boolean")
        }
        let cursor = arguments["cursor"]
        guard paged else {
            if let cursor, cursor != .null {
                throw ScriptingError.invalidArgument("cursor requires page:true")
            }
            return nil
        }
        try checkpoint()
        let limit: Int
        switch arguments["limit"] {
        case .none, .some(.null):
            limit = defaultListPageLimit
        case .some(.int(let value)) where (1...Int64(maximumListPageLimit)).contains(value):
            limit = Int(value)
        default:
            throw ScriptingError.invalidArgument("limit must be an integer from 1 to 1000 when page is true")
        }
        if command == "strings" {
            let filter = try stringListFilter(arguments)
            if let source = try snapshotStringDiscovery(snapshot, checkpoint: checkpoint) {
                return try discoveryPage(source, filter: filter, limit: limit, cursor: cursor,
                                         snapshot: snapshot, checkpoint: checkpoint)
            }
            if cursor?.stringValue?.hasPrefix("s2.") == true {
                throw ScriptingError.invalidArgument("staleCursor: the string source is no longer available; restart without a cursor")
            }
            if !filter.isEmpty {
                let selected = try admittedStringOffsets(snapshot.stringLiterals, filter: filter, checkpoint: checkpoint)
                let total = selected.count
                var position = 0
                if let cursor, cursor != .null {
                    let decoded = try decodeListPageCursor(cursor)
                    var low = 0, high = selected.count
                    while low < high {
                        try checkpoint()
                        let middle = low + (high - low) / 2
                        if selected[middle] < decoded.offset { low = middle + 1 } else { high = middle }
                    }
                    guard decoded.command == command,
                          decoded.slot == snapshot.primarySlot.rawValue,
                          decoded.generation == snapshot.analysisGenerationID,
                          decoded.digest == filter.digest,
                          low < selected.count, selected[low] == decoded.offset else {
                        throw ScriptingError.invalidArgument(
                            "staleCursor: the list changed or the cursor belongs to another list; restart without a cursor")
                    }
                    position = low
                }
                var rows: [ScriptValue] = []
                rows.reserveCapacity(min(limit, total))
                var usedBytes = 0
                while position < selected.count {
                    try checkpoint()
                    let literal = snapshot.stringLiterals[selected[position]]
                    if rows.count == limit { break }
                    let value = try listPageField(literal.value, checkpoint: checkpoint)
                    var fields: [String: ScriptValue] = [
                        "value": .string(value.text), "address": .hex(literal.address),
                    ]
                    if value.truncated {
                        fields["valueTruncated"] = .bool(true)
                        fields["valueByteLength"] = .int(Int64(value.byteLength))
                    }
                    let row = ScriptValue.object(fields)
                    let rowBytes = try listPageWireBytes(row) + 1
                    if !rows.isEmpty && rowBytes > maximumListPageBytes - usedBytes { break }
                    rows.append(row)
                    usedBytes += rowBytes
                    position += 1
                }
                let next: ScriptValue = position < selected.count
                    ? .string(encodeFilteredStringCursor(offset: selected[position], digest: filter.digest, snapshot: snapshot))
                    : .null
                let complete: ScriptValue
                switch snapshot.stringLiteralCoverage {
                case .some(.complete): complete = .bool(true)
                case .some(.incomplete), .some(.notAttempted): complete = .bool(false)
                case .none: complete = .null
                }
                try checkpoint()
                return .object([
                    "rows": .array(rows), "total": complete == .bool(true) ? .int(Int64(total)) : .null,
                    "totalLowerBound": .int(Int64(total)), "totalIsExact": .bool(complete == .bool(true)),
                    "source": .string("retained"),
                    "isTruncated": .bool(next != .null), "nextCursor": next, "sourceComplete": complete,
                ])
            }
        }
        let filter: ListRowFilter
        if command == "functions" || command == "symbols" {
            filter = try ListRowFilter.parse(arguments, command: command)
        } else {
            filter = ListRowFilter(nameContains: nil, regex: nil, kind: nil)
        }
        if command == "functions", !filter.isEmpty {
            return try filteredFunctionsPage(filter, limit: limit, cursor: cursor, snapshot: snapshot, checkpoint: checkpoint)
        }
        let matcher = try filter.matcher()
        let fullCount = command == "functions" ? snapshot.functions.count
            : command == "symbols" ? snapshot.symbols.count : snapshot.stringLiterals.count
        let symbolIndices: [Int]? = command == "symbols" && !filter.isEmpty
            ? try SymbolFilterSelection.indices(snapshot.symbols, matching: matcher, checkpoint: checkpoint) : nil
        func symbolIndexPosition(_ target: Int) -> Int? {
            guard let symbolIndices else { return nil }
            var low = 0, high = symbolIndices.count
            while low < high {
                let middle = low + (high - low) / 2
                if symbolIndices[middle] < target { low = middle + 1 } else { high = middle }
            }
            return low < symbolIndices.count && symbolIndices[low] == target ? low : nil
        }
        func matches(_ index: Int) -> Bool {
            guard !filter.isEmpty else { return true }
            if command == "functions" {
                let function = snapshot.functions[index]
                return matcher(snapshot.displayName(at: function.startAddress, default: function.name),
                               function.name, nil)
            }
            return symbolIndexPosition(index) != nil
        }
        let digest = filter.isEmpty ? nil : filter.digest
        var total = fullCount
        if let symbolIndices {
            total = symbolIndices.count
        } else if !filter.isEmpty {
            total = 0
            for index in 0..<fullCount {
                if index % checkpointInterval == 0 { try checkpoint() }
                if matches(index) { total += 1 }
            }
        }
        var offset = 0
        if let cursor, cursor != .null {
            let decoded = try decodeListPageCursor(cursor)
            guard decoded.command == command,
                  decoded.slot == snapshot.primarySlot.rawValue,
                  decoded.generation == snapshot.analysisGenerationID,
                  decoded.digest == digest,
                  decoded.offset < fullCount,
                  matches(decoded.offset) else {
                throw ScriptingError.invalidArgument(
                    "staleCursor: the list changed or the cursor belongs to another list; restart without a cursor")
            }
            offset = decoded.offset
        }

        var symbolPosition = 0
        if let symbolIndices {
            if offset > 0 { symbolPosition = symbolIndexPosition(offset) ?? symbolIndices.count }
            offset = symbolPosition < symbolIndices.count ? symbolIndices[symbolPosition] : fullCount
        }
        var rows: [ScriptValue] = []
        rows.reserveCapacity(min(limit, max(0, total - offset)))
        var usedBytes = 0
        var examined = 0
        while offset < fullCount && rows.count < limit {
            if (filter.isEmpty ? rows.count : examined) % checkpointInterval == 0 { try checkpoint() }
            examined += 1
            if symbolIndices == nil && !matches(offset) { offset += 1; continue }
            let row: ScriptValue
            if command == "functions" {
                let function = snapshot.functions[offset]
                let emittedName = snapshot.displayName(at: function.startAddress, default: function.name)
                let name = try listPageField(emittedName, checkpoint: checkpoint)
                var fields: [String: ScriptValue] = [
                    "name": .string(name.text),
                    "address": .hex(function.startAddress),
                    "end": .hex(function.endAddress),
                    "confidence": .double(function.confidence),
                ]
                if let demangled = scriptingDemangled(emittedName) { fields["demangled"] = .string(demangled) }
                if name.truncated {
                    fields["nameTruncated"] = .bool(true)
                    fields["nameByteLength"] = .int(Int64(name.byteLength))
                }
                row = .object(fields)
            } else if command == "symbols" {
                let symbol = snapshot.symbols[offset]
                let name = try listPageField(symbol.name, checkpoint: checkpoint)
                let kind = try ListRowFilter.pageKind(symbol.kind, checkpoint: checkpoint)
                var fields: [String: ScriptValue] = [
                    "name": .string(name.text), "address": symbol.address.map(ScriptValue.hex) ?? .null,
                    "kind": .string(kind.text),
                ]
                if let demangled = scriptingDemangled(symbol.name) { fields["demangled"] = .string(demangled) }
                if name.truncated {
                    fields["nameTruncated"] = .bool(true)
                    fields["nameByteLength"] = .int(Int64(name.byteLength))
                }
                if kind.truncated {
                    fields["kindTruncated"] = .bool(true)
                    fields["kindByteLength"] = .int(Int64(kind.byteLength))
                }
                row = .object(fields)
            } else {
                let literal = snapshot.stringLiterals[offset]
                let value = try listPageField(literal.value, checkpoint: checkpoint)
                var fields: [String: ScriptValue] = [
                    "value": .string(value.text), "address": .hex(literal.address),
                ]
                if value.truncated {
                    fields["valueTruncated"] = .bool(true)
                    fields["valueByteLength"] = .int(Int64(value.byteLength))
                }
                row = .object(fields)
            }
            let rowBytes = try listPageWireBytes(row) + 1
            // The field caps make even a seven-fold wire-escaped first row fit.
            // Do not consume a candidate that belongs to the following page.
            if !rows.isEmpty && rowBytes > maximumListPageBytes - usedBytes { break }
            rows.append(row)
            usedBytes += rowBytes
            if let symbolIndices {
                symbolPosition += 1
                offset = symbolPosition < symbolIndices.count ? symbolIndices[symbolPosition] : fullCount
            } else {
                offset += 1
            }
        }
        if !filter.isEmpty && symbolIndices == nil {
            var scanned = 0
            while offset < fullCount {
                if scanned % checkpointInterval == 0 { try checkpoint() }
                if matches(offset) { break }
                offset += 1
                scanned += 1
            }
        }
        let next: ScriptValue = offset < fullCount
            ? .string(encodeListPageCursor(command: command, offset: offset, snapshot: snapshot, filter: digest))
            : .null
        let complete: ScriptValue
        if command == "functions" || command == "symbols" {
            complete = .null
        } else {
            switch snapshot.stringLiteralCoverage {
            case .some(.complete): complete = .bool(true)
            case .some(.incomplete), .some(.notAttempted): complete = .bool(false)
            case .none: complete = .null
            }
        }
        try checkpoint()
        var result: [String: ScriptValue] = [
            "rows": .array(rows), "total": .int(Int64(total)),
            "isTruncated": .bool(next != .null), "nextCursor": next,
            "sourceComplete": complete,
        ]
        if command == "strings" {
            result["total"] = complete == .bool(true) ? .int(Int64(total)) : .null
            result["totalLowerBound"] = .int(Int64(total))
            result["totalIsExact"] = .bool(complete == .bool(true))
            result["source"] = .string("retained")
        }
        return .object(result)
    }
    nonisolated static func snapshotStringDiscovery(_ snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void) throws -> MachOStringDiscovery? {
        guard snapshot.stringLiteralCoverage != .notAttempted else { return nil }
        do { return try MachOParser().stringDiscovery(in: snapshot.imageBytes, checkpoint: checkpoint) }
        catch is MachOParserError { return nil }
    }

    private struct DiscoveryCursor: Codable, Sendable {
        var generation: UUID
        var slot: Int
        var position: MachOStringDiscovery.Position
    }

    private nonisolated static func encodeDiscoveryCursor(_ position: MachOStringDiscovery.Position,
        filter: StringListFilter, snapshot: WorkspaceSnapshot) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(DiscoveryCursor(generation: snapshot.analysisGenerationID,
            slot: snapshot.primarySlot.rawValue, position: position))
        let signature = snapshot.authenticateStringDiscovery(data + Data([0]) + (try filter.cursorFilterBytes()))
        return "s2." + data.base64EncodedString() + "." + signature.base64EncodedString()
    }

    private nonisolated static func decodeDiscoveryCursor(_ value: ScriptValue?, filter: StringListFilter,
        snapshot: WorkspaceSnapshot) throws -> MachOStringDiscovery.Position {
        guard let value, value != .null else { return .init() }
        func stale() -> ScriptingError {
            .invalidArgument("staleCursor: the string source or filter changed; restart without a cursor")
        }
        guard let token = value.stringValue, token.utf8.prefix(maximumListCursorBytes + 1).count <= maximumListCursorBytes else { throw stale() }
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == "s2",
              let data = Data(base64Encoded: String(parts[1])), data.base64EncodedString() == parts[1],
              let signature = Data(base64Encoded: String(parts[2])), signature.count == 32,
              signature.base64EncodedString() == parts[2],
              snapshot.verifiesStringDiscovery(signature, data: data + Data([0]) + (try filter.cursorFilterBytes())),
              let decoded = try? JSONDecoder().decode(DiscoveryCursor.self, from: data),
              decoded.generation == snapshot.analysisGenerationID, decoded.slot == snapshot.primarySlot.rawValue else { throw stale() }
        return decoded.position
    }

    private nonisolated static func discoveryPage(_ source: MachOStringDiscovery,
        filter: StringListFilter, limit: Int, cursor: ScriptValue?, snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void) throws -> ScriptValue {
        let start = try decodeDiscoveryCursor(cursor, filter: filter, snapshot: snapshot)
        var rows: [ScriptValue] = [], used = 0
        let end = try source.scan(from: start, checkpoint: checkpoint) { literal in
            guard filter.matches(value: literal.value, section: literal.sourceSection) else { return .skip }
            let row = ScriptValue.object(["value": .string(literal.value), "address": .hex(literal.address)])
            let size = try listPageWireBytes(row) + 1
            guard rows.isEmpty || size <= maximumListPageBytes - used else { return .retry }
            rows.append(row); used += size
            return rows.count == limit ? .includeAndStop : .include
        }
        let finished = source.exhausted(end), exact = finished && !end.incomplete
        try checkpoint()
        return .object([
            "rows": .array(rows), "total": exact ? .int(Int64(end.matched)) : .null,
            "totalLowerBound": .int(Int64(end.matched)), "totalIsExact": .bool(exact),
            "isTruncated": .bool(!finished),
            "nextCursor": finished ? .null : .string(try encodeDiscoveryCursor(end, filter: filter, snapshot: snapshot)),
            "sourceComplete": finished ? .bool(!end.incomplete) : .null,
            "scanComplete": .bool(finished), "source": .string("selectedSlice"),
        ])
    }

    nonisolated static func discoveryRows(_ source: MachOStringDiscovery, filter: StringListFilter,
        limit: Int?, checkpoint: () throws -> Void) throws -> ScriptValue {
        if limit == 0 { return .array([]) }
        let budget = 8_388_608
        var rows: [ScriptValue] = [], used = 0
        let end = try source.scan(byteLimit: budget, checkpoint: checkpoint) { literal in
            guard filter.matches(value: literal.value, section: literal.sourceSection) else { return .skip }
            let row = ScriptValue.object(["value": .string(literal.value), "address": .hex(literal.address)])
            let size = try listPageWireBytes(row) + 1
            guard rows.count < 100_000, size <= budget - used else { return .retry }
            rows.append(row); used += size
            return rows.count == limit ? .includeAndStop : .include
        }
        if end.incomplete {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .malformedInput,
                detail: "strings source is incomplete; use page:true to inspect recovered rows and coverage",
                narrowing: []))
        }
        if rows.count == limit || source.exhausted(end) { return .array(rows) }
        throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
            detail: "strings requires bounded continuation; retry with page:true and follow nextCursor, including empty pages",
            narrowing: []))
    }

    nonisolated static func stringCountFields(_ snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void = {}) throws -> [String: ScriptValue] {
        let retained = snapshot.stringLiterals.count
        var exact: Int? = snapshot.stringLiteralCoverage == .complete ? retained : nil
        var lower = retained
        if exact == nil, let source = try snapshotStringDiscovery(snapshot, checkpoint: checkpoint) {
            let end = try source.scan(byteLimit: 8_388_608, checkpoint: checkpoint) { _ in .include }
            lower = max(retained, end.discovered)
            if source.exhausted(end), !end.incomplete, end.discovered >= retained { exact = end.discovered }
        }
        let capped: ScriptValue
        if let exact { capped = .bool(exact > retained) }
        else if lower > retained || snapshot.stringLiteralCoverage?.stopReason == .stringCountLimitReached { capped = .bool(true) }
        else { capped = .null }
        return ["stringCount": exact.map { .int(Int64($0)) } ?? .null,
                "stringRetainedCount": .int(Int64(retained)), "stringCountLowerBound": .int(Int64(lower)),
                "stringCountExact": .bool(exact != nil), "stringCountCapped": capped]
    }

    private nonisolated static func filteredFunctionsPage(
        _ filter: ListRowFilter, limit: Int, cursor: ScriptValue?, snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void
    ) throws -> ScriptValue {
        let selected = try FunctionFilterSelection.select(snapshot, matching: filter.matcher(), checkpoint: checkpoint)
        var position = 0
        if let cursor, cursor != .null {
            let decoded = try decodeListPageCursor(cursor)
            guard decoded.command == "functions", decoded.slot == snapshot.primarySlot.rawValue,
                  decoded.generation == snapshot.analysisGenerationID, decoded.digest == filter.digest else {
                throw ScriptingError.invalidArgument("staleCursor: the list changed or the cursor belongs to another list; restart without a cursor")
            }
            var high = selected.count
            while position < high {
                try checkpoint()
                let middle = position + (high - position) / 2
                if selected[middle].offset < decoded.offset { position = middle + 1 } else { high = middle }
            }
            guard position < selected.count, selected[position].offset == decoded.offset else {
                throw ScriptingError.invalidArgument("staleCursor: the list changed or the cursor belongs to another list; restart without a cursor")
            }
        }
        var rows: [ScriptValue] = [], usedBytes = 0
        while position < selected.count && rows.count < limit {
            try checkpoint()
            let entry = selected[position]
            let name = try listPageField(entry.displayName, checkpoint: checkpoint)
            var fields: [String: ScriptValue] = ["name": .string(name.text), "address": .hex(entry.function.startAddress),
                "end": .hex(entry.function.endAddress), "confidence": .double(entry.function.confidence)]
            if let demangled = scriptingDemangled(entry.displayName) { fields["demangled"] = .string(demangled) }
            if name.truncated { fields["nameTruncated"] = .bool(true); fields["nameByteLength"] = .int(Int64(name.byteLength)) }
            let row = ScriptValue.object(fields)
            let bytes = try listPageWireBytes(row) + 1
            if !rows.isEmpty && bytes > maximumListPageBytes - usedBytes { break }
            rows.append(row); usedBytes += bytes; position += 1
        }
        let next: ScriptValue = position < selected.count
            ? .string(encodeListPageCursor(command: "functions", offset: selected[position].offset, snapshot: snapshot, filter: filter.digest)) : .null
        try checkpoint()
        return .object(["rows": .array(rows), "total": .int(Int64(selected.count)), "isTruncated": .bool(next != .null), "nextCursor": next, "sourceComplete": .null])
    }

    nonisolated static func listPageWireBytes(_ row: ScriptValue) throws -> Int {
        let text = String(decoding: try row.jsonData(), as: UTF8.self)
        return try ScriptValue.string(text).jsonData().count - 2
    }


    private nonisolated static func encodeListPageCursor(
        command: String, offset: Int, snapshot: WorkspaceSnapshot, filter: String? = nil
    ) -> String {
        let body = "l1|\(command)|\(snapshot.primarySlot.rawValue)|\(offset)|\(snapshot.analysisGenerationID.uuidString)"
        return Data((body + (filter.map { "|" + $0 } ?? "")).utf8).base64EncodedString()
    }

    private nonisolated static func encodeFilteredStringCursor(
        offset: Int, digest: String, snapshot: WorkspaceSnapshot
    ) -> String {
        Data("l1|strings|\(snapshot.primarySlot.rawValue)|\(offset)|\(snapshot.analysisGenerationID.uuidString)|\(digest)"
            .utf8).base64EncodedString()
    }


    private nonisolated static func decodeListPageCursor(
        _ value: ScriptValue
    ) throws -> (command: String, slot: Int, offset: Int, generation: UUID, digest: String?) {
        func malformed() -> ScriptingError { .invalidArgument("malformed cursor") }
        guard case .string(let text) = value,
              text.utf8.prefix(maximumListCursorBytes + 1).count <= maximumListCursorBytes,
              let data = Data(base64Encoded: text),
              data.base64EncodedString() == text,
              let decoded = String(data: data, encoding: .utf8) else { throw malformed() }
        let fields = decoded.split(separator: "|", omittingEmptySubsequences: false)
        guard (fields.count == 5 || fields.count == 6), fields[0] == "l1",
              pagedListCommands.contains(String(fields[1])),
              let slot = Int(fields[2]), String(slot) == String(fields[2]),
              !fields[3].isEmpty, fields[3].utf8.allSatisfy({ (48...57).contains($0) }),
              let offset = Int(fields[3]), offset > 0,
              let generation = UUID(uuidString: String(fields[4])) else { throw malformed() }
        var digest: String?
        if fields.count == 6 {
            guard ["functions", "symbols", "strings"].contains(String(fields[1])), fields[5].utf8.count == 16,
                  fields[5].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                throw malformed()
            }
            digest = String(fields[5])
        }
        return (String(fields[1]), slot, offset, generation, digest)
    }

    /// The full UTF-8 length is `utf8.count` (O(1) for a native String); only the emitted prefix is walked.
    private nonisolated static func listPageField(_ text: String, checkpoint: () throws -> Void) throws -> (text: String, byteLength: Int, truncated: Bool) {
        let byteLength = text.utf8.count
        guard byteLength > maximumListPageFieldBytes else { return (text, byteLength, false) }
        var prefix = ""
        var prefixBytes = 0
        for (index, scalar) in text.unicodeScalars.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            let width: Int
            switch scalar.value {
            case 0...0x7f: width = 1
            case 0x80...0x7ff: width = 2
            case 0x800...0xffff: width = 3
            default: width = 4
            }
            guard width <= maximumListPageFieldBytes - prefixBytes else { break }
            prefix.unicodeScalars.append(scalar)
            prefixBytes += width
        }
        return (prefix, byteLength, true)
    }
}
