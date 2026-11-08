import Foundation

struct WitnessLimits: Equatable, Sendable {
    let maxInstructions: Int, maxCallerWords: Int, maxSteps: Int, maxTotalWork: Int
    let maxNodes: Int, maxEdges: Int, maxDepth: Int, maxBytes: Int, maxContainerItems: Int, maxString: Int
    init() {
        maxInstructions = 64; maxCallerWords = 4096; maxSteps = 512; maxTotalWork = 262144
        maxNodes = 16; maxEdges = 24; maxDepth = 8; maxBytes = 65536; maxContainerItems = 4096; maxString = 2048
    }
    init(maxInstructions: Int = 64, maxCallerWords: Int = 4096, maxSteps: Int = 512, maxTotalWork: Int = 262144,
         maxNodes: Int = 16, maxEdges: Int = 24, maxDepth: Int = 8, maxBytes: Int = 65536,
         maxContainerItems: Int = 4096, maxString: Int = 2048) throws {
        guard [maxInstructions, maxCallerWords, maxSteps, maxTotalWork, maxNodes, maxEdges, maxDepth, maxBytes, maxContainerItems, maxString].allSatisfy({ $0 >= 0 }) else {
            throw SwiftOutcomeError(code: "Witness limits must be nonnegative integers")
        }
        self.maxInstructions = maxInstructions; self.maxCallerWords = maxCallerWords; self.maxSteps = maxSteps
        self.maxTotalWork = maxTotalWork; self.maxNodes = maxNodes; self.maxEdges = maxEdges; self.maxDepth = maxDepth
        self.maxBytes = maxBytes; self.maxContainerItems = maxContainerItems; self.maxString = maxString
    }
}

struct WitnessIdentity: Equatable, Sendable {
    let sliceSHA256: String, callerPC: String, callPC: String
    let model = "swift-outcome-witness-v1"
}

func sourceModels(_ profile: String) throws -> SwiftOutcomeJSON {
    guard ["legacy", "methods"].contains(profile) else { throw SwiftOutcomeError(code: "'" + profile + "'") }
    var models: [String: SwiftOutcomeJSON] = [
        "edge": .string(profile == "methods" ? "swift-sync-error-edges-v38" : "swift-sync-error-edges-v37"),
        "return_choice": .string(profile == "methods" ? "swift-return-choice-v46" : "swift-return-choice-v45"),
        "region": .string("swift-sync-error-region-v24"), "incoming": .string("swift-region-direct-entries-v7"),
        "presentation": .string("swift-structural-presentation-v10"), "success_result": .string("swift-success-result-v24"),
        "success_constant": .string("swift-success-constant-v17"), "error_constant": .string("swift-error-constant-v19"),
        "flag_entry": .string("swift-compare-flag-entries-v1")]
    if profile == "methods" { models["declaration"] = .string("swift-throwing-declarations-v1") }
    return .object(models)
}

func boundedCopy(_ value: SwiftOutcomeJSON, limits: WitnessLimits = WitnessLimits()) throws -> SwiftOutcomeJSON {
    var todo: [(SwiftOutcomeJSON, Int)] = [(value, 0)], count = 0
    var chars: Int128 = 0
    while let (node, depth) = todo.popLast() {
        count += 1
        guard count <= limits.maxContainerItems, depth <= limits.maxDepth else { throw SwiftOutcomeError(code: "witness_memory_limit") }
        switch node {
        case .object(let rows):
            guard rows.count <= limits.maxContainerItems - count else { throw SwiftOutcomeError(code: "witness_memory_limit") }
            for key in SwiftOutcomeWitnessCodec.scalarSorted(rows.keys) {
                guard key.unicodeScalars.count <= limits.maxString else { throw SwiftOutcomeError(code: "witness_container") }
                chars += Int128(key.unicodeScalars.count); todo.append((rows[key]!, depth + 1))
            }
        case .array(let rows):
            guard rows.count <= limits.maxContainerItems - count else { throw SwiftOutcomeError(code: "witness_memory_limit") }
            todo.append(contentsOf: rows.map { ($0, depth + 1) })
        case .string(let text):
            guard text.unicodeScalars.count <= limits.maxString else { throw SwiftOutcomeError(code: "witness_string_limit") }
            chars += Int128(text.unicodeScalars.count)
        case .null, .bool, .integer: break
        }
        guard chars <= Int128(limits.maxBytes) else { throw SwiftOutcomeError(code: "witness_output_limit") }
    }
    // Exact encoded size is counted without allocating the complete v1 string.
    var pending = [value], size: Int128 = 0
    while let node = pending.popLast() {
        switch node {
        case .object(let rows):
            size += 2 + Int128(max(0, rows.count - 1)) * 2 + Int128(rows.count) * 2
            for (key, child) in rows { size += Int128(SwiftOutcomeWitnessCodec.canonicalBytes(.string(key)).count); pending.append(child) }
        case .array(let rows): size += 2 + Int128(max(0, rows.count - 1)) * 2; pending.append(contentsOf: rows)
        default: size += Int128(SwiftOutcomeWitnessCodec.canonicalBytes(node).count)
        }
        guard size <= Int128(limits.maxBytes) else { throw SwiftOutcomeError(code: "witness_output_limit") }
    }
    return value
}

func imageIdentity(_ image: SwiftOutcomeImage) -> SwiftOutcomeJSON {
    .object(["architecture": .string(image.architecture), "cpu_subtype": .integer(Int128(image.cpuSubtype)),
        "uuid": image.uuid.map(SwiftOutcomeJSON.string) ?? .null, "slice_sha256": .string(image.sliceSHA256),
        "container_sha256": .string(image.containerSHA256), "slice_offset": .integer(Int128(image.sliceOffset)),
        "slice_size": .integer(Int128(image.sliceSize)), "preferred_base": .string(swiftOutcomeHex(image.preferredBase))])
}

func buildOutcomeWitness(image: SwiftOutcomeImage, function: SwiftErrorFlowFunction, call: SwiftOutcomeJSON,
                         limits: WitnessLimits = WitnessLimits(), modelProfile: String = "legacy") -> SwiftOutcomeJSON {
    var result: SwiftOutcomeJSON = .object([
        "schema_version": .integer(1), "model_version": .string("swift-outcome-witness-v1"),
        "validation_model_version": .string("swift-outcome-validation-v1"), "status": .string("unresolved"),
        "reason": .string("validation_required"), "source_reconstruction_allowed": .bool(false),
        "call_return_proven": .bool(false), "runtime_branch_proven": .bool(false), "handler_semantics_proven": .bool(false),
        "limitations": .array([.string("Structural observations only; reachability, exclusive entry, call return and handler semantics remain unproven.")])])
    func required(_ object: SwiftOutcomeJSON, _ key: String) throws -> SwiftOutcomeJSON {
        try swiftOutcomeItem(object, key)
    }
    func lastPC(_ instructions: SwiftOutcomeJSON) throws -> SwiftOutcomeJSON {
        try required(swiftOutcomeLast(instructions), "pc")
    }
    do {
        guard ["legacy", "methods"].contains(modelProfile), let callObject = call.object else { throw SwiftOutcomeError(code: "witness_input") }
        let evidence = try boundedCopy(.object(callObject.filter { !["outcome_witness", "presentation"].contains($0.key) }), limits: limits)
        result["image"] = imageIdentity(image); result["caller"] = swiftOutcomeFunctionRange(function)
        result["model_profile"] = .string(modelProfile); result["source_models"] = try sourceModels(modelProfile); result["evidence"] = evidence
        let callPC = try required(evidence, "call_pc")
        guard let text = callPC.string else { throw SwiftOutcomeError(code: "sequence item 3: expected str instance, " + swiftOutcomePythonType(callPC) + " found") }
        result["witness_id"] = .string("swift-outcome-witness-v1:" + image.sliceSHA256 + ":" + swiftOutcomeHex(function.start) + ":" + text)
        var nodes: [SwiftOutcomeJSON] = []
        for (key, label) in [("call_pc", "call"), ("test_pc", "test"), ("success_pc", "success"), ("error_pc", "error")] {
            if let value = evidence.object?[key] { nodes.append(.object(["id": .string(label), "pc": value])) }
        }
        let region = evidence.object?["error_region"] ?? .object([:])
        if let join = region.object?["join_pc"] { nodes.append(.object(["id": .string("join"), "pc": join])) }
        let ids = Set(nodes.compactMap { $0["id"].string })
        var edges: [SwiftOutcomeJSON] = []
        for (from, to) in [("call", "test"), ("test", "success"), ("test", "error"), ("error", "join"), ("success", "join")] where ids.contains(from) && ids.contains(to) {
            let pc: SwiftOutcomeJSON
            switch from {
            case "test": pc = try required(evidence, "test_pc")
            case "error": pc = try lastPC(required(region, "instructions"))
            case "success": pc = try lastPC(required(required(region, "success_interval"), "instructions"))
            default: pc = callPC
            }
            edges.append(.object(["from": .string(from), "to": .string(to), "provenance_pc": pc, "relationship": .string("recorded_structural")]))
        }
        guard nodes.count <= limits.maxNodes, edges.count <= limits.maxEdges else { throw SwiftOutcomeError(code: "witness_graph_limit") }
        result["graph"] = .object(["nodes": .array(nodes), "edges": .array(edges)])
        result["accounting"] = .object(["nodes": .integer(Int128(nodes.count)), "edges": .integer(Int128(edges.count))])
        _ = try boundedCopy(result, limits: limits)
    } catch {
        var failure: [String: SwiftOutcomeJSON] = [:]
        for key in ["schema_version", "model_version", "validation_model_version", "source_reconstruction_allowed", "call_return_proven", "runtime_branch_proven", "handler_semantics_proven"] { failure[key] = result[key] }
        failure["status"] = .string("unresolved"); failure["reason"] = .string((error as? SwiftOutcomeError)?.code ?? "witness_input"); failure["details_complete"] = .bool(false)
        return .object(failure)
    }
    return result
}

