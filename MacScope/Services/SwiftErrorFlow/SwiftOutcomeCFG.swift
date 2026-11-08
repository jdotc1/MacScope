import Foundation

struct SwiftCFGLimits: Equatable, Sendable {
    let maxWork: Int, maxBlocks: Int, maxEdges: Int, maxDepth: Int, maxRetainedWords: Int
    init() { maxWork = 65536; maxBlocks = 4096; maxEdges = 16384; maxDepth = 4096; maxRetainedWords = 4096 }
    init(maxWork: Int = 65536, maxBlocks: Int = 4096, maxEdges: Int = 16384,
         maxDepth: Int = 4096, maxRetainedWords: Int = 4096) throws {
        for (name, value, cap) in [("max_work", maxWork, 262144), ("max_blocks", maxBlocks, 8192),
                                 ("max_edges", maxEdges, 32768), ("max_depth", maxDepth, 8192),
                                 ("max_retained_words", maxRetainedWords, 16384)] {
            guard value >= 0, value <= cap else { throw SwiftOutcomeError(code: "\(name) must be an integer in 0..\(cap)") }
        }
        self.maxWork = maxWork; self.maxBlocks = maxBlocks; self.maxEdges = maxEdges
        self.maxDepth = maxDepth; self.maxRetainedWords = maxRetainedWords
    }
}

struct SwiftOutcomeImage: Sendable {
    struct Section: Equatable, Sendable {
        let address: UInt64, size: Int128, fileOffset: UInt64
        let executable: Bool
        let flags: UInt32
        var end: Int128 { Int128(address) + size }
    }
    let sliceSHA256: String, containerSHA256: String, architecture: String
    let sliceOffset: UInt64, sliceSize: UInt64, cpuSubtype: UInt32
    let uuid: String? = nil
    let preferredBase: Int128
    let sliceIndex: Int? = nil
    let containerSliceCount: Int? = nil
    let sections: [Section]
    let functions: [SwiftErrorFlowFunction]
    private let words: [UInt32]
    private let codeAddress: UInt64

    init(_ request: SwiftErrorFlowRequest) {
        sliceSHA256 = request.slice.artifactSHA256; containerSHA256 = request.slice.artifactSHA256
        sliceOffset = request.slice.sliceOffset; sliceSize = request.slice.sliceByteCount
        architecture = request.slice.cpuType == 0x0100000c && request.slice.cpuSubtype == 0 ? "arm64" : "unsupported"
        cpuSubtype = request.slice.cpuSubtype
        preferredBase = Int128(request.code.baseAddress) - Int128(request.code.sliceRelativeFileOffset)
        sections = [Section(address: request.code.baseAddress, size: Int128(request.code.words.count) * 4,
            fileOffset: request.code.sliceRelativeFileOffset, executable: true, flags: 0)]
        functions = request.functions; words = request.code.words; codeAddress = request.code.baseAddress
    }
    func bytesAt(address: UInt64, size: Int) throws -> Data {
        guard size >= 0 else { throw SwiftOutcomeError(code: "negative_size") }
        guard let section = sections.first(where: { $0.address <= address && Int128(address) + Int128(size) <= $0.end }) else {
            throw SwiftOutcomeError(code: "unmapped_address")
        }
        let fileOffset = Int128(section.fileOffset) + Int128(address) - Int128(section.address)
        guard ![UInt32(1), 12, 18].contains(section.flags & 0xff), fileOffset >= 0,
              fileOffset + Int128(size) <= Int128(sliceSize) else { throw SwiftOutcomeError(code: "unmapped_bytes") }
        let start = Int128(address) - Int128(codeAddress)
        guard start >= 0, start + Int128(size) <= Int128(words.count) * 4, let first = Int(exactly: start) else {
            throw SwiftOutcomeError(code: "unmapped_bytes")
        }
        var bytes: [UInt8] = []; bytes.reserveCapacity(size)
        for offset in first..<(first + size) { bytes.append(UInt8(truncatingIfNeeded: words[offset / 4] >> ((offset % 4) * 8))) }
        return Data(bytes)
    }
    func wordAt(_ address: UInt64) throws -> UInt32 {
        let bytes = [UInt8](try bytesAt(address: address, size: 4))
        return UInt32(bytes[0]) | UInt32(bytes[1]) << 8 | UInt32(bytes[2]) << 16 | UInt32(bytes[3]) << 24
    }
}

func buildSwiftCFG(image: SwiftOutcomeImage, function: SwiftErrorFlowFunction,
                   limits: SwiftCFGLimits = SwiftCFGLimits()) throws -> SwiftOutcomeJSON {
    try SwiftOutcomeCFGBuilder(image: image, function: function, limits: limits).build()
}

private final class SwiftOutcomeCFGBuilder {
    let image: SwiftOutcomeImage, function: SwiftErrorFlowFunction, limits: SwiftCFGLimits
    var workCount = 0, retainedWords = 0, blockCount = 0, edgeCount = 0, maxDiscoveryDepth = 0
    var allClassified = false
    var blocks: [SwiftOutcomeJSON] = [], edges: [SwiftOutcomeJSON] = []
    var calls: [SwiftOutcomeJSON] = [], returns: [SwiftOutcomeJSON] = [], exceptions: [SwiftOutcomeJSON] = []
    var leaders: Set<UInt64> = []
    init(image: SwiftOutcomeImage, function: SwiftErrorFlowFunction, limits: SwiftCFGLimits) {
        self.image = image; self.function = function; self.limits = limits
        leaders.insert(function.start)
    }
    func work() throws {
        guard workCount < limits.maxWork else { throw SwiftOutcomeError(code: "work_limit") }
        workCount += 1
    }
    func finish(_ status: String, _ reason: String) -> SwiftOutcomeJSON {
        .object(["model": .string("swift-bounded-structural-cfg-v1"), "status": .string(status), "reason": .string(reason),
            "function_pc": .string(swiftOutcomeHex(function.start)), "blocks": .array(blocks), "edges": .array(edges),
            "call_return_candidates": .array(calls), "returns": .array(returns), "exception_transfers": .array(exceptions),
            "external_exception_handling_unmodeled": .bool(true), "exception_resume_proven": .bool(false),
            "runtime_return_proven": .bool(false), "dominance_proven": .bool(false), "exclusive_path_proven": .bool(false),
            "source_reconstruction_allowed": .bool(false),
            "completeness": .object(["all_words_classified": .bool(allClassified), "complete": .bool(status == "eligible_structural_only"), "reason": .string(reason)]),
            "accounting": .object(["work": .integer(Int128(workCount)), "retained_words": .integer(Int128(retainedWords)),
                "blocks": .integer(Int128(blockCount)), "edges": .integer(Int128(edgeCount)), "max_discovery_depth": .integer(Int128(maxDiscoveryDepth))])])
    }
    func leader(_ pc: UInt64) throws {
        if !leaders.contains(pc) {
            guard leaders.count < limits.maxBlocks else { throw SwiftOutcomeError(code: "blocks_limit") }
            leaders.insert(pc)
        }
    }
    func edge(_ row: SwiftOutcomeJSON, _ kind: String, _ target: Int128? = nil) throws {
        guard edges.count < limits.maxEdges else { throw SwiftOutcomeError(code: "edges_limit") }
        try work()
        if let target {
            guard target >= 0, target < Int128(1) << 64, target % 4 == 0 else { throw SwiftOutcomeError(code: "invalid_branch_target") }
            guard Int128(function.start) <= target, target < Int128(function.endExclusive) else { throw SwiftOutcomeError(code: "branch_outside_function") }
        }
        var record: [String: SwiftOutcomeJSON] = [:]
        for key in ["pc", "word", "slice_offset", "container_offset"] { record[key] = row[key] }
        record["source_pc"] = row["pc"]; record["target_pc"] = target.map { .string(swiftOutcomeHex($0)) } ?? .null
        record["kind"] = .string(kind); edges.append(.object(record)); edgeCount += 1
        if let target { try leader(UInt64(target)) }
    }
    func build() throws -> SwiftOutcomeJSON {
        do {
            if image.architecture != "arm64" || ![UInt32(0), 1].contains(image.cpuSubtype) { return finish("declined", "ordinary_arm64_required") }
            var matches = 0
            for member in image.functions {
                try work()
                if member == function { matches += 1 }
                else if member.start < function.endExclusive && function.start < member.endExclusive { return finish("blocked", "overlapping_function_membership") }
            }
            guard matches == 1 else { return finish("blocked", "exact_function_membership_required") }
            guard function.boundarySource == "lc_function_starts" else { return finish("declined", "exact_lc_function_starts_required") }
            let size = Int128(function.endExclusive) - Int128(function.start)
            guard size > 0, function.start % 4 == 0, size % 4 == 0 else { return finish("blocked", "invalid_function_extent") }
            let count128 = size / 4
            if count128 > limits.maxRetainedWords { return finish("blocked", "retained_words_limit") }
            if count128 > limits.maxWork - workCount { return finish("blocked", "work_limit") }
            let count = Int(count128)
            var section: SwiftOutcomeImage.Section?
            for candidate in image.sections {
                try work()
                if candidate.address <= function.start && Int128(function.endExclusive) <= candidate.end {
                    if section != nil { return finish("blocked", "ambiguous_file_mapping") }
                    section = candidate
                }
            }
            guard let section, section.executable, ![UInt32(1), 12, 18].contains(section.flags & 0xff) else { return finish("blocked", "executable_file_mapping_required") }
            let offset = Int128(section.fileOffset) + Int128(function.start) - Int128(section.address)
            if offset < 0 || offset + size > Int128(image.sliceSize) { return finish("blocked", "truncated_file_mapping") }
            if limits.maxBlocks == 0 { return finish("blocked", "blocks_limit") }
            if limits.maxDepth == 0 { return finish("blocked", "depth_limit") }
            var rows: [SwiftOutcomeJSON] = [], unresolved = false
            let branches: Set<String> = ["b", "bcond", "wcbz", "wcbnz", "xcbz", "xcbnz", "wtbz", "wtbnz", "xtbz", "xtbnz"]
            for index in 0..<count {
                try work()
                let pc = function.start + UInt64(index) * 4
                let word = try image.wordAt(pc)
                var row: SwiftOutcomeJSON = .object(["pc": .string(swiftOutcomeHex(pc)), "word": .string(swiftOutcomeWord(word)),
                    "slice_offset": .string(swiftOutcomeHex(offset + Int128(index) * 4)),
                    "container_offset": .string(swiftOutcomeHex(Int128(image.sliceOffset) + offset + Int128(index) * 4))])
                var instruction: SwiftOutcomeInstruction?, kind: String
                do { let decoded = try decodeSwiftOutcomeInstruction(word: word, address: pc); instruction = decoded; kind = decoded.kind }
                catch let error as SwiftOutcomeError { row["unresolved_reason"] = .string(error.code); kind = "unresolved" }
                row["kind"] = .string(kind); rows.append(row); retainedWords += 1
                let following = Int128(pc) + 4
                if branches.contains(kind), let instruction {
                    try edge(row, kind == "b" ? "branch" : "conditional_taken", Int128(pc) + instruction.immediate)
                    if kind != "b" { try edge(row, "conditional_fallthrough", following) }
                } else if kind == "bl", let instruction {
                    let target = Int128(pc) + instruction.immediate
                    guard target >= 0, target < Int128(1) << 64, target % 4 == 0 else { throw SwiftOutcomeError(code: "invalid_call_target") }
                    try edge(row, "call_return_candidate", following)
                    var call = row; call["callee_pc"] = .string(swiftOutcomeHex(target)); call["continuation_pc"] = .string(swiftOutcomeHex(following)); call["runtime_return_proven"] = .bool(false); calls.append(call)
                } else if kind == "ret" { try edge(row, "return"); returns.append(row) }
                else if kind == "brk" {
                    try edge(row, "exception_transfer"); var exception = row
                    exception["exception"] = .string("breakpoint"); exception["resume_proven"] = .bool(false); exceptions.append(exception)
                } else if kind == "unresolved" { unresolved = true; try edge(row, "unresolved") }
                else if following == Int128(function.endExclusive) { throw SwiftOutcomeError(code: "fallthrough_outside_function") }
                else { continue }
                if following < Int128(function.endExclusive) { try leader(UInt64(following)) }
            }
            allClassified = !unresolved
            var owner: [UInt64: Int] = [:]
            for row in rows {
                try work(); let pc = swiftOutcomeParseHex(row["pc"])!
                if leaders.contains(pc) {
                    guard blocks.count < limits.maxBlocks else { throw SwiftOutcomeError(code: "blocks_limit") }
                    blocks.append(.object(["start_pc": row["pc"], "end_pc_exclusive": .null,
                        "instructions": .array([]), "successors": .array([]), "predecessors": .array([])])); blockCount += 1
                }
                let index = blocks.count - 1
                blocks[index]["instructions"] = .array((blocks[index]["instructions"].array ?? []) + [row])
                blocks[index]["end_pc_exclusive"] = .string(swiftOutcomeHex(Int128(pc) + 4)); owner[pc] = index
            }
            let terminalSources = Set(edges.compactMap { swiftOutcomeParseHex($0["source_pc"]) })
            for block in blocks {
                let row = block["instructions"].array!.last!, pc = swiftOutcomeParseHex(row["pc"])!
                if !terminalSources.contains(pc) { try edge(row, "fallthrough", Int128(pc) + 4) }
            }
            for item in edges {
                try work(); let source = owner[swiftOutcomeParseHex(item["source_pc"])!]!
                blocks[source]["successors"] = .array(blocks[source]["successors"].array! + [item])
                if let target = swiftOutcomeParseHex(item["target_pc"]), let index = owner[target] { blocks[index]["predecessors"] = .array(blocks[index]["predecessors"].array! + [item]) }
            }
            var seen: Set<UInt64> = []
            for root in blocks.indices {
                let start = swiftOutcomeParseHex(blocks[root]["start_pc"])!
                if seen.contains(start) { continue }
                var pending: [(Int, Int)] = [(root, 1)]; seen.insert(start)
                while let (index, depth) = pending.popLast() {
                    try work()
                    guard depth <= limits.maxDepth else { throw SwiftOutcomeError(code: "depth_limit") }
                    maxDiscoveryDepth = max(maxDiscoveryDepth, depth)
                    for item in blocks[index]["successors"].array!.reversed() {
                        if let target = swiftOutcomeParseHex(item["target_pc"]), !seen.contains(target) {
                            guard depth < limits.maxDepth else { throw SwiftOutcomeError(code: "depth_limit") }
                            seen.insert(target); pending.append((owner[target]!, depth + 1))
                        }
                    }
                }
            }
            return finish(unresolved ? "unresolved" : "eligible_structural_only", unresolved ? "unclassified_instruction_edges" : "bounded_classified_subset")
        } catch let error as SwiftOutcomeError { return finish("blocked", error.code) }
    }
}

func swiftOutcomeParseHex(_ value: SwiftOutcomeJSON) -> UInt64? {
    guard let text = value.string, text.hasPrefix("0x") else { return nil }
    return UInt64(text.dropFirst(2), radix: 16)
}

func swiftOutcomeFunctionRange(_ function: SwiftErrorFlowFunction) -> SwiftOutcomeJSON {
    .object(["start_pc": .string(swiftOutcomeHex(function.start)), "end_pc_exclusive": .string(swiftOutcomeHex(function.endExclusive)), "boundary_source": .string(function.boundarySource)])
}
