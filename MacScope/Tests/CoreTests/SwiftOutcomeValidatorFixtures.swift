import Foundation
import CryptoKit
#if canImport(MacScope)
@testable import MacScope

// Test-authored bytes and wire facts. No producer or CFG implementation is used.
enum OutcomeFixture {
    static let symbol = "_$s4Test3fooyS2iKF"
    static func hex(_ n: Int) -> String { "0x" + String(n, radix: 16) }
    static func word(_ n: UInt32) -> String { String(format: "0x%08x", n) }
    static func put(_ data: inout Data, _ offset: Int, _ width: Int, _ value: UInt64) {
        for i in 0..<width { data[offset + i] = UInt8(truncatingIfNeeded: value >> (8 * i)) }
    }
    static func text(_ data: inout Data, _ offset: Int, _ value: String) {
        for (i, byte) in value.utf8.enumerated() { data[offset + i] = byte }
    }
    static func json(_ source: String) throws -> SwiftOutcomeJSON {
        try SwiftOutcomeWitnessCodec.parse(Data(source.utf8))
    }
    static func finish(_ c: inout SwiftOutcomeJSON) {
        for _ in 0..<4 { c["accounting"]["encoded_bytes"] = .integer(Int128(SwiftOutcomeWitnessCodec.canonicalBytes(c).count)) }
    }
    static func assign(_ c: inout SwiftOutcomeJSON, _ path: [String], _ value: SwiftOutcomeJSON) {
        guard let first = path.first else { c = value; return }
        if let i = Int(first), var array = c.array, array.indices.contains(i) {
            assign(&array[i], Array(path.dropFirst()), value); c = .array(array)
        } else { var child = c[first]; assign(&child, Array(path.dropFirst()), value); c[first] = child }
    }
    static func image(_ data: Data, count: Int = 4, admitted: Bool = true) -> SwiftOutcomeValidatorImage {
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let functions = [SwiftErrorFlowFunction(start: 0x1000, endExclusive: UInt64(0x1000 + 4 * count), boundarySource: "lc_function_starts"), SwiftErrorFlowFunction(start: UInt64(0x1000 + 4 * count), endExclusive: UInt64(0x1010 + 4 * count), boundarySource: "lc_function_starts")]
        let sections = [SwiftOutcomeValidatorSection(segment: "__TEXT", name: "__text", address: 0x1000, size: UInt64(4 * (count + 4)), fileOffset: 256, flags: 0x80000400)]
        if admitted {
            return SwiftOutcomeValidatorImage.admit(data: data, path: "manual fixture", sliceSHA256: digest, containerSHA256: digest, architecture: "arm64", cpuSubtype: 0, uuid: nil, fileType: 2, preferredBase: 0xf00, sliceOffset: 0, sliceSize: UInt64(data.count), sliceIndex: 0, containerSliceCount: 1, sections: sections, functions: functions)
        }
        return SwiftOutcomeValidatorImage.unadmitted(data: data, path: "manual fixture", sliceSHA256: digest, containerSHA256: digest, architecture: "arm64", cpuSubtype: 0, uuid: nil, fileType: 2, preferredBase: 0xf00, sliceOffset: 0, sliceSize: UInt64(data.count), sliceIndex: 0, containerSliceCount: 1, sections: sections, functions: functions)
    }
    static func qualification(_ image: SwiftOutcomeValidatorImage, digest: String? = nil) -> SwiftOutcomeLoweringObservation {
        SwiftOutcomeLoweringObservation(evidenceID: "manual-reviewed", sliceSHA256: digest ?? image.sliceSHA256, sourceSHA256: "source-fixture", compiler: "test compiler", target: "arm64-apple-macosx14.0", optimization: "-O", symbol: String(symbol.dropFirst()), parameterTypes: ["Swift.Int"], resultType: "Swift.Int", parameterLocations: ["x0"], resultLocation: "x0", observations: [(pc: image.functions[1].start, bytesHex: "c0035fd6", note: "manual observed return byte")], sourceCapture: "manual-source:1", disassemblyCapture: "manual-disassembly:1")
    }
    struct Value {
        var image: SwiftOutcomeValidatorImage
        var candidate: SwiftOutcomeJSON
        var function: SwiftErrorFlowFunction { image.functions[0] }
        var registry: SwiftOutcomeABIRegistry { SwiftOutcomeABIRegistry([OutcomeFixture.qualification(image)]) }
        func validate(limits: BroadWitnessLimits = BroadWitnessLimits(), ledger: Any? = nil) -> SwiftOutcomeJSON {
            validateBroadSwiftWitness(image: image, function: function, candidate: candidate, limits: limits, registry: registry, imageLedger: ledger)
        }
    }
    static func manual() throws -> Value {
        var data = Data(repeating: 0, count: 1024)
        for (offset, value) in [(0,0xfeedfacf),(4,0x100000c),(8,0),(12,2),(16,3),(20,192),(24,0),(28,0),(32,0x19),(36,152),(88,7),(92,5),(96,1),(100,0),(152,256),(156,2),(168,0x80000400),(184,2),(188,24),(192,512),(196,1),(200,768),(204,symbol.utf8.count+2),(208,0x26),(212,16),(216,900),(220,4),(512,1)] { put(&data, offset, 4, UInt64(value)) }
        text(&data,40,"__TEXT"); text(&data,104,"__text"); text(&data,120,"__TEXT")
        for (offset,value) in [(56,0xf00),(64,8192),(72,0),(80,1024),(136,0x1000),(144,32),(520,0x1010)] { put(&data,offset,8,UInt64(value)) }
        data[516] = 15; data[517] = 1; text(&data,769,symbol)
        data[900] = 0x80; data[901] = 2; data[902] = 16
        let words: [UInt32] = [0x94000004,0xb4000055,0xd65f03c0,0xd65f03c0,0xd65f03c0,0xd65f03c0,0xd65f03c0,0xd65f03c0]
        for (i,w) in words.enumerated() { put(&data,256+i*4,4,UInt64(w)) }
        let im = image(data)
        var c = try json(#"{"model_version":"swift-outcome-witness-v2","validation_model":"swift-outcome-validation-v2","profile":"broad-v1","source_models":{"edge":"swift-broad-error-flow-v1","witness":"swift-outcome-witness-v2","validation":"swift-outcome-validation-v2","cfg":"swift-bounded-structural-cfg-v1","value":"swift-outcome-values-v1"},"status":"unresolved","eligible":false,"reason":"validation_required","identity":{"slice_sha256":"","container_sha256":"","slice_offset":"0x0","slice_size":"0x400","architecture":"arm64","cpu_subtype":0,"uuid":null,"preferred_base":"0xf00","slice_index":0,"container_slice_count":1,"caller":{"start_pc":"0x1000","end_pc_exclusive":"0x1010","boundary_source":"lc_function_starts"},"callee":{"start_pc":"0x1010","end_pc_exclusive":"0x1020","boundary_source":"lc_function_starts"},"call_pc":"0x1000"},"call":{"pc":"0x1000","word":"0x94000004","callee_pc":"0x1010","provenance":{"call":{"pc":"0x1000","word":"0x94000004","slice_file_offset":"0x100","container_file_offset":"0x100"},"callee_entry":{"pc":"0x1010","word":"0xd65f03c0","slice_file_offset":"0x110","container_file_offset":"0x110"}},"declaration":{"status":"syntax_admitted","identity":{},"reason":null},"abi":{"status":"admitted","profile":"swift6-arm64-sync-untyped-research-v1","error_register":"x21","research_only":true,"evidence":{"lowering":{"qualification_id":"manual-reviewed"}}}},"cfg":{"model":"swift-bounded-structural-cfg-v1","status":"eligible_structural_only","function_pc":"0x1000","blocks":[],"edges":[],"returns":[],"call_return_candidates":[],"completeness":{"complete":true,"all_words_classified":true},"accounting":{"work":20,"retained_words":4,"blocks":4,"edges":5,"max_discovery_depth":3}},"post_call":{"status":"candidate","reason":"qualified_error_alias_zero_test","test_pc":"0x1004","test_word":"0xb4000055","test_register":"x21","error_successor_pc":"0x1008","success_successor_pc":"0x100c","trace":["0x1004"]},"regions":{"status":"structural_candidates","success_entry_pc":"0x100c","error_entry_pc":"0x1008","paths":[{"outcome":"success","entry_pc":"0x100c","reachability":"unproven"},{"outcome":"error","entry_pc":"0x1008","reachability":"unproven"}],"tails":[{"pc":"0x1008","kind":"return","outcome":"unknown"},{"pc":"0x100c","kind":"return","outcome":"unknown"}]},"value_facts":{"seed":{"register":"x21","kind":"register_copy","origin":"abi_post_call_error:x21","width":64},"observations":[]},"completeness":{"complete":true,"missing":[]},"accounting":{"work":20,"instructions":4,"blocks":4,"edges":5,"value_steps":0,"encoded_bytes":1},"limitations":["research_only"]}"#)
        c["identity"]["slice_sha256"] = .string(im.sliceSHA256); c["identity"]["container_sha256"] = .string(im.containerSHA256)
        c["call"]["declaration"]["identity"] = parseBroadSwiftDeclaration(symbol).identity?.json ?? .null
        let rows = words.prefix(4).enumerated().map { row($0.offset,$0.element,["bl","xcbz","ret","ret"][$0.offset]) }
        let edges = [edge(rows[0],"call_return_candidate",1),edge(rows[1],"conditional_taken",3),edge(rows[1],"conditional_fallthrough",2),edge(rows[2],"return",nil),edge(rows[3],"return",nil)]
        c["cfg"]["edges"] = .array(edges)
        c["cfg"]["blocks"] = .array(rows.enumerated().map { i,r in .object(["start_pc":r["pc"],"end_pc_exclusive":.string(hex(0x1004+4*i)),"instructions":.array([r]),"successors":.array(edges.filter {$0["source_pc"] == r["pc"]}),"predecessors":.array(edges.filter {$0["target_pc"] == r["pc"]})]) })
        c["cfg"]["returns"] = .array(Array(rows.suffix(2)))
        var call = rows[0]; call["callee_pc"] = .string("0x1010"); call["continuation_pc"] = .string("0x1004"); call["runtime_return_proven"] = .bool(false)
        c["cfg"]["call_return_candidates"] = .array([call]); finish(&c)
        return Value(image:im,candidate:c)
    }
    static func row(_ i: Int, _ word: UInt32, _ kind: String) -> SwiftOutcomeJSON {
        .object(["pc":.string(hex(0x1000+4*i)),"word":.string(self.word(word)),"slice_offset":.string(hex(256+4*i)),"container_offset":.string(hex(256+4*i)),"kind":.string(kind)])
    }
    static func edge(_ row: SwiftOutcomeJSON, _ kind: String, _ target: Int?) -> SwiftOutcomeJSON {
        var e = row; e["source_pc"] = row["pc"]; e["kind"] = .string(kind); e["target_pc"] = target.map { .string(hex(0x1000+4*$0)) } ?? .null; return e
    }
}
#endif

#if canImport(MacScope)
extension OutcomeFixture {
    static func expanded(_ input: [(UInt32,String)], branches: [Int:[Int]], success: Int, error: Int, observations: [SwiftOutcomeJSON] = [], comparison: Int? = nil, callIndex: Int = 0) throws -> Value {
        var f = try manual(); var specs = input; let count = specs.count
        specs[callIndex] = (0x94000000 | UInt32(count-callIndex),"bl")
        var data = f.image.data
        put(&data,144,8,UInt64(4*(count+4))); put(&data,136,8,0x1000); put(&data,152,4,256)
        for (i,spec) in (specs + Array(repeating:(UInt32(0xd65f03c0),"ret"),count:4)).enumerated() { put(&data,256+4*i,4,UInt64(spec.0)) }
        put(&data,520,8,UInt64(0x1000+count*4)); data[902] = UInt8(count*4)
        f.image = image(data,count:count)
        var c = f.candidate
        c["identity"]["slice_sha256"] = .string(f.image.sliceSHA256); c["identity"]["container_sha256"] = .string(f.image.containerSHA256)
        c["identity"]["caller"]["end_pc_exclusive"] = .string(hex(0x1000+count*4))
        c["identity"]["callee"]["start_pc"] = .string(hex(0x1000+count*4)); c["identity"]["callee"]["end_pc_exclusive"] = .string(hex(0x1010+count*4)); c["identity"]["call_pc"] = .string(hex(0x1000+callIndex*4))
        c["call"]["pc"] = .string(hex(0x1000+callIndex*4)); c["call"]["word"] = .string(word(specs[callIndex].0)); c["call"]["callee_pc"] = .string(hex(0x1000+count*4))
        for (key,i,w) in [("call",callIndex,specs[callIndex].0),("callee_entry",count,UInt32(0xd65f03c0))] {
            c["call"]["provenance"][key] = .object(["pc":.string(hex(0x1000+4*i)),"word":.string(word(w)),"slice_file_offset":.string(hex(256+4*i)),"container_file_offset":.string(hex(256+4*i))])
        }
        let rows = specs.enumerated().map { row($0.offset,$0.element.0,$0.element.1) }
        var edges: [SwiftOutcomeJSON] = []; var leaders: Set<Int> = [0]; var terminals: Set<Int> = []
        func add(_ i: Int,_ kind: String,_ target: Int? = nil) {
            edges.append(edge(rows[i],kind,target)); terminals.insert(i); if let target { leaders.insert(target) }
        }
        for i in specs.indices {
            if i == callIndex { add(i,"call_return_candidate",i+1) }
            else if specs[i].1 == "ret" { add(i,"return") }
            else if specs[i].1 == "brk" { add(i,"exception_transfer") }
            else if let choices = branches[i] { add(i,specs[i].1 == "b" ? "branch" : "conditional_taken",choices[0]); if specs[i].1 != "b" { add(i,"conditional_fallthrough",choices[1]) } }
            if terminals.contains(i) && i+1<count { leaders.insert(i+1) }
        }
        var blocks: [[Int]] = []
        for i in specs.indices { if leaders.contains(i) { blocks.append([]) }; blocks[blocks.count-1].append(i) }
        for block in blocks { let i = block.last!; if !terminals.contains(i) { add(i,"fallthrough",i+1) } }
        var owner: [Int:Int] = [:]; for (b,indices) in blocks.enumerated() { for i in indices { owner[i] = b } }
        let wireBlocks: [SwiftOutcomeJSON] = blocks.map { indices in
            .object(["start_pc": rows[indices.first!]["pc"],"end_pc_exclusive":.string(hex(0x1004+4*indices.last!)),"instructions":.array(indices.map { rows[$0] }),"successors":.array(edges.filter { e in indices.contains { rows[$0]["pc"] == e["source_pc"] } }),"predecessors":.array(edges.filter { e in e["target_pc"] == rows[indices.first!]["pc"] })])
        }
        var seen: Set<Int> = []; var depthMax = 0
        for b in blocks.indices where !seen.contains(b) {
            seen.insert(b); var stack = [(b,1)]
            while let (current,depth) = stack.popLast() {
                depthMax = max(depthMax,depth)
                for e in wireBlocks[current]["successors"].array!.reversed() {
                    if let target = rows.firstIndex(where: {$0["pc"] == e["target_pc"]}), let next = owner[target], seen.insert(next).inserted { stack.append((next,depth+1)) }
                }
            }
        }
        c["cfg"]["blocks"] = .array(wireBlocks); c["cfg"]["edges"] = .array(edges); c["cfg"]["returns"] = .array(rows.filter {$0["kind"] == .string("ret")})
        var call = rows[callIndex]; call["callee_pc"] = .string(hex(0x1000+count*4)); call["continuation_pc"] = .string(hex(0x1004+callIndex*4)); call["runtime_return_proven"] = .bool(false)
        c["cfg"]["call_return_candidates"] = .array([call])
        c["cfg"]["accounting"] = .object(["work":.integer(100),"retained_words":.integer(Int128(count)),"blocks":.integer(Int128(blocks.count)),"edges":.integer(Int128(edges.count)),"max_discovery_depth":.integer(Int128(depthMax))])
        if specs.contains(where: {$0.1 == "brk"}) {
            c["cfg"]["exception_transfers"] = .array(rows.filter {$0["kind"] == .string("brk")}.map { r in var v=r; v["exception"] = .string("breakpoint"); v["resume_proven"] = .bool(false); return v })
            c["cfg"]["external_exception_handling_unmodeled"] = .bool(true); c["cfg"]["exception_resume_proven"] = .bool(false)
        }
        let test = branches.keys.sorted().first { ["xcbz","xcbnz","bcond"].contains(specs[$0].1) }!
        var trace: [SwiftOutcomeJSON] = []; var i = callIndex+1
        while true { trace.append(rows[i]["pc"]); if i == test { break }; i = specs[i].1 == "b" ? branches[i]![0] : i+1 }
        c["post_call"]["test_pc"] = rows[test]["pc"]; c["post_call"]["test_word"] = rows[test]["word"]; c["post_call"]["trace"] = .array(trace)
        c["post_call"]["success_successor_pc"] = rows[success]["pc"]; c["post_call"]["error_successor_pc"] = rows[error]["pc"]
        if let comparison { c["post_call"]["test_kind"] = .string("cmp_zero_bcond"); c["post_call"]["comparison_pc"] = rows[comparison]["pc"]; c["post_call"]["comparison_word"] = rows[comparison]["word"]; c["post_call"]["test_condition"] = .string(specs[test].0 & 15 == 0 ? "eq" : "ne") }
        func reached(_ start: Int) -> Set<Int> {
            var found: Set<Int> = []; var todo = [start]
            while let i = todo.popLast() { if !found.insert(i).inserted { continue }; if ["ret","brk"].contains(specs[i].1) { continue }; todo.append(contentsOf: branches[i] ?? [i+1]) }
            return found
        }
        let ss = reached(success), es = reached(error)
        c["regions"]["success_entry_pc"] = rows[success]["pc"]; c["regions"]["error_entry_pc"] = rows[error]["pc"]
        c["regions"]["paths"] = .array([("success",success),("error",error)].map { .object(["outcome":.string($0.0),"entry_pc":rows[$0.1]["pc"],"reachability":.string("unproven")]) })
        c["regions"]["partition"] = .object(["success_only_pcs":.array(ss.subtracting(es).sorted().map {rows[$0]["pc"]}),"error_only_pcs":.array(es.subtracting(ss).sorted().map {rows[$0]["pc"]}),"shared_pcs":.array(ss.intersection(es).sorted().map {rows[$0]["pc"]}),"unreachable_pcs":.array(Set(specs.indices).subtracting(ss.union(es)).sorted().map {rows[$0]["pc"]})])
        c["regions"]["tails"] = .array(specs.indices.filter {specs[$0].1 == "ret"}.map { i in .object(["pc":rows[i]["pc"],"kind":.string("return"),"outcome":.string(ss.contains(i) && es.contains(i) ? "shared" : ss.contains(i) ? "success" : es.contains(i) ? "error" : "unreachable")]) })
        c["value_facts"]["observations"] = .array(observations)
        c["accounting"]["work"] = .integer(100); c["accounting"]["instructions"] = .integer(Int128(count)); c["accounting"]["blocks"] = .integer(Int128(blocks.count)); c["accounting"]["edges"] = .integer(Int128(edges.count)); c["accounting"]["value_steps"] = .integer(Int128(observations.count)); finish(&c); f.candidate = c
        return f
    }
}
#endif
