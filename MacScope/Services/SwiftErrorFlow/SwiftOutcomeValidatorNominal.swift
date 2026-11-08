import Foundation

struct SwiftNominalDeclarationInput {
    let module: String
    let context: [(name: String, kind: String)]
}
struct SwiftNominalSectionInput {
    let segment: String, name: String
    let address: UInt64, end: UInt64, size: UInt64
    let offset: Int
    let flags: UInt32
    var executable: Bool { name == "__text" || flags & 0x80000400 != 0 }
}

func replaySwiftNominalContext(declaration: SwiftNominalDeclarationInput,
    sections: [SwiftNominalSectionInput], read: (Int,Int) throws -> Data,
    limits: BroadWitnessLimits) throws -> SwiftOutcomeJSON {
    var work = 0
    return try replaySwiftNominalContext(declaration: declaration, sections: sections, read: { off,n in
        guard n >= 0 && n < Int.max && n+1 <= limits.maxWork-work else {
            throw SwiftOutcomeValidatorStop(reason: "validator_work_limit", status: "unresolved")
        }
        work += n+1
        return try read(off,n)
    }, limits: limits, charge: { n in
        guard n >= 0 && n <= limits.maxWork-work else {
            throw SwiftOutcomeValidatorStop(reason: "validator_work_limit", status: "unresolved")
        }
        work += n
    })
}

func replaySwiftNominalContext(declaration: SwiftNominalDeclarationInput,
    sections: [SwiftNominalSectionInput], read: (Int,Int) throws -> Data,
    limits: BroadWitnessLimits, charge: (Int) throws -> Void) throws -> SwiftOutcomeJSON {
    func need(_ condition: Bool, _ reason: String) throws {
        if !condition { throw SwiftOutcomeValidatorStop(reason: reason, status: "unresolved") }
    }
    try need(sections.count <= 4096,"nominal_section_limit")
    try charge(sections.count * max(1,Int.bitWidth-sections.count.leadingZeroBitCount))
    let ordered = sections.filter { $0.size > 0 }.sorted { $0.address < $1.address }
    for (left,right) in zip(ordered,ordered.dropFirst()) { try need(left.end <= right.address,"nominal_mapping_ambiguous") }
    let typed = sections.filter { $0.segment == "__TEXT" && $0.name == "__swift5_types" }
    try need(typed.count == 1,"nominal_context_missing")
    let s = typed[0]
    try need(s.size % 4 == 0 && s.size/4 <= UInt64(limits.maxBlocks),"nominal_context_limit")
    func locate(_ pc: Int128, _ n: Int) throws -> SwiftNominalSectionInput {
        try charge(max(1,Int.bitWidth-ordered.count.leadingZeroBitCount))
        try need(pc >= 0 && n >= 0 && pc+Int128(n) <= Int128(UInt64.max)+1,"nominal_mapping")
        var lo = 0, hi = ordered.count
        while lo < hi { let m = lo+(hi-lo)/2; if Int128(ordered[m].address) <= pc { lo = m+1 } else { hi = m } }
        try need(lo > 0,"nominal_mapping")
        let section = ordered[lo-1]
        try need(pc+Int128(n) <= Int128(section.end),"nominal_mapping")
        try need(![1,12,18].contains(Int(section.flags & 255)),"nominal_zero_fill")
        return section
    }
    func offset(_ section: SwiftNominalSectionInput, _ pc: Int128) throws -> Int {
        guard let off = Int(exactly:Int128(section.offset)+pc-Int128(section.address)), off >= 0 else {
            throw SwiftOutcomeValidatorStop(reason:"nominal_mapping",status:"unresolved")
        }
        return off
    }
    func raw(_ pc: Int128, _ n: Int) throws -> Data {
        let section = try locate(pc,n)
        let data = try read(offset(section,pc),n)
        try need(data.count == n,"nominal_mapping")
        return data
    }
    func word(_ pc: Int128) throws -> UInt32 {
        let b = Array(try raw(pc,4))
        return UInt32(b[0]) | UInt32(b[1]) << 8 | UInt32(b[2]) << 16 | UInt32(b[3]) << 24
    }
    func relative(_ pc: Int128, context: Bool = false) throws -> Int128 {
        let off = Int32(bitPattern:try word(pc))
        try need(off != 0 && !(context && off & 1 != 0),"nominal_indirect_parent")
        return pc+Int128(off)
    }
    func name(_ pc: Int128) throws -> String {
        let capacity = min(limits.maxString,256)
        try need(capacity > 0,"nominal_name_limit")
        let section = try locate(pc,1)
        var output: [UInt8] = [], cursor = pc
        while output.count < capacity {
            try need(cursor < Int128(section.end),"nominal_name_extent")
            let size = Int(min(Int128(32),Int128(capacity-output.count),Int128(section.end)-cursor))
            let chunk = Array(try read(offset(section,cursor),size)); try charge(1)
            try need(chunk.count == size,"nominal_name_extent")
            if let zero = chunk.firstIndex(of:0) {
                output.append(contentsOf:chunk[..<zero]); try need(!output.isEmpty,"nominal_empty_name")
                try need(output.allSatisfy { $0 < 128 },"nominal_name_encoding")
                return String(decoding:output,as:UTF8.self)
            }
            output.append(contentsOf:chunk); cursor += Int128(size)
        }
        throw SwiftOutcomeValidatorStop(reason:"nominal_name_limit",status:"unresolved")
    }
    func hex(_ n: Int128) -> String { "0x"+String(n,radix:16) }
    func bytesHex(_ data: Data) -> String { data.map { String(format:"%02x",$0) }.joined() }
    let kinds: [UInt32:String] = [0:"module",16:"class",17:"struct",18:"enum"]
    var matches: [Int128:SwiftOutcomeJSON] = [:], visited = Set<Int128>()
    var entryOffset: UInt64 = 0
    while entryOffset < s.size {
        let entry = Int128(s.address)+Int128(entryOffset); entryOffset += 4
        var pc = try relative(entry,context:true)
        if !visited.insert(pc).inserted { continue }
        let leaf = pc
        var chain: [(String,String)] = [], seen = Set<Int128>(), records: [SwiftOutcomeJSON] = []
        let leafFlags = try word(pc)
        if [16,17,18].contains(leafFlags & 31) && leafFlags & 0xff00 == 0 {
            guard let last = declaration.context.last else { throw SwiftOutcomeValidatorStop(reason:"nominal_context_ambiguous_or_missing",status:"unresolved") }
            if try name(relative(pc+8)) != last.name { continue }
        }
        var ended = false
        for _ in 0..<limits.maxDepth {
            try charge(1); try need(seen.insert(pc).inserted,"nominal_cycle")
            try need(pc % 4 == 0,"nominal_descriptor_alignment")
            let flags = try word(pc), kind = flags & 31
            guard let kindName = kinds[kind] else { throw SwiftOutcomeValidatorStop(reason:"nominal_kind",status:"unresolved") }
            let allowed: UInt32 = 0x5f | (kind == 16 ? 0x80000000 : 0)
            try need(flags & ~allowed == 0,"nominal_flags")
            let descriptor = try raw(pc,kind == 0 ? 12 : kind == 16 ? 44 : 28)
            let namePC = try relative(pc+8), n = try name(namePC)
            let record: SwiftOutcomeJSON = .object([
                "descriptor_pc":.string(hex(pc)),"descriptor_flags":.string(hex(Int128(flags))),
                "kind":.string(kindName),"name":.string(n),"name_pc":.string(hex(namePC)),
                "raw_name":.string(bytesHex(Data(n.utf8)+Data([0]))),"raw_descriptor":.string(bytesHex(descriptor))])
            if kind == 0 {
                try need(try word(pc+4) == 0,"nominal_module_parent")
                let reverse = Array(chain.reversed())
                let sameContext = reverse.count == declaration.context.count && zip(reverse,declaration.context).allSatisfy { $0.0.0 == $0.1.name && $0.0.1 == $0.1.kind }
                if n == declaration.module && sameContext {
                    matches[leaf] = .object(["status":.string("admitted_nominal_context"),"entry_pc":.string(hex(entry)),
                        "raw_entry":.string(bytesHex(try raw(entry,4))),"records":.array(Array(records.reversed())),"module":record])
                }
                ended = true; break
            }
            records.append(record); chain.append((n,kindName)); pc = try relative(pc+4,context:true)
        }
        try need(ended,"nominal_depth_limit")
    }
    try need(matches.count == 1,"nominal_context_ambiguous_or_missing")
    return matches.values.first!
}
