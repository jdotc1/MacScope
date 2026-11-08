import Foundation

struct SwiftOutcomeRawSymbolTable {
    let offset: Int, count: Int, strings: Int, length: Int
}
struct SwiftOutcomeRawSymbol {
    let stringIndex: Int
    let kind: UInt8, section: UInt8
    let description: UInt16
}
private final class SwiftOutcomeLedgerIssuer: Sendable {}
private let swiftOutcomeLedgerIssuer = SwiftOutcomeLedgerIssuer()
private final class SwiftOutcomeLedgerCounter: @unchecked Sendable {
    let lock = NSLock()
    var count = 0
}
private let swiftOutcomeLedgerCounter = SwiftOutcomeLedgerCounter()

final class SwiftOutcomeImageLedger {
    private let image: SwiftOutcomeValidatorImage
    private let issuer: SwiftOutcomeLedgerIssuer?
    let status: String
    let reason: String?
    let initialWorkSteps: Int
    let sections: [SwiftNominalSectionInput]
    let starts: [UInt64]
    let boundaries: [UInt64: UInt64]
    let functionIndex: [UInt64: SwiftErrorFlowFunction]
    let symbolTable: SwiftOutcomeRawSymbolTable?
    let symbols: [UInt64: [SwiftOutcomeRawSymbol]]
    static var factoryCallCount: Int {
        swiftOutcomeLedgerCounter.lock.lock()
        defer { swiftOutcomeLedgerCounter.lock.unlock() }
        return swiftOutcomeLedgerCounter.count
    }
    fileprivate init(image: SwiftOutcomeValidatorImage, issued: Bool, status: String, reason: String?,
                     work: Int, sections: [SwiftNominalSectionInput], starts: [UInt64],
                     boundaries: [UInt64: UInt64], functionIndex: [UInt64: SwiftErrorFlowFunction],
                     table: SwiftOutcomeRawSymbolTable?, symbols: [UInt64: [SwiftOutcomeRawSymbol]]) {
        self.image = image; issuer = issued ? swiftOutcomeLedgerIssuer : nil
        self.status = status; self.reason = reason; initialWorkSteps = work
        self.sections = sections; self.starts = starts; self.boundaries = boundaries
        self.functionIndex = functionIndex; symbolTable = table; self.symbols = symbols
    }
    func matches(_ image: SwiftOutcomeValidatorImage) -> Bool {
        issuer === swiftOutcomeLedgerIssuer && self.image === image && image.hasValidAdmission && status == "ready"
    }
    func copy() -> SwiftOutcomeImageLedger {
        SwiftOutcomeImageLedger(image: image, issued: false, status: status, reason: reason,
            work: initialWorkSteps, sections: sections, starts: starts, boundaries: boundaries,
            functionIndex: functionIndex, table: symbolTable, symbols: symbols)
    }
}

func createIndependentSwiftImageLedger(_ image: SwiftOutcomeValidatorImage, maxWork: Int = 262144) -> SwiftOutcomeImageLedger {
    swiftOutcomeLedgerCounter.lock.lock()
    swiftOutcomeLedgerCounter.count += 1
    swiftOutcomeLedgerCounter.lock.unlock()
    var work = 0
    var sections: [SwiftNominalSectionInput] = []
    var starts: [UInt64] = [], boundaries: [UInt64: UInt64] = [:]
    var functionIndex: [UInt64: SwiftErrorFlowFunction] = [:]
    var symbols: [UInt64: [SwiftOutcomeRawSymbol]] = [:]
    var table: SwiftOutcomeRawSymbolTable?
    var status = "ready", reason: String?
    func need(_ yes: Bool, _ why: String, _ state: String = "declined") throws {
        if !yes { throw SwiftOutcomeValidatorStop(reason: why, status: state) }
    }
    func charge(_ n: Int = 1) throws {
        try need(n >= 0 && n <= maxWork - work, "validator_image_work_limit", "unresolved")
        work += n
    }
    func read(_ off: Int, _ n: Int) throws -> [UInt8] {
        try charge(n + 1)
        try need(off >= 0 && off <= image.data.count && n >= 0 && n <= image.data.count - off
                 && Int128(off) + Int128(n) <= Int128(image.sliceSize), "raw_extent")
        let start = image.data.index(image.data.startIndex, offsetBy: off)
        let end = image.data.index(start, offsetBy: n)
        return Array(image.data[start..<end])
    }
    func uint(_ b: [UInt8], _ offset: Int, _ count: Int) -> UInt64 {
        var value: UInt64 = 0
        for i in 0..<count { value |= UInt64(b[offset+i]) << (8*i) }
        return value
    }
    func ascii(_ b: ArraySlice<UInt8>) throws -> String {
        var bytes = Array(b)
        while bytes.last == 0 { bytes.removeLast() }
        try need(bytes.allSatisfy { $0 < 128 }, "malformed_image_directory")
        return String(decoding: bytes, as: UTF8.self)
    }
    func integer(_ n: UInt64, _ why: String) throws -> Int {
        guard let value = Int(exactly: n) else { throw SwiftOutcomeValidatorStop(reason: why, status: "declined") }
        return value
    }
    do {
        try need(maxWork >= 0 && maxWork <= 262144, "invalid_image_ledger_limit")
        try need(image.hasValidAdmission, "image_admission_custody", "unresolved")
        try need(image.architecture == "arm64" && [0,1].contains(image.cpuSubtype), "ordinary_arm64_required")
        try need(image.sliceSize == UInt64(image.data.count), "slice_extent")
        let header = try read(0,32)
        try need(uint(header,0,4) == 0xfeedfacf && uint(header,4,4) == 0x100000c
                 && uint(header,8,4) == UInt64(image.cpuSubtype) && Int128(uint(header,12,4)) == Int128(image.fileType), "raw_header_identity")
        let commands = Int(uint(header,16,4)), commandBytes = Int(uint(header,20,4))
        try need(commands <= 4096 && commandBytes <= image.data.count - 32, "raw_command_extent", "unresolved")
        var cursor = 32
        var startsBlob: (Int,Int)?
        var base: UInt64?
        for _ in 0..<commands {
            let h = try read(cursor,8), command = uint(h,0,4), size = Int(uint(h,4,4))
            try need(size >= 8 && size % 8 == 0 && size <= 32 + commandBytes - cursor, "raw_command_extent")
            if command == 0x19 {
                try need(size >= 72, "raw_segment_extent")
                let b = try read(cursor+8,64)
                var segmentName = Array(b[0..<16])
                while segmentName.last == 0 { segmentName.removeLast() }
                let vm = uint(b,16,8), vmSize = uint(b,24,8)
                let off = uint(b,32,8), fileSize = uint(b,40,8), count = Int(uint(b,56,4))
                try need(count <= 4096 && size == 72 + 80*count, "raw_section_extent")
                let vmEnd = Int128(vm) + Int128(vmSize), fileEnd = Int128(off) + Int128(fileSize)
                try need(vmEnd <= Int128(UInt64.max) + 1 && fileEnd <= Int128(image.sliceSize), "raw_segment_extent")
                if segmentName == Array("__TEXT".utf8) { try need(base == nil, "ambiguous_text_base"); base = vm }
                for j in 0..<count {
                    let b = try read(cursor+72+j*80,80)
                    let va = uint(b,32,8), sz = uint(b,40,8), fo = uint(b,48,4), flags = UInt32(uint(b,64,4))
                    try need(uint(b,60,4) == 0, "raw_relocations_unsupported", "unresolved")
                    let end = Int128(va) + Int128(sz)
                    try need(va >= vm && end <= vmEnd && end <= Int128(UInt64.max)+1
                             && ([1,12,18].contains(Int(flags & 255)) || (fo >= off && Int128(fo)+Int128(sz) <= fileEnd)), "raw_section_extent")
                    // The typed range end cannot represent 2^64: refuse rather than wrap.
                    guard let end64 = UInt64(exactly: end) else { throw SwiftOutcomeValidatorStop(reason: "raw_section_extent", status: "declined") }
                    sections.append(SwiftNominalSectionInput(segment: try ascii(b[16..<32]), name: try ascii(b[0..<16]),
                        address: va, end: end64, size: sz, offset: try integer(fo,"raw_section_extent"), flags: flags))
                }
            } else if command == 2 {
                try need(table == nil && size == 24, "raw_symbol_table")
                let b = try read(cursor+8,16)
                table = SwiftOutcomeRawSymbolTable(offset: Int(uint(b,0,4)), count: Int(uint(b,4,4)),
                                                    strings: Int(uint(b,8,4)), length: Int(uint(b,12,4)))
            } else if command == 0x26 {
                try need(startsBlob == nil && size == 16, "raw_function_starts")
                let b = try read(cursor+8,8); startsBlob = (Int(uint(b,0,4)),Int(uint(b,4,4)))
            } else if command == 0xb {
                try need(size == 80,"raw_dynamic_symbols")
                let first = try read(cursor+68,4), last = try read(cursor+76,4)
                try need(uint(first,0,4) == uint(last,0,4) && uint(last,0,4) == 0,"raw_relocations_unsupported","unresolved")
            }
            cursor += size
        }
        try need(cursor == 32+commandBytes && base == image.preferredBase, "raw_command_geometry")
        try need(sections.count == image.sections.count,"section_metadata")
        let ordered = sections.filter { $0.size > 0 }.sorted { $0.address < $1.address }
        for (a,b) in zip(ordered,ordered.dropFirst()) { try need(a.end <= b.address,"overlapping_raw_sections") }
        for (raw,s) in zip(sections,image.sections) {
            try need(raw.segment == s.segment && raw.name == s.name && raw.address == s.address
                     && raw.size == s.size && UInt64(raw.offset) == s.fileOffset && raw.flags == s.flags,"section_metadata")
        }
        let lookupCost = max(1, Int.bitWidth - ordered.count.leadingZeroBitCount)
        func sectionAt(_ pc: UInt64) -> SwiftNominalSectionInput? {
            var lo = 0, hi = ordered.count
            while lo < hi { let m = lo + (hi-lo)/2; if ordered[m].address <= pc { lo = m+1 } else { hi = m } }
            return lo == 0 ? nil : ordered[lo-1]
        }
        guard let blob = startsBlob else { throw SwiftOutcomeValidatorStop(reason:"raw_function_starts_missing",status:"unresolved") }
        let bytes = try read(blob.0,blob.1)
        var value: UInt64 = 0, shift = 0, pc = base ?? 0, terminated = false
        for byte in bytes {
            try charge(); try need(!terminated || byte == 0,"raw_function_starts_trailing")
            if terminated { continue }
            try need(shift < 64 && (shift != 63 || byte <= 1),"raw_function_starts_overflow")
            value |= UInt64(byte & 127) << shift
            if byte & 128 != 0 { shift += 7; continue }
            if value == 0 { terminated = true; continue }
            let sum = pc.addingReportingOverflow(value)
            try need(!sum.overflow && sum.partialValue % 4 == 0,"raw_function_starts_address"); pc = sum.partialValue
            try charge(lookupCost); try need(pc <= UInt64.max-3,"vm_extent")
            guard let section = sectionAt(pc), Int128(pc)+4 <= Int128(section.end) else {
                throw SwiftOutcomeValidatorStop(reason:"raw_mapping_ambiguous",status:"declined")
            }
            try need(section.executable && ![1,8,12,18].contains(Int(section.flags & 255))
                     && !section.name.lowercased().contains("stub"),"raw_mapping_not_executable")
            starts.append(pc); try need(starts.count <= 262144,"raw_function_starts_limit","unresolved")
            value = 0; shift = 0
        }
        try need(terminated,"raw_function_starts_termination")
        guard let t = table else { throw SwiftOutcomeValidatorStop(reason:"raw_symbols_missing",status:"declined") }
        try need(t.count <= maxWork/17,"raw_symbols_limit","unresolved")
        try need(Int128(t.offset)+16*Int128(t.count) <= Int128(image.sliceSize)
                 && Int128(t.strings)+Int128(t.length) <= Int128(image.sliceSize),"raw_symbols_extent")
        for i in 0..<t.count {
            let b = try read(t.offset+16*i,16)
            symbols[uint(b,8,8), default:[]].append(SwiftOutcomeRawSymbol(stringIndex:Int(uint(b,0,4)),kind:b[4],section:b[5],description:UInt16(uint(b,6,2))))
        }
        try charge(image.functions.count); try need(image.functions.count <= maxWork,"image_function_limit","unresolved")
        for (i,pc) in starts.enumerated() {
            try charge(lookupCost+1)
            guard let section = sectionAt(pc) else { throw SwiftOutcomeValidatorStop(reason:"raw_mapping_ambiguous",status:"declined") }
            boundaries[pc] = i+1 < starts.count && starts[i+1] < section.end ? starts[i+1] : section.end
        }
        var previousEnd: UInt64 = 0
        for f in image.functions.sorted(by: { $0.start < $1.start }) {
            try charge(); try need(f.start >= previousEnd && f.start < f.endExclusive,"overlapping_functions")
            try need(boundaries[f.start] == f.endExclusive,"raw_function_metadata")
            try need(functionIndex[f.start] == nil,"duplicate_function_metadata")
            functionIndex[f.start] = f; previousEnd = f.endExclusive
        }
        try need(Set(functionIndex.keys) == Set(starts),"raw_function_metadata")
    } catch let stop as SwiftOutcomeValidatorStop { status = stop.status; reason = stop.reason }
    catch { status = "declined"; reason = "malformed_image_directory" }
    if status != "ready" { sections = []; starts = []; boundaries = [:]; functionIndex = [:]; symbols = [:]; table = nil }
    return SwiftOutcomeImageLedger(image:image,issued:true,status:status,reason:reason,work:work,
        sections:sections,starts:starts,boundaries:boundaries,functionIndex:functionIndex,table:table,symbols:symbols)
}
