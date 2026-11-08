import Foundation

struct SwiftOutcomeInstruction: Equatable, Sendable {
    var address: UInt64
    var word: UInt32
    var kind: String
    var rd: Int = 0
    var rn: Int = 0
    var rt2: Int = 0
    var immediate: Int128 = 0
    var addressing: String = ""
}

/// The legacy supplemental analyses use their original Swift-local -> CFG -> base
/// classification, without broad-only forms or the v2 native-compatibility policy.
/// The live outcomeWitnessV2 route continues to use decodeSwiftOutcomeInstruction.
func decodeSwiftOutcomeLegacyInstruction(word: UInt32, address: UInt64 = 0) throws -> SwiftOutcomeInstruction {
    try SwiftOutcomeWordDecoder(word: word, address: address).historical()
}

enum SwiftOutcomeInstructionKinds {
    static let fpDestinations: Set<String> = ["scvtf_s_w", "scvtf_s_x", "scvtf_d_w", "scvtf_d_x", "fmov_s_w", "fmov_d_x", "fmov_s_reg", "fmov_d_reg", "fmov_s_imm", "fmov_d_imm", "fdiv_s", "fdiv_d", "qldr", "sldr", "dldr", "movi_2s_lsl24"]
    static let gprDestinations: Set<String> = ["adr", "adrp", "fmov_w_s", "fmov_x_d", "wldrb", "wldrh", "xadd_reg", "xsub_reg", "wadd_reg", "wsub_reg", "xadd_ext", "xsub_ext", "xldr_raw", "xldur", "wldr_raw", "wldur", "fcvtzs_w_s", "fcvtzs_w_d", "fcvtzs_x_s", "fcvtzs_x_d"]
    static let fpFlags: Set<String> = ["fcmp_s_reg", "fcmp_s_zero", "fcmp_d_reg", "fcmp_d_zero"]
    static let fpMemoryStores: Set<String> = ["sstr", "dstr", "qstr"]
    static let memoryWidths: [String: Int] = ["wstrb":1, "wldrb":1, "wstrh":2, "wldrh":2, "xstr_raw":8, "xldr_raw":8, "xstur":8, "xldur":8, "qstr":16, "qldr":16, "wstr_raw":4, "wldr_raw":4, "wstur":4, "wldur":4, "sstr":4, "sldr":4, "dstr":8, "dldr":8]
}

func decodeSwiftOutcomeInstruction(word: UInt32, address: UInt64 = 0) throws -> SwiftOutcomeInstruction {
    let descriptor = try SwiftOutcomeWordDecoder(word: word, address: address).broad()
    // Missing source forms are refused before invoking the native decoder.
    guard SwiftOutcomeDecoderCrossCheck.mnemonics(for: descriptor.kind) != nil || SwiftOutcomeDecoderCrossCheck.flow(for: descriptor.kind) != nil else {
        throw SwiftOutcomeError(code: "decoder_form_missing")
    }
    let bytes = (0..<4).map { UInt8(truncatingIfNeeded: word >> ($0 * 8)) }
    guard let decoded = ARM64Decoder().decode(Data(bytes), baseAddress: address, maxInstructionCount: 1).first else {
        throw SwiftOutcomeError(code: "decoder_form_missing")
    }
    try SwiftOutcomeDecoderCrossCheck.check(descriptor, decoded: decoded)
    return descriptor
}

enum SwiftOutcomeDecoderCrossCheck {
    static func flow(for kind: String) -> InstructionFlow? {
        switch kind {
        case "bl": return .call
        case "b": return .jump
        case "bcond", "xcbz", "xcbnz", "wcbz", "wcbnz", "xtbz", "xtbnz", "wtbz", "wtbnz": return .conditionalJump
        case "ret": return .return
        case "brk": return .trap
        default: return nil
        }
    }
    static func check(_ descriptor: SwiftOutcomeInstruction, decoded: DecodedInstruction) throws {
        if let expectedFlow = flow(for: descriptor.kind) {
            let target: UInt64?
            if descriptor.kind == "ret" || descriptor.kind == "brk" { target = nil }
            else {
                let sum = Int128(descriptor.address).addingReportingOverflow(descriptor.immediate)
                guard !sum.overflow, sum.partialValue >= 0, sum.partialValue <= Int128(UInt64.max) else { throw SwiftOutcomeError(code: "decoder_form_mismatch") }
                target = UInt64(sum.partialValue)
            }
            guard decoded.flow == expectedFlow, decoded.branchTarget == target else { throw SwiftOutcomeError(code: "decoder_form_mismatch") }
        } else {
            guard let names = mnemonics(for: descriptor.kind) else { throw SwiftOutcomeError(code: "decoder_form_missing") }
            guard names.contains(decoded.mnemonic) else { throw SwiftOutcomeError(code: "decoder_form_mismatch") }
        }
    }
    static func mnemonics(for kind: String) -> Set<String>? {
        switch kind {
        case "nop": return ["nop"]
        case "adr", "adrp", "stp", "ldp", "smulh", "umulh": return [kind]
        case "mov", "wmov", "movz", "movn", "wmovz", "wmovn": return ["mov"]
        case "xmovk", "wmovk": return ["movk"]
        case "add": return ["add", "mov"]
        case "sub": return ["sub"]
        case "wadd", "xadd_reg", "wadd_reg", "xadd_ext": return ["add"]
        case "xsub_reg", "wsub_reg": return ["sub", "neg"]
        case "xsub_ext": return ["sub"]
        case "wadds", "xadds", "wadds_reg", "xadds_reg", "wadds_ext", "xadds_ext": return ["adds", "cmn"]
        case "wsubs", "xsubs", "wsubs_ext", "xsubs_ext": return ["subs", "cmp"]
        case "wsubs_reg", "xsubs_reg": return ["subs", "cmp", "negs"]
        case "xldr", "xldr_post", "wldr", "xldr_raw", "wldr_raw": return ["ldr"]
        case "xstr", "wstr", "xstr_raw", "wstr_raw": return ["str"]
        case "xldur", "wldur": return ["ldur"]
        case "xstur", "wstur": return ["stur"]
        case "wldrb": return ["ldrb", "ldurb"]
        case "wstrb": return ["strb", "sturb"]
        case "wldrh": return ["ldrh", "ldurh"]
        case "wstrh": return ["strh", "sturh"]
        case "smaddl": return ["smaddl", "smull"]
        case "smsubl": return ["smsubl", "smnegl"]
        case "umaddl": return ["umaddl", "umull"]
        case "umsubl": return ["umsubl", "umnegl"]
        default: break
        }
        guard kind.first == "w" || kind.first == "x" else { return nil }
        let suffix = String(kind.dropFirst())
        switch suffix {
        case "udiv", "sdiv", "rbit", "rev", "rev16", "rev32", "cls", "clz", "adc", "adcs", "csel": return [suffix]
        case "sbc": return ["sbc", "ngc"]
        case "sbcs": return ["sbcs", "ngcs"]
        case "ccmp_reg", "ccmp_imm": return ["ccmp"]
        case "ccmn_reg", "ccmn_imm": return ["ccmn"]
        case "and_reg", "and_imm": return ["and"]
        case "orr_reg": return ["orr"]
        case "orr_imm": return ["orr", "mov"]
        case "orn_reg": return ["orn", "mvn"]
        case "eor_reg", "eor_imm": return ["eor"]
        case "bic_reg": return ["bic"]
        case "eon_reg": return ["eon"]
        case "ands", "ands_imm": return ["ands", "tst"]
        case "bics": return ["bics"]
        case "madd": return ["madd", "mul"]
        case "msub": return ["msub", "mneg"]
        case "lslv", "lsl": return ["lsl"]
        case "lsrv": return ["lsr"]
        case "asrv": return ["asr"]
        case "rorv": return ["ror"]
        case "extr": return ["extr", "ror"]
        case "sbfm": return kind.first == "x" ? ["sxtb", "sxth", "sxtw", "asr", "sbfiz", "sbfx"] : ["sxtb", "sxth", "asr", "sbfiz", "sbfx"]
        case "ubfm": return kind.first == "x" ? ["lsr", "lsl", "ubfiz", "ubfx"] : ["uxtb", "uxth", "lsr", "lsl", "ubfiz", "ubfx"]
        case "bfm": return ["bfc", "bfi", "bfxil"]
        case "csinc": return ["csinc", "cset", "cinc"]
        case "csinv": return ["csinv", "csetm", "cinv"]
        case "csneg": return ["csneg", "cneg"]
        default: return nil
        }
    }
}

private struct SwiftOutcomeWordDecoder {
    let word: UInt32
    let address: UInt64
    var rd: Int { Int(word & 31) }
    var rn: Int { Int((word >> 5) & 31) }
    var rm: Int { Int((word >> 16) & 31) }
    var wide: Bool { word & 0x80000000 != 0 }
    var prefix: String { wide ? "x" : "w" }
    func signed(_ value: UInt32, _ bits: Int) -> Int128 {
        Int128(value) - (value & (UInt32(1) << (bits - 1)) == 0 ? 0 : Int128(1) << bits)
    }
    func make(_ kind: String, _ d: Int = 0, _ n: Int = 0, _ t: Int = 0, _ i: Int128 = 0, _ a: String = "") -> SwiftOutcomeInstruction {
        SwiftOutcomeInstruction(address: address, word: word, kind: kind, rd: d, rn: n, rt2: t, immediate: i, addressing: a)
    }
    func fail(_ code: String) -> SwiftOutcomeError { SwiftOutcomeError(code: code) }
    var extensionName: String { ["uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"][Int((word >> 13) & 7)] }
    func broad() throws -> SwiftOutcomeInstruction {
        if word & 0x1f000000 == 0x10000000 {
            let immediate = signed(((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3), 21)
            return make(wide ? "adrp" : "adr", rd, 0, 0, immediate * (wide ? 4096 : 1))
        }
        if word & 0xffe0001f == 0xd4200000 { return make("brk", 0, 0, 0, Int128((word >> 5) & 0xffff)) }
        let arithmetic: [UInt32: String] = [0x8b000000:"xadd_reg", 0xcb000000:"xsub_reg", 0x0b000000:"wadd_reg", 0x4b000000:"wsub_reg"]
        if let k = arithmetic[word & 0xffe0fc00] { return make(k, rd, rn, rm, 0, "lsl") }
        let ext = word & 0xffe00000
        if ext == 0x8b200000 || ext == 0xcb200000 {
            let shift = (word >> 10) & 7
            guard shift <= 4 else { throw fail("broad_extend_shift") }
            return make(ext == 0x8b200000 ? "xadd_ext" : "xsub_ext", rd, rn, rm, Int128(shift), extensionName)
        }
        let single = word & 0xffe00c00
        let writebacks: [UInt32: (String, String)] = [0xf8000400:("xstr","post"), 0xf8000c00:("xstr","pre"), 0xf8400400:("xldr_post","post"), 0xf8400c00:("xldr","pre")]
        if let (k,a) = writebacks[single] {
            guard rn == 31 || rn != rd else { throw fail("broad_memory_writeback_overlap") }
            return make(k, rd, rn, 0, signed((word >> 12) & 511, 9), a)
        }
        let memory: [UInt32: (String, Int)] = [0xb9000000:("wstr_raw",4), 0xb9400000:("wldr_raw",4), 0xbd000000:("sstr",4), 0xbd400000:("sldr",4), 0xfd000000:("dstr",8), 0xfd400000:("dldr",8)]
        if let (k,s) = memory[word & 0xffc00000], !(k == "wstr_raw" || k == "wldr_raw") || rn != 31 { return make(k, rd, rn, 0, Int128((word >> 10) & 4095) * Int128(s), "offset") }
        let unscaled: [UInt32: String] = [0xb8000000:"wstur",0xb8400000:"wldur",0xbc000000:"sstr",0xbc400000:"sldr",0xfc000000:"dstr",0xfc400000:"dldr"]
        if let k = unscaled[single] { return make(k, rd, rn, 0, signed((word >> 12) & 511, 9), "offset") }
        if word & 0xfff8fc00 == 0x0f006400 { return make("movi_2s_lsl24", rd, 0, 0, Int128(((word >> 16) & 7) << 5 | ((word >> 5) & 31))) }
        let raw: [UInt32: (String, Int)] = [0xf9000000:("xstr_raw",8),0xf9400000:("xldr_raw",8),0x3d800000:("qstr",16),0x3dc00000:("qldr",16)]
        if let (k,s) = raw[word & 0xffc00000], k.hasPrefix("q") || (rn != 29 && rn != 31) { return make(k, rd, rn, 0, Int128((word >> 10) & 4095) * Int128(s), "offset") }
        if single == 0xf8000000 || single == 0xf8400000 { return make(single == 0xf8000000 ? "xstur" : "xldur", rd, rn, 0, signed((word >> 12) & 511, 9), "offset") }
        var conversions: [UInt32: String] = [0x1e270000:"fmov_s_w",0x9e670000:"fmov_d_x",0x1e260000:"fmov_w_s",0x9e660000:"fmov_x_d",0x1e204000:"fmov_s_reg",0x1e604000:"fmov_d_reg"]
        for (fp,bits) in [("s",UInt32(0)),("d",UInt32(0x400000))] {
            for (gp,sf) in [("w",UInt32(0)),("x",UInt32(0x80000000))] {
                conversions[0x1e220000 | bits | sf] = "scvtf_\(fp)_\(gp)"
                conversions[0x1e380000 | bits | sf] = "fcvtzs_\(gp)_\(fp)"
            }
        }
        if let k = conversions[word & 0xfffffc00] { return make(k, rd, rn) }
        for (fp,bits) in [("s",UInt32(0)),("d",UInt32(0x400000))] {
            if word & 0xffe01fe0 == 0x1e201000 | bits { return make("fmov_\(fp)_imm", rd, 0, 0, Int128((word >> 13) & 255)) }
            if word & 0xffe0fc00 == 0x1e201800 | bits { return make("fdiv_\(fp)", rd, rn, rm) }
            if word & 0xffe0fc1f == 0x1e202000 | bits { return make("fcmp_\(fp)_reg", 0, rn, rm) }
            if word & 0xfffffc1f == 0x1e202008 | bits { return make("fcmp_\(fp)_zero", 0, rn) }
        }
        let narrow: [UInt32:(String,Int)] = [0x39000000:("wstrb",1),0x39400000:("wldrb",1),0x79000000:("wstrh",2),0x79400000:("wldrh",2)]
        if let (k,s) = narrow[word & 0xffc00000] { return make(k, rd, rn, 0, Int128((word >> 10) & 4095) * Int128(s), "offset") }
        let narrowUnscaled: [UInt32:String] = [0x38000000:"wstrb",0x38400000:"wldrb",0x78000000:"wstrh",0x78400000:"wldrh"]
        if let k = narrowUnscaled[single] { return make(k, rd, rn, 0, signed((word >> 12) & 511, 9), "offset") }
        return try historical()
    }
    func historical() throws -> SwiftOutcomeInstruction {
        if word & 0xffe00fe0 == 0xf84007e0 {
            var d = try SwiftOutcomeWordDecoder(word: 0xf9400000 | (word & 0x3ff), address: address).cfg()
            d.word = word; d.kind = "xldr_post"; d.immediate = signed((word >> 12) & 511, 9); d.addressing = "post"
            return d
        }
        if word & 0xffe0ffe0 == 0x2a0003e0 {
            var d = try cfg(); d.kind = "wmov"; d.rn = d.rt2; d.rt2 = 0; d.addressing = ""; return d
        }
        if [UInt32(0x52800000),0x12800000].contains(word & 0xff800000) {
            guard (word >> 21) & 3 < 2 else { throw fail("swift_wide_shift") }
            var d = try SwiftOutcomeWordDecoder(word: word | 0x80000000, address: address).cfg()
            d.word = word; d.kind = "w" + d.kind; return d
        }
        return try cfg()
    }
    func cfg() throws -> SwiftOutcomeInstruction {
        if word & 0x7f800000 == 0x72800000 {
            let shift = Int((word >> 21) & 3) * 16
            guard wide || shift < 32 else { throw fail("invalid_movk_shift") }
            return make(prefix + "movk", rd, 0, 0, Int128((word >> 5) & 65535), String(shift))
        }
        if word & 0x7fe0fc00 == 0x1ac00800 { return make(prefix + "udiv", rd, rn, rm) }
        if word & 0x7fe0fc00 == 0x1ac00c00 { return make(prefix + "sdiv", rd, rn, rm) }
        if word & 0x7ffffc00 == 0x5ac00400 { return make(prefix + "rev16", rd, rn) }
        if word & 0xfffffc00 == 0xdac00800 { return make("xrev32", rd, rn) }
        if [UInt32(0x5ac00800),0xdac00c00].contains(word & 0xfffffc00) { return make(prefix + "rev", rd, rn) }
        if word & 0x7ffffc00 == 0x5ac00000 { return make(prefix + "rbit", rd, rn) }
        if word & 0x7ffffc00 == 0x5ac01400 { return make(prefix + "cls", rd, rn) }
        if word & 0x7ffffc00 == 0x5ac01000 { return make(prefix + "clz", rd, rn) }
        var form = word & 0xffe00c10
        if [UInt32(0x3a400000),0x3a400800,0x7a400000,0x7a400800,0xba400000,0xba400800,0xfa400000,0xfa400800].contains(form) {
            let condition = (word >> 12) & 15
            guard condition < 14 else { throw fail("cfg_condition_not_modeled") }
            return make(prefix + (word & 0x40000000 != 0 ? "ccmp" : "ccmn") + (word & 0x800 != 0 ? "_imm" : "_reg"), 31, rn, rm, Int128(word & 15), String(condition))
        }
        form = word & 0xffe0fc00
        if [UInt32(0x1a000000),0x3a000000,0x5a000000,0x7a000000,0x9a000000,0xba000000,0xda000000,0xfa000000].contains(form) {
            return make(prefix + ["adc","adcs","sbc","sbcs"][Int((word >> 29) & 3)], rd, rn, rm)
        }
        form = word & 0xff800000
        let immediateForms: [UInt32:String] = [0x11000000:"wadd",0x31000000:"wadds",0x71000000:"wsubs",0xb1000000:"xadds",0xf1000000:"xsubs"]
        if let k = immediateForms[form] {
            guard rn != 31, !(form == 0x11000000 && rd == 31) else { throw fail("cfg_wsp_not_modeled") }
            return make(k, rd, rn, 0, Int128((word >> 10) & 4095) << (word & 0x400000 != 0 ? 12 : 0))
        }
        form = word & 0xff200000
        let shifted: [UInt32:String] = [0x2b000000:"wadds_reg",0x6b000000:"wsubs_reg",0xab000000:"xadds_reg",0xeb000000:"xsubs_reg"]
        if let k = shifted[form] {
            let shift = Int((word >> 22) & 3), amount = Int((word >> 10) & 63)
            guard shift != 3, wide || amount < 32 else { throw fail("cfg_shift_not_modeled") }
            return make(k, rd, rn, rm, Int128(amount), ["lsl","lsr","asr"][shift])
        }
        form = word & 0xffe00000
        let extended: [UInt32:String] = [0x2b200000:"wadds_ext",0x6b200000:"wsubs_ext",0xab200000:"xadds_ext",0xeb200000:"xsubs_ext"]
        if let k = extended[form] {
            let option = (word >> 13) & 7, amount = (word >> 10) & 7
            guard rn != 31 else { throw fail("cfg_extended_sp_not_modeled") }
            guard amount <= 4, wide || (option != 3 && option != 7) else { throw fail("cfg_extend_not_modeled") }
            return make(k, rd, rn, rm, Int128(amount), extensionName)
        }
        if word & 0xffe0ffe0 == 0xaa0003e0 { return try base() }
        form = word & 0xff000000
        if [UInt32(0x0a000000),0x2a000000,0x4a000000,0x8a000000,0xaa000000,0xca000000].contains(form) {
            let amount = Int((word >> 10) & 63)
            guard wide || amount < 32 else { throw fail("cfg_logical_shift_not_modeled") }
            let operation = [["and","bic"],["orr","orn"],["eor","eon"]][Int((word >> 29) & 3)][word & 0x200000 != 0 ? 1 : 0]
            return make(prefix + operation + "_reg", rd, rn, rm, Int128(amount), ["lsl","lsr","asr","ror"][Int((word >> 22) & 3)])
        }
        if form == 0x6a000000 || form == 0xea000000 {
            let amount = Int((word >> 10) & 63)
            guard wide || amount < 32 else { throw fail("cfg_logical_shift_not_modeled") }
            return make(prefix + (word & 0x200000 != 0 ? "bics" : "ands"), rd, rn, rm, Int128(amount), ["lsl","lsr","asr","ror"][Int((word >> 22) & 3)])
        }
        form = word & 0xff800000
        if [UInt32(0x12000000),0x32000000,0x52000000,0x72000000,0x92000000,0xb2000000,0xd2000000,0xf2000000].contains(form) {
            let width = wide ? 64 : 32, n = Int((word >> 22) & 1), imms = Int((word >> 10) & 63), immr = Int((word >> 16) & 63)
            let control = (n << 6) | (~imms & 63)
            let length = control == 0 ? -1 : Int.bitWidth - control.leadingZeroBitCount - 1
            guard (wide || n == 0), length >= 1 else { throw fail("invalid_logical_immediate") }
            let size = 1 << length, levels = (1 << length) - 1
            let s = imms & levels, r = immr & levels
            guard size <= width, s != levels else { throw fail("invalid_logical_immediate") }
            var element = (Int128(1) << (s + 1)) - 1
            element = ((element >> r) | (element << (size - r))) & ((Int128(1) << size) - 1)
            var mask: Int128 = 0
            for offset in stride(from: 0, to: width, by: size) { mask |= element << offset }
            let operation = ["and","orr","eor","ands"][Int((word >> 29) & 3)]
            guard operation == "ands" || rd != 31 else { throw fail("cfg_logical_sp_destination_not_modeled") }
            return make(prefix + operation + "_imm", rd, rn, 0, mask)
        }
        form = word & 0xffe0fc00
        if form == 0x9b407c00 || form == 0x9bc07c00 { return make(word & 0x800000 != 0 ? "umulh" : "smulh", rd, rn, rm) }
        form = word & 0xffe08000
        if [UInt32(0x9b200000),0x9b208000,0x9ba00000,0x9ba08000].contains(form) {
            return make((word & 0x800000 != 0 ? "u" : "s") + (word & 0x8000 != 0 ? "msubl" : "maddl"), rd, rn, rm, Int128((word >> 10) & 31))
        }
        if [UInt32(0x1b000000),0x1b008000,0x9b000000,0x9b008000].contains(form) { return make(prefix + (word & 0x8000 != 0 ? "msub" : "madd"), rd, rn, rm, Int128((word >> 10) & 31)) }
        form = word & 0xffe0fc00
        if [UInt32(0x1ac02000),0x1ac02400,0x1ac02800,0x1ac02c00,0x9ac02000,0x9ac02400,0x9ac02800,0x9ac02c00].contains(form) {
            return make(prefix + ["lslv","lsrv","asrv","rorv"][Int((word >> 10) & 3)], rd, rn, rm)
        }
        if word & 0x1f800000 == 0x13800000 {
            form = word & 0xffe00000
            let amount = Int((word >> 10) & 63)
            guard (form == 0x13800000 || form == 0x93c00000), wide || amount < 32 else { throw fail("invalid_extract_encoding") }
            return make(prefix + "extr", rd, rn, rm, Int128(amount))
        }
        if word & 0x1f800000 == 0x13000000 {
            form = word & 0xffc00000
            guard [UInt32(0x13000000),0x33000000,0x53000000,0x93400000,0xb3400000,0xd3400000].contains(form) else { throw fail("invalid_bitfield_encoding") }
            let immr = Int((word >> 16) & 63), imms = Int((word >> 10) & 63)
            guard wide || (immr < 32 && imms < 32) else { throw fail("invalid_bitfield_encoding") }
            if form == 0x53000000, immr > 0, immr < 32, imms + 1 == immr { return make("wlsl", rd, rn, 0, Int128(32 - immr)) }
            return make(prefix + ["sbfm","bfm","ubfm"][Int((word >> 29) & 3)], rd, rn, 0, Int128(imms), String(immr))
        }
        form = word & 0xffc00000
        if form == 0xf9000000 || form == 0xf9400000 {
            guard rn == 29 || rn == 31 else { throw fail("cfg_memory_base_not_modeled") }
            return make(form == 0xf9000000 ? "xstr" : "xldr", rd, rn, 0, Int128((word >> 10) & 4095) * 8)
        }
        if form == 0xb9000000 || form == 0xb9400000 {
            guard rn == 31 else { throw fail("cfg_memory_base_not_modeled") }
            return make(form == 0xb9000000 ? "wstr" : "wldr", rd, 31, 0, Int128((word >> 10) & 4095) * 4)
        }
        form = word & 0xffe00c00
        if [UInt32(0x1a800000),0x1a800400,0x5a800000,0x5a800400,0x9a800000,0x9a800400,0xda800000,0xda800400].contains(form) {
            let condition = (word >> 12) & 15
            guard condition < 14 else { throw fail("cfg_condition_not_modeled") }
            let operation = ["csel","csinc","csinv","csneg"][Int(((word >> 30) & 1) * 2 + ((word >> 10) & 1))]
            return make(prefix + operation, rd, rn, rm, 0, String(condition))
        }
        if word & 0x7e000000 == 0x36000000 {
            let bit = ((word >> 19) & 31) | ((word >> 26) & 32)
            return make((bit >= 32 ? "x" : "w") + (word & 0x1000000 != 0 ? "tbnz" : "tbz"), 0, rd, 0, signed((word >> 5) & 0x3fff, 14) * 4, String(bit))
        }
        if word & 0x7e000000 == 0x34000000 { return make(prefix + (word & 0x1000000 != 0 ? "cbnz" : "cbz"), 0, rd, 0, signed((word >> 5) & 0x7ffff, 19) * 4) }
        if word & 0xfc000000 == 0x14000000 { return make("b", 0, 0, 0, signed(word & 0x3ffffff, 26) * 4) }
        if word & 0xff000010 == 0x54000000 {
            guard word & 15 < 14 else { throw fail("cfg_condition_not_modeled") }
            return make("bcond", 0, 0, 0, signed((word >> 5) & 0x7ffff, 19) * 4, String(word & 15))
        }
        return try base()
    }
    func base() throws -> SwiftOutcomeInstruction {
        if word == 0xd503201f { return make("nop") }
        if word == 0xd65f03c0 { return make("ret", 0, 30) }
        if [UInt32(0xd503233f),0xd503237f,0xd50323bf,0xd50323ff,0xd50320ff,0xd65f0bff,0xd65f0fff].contains(word) { throw fail("unsupported_pauth") }
        if word & 0xfc000000 == 0x94000000 { return make("bl", 0, 0, 0, signed(word & 0x3ffffff, 26) * 4) }
        let pairs: [UInt32:(String,String)] = [0xa9000000:("stp","offset"),0xa9800000:("stp","pre"),0xa8800000:("stp","post"),0xa9400000:("ldp","offset"),0xa9c00000:("ldp","pre"),0xa8c00000:("ldp","post")]
        if let (k,a) = pairs[word & 0xffc00000] {
            let t = Int((word >> 10) & 31)
            guard rn == 29 || rn == 31 else { throw fail("unsupported_memory_base") }
            guard k != "ldp" || rd != t else { throw fail("ambiguous_pair_registers") }
            guard a == "offset" || rn == 31 || (rn != rd && rn != t) else { throw fail("ambiguous_writeback") }
            return make(k, rd, rn, t, signed((word >> 15) & 127, 7) * 8, a)
        }
        let form = word & 0xff800000
        if form == 0x91000000 || form == 0xd1000000 { return make(form == 0x91000000 ? "add" : "sub", rd, rn, 0, Int128((word >> 10) & 4095) << (word & 0x400000 != 0 ? 12 : 0)) }
        if word & 0xffe0ffe0 == 0xaa0003e0 { return make("mov", rd, rm) }
        if form == 0xd2800000 || form == 0x92800000 { return make(form == 0xd2800000 ? "movz" : "movn", rd, 0, 0, Int128((word >> 5) & 65535) << (Int((word >> 21) & 3) * 16)) }
        if word & 0x7c000000 == 0x14000000 || word & 0xfe000000 == 0xd6000000 || word & 0xff000010 == 0x54000000 || [UInt32(0x34000000),0x36000000].contains(word & 0x7e000000) { throw fail("unsupported_control_flow") }
        throw fail("unsupported_instruction")
    }
}
