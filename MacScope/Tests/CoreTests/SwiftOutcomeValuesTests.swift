import XCTest
#if canImport(MacScope)
@testable import MacScope

final class SwiftOutcomeValuesTests: XCTestCase {
    private let seed: SwiftAbstractValue = .registerCopy(origin: "seed", width: 64)
    private func instruction(_ kind: String, rd: Int = 0, rn: Int = 0, rt2: Int = 0, immediate: Int128 = 0, addressing: String = "") -> SwiftOutcomeInstruction {
        SwiftOutcomeInstruction(address: 0, word: 0, kind: kind, rd: rd, rn: rn, rt2: rt2, immediate: immediate, addressing: addressing)
    }
    private func code(_ expected: String, _ body: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { XCTAssertEqual($0 as? SwiftOutcomeError, SwiftOutcomeError(code: expected), file: file, line: line) }
    }
    func testVA01DomainFactories() throws {
        code("literal_width") { _ = try SwiftAbstractValue.makeLiteral(value: 1 << 32, width: 32) }
        code("literal_width") { _ = try SwiftAbstractValue.makeLiteral(value: 5, width: 16) }
        XCTAssertEqual(try SwiftAbstractValue.makeLiteral(value: 0xffffffff, width: 32), SwiftAbstractValue.literal(value: 0xffffffff, width: 32))
        code("register_copy_domain") { _ = try SwiftAbstractValue.makeRegisterCopy(origin: "x", width: 8) }
        code("stack_slot_domain") { _ = try SwiftAbstractValue.makeStackSlot(slot: 0, epoch: -1, width: 64) }
        code("derived_domain") { _ = try SwiftAbstractValue.makeDerived(operation: "add", inputs: [], width: 16, knownBits: nil) }
    }
    func testVA02InitialState() throws {
        let state = try initialState([21: seed])
        let expected: ValueState = ValueState(registers: [SwiftRegisterValue(register: 21, value: seed)], registerEpochs: [], stack: [], spOffset: 0, stackEpoch: 0, steps: 0, refusal: nil)
        XCTAssertEqual(state, expected)
        XCTAssertEqual(try initialState([:], limits: ValueLimits(maxStateEntries: 0)), ValueState())
        code("state_entry_limit") { _ = try initialState([21: seed], limits: ValueLimits(maxStateEntries: 0)) }
    }
    func testVA03RegisterCopy() throws {
        let result = transferSwiftValue(try initialState([21: seed]), instruction("mov", rd: 19, rn: 21))
        XCTAssertEqual(result.status, String("resolved")); XCTAssertNil(result.reason)
        let expected: [SwiftRegisterValue] = [.init(register: 19, value: seed), .init(register: 21, value: seed)]
        XCTAssertEqual(result.state.registers, expected)
        XCTAssertEqual(result.state.registerEpochs, [SwiftRegisterEpoch(register: 19, epoch: 1)])
        XCTAssertEqual(result.state.steps, Int(1))
    }
    func testVA04MoveWide() throws {
        let cases: [(String, Int128, UInt64)] = [("wmovz", 0x1234, 0x1234), ("wmovn", 0, 0xffffffff), ("movn", 0, 0xffffffffffffffff)]
        for (kind, immediate, expected) in cases {
            let value = transferSwiftValue(try initialState(), instruction(kind, immediate: immediate))
            XCTAssertEqual(value.state.registers, [SwiftRegisterValue(register: 0, value: .literal(value: expected, width: 64))])
            XCTAssertEqual(value.state.registerEpochs, [SwiftRegisterEpoch(register: 0, epoch: 1)])
        }
    }
    func testVA05RefusalPreservesState() throws {
        let input = try initialState(), result = transferSwiftValue(try initialState(), instruction("movz", immediate: 0x12345))
        XCTAssertEqual(result.status, String("unresolved")); XCTAssertEqual(result.reason, String("move_immediate_unqualified")); XCTAssertEqual(result.state, input)
    }
    func testVA06MoveKeepLanes() throws {
        let input = try initialState([0: .literal(value: 0x1111, width: 64)])
        let value = transferSwiftValue(input, instruction("xmovk", immediate: 0x2222, addressing: "16"))
        XCTAssertEqual(value.state.registers, [SwiftRegisterValue(register: 0, value: .literal(value: 0x22221111, width: 64))])
        for shift in ["8", "x"] { XCTAssertEqual(transferSwiftValue(input, instruction("xmovk", immediate: 0x2222, addressing: shift)).reason, String("move_lane_unqualified")) }
        XCTAssertEqual(transferSwiftValue(input, instruction("xmovk", immediate: 0x10000, addressing: "16")).reason, String("move_immediate_unqualified"))
        XCTAssertEqual(transferSwiftValue(input, instruction("wmovk", immediate: 0x2222, addressing: "32")).reason, String("move_lane_unqualified"))
    }
    func testVA07RefusalsAndNOP() throws {
        let input = try initialState()
        XCTAssertEqual(transferSwiftValue(input, instruction("frobnicate")).reason, String("instruction_effect_unqualified"))
        XCTAssertEqual(transferSwiftValue(input, instruction("brk")).reason, String("exception_transfer_effect_unqualified"))
        XCTAssertEqual(transferSwiftValue(input, instruction("nop"), limits: ValueLimits(maxSteps: 0)).reason, String("value_step_limit"))
        let nop = transferSwiftValue(input, instruction("nop"))
        XCTAssertEqual(nop.status, String("resolved")); XCTAssertEqual(nop.state.steps, Int(1)); XCTAssertEqual(nop.state.registers, [SwiftRegisterValue]())
    }
    func testVA08CallClobbers() throws {
        let a: SwiftAbstractValue = .registerCopy(origin: "a", width: 64), b: SwiftAbstractValue = .registerCopy(origin: "b", width: 64)
        let value = transferSwiftValue(try initialState([19: a, 20: b]), instruction("bl"))
        XCTAssertEqual(value.status, String("resolved")); XCTAssertEqual(value.state.registers.count, Int(22))
        for register in Array(0...18) + [30] { XCTAssertEqual(value.state.readRegister(register), SwiftAbstractValue.unknown) }
        XCTAssertEqual(value.state.readRegister(19), a); XCTAssertEqual(value.state.readRegister(20), b)
        let expected: [SwiftRegisterEpoch] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 30].map { SwiftRegisterEpoch(register: $0, epoch: 1) }
        XCTAssertEqual(value.state.registerEpochs, expected); XCTAssertEqual(value.state.stackEpoch, Int(1)); XCTAssertEqual(value.state.steps, Int(1))
    }
    func testVA09StackRoundTrip() throws {
        let first = transferSwiftValue(try initialState([0: seed]), instruction("sub", rd: 31, rn: 31, immediate: 16))
        XCTAssertEqual(first.state.spOffset, Int(-16))
        let second = transferSwiftValue(first.state, instruction("xstr", rn: 31, immediate: 8, addressing: "offset"))
        let final = transferSwiftValue(second.state, instruction("xldr", rd: 1, rn: 31, immediate: 8, addressing: "offset"))
        let expected: ValueState = ValueState(registers: [.init(register: 0, value: seed), .init(register: 1, value: seed)], registerEpochs: [.init(register: 1, epoch: 1)], stack: [.init(slot: -8, epoch: 1, width: 64, value: seed)], spOffset: -16, stackEpoch: 1, steps: 3, refusal: nil)
        XCTAssertEqual(final.state, expected)
    }
    func testVA10UnqualifiedStack() throws {
        let input = try initialState(), ins = instruction("xstr", rn: 31, addressing: "offset")
        XCTAssertEqual(transferSwiftValue(input, ins).reason, String("memory_outside_frame"))
        var unknown = input; unknown.spOffset = nil
        XCTAssertEqual(transferSwiftValue(unknown, ins).reason, String("stack_base_unqualified"))
    }
    func testVA11ModularArithmetic() throws {
        let input = try initialState([0: .literal(value: 5, width: 64)])
        let sum = transferSwiftValue(input, instruction("add", rd: 1, immediate: 3))
        let expected: [SwiftRegisterValue] = [.init(register: 0, value: .literal(value: 5, width: 64)), .init(register: 1, value: .literal(value: 8, width: 64))]
        XCTAssertEqual(sum.state.registers, expected)
        XCTAssertEqual(transferSwiftValue(input, instruction("sub", rd: 1, immediate: 6)).state.readRegister(1), SwiftAbstractValue.literal(value: 0xffffffffffffffff, width: 64))
    }
    func testValueReadWidthAndZeroRegister() throws {
        let state = try initialState([0: .literal(value: 0x123456789, width: 64)])
        XCTAssertEqual(state.readRegister(31, width: 32), SwiftAbstractValue.literal(value: 0, width: 32))
        XCTAssertEqual(state.readRegister(0, width: 32), SwiftAbstractValue.literal(value: 0x23456789, width: 32))
        XCTAssertEqual(state.readRegister(1), SwiftAbstractValue.unknown)
    }
    func testValueFabricatedOverflowRefusesWithoutChangingInput() throws {
        var input = try initialState(); input.stackEpoch = Int.max
        let call = transferSwiftValue(input, instruction("bl"))
        XCTAssertEqual(call.reason, String("value_state_limit")); XCTAssertEqual(call.state, input)
        let frame = try initialState()
        let offset = transferSwiftValue(frame, instruction("sub", rd: 31, rn: 31, immediate: Int128.min))
        XCTAssertEqual(offset.reason, String("stack_base_unqualified")); XCTAssertEqual(offset.state, frame)
        let literal = transferSwiftValue(try initialState([0: .literal(value: 5, width: 64)]), instruction("sub", rd: 1, immediate: Int128.min))
        XCTAssertEqual(literal.state.readRegister(1), SwiftAbstractValue.literal(value: 5, width: 64))
    }

    private func tpState(_ words: [UInt32], seed: [Int: SwiftAbstractValue] = [:]) throws -> ValueState {
        var state = try initialState(seed)
        for word in words {
            let instruction = try decodeSwiftOutcomeInstruction(word: word, address: 0x1000)
            let step = transferSwiftValue(state, instruction)
            XCTAssertEqual(step.status, String("resolved"))
            state = step.state
        }
        return state
    }
    private func tpZ(_ value: UInt32, _ shift: UInt32 = 0, _ rd: UInt32 = 0) -> UInt32 {
        0xd2800000 | ((shift / 16) << 21) | (value << 5) | rd
    }
    private func tpK(_ value: UInt32, _ shift: UInt32 = 0, _ rd: UInt32 = 0) -> UInt32 {
        0xf2800000 | ((shift / 16) << 21) | (value << 5) | rd
    }
    private func tpW(_ destination: UInt32, _ source: UInt32) -> UInt32 { 0x2a0003e0 | (source << 16) | destination }
    func testTP2PortableMOVKComponents() throws {
        XCTAssertEqual(try tpState([tpZ(0x1234), tpK(0x5678,16), tpK(0x9abc,32), tpK(0xdef0,48)]).readRegister(0), .literal(value: 0xdef09abc56781234, width: 64))
        XCTAssertEqual(try tpState([0x92800000,tpK(0,16),tpK(0x1234,16)]).readRegister(0), .literal(value: 0xffffffff1234ffff, width: 64))
        let bare = try tpState([tpK(1)])
        XCTAssertEqual(bare.readRegister(0), .derived(operation: "insert_lane", inputs: [.unknown,.literal(value: 1,width: 64),.literal(value: 0,width: 64)], width: 64, knownBits: nil))
        let first: SwiftAbstractValue = .derived(operation: "insert_lane", inputs: [.unknown,.literal(value: 1,width: 64),.literal(value: 0,width: 64)], width: 64, knownBits: nil)
        let second: SwiftAbstractValue = .derived(operation: "insert_lane", inputs: [first,.literal(value: 2,width: 64),.literal(value: 16,width: 64)], width: 64, knownBits: nil)
        let third: SwiftAbstractValue = .derived(operation: "insert_lane", inputs: [second,.literal(value: 3,width: 64),.literal(value: 32,width: 64)], width: 64, knownBits: nil)
        let fourth: SwiftAbstractValue = .derived(operation: "insert_lane", inputs: [third,.literal(value: 4,width: 64),.literal(value: 48,width: 64)], width: 64, knownBits: nil)
        XCTAssertEqual(try tpState([tpK(1),tpK(2,16),tpK(3,32),tpK(4,48)]).readRegister(0), fourth)
        let overwrite = try tpState([tpZ(1),0xaa1303e0,tpK(2,16)])
        XCTAssertEqual(overwrite.readRegister(0), .derived(operation: "insert_lane", inputs: [.unknown,.literal(value: 2,width: 64),.literal(value: 16,width: 64)], width: 64, knownBits: nil))
        let seed: SwiftAbstractValue = .registerCopy(origin: "call-result", width: 64)
        let altered = try tpState([0xaa0003f3,tpK(1,0,19),0xaa1303e0], seed: [0:seed])
        XCTAssertEqual(altered.readRegister(0), .derived(operation: "insert_lane", inputs: [seed,.literal(value: 1,width: 64),.literal(value: 0,width: 64)], width: 64, knownBits: nil))
        XCTAssertEqual(try tpState([tpK(1,0,19)],seed:[0:seed]).readRegister(0), seed)
        XCTAssertEqual(try tpState([tpZ(42),tpK(0xffff,48,31)]).readRegister(0), .literal(value:42,width:64))
        XCTAssertEqual(try tpState([0x94000100,tpZ(0x1234),tpK(0xabcd,48)]).readRegister(0), .literal(value:0xabcd000000001234,width:64))
        XCTAssertEqual(try tpState([tpZ(1),0x94000100,tpK(2,16)]).readRegister(0), .derived(operation:"insert_lane",inputs:[.unknown,.literal(value:2,width:64),.literal(value:16,width:64)],width:64,knownBits:nil))
        XCTAssertEqual(try tpState([tpZ(0x1234),tpK(0x5678,16)]).readRegister(0), .literal(value:0x56781234,width:64))
        XCTAssertEqual(try tpState([0x92800000,tpK(0xabcd,48)]).readRegister(0), .literal(value:0xabcdffffffffffff,width:64))
        // The donor's arm/tail recovery limits are not value-domain limits.
        let chain: [UInt32] = [tpZ(1)] + Array(repeating:tpK(2,16),count:7)
        XCTAssertEqual(try tpState(chain).readRegister(0), .literal(value:0x20001,width:64))
        XCTAssertEqual(try tpState(chain+[tpK(3,32)]).readRegister(0), .literal(value:0x300020001,width:64))
    }
    func testTP3PortableWCopyComponents() throws {
        XCTAssertEqual(try tpState([0x52a24693,tpW(0,19)]).readRegister(0), .literal(value:0x12340000,width:64))
        XCTAssertEqual(try tpState([0x92800013,tpW(0,19)]).readRegister(0), .literal(value:0xffffffff,width:64))
        XCTAssertEqual(try tpState([0x92800013,0xaa1303e0]).readRegister(0), .literal(value:0xffffffffffffffff,width:64))
        XCTAssertEqual(try tpState([0x52800553,tpW(20,19),tpW(0,20),tpW(0,0)]).readRegister(0), .literal(value:42,width:64))
        XCTAssertEqual(try tpState([0x52800020,tpW(0,19)]).readRegister(0), .unknown)
        let seed: SwiftAbstractValue = .registerCopy(origin:"call-result",width:64)
        let projection: SwiftAbstractValue = .derived(operation:"zero_extend",inputs:[.derived(operation:"truncate",inputs:[seed],width:32,knownBits:nil)],width:64,knownBits:nil)
        XCTAssertEqual(try tpState([tpW(0,0)],seed:[0:seed]).readRegister(0), projection)
        XCTAssertEqual(try tpState([0xaa0003f3,tpW(0,19)],seed:[0:seed]).readRegister(0), projection)
        XCTAssertEqual(try tpState([tpW(19,0)],seed:[0:seed]).readRegister(0), seed)
        XCTAssertEqual(try tpState([0x52800033,tpW(31,19),tpW(0,31)]).readRegister(0), .literal(value:0,width:64))
        XCTAssertEqual(try tpState([0x94000100,0x52800553,tpW(0,19)]).readRegister(0), .literal(value:42,width:64))
        // Broad value transfer retains callee-saved x19, unlike the legacy error-arm recovery.
        XCTAssertEqual(try tpState([0x52800553,0x94000100,tpW(0,19)]).readRegister(0), .literal(value:42,width:64))
        XCTAssertEqual(try tpState([0x12800013,tpW(0,19)]).readRegister(0), .literal(value:0xffffffff,width:64))
        let chain: [UInt32] = [0x52800033] + Array(repeating:tpW(0,19),count:7)
        XCTAssertEqual(try tpState(chain+[tpW(0,0)]).readRegister(0), .literal(value:1,width:64))
    }
    func testTP1TP5TP6TP7TP8PortableLiteralComponents() throws {
        XCTAssertEqual(try tpState([0x12800000]).readRegister(0), .literal(value:0xffffffff,width:64))
        XCTAssertEqual(try tpState([0x92800000]).readRegister(0), .literal(value:0xffffffffffffffff,width:64))
        XCTAssertEqual(try tpState([0xd2800000]).readRegister(0), .literal(value:0,width:64))
        XCTAssertEqual(try tpState([0x528acf00,0x72a24680]).readRegister(0), .literal(value:0x12345678,width:64))
        XCTAssertEqual(try tpState([0x5299bde0,0x72b13560]).readRegister(0), .literal(value:0x89abcdef,width:64))
        // Partial insertion without the donor's error seed retains unknown provenance, not a literal.
        let partial = try tpState([0xd503201f,0x72a24680]).readRegister(0)
        XCTAssertEqual(partial, .derived(operation:"zero_extend",inputs:[.derived(operation:"insert_lane",inputs:[.unknown,.literal(value:0x1234,width:32),.literal(value:16,width:32)],width:32,knownBits:nil)],width:64,knownBits:nil))
    }
    func testTP1PortableAliasComponents() throws {
        let seed: SwiftAbstractValue = .registerCopy(origin:"error",width:64)
        XCTAssertEqual(try tpState([0xaa1503f3],seed:[21:seed]).readRegister(19),seed)
        XCTAssertEqual(try tpState([0xaa1503e0],seed:[21:seed]).readRegister(0),seed)
        let result: SwiftAbstractValue = .registerCopy(origin:"result",width:64)
        XCTAssertEqual(try tpState([0xaa0003f3,0xaa1f03e0,0xaa1303e0],seed:[0:result]).readRegister(0),result)
        XCTAssertEqual(try tpState([0x92800000,0x9400000c,0xd503201f]).readRegister(0),.unknown)
    }
    func testTP7PortableImmediateArithmetic() throws {
        let cases: [(UInt32,UInt64,UInt64)] = [(5,5,5),(0x1001,4096,4096),(0x1fff,16773120,16773120)]
        for (encoded, effective, _) in cases {
            let shift: UInt32 = encoded > 0xfff ? 1 << 22 : 0
            let imm: UInt32 = encoded & 0xfff
            let add: UInt32 = 0x91000000 | shift | (imm << 10)
            let sub: UInt32 = 0xd1000000 | shift | (imm << 10)
            XCTAssertEqual(try decodeSwiftOutcomeInstruction(word:add).immediate,Int128(effective))
            XCTAssertEqual(try decodeSwiftOutcomeInstruction(word:sub).immediate,Int128(effective))
            XCTAssertEqual(try tpState([add],seed:[0:.literal(value:0,width:64)]).readRegister(0),.literal(value:effective,width:64))
        }
        let seed: SwiftAbstractValue = .registerCopy(origin:"result",width:64)
        XCTAssertEqual(try tpState([0xaa0003f3,0xaa1f03e0,0x91400674,0xaa1403e0],seed:[0:seed]).readRegister(0),.derived(operation:"add",inputs:[seed,.literal(value:4096,width:64)],width:64,knownBits:nil))
        XCTAssertEqual(try tpState([0xaa0003f3,0xaa1f03e0,0xd1400674,0xaa1403e0],seed:[0:seed]).readRegister(0),.derived(operation:"sub",inputs:[seed,.literal(value:4096,width:64)],width:64,knownBits:nil))
    }

}
#endif
