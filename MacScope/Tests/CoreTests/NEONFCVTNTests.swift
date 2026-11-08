import XCTest
@testable import MacScope

// Source-only definitions. Arm FCVTN/FCVTN2 Operation: FPConvert with
// FPCR(), low64 zero-high or high64 preserve-low placement, normal completion.
final class NEONFCVTNTests: XCTestCase {
    private func row(_ bytes: String, _ mnemonic: String, _ operands: String,
                     address: UInt64 = 0x1000) -> MacIRSourceSpan {
        MacIRSourceSpan(address: address, byteText: bytes, mnemonic: mnemonic, operands: operands)
    }

    private func descriptor(_ source: MacIRSourceSpan, word: UInt32, input: Int,
                            output: Int, lanes: Int, high: Bool, destination: String,
                            sources: [String], name: String, controls: [MacIRVectorFP.ControlField],
                            file: StaticString = #filePath, line: UInt = #line) throws {
        let fp = try XCTUnwrap(MacIRVectorFP(source: source), file: file, line: line)
        XCTAssertEqual(fp.encodedWord, word, file: file, line: line)
        XCTAssertEqual(fp.operation, .narrow, file: file, line: line)
        XCTAssertEqual(fp.inputDomain, .ieeeBinary, file: file, line: line)
        XCTAssertEqual(fp.inputBits, input, file: file, line: line)
        XCTAssertEqual(fp.resultBits, output, file: file, line: line)
        XCTAssertEqual(fp.laneCount, lanes, file: file, line: line)
        XCTAssertEqual(fp.highHalf, high, file: file, line: line)
        XCTAssertEqual(fp.destination, destination, file: file, line: line)
        XCTAssertEqual(fp.sources, sources, file: file, line: line)
        XCTAssertNil(fp.selectedElement, file: file, line: line)
        XCTAssertNil(fp.fusedAddendArgumentIndex, file: file, line: line)
        XCTAssertEqual(fp.resultPlacement, high ? .preserveLow64 : .zeroHigh64, file: file, line: line)
        XCTAssertEqual(fp.resultBitOffset, high ? 64 : 0, file: file, line: line)
        XCTAssertEqual(fp.readsDestination, high, file: file, line: line)
        XCTAssertEqual(fp.intrinsicName, name, file: file, line: line)
        XCTAssertEqual(fp.armPseudocode, "FPConvert", file: file, line: line)
        XCTAssertEqual(fp.completion, .normalOnlyMayTrap, file: file, line: line)
        XCTAssertEqual(fp.rounding, .fpcr, file: file, line: line)
        XCTAssertTrue(fp.usesFPCRRounding, file: file, line: line)
        XCTAssertEqual(fp.exceptionMask, 0x9f, file: file, line: line)
        XCTAssertEqual(fp.exceptionEnableMask, 0x9f00, file: file, line: line)
        XCTAssertEqual(fp.controlFields, controls, file: file, line: line)
    }

    func testL01L02L06HalfDescriptorsAndControls() throws {
        try descriptor(row("20 68 21 0e", "fcvtn", "v0.4h, v1.4s"),
            word: 0x0e216820, input: 32, output: 16, lanes: 4, high: false,
            destination: "v0", sources: ["v1"], name: "a64_vector_fp_narrow_32_16_4_low",
            controls: [.flushToZero, .alternateHandling, .exceptionEnables,
                .rounding, .flushInputsToZero, .defaultNaN, .alternateHalfPrecision])
        try descriptor(row("20 68 21 4e", "fcvtn2", "v0.8h, v1.4s"),
            word: 0x4e216820, input: 32, output: 16, lanes: 4, high: true,
            destination: "v0", sources: ["v1"], name: "a64_vector_fp_narrow_32_16_4_high",
            controls: [.flushToZero, .alternateHandling, .exceptionEnables,
                .rounding, .flushInputsToZero, .defaultNaN, .alternateHalfPrecision])
    }

    func testL03AllRetainedDoubleDescriptorsUnchanged() throws {
        try descriptor(row("21 68 61 0e", "fcvtn", "v1.2s, v1.2d"),
            word: 0x0e616821, input: 64, output: 32, lanes: 2, high: false,
            destination: "v1", sources: ["v1"], name: "a64_vector_fp_narrow_64_32_2_low",
            controls: [.flushToZero, .alternateHandling, .exceptionEnables,
                .rounding, .flushInputsToZero, .defaultNaN])
        try descriptor(row("42 68 61 0e", "fcvtn", "v2.2s, v2.2d"),
            word: 0x0e616842, input: 64, output: 32, lanes: 2, high: false,
            destination: "v2", sources: ["v2"], name: "a64_vector_fp_narrow_64_32_2_low",
            controls: [.flushToZero, .alternateHandling, .exceptionEnables,
                .rounding, .flushInputsToZero, .defaultNaN])
        try descriptor(row("61 68 61 4e", "fcvtn2", "v1.4s, v3.2d"),
            word: 0x4e616861, input: 64, output: 32, lanes: 2, high: true,
            destination: "v1", sources: ["v3"], name: "a64_vector_fp_narrow_64_32_2_high",
            controls: [.flushToZero, .alternateHandling, .exceptionEnables,
                .rounding, .flushInputsToZero, .defaultNaN])
        try descriptor(row("02 68 61 4e", "fcvtn2", "v2.4s, v0.2d"),
            word: 0x4e616802, input: 64, output: 32, lanes: 2, high: true,
            destination: "v2", sources: ["v0"], name: "a64_vector_fp_narrow_64_32_2_high",
            controls: [.flushToZero, .alternateHandling, .exceptionEnables,
                .rounding, .flushInputsToZero, .defaultNaN])
    }

    func testL04L05AliasedHalfDescriptors() throws {
        try descriptor(row("a5 68 21 0e", "fcvtn", "v5.4h, v5.4s"),
            word: 0x0e2168a5, input: 32, output: 16, lanes: 4, high: false,
            destination: "v5", sources: ["v5"], name: "a64_vector_fp_narrow_32_16_4_low",
            controls: [.flushToZero, .alternateHandling, .exceptionEnables,
                .rounding, .flushInputsToZero, .defaultNaN, .alternateHalfPrecision])
        try descriptor(row("a5 68 21 4e", "fcvtn2", "v5.8h, v5.4s"),
            word: 0x4e2168a5, input: 32, output: 16, lanes: 4, high: true,
            destination: "v5", sources: ["v5"], name: "a64_vector_fp_narrow_32_16_4_high",
            controls: [.flushToZero, .alternateHandling, .exceptionEnables,
                .rounding, .flushInputsToZero, .defaultNaN, .alternateHalfPrecision])
    }

    private func effects(_ source: MacIRSourceSpan, reads: Set<Int>, writes: Set<Int>,
                         file: StaticString = #filePath, line: UInt = #line) {
        let effect = MacIRBuilder.ssaEffects(for: source)
        XCTAssertTrue(effect.refusals.isEmpty, file: file, line: line)
        XCTAssertEqual(Set(effect.reads.cells), reads, file: file, line: line)
        XCTAssertEqual(Set(effect.writes.map { $0.cell }), writes, file: file, line: line)
    }

    func testE01E04PhysicalSSAEffects() {
        effects(row("20 68 21 0e", "fcvtn", "v0.4h, v1.4s"),
            reads: [33, 65, 99, 100], writes: [32, 64, 99]) // E01
        effects(row("20 68 21 4e", "fcvtn2", "v0.8h, v1.4s"),
            reads: [32, 33, 64, 65, 99, 100], writes: [32, 64, 99]) // E02
        effects(row("21 68 61 0e", "fcvtn", "v1.2s, v1.2d"),
            reads: [33, 65, 99, 100], writes: [33, 65, 99]) // E03
        effects(row("61 68 61 4e", "fcvtn2", "v1.4s, v3.2d"),
            reads: [33, 35, 65, 67, 99, 100], writes: [33, 65, 99]) // E04
    }

    func testS01S03HalfStatusAndWholeFPCRRemainSymbolic() throws {
        let source = row("20 68 21 0e", "fcvtn", "v0.4h, v1.4s")
        let fp = try XCTUnwrap(MacIRVectorFP(source: source))
        for control in [UInt32(0x00000000), UInt32(0x00400000)] { // S01 RN; S02 RP
            var state = MacIRFPState(fpcr: .constant(control), fpsr: .constant(0x08000002))
            XCTAssertTrue(state.accumulateExceptions(.constant(0x10), access: .permitted))
            XCTAssertEqual(state.fpsr, .constant(0x08000012))
            var builder = BuilderState(parameters: [])
            let lifted = MacIRBuilder.liftVectorFP(fp, source: source, state: &builder,
                fpcr: .immediate(Int64(control)), exceptions: .immediate(2),
                exceptionOutput: .register(name: "fpsr_exception_bits", version: 1))
            let effect = try XCTUnwrap(lifted.first?.vectorFP)
            XCTAssertEqual(effect.fpcrInput, .immediate(Int64(control)))
            XCTAssertEqual(Array(effect.numericArguments.suffix(3)),
                [.immediate(Int64(control)), .unknown("fp_access_features_sme"), .immediate(2)])
            XCTAssertEqual(effect.raisedExceptions, .unknown("fp_raised_exceptions"))
            XCTAssertEqual(effect.normalExceptionResult,
                .binaryExpression(op: "|", left: .binaryExpression(op: "&", left: .immediate(2),
                    right: .immediate(0x9f)), right: .binaryExpression(op: "&",
                    left: .unknown("fp_raised_exceptions"), right: .immediate(0x9f))))
            XCTAssertEqual(lifted.last?.vectorFPStatus, effect)
        }
        var enabled = MacIRFPState(fpcr: .constant(0x100), fpsr: .constant(0x08000002))
        XCTAssertFalse(enabled.accumulateExceptions(.constant(0x10), access: .permitted)) // S03
        XCTAssertEqual(enabled.fpsr, .constant(0x08000002))
    }

    private func machine(_ source: MacIRSourceSpan, reads: Set<String>, writes: Set<String>,
                         file: StaticString = #filePath, line: UInt = #line) {
        let flow = C2MachineFlow(rows: [source])
        XCTAssertNil(flow.error, file: file, line: line)
        XCTAssertEqual(flow.reads[0], reads, file: file, line: line)
        XCTAssertEqual(flow.writes[0], writes, file: file, line: line)
        XCTAssertTrue(flow.reads[0].isDisjoint(with: ["fpcr", "fpsr"]), file: file, line: line)
        XCTAssertTrue(flow.writes[0].isDisjoint(with: ["fpcr", "fpsr"]), file: file, line: line)
    }

    func testM01M07IndependentMachineRegisterSets() {
        machine(row("21 68 61 0e", "fcvtn", "v1.2s, v1.2d"), reads: ["v1"], writes: ["v1"]) // M01
        machine(row("42 68 61 0e", "fcvtn", "v2.2s, v2.2d"), reads: ["v2"], writes: ["v2"]) // M02
        machine(row("61 68 61 4e", "fcvtn2", "v1.4s, v3.2d"), reads: ["v1", "v3"], writes: ["v1"]) // M03
        machine(row("02 68 61 4e", "fcvtn2", "v2.4s, v0.2d"), reads: ["v0", "v2"], writes: ["v2"]) // M04
        machine(row("20 68 21 0e", "fcvtn", "v0.4h, v1.4s"), reads: ["v1"], writes: ["v0"]) // M05
        machine(row("20 68 21 4e", "fcvtn2", "v0.8h, v1.4s"), reads: ["v0", "v1"], writes: ["v0"]) // M06
        machine(row("a5 68 21 0e", "fcvtn", "v5.4h, v5.4s"), reads: ["v5"], writes: ["v5"]) // M07 low
        machine(row("a5 68 21 4e", "fcvtn2", "v5.8h, v5.4s"), reads: ["v5"], writes: ["v5"]) // M07 high
        // Canonical register-number boundaries are admitted, not only v0-v5.
        machine(row("", "fcvtn", "v31.4h, v0.4s"), reads: ["v0"], writes: ["v31"])
    }

    func testM08RealFourRowReachingDefinitions() {
        let flow = C2MachineFlow(rows: [
            row("21 68 61 0e", "fcvtn", "v1.2s, v1.2d", address: 0x6950),
            row("42 68 61 0e", "fcvtn", "v2.2s, v2.2d", address: 0x6954),
            row("61 68 61 4e", "fcvtn2", "v1.4s, v3.2d", address: 0x6958),
            row("02 68 61 4e", "fcvtn2", "v2.4s, v0.2d", address: 0x695c)])
        XCTAssertNil(flow.error)
        XCTAssertEqual(flow.reads, [["v1"], ["v2"], ["v1", "v3"], ["v0", "v2"]])
        XCTAssertEqual(flow.writes, [["v1"], ["v2"], ["v1"], ["v2"]])
        XCTAssertEqual(flow.before[2]["v1"], Set<UInt64>([0x6950]))
        XCTAssertEqual(flow.before[2]["v2"], Set<UInt64>([0x6954]))
        XCTAssertEqual(flow.before[3]["v1"], Set<UInt64>([0x6958]))
        XCTAssertEqual(flow.before[3]["v2"], Set<UInt64>([0x6954]))
        for sets in [flow.reads, flow.writes] {
            XCTAssertTrue(sets.allSatisfy { $0.isDisjoint(with: ["fpcr", "fpsr"]) })
        }
    }

    func testR01R13MalformedMachineOperands() {
        let cases = [
            ("fcvtn", "v0.8h, v1.4s"), // R01
            ("fcvtn2", "v0.4h, v1.4s"), // R02
            ("fcvtn", "v0.4s, v1.2d"), // R03
            ("fcvtn", "v0.2s, v1.4s"), // R04
            ("fcvtn", "v0.2d, v1.2s"), // R05
            ("fcvtn", "v0.2s"), // R06
            ("fcvtn", "v0.2s, v1.2d, v2.2d"), // R07
            ("fcvtn", "v0.2s, v1.2d,"), // R08
            ("fcvtn", "s0, d1"), // R09
            ("fcvtn", "v32.2s, v1.2d"), // R10
            ("fcvtn", "v01.2s, v1.2d"), // R11
            ("fcvtn", "v0.2s, v1"), // R12
            ("fcvtn", "V0.2S, V1.2D"), // R13
            ("fcvtn", "v0.4h, v1.2d"),
            ("fcvtn2", "v0.8h, v1.4s,"),
            ("fcvtn", "v0.4h, v32.4s"),
            ("fcvtn", "v0.4h, v01.4s"),
            ("fcvtn", "v0.4h, v1.4s.extra")]
        for (mnemonic, operands) in cases {
            let flow = C2MachineFlow(rows: [row("", mnemonic, operands)])
            XCTAssertEqual(flow.error, "0x1000: invalid narrow or wide vector operands", operands)
            XCTAssertEqual(flow.reads[0], Set<String>(), operands)
            XCTAssertEqual(flow.writes[0], Set<String>(), operands)
        }
    }

    func testR14OtherConversionFamiliesRemainUnsupported() {
        for mnemonic in ["fcvtxn", "fcvtxn2", "fcvtl", "fcvtl2", "bfcvtn", "bfcvtn2"] {
            let flow = C2MachineFlow(rows: [row("", mnemonic, "v0.2s, v1.2d")])
            XCTAssertEqual(flow.error, "0x1000: unsupported machine mnemonic \(mnemonic)")
            XCTAssertEqual(flow.reads[0], Set<String>())
            XCTAssertEqual(flow.writes[0], Set<String>())
        }
    }

    func testR15R20LiftRefusalsRemainNarrow() {
        let cases = [
            row("20 68 21 0e", "fcvtn", "v0.8h, v1.4s"), // R15 byte/text mismatch
            row("20 14 42 0e", "fadd", "v0.4h, v1.4h, v2.4h"), // R16
            row("20 1c 42 2e", "fmul", "v0.4h, v1.4h, v2.4h"), // R17
            row("20 68 a1 0e", "bfcvtn", "v0.4h, v1.4s"), // R18
            row("20 68 61 2e", "fcvtxn", "v0.2s, v1.2d"), // R19
            row("20 78 21 0e", "fcvtl", "v0.4s, v1.4h"), // R20
            row("20 0c 42 0e", "fmla", "v0.4h, v1.4h, v2.4h"),
            row("20 b8 f9 0e", "fcvtzs", "v0.4h, v1.4h")]
        for source in cases { XCTAssertNil(MacIRVectorFP(source: source), source.operands) }
    }
}
