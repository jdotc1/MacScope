import XCTest
@testable import MacScope

final class PseudocodeUnknownOperandDependenciesTests: XCTestCase {
    private func printedStatements(
        destination: MacIRValue? = nil,
        inputs: MacIRUnknownInputs = .none,
        mnemonic: String = "opaque",
        operands: String = "",
        parameters: [MacIRFunctionParameter] = [],
        nameBindings: [MacIRNameBinding] = [],
        registerNameOverrides: [String: String] = [:]
    ) -> [String] {
        let address: UInt64 = 0x4450
        let instruction = MacIRInstruction(
            source: MacIRSourceSpan(address: address, byteText: "00 00 00 00",
                mnemonic: mnemonic, operands: operands, comment: nil),
            operation: .unknown(destination: destination, inputs: inputs,
                mnemonic: mnemonic, operands: operands)
        )
        let function = MacIRFunction(name: "unknown_dependencies", startAddress: address,
            parameters: parameters, nameBindings: nameBindings, instructions: [instruction])
        let printer = PseudocodePrinter(options: DecompilerOptions(
            structureControlFlow: false, deadCodeElimination: false,
            nopElision: false, functionSizeGate: 1024))
        return printer.print(function: function, registerNameOverrides: registerNameOverrides)
            .lines(sourcedAt: address).map { $0.text.trimmingCharacters(in: .whitespaces) }
    }

    func testDestinationAndTwoInputsPreserveNestedRecoveredExpression() {
        let recovered = MacIRValue.register(name: "x19", version: 4)
        let nested = MacIRValue.binaryExpression(op: "+",
            left: .binaryExpression(op: "*", left: recovered, right: .immediate(2)),
            right: .immediate(3))
        let reads = [
            MacIRUnknownRead(register: "x1", value: nested),
            MacIRUnknownRead(register: "x2", value: .argument(bindingID: .gpr(0)))
        ]
        let lines = printedStatements(destination: .register(name: "x8", version: 2),
            inputs: MacIRUnknownInputs(mayRead: reads, definiteRead: [reads[1]]),
            operands: "x8, x1, x2",
            parameters: [MacIRFunctionParameter(index: 0, register: "x0", type: "int64_t",
                name: "sample_count")],
            nameBindings: [MacIRNameBinding(target: .register(name: "x19", version: 4),
                name: "saved_count", kind: .registerTemporary)])

        XCTAssertEqual(lines, [
            #"x8_2 = __unknown("opaque", "x8, x1, x2", (saved_count * 0x2) + 0x3, sample_count);"#
        ])
    }

    func testDestinationFreeUnknownUsesRegisterOverrideAndArgumentName() {
        let reads = [
            MacIRUnknownRead(register: "w19", value: .register(name: "w19", version: 7)),
            MacIRUnknownRead(register: "x0", value: .argument(bindingID: .gpr(0)))
        ]
        let lines = printedStatements(inputs: MacIRUnknownInputs(mayRead: reads),
            operands: "w19, x0",
            parameters: [MacIRFunctionParameter(index: 0, register: "x0", type: "int64_t",
                name: "renamed_input")],
            registerNameOverrides: ["X19": "cursor"])

        XCTAssertEqual(lines, [
            #"__unknown("opaque", "w19, x0", cursor, renamed_input);"#
        ])
    }

    func testRepeatedInputsKeepTheirStoredOrderAndMultiplicity() {
        let first = MacIRUnknownRead(register: "x7", value: .immediate(9))
        let middle = MacIRUnknownRead(register: "x1", value: .immediate(2))
        let lines = printedStatements(inputs: MacIRUnknownInputs(
            mayRead: [first, middle, first], definiteRead: [middle]),
            operands: "x7, x1, x7")

        XCTAssertEqual(lines, [
            #"__unknown("opaque", "x7, x1, x7", 0x9, 0x2, 0x9);"#
        ])
    }

    func testEmptyInputsKeepLegacyOutputWithAndWithoutDestination() {
        XCTAssertEqual(printedStatements(mnemonic: "opaque", operands: "x8, #1"), [
            #"__unknown("opaque", "x8, #1");"#
        ])
        XCTAssertEqual(printedStatements(destination: .register(name: "x8", version: 3),
            mnemonic: "opaque", operands: "x8, #1", registerNameOverrides: ["x8": "output"]), [
            #"output = __unknown("opaque", "x8, #1");"#
        ])
    }

    func testArithmeticLookingRawTextRemainsUnknown() {
        let lines = printedStatements(destination: .register(name: "x0", version: 1),
            inputs: MacIRUnknownInputs(mayRead: [
                MacIRUnknownRead(register: "x1", value: .immediate(7))
            ]), mnemonic: "add", operands: "x0, x1, #8")

        XCTAssertEqual(lines, [
            #"x0_1 = __unknown("add", "x0, x1, #8", 0x7);"#
        ])
    }

    func testMnemonicAndRawOperandsKeepQuoteAndBackslashEscaping() {
        let mnemonic = #"opaque"\suffix"#
        let operands = #"x1, "quoted\path""#
        let inputs = MacIRUnknownInputs(mayRead: [
            MacIRUnknownRead(register: "x1", value: .argument(bindingID: .gpr(1)))
        ])

        XCTAssertEqual(printedStatements(inputs: inputs, mnemonic: mnemonic, operands: operands), [
            #"__unknown("opaque\"\\suffix", "x1, \"quoted\\path\"", in_x1);"#
        ])
        XCTAssertEqual(printedStatements(mnemonic: mnemonic, operands: operands), [
            #"__unknown("opaque\"\\suffix", "x1, \"quoted\\path\"");"#
        ])
    }

    func testFlagsOnlyInputsDoNotInventAValueArgument() {
        let inputs = MacIRUnknownInputs(mayReadNZCV: true, definitelyReadsNZCV: true)

        XCTAssertEqual(printedStatements(inputs: inputs, operands: "nzcv"), [
            #"__unknown("opaque", "nzcv");"#
        ])
    }
}
