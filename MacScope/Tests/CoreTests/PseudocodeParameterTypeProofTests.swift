import XCTest
@testable import MacScope

final class PseudocodeParameterTypeProofTests: XCTestCase {
    private let conservative32 = "((in_x0 & 0x80000000) == 0 ? (int32_t)in_x0 : -1 - (int32_t)(uint32_t)~in_x0)"
    private let conservative64 = "((in_x0 & 0x8000000000000000) == 0 ? (int64_t)in_x0 : -1 - (int64_t)(uint64_t)~in_x0)"

    private func parameter(_ position: Int, binding: Int = 0, width: Int = 64,
                           type: String, name: String) throws -> MacIRFunctionParameter {
        try XCTUnwrap(MacIRFunctionParameter(
            id: MacIRParameterRowID(rawValue: "parameter-proof-row:\(position)"),
            bindingID: .gpr(binding), sourcePosition: position,
            abiLocation: .gpr(index: binding, carrierWidth: width),
            type: type, name: name, evidence: .authoritativeUser))
    }

    private func projection(binding: Int = 0, width: Int = 64) -> MacIRValue {
        .binaryExpression(op: MacIRBuilder.signedProjectionOperator,
                          left: .argument(bindingID: .gpr(binding)),
                          right: .immediate(Int64(width)))
    }

    private func printReturn(_ value: MacIRValue,
                             parameters: [MacIRFunctionParameter]) -> PseudocodeDocument {
        let function = MacIRFunction(name: "parameter_type_proof", startAddress: 0x1000,
            parameters: parameters, instructions: [
                MacIRInstruction(source: MacIRSourceSpan(address: 0x1000,
                    byteText: "c0 03 5f d6", mnemonic: "ret", operands: ""),
                    operation: .returnValue(value))
            ])
        return PseudocodePrinter(options: DecompilerOptions(
            structureControlFlow: false, deadCodeElimination: false,
            nopElision: false, functionSizeGate: 1024)).print(function: function)
    }

    private func returnLines(_ document: PseudocodeDocument) -> [String] {
        document.lines(sourcedAt: 0x1000).map {
            $0.text.trimmingCharacters(in: .whitespaces)
        }
    }

    func testUniqueSignedParameterKeepsPlainWidthCast() throws {
        for width in [32, 64] {
            let input = try parameter(0, width: width, type: "int\(width)_t", name: "signedInput")
            let document = printReturn(projection(width: width), parameters: [input])
            XCTAssertEqual(returnLines(document), ["return (int\(width)_t)(signedInput); // return"])
            XCTAssertEqual(document.parameters, [input])
        }
    }

    func testConflictingSignedUnsignedBindingUsesConservativeTransport() throws {
        for width in [32, 64] {
            // A signed final row used to win the fallback despite the duplicate binding.
            let unsigned = try parameter(0, width: width, type: "uint\(width)_t", name: "unsignedInput")
            let signed = try parameter(1, width: width, type: "int\(width)_t", name: "signedInput")
            let document = printReturn(projection(width: width), parameters: [unsigned, signed])
            let expected = width == 32 ? conservative32 : conservative64
            XCTAssertEqual(returnLines(document), ["return \(expected); // return"])
            XCTAssertEqual(document.parameters, [unsigned, signed])
        }
    }

    func testReversingDuplicateRowsPreservesProjectedBodyExpression() throws {
        let signed = try parameter(0, type: "int64_t", name: "signedInput")
        let unsigned = try parameter(1, type: "uint64_t", name: "unsignedInput")
        let forward = printReturn(projection(), parameters: [signed, unsigned])
        let reversed = printReturn(projection(), parameters: [unsigned, signed])
        XCTAssertEqual(returnLines(forward), ["return \(conservative64); // return"])
        XCTAssertEqual(returnLines(reversed), returnLines(forward))
        // Reversal is an input-table change, not authority to rewrite row identities or order.
        XCTAssertEqual(reversed.parameters, [unsigned, signed])
        XCTAssertEqual(forward.lines.first?.text,
            "int64_t parameter_type_proof(int64_t signedInput, uint64_t unsignedInput) {")
        XCTAssertEqual(reversed.lines.first?.text, forward.lines.first?.text)
    }

    func testDuplicatePointerBindingDoesNotInventPointerType() throws {
        let first = try parameter(0, type: "int32_t *", name: "wordPointer")
        let second = try parameter(1, type: "uint64_t *", name: "widePointer")
        let byteOffset = MacIRValue.binaryExpression(op: "+",
            left: .argument(bindingID: .gpr(0)), right: .immediate(8))
        for parameters in [[first, second], [second, first]] {
            XCTAssertEqual(returnLines(printReturn(projection(), parameters: parameters)),
                           ["return \(conservative64); // return"])
            XCTAssertEqual(returnLines(printReturn(byteOffset, parameters: parameters)),
                           ["return in_x0 + 0x8; // return"])
        }
    }

    func testMissingBindingUsesPlaceholderAndConservativeTransport() {
        let document = printReturn(projection(), parameters: [])
        XCTAssertEqual(returnLines(document), ["return \(conservative64); // return"])
        XCTAssertTrue(document.parameters.isEmpty)
    }

    func testDistinctUniqueNeighborRetainsItsNameAndSignedType() throws {
        let unsigned = try parameter(0, type: "uint64_t", name: "unsignedInput")
        let signed = try parameter(1, type: "int64_t", name: "signedInput")
        let neighbor = try parameter(2, binding: 1, type: "int64_t", name: "neighbor")
        let expression = MacIRValue.binaryExpression(op: "+",
            left: projection(), right: projection(binding: 1))
        let document = printReturn(expression, parameters: [unsigned, signed, neighbor])
        XCTAssertEqual(returnLines(document),
            ["return (\(conservative64)) + ((int64_t)(neighbor)); // return"])
        XCTAssertEqual(document.parameters, [unsigned, signed, neighbor])
    }

    func testEqualTypeDuplicatesStillCannotProveAUniqueBinding() throws {
        let first = try parameter(0, type: "int64_t", name: "firstInput")
        let second = try parameter(1, type: "int64_t", name: "secondInput")
        let document = printReturn(projection(), parameters: [first, second])
        XCTAssertEqual(returnLines(document), ["return \(conservative64); // return"])
    }

    func testUniqueRecoveredParameterKeepsExistingTypeRecovery() {
        let input = MacIRFunctionParameter(index: 0, register: "x0", type: "int64_t", name: "recovered")
        let document = printReturn(projection(), parameters: [input])
        XCTAssertEqual(returnLines(document), ["return (int64_t)(recovered); // return"])
        XCTAssertEqual(document.lines.first?.text,
            "int64_t parameter_type_proof(/* ABI inputs: x0:int64_t recovered */) {")
        XCTAssertEqual(document.parameters, [input])
    }

    func testUniquePointerKeepsExistingBareProjection() throws {
        let input = try parameter(0, type: "int32_t *", name: "pointerInput")
        let document = printReturn(projection(), parameters: [input])
        XCTAssertEqual(returnLines(document), ["return pointerInput; // return"])
    }
}
