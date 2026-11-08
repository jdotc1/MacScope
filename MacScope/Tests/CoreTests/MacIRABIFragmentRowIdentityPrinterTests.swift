import XCTest
@testable import MacScope

final class MacIRABIFragmentRowIdentityPrinterTests: XCTestCase {
    private let sharedRow = MacIRParameterRowID(rawValue: "shared-fragment-row")

    private func parameter(
        id: MacIRParameterRowID,
        name: String,
        type: String,
        richLocation: DarwinARM64RichParameterLocation? = nil
    ) throws -> MacIRFunctionParameter {
        try XCTUnwrap(MacIRFunctionParameter(
            id: id, bindingID: nil, sourcePosition: nil,
            abiLocation: .unbound(reason: .unsupportedType(type)),
            richLocation: richLocation, type: type, name: name,
            evidence: .authoritativeUser
        ))
    }

    private func instruction(
        _ address: UInt64,
        _ operation: MacIROperation,
        mnemonic: String = "mov"
    ) -> MacIRInstruction {
        MacIRInstruction(source: MacIRSourceSpan(
            address: address, byteText: "00 00 00 00", mnemonic: mnemonic,
            operands: "", comment: nil
        ), operation: operation)
    }

    private func fragmentAssignment(
        rowID: MacIRParameterRowID,
        byteOffset: Int = 0,
        size: Int = 8,
        address: UInt64 = 0x1000,
        destination: String = "x10"
    ) -> MacIRInstruction {
        instruction(address, .assign(
            destination: .register(name: destination, version: 1),
            source: .argumentFragment(rowID: rowID, byteOffset: byteOffset, size: size)
        ))
    }

    private func renderedLines(
        parameters: [MacIRFunctionParameter],
        instructions: [MacIRInstruction],
        types: [TypeDefinition] = []
    ) -> [String] {
        let function = MacIRFunction(
            name: "fragment_rows", startAddress: 0x1000,
            parameters: parameters, instructions: instructions
        )
        let document = PseudocodePrinter(options: DecompilerOptions(
            structureControlFlow: false, deadCodeElimination: false,
            nopElision: false, functionSizeGate: 1024
        )).print(function: function, types: types)
        return instructions.flatMap { instruction in
            document.lines(sourcedAt: instruction.source.address).map {
                $0.text.trimmingCharacters(in: .whitespaces)
            }
        }
    }

    private var wordTypes: [TypeDefinition] {
        [
            TypeDefinition(kind: .struct, name: "FirstRecord", fields: [
                FieldDef(name: "firstWord", type: "uint64_t")
            ]),
            TypeDefinition(kind: .struct, name: "SecondRecord", fields: [
                FieldDef(name: "secondWord", type: "int64_t")
            ])
        ]
    }

    private var packetType: TypeDefinition {
        TypeDefinition(kind: .struct, name: "Packet", fields: [
            FieldDef(name: "low", type: "uint64_t"),
            FieldDef(name: "high", type: "uint64_t")
        ])
    }

    private var gprCarrier: DarwinARM64RichParameterLocation {
        .composite(pieces: [DarwinARM64RichParameterPiece(
            register: .gpr(index: 0, carrierWidth: 64), valueByteOffset: 0, size: 8
        )])
    }

    private var doubleGPRCarrier: DarwinARM64RichParameterLocation {
        .composite(pieces: [
            DarwinARM64RichParameterPiece(register: .gpr(index: 0, carrierWidth: 64),
                                         valueByteOffset: 0, size: 8),
            DarwinARM64RichParameterPiece(register: .gpr(index: 1, carrierWidth: 64),
                                         valueByteOffset: 8, size: 8)
        ])
    }

    private func doubleBitMoves() -> [MacIRInstruction] {
        let fragment = MacIRValue.argumentFragment(rowID: sharedRow, byteOffset: 0, size: 8)
        let firstCopy = MacIRValue.register(name: "x19", version: 1)
        let secondCopy = MacIRValue.register(name: "x20", version: 1)
        return [
            instruction(0x1000, .assign(destination: firstCopy, source: fragment)),
            instruction(0x1004, .assign(destination: secondCopy, source: firstCopy)),
            instruction(0x1008, .intrinsic(destination: .register(name: "d0", version: 1),
                name: "fmov", arguments: [fragment]), mnemonic: "fmov"),
            instruction(0x100c, .intrinsic(destination: .register(name: "d1", version: 1),
                name: "fmov", arguments: [secondCopy]), mnemonic: "fmov")
        ]
    }

    func testUniqueRowRetainsExactFieldRecovery() throws {
        let row = try parameter(id: sharedRow, name: "payload", type: "Packet")
        XCTAssertEqual(renderedLines(parameters: [row], instructions: [
            fragmentAssignment(rowID: sharedRow, byteOffset: 8)
        ], types: [packetType]), ["x10_1 = payload.high;"])
    }

    func testConflictingDuplicateRowNamesAndTypesKeepUnknownFragment() throws {
        let first = try parameter(id: sharedRow, name: "firstPayload", type: "FirstRecord")
        let second = try parameter(id: sharedRow, name: "secondPayload", type: "SecondRecord")
        XCTAssertEqual(renderedLines(parameters: [first, second], instructions: [
            fragmentAssignment(rowID: sharedRow)
        ], types: wordTypes), ["x10_1 = __abi_fragment(unknown, 0, 8);"])
    }

    func testReversingConflictingDuplicateRowsKeepsSameConservativeBody() throws {
        let first = try parameter(id: sharedRow, name: "firstPayload", type: "FirstRecord")
        let second = try parameter(id: sharedRow, name: "secondPayload", type: "SecondRecord")
        let instructions = [fragmentAssignment(rowID: sharedRow)]
        let forward = renderedLines(parameters: [first, second], instructions: instructions, types: wordTypes)
        let reversed = renderedLines(parameters: [second, first], instructions: instructions, types: wordTypes)
        XCTAssertEqual(forward, ["x10_1 = __abi_fragment(unknown, 0, 8);"])
        XCTAssertEqual(reversed, forward)
    }

    func testIdenticalDuplicateRowsRemainAmbiguous() throws {
        let row = try parameter(id: sharedRow, name: "payload", type: "Opaque")
        XCTAssertEqual(renderedLines(parameters: [row, row], instructions: [
            fragmentAssignment(rowID: sharedRow)
        ]), ["x10_1 = __abi_fragment(unknown, 0, 8);"])
    }

    func testThirdOccurrenceCannotReadmitAnAmbiguousRow() throws {
        let first = try parameter(id: sharedRow, name: "firstPayload", type: "FirstOpaque")
        let second = try parameter(id: sharedRow, name: "secondPayload", type: "SecondOpaque")
        XCTAssertEqual(renderedLines(parameters: [first, second, first], instructions: [
            fragmentAssignment(rowID: sharedRow)
        ]), ["x10_1 = __abi_fragment(unknown, 0, 8);"])
    }

    func testUniqueOpaqueRowAndMissingRowKeepExistingFallbacks() throws {
        let row = try parameter(id: sharedRow, name: "payload", type: "Opaque")
        let missing = MacIRParameterRowID(rawValue: "missing-fragment-row")
        XCTAssertEqual(renderedLines(parameters: [row], instructions: [
            fragmentAssignment(rowID: sharedRow),
            fragmentAssignment(rowID: missing, byteOffset: 12, size: 4,
                               address: 0x1004, destination: "x11")
        ]), [
            "x10_1 = __abi_fragment(payload, 0, 8);",
            "x11_1 = __abi_fragment(unknown, 12, 4);"
        ])
    }

    func testUniqueNeighborAndMissingRowAreUnaffectedByAmbiguousGroup() throws {
        let first = try parameter(id: sharedRow, name: "firstPayload", type: "FirstRecord")
        let second = try parameter(id: sharedRow, name: "secondPayload", type: "SecondRecord")
        let neighborID = MacIRParameterRowID(rawValue: "neighbor-fragment-row")
        let neighbor = try parameter(id: neighborID, name: "neighbor", type: "Packet")
        let missing = MacIRParameterRowID(rawValue: "missing-fragment-row")
        XCTAssertEqual(renderedLines(parameters: [first, neighbor, second], instructions: [
            fragmentAssignment(rowID: sharedRow),
            fragmentAssignment(rowID: neighborID, byteOffset: 8, address: 0x1004, destination: "x11"),
            fragmentAssignment(rowID: missing, byteOffset: 12, size: 4,
                               address: 0x1008, destination: "x12")
        ], types: wordTypes + [packetType]), [
            "x10_1 = __abi_fragment(unknown, 0, 8);",
            "x11_1 = neighbor.high;",
            "x12_1 = __abi_fragment(unknown, 12, 4);"
        ])
    }

    func testUniqueGPRDoubleFieldRetainsDirectAndCopiedBitMoveRecovery() throws {
        let type = TypeDefinition(kind: .struct, name: "DoubleRecord", fields: [
            FieldDef(name: "value", type: "double"),
            FieldDef(name: "bits", type: "uint64_t")
        ])
        let row = try parameter(id: sharedRow, name: "payload", type: "DoubleRecord",
                                richLocation: doubleGPRCarrier)
        XCTAssertEqual(renderedLines(parameters: [row], instructions: doubleBitMoves(), types: [type]), [
            "x19_1 = __abi_fragment(payload, 0, 8);",
            "x20_1 = x19_1;",
            "d0_1 = payload.value;",
            "d1_1 = payload.value;"
        ])
    }

    func testAmbiguousRowCannotRecoverDirectOrCopiedDoubleBitMovedField() throws {
        let firstType = TypeDefinition(kind: .struct, name: "FirstDoubleRecord", fields: [
            FieldDef(name: "firstValue", type: "double"),
            FieldDef(name: "bits", type: "uint64_t")
        ])
        let secondType = TypeDefinition(kind: .struct, name: "SecondDoubleRecord", fields: [
            FieldDef(name: "secondValue", type: "double"),
            FieldDef(name: "bits", type: "uint64_t")
        ])
        let first = try parameter(id: sharedRow, name: "firstPayload", type: "FirstDoubleRecord",
                                  richLocation: doubleGPRCarrier)
        let second = try parameter(id: sharedRow, name: "secondPayload", type: "SecondDoubleRecord",
                                   richLocation: doubleGPRCarrier)
        let expected = [
            "x19_1 = __abi_fragment(unknown, 0, 8);",
            "x20_1 = x19_1;",
            "d0_1 = __fmov(__abi_fragment(unknown, 0, 8));",
            "d1_1 = __fmov(x20_1);"
        ]
        for rows in [[first, second], [second, first], [first, first]] {
            XCTAssertEqual(renderedLines(parameters: rows, instructions: doubleBitMoves(),
                                         types: [firstType, secondType]), expected)
        }
    }

    func testMissingRowKeepsDirectAndCopiedBitMovesRaw() {
        XCTAssertEqual(renderedLines(parameters: [], instructions: doubleBitMoves()), [
            "x19_1 = __abi_fragment(unknown, 0, 8);",
            "x20_1 = x19_1;",
            "d0_1 = __fmov(__abi_fragment(unknown, 0, 8));",
            "d1_1 = __fmov(x20_1);"
        ])
    }

    func testFloatBitMoveRecoversOnlyForUniqueRow() throws {
        let type = TypeDefinition(kind: .struct, name: "FloatRecord", fields: [
            FieldDef(name: "value", type: "float"),
            FieldDef(name: "bits", type: "uint32_t")
        ])
        let row = try parameter(id: sharedRow, name: "payload", type: "FloatRecord",
                                richLocation: gprCarrier)
        let fragment = MacIRValue.argumentFragment(rowID: sharedRow, byteOffset: 0, size: 8)
        let copy = MacIRValue.register(name: "x19", version: 1)
        let instructions = [
            instruction(0x1000, .assign(destination: copy, source: fragment)),
            instruction(0x1004, .intrinsic(destination: .register(name: "s0", version: 1),
                name: "fmov", arguments: [.unary(op: "(uint32_t)", value: fragment)]), mnemonic: "fmov"),
            instruction(0x1008, .intrinsic(destination: .register(name: "s1", version: 1),
                name: "fmov", arguments: [.unary(op: "(uint32_t)", value: copy)]), mnemonic: "fmov")
        ]
        XCTAssertEqual(renderedLines(parameters: [row], instructions: instructions, types: [type]), [
            "x19_1 = __abi_fragment(payload, 0, 8);",
            "s0_1 = payload.value;",
            "s1_1 = payload.value;"
        ])
        XCTAssertEqual(renderedLines(parameters: [row, row], instructions: instructions, types: [type]), [
            "x19_1 = __abi_fragment(unknown, 0, 8);",
            "s0_1 = __fmov((uint32_t)(__abi_fragment(unknown, 0, 8)));",
            "s1_1 = __fmov((uint32_t)(x19_1));"
        ])
    }
}
