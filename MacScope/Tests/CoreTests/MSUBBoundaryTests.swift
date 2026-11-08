import XCTest
@testable import MacScope

// Source-authored regression definitions.
// Pins what multiplyAccumulateOperation does for MSUB (MacIRBuilder.swift:3224-3291) in the
// cases not covered in DecompilerCoreTests.swift: 32-bit width, zero-register operands, in-place destinations,
// mixed widths, wrong arity and the subtraction shape of an MSUB whose quotient is not adjacent. The SSA wrap
// (Rd = (uintN_t)Ra - ((uintN_t)Rn * (uintN_t)Rm)) came from b85ad20da; the default (legacy)
// lifter keeps the uncast Ra - (Rn * Rm).
// Operands are produced by division instructions, so every expected value is read back from the
// lifted function itself and no register value is assumed.
final class MSUBBoundaryTests: XCTestCase {
    private enum ShapeFailure: Error { case notBinary }

    private func row(_ address: UInt64, _ mnemonic: String, _ operands: String = "") -> InstructionRow {
        InstructionRow(address: address, bytes: "00 00 00 00", mnemonic: mnemonic,
            operands: operands, hasBreakpoint: false, comment: nil)
    }

    private func prefix(_ width: Int) -> String { width == 32 ? "w" : "x" }

    // The unsigned cast spelling at a width (MacIRBuilder.swift:4279).
    private func cast(_ width: Int) -> String { width == 32 ? "(uint32_t)" : "(uint64_t)" }

    // SSA wraps an operand in the width cast; the default lifter leaves it as read.
    private func expected(_ value: MacIRValue, width: Int) -> MacIRValue {
        SSAPropertyAssertions.enabled ? .unary(op: cast(width), value: value) : value
    }

    private func lift(_ rows: [InstructionRow], requireMode: Bool = true) -> MacIRFunction {
        let function = MacIRBuilder().buildFunction(name: "_msub_boundary", instructions: rows)
        if requireMode {
            XCTAssertEqual(function.ssaEnabled, MacIRConfiguration.ssaEnabled,
                           "a requested SSA check must not pass through a legacy fallback")
        }
        return function
    }

    private func instruction(_ function: MacIRFunction, at address: UInt64) throws -> MacIRInstruction {
        try XCTUnwrap(function.instructions.first { $0.source.address == address })
    }

    // The value written by a division row.
    private func quotient(_ function: MacIRFunction, at address: UInt64) throws -> MacIRValue {
        let operation = try instruction(function, at: address).operation
        let destination: MacIRValue? = {
            if case let .intrinsic(destination, _, _) = operation { return destination }
            return nil
        }()
        return try XCTUnwrap(destination, "no division producer at \(address)")
    }

    private func subtraction(_ function: MacIRFunction, at address: UInt64)
        throws -> (destination: MacIRValue, left: MacIRValue, right: MacIRValue) {
        let operation = try instruction(function, at: address).operation
        guard case let .binary(destination, op, left, right) = operation else {
            XCTFail("msub was not lifted to a binary operation: \(operation)")
            throw ShapeFailure.notBinary
        }
        XCTAssertEqual(op, "-")
        return (destination, left, right)
    }

    // Three independent divisions (no adjacency to the MSUB beyond the last one, whose dividend
    // differs from the addend), then the MSUB at 0x100c, then ret. Registers: operand registers are
    // numbered 8, 9, 10; the destination is numbered 11.
    private func rows(widths: [Int], msub: String) -> [InstructionRow] {
        [
            row(0x1000, "sdiv", "\(prefix(widths[0]))8, \(prefix(widths[0]))12, \(prefix(widths[0]))13"),
            row(0x1004, "sdiv", "\(prefix(widths[1]))9, \(prefix(widths[1]))14, \(prefix(widths[1]))15"),
            row(0x1008, "sdiv", "\(prefix(widths[2]))10, \(prefix(widths[2]))16, \(prefix(widths[2]))17"),
            row(0x100c, "msub", msub),
            row(0x1010, "ret")
        ]
    }

    // MSUB Rd, Rn, Rm, Ra computes Ra - Rn * Rm (operands[3] is the addend, MacIRBuilder.swift:3251).
    func testMSUBWrapsAddendAndBothFactorsAtDestinationWidth() throws {
        for width in [32, 64] {
            let p = prefix(width)
            let function = lift(rows(widths: [width, width, width], msub: "\(p)11, \(p)8, \(p)9, \(p)10"))
            let factorA = try quotient(function, at: 0x1000)
            let factorB = try quotient(function, at: 0x1004)
            let addend = try quotient(function, at: 0x1008)
            let result = try subtraction(function, at: 0x100c)
            XCTAssertEqual(result.left, expected(addend, width: width), "width \(width)")
            XCTAssertEqual(result.right, .binaryExpression(op: "*",
                left: expected(factorA, width: width),
                right: expected(factorB, width: width)), "width \(width)")
        }
    }

    // xzr/wzr read as the immediate 0 (MacIRBuilder.swift:4789) and take the same width cast.
    func testMSUBZeroRegisterOperandsAreImmediateZeroAtWidth() throws {
        for width in [32, 64] {
            let p = prefix(width)
            let zero = "\(p)zr"
            for position in 0..<3 {
                var names = ["\(p)8", "\(p)9", "\(p)10"]
                names[position] = zero
                let function = lift(rows(widths: [width, width, width],
                    msub: "\(p)11, \(names[0]), \(names[1]), \(names[2])"))
                // The division whose register was replaced by the zero register is not read back.
                var values: [MacIRValue] = []
                for (index, address) in [UInt64(0x1000), 0x1004, 0x1008].enumerated() {
                    try values.append(index == position ? .immediate(0) : quotient(function, at: address))
                }
                let result = try subtraction(function, at: 0x100c)
                let label = "width \(width), zero operand \(position)"
                XCTAssertEqual(result.left, expected(values[2], width: width), label)
                XCTAssertEqual(result.right, .binaryExpression(op: "*",
                    left: expected(values[0], width: width),
                    right: expected(values[1], width: width)), label)
            }
        }
    }

    // All source operands are read before the destination is written (MacIRBuilder.swift:3230-3233,
    // MacIRBuilder.swift:3251), so a destination that is also a source still uses the incoming value.
    func testMSUBInPlaceDestinationReadsIncomingValues() throws {
        for width in [32, 64] {
            let p = prefix(width)
            for position in 0..<3 {
                let names = ["\(p)8", "\(p)9", "\(p)10"]
                let overwritten = names[position]
                let function = lift(rows(widths: [width, width, width],
                    msub: "\(overwritten), \(names[0]), \(names[1]), \(names[2])"))
                let incoming = [try quotient(function, at: 0x1000), try quotient(function, at: 0x1004),
                                try quotient(function, at: 0x1008)]
                let result = try subtraction(function, at: 0x100c)
                let label = "width \(width), destination is operand \(position)"
                XCTAssertEqual(result.left, expected(incoming[2], width: width), label)
                XCTAssertEqual(result.right, .binaryExpression(op: "*",
                    left: expected(incoming[0], width: width),
                    right: expected(incoming[1], width: width)), label)
                XCTAssertNotEqual(result.destination, incoming[position], label)
            }
        }
    }

    // The wrap needs every operand at the destination width (MacIRBuilder.swift:3277-3278). A mixed
    // width MSUB keeps the uncast Ra - (Rn * Rm) in both lifter modes.
    func testMSUBMixedWidthOperandsAreNotWrapped() throws {
        // widths are [destination, Rn, Rm, Ra]
        let cases: [[Int]] = [[64, 32, 64, 64], [64, 64, 32, 64], [64, 64, 64, 32], [32, 64, 64, 64], [32, 32, 32, 64], [64, 32, 32, 32]]
        for widths in cases {
            let names = [
                "\(prefix(widths[0]))11", "\(prefix(widths[1]))8", "\(prefix(widths[2]))9", "\(prefix(widths[3]))10"
            ]
            let function = lift(rows(widths: [widths[1], widths[2], widths[3]],
                msub: names.joined(separator: ", ")), requireMode: false)
            let factorA = try quotient(function, at: 0x1000)
            let factorB = try quotient(function, at: 0x1004)
            let addend = try quotient(function, at: 0x1008)
            let result = try subtraction(function, at: 0x100c)
            XCTAssertEqual(result.left, addend, "widths \(widths)")
            XCTAssertEqual(result.right, .binaryExpression(op: "*", left: factorA, right: factorB), "widths \(widths)")
        }
    }

    // MSUB takes exactly four operands (MacIRBuilder.swift:3225-3228); anything else is the unknown form.
    func testMSUBWithWrongOperandCountFallsBackToUnknown() throws {
        for operands in ["x11, x8, x9", "x11, x8, x9, x10, x12"] {
            let function = lift([row(0x1000, "msub", operands), row(0x1004, "ret")], requireMode: false)
            XCTAssertEqual(
                try instruction(function, at: 0x1000).operation.withoutUnknownInputs,
                .unknown(mnemonic: "msub", operands: operands),
                operands
            )
        }
    }

    // The remainder fold needs the MSUB at the address right after the division (MacIRBuilder.swift:645,
    // MacIRBuilder.swift:3264). With one instruction in between the MSUB stays a subtraction, and it takes
    // the same operand wrap as any other MSUB: a cast in SSA, none in the default lifter. The quotient is
    // the first factor and the dividend is the addend, which is the exact shape the fold would have taken.
    func testMSUBQuotientNotAdjacentKeepsSubtractionShape() throws {
        for division in ["sdiv", "udiv"] {
            let function = lift([
                row(0x1000, division, "x8, x12, x13"),
                row(0x1004, "mov", "x14, x15"),
                row(0x1008, "msub", "x11, x8, x13, x12"),
                row(0x100c, "ret")
            ])
            let producer = try instruction(function, at: 0x1000).operation
            guard case let .intrinsic(quotientValue?, _, arguments) = producer, arguments.count == 2 else {
                return XCTFail("missing division producer: \(producer)")
            }
            let result = try subtraction(function, at: 0x1008)
            XCTAssertEqual(result.left, expected(arguments[0], width: 64), division)
            XCTAssertEqual(result.right, .binaryExpression(op: "*",
                left: expected(quotientValue, width: 64),
                right: expected(arguments[1], width: 64)), division)
        }
    }
}
