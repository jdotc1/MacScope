import XCTest
@testable import MacScope

// Source-authored regression definitions.
final class MulOperandCastTests: XCTestCase {
    private func row(_ address: UInt64, _ mnemonic: String, _ operands: String = "") -> InstructionRow {
        InstructionRow(address: address, bytes: "", mnemonic: mnemonic,
            operands: operands, hasBreakpoint: false, comment: nil)
    }

    func testSignedDivisionOperandsKeepUnsignedCastsAtBothWidths() throws {
        for width in [32, 64] {
            let prefix = width == 32 ? "w" : "x"
            let function = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: true)
                .buildFunction(name: "signed_mul_casts", startAddress: 0x1000, instructions: [
                    row(0x1000, "sdiv", "\(prefix)8, \(prefix)12, \(prefix)13"),
                    row(0x1004, "sdiv", "\(prefix)9, \(prefix)14, \(prefix)15"),
                    row(0x1008, "mul", "\(prefix)11, \(prefix)8, \(prefix)9"),
                    row(0x100c, "ret")
                ])
            XCTAssertTrue(function.ssaEnabled, "must exercise scalar SSA")
            let first = try XCTUnwrap(function.instructions.first { $0.source.address == 0x1000 })
            let second = try XCTUnwrap(function.instructions.first { $0.source.address == 0x1004 })
            let multiply = try XCTUnwrap(function.instructions.first { $0.source.address == 0x1008 })
            guard case let .intrinsic(firstDestination?, _, _) = first.operation,
                  case let .intrinsic(secondDestination?, _, _) = second.operation,
                  case let .binary(_, operation, left, right) = multiply.operation else {
                return XCTFail("missing division producers or multiply")
            }
            XCTAssertEqual(operation, "*")
            let spelling = width == 32 ? "(uint32_t)" : "(uint64_t)"
            XCTAssertEqual(left, .unary(op: spelling, value: firstDestination))
            XCTAssertEqual(right, .unary(op: spelling, value: secondDestination))
        }
    }

    func testUMOVWHintAndProjectedRightOperandNeedNoSecondCast() throws {
        let specifications = [
            ("e4 e4 00 4f", "movi", "v4.16b, #7"),
            ("2e 01 80 d2", "mov", "x14, #9"),
            ("6a 00 80 d2", "mov", "x10, #3"),
            ("8e 3c 14 0e", "umov", "w14, v4.s[2]"),
            ("cf 7d 0a 1b", "mul", "w15, w14, w10"),
            ("f0 03 0e 2a", "mov", "w16, w14"),
            ("1f 20 03 d5", "nop", ""),
            ("e5 ff ff b5", "cbnz", "x5, 0x1018"),
            ("c0 03 5f d6", "ret", "")
        ]
        let rows = specifications.enumerated().map { index, item in
            InstructionRow(address: 0x1000 + UInt64(index * 4), bytes: item.0,
                mnemonic: item.1, operands: item.2, hasBreakpoint: false, comment: nil)
        }
        let function = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: true)
            .buildFunction(name: "narrow_typed_copy_loop", startAddress: 0x1000, instructions: rows)
        XCTAssertFalse(function.ssaEnabled, "general vector region must retain the physical-view path")
        let extraction = try XCTUnwrap(function.instructions.first { $0.source.address == 0x100c })
        let rightProducer = try XCTUnwrap(function.instructions.first { $0.source.address == 0x1008 })
        let multiply = try XCTUnwrap(function.instructions.first { $0.source.address == 0x1010 })
        guard case let .intrinsic(destination?, _, _) = extraction.operation,
              case let .assign(rightDestination, _) = rightProducer.operation,
              case let .binary(_, operation, left, right) = multiply.operation else {
            return XCTFail("missing typed extraction, right producer or multiply")
        }
        XCTAssertEqual(operation, "*")
        XCTAssertEqual(left, destination)
        XCTAssertEqual(right, .unary(op: "(uint32_t)", value: rightDestination))
    }
}
