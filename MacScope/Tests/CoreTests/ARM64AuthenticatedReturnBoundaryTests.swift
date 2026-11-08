import Foundation
import XCTest
@testable import MacScope

/// Fixed fields from LLVM llvmorg-21.1.0 AuthReturn and SignAuthReturnReg.
/// These source-authored fixtures have not been executed or assembled locally.
final class ARM64AuthenticatedReturnBoundaryTests: XCTestCase {
    private func decode(_ word: UInt32) throws -> DecodedInstruction {
        var littleEndian = word.littleEndian
        let instructions = withUnsafeBytes(of: &littleEndian) {
            ARM64Decoder().decode(Data($0), baseAddress: 0x1000, maxInstructionCount: 1)
        }
        return try XCTUnwrap(instructions.first)
    }

    func testAllocatedFixedAuthenticatedReturnsRemainReturns() throws {
        let cases: [(UInt32, String)] = [
            (0xd65f0bff, "retaa"), (0xd65f0fff, "retab"),
            (0xd69f0bff, "eretaa"), (0xd69f0fff, "eretab")
        ]
        for (word, name) in cases {
            let actual = try decode(word)
            XCTAssertEqual(actual.mnemonic, name)
            XCTAssertEqual(actual.operands, "")
            XCTAssertEqual(actual.flow, .return)
            XCTAssertNil(actual.branchTarget)
        }
    }

    func testPAuthLRRegisterModifierRemainsAllocated() throws {
        for (word, name) in [(UInt32(0xd65f0be1), "retaasppcr"), (0xd65f0fe1, "retabsppcr")] {
            let actual = try decode(word)
            XCTAssertEqual(actual.mnemonic, name)
            XCTAssertEqual(actual.operands, "x1")
            XCTAssertEqual(actual.flow, .return)
        }
    }

    func testReservedAuthenticatedReturnRnDoesNotAcquireReturnFlow() throws {
        for word in [UInt32(0xd65f081f), 0xd65f0c1f, 0xd65f0801, 0xd65f0c01, 0xd65f0bdf] {
            let actual = try decode(word)
            XCTAssertEqual(actual.mnemonic, "unknown")
            XCTAssertEqual(actual.flow, .normal)
            XCTAssertNil(actual.branchTarget)
        }
    }

    func testExceptionAuthenticatedReturnRequiresBothFixedFields() throws {
        for word in [UInt32(0xd69f081f), 0xd69f0c1f, 0xd69f0be0, 0xd69f0fe0] {
            let actual = try decode(word)
            XCTAssertEqual(actual.mnemonic, "unknown")
            XCTAssertEqual(actual.flow, .normal)
            XCTAssertNil(actual.branchTarget)
        }
    }
}
