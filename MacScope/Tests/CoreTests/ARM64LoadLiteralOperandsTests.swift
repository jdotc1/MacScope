import Foundation
import XCTest
@testable import MacScope

final class ARM64LoadLiteralOperandsTests: XCTestCase {
    func testAllocatorStubLiteralsHaveCompleteReadOperands() throws {
        try assertLiteral(word: 0x580003f0, address: 0x1104, displacement: 0x7c,
                          mnemonic: "ldr", register: 16, registerWidth: 64, accessWidth: 64,
                          text: "x16, 0x0000000000001180")
        try assertLiteral(word: 0x58000410, address: 0x1100, displacement: 0x80,
                          mnemonic: "ldr", register: 16, registerWidth: 64, accessWidth: 64,
                          text: "x16, 0x0000000000001180")
    }

    func testIntegerWidthsZeroRegisterAndNegativeDisplacement() throws {
        try assertLiteral(word: 0x1800041f, address: 0x1100, displacement: 0x80,
                          mnemonic: "ldr", register: 31, registerWidth: 32, accessWidth: 32,
                          text: "wzr, 0x0000000000001180")
        try assertLiteral(word: 0x98000410, address: 0x1100, displacement: 0x80,
                          mnemonic: "ldrsw", register: 16, registerWidth: 64, accessWidth: 32,
                          text: "x16, 0x0000000000001180")
        try assertLiteral(word: 0x58fffff0, address: 0x1104, displacement: -4,
                          mnemonic: "ldr", register: 16, registerWidth: 64, accessWidth: 64,
                          text: "x16, 0x0000000000001100")
    }

    func testFloatingPointAndPrefetchKeepUnavailableOperands() throws {
        let words: [UInt32] = [0x1c000410, 0x5c000410, 0x9c000410, 0xd8000410]
        for word in words {
            let decoded = try XCTUnwrap(ARM64Decoder().decodeLoadLiteral(
                word: word, bytes: bytes(word), address: 0x1100))
            XCTAssertEqual(decoded.structuredOperands?.coverage, .unavailable)
        }
    }

    private func assertLiteral(word: UInt32, address: UInt64, displacement: Int64,
                               mnemonic: String, register: Int, registerWidth: Int,
                               accessWidth: Int, text: String,
                               file: StaticString = #filePath, line: UInt = #line) throws {
        let decoded = try XCTUnwrap(ARM64Decoder().decodeLoadLiteral(
            word: word, bytes: bytes(word), address: address), file: file, line: line)
        let operands = try XCTUnwrap(decoded.structuredOperands, file: file, line: line)
        XCTAssertEqual(decoded.mnemonic, mnemonic, file: file, line: line)
        XCTAssertEqual(decoded.operands, text, file: file, line: line)
        XCTAssertEqual(operands.coverage, .complete, file: file, line: line)
        XCTAssertEqual(operands.opcodeClass, mnemonic, file: file, line: line)
        XCTAssertEqual(operands.operands, [
            .register(.init(index: register, width: registerWidth,
                            role: register == 31 ? .zero : .ordinary)),
            .pcRelative(.init(baseAddress: address, displacement: displacement,
                              pageRelative: false, format: .hexAddress))
        ], file: file, line: line)
        XCTAssertEqual(operands.semantics?.memoryAccessWidth, accessWidth, file: file, line: line)
        XCTAssertEqual(operands.semantics?.memoryAccess, .read, file: file, line: line)
    }

    private func bytes(_ word: UInt32) -> [UInt8] {
        [UInt8(truncatingIfNeeded: word), UInt8(truncatingIfNeeded: word >> 8),
         UInt8(truncatingIfNeeded: word >> 16), UInt8(truncatingIfNeeded: word >> 24)]
    }
}
