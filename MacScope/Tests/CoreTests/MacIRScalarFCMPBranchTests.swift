import Foundation
import XCTest
@testable import MacScope

final class MacIRScalarFCMPBranchTests: XCTestCase {
    private func row(_ address: UInt64, _ word: UInt32, _ mnemonic: String, _ operands: String = "") -> InstructionRow {
        InstructionRow(address: address,
            bytes: (0..<4).map { String(format: "%02x", (word >> ($0 * 8)) & 255) }.joined(separator: " "),
            mnemonic: mnemonic, operands: operands, hasBreakpoint: false, comment: nil)
    }

    private func rows(word: UInt32 = 0x1e612000, operands: String = "d0, d1", minus: Bool = false) -> [InstructionRow] {
        [row(0x1000, word, "fcmp", operands),
         row(0x1004, minus ? 0x54000064 : 0x54000065, minus ? "b.mi" : "b.pl", "0x1010"),
         row(0x1008, 0x52800000, "mov", "w0, #0"), row(0x100c, 0xd65f03c0, "ret"),
         row(0x1010, 0x52800020, "mov", "w0, #1"), row(0x1014, 0xd65f03c0, "ret")]
    }

    private func lift(_ rows: [InstructionRow]) -> MacIRFunction {
        MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false).buildFunction(name: "fcmp_branch", instructions: rows)
    }

    // Interpret the emitted predicate and Boolean branch, not source mnemonics.
    // Expected outcomes below are hand-derived from Arm NZCV L/E/G/U states.
    private func taken(_ function: MacIRFunction, left: Double, right: Double) throws -> Bool {
        guard case let .compareToBool(destination, op, lhs, rhs) = function.instructions[0].operation,
              case let .unary(leftCast, _) = lhs, case let .unary(rightCast, _) = rhs,
              case let .conditionalBranch(branchOp, flag, zero, _) = function.instructions[1].operation else {
            throw NSError(domain: "FCMPTest", code: 1)
        }
        XCTAssertEqual(leftCast, rightCast)
        XCTAssertTrue(["(float)", "(double)"].contains(leftCast))
        XCTAssertEqual(destination, flag)
        XCTAssertEqual(zero, .immediate(0))
        let a = leftCast == "(float)" ? Double(Float(left)) : left
        let b = rightCast == "(float)" ? Double(Float(right)) : right
        let predicate: Bool
        switch op {
        case "<": predicate = a < b
        case "<=": predicate = a <= b
        case ">": predicate = a > b
        case ">=": predicate = a >= b
        case "==": predicate = a == b
        case "!=": predicate = a != b
        default: throw NSError(domain: "FCMPTest", code: 2)
        }
        switch branchOp {
        case "==": return !predicate
        case "!=": return predicate
        default: throw NSError(domain: "FCMPTest", code: 3)
        }
    }

    func testNativeSingleAndDoubleMIAndPLHaveIEEEOrderedLessSemantics() throws {
        let cases: [(Double, Double, Bool)] = [
            (-1, 1, false), (1, -1, true), (2, 2, true),
            (-0.0, 0.0, true), (0.0, -0.0, true),
            (-.infinity, .infinity, false), (.infinity, -.infinity, true),
            (.infinity, .infinity, true), (-.infinity, -.infinity, true),
            (.nan, 1, true), (1, .nan, true), (.nan, .nan, true),
            (Double(bitPattern: 0x7ff0000000000001), 1, true)
        ]
        for (word, operands): (UInt32, String) in [(0x1e212000, "s0, s1"), (0x1e612000, "d0, d1")] {
            for minus in [false, true] {
                let function = lift(rows(word: word, operands: operands, minus: minus))
                for (a, b, pl) in cases {
                    XCTAssertEqual(try taken(function, left: a, right: b), minus ? !pl : pl)
                }
            }
        }
    }

    func testCapturedDoublePLBytesAndAddresses() throws {
        let function = lift([
            row(0x10000052c, 0x1e612000, "fcmp", "d0, d1"),
            row(0x100000530, 0x540000a5, "b.pl", "0x100000544"),
            row(0x100000534, 0x52800000, "mov", "w0, #0"),
            row(0x100000538, 0xd65f03c0, "ret"),
            row(0x10000053c, 0xd503201f, "nop"), row(0x100000540, 0xd503201f, "nop"),
            row(0x100000544, 0x52800020, "mov", "w0, #1"),
            row(0x100000548, 0xd65f03c0, "ret")])
        XCTAssertTrue(try taken(function, left: .nan, right: 1))
        XCTAssertFalse(try taken(function, left: -1, right: 1))
    }

    func testPrinterKeepsBooleanBoundaryAndDoesNotInvertFloatRelation() {
        let function = lift(rows())
        let printed = PseudocodePrinter().print(function: function).text
        XCTAssertFalse(printed.contains("__unknown(\"fcmp\""), printed)
        XCTAssertFalse(printed.contains("__branch_pl"), printed)
        XCTAssertFalse(printed.contains(">="), printed)
        XCTAssertTrue(printed.contains("(double)"), printed)
        XCTAssertTrue(printed.contains(" < "), printed)
        guard case let .conditionalBranch(op, _, right, _) = function.instructions[1].operation else {
            return XCTFail(printed)
        }
        XCTAssertEqual(op, "==")
        XCTAssertEqual(right, .immediate(0))
    }

    func testRejectsMalformedAndUnsupportedProducerForms() {
        for (word, operands): (UInt32, String) in [
            (0, "d0, d1"), (0x1e612001, "d0, d1"), // invalid/reserved bits
            (0x1e612010, "d0, d1"), // FCMPE is not FCMP
            (0x1ee12000, "h0, h1"), // half precision
            (0x1e612008, "d0, #0.0"), // immediate form outside this slice
            (0x1e612000, "d0, s1"), (0x1e612000, "d0, #1.0"),
            (0x1e612000, "d0, d2"), (0x1e612000, "v0.2d, v1.2d")
        ] {
            let function = lift(rows(word: word, operands: operands))
            guard case .unknown = function.instructions[0].operation else {
                XCTFail("Admitted unsupported \(String(word, radix: 16)) \(operands)"); continue
            }
        }
    }

    func testRejectsBranchEncodingMismatchAndSideEntry() {
        var mismatch = rows()
        mismatch[1] = row(0x1004, 0x54000064, "b.pl", "0x1010")
        var wrongTarget = rows()
        wrongTarget[1] = row(0x1004, 0x54000065, "b.pl", "0x1008")
        let sideEntry = [row(0x0ffc, 0x14000002, "b", "0x1004")] + rows()
        for input in [mismatch, wrongTarget, sideEntry] {
            let function = lift(input)
            let producer = function.instructions.first { $0.source.address == 0x1000 }
            guard case .unknown = producer?.operation else { XCTFail("Pair must remain refused"); continue }
        }
    }

    func testIndirectBranchCanBypassProducerAndMustRefusePair() {
        let function = lift([
            row(0x0ff8, 0xd2820089, "mov", "x9, #0x1004"),
            row(0x0ffc, 0xd61f0120, "br", "x9")
        ] + rows())
        guard let producer = function.instructions.first(where: { $0.source.address == 0x1000 }),
              let consumer = function.instructions.first(where: { $0.source.address == 0x1004 }),
              case .unknown = producer.operation,
              case .intrinsic(nil, "branch_pl", _) = consumer.operation else {
            return XCTFail("Indirect entry at B.PL must not read an undefined predicate temporary")
        }
    }

    func testInterveningRowsCannotReuseFCMPOrEarlierIntegerFlags() {
        for (word, mnemonic, operands): (UInt32, String, String) in [
            (0xd503201f, "nop", ""), (0x7100041f, "cmp", "w0, #1"),
            (0x31000400, "adds", "w0, w0, #1"), (0xd51b4200, "msr", "nzcv, x0"),
            (0x94000008, "bl", "0x1024")
        ] {
            var input = rows()
            input[0] = row(0x0ffc, 0x1e612000, "fcmp", "d0, d1")
            input.insert(row(0x1000, word, mnemonic, operands), at: 1)
            let function = lift(input)
            guard case .unknown = function.instructions[0].operation else { XCTFail("Nonadjacent pair admitted"); continue }
        }
        let input = [row(0x0ffc, 0x7100041f, "cmp", "w0, #1"),
            row(0x1000, 0x1e612000, "fcmp", "d0, d1"),
            row(0x1004, 0x1a820020, "csel", "w0, w1, w2, eq"),
            row(0x1008, 0xd65f03c0, "ret")]
        let function = lift(input)
        guard case .unknown = function.instructions[2].operation else {
            return XCTFail("FCMP must still invalidate prior integer comparison for CSEL")
        }
    }

    func testComparisonUsesActualReachingFPDefinitions() {
        var input = rows(word: 0x1e672060, operands: "d3, d7")
        input.insert(contentsOf: [
            row(0x0ff8, 0x9e670003, "fmov", "d3, x0"),
            row(0x0ffc, 0x9e670027, "fmov", "d7, x1")], at: 0)
        let function = lift(input)
        guard case let .intrinsic(leftDefinition?, "fmov", _) = function.instructions[0].operation,
              case let .intrinsic(rightDefinition?, "fmov", _) = function.instructions[1].operation,
              case let .compareToBool(_, "<", left, right) = function.instructions[2].operation else {
            return XCTFail("Expected two FP definitions and an admitted comparison")
        }
        XCTAssertNotEqual(leftDefinition, rightDefinition)
        XCTAssertEqual(left, .unary(op: "(double)", value: leftDefinition))
        XCTAssertEqual(right, .unary(op: "(double)", value: rightDefinition))

        // An unsupported consumer retains the original FCMP read snapshot.
        input[3] = row(0x1004, 0x54000060, "b.eq", "0x1010")
        let original = lift(input)
        guard case let .unknown(nil, reads, "fcmp", _) = original.instructions[2].operation else {
            return XCTFail("Expected original opaque FCMP reads")
        }
        XCTAssertEqual(reads.mayRead.first { $0.register == "d3" }?.value, leftDefinition)
        XCTAssertEqual(reads.mayRead.first { $0.register == "d7" }?.value, rightDefinition)
    }

    func testStatusAccessAndSSAFallbackRemainConservative() {
        for (word, mnemonic, operands): (UInt32, String, String) in [
            (0xd53b4420, "mrs", "x0, fpsr"), (0xd53b4400, "mrs", "x0, fpcr"),
            (0xd51b4420, "msr", "fpsr, x0"), (0xd51b4400, "msr", "fpcr, x0")
        ] {
            var input = rows()
            // Status access is on the active fallthrough path, before RET.
            input[2] = row(0x1008, word, mnemonic, operands)
            let function = lift(input)
            guard case .unknown = function.instructions[0].operation,
                  case .unknown = function.instructions[2].operation else {
                XCTFail("Observable FP state must preserve the original FCMP/status refusals")
                continue
            }
        }
        let ssa = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: true)
            .buildFunction(name: "fcmp_ssa", instructions: rows())
        XCTAssertFalse(ssa.instructions.contains { instruction in
            guard instruction.source.address == 0x1000 else { return false }
            if case .compareToBool = instruction.operation { return true }
            return false
        })
    }
}
