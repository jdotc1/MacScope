import XCTest
@testable import MacScope

final class NEONIntegerVectorFormsTests: XCTestCase {
    // Arm A64 XML 2025-12 Operation sections cited for every literal row.
    // Expectations use unbounded integer arithmetic, truncating only at the
    // architectural destination lane width.
    private struct Oracle {
        let id: String
        let mnemonic: String
        let operands: String
        let kind: MacIRNEONLaneOp.Kind
        let bits: Int
        let bytes: Int
        let highHalf: Bool
        let isSigned: Bool
        let shift: Int
        let elementIndex: Int?
        let aliasesDestination: Bool
        let n: MacIRNEONLaneOp.Vector
        let m: MacIRNEONLaneOp.Vector
        let old: MacIRNEONLaneOp.Vector
        let expected: MacIRNEONLaneOp.Vector
        let qc: Bool
        let setsQC: Bool
    }

    func testLiteralArchitecturalOracles() throws {
        let rows: [Oracle] = [
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal-1", mnemonic: "smlal", operands: "v0.8h, v1.8b, v2.8b",
                  kind: .mlal, bits: 8, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0706050403020100, 0x5c5b5a5958575655), m: (0x0706050403020100, 0x5c5b5a5958575655), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x00050001ffffffff, 0x0029001d0013000b), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal-2", mnemonic: "smlal", operands: "v0.8h, v1.8b, v2.8b",
                  kind: .mlal, bits: 8, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x06050403020100ff, 0x5c5b5a5958575655), m: (0x0908070605040302, 0x5c5b5a5958575655), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x00060001fffefffd, 0x002e00210016000d), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal-3", mnemonic: "smlal", operands: "v0.4s, v1.4h, v2.4h",
                  kind: .mlal, bits: 16, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8003800280018000, 0x0058005700560055), m: (0x8003800280018000, 0x0058005700560055), old: (0xfffffffeffffffff, 0xfffffffcfffffffd),
                  expected: (0x3ffeffff3fffffff, 0x3ffd00053ffe0001), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal-4", mnemonic: "smlal", operands: "v0.4s, v1.4h, v2.4h",
                  kind: .mlal, bits: 16, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8002800180007fff, 0x0058005700560055), m: (0x000200010000ffff, 0x0058005700560055), old: (0xfffffffeffffffff, 0xfffffffcfffffffd),
                  expected: (0xfffffffeffff8000, 0xffff0000ffff7ffe), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal-5", mnemonic: "smlal", operands: "v0.2d, v1.2s, v2.2s",
                  kind: .mlal, bits: 32, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000000200000001, 0x0000005600000055), m: (0x00000000ffffffff, 0x0000005600000055), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0xfffffffffffffffe, 0xfffffffffffffffe), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal-6", mnemonic: "smlal", operands: "v0.2d, v1.2s, v2.2s",
                  kind: .mlal, bits: 32, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000000180000000, 0x0000005600000055), m: (0x8000000180000000, 0x0000005600000055), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0x3fffffffffffffff, 0x3ffffffeffffffff), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal-7", mnemonic: "smlal", operands: "v0.2d, v1.2s, v2.2s",
                  kind: .mlal, bits: 32, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x00000000ffffffff, 0x0000005600000055), m: (0x0000000200000001, 0x0000005600000055), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0xfffffffffffffffe, 0xfffffffffffffffe), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal-8", mnemonic: "smlal", operands: "v0.8h, v1.8b, v2.8b",
                  kind: .mlal, bits: 8, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0e0d0c0b0a090807, 0x5c5b5a5958575655), m: (0x5c5b5a5958575655, 0x5c5b5a5958575655), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x036c030c02ae0252, 0x05000498043203ce), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal2-1", mnemonic: "smlal2", operands: "v0.8h, v1.16b, v2.16b",
                  kind: .mlal, bits: 8, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x5c5b5a5958575655, 0x0706050403020100), m: (0x5c5b5a5958575655, 0x0706050403020100), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x00050001ffffffff, 0x0029001d0013000b), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal2-2", mnemonic: "smlal2", operands: "v0.8h, v1.16b, v2.16b",
                  kind: .mlal, bits: 8, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x5c5b5a5958575655, 0x06050403020100ff), m: (0x5c5b5a5958575655, 0x0908070605040302), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x00060001fffefffd, 0x002e00210016000d), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal2-3", mnemonic: "smlal2", operands: "v0.4s, v1.8h, v2.8h",
                  kind: .mlal, bits: 16, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0058005700560055, 0x8003800280018000), m: (0x0058005700560055, 0x8003800280018000), old: (0xfffffffeffffffff, 0xfffffffcfffffffd),
                  expected: (0x3ffeffff3fffffff, 0x3ffd00053ffe0001), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal2-4", mnemonic: "smlal2", operands: "v0.4s, v1.8h, v2.8h",
                  kind: .mlal, bits: 16, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0058005700560055, 0x8002800180007fff), m: (0x0058005700560055, 0x000200010000ffff), old: (0xfffffffeffffffff, 0xfffffffcfffffffd),
                  expected: (0xfffffffeffff8000, 0xffff0000ffff7ffe), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal2-5", mnemonic: "smlal2", operands: "v0.2d, v1.4s, v2.4s",
                  kind: .mlal, bits: 32, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000005600000055, 0x0000000200000001), m: (0x0000005600000055, 0x00000000ffffffff), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0xfffffffffffffffe, 0xfffffffffffffffe), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal2-6", mnemonic: "smlal2", operands: "v0.2d, v1.4s, v2.4s",
                  kind: .mlal, bits: 32, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000005600000055, 0x8000000180000000), m: (0x0000005600000055, 0x8000000180000000), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0x3fffffffffffffff, 0x3ffffffeffffffff), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal2-7", mnemonic: "smlal2", operands: "v0.2d, v1.4s, v2.4s",
                  kind: .mlal, bits: 32, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000005600000055, 0x00000000ffffffff), m: (0x0000005600000055, 0x0000000200000001), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0xfffffffffffffffe, 0xfffffffffffffffe), qc: false, setsQC: false),
            // smlal_advsimd_vec.xml#Operation
            .init(id: "smlal2-8", mnemonic: "smlal2", operands: "v0.8h, v1.16b, v2.16b",
                  kind: .mlal, bits: 8, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x5c5b5a5958575655, 0x0e0d0c0b0a090807), m: (0x5c5b5a5958575655, 0x5c5b5a5958575655), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x036c030c02ae0252, 0x05000498043203ce), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll-1", mnemonic: "ushll", operands: "v0.8h, v1.8b, #0",
                  kind: .shll, bits: 8, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0706050403020100, 0x5c5b5a5958575655), m: (0x0706050403020100, 0x5c5b5a5958575655), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x0003000200010000, 0x0007000600050004), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll-2", mnemonic: "ushll", operands: "v0.8h, v1.8b, #1",
                  kind: .shll, bits: 8, bytes: 16, highHalf: false, isSigned: false, shift: 1,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x06050403020100ff, 0x5c5b5a5958575655), m: (0x0908070605040302, 0x5c5b5a5958575655), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x00040002000001fe, 0x000c000a00080006), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll-3", mnemonic: "ushll", operands: "v0.4s, v1.4h, #15",
                  kind: .shll, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 15,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8003800280018000, 0x0058005700560055), m: (0x8003800280018000, 0x0058005700560055), old: (0xfffffffeffffffff, 0xfffffffcfffffffd),
                  expected: (0x4000800040000000, 0x4001800040010000), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll-4", mnemonic: "ushll", operands: "v0.4s, v1.4h, #0",
                  kind: .shll, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8002800180007fff, 0x0058005700560055), m: (0x000200010000ffff, 0x0058005700560055), old: (0xfffffffeffffffff, 0xfffffffcfffffffd),
                  expected: (0x0000800000007fff, 0x0000800200008001), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll-5", mnemonic: "ushll", operands: "v0.2d, v1.2s, #1",
                  kind: .shll, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 1,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000000200000001, 0x0000005600000055), m: (0x00000000ffffffff, 0x0000005600000055), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0x0000000000000002, 0x0000000000000004), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll-6", mnemonic: "ushll", operands: "v0.2d, v1.2s, #31",
                  kind: .shll, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 31,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000000180000000, 0x0000005600000055), m: (0x8000000180000000, 0x0000005600000055), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0x4000000000000000, 0x4000000080000000), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll-7", mnemonic: "ushll", operands: "v0.2d, v1.2s, #0",
                  kind: .shll, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x00000000ffffffff, 0x0000005600000055), m: (0x0000000200000001, 0x0000005600000055), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0x00000000ffffffff, 0x0000000000000000), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll-8", mnemonic: "ushll", operands: "v0.8h, v1.8b, #3",
                  kind: .shll, bits: 8, bytes: 16, highHalf: false, isSigned: false, shift: 3,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0e0d0c0b0a090807, 0x5c5b5a5958575655), m: (0x5c5b5a5958575655, 0x5c5b5a5958575655), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x0050004800400038, 0x0070006800600058), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll2-1", mnemonic: "ushll2", operands: "v0.8h, v1.16b, #0",
                  kind: .shll, bits: 8, bytes: 16, highHalf: true, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x5c5b5a5958575655, 0x0706050403020100), m: (0x5c5b5a5958575655, 0x0706050403020100), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x0003000200010000, 0x0007000600050004), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll2-2", mnemonic: "ushll2", operands: "v0.8h, v1.16b, #1",
                  kind: .shll, bits: 8, bytes: 16, highHalf: true, isSigned: false, shift: 1,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x5c5b5a5958575655, 0x06050403020100ff), m: (0x5c5b5a5958575655, 0x0908070605040302), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x00040002000001fe, 0x000c000a00080006), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll2-3", mnemonic: "ushll2", operands: "v0.4s, v1.8h, #15",
                  kind: .shll, bits: 16, bytes: 16, highHalf: true, isSigned: false, shift: 15,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0058005700560055, 0x8003800280018000), m: (0x0058005700560055, 0x8003800280018000), old: (0xfffffffeffffffff, 0xfffffffcfffffffd),
                  expected: (0x4000800040000000, 0x4001800040010000), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll2-4", mnemonic: "ushll2", operands: "v0.4s, v1.8h, #0",
                  kind: .shll, bits: 16, bytes: 16, highHalf: true, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0058005700560055, 0x8002800180007fff), m: (0x0058005700560055, 0x000200010000ffff), old: (0xfffffffeffffffff, 0xfffffffcfffffffd),
                  expected: (0x0000800000007fff, 0x0000800200008001), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll2-5", mnemonic: "ushll2", operands: "v0.2d, v1.4s, #1",
                  kind: .shll, bits: 32, bytes: 16, highHalf: true, isSigned: false, shift: 1,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000005600000055, 0x0000000200000001), m: (0x0000005600000055, 0x00000000ffffffff), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0x0000000000000002, 0x0000000000000004), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll2-6", mnemonic: "ushll2", operands: "v0.2d, v1.4s, #31",
                  kind: .shll, bits: 32, bytes: 16, highHalf: true, isSigned: false, shift: 31,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000005600000055, 0x8000000180000000), m: (0x0000005600000055, 0x8000000180000000), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0x4000000000000000, 0x4000000080000000), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll2-7", mnemonic: "ushll2", operands: "v0.2d, v1.4s, #0",
                  kind: .shll, bits: 32, bytes: 16, highHalf: true, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000005600000055, 0x00000000ffffffff), m: (0x0000005600000055, 0x0000000200000001), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0x00000000ffffffff, 0x0000000000000000), qc: false, setsQC: false),
            // ushll_advsimd.xml#Operation
            .init(id: "ushll2-8", mnemonic: "ushll2", operands: "v0.8h, v1.16b, #3",
                  kind: .shll, bits: 8, bytes: 16, highHalf: true, isSigned: false, shift: 3,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x5c5b5a5958575655, 0x0e0d0c0b0a090807), m: (0x5c5b5a5958575655, 0x5c5b5a5958575655), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x0050004800400038, 0x0070006800600058), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll-1", mnemonic: "sshll", operands: "v0.8h, v1.8b, #0",
                  kind: .shll, bits: 8, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0706050403020100, 0x5c5b5a5958575655), m: (0x0706050403020100, 0x5c5b5a5958575655), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x0003000200010000, 0x0007000600050004), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll-2", mnemonic: "sshll", operands: "v0.8h, v1.8b, #1",
                  kind: .shll, bits: 8, bytes: 16, highHalf: false, isSigned: true, shift: 1,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x06050403020100ff, 0x5c5b5a5958575655), m: (0x0908070605040302, 0x5c5b5a5958575655), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x000400020000fffe, 0x000c000a00080006), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll-3", mnemonic: "sshll", operands: "v0.4s, v1.4h, #15",
                  kind: .shll, bits: 16, bytes: 16, highHalf: false, isSigned: true, shift: 15,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8003800280018000, 0x0058005700560055), m: (0x8003800280018000, 0x0058005700560055), old: (0xfffffffeffffffff, 0xfffffffcfffffffd),
                  expected: (0xc0008000c0000000, 0xc0018000c0010000), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll-4", mnemonic: "sshll", operands: "v0.4s, v1.4h, #0",
                  kind: .shll, bits: 16, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8002800180007fff, 0x0058005700560055), m: (0x000200010000ffff, 0x0058005700560055), old: (0xfffffffeffffffff, 0xfffffffcfffffffd),
                  expected: (0xffff800000007fff, 0xffff8002ffff8001), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll-5", mnemonic: "sshll", operands: "v0.2d, v1.2s, #1",
                  kind: .shll, bits: 32, bytes: 16, highHalf: false, isSigned: true, shift: 1,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000000200000001, 0x0000005600000055), m: (0x00000000ffffffff, 0x0000005600000055), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0x0000000000000002, 0x0000000000000004), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll-6", mnemonic: "sshll", operands: "v0.2d, v1.2s, #31",
                  kind: .shll, bits: 32, bytes: 16, highHalf: false, isSigned: true, shift: 31,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000000180000000, 0x0000005600000055), m: (0x8000000180000000, 0x0000005600000055), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0xc000000000000000, 0xc000000080000000), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll-7", mnemonic: "sshll", operands: "v0.2d, v1.2s, #0",
                  kind: .shll, bits: 32, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x00000000ffffffff, 0x0000005600000055), m: (0x0000000200000001, 0x0000005600000055), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0xffffffffffffffff, 0x0000000000000000), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll-8", mnemonic: "sshll", operands: "v0.8h, v1.8b, #3",
                  kind: .shll, bits: 8, bytes: 16, highHalf: false, isSigned: true, shift: 3,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0e0d0c0b0a090807, 0x5c5b5a5958575655), m: (0x5c5b5a5958575655, 0x5c5b5a5958575655), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x0050004800400038, 0x0070006800600058), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll2-1", mnemonic: "sshll2", operands: "v0.8h, v1.16b, #0",
                  kind: .shll, bits: 8, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x5c5b5a5958575655, 0x0706050403020100), m: (0x5c5b5a5958575655, 0x0706050403020100), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x0003000200010000, 0x0007000600050004), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll2-2", mnemonic: "sshll2", operands: "v0.8h, v1.16b, #1",
                  kind: .shll, bits: 8, bytes: 16, highHalf: true, isSigned: true, shift: 1,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x5c5b5a5958575655, 0x06050403020100ff), m: (0x5c5b5a5958575655, 0x0908070605040302), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x000400020000fffe, 0x000c000a00080006), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll2-3", mnemonic: "sshll2", operands: "v0.4s, v1.8h, #15",
                  kind: .shll, bits: 16, bytes: 16, highHalf: true, isSigned: true, shift: 15,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0058005700560055, 0x8003800280018000), m: (0x0058005700560055, 0x8003800280018000), old: (0xfffffffeffffffff, 0xfffffffcfffffffd),
                  expected: (0xc0008000c0000000, 0xc0018000c0010000), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll2-4", mnemonic: "sshll2", operands: "v0.4s, v1.8h, #0",
                  kind: .shll, bits: 16, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0058005700560055, 0x8002800180007fff), m: (0x0058005700560055, 0x000200010000ffff), old: (0xfffffffeffffffff, 0xfffffffcfffffffd),
                  expected: (0xffff800000007fff, 0xffff8002ffff8001), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll2-5", mnemonic: "sshll2", operands: "v0.2d, v1.4s, #1",
                  kind: .shll, bits: 32, bytes: 16, highHalf: true, isSigned: true, shift: 1,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000005600000055, 0x0000000200000001), m: (0x0000005600000055, 0x00000000ffffffff), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0x0000000000000002, 0x0000000000000004), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll2-6", mnemonic: "sshll2", operands: "v0.2d, v1.4s, #31",
                  kind: .shll, bits: 32, bytes: 16, highHalf: true, isSigned: true, shift: 31,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000005600000055, 0x8000000180000000), m: (0x0000005600000055, 0x8000000180000000), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0xc000000000000000, 0xc000000080000000), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll2-7", mnemonic: "sshll2", operands: "v0.2d, v1.4s, #0",
                  kind: .shll, bits: 32, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000005600000055, 0x00000000ffffffff), m: (0x0000005600000055, 0x0000000200000001), old: (0xffffffffffffffff, 0xfffffffffffffffe),
                  expected: (0xffffffffffffffff, 0x0000000000000000), qc: false, setsQC: false),
            // sshll_advsimd.xml#Operation
            .init(id: "sshll2-8", mnemonic: "sshll2", operands: "v0.8h, v1.16b, #3",
                  kind: .shll, bits: 8, bytes: 16, highHalf: true, isSigned: true, shift: 3,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x5c5b5a5958575655, 0x0e0d0c0b0a090807), m: (0x5c5b5a5958575655, 0x5c5b5a5958575655), old: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb),
                  expected: (0x0050004800400038, 0x0070006800600058), qc: false, setsQC: false),
            // sqdmulh_advsimd_vec.xml#Operation
            .init(id: "sqdmulh-1", mnemonic: "sqdmulh", operands: "v0.4h, v1.4h, v2.4h",
                  kind: .sqdmulh, bits: 16, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000800080008000, 0x0000000000000000), m: (0x8000800080008000, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x7fff7fff7fff7fff, 0x0000000000000000), qc: true, setsQC: true),
            // sqdmulh_advsimd_vec.xml#Operation
            .init(id: "sqdmulh-2", mnemonic: "sqdmulh", operands: "v0.4s, v1.4s, v2.4s",
                  kind: .sqdmulh, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000000080000000, 0x8000000080000000), m: (0x8000000080000000, 0x8000000080000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x7fffffff7fffffff, 0x7fffffff7fffffff), qc: true, setsQC: true),
            // sqdmulh_advsimd_vec.xml#Operation
            .init(id: "sqdmulh-3", mnemonic: "sqdmulh", operands: "v0.4h, v1.4h, v2.4h",
                  kind: .sqdmulh, bits: 16, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000800080008000, 0x0000000000000000), m: (0x7fff7fff7fff7fff, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x8001800180018001, 0x0000000000000000), qc: false, setsQC: true),
            // sqdmulh_advsimd_vec.xml#Operation
            .init(id: "sqdmulh-4", mnemonic: "sqdmulh", operands: "v0.4s, v1.4s, v2.4s",
                  kind: .sqdmulh, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x7fffffff7fffffff, 0x7fffffff7fffffff), m: (0x7fffffff7fffffff, 0x7fffffff7fffffff), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x7ffffffe7ffffffe, 0x7ffffffe7ffffffe), qc: false, setsQC: true),
            // sqdmulh_advsimd_vec.xml#Operation
            .init(id: "sqdmulh-5", mnemonic: "sqdmulh", operands: "v0.4h, v1.4h, v2.4h",
                  kind: .sqdmulh, bits: 16, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000800080008000, 0x0000000000000000), m: (0x0001000100010001, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0x0000000000000000), qc: false, setsQC: true),
            // sqdmulh_advsimd_vec.xml#Operation
            .init(id: "sqdmulh-6", mnemonic: "sqdmulh", operands: "v0.4s, v1.4s, v2.4s",
                  kind: .sqdmulh, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000000100000001, 0x0000000100000001), m: (0xffffffffffffffff, 0xffffffffffffffff), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0xffffffffffffffff), qc: false, setsQC: true),
            // sqdmulh_advsimd_vec.xml#Operation
            .init(id: "sqdmulh-7", mnemonic: "sqdmulh", operands: "v0.4h, v1.4h, v2.4h",
                  kind: .sqdmulh, bits: 16, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0x0000000000000000), m: (0xffffffffffffffff, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: true),
            // sqdmulh_advsimd_vec.xml#Operation
            .init(id: "sqdmulh-8", mnemonic: "sqdmulh", operands: "v0.4s, v1.4s, v2.4s",
                  kind: .sqdmulh, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x7fffffff7fffffff, 0x7fffffff7fffffff), m: (0x8000000080000000, 0x8000000080000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x8000000180000001, 0x8000000180000001), qc: false, setsQC: true),
            // cmlt_advsimd.xml#Operation
            .init(id: "cmlt-1", mnemonic: "cmlt", operands: "v0.8b, v1.8b, #0",
                  kind: .cmltz, bits: 8, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000000000000000, 0x0000000000000000), m: (0x0000000000000000, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // cmlt_advsimd.xml#Operation
            .init(id: "cmlt-2", mnemonic: "cmlt", operands: "v0.8h, v1.8h, #0",
                  kind: .cmltz, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0xffffffffffffffff), m: (0x0002000200020002, 0x0002000200020002), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0xffffffffffffffff), qc: false, setsQC: false),
            // cmlt_advsimd.xml#Operation
            .init(id: "cmlt-3", mnemonic: "cmlt", operands: "v0.2s, v1.2s, #0",
                  kind: .cmltz, bits: 32, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000000080000000, 0x0000000000000000), m: (0x8000000080000000, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0x0000000000000000), qc: false, setsQC: false),
            // cmlt_advsimd.xml#Operation
            .init(id: "cmlt-4", mnemonic: "cmlt", operands: "v0.2d, v1.2d, #0",
                  kind: .cmltz, bits: 64, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x7fffffffffffffff, 0x7fffffffffffffff), m: (0xffffffffffffffff, 0xffffffffffffffff), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // cmlt_advsimd.xml#Operation
            .init(id: "cmlt-5", mnemonic: "cmlt", operands: "v0.8b, v1.8b, #0",
                  kind: .cmltz, bits: 8, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0101010101010101, 0x0000000000000000), m: (0xffffffffffffffff, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // cmlt_advsimd.xml#Operation
            .init(id: "cmlt-6", mnemonic: "cmlt", operands: "v0.8h, v1.8h, #0",
                  kind: .cmltz, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000800080008000, 0x8000800080008000), m: (0x8000800080008000, 0x8000800080008000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0xffffffffffffffff), qc: false, setsQC: false),
            // cmlt_advsimd.xml#Operation
            .init(id: "cmlt-7", mnemonic: "cmlt", operands: "v0.2s, v1.2s, #0",
                  kind: .cmltz, bits: 32, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0x0000000000000000), m: (0x0000000100000001, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0x0000000000000000), qc: false, setsQC: false),
            // cmlt_advsimd.xml#Operation
            .init(id: "cmlt-8", mnemonic: "cmlt", operands: "v0.2d, v1.2d, #0",
                  kind: .cmltz, bits: 64, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000000000000007, 0x0000000000000007), m: (0x0000000000000055, 0x0000000000000055), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // abs_advsimd.xml#Operation
            .init(id: "abs-1", mnemonic: "abs", operands: "v0.8b, v1.8b",
                  kind: .abs, bits: 8, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000000000000000, 0x0000000000000000), m: (0x0000000000000000, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // abs_advsimd.xml#Operation
            .init(id: "abs-2", mnemonic: "abs", operands: "v0.8h, v1.8h",
                  kind: .abs, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0xffffffffffffffff), m: (0x0002000200020002, 0x0002000200020002), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0001000100010001, 0x0001000100010001), qc: false, setsQC: false),
            // abs_advsimd.xml#Operation
            .init(id: "abs-3", mnemonic: "abs", operands: "v0.2s, v1.2s",
                  kind: .abs, bits: 32, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000000080000000, 0x0000000000000000), m: (0x8000000080000000, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x8000000080000000, 0x0000000000000000), qc: false, setsQC: false),
            // abs_advsimd.xml#Operation
            .init(id: "abs-4", mnemonic: "abs", operands: "v0.2d, v1.2d",
                  kind: .abs, bits: 64, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x7fffffffffffffff, 0x7fffffffffffffff), m: (0xffffffffffffffff, 0xffffffffffffffff), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x7fffffffffffffff, 0x7fffffffffffffff), qc: false, setsQC: false),
            // abs_advsimd.xml#Operation
            .init(id: "abs-5", mnemonic: "abs", operands: "v0.8b, v1.8b",
                  kind: .abs, bits: 8, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0101010101010101, 0x0000000000000000), m: (0xffffffffffffffff, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0101010101010101, 0x0000000000000000), qc: false, setsQC: false),
            // abs_advsimd.xml#Operation
            .init(id: "abs-6", mnemonic: "abs", operands: "v0.8h, v1.8h",
                  kind: .abs, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000800080008000, 0x8000800080008000), m: (0x8000800080008000, 0x8000800080008000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x8000800080008000, 0x8000800080008000), qc: false, setsQC: false),
            // abs_advsimd.xml#Operation
            .init(id: "abs-7", mnemonic: "abs", operands: "v0.2s, v1.2s",
                  kind: .abs, bits: 32, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0x0000000000000000), m: (0x0000000100000001, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000100000001, 0x0000000000000000), qc: false, setsQC: false),
            // abs_advsimd.xml#Operation
            .init(id: "abs-8", mnemonic: "abs", operands: "v0.2d, v1.2d",
                  kind: .abs, bits: 64, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000000000000007, 0x0000000000000007), m: (0x0000000000000055, 0x0000000000000055), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000007, 0x0000000000000007), qc: false, setsQC: false),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn-1", mnemonic: "rshrn", operands: "v0.8b, v1.8h, #1",
                  kind: .rshrn, bits: 8, bytes: 16, highHalf: false, isSigned: false, shift: 1,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0003000200010000, 0x0007000600050004), m: (0x0003000200010000, 0x0007000600050004), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0403030202010100, 0x0000000000000000), qc: false, setsQC: false),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn-2", mnemonic: "rshrn", operands: "v0.8b, v1.8h, #8",
                  kind: .rshrn, bits: 8, bytes: 16, highHalf: false, isSigned: false, shift: 8,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x000200010000ffff, 0x0006000500040003), m: (0x0004000300020001, 0x0008000700060005), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn-3", mnemonic: "rshrn", operands: "v0.4h, v1.4s, #1",
                  kind: .rshrn, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 1,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000800100008000, 0x0000800300008002), m: (0x0000000100000000, 0x0000000300000002), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x4002400140014000, 0x0000000000000000), qc: false, setsQC: false),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn-4", mnemonic: "rshrn", operands: "v0.4h, v1.4s, #16",
                  kind: .rshrn, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 16,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x000100000000ffff, 0x0001000200010001), m: (0x0000000200000001, 0x0000000400000003), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0001000100010001, 0x0000000000000000), qc: false, setsQC: false),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn-5", mnemonic: "rshrn", operands: "v0.2s, v1.2d, #1",
                  kind: .rshrn, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 1,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000000100000000, 0x0000000100000001), m: (0x0000000000000000, 0x0000000000000001), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x8000000180000000, 0x0000000000000000), qc: false, setsQC: false),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn-6", mnemonic: "rshrn", operands: "v0.2s, v1.2d, #32",
                  kind: .rshrn, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 32,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000000000000000, 0x8000000000000001), m: (0x0000000000000001, 0x0000000000000002), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x8000000080000000, 0x0000000000000000), qc: false, setsQC: false),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn-7", mnemonic: "rshrn", operands: "v0.2s, v1.2d, #32",
                  kind: .rshrn, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 32,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0x0000000000000000), m: (0xffffffffffffffff, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn-8", mnemonic: "rshrn", operands: "v0.8b, v1.8h, #1",
                  kind: .rshrn, bits: 8, bytes: 16, highHalf: false, isSigned: false, shift: 1,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x000200010000ffff, 0x0006000500040003), m: (0x0004000300020001, 0x0008000700060005), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0303020201010000, 0x0000000000000000), qc: false, setsQC: false),
            // cmtst_advsimd.xml#Operation
            .init(id: "cmtst-1", mnemonic: "cmtst", operands: "v0.8b, v1.8b, v2.8b",
                  kind: .cmtst, bits: 8, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000000000000000, 0x0000000000000000), m: (0x0000000000000000, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // cmtst_advsimd.xml#Operation
            .init(id: "cmtst-2", mnemonic: "cmtst", operands: "v0.8h, v1.8h, v2.8h",
                  kind: .cmtst, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0xffffffffffffffff), m: (0x0002000200020002, 0x0002000200020002), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0xffffffffffffffff), qc: false, setsQC: false),
            // cmtst_advsimd.xml#Operation
            .init(id: "cmtst-3", mnemonic: "cmtst", operands: "v0.2s, v1.2s, v2.2s",
                  kind: .cmtst, bits: 32, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000000080000000, 0x0000000000000000), m: (0x8000000080000000, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0x0000000000000000), qc: false, setsQC: false),
            // cmtst_advsimd.xml#Operation
            .init(id: "cmtst-4", mnemonic: "cmtst", operands: "v0.2d, v1.2d, v2.2d",
                  kind: .cmtst, bits: 64, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x7fffffffffffffff, 0x7fffffffffffffff), m: (0xffffffffffffffff, 0xffffffffffffffff), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0xffffffffffffffff), qc: false, setsQC: false),
            // cmtst_advsimd.xml#Operation
            .init(id: "cmtst-5", mnemonic: "cmtst", operands: "v0.8b, v1.8b, v2.8b",
                  kind: .cmtst, bits: 8, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0101010101010101, 0x0000000000000000), m: (0xffffffffffffffff, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0x0000000000000000), qc: false, setsQC: false),
            // cmtst_advsimd.xml#Operation
            .init(id: "cmtst-6", mnemonic: "cmtst", operands: "v0.8h, v1.8h, v2.8h",
                  kind: .cmtst, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000800080008000, 0x8000800080008000), m: (0x8000800080008000, 0x8000800080008000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0xffffffffffffffff), qc: false, setsQC: false),
            // cmtst_advsimd.xml#Operation
            .init(id: "cmtst-7", mnemonic: "cmtst", operands: "v0.2s, v1.2s, v2.2s",
                  kind: .cmtst, bits: 32, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0x0000000000000000), m: (0x0000000100000001, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0x0000000000000000), qc: false, setsQC: false),
            // cmtst_advsimd.xml#Operation
            .init(id: "cmtst-8", mnemonic: "cmtst", operands: "v0.2d, v1.2d, v2.2d",
                  kind: .cmtst, bits: 64, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000000000000007, 0x0000000000000007), m: (0x0000000000000055, 0x0000000000000055), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0xffffffffffffffff), qc: false, setsQC: false),
            // ushl_advsimd.xml#Operation
            .init(id: "ushl-1", mnemonic: "ushl", operands: "v0.8b, v1.8b, v2.8b",
                  kind: .ushl, bits: 8, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0x0000000000000000), m: (0x0808080808080808, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // ushl_advsimd.xml#Operation
            .init(id: "ushl-2", mnemonic: "ushl", operands: "v0.8h, v1.8h, v2.8h",
                  kind: .ushl, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0xffffffffffffffff), m: (0x0101010101010101, 0x0101010101010101), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xfffefffefffefffe, 0xfffefffefffefffe), qc: false, setsQC: false),
            // ushl_advsimd.xml#Operation
            .init(id: "ushl-3", mnemonic: "ushl", operands: "v0.2s, v1.2s, v2.2s",
                  kind: .ushl, bits: 32, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0x0000000000000000), m: (0x0000011f0000011f, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x8000000080000000, 0x0000000000000000), qc: false, setsQC: false),
            // ushl_advsimd.xml#Operation
            .init(id: "ushl-4", mnemonic: "ushl", operands: "v0.2d, v1.2d, v2.2d",
                  kind: .ushl, bits: 64, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0xffffffffffffffff), m: (0x0000000000000140, 0x0000000000000140), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // ushl_advsimd.xml#Operation
            .init(id: "ushl-5", mnemonic: "ushl", operands: "v0.8b, v1.8b, v2.8b",
                  kind: .ushl, bits: 8, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0x0000000000000000), m: (0xf8f8f8f8f8f8f8f8, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // ushl_advsimd.xml#Operation
            .init(id: "ushl-6", mnemonic: "ushl", operands: "v0.8h, v1.8h, v2.8h",
                  kind: .ushl, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0xffffffffffffffff), m: (0xfff1fff1fff1fff1, 0xfff1fff1fff1fff1), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0001000100010001, 0x0001000100010001), qc: false, setsQC: false),
            // ushl_advsimd.xml#Operation
            .init(id: "ushl-7", mnemonic: "ushl", operands: "v0.2s, v1.2s, v2.2s",
                  kind: .ushl, bits: 32, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0x0000000000000000), m: (0x000001ff000001ff, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x7fffffff7fffffff, 0x0000000000000000), qc: false, setsQC: false),
            // ushl_advsimd.xml#Operation
            .init(id: "ushl-8", mnemonic: "ushl", operands: "v0.2d, v1.2d, v2.2d",
                  kind: .ushl, bits: 64, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0xffffffffffffffff), m: (0x0000000000000180, 0x0000000000000180), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // addhn_advsimd.xml#Operation
            .init(id: "addhn-1", mnemonic: "addhn", operands: "v0.8b, v1.8h, v2.8h",
                  kind: .addhn, bits: 8, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0003000200010000, 0x0007000600050004), m: (0x0003000200010000, 0x0007000600050004), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // addhn_advsimd.xml#Operation
            .init(id: "addhn-2", mnemonic: "addhn", operands: "v0.8b, v1.8h, v2.8h",
                  kind: .addhn, bits: 8, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x000200010000ffff, 0x0006000500040003), m: (0x0004000300020001, 0x0008000700060005), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // addhn_advsimd.xml#Operation
            .init(id: "addhn-3", mnemonic: "addhn", operands: "v0.4h, v1.4s, v2.4s",
                  kind: .addhn, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000800100008000, 0x0000800300008002), m: (0x0000000100000000, 0x0000000300000002), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000000000000, 0x0000000000000000), qc: false, setsQC: false),
            // addhn_advsimd.xml#Operation
            .init(id: "addhn-4", mnemonic: "addhn", operands: "v0.4h, v1.4s, v2.4s",
                  kind: .addhn, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x000100000000ffff, 0x0001000200010001), m: (0x0000000200000001, 0x0000000400000003), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0001000100010001, 0x0000000000000000), qc: false, setsQC: false),
            // addhn_advsimd.xml#Operation
            .init(id: "addhn-5", mnemonic: "addhn", operands: "v0.2s, v1.2d, v2.2d",
                  kind: .addhn, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x0000000100000000, 0x0000000100000001), m: (0x0000000000000000, 0x0000000000000001), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x0000000100000001, 0x0000000000000000), qc: false, setsQC: false),
            // addhn_advsimd.xml#Operation
            .init(id: "addhn-6", mnemonic: "addhn", operands: "v0.2s, v1.2d, v2.2d",
                  kind: .addhn, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0x8000000000000000, 0x8000000000000001), m: (0x0000000000000001, 0x0000000000000002), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x8000000080000000, 0x0000000000000000), qc: false, setsQC: false),
            // addhn_advsimd.xml#Operation
            .init(id: "addhn-7", mnemonic: "addhn", operands: "v0.2s, v1.2d, v2.2d",
                  kind: .addhn, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0x0000000000000000), m: (0xffffffffffffffff, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0x00000000ffffffff, 0x0000000000000000), qc: false, setsQC: false),
            // addhn_advsimd.xml#Operation
            .init(id: "addhn-8", mnemonic: "addhn", operands: "v0.8b, v1.8h, v2.8h",
                  kind: .addhn, bits: 8, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (0xffffffffffffffff, 0xffffffffffffffff), m: (0x0000000000000000, 0x0000000000000000), old: (0xffffffffffffffff, 0xffffffffffffffff),
                  expected: (0xffffffffffffffff, 0x0000000000000000), qc: false, setsQC: false),
            // smlal_advsimd_elt.xml#Operation
            .init(id: "smlal-element-1", mnemonic: "smlal", operands: "v0.4s, v1.4h, v2.h[0]",
                  kind: .mlal, bits: 16, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: 0, aliasesDestination: false,
                  n: (0x8009800680038000, 0x80158012800f800c), m: (0x0020001b00168000, 0x0034002f002a0025), old: (0x123456789abcdef0, 0xfedcba9876543210),
                  expected: (0x5232d678dabcdef0, 0x3ed83a98b6513210), qc: false, setsQC: false),
            // smlal_advsimd_elt.xml#Operation
            .init(id: "smlal-element-2", mnemonic: "smlal", operands: "v0.2d, v1.2s, v2.s[3]",
                  kind: .mlal, bits: 32, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: 3, aliasesDestination: false,
                  n: (0x8000000380000000, 0x8000000980000006), m: (0x0000001600000011, 0x800000000000001b), old: (0x123456789abcdef0, 0xfedcba9876543210),
                  expected: (0x523456789abcdef0, 0x3edcba96f6543210), qc: false, setsQC: false),
            // smlal_advsimd_elt.xml#Operation
            .init(id: "smlal-element-3", mnemonic: "smlal", operands: "v0.4s, v0.4h, v0.h[7]",
                  kind: .mlal, bits: 16, bytes: 16, highHalf: false, isSigned: true, shift: 0,
                  elementIndex: 7, aliasesDestination: true,
                  n: (0x8009800680038000, 0x80158012800f800c), m: (0x8009800680038000, 0x80158012800f800c), old: (0x8009800680038000, 0x80158012800f800c),
                  expected: (0xbffd8045bff90000, 0xc00680cfc002008a), qc: false, setsQC: false),
            // smlal_advsimd_elt.xml#Operation
            .init(id: "smlal2-element-1", mnemonic: "smlal2", operands: "v0.4s, v1.8h, v2.h[0]",
                  kind: .mlal, bits: 16, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: 0, aliasesDestination: false,
                  n: (0x8009800680038000, 0x80158012800f800c), m: (0x0020001b00168000, 0x0034002f002a0025), old: (0x123456789abcdef0, 0xfedcba9876543210),
                  expected: (0x522cd678dab6def0, 0x3ed23a98b64b3210), qc: false, setsQC: false),
            // smlal_advsimd_elt.xml#Operation
            .init(id: "smlal2-element-2", mnemonic: "smlal2", operands: "v0.2d, v1.4s, v2.s[3]",
                  kind: .mlal, bits: 32, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: 3, aliasesDestination: false,
                  n: (0x8000000380000000, 0x8000000980000006), m: (0x0000001600000011, 0x800000000000001b), old: (0x123456789abcdef0, 0xfedcba9876543210),
                  expected: (0x523456759abcdef0, 0x3edcba93f6543210), qc: false, setsQC: false),
            // smlal_advsimd_elt.xml#Operation
            .init(id: "smlal2-element-3", mnemonic: "smlal2", operands: "v0.4s, v0.8h, v0.h[7]",
                  kind: .mlal, bits: 16, bytes: 16, highHalf: true, isSigned: true, shift: 0,
                  elementIndex: 7, aliasesDestination: true,
                  n: (0x8009800680038000, 0x80158012800f800c), m: (0x8009800680038000, 0x80158012800f800c), old: (0x8009800680038000, 0x80158012800f800c),
                  expected: (0xbff78141bff300fc, 0xc00081cbbffc0186), qc: false, setsQC: false),
            // sqdmulh_advsimd_elt.xml#Operation
            .init(id: "sqdmulh-element-1", mnemonic: "sqdmulh", operands: "v0.8h, v1.8h, v2.h[0]",
                  kind: .sqdmulh, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: 0, aliasesDestination: false,
                  n: (0x8009800680038000, 0x80158012800f800c), m: (0x0020001b00168000, 0x0034002f002a0025), old: (0x123456789abcdef0, 0xfedcba9876543210),
                  expected: (0x7ff77ffa7ffd7fff, 0x7feb7fee7ff17ff4), qc: true, setsQC: true),
            // sqdmulh_advsimd_elt.xml#Operation
            .init(id: "sqdmulh-element-2", mnemonic: "sqdmulh", operands: "v0.4s, v1.4s, v2.s[3]",
                  kind: .sqdmulh, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: 3, aliasesDestination: false,
                  n: (0x8000000380000000, 0x8000000980000006), m: (0x0000001600000011, 0x800000000000001b), old: (0x123456789abcdef0, 0xfedcba9876543210),
                  expected: (0x7ffffffd7fffffff, 0x7ffffff77ffffffa), qc: true, setsQC: true),
            // sqdmulh_advsimd_elt.xml#Operation
            .init(id: "sqdmulh-element-3", mnemonic: "sqdmulh", operands: "v0.8h, v0.8h, v0.h[7]",
                  kind: .sqdmulh, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: 7, aliasesDestination: true,
                  n: (0x8009800680038000, 0x80158012800f800c), m: (0x8009800680038000, 0x80158012800f800c), old: (0x8009800680038000, 0x80158012800f800c),
                  expected: (0x7fe27fe57fe87feb, 0x7fd67fd97fdc7fdf), qc: false, setsQC: true),
        ]
        for row in rows {
            let parsed = try XCTUnwrap(MacIRBuilder.neonLaneOperation(mnemonic: row.mnemonic, operandText: row.operands), row.id)
            let admitted = try XCTUnwrap(MacIRBuilder.ssaIntegerLaneOperation(mnemonic: row.mnemonic, operands: row.operands), row.id)
            XCTAssertEqual(admitted, parsed, row.id)
            let source = MacIRSourceSpan(address: 0x1000, byteText: "", mnemonic: row.mnemonic, operands: row.operands)
            let effects = MacIRBuilder.ssaEffects(for: source, observesFPSR: true)
            XCTAssertTrue(effects.refusals.isEmpty, row.id)
            XCTAssertTrue(effects.writes.contains { $0.cell == 32 }, row.id)
            XCTAssertTrue(effects.writes.contains { $0.cell == 64 }, row.id)
            XCTAssertEqual(effects.writes.contains { $0.cell == 98 }, row.setsQC, row.id)
            XCTAssertEqual(effects.reads.contains(98), row.setsQC, row.id)
            XCTAssertFalse(effects.writes.contains { $0.cell == 99 || $0.cell == 100 }, row.id)
            let op = parsed.semantics
            XCTAssertEqual(op.kind, row.kind, row.id)
            XCTAssertEqual(op.laneBits, row.bits, row.id)
            XCTAssertEqual(op.activeBytes, row.bytes, row.id)
            XCTAssertEqual(op.highHalf, row.highHalf, row.id)
            XCTAssertEqual(op.isSigned, row.isSigned, row.id)
            XCTAssertEqual(op.shift, row.shift, row.id)
            XCTAssertEqual(op.elementIndex, row.elementIndex, row.id)
            XCTAssertEqual(op.readsDestination, row.kind == .mlal, row.id)
            if row.aliasesDestination {
                XCTAssertEqual(parsed.sources, ["v0", "v0"], row.id)
                XCTAssertTrue(effects.reads.contains(32), row.id)
                XCTAssertTrue(effects.reads.contains(64), row.id)
                // Identical literal inputs enforce simultaneous pre-write reads:
                // Vn, indexed Vm, and old Vd are snapshots of the same register.
                XCTAssertEqual(row.n.low, row.m.low, row.id)
                XCTAssertEqual(row.n.high, row.m.high, row.id)
                XCTAssertEqual(row.n.low, row.old.low, row.id)
                XCTAssertEqual(row.n.high, row.old.high, row.id)
            } else if op.readsDestination {
                XCTAssertTrue(effects.reads.contains(32), row.id)
                XCTAssertTrue(effects.reads.contains(64), row.id)
            }
            XCTAssertEqual(parsed.destination, "v0", row.id)
            XCTAssertEqual(parsed.sources.count, op.sourceCount, row.id)
            let actual = op.evaluate(n: row.n, m: row.m, oldDestination: row.old)
            XCTAssertEqual(actual.low, row.expected.low, row.id)
            XCTAssertEqual(actual.high, row.expected.high, row.id)
            XCTAssertEqual(op.setsQC, row.setsQC, row.id)
            XCTAssertEqual(op.saturates(n: row.n, m: row.m), row.qc, row.id)
        }
    }

    func testMalformedShapesStayOutsideIntegerAdmission() {
        let malformed: [(String, String)] = [
            ("smlal", "v0.8h, v1.16b, v2.8b"),
            ("smlal2", "v0.8h, v1.8b, v2.16b"),
            ("ushll", "v0.8h, v1.8b, #8"),
            ("ushll2", "v0.8h, v1.8b, #0"),
            ("sshll", "v0.4s, v1.4h, #-1"),
            ("sshll2", "v0.4s, v1.8h, #16"),
            ("sqdmulh", "v0.16b, v1.16b, v2.16b"),
            ("cmlt", "v0.4s, v1.4s, #1"),
            ("abs", "v0.4s, v1.8h"),
            ("rshrn", "v0.8b, v1.8h, #0"),
            ("cmtst", "v0.1d, v1.1d, v2.1d"),
            ("ushl", "v0.4s, v1.4s, v2.8h"),
            ("addhn", "v0.8b, v1.8h, v2.4s")
        ]
        for (mnemonic, operands) in malformed {
            XCTAssertNil(MacIRBuilder.ssaIntegerLaneOperation(mnemonic: mnemonic, operands: operands), mnemonic)
        }
        XCTAssertNil(MacIRBuilder.ssaIntegerLaneOperation(mnemonic: "addhn2", operands: "v0.8b, v1.8h, v2.8h"))
    }

    func testOpaqueRowsInvalidateSIMDBindingsBeforeIntegerLaneReads() throws {
        for mnemonic in ["unknown", "unavailable", "", "udf"] {
            let rows = [("sqdmulh", "v1.8h, v2.8h, v3.8h"), (mnemonic, "0x4ee29485"),
                        ("rshrn", "v0.8b, v1.8h, #1"), ("ret", "")]
                .enumerated().map { index, item in
                    InstructionRow(address: 0x1000 + UInt64(index * 4), bytes: "",
                        mnemonic: item.0, operands: item.1, hasBreakpoint: false, comment: nil)
                }
            let function = MacIRBuilder(ssaEnabled: true).buildFunction(name: "opaque_lane_barrier",
                startAddress: 0x1000, instructions: rows)
            XCTAssertTrue(function.ssaEnabled, mnemonic)
            let info = try XCTUnwrap(function.ssaInfo, mnemonic)
            let expectedReason: MacIRRefusal.Reason = mnemonic.isEmpty || mnemonic == "udf"
                ? .undecodableRow : .unknownEffects
            for cell in 32..<96 {
                let id = try XCTUnwrap(info.plan.rowWriteBindings[1][cell], mnemonic)
                XCTAssertEqual(info.plan.definitions[id].origin, .refusal(expectedReason, 0x1004), mnemonic)
            }
            for cell in [33, 65] {
                if mnemonic == "udf" {
                    // UDF terminates its block. No value crosses into the
                    // unreachable successor, which has its own refused entry.
                    let id = try XCTUnwrap(info.plan.rowReadBindings[2][cell], mnemonic)
                    XCTAssertEqual(info.plan.definitions[id].origin, .refusal(.unreachableBlock, 0x1008))
                } else {
                    XCTAssertEqual(info.plan.rowReadBindings[2][cell], info.plan.rowWriteBindings[1][cell], mnemonic)
                }
                XCTAssertNotEqual(info.plan.rowReadBindings[2][cell], info.plan.rowWriteBindings[0][cell], mnemonic)
            }
            let numeric = try XCTUnwrap(function.instructions.first {
                $0.source.address == 0x1008 && $0.neonLaneOp != nil
            }, mnemonic)
            guard case let .intrinsic(_, _, arguments) = numeric.operation,
                  let input = arguments.first, case .unknown = input else {
                return XCTFail("an exact lane after an opaque row must consume an unavailable SIMD input: \(mnemonic)")
            }
        }
    }

    // Arm A64 mul_advsimd_vec / mul_advsimd_elt Operation; literal modular products.
    func testVectorMulIsAdmittedByTheSSALaneDescriptor() throws {
        let rows: [Oracle] = [
            .init(id: "mul-8b", mnemonic: "mul", operands: "v0.8b, v1.8b, v2.8b",
                  kind: .mul, bits: 8, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (low: 0x0807_0605_0403_0201, high: 0x100f_0e0d_0c0b_0a09),
                  m: (low: 0x100f_0e0d_0c0b_0a09, high: 0x201f_1e1d_1c1b_1a19),
                  old: (low: 0x1234_5678_9abc_def0, high: 0xfedc_ba98_7654_3210),
                  expected: (low: 0x8069_5441_3021_1409, high: 0), qc: false, setsQC: false),
            .init(id: "mul-16b", mnemonic: "mul", operands: "v0.16b, v1.16b, v2.16b",
                  kind: .mul, bits: 8, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (low: 0x0807_0605_0403_0201, high: 0x100f_0e0d_0c0b_0a09),
                  m: (low: 0x100f_0e0d_0c0b_0a09, high: 0x201f_1e1d_1c1b_1a19),
                  old: (low: 0x1234_5678_9abc_def0, high: 0xfedc_ba98_7654_3210),
                  expected: (low: 0x8069_5441_3021_1409, high: 0x00d1_a479_5029_04e1), qc: false, setsQC: false),
            .init(id: "mul-4h", mnemonic: "mul", operands: "v0.4h, v1.4h, v2.4h",
                  kind: .mul, bits: 16, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (low: 0x8000_7fff_0003_ffff, high: 0xdead_beef_dead_beef),
                  m: (low: 0x0002_0002_0002_0002, high: 0xffff_ffff_ffff_ffff),
                  old: (low: 0x1234_5678_9abc_def0, high: 0xfedc_ba98_7654_3210),
                  expected: (low: 0x0000_fffe_0006_fffe, high: 0), qc: false, setsQC: false),
            .init(id: "mul-8h", mnemonic: "mul", operands: "v0.8h, v1.8h, v2.8h",
                  kind: .mul, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (low: 0x8000_7fff_0003_ffff, high: 0x7fff_ffff_0003_0005),
                  m: (low: 0x0002_0002_0002_0002, high: 0x0003_ffff_0007_0009),
                  old: (low: 0x1234_5678_9abc_def0, high: 0xfedc_ba98_7654_3210),
                  expected: (low: 0x0000_fffe_0006_fffe, high: 0x7ffd_0001_0015_002d), qc: false, setsQC: false),
            .init(id: "mul-2s", mnemonic: "mul", operands: "v0.2s, v1.2s, v2.2s",
                  kind: .mul, bits: 32, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (low: 0x8000_0000_7fff_ffff, high: 0x0000_0005_ffff_ffff),
                  m: (low: 0x0000_0003_0000_0002, high: 0x0000_0009_0000_0011),
                  old: (low: 0x1234_5678_9abc_def0, high: 0xfedc_ba98_7654_3210),
                  expected: (low: 0x8000_0000_ffff_fffe, high: 0), qc: false, setsQC: false),
            .init(id: "mul-4s", mnemonic: "mul", operands: "v0.4s, v1.4s, v2.4s",
                  kind: .mul, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: false,
                  n: (low: 0x8000_0000_7fff_ffff, high: 0x0000_0005_ffff_ffff),
                  m: (low: 0x0000_0003_0000_0002, high: 0x0000_0009_0000_0011),
                  old: (low: 0x1234_5678_9abc_def0, high: 0xfedc_ba98_7654_3210),
                  expected: (low: 0x8000_0000_ffff_fffe, high: 0x0000_002d_ffff_ffef), qc: false, setsQC: false),
            .init(id: "mul-alias-8h", mnemonic: "mul", operands: "v0.8h, v0.8h, v0.8h",
                  kind: .mul, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: nil, aliasesDestination: true,
                  n: (low: 0x0004_0003_0002_0001, high: 0x0008_0007_0006_0005),
                  m: (low: 0x0004_0003_0002_0001, high: 0x0008_0007_0006_0005),
                  old: (low: 0x0004_0003_0002_0001, high: 0x0008_0007_0006_0005),
                  expected: (low: 0x0010_0009_0004_0001, high: 0x0040_0031_0024_0019), qc: false, setsQC: false),
            .init(id: "mul-element-4h-3", mnemonic: "mul", operands: "v0.4h, v1.4h, v2.h[3]",
                  kind: .mul, bits: 16, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: 3, aliasesDestination: false,
                  n: (low: 0x8000_7fff_0003_ffff, high: 0xdead_beef_dead_beef),
                  m: (low: 0x0003_0002_0001_0000, high: 0x0007_0006_0005_0004),
                  old: (low: 0x1234_5678_9abc_def0, high: 0xfedc_ba98_7654_3210),
                  expected: (low: 0x8000_7ffd_0009_fffd, high: 0), qc: false, setsQC: false),
            .init(id: "mul-element-8h-7", mnemonic: "mul", operands: "v0.8h, v1.8h, v2.h[7]",
                  kind: .mul, bits: 16, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: 7, aliasesDestination: false,
                  n: (low: 0x0004_0003_0002_0001, high: 0x0008_0007_0006_0005),
                  m: (low: 0x0003_0002_0001_0000, high: 0x0007_0006_0005_0004),
                  old: (low: 0x1234_5678_9abc_def0, high: 0xfedc_ba98_7654_3210),
                  expected: (low: 0x001c_0015_000e_0007, high: 0x0038_0031_002a_0023), qc: false, setsQC: false),
            .init(id: "mul-element-2s-1", mnemonic: "mul", operands: "v0.2s, v1.2s, v2.s[1]",
                  kind: .mul, bits: 32, bytes: 8, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: 1, aliasesDestination: false,
                  n: (low: 0x8000_0000_7fff_ffff, high: 0x0000_0005_ffff_ffff),
                  m: (low: 0x0000_0007_0000_0002, high: 0x0000_0009_0000_0011),
                  old: (low: 0x1234_5678_9abc_def0, high: 0xfedc_ba98_7654_3210),
                  expected: (low: 0x8000_0000_7fff_fff9, high: 0), qc: false, setsQC: false),
            .init(id: "mul-element-4s-3", mnemonic: "mul", operands: "v0.4s, v1.4s, v2.s[3]",
                  kind: .mul, bits: 32, bytes: 16, highHalf: false, isSigned: false, shift: 0,
                  elementIndex: 3, aliasesDestination: false,
                  n: (low: 0x8000_0000_7fff_ffff, high: 0x0000_0005_ffff_ffff),
                  m: (low: 0x0000_0007_0000_0002, high: 0x0000_0009_0000_0011),
                  old: (low: 0x1234_5678_9abc_def0, high: 0xfedc_ba98_7654_3210),
                  expected: (low: 0x8000_0000_7fff_fff7, high: 0x0000_002d_ffff_fff7), qc: false, setsQC: false)
        ]
        for row in rows {
            let parsed = try XCTUnwrap(MacIRBuilder.neonLaneOperation(mnemonic: row.mnemonic, operandText: row.operands), row.id)
            let admitted = try XCTUnwrap(MacIRBuilder.ssaIntegerLaneOperation(mnemonic: row.mnemonic, operands: row.operands), row.id)
            XCTAssertEqual(admitted, parsed, row.id)
            let source = MacIRSourceSpan(address: 0x1000, byteText: "", mnemonic: row.mnemonic, operands: row.operands)
            let effects = MacIRBuilder.ssaEffects(for: source, observesFPSR: true)
            XCTAssertTrue(effects.refusals.isEmpty, row.id)
            XCTAssertTrue(effects.writes.contains { $0.cell == 32 }, row.id)
            XCTAssertTrue(effects.writes.contains { $0.cell == 64 }, row.id)
            XCTAssertEqual(effects.writes.contains { $0.cell == 98 }, row.setsQC, row.id)
            XCTAssertEqual(effects.reads.contains(98), row.setsQC, row.id)
            XCTAssertFalse(effects.writes.contains { $0.cell == 99 || $0.cell == 100 }, row.id)
            let op = parsed.semantics
            XCTAssertEqual(op.kind, row.kind, row.id)
            XCTAssertEqual(op.laneBits, row.bits, row.id)
            XCTAssertEqual(op.activeBytes, row.bytes, row.id)
            XCTAssertEqual(op.highHalf, row.highHalf, row.id)
            XCTAssertEqual(op.isSigned, row.isSigned, row.id)
            XCTAssertEqual(op.shift, row.shift, row.id)
            XCTAssertEqual(op.elementIndex, row.elementIndex, row.id)
            XCTAssertEqual(op.readsDestination, row.kind == .mlal, row.id)
            if row.aliasesDestination {
                XCTAssertEqual(parsed.sources, ["v0", "v0"], row.id)
                XCTAssertTrue(effects.reads.contains(32), row.id)
                XCTAssertTrue(effects.reads.contains(64), row.id)
                // Identical literal inputs enforce simultaneous pre-write reads:
                // Vn, indexed Vm, and old Vd are snapshots of the same register.
                XCTAssertEqual(row.n.low, row.m.low, row.id)
                XCTAssertEqual(row.n.high, row.m.high, row.id)
                XCTAssertEqual(row.n.low, row.old.low, row.id)
                XCTAssertEqual(row.n.high, row.old.high, row.id)
            } else if op.readsDestination {
                XCTAssertTrue(effects.reads.contains(32), row.id)
                XCTAssertTrue(effects.reads.contains(64), row.id)
            }
            XCTAssertEqual(parsed.destination, "v0", row.id)
            XCTAssertEqual(parsed.sources.count, op.sourceCount, row.id)
            XCTAssertEqual(op.sourceCount, 2, row.id)
            // The descriptor carries whole vN names, so effects read both halves,
            // including Q=0 and indexed forms (not just the architectural lanes).
            let sourceCells = row.aliasesDestination ? [32, 64] : [33, 65, 34, 66]
            for cell in sourceCells { XCTAssertTrue(effects.reads.contains(cell), row.id) }
            let actual = op.evaluate(n: row.n, m: row.m, oldDestination: row.old)
            XCTAssertEqual(actual.low, row.expected.low, row.id)
            XCTAssertEqual(actual.high, row.expected.high, row.id)
            XCTAssertEqual(op.setsQC, row.setsQC, row.id)
            XCTAssertEqual(op.saturates(n: row.n, m: row.m), row.qc, row.id)
        }
    }

    func testVectorMulStaysOutsideAdmissionWhenMalformedOrScalar() {
        let operands = [
            "w0, w1, w2", "x0, x1, x2",
            "v0.2d, v1.2d, v2.2d", "v0.1d, v1.1d, v2.1d",
            "v0.4h, v1.8h, v2.4h", "v0.4h, v1.4h",
            "v0.8b, v1.8b, v2.h[3]", "v0.4h, v1.4h, v16.h[3]"
        ]
        for text in operands {
            XCTAssertNil(MacIRBuilder.ssaIntegerLaneOperation(mnemonic: "mul", operands: text), text)
        }
    }

    func testCensusMulFourHalvesRowsLiftToTypedIntrinsicsInSSA() throws {
        // Census order: 14 ifast sites followed by 12 4x4 sites. Duplicates are sites.
        let rows = [
            "v5.4h, v5.4h, v16.4h",
            "v7.4h, v17.4h, v7.4h",
            "v6.4h, v21.4h, v6.4h",
            "v4.4h, v18.4h, v4.4h",
            "v3.4h, v19.4h, v3.4h",
            "v2.4h, v20.4h, v2.4h",
            "v1.4h, v22.4h, v1.4h",
            "v16.4h, v18.4h, v16.4h",
            "v7.4h, v20.4h, v7.4h",
            "v6.4h, v22.4h, v6.4h",
            "v0.4h, v17.4h, v4.4h",
            "v3.4h, v19.4h, v3.4h",
            "v2.4h, v21.4h, v2.4h",
            "v1.4h, v23.4h, v1.4h",
            "v18.4h, v18.4h, v1.4h",
            "v23.4h, v23.4h, v25.4h",
            "v20.4h, v24.4h, v16.4h",
            "v22.4h, v22.4h, v4.4h",
            "v23.4h, v19.4h, v3.4h",
            "v24.4h, v17.4h, v2.4h",
            "v18.4h, v18.4h, v1.4h",
            "v22.4h, v22.4h, v0.4h",
            "v20.4h, v23.4h, v16.4h",
            "v21.4h, v21.4h, v4.4h",
            "v22.4h, v19.4h, v3.4h",
            "v23.4h, v17.4h, v2.4h"
        ]
        XCTAssertEqual(rows.count, 26)
        for operands in rows {
            let mulRow = InstructionRow(address: 0x1000, bytes: "", mnemonic: "mul",
                operands: operands, hasBreakpoint: false, comment: nil)
            let retRow = InstructionRow(address: 0x1004, bytes: "", mnemonic: "ret",
                operands: "", hasBreakpoint: false, comment: nil)
            let scalarRow = InstructionRow(address: 0x1004, bytes: "", mnemonic: "add",
                operands: "x9, x10, x11", hasBreakpoint: false, comment: nil)
            let companionRetRow = InstructionRow(address: 0x1008, bytes: "", mnemonic: "ret",
                operands: "", hasBreakpoint: false, comment: nil)
            // Preserve the original semantic control. Only the companion proves
            // SSA coverage: scalar arithmetic excludes the earlier vector region.
            for (requiresSSA, instructions) in [(false, [mulRow, retRow]),
                                               (true, [mulRow, scalarRow, companionRetRow])] {
                let function = MacIRBuilder(ssaEnabled: true).buildFunction(name: "mul4h",
                    startAddress: 0x1000, instructions: instructions)
                if requiresSSA {
                    XCTAssertTrue(function.ssaEnabled, operands)
                    _ = try XCTUnwrap(function.ssaInfo, operands)
                }
                let numeric = try XCTUnwrap(function.instructions.first { $0.source.address == mulRow.address }, operands)
                XCTAssertEqual(numeric.neonLaneOp?.kind, .mul, operands)
                XCTAssertEqual(numeric.neonLaneOp?.laneBits, 16, operands)
                XCTAssertEqual(numeric.neonLaneOp?.activeBytes, 8, operands)
                guard case let .intrinsic(_, name, arguments) = numeric.operation else {
                    XCTFail("expected typed mul intrinsic: \(operands)")
                    continue
                }
                XCTAssertEqual(name, "neon_mul_4h_zero_high64", operands)
                XCTAssertEqual(arguments.count, 2, operands)
                // Include every operation's direct values, not only the MUL arguments.
                for instruction in function.instructions {
                    for value in vectorMulDirectValues(instruction) {
                        if case let .unknown(name) = value {
                            XCTAssertFalse(name.contains(".4h"), operands)
                        }
                    }
                }
            }
        }
        let chainControls = [("mul", "v5.4h, v5.4h, v16.4h"),
                             ("add", "v6.4h, v5.4h, v5.4h"), ("ret", "")]
        let chainCompanion = [("mul", "v5.4h, v5.4h, v16.4h"),
                              ("add", "v6.4h, v5.4h, v5.4h"),
                              ("add", "x9, x10, x11"), ("ret", "")]
        for (requiresSSA, fixture) in [(false, chainControls), (true, chainCompanion)] {
            let chainRows = fixture.enumerated().map { index, item in
                InstructionRow(address: 0x1000 + UInt64(index * 4), bytes: "",
                    mnemonic: item.0, operands: item.1, hasBreakpoint: false, comment: nil)
            }
            let chain = MacIRBuilder(ssaEnabled: true).buildFunction(name: "mul4h_chain",
                startAddress: 0x1000, instructions: chainRows)
            if requiresSSA {
                XCTAssertTrue(chain.ssaEnabled)
                _ = try XCTUnwrap(chain.ssaInfo)
            }
            let mul = try XCTUnwrap(chain.instructions.first { $0.source.address == 0x1000 })
            let add = try XCTUnwrap(chain.instructions.first { $0.source.address == 0x1004 })
            guard case let .intrinsic(destination, mulName, _) = mul.operation,
                  case let .intrinsic(_, addName, arguments) = add.operation else {
                return XCTFail("expected typed MUL/ADD def-use chain")
            }
            XCTAssertEqual(mul.neonLaneOp?.kind, .mul)
            XCTAssertEqual(mul.neonLaneOp?.laneBits, 16)
            XCTAssertEqual(mul.neonLaneOp?.activeBytes, 8)
            XCTAssertEqual(mulName, "neon_mul_4h_zero_high64")
            if case let .intrinsic(_, _, mulArguments) = mul.operation {
                XCTAssertEqual(mulArguments.count, 2)
            }
            XCTAssertEqual(addName, "neon_add_4h_zero_high64")
            let output = try XCTUnwrap(destination)
            let input = try XCTUnwrap(arguments.first)
            // Compare printed values; no Equatable declaration is supplied for MacIRValue.
            XCTAssertEqual(String(describing: input), String(describing: output))
            for instruction in chain.instructions {
                for value in vectorMulDirectValues(instruction) {
                    if case let .unknown(name) = value { XCTAssertFalse(name.contains(".4h")) }
                }
            }
        }
    }

    func testScalarMulIsUnchangedByVectorMulAdmission() throws {
        let operands = ["w0, w1, w2", "x3, x4, x5"]
        let rows = [("mul", operands[0]), ("mul", operands[1]), ("ret", "")]
            .enumerated().map { index, item in
                InstructionRow(address: 0x1000 + UInt64(index * 4), bytes: "",
                    mnemonic: item.0, operands: item.1, hasBreakpoint: false, comment: nil)
            }
        let function = MacIRBuilder(ssaEnabled: true).buildFunction(name: "scalar_mul",
            startAddress: 0x1000, instructions: rows)
        XCTAssertTrue(function.ssaEnabled)
        for (index, text) in operands.enumerated() {
            XCTAssertNil(MacIRBuilder.ssaIntegerLaneOperation(mnemonic: "mul", operands: text))
            let instruction = try XCTUnwrap(function.instructions.first {
                $0.source.address == 0x1000 + UInt64(index * 4)
            })
            XCTAssertNil(instruction.neonLaneOp)
            guard case let .binary(_, op, _, _) = instruction.operation else {
                XCTFail("scalar MUL must remain binary: \(text)")
                continue
            }
            XCTAssertEqual(op, "*", text)
        }
    }

    private func vectorMulDirectValues(_ instruction: MacIRInstruction) -> [MacIRValue] {
        var values: [MacIRValue] = []
        if let target = instruction.returnTarget { values.append(target) }
        switch instruction.operation {
        case let .assign(a, b), let .load(a, b), let .store(a, b): values += [a, b]
        case let .binary(a, _, b, c), let .compareToBool(a, _, b, c),
             let .loadWriteback(a, b, c, _, _), let .storeWriteback(a, b, c, _, _),
             let .stackSlotRead(a, b, c): values += [a, b, c]
        case let .stackSlotPairRead(a, b, c, d, e, f): values += [a, b, c, d, e, f]
        case let .call(frame, result):
            values += frame.bindingValues
            if let result { values.append(result) }
        case let .conditionalBranch(_, a, b, c): values += [a, b, c]
        case let .select(a, _, b, c, d, e): values += [a, b, c, d, e]
        case let .returnValue(value): if let value { values.append(value) }
        case let .intrinsic(destination, _, arguments):
            values += arguments
            if let destination { values.append(destination) }
        case let .switchDispatch(index, cases, defaultTarget):
            values.append(index); values += cases.map(\.target)
            if let defaultTarget { values.append(defaultTarget) }
        case let .unknown(destination, inputs, _, _):
            if let destination { values.append(destination) }
            values += inputs.mayRead.map(\.value) + inputs.definiteRead.map(\.value)
        }
        return values
    }

}
