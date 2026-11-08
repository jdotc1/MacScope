import XCTest
@testable import MacScope

final class NEONNarrowRoundAdmissionTests: XCTestCase {
    // Literal independent arbitrary-precision oracles; source-static only, not run.
    func testArchitecturalOraclesAndAdmission() throws {
        struct Row {
            let id: String
            let mnemonic: String
            let operands: String
            let n: MacIRNEONLaneOp.Vector
            let m: MacIRNEONLaneOp.Vector
            let old: MacIRNEONLaneOp.Vector
            let expected: MacIRNEONLaneOp.Vector
        }
        let rows: [Row] = [
            // smlsl_advsimd_vec.xml#Operation
            .init(id: "smlsl2-1", mnemonic: "smlsl2", operands: "v0.8h, v1.16b, v2.16b",
                  n: (0x0707070707070707, 0x8786858483828180), m: (0x0909090909090909, 0x8080808080808080),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0xd3b417785b3c9ef0, 0xc25c7d9838d4f410)),
            // smlsl_advsimd_vec.xml#Operation
            .init(id: "smlsl2-2", mnemonic: "smlsl2", operands: "v0.8h, v1.16b, v2.16b",
                  n: (0x0707070707070707, 0x868584838281807f), m: (0x0909090909090909, 0xffffffffffffffff),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x11b655f99a3cdf6f, 0xfe62ba1d75d83193)),
            // smlsl_advsimd_vec.xml#Operation
            .init(id: "smlsl2-3", mnemonic: "smlsl2", operands: "v0.8h, v1.16b, v2.16b",
                  n: (0x0707070707070707, 0x06050403020100ff), m: (0x0909090909090909, 0x0101010101010101),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123256779abcdef1, 0xfed6ba937650320d)),
            // smlsl_advsimd_vec.xml#Operation
            .init(id: "smlsl2-4", mnemonic: "smlsl2", operands: "v0.4s, v1.8h, v2.8h",
                  n: (0x0007000700070007, 0x8003800280018000), m: (0x0009000900090009, 0x8000800080008000),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0xd234d6785abcdef0, 0xbede3a9836553210)),
            // smlsl_advsimd_vec.xml#Operation
            .init(id: "smlsl2-5", mnemonic: "smlsl2", operands: "v0.4s, v1.8h, v2.8h",
                  n: (0x0007000700070007, 0x8002800180007fff), m: (0x0009000900090009, 0xffffffffffffffff),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x1233d6789abd5eef, 0xfedc3a9a7653b211)),
            // smlsl_advsimd_vec.xml#Operation
            .init(id: "smlsl2-6", mnemonic: "smlsl2", operands: "v0.4s, v1.8h, v2.8h",
                  n: (0x0007000700070007, 0x000200010000ffff), m: (0x0009000900090009, 0x0001000100010001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123456789abcdef1, 0xfedcba967654320f)),
            // smlsl_advsimd_vec.xml#Operation
            .init(id: "smlsl2-7", mnemonic: "smlsl2", operands: "v0.2d, v1.4s, v2.4s",
                  n: (0x0000000700000007, 0x8000000180000000), m: (0x0000000900000009, 0x8000000080000000),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0xd23456789abcdef0, 0xbedcba98f6543210)),
            // smlsl_advsimd_vec.xml#Operation
            .init(id: "smlsl2-8", mnemonic: "smlsl2", operands: "v0.2d, v1.4s, v2.4s",
                  n: (0x0000000700000007, 0x800000007fffffff), m: (0x0000000900000009, 0xffffffffffffffff),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123456791abcdeef, 0xfedcba97f6543210)),
            // smlsl_advsimd_vec.xml#Operation
            .init(id: "smlsl2-9", mnemonic: "smlsl2", operands: "v0.2d, v1.4s, v2.4s",
                  n: (0x0000000700000007, 0x00000000ffffffff), m: (0x0000000900000009, 0x0000000100000001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123456789abcdef1, 0xfedcba9876543210)),
            // raddhn_advsimd.xml#Operation
            .init(id: "raddhn-1", mnemonic: "raddhn", operands: "v0.8b, v1.8h, v2.8h",
                  n: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb), m: (0xffffffffffffffff, 0xffffffffffffffff),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x0000000000000000, 0x0000000000000000)),
            // raddhn_advsimd.xml#Operation
            .init(id: "raddhn-2", mnemonic: "raddhn", operands: "v0.8b, v1.8h, v2.8h",
                  n: (0x007c007d007e007f, 0x00780079007a007b), m: (0x0001000100010001, 0x0001000100010001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x0000000000000001, 0x0000000000000000)),
            // raddhn_advsimd.xml#Operation
            .init(id: "raddhn-3", mnemonic: "raddhn", operands: "v0.8b, v1.8h, v2.8h",
                  n: (0x00fc00fd00fe00ff, 0x00f800f900fa00fb), m: (0x0001000100010001, 0x0001000100010001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x0101010101010101, 0x0000000000000000)),
            // raddhn_advsimd.xml#Operation
            .init(id: "raddhn-4", mnemonic: "raddhn", operands: "v0.4h, v1.4s, v2.4s",
                  n: (0xfffffffeffffffff, 0xfffffffcfffffffd), m: (0xffffffffffffffff, 0xffffffffffffffff),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x0000000000000000, 0x0000000000000000)),
            // raddhn_advsimd.xml#Operation
            .init(id: "raddhn-5", mnemonic: "raddhn", operands: "v0.4h, v1.4s, v2.4s",
                  n: (0x00007ffe00007fff, 0x00007ffc00007ffd), m: (0x0000000100000001, 0x0000000100000001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x0000000000000001, 0x0000000000000000)),
            // raddhn_advsimd.xml#Operation
            .init(id: "raddhn-6", mnemonic: "raddhn", operands: "v0.4h, v1.4s, v2.4s",
                  n: (0x0000fffe0000ffff, 0x0000fffc0000fffd), m: (0x0000000100000001, 0x0000000100000001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x0001000100010001, 0x0000000000000000)),
            // raddhn_advsimd.xml#Operation
            .init(id: "raddhn-7", mnemonic: "raddhn", operands: "v0.2s, v1.2d, v2.2d",
                  n: (0xffffffffffffffff, 0xfffffffffffffffe), m: (0xffffffffffffffff, 0xffffffffffffffff),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x0000000000000000, 0x0000000000000000)),
            // raddhn_advsimd.xml#Operation
            .init(id: "raddhn-8", mnemonic: "raddhn", operands: "v0.2s, v1.2d, v2.2d",
                  n: (0x000000007fffffff, 0x000000007ffffffe), m: (0x0000000000000001, 0x0000000000000001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x0000000000000001, 0x0000000000000000)),
            // raddhn_advsimd.xml#Operation
            .init(id: "raddhn-9", mnemonic: "raddhn", operands: "v0.2s, v1.2d, v2.2d",
                  n: (0x00000000ffffffff, 0x00000000fffffffe), m: (0x0000000000000001, 0x0000000000000001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x0000000100000001, 0x0000000000000000)),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn2-1", mnemonic: "rshrn2", operands: "v0.16b, v1.8h, #1",
                  n: (0xfffcfffdfffeffff, 0xfff8fff9fffafffb), m: (0xffffffffffffffff, 0xffffffffffffffff),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123456789abcdef0, 0xfcfdfdfefeffff00)),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn2-2", mnemonic: "rshrn2", operands: "v0.16b, v1.8h, #8",
                  n: (0x007c007d007e007f, 0x00780079007a007b), m: (0x0001000100010001, 0x0001000100010001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123456789abcdef0, 0x0000000000000000)),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn2-3", mnemonic: "rshrn2", operands: "v0.16b, v1.8h, #7",
                  n: (0x00fc00fd00fe00ff, 0x00f800f900fa00fb), m: (0x0001000100010001, 0x0001000100010001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123456789abcdef0, 0x0202020202020202)),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn2-4", mnemonic: "rshrn2", operands: "v0.8h, v1.4s, #1",
                  n: (0xfffffffeffffffff, 0xfffffffcfffffffd), m: (0xffffffffffffffff, 0xffffffffffffffff),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123456789abcdef0, 0xfffeffffffff0000)),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn2-5", mnemonic: "rshrn2", operands: "v0.8h, v1.4s, #16",
                  n: (0x00007ffe00007fff, 0x00007ffc00007ffd), m: (0x0000000100000001, 0x0000000100000001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123456789abcdef0, 0x0000000000000000)),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn2-6", mnemonic: "rshrn2", operands: "v0.8h, v1.4s, #15",
                  n: (0x0000fffe0000ffff, 0x0000fffc0000fffd), m: (0x0000000100000001, 0x0000000100000001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123456789abcdef0, 0x0002000200020002)),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn2-7", mnemonic: "rshrn2", operands: "v0.4s, v1.2d, #1",
                  n: (0xffffffffffffffff, 0xfffffffffffffffe), m: (0xffffffffffffffff, 0xffffffffffffffff),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123456789abcdef0, 0xffffffff00000000)),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn2-8", mnemonic: "rshrn2", operands: "v0.4s, v1.2d, #32",
                  n: (0x000000007fffffff, 0x000000007ffffffe), m: (0x0000000000000001, 0x0000000000000001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123456789abcdef0, 0x0000000000000000)),
            // rshrn_advsimd.xml#Operation
            .init(id: "rshrn2-9", mnemonic: "rshrn2", operands: "v0.4s, v1.2d, #31",
                  n: (0x00000000ffffffff, 0x00000000fffffffe), m: (0x0000000000000001, 0x0000000000000001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123456789abcdef0, 0x0000000200000002)),
            // umlsl_advsimd_vec.xml#Operation
            .init(id: "umlsl2-1", mnemonic: "umlsl2", operands: "v0.8h, v1.16b, v2.16b",
                  n: (0x0707070707070707, 0x8786858483828180), m: (0x0909090909090909, 0x8080808080808080),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0xd0b415785a3c9ef0, 0xbb5c779833d4f010)),
            // umlsl_advsimd_vec.xml#Operation
            .init(id: "umlsl2-2", mnemonic: "umlsl2", operands: "v0.8h, v1.16b, v2.16b",
                  n: (0x0707070707070707, 0x868584838281807f), m: (0x0909090909090909, 0xffffffffffffffff),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x90b6d5f91b3c606f, 0x7962361df2d8af93)),
            // umlsl_advsimd_vec.xml#Operation
            .init(id: "umlsl2-3", mnemonic: "umlsl2", operands: "v0.4s, v1.8h, v2.8h",
                  n: (0x0007000700070007, 0x8003800280018000), m: (0x0009000900090009, 0x8000800080008000),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0xd233d6785abcdef0, 0xbedb3a9836533210)),
            // umlsl_advsimd_vec.xml#Operation
            .init(id: "umlsl2-4", mnemonic: "umlsl2", operands: "v0.4s, v1.8h, v2.8h",
                  n: (0x0007000700070007, 0x8002800180007fff), m: (0x0009000900090009, 0xffffffffffffffff),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x9234d6781abe5eef, 0x7edb3a9af653b211)),
            // umlsl_advsimd_vec.xml#Operation
            .init(id: "umlsl2-5", mnemonic: "umlsl2", operands: "v0.4s, v1.8h, v2.8h",
                  n: (0x0007000700070007, 0x000200010000ffff), m: (0x0009000900090009, 0x0001000100010001),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x123456789abbdef1, 0xfedcba967654320f)),
            // umlsl_advsimd_vec.xml#Operation
            .init(id: "umlsl2-6", mnemonic: "umlsl2", operands: "v0.2d, v1.4s, v2.4s",
                  n: (0x0000000700000007, 0x8000000180000000), m: (0x0000000900000009, 0x8000000080000000),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0xd23456789abcdef0, 0xbedcba97f6543210)),
            // umlsl_advsimd_vec.xml#Operation
            .init(id: "umlsl2-7", mnemonic: "umlsl2", operands: "v0.2d, v1.4s, v2.4s",
                  n: (0x0000000700000007, 0x800000007fffffff), m: (0x0000000900000009, 0xffffffffffffffff),
                  old: (0x123456789abcdef0, 0xfedcba9876543210), expected: (0x9234567a1abcdeef, 0x7edcba98f6543210)),
            // Synthetic unsigned long-family oracle; products are 2*4 and 3*5.
            .init(id: "umlsl-synthetic", mnemonic: "umlsl", operands: "v0.2d, v1.2s, v2.2s",
                  n: (0x0000000300000002, 0x0000000300000002), m: (0x0000000500000004, 0x0000000500000004),
                  old: (100, 200), expected: (92, 185)),
            // Synthetic unsigned long-family oracle; products are 2*4 and 3*5.
            .init(id: "umlal-synthetic", mnemonic: "umlal", operands: "v0.2d, v1.2s, v2.2s",
                  n: (0x0000000300000002, 0x0000000300000002), m: (0x0000000500000004, 0x0000000500000004),
                  old: (100, 200), expected: (108, 215)),
            // Synthetic unsigned long-family oracle; products are 2*4 and 3*5.
            .init(id: "umlal2-synthetic", mnemonic: "umlal2", operands: "v0.2d, v1.4s, v2.4s",
                  n: (0x0000000300000002, 0x0000000300000002), m: (0x0000000500000004, 0x0000000500000004),
                  old: (100, 200), expected: (108, 215)),
            // Synthetic unsigned long-family oracle; products are 2*4 and 3*5.
            .init(id: "umull2-synthetic", mnemonic: "umull2", operands: "v0.2d, v1.4s, v2.4s",
                  n: (0x0000000300000002, 0x0000000300000002), m: (0x0000000500000004, 0x0000000500000004),
                  old: (100, 200), expected: (8, 15)),
        ]
        for row in rows {
            let parsed = try XCTUnwrap(MacIRBuilder.ssaIntegerLaneOperation(mnemonic: row.mnemonic, operands: row.operands), row.id)
            let source = MacIRSourceSpan(address: 0x1000, byteText: "", mnemonic: row.mnemonic, operands: row.operands)
            let flow = C2MachineFlow(rows: [source])
            XCTAssertNil(flow.error, row.id)
            XCTAssertEqual(flow.writes[0], Set(["v0"]), row.id)
            XCTAssertEqual(flow.reads[0].contains("v0"), !["raddhn", "umull2"].contains(row.mnemonic), row.id)
            let effects = MacIRBuilder.ssaEffects(for: source)
            XCTAssertTrue(effects.refusals.isEmpty, row.id)
            XCTAssertEqual(Set(effects.writes.map { $0.cell }), Set([32, 64]), row.id)
            XCTAssertEqual(effects.reads.contains(32), !["raddhn", "umull2"].contains(row.mnemonic), row.id)
            XCTAssertEqual(effects.reads.contains(64), !["raddhn", "umull2"].contains(row.mnemonic), row.id)
            XCTAssertFalse(effects.reads.contains(98), row.id)
            let actual = parsed.semantics.evaluate(n: row.n, m: row.m, oldDestination: row.old)
            XCTAssertEqual(actual.low, row.expected.low, row.id)
            XCTAssertEqual(actual.high, row.expected.high, row.id)
            XCTAssertFalse(parsed.semantics.setsQC, row.id)
            if row.mnemonic == "rshrn2" { XCTAssertEqual(actual.low, row.old.low, row.id) }
        }
    }

    func testInvalidFormsRemainRefused() {
        for (mnemonic, operands) in [
            ("smlsl2", "v0.8h, v1.8b, v2.8b"),
            ("umlsl2", "v0.8h, v1.8b, v2.8b"),
            ("umlsl2", "v0.4s, v1.8h, v2.4h"),
            ("raddhn", "v0.8b, v1.8h, v2.4s"),
            ("rshrn2", "v0.16b, v1.8h, #0"),
            ("rshrn2", "v0.16b, v1.8h, #9")
        ] {
            XCTAssertNil(MacIRBuilder.ssaIntegerLaneOperation(mnemonic: mnemonic, operands: operands))
            let effects = MacIRBuilder.ssaEffects(for: .init(address: 0x1000, byteText: "", mnemonic: mnemonic, operands: operands))
            XCTAssertFalse(effects.refusals.isEmpty)
            let flow = C2MachineFlow(rows: [.init(address: 0x1000, byteText: "", mnemonic: mnemonic, operands: operands)])
            XCTAssertNotNil(flow.error)
        }
    }

    func testEveryRetainedFirstBlockerHasAdmission() throws {
        let sites: [(UInt64, String, String)] = [
            // rshrn_advsimd.xml#Operation
            (0x3d890, "rshrn2", "v4.8h, v19.4s, #0x2"),
            // raddhn_advsimd.xml#Operation
            (0x4e27c, "raddhn", "v6.4h, v6.4s, v11.4s"),
            // raddhn_advsimd.xml#Operation
            (0x4e6b8, "raddhn", "v6.4h, v6.4s, v11.4s"),
            // raddhn_advsimd.xml#Operation
            (0x4eaf4, "raddhn", "v6.4h, v6.4s, v11.4s"),
            // raddhn_advsimd.xml#Operation
            (0x4ef30, "raddhn", "v6.4h, v6.4s, v11.4s"),
            // raddhn_advsimd.xml#Operation
            (0x4f36c, "raddhn", "v6.4h, v6.4s, v11.4s"),
            // raddhn_advsimd.xml#Operation
            (0x4f7a8, "raddhn", "v6.4h, v6.4s, v11.4s"),
            // raddhn_advsimd.xml#Operation
            (0x4fbe4, "raddhn", "v6.4h, v6.4s, v11.4s"),
            // raddhn_advsimd.xml#Operation
            (0x4ffe0, "raddhn", "v0.4h, v1.4s, v19.4s"),
            // raddhn_advsimd.xml#Operation
            (0x50160, "raddhn", "v0.4h, v1.4s, v19.4s"),
            // raddhn_advsimd.xml#Operation
            (0x502dc, "raddhn", "v0.4h, v1.4s, v20.4s"),
            // raddhn_advsimd.xml#Operation
            (0x5045c, "raddhn", "v0.4h, v1.4s, v19.4s"),
            // raddhn_advsimd.xml#Operation
            (0x505d8, "raddhn", "v0.4h, v1.4s, v20.4s"),
            // raddhn_advsimd.xml#Operation
            (0x50754, "raddhn", "v0.4h, v1.4s, v20.4s"),
            // raddhn_advsimd.xml#Operation
            (0x508d0, "raddhn", "v0.4h, v1.4s, v20.4s"),
            // smlsl_advsimd_vec.xml#Operation
            (0x51e9c, "smlsl2", "v18.4s, v7.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x520dc, "smlsl2", "v18.4s, v7.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x52320, "smlsl2", "v22.4s, v19.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x525b0, "smlsl2", "v18.4s, v7.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x527f4, "smlsl2", "v22.4s, v19.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x52a88, "smlsl2", "v22.4s, v19.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x52d1c, "smlsl2", "v22.4s, v19.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x52fac, "smlsl2", "v18.4s, v7.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x531f0, "smlsl2", "v17.4s, v7.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x53418, "smlsl2", "v19.4s, v17.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x5371c, "smlsl2", "v17.4s, v7.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x53944, "smlsl2", "v19.4s, v17.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x53c50, "smlsl2", "v21.4s, v19.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x53f18, "smlsl2", "v23.4s, v17.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x54338, "smlsl2", "v17.4s, v7.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x54560, "smlsl2", "v19.4s, v17.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x5486c, "smlsl2", "v21.4s, v19.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x54b34, "smlsl2", "v23.4s, v17.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x54f5c, "smlsl2", "v21.4s, v19.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x55224, "smlsl2", "v23.4s, v17.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x55664, "smlsl2", "v21.4s, v19.8h, v2.8h"),
            // smlsl_advsimd_vec.xml#Operation
            (0x5592c, "smlsl2", "v23.4s, v17.8h, v2.8h"),
            // rshrn_advsimd.xml#Operation
            (0x55d9c, "rshrn2", "v16.16b, v2.8h, #0x2"),
            // rshrn_advsimd.xml#Operation
            (0x5649c, "rshrn2", "v7.8h, v16.4s, #0xb"),
            // rshrn_advsimd.xml#Operation
            (0x574d8, "rshrn2", "v1.8h, v3.4s, #0xd"),
            // rshrn_advsimd.xml#Operation
            (0x576a4, "rshrn2", "v23.8h, v5.4s, #0xc"),
        ]
        XCTAssertEqual(sites.count, 41)
        for (address, mnemonic, operands) in sites {
            let source = MacIRSourceSpan(address: address, byteText: "", mnemonic: mnemonic, operands: operands)
            XCTAssertNotNil(MacIRBuilder.ssaIntegerLaneOperation(mnemonic: mnemonic, operands: operands))
            XCTAssertTrue(MacIRBuilder.ssaEffects(for: source).refusals.isEmpty)
            XCTAssertNil(C2MachineFlow(rows: [source]).error)
        }
    }
    func testUMLSL2FirstBlockersHaveAdmission() {
        let sites: [(UInt64, String)] = [
            (0x4e53c, "v19.4s, v7.8h, v29.8h"),
            (0x4e978, "v19.4s, v7.8h, v29.8h"),
            (0x4edb4, "v19.4s, v16.8h, v29.8h"),
            (0x4f1f0, "v19.4s, v7.8h, v29.8h"),
            (0x4f62c, "v19.4s, v16.8h, v29.8h"),
            (0x4fa68, "v19.4s, v16.8h, v29.8h"),
            (0x4fea4, "v19.4s, v16.8h, v29.8h"),
        ]
        XCTAssertEqual(sites.count, 7)
        for (address, operands) in sites {
            let source = MacIRSourceSpan(address: address, byteText: "", mnemonic: "umlsl2", operands: operands)
            XCTAssertNotNil(MacIRBuilder.ssaIntegerLaneOperation(mnemonic: "umlsl2", operands: operands))
            XCTAssertTrue(MacIRBuilder.ssaEffects(for: source).refusals.isEmpty)
            XCTAssertNil(C2MachineFlow(rows: [source]).error)
        }
    }

    func testUMLSL2AllCensusSitesAreAdmitted() {
        let sites: [(UInt64, String)] = [
            (0x4e53c, "v19.4s, v7.8h, v29.8h"),
            (0x4e540, "v19.4s, v2.8h, v30.8h"),
            (0x4e54c, "v21.4s, v16.8h, v29.8h"),
            (0x4e550, "v21.4s, v1.8h, v30.8h"),
            (0x4e56c, "v23.4s, v2.8h, v31.8h"),
            (0x4e570, "v23.4s, v3.8h, v9.8h"),
            (0x4e57c, "v25.4s, v1.8h, v31.8h"),
            (0x4e580, "v25.4s, v0.8h, v9.8h"),
            (0x4e678, "v19.4s, v16.8h, v29.8h"),
            (0x4e67c, "v19.4s, v2.8h, v30.8h"),
            (0x4e688, "v21.4s, v4.8h, v29.8h"),
            (0x4e68c, "v21.4s, v1.8h, v30.8h"),
            (0x4e6a8, "v23.4s, v2.8h, v31.8h"),
            (0x4e6ac, "v23.4s, v3.8h, v9.8h"),
            (0x4e6b8, "v25.4s, v1.8h, v31.8h"),
            (0x4e6bc, "v25.4s, v0.8h, v9.8h"),
            (0x4e75c, "v6.4s, v3.8h, v29.8h"),
            (0x4e760, "v6.4s, v4.8h, v30.8h"),
            (0x4e788, "v16.4s, v4.8h, v31.8h"),
            (0x4e78c, "v16.4s, v0.8h, v9.8h"),
            (0x4e978, "v19.4s, v7.8h, v29.8h"),
            (0x4e97c, "v19.4s, v2.8h, v30.8h"),
            (0x4e988, "v21.4s, v16.8h, v29.8h"),
            (0x4e98c, "v21.4s, v1.8h, v30.8h"),
            (0x4e9a8, "v23.4s, v2.8h, v31.8h"),
            (0x4e9ac, "v23.4s, v3.8h, v9.8h"),
            (0x4e9b8, "v25.4s, v1.8h, v31.8h"),
            (0x4e9bc, "v25.4s, v0.8h, v9.8h"),
            (0x4eab4, "v19.4s, v16.8h, v29.8h"),
            (0x4eab8, "v19.4s, v2.8h, v30.8h"),
            (0x4eac4, "v21.4s, v4.8h, v29.8h"),
            (0x4eac8, "v21.4s, v1.8h, v30.8h"),
            (0x4eae4, "v23.4s, v2.8h, v31.8h"),
            (0x4eae8, "v23.4s, v3.8h, v9.8h"),
            (0x4eaf4, "v25.4s, v1.8h, v31.8h"),
            (0x4eaf8, "v25.4s, v0.8h, v9.8h"),
            (0x4eb98, "v6.4s, v3.8h, v29.8h"),
            (0x4eb9c, "v6.4s, v4.8h, v30.8h"),
            (0x4ebc4, "v16.4s, v4.8h, v31.8h"),
            (0x4ebc8, "v16.4s, v0.8h, v9.8h"),
            (0x4edb4, "v19.4s, v16.8h, v29.8h"),
            (0x4edb8, "v19.4s, v2.8h, v30.8h"),
            (0x4edc4, "v21.4s, v17.8h, v29.8h"),
            (0x4edc8, "v21.4s, v1.8h, v30.8h"),
            (0x4ede4, "v23.4s, v2.8h, v31.8h"),
            (0x4ede8, "v23.4s, v3.8h, v9.8h"),
            (0x4edf4, "v25.4s, v1.8h, v31.8h"),
            (0x4edf8, "v25.4s, v0.8h, v9.8h"),
            (0x4eef0, "v19.4s, v5.8h, v29.8h"),
            (0x4eef4, "v19.4s, v2.8h, v30.8h"),
            (0x4ef00, "v21.4s, v4.8h, v29.8h"),
            (0x4ef04, "v21.4s, v1.8h, v30.8h"),
            (0x4ef20, "v23.4s, v2.8h, v31.8h"),
            (0x4ef24, "v23.4s, v3.8h, v9.8h"),
            (0x4ef30, "v25.4s, v1.8h, v31.8h"),
            (0x4ef34, "v25.4s, v0.8h, v9.8h"),
            (0x4efd4, "v6.4s, v4.8h, v29.8h"),
            (0x4efd8, "v6.4s, v5.8h, v30.8h"),
            (0x4f000, "v16.4s, v5.8h, v31.8h"),
            (0x4f004, "v16.4s, v0.8h, v9.8h"),
            (0x4f1f0, "v19.4s, v7.8h, v29.8h"),
            (0x4f1f4, "v19.4s, v2.8h, v30.8h"),
            (0x4f200, "v21.4s, v16.8h, v29.8h"),
            (0x4f204, "v21.4s, v1.8h, v30.8h"),
            (0x4f220, "v23.4s, v2.8h, v31.8h"),
            (0x4f224, "v23.4s, v3.8h, v9.8h"),
            (0x4f230, "v25.4s, v1.8h, v31.8h"),
            (0x4f234, "v25.4s, v0.8h, v9.8h"),
            (0x4f32c, "v19.4s, v16.8h, v29.8h"),
            (0x4f330, "v19.4s, v2.8h, v30.8h"),
            (0x4f33c, "v21.4s, v4.8h, v29.8h"),
            (0x4f340, "v21.4s, v1.8h, v30.8h"),
            (0x4f35c, "v23.4s, v2.8h, v31.8h"),
            (0x4f360, "v23.4s, v3.8h, v9.8h"),
            (0x4f36c, "v25.4s, v1.8h, v31.8h"),
            (0x4f370, "v25.4s, v0.8h, v9.8h"),
            (0x4f410, "v6.4s, v3.8h, v29.8h"),
            (0x4f414, "v6.4s, v4.8h, v30.8h"),
            (0x4f43c, "v16.4s, v4.8h, v31.8h"),
            (0x4f440, "v16.4s, v0.8h, v9.8h"),
            (0x4f62c, "v19.4s, v16.8h, v29.8h"),
            (0x4f630, "v19.4s, v2.8h, v30.8h"),
            (0x4f63c, "v21.4s, v17.8h, v29.8h"),
            (0x4f640, "v21.4s, v1.8h, v30.8h"),
            (0x4f65c, "v23.4s, v2.8h, v31.8h"),
            (0x4f660, "v23.4s, v3.8h, v9.8h"),
            (0x4f66c, "v25.4s, v1.8h, v31.8h"),
            (0x4f670, "v25.4s, v0.8h, v9.8h"),
            (0x4f768, "v19.4s, v5.8h, v29.8h"),
            (0x4f76c, "v19.4s, v2.8h, v30.8h"),
            (0x4f778, "v21.4s, v4.8h, v29.8h"),
            (0x4f77c, "v21.4s, v1.8h, v30.8h"),
            (0x4f798, "v23.4s, v2.8h, v31.8h"),
            (0x4f79c, "v23.4s, v3.8h, v9.8h"),
            (0x4f7a8, "v25.4s, v1.8h, v31.8h"),
            (0x4f7ac, "v25.4s, v0.8h, v9.8h"),
            (0x4f84c, "v6.4s, v4.8h, v29.8h"),
            (0x4f850, "v6.4s, v5.8h, v30.8h"),
            (0x4f878, "v16.4s, v5.8h, v31.8h"),
            (0x4f87c, "v16.4s, v0.8h, v9.8h"),
            (0x4fa68, "v19.4s, v16.8h, v29.8h"),
            (0x4fa6c, "v19.4s, v2.8h, v30.8h"),
            (0x4fa78, "v21.4s, v17.8h, v29.8h"),
            (0x4fa7c, "v21.4s, v1.8h, v30.8h"),
            (0x4fa98, "v23.4s, v2.8h, v31.8h"),
            (0x4fa9c, "v23.4s, v3.8h, v9.8h"),
            (0x4faa8, "v25.4s, v1.8h, v31.8h"),
            (0x4faac, "v25.4s, v0.8h, v9.8h"),
            (0x4fba4, "v19.4s, v5.8h, v29.8h"),
            (0x4fba8, "v19.4s, v2.8h, v30.8h"),
            (0x4fbb4, "v21.4s, v4.8h, v29.8h"),
            (0x4fbb8, "v21.4s, v1.8h, v30.8h"),
            (0x4fbd4, "v23.4s, v2.8h, v31.8h"),
            (0x4fbd8, "v23.4s, v3.8h, v9.8h"),
            (0x4fbe4, "v25.4s, v1.8h, v31.8h"),
            (0x4fbe8, "v25.4s, v0.8h, v9.8h"),
            (0x4fc88, "v6.4s, v4.8h, v29.8h"),
            (0x4fc8c, "v6.4s, v5.8h, v30.8h"),
            (0x4fcb4, "v16.4s, v5.8h, v31.8h"),
            (0x4fcb8, "v16.4s, v0.8h, v9.8h"),
            (0x4fea4, "v19.4s, v16.8h, v29.8h"),
            (0x4fea8, "v19.4s, v2.8h, v30.8h"),
            (0x4feb4, "v21.4s, v17.8h, v29.8h"),
            (0x4feb8, "v21.4s, v1.8h, v30.8h"),
            (0x4fed4, "v23.4s, v2.8h, v31.8h"),
            (0x4fed8, "v23.4s, v3.8h, v9.8h"),
            (0x4fee4, "v25.4s, v1.8h, v31.8h"),
            (0x4fee8, "v25.4s, v0.8h, v9.8h"),
            (0x4ffe0, "v19.4s, v5.8h, v29.8h"),
            (0x4ffe4, "v19.4s, v2.8h, v30.8h"),
            (0x4fff0, "v21.4s, v4.8h, v29.8h"),
            (0x4fff4, "v21.4s, v1.8h, v30.8h"),
            (0x50010, "v23.4s, v2.8h, v31.8h"),
            (0x50014, "v23.4s, v3.8h, v9.8h"),
            (0x50020, "v25.4s, v1.8h, v31.8h"),
            (0x50024, "v25.4s, v0.8h, v9.8h"),
            (0x500c4, "v6.4s, v4.8h, v29.8h"),
            (0x500c8, "v6.4s, v5.8h, v30.8h"),
            (0x500f0, "v16.4s, v5.8h, v31.8h"),
            (0x500f4, "v16.4s, v0.8h, v9.8h"),
        ]
        XCTAssertEqual(sites.count, 140)
        for (address, operands) in sites {
            let source = MacIRSourceSpan(address: address, byteText: "", mnemonic: "umlsl2", operands: operands)
            XCTAssertNotNil(MacIRBuilder.ssaIntegerLaneOperation(mnemonic: "umlsl2", operands: operands))
            XCTAssertTrue(MacIRBuilder.ssaEffects(for: source).refusals.isEmpty)
            XCTAssertNil(C2MachineFlow(rows: [source]).error)
        }
    }

    func testUMLSL2ByElementRemainsHarnessRefused() {
        let source = MacIRSourceSpan(address: 0x1000, byteText: "", mnemonic: "umlsl2", operands: "v0.2d, v1.4s, v2.s[1]")
        // The indexed descriptor is valid; only the independent harness rejects it.
        XCTAssertNotNil(MacIRBuilder.ssaIntegerLaneOperation(mnemonic: source.mnemonic, operands: source.operands))
        XCTAssertTrue(MacIRBuilder.ssaEffects(for: source).refusals.isEmpty)
        XCTAssertNotNil(C2MachineFlow(rows: [source]).error)
    }

}
