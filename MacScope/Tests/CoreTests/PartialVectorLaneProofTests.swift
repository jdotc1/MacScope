import XCTest
@testable import MacScope

// Descriptor, machine-flow, exact parser/renderer and census regression controls
// for selected-lane vector loads (LD1 halfword lanes and LD4 B/H/S/D lanes).
final class PartialVectorLaneProofTests: XCTestCase {
    private func register(_ name: String, _ version: Int = 0) -> MacIRValue {
        .register(name: name, version: version)
    }

    private func frame(
        elementBytes: Int = 2, laneIndex: Int = 1,
        old: MacIRValue = .register(name: "v16", version: 0),
        destination: MacIRValue = .register(name: "v16", version: 1),
        oldBase: MacIRValue = .register(name: "x12", version: 0),
        baseDestination: MacIRValue? = nil,
        post: MacIRNEONContiguousRegisterPost? = nil
    ) -> MacIRNEONStructureLaneMemory? {
        .init(effect: .load, elementBytes: elementBytes, laneIndex: laneIndex,
              structureCount: 1, baseRegister: "x12", oldBase: oldBase,
              oldVectors: [old], destinations: [destination],
              baseDestination: baseDestination, frameSequence: 0,
              firstByteSequence: 0, registerPost: post)
    }

    private func row(_ address: UInt64, _ mnemonic: String, _ operands: String) -> MacIRSourceSpan {
        // This independent decoded-text model does not read byteText. Empty
        // bytes intentionally prevent this fixture from claiming decoder proof.
        .init(address: address, byteText: "", mnemonic: mnemonic, operands: operands)
    }

    func testEveryHalfwordLaneHasExactlyFourteenPreservedBytes() throws {
        for lane in 0..<8 {
            let effect = try XCTUnwrap(frame(laneIndex: lane))
            let replaced = Set([2 * lane, 2 * lane + 1])
            XCTAssertEqual(effect.vectorByteOffset, 2 * lane)
            XCTAssertEqual(effect.byteCount, 2)
            XCTAssertEqual(effect.orderedBytes.map(\.offset), [0, 1])
            XCTAssertEqual(effect.orderedBytes.map(\.vector), [0, 0])
            XCTAssertEqual(effect.orderedBytes.map(\.lane), [2 * lane, 2 * lane + 1])
            XCTAssertEqual(effect.preservedVectorBytes.count, 14)
            XCTAssertTrue(Set(effect.preservedVectorBytes).isDisjoint(with: replaced))
            XCTAssertEqual(Set(effect.preservedVectorBytes).union(replaced), Set(0..<16))
        }
    }

    func testUnknownWidthLaneAndCarrierEvidenceFailClosed() {
        for width in [-1, 0, 1, 3, 4, 8, 16] {
            XCTAssertNil(frame(elementBytes: width))
        }
        for lane in [-1, 8, Int.max] {
            XCTAssertNil(frame(laneIndex: lane))
        }
        XCTAssertNil(frame(old: .unknown("unavailable_v16")))
        XCTAssertNil(frame(destination: .unknown("unavailable_v16")))
        XCTAssertNil(frame(oldBase: .unknown("unavailable_x12")))
        XCTAssertNil(frame(old: .unary(op: "(uint64_t)", value: register("v16"))))
        for alias in ["q16", "d16", "s16", "h16", "b16", "vh16"] {
            XCTAssertNil(frame(old: register(alias)))
            XCTAssertNil(frame(destination: register(alias, 1)))
        }
        XCTAssertNil(frame(old: register("v16", -1)))
    }

    func testNewIdentityMustBelongToSamePhysicalVector() throws {
        XCTAssertNil(frame(destination: register("v17", 1)))
        XCTAssertNil(frame(destination: register("v16", 0)))
        XCTAssertNil(frame(old: register("v16", 7), destination: register("v16", 6)))
        // Nonadjacent fresh identities are permitted by the supplied descriptor.
        let effect = try XCTUnwrap(frame(old: register("v16", 7), destination: register("v16", 64)))
        XCTAssertEqual(effect.oldVectors, [register("v16", 7)])
        XCTAssertEqual(effect.destinations, [register("v16", 64)])
    }

    func testPartialUpdateCannotDropOrSubstituteItsPreservedCarrier() throws {
        let effect = try XCTUnwrap(frame())
        XCTAssertTrue(effect.matches(effect.operation(0), ordinal: 0))
        let base = register("x12"), old = register("v16"), output = register("v16", 1)
        for arguments in [[base], [base, output], [old, base], [base, register("v17")]] {
            XCTAssertFalse(effect.matches(.intrinsic(destination: output,
                name: "neon_structure_lane_load", arguments: arguments), ordinal: 0))
        }
        XCTAssertFalse(effect.matches(.load(destination: output, address: base), ordinal: 0))
        XCTAssertFalse(effect.matches(effect.operation(0), ordinal: -1))
        XCTAssertFalse(effect.matches(effect.operation(0), ordinal: 1))
    }

    func testAliasedPostIndexUsesTheOldBaseSnapshot() throws {
        let old = register("x12", 4), new = register("x12", 9)
        let post = try XCTUnwrap(MacIRNEONContiguousRegisterPost(
            incrementRegister: "x12", oldIncrement: old))
        let effect = try XCTUnwrap(frame(oldBase: old, baseDestination: new, post: post))
        XCTAssertEqual(effect.newBase, .binaryExpression(op: "+", left: old, right: old))
        XCTAssertEqual(effect.fixedPostDelta, 0)
        XCTAssertEqual(effect.effectCount, 2)
        XCTAssertEqual(effect.operation(1), .assign(destination: new, source: effect.newBase))
        XCTAssertNil(frame(oldBase: old, post: post))
        let wrong = try XCTUnwrap(MacIRNEONContiguousRegisterPost(
            incrementRegister: "x12", oldIncrement: new))
        XCTAssertNil(frame(oldBase: old, baseDestination: new, post: wrong))
        XCTAssertNil(MacIRNEONContiguousRegisterPost(
            incrementRegister: "w12", oldIncrement: register("w12", 4)))
    }

    func testLaneChainReadsPriorPartialValueAndWholeAliasConsumer() {
        let rows = [row(0x1000, "ld1", "{v16.h}[1], [x12]"),
                    row(0x1004, "ld1", "{v16.h}[7], [x12], x12"),
                    row(0x1008, "str", "q16, [x0]"),
                    row(0x100c, "ret", "")]
        let flow = C2MachineFlow(rows: rows)
        XCTAssertNil(flow.error)
        XCTAssertEqual(flow.reads[0], Set(["v16", "x12"]))
        XCTAssertEqual(flow.reads[1], Set(["v16", "x12"]))
        XCTAssertEqual(flow.writes[1], Set(["v16", "x12"]))
        XCTAssertEqual(flow.before[0]["v16"], Set([UInt64(0)]))
        XCTAssertEqual(flow.before[1]["v16"], Set([UInt64(0x1000)]))
        XCTAssertEqual(flow.before[2]["v16"], Set([UInt64(0x1004)]))
        XCTAssertEqual(flow.before[2]["x12"], Set([UInt64(0x1004)]))
        XCTAssertEqual(flow.reads[2], Set(["v16", "x0"]))
    }

    func testJoinRetainsBothPossiblePartialUpdateProducers() {
        let flow = C2MachineFlow(rows: [
            row(0x1000, "cbz", "x0, 0x100c"),
            row(0x1004, "ld1", "{v16.h}[1], [x12]"),
            row(0x1008, "b", "0x1010"),
            row(0x100c, "ld1", "{v16.h}[7], [x12]"),
            row(0x1010, "ld1", "{v16.h}[3], [x12]"),
            row(0x1014, "str", "q16, [x1]"), row(0x1018, "ret", "")])
        XCTAssertNil(flow.error)
        XCTAssertEqual(flow.before[4]["v16"], Set([UInt64(0x1004), UInt64(0x100c)]))
        XCTAssertEqual(flow.reads[4], Set(["v16", "x12"]))
        XCTAssertEqual(flow.before[5]["v16"], Set([UInt64(0x1010)]))
    }

    func testUnprovedLaneFormsRemainNamedRefusals() {
        for operands in ["{v16.b}[0], [x12]", "{v16.s}[0], [x12]",
                         "{v16.d}[0], [x12]", "{v16.h}[8], [x12]",
                         "{v16.h}[1], [sp]", "{v16.h}[1], [x12], w13",
                         "{v16.h}[1], [x12], #4"] {
            XCTAssertEqual(C2MachineFlow(rows: [row(0x1000, "ld1", operands)]).error,
                "0x1000: partial vector lane load")
        }
        for mnemonic in ["ld2", "ld3", "ld4"] {
            XCTAssertEqual(C2MachineFlow(rows: [row(0x1000, mnemonic,
                "{v16.h, v17.h}[1], [x12]")]).error,
                "0x1000: partial vector lane load")
        }
    }

    func testLD4EveryWidthPreservesFourInputsAndDefinesFourResults() throws {
        for (suffix, bytes) in [("b", 1), ("h", 2), ("s", 4), ("d", 8)] {
            for lane in [0, 16 / bytes - 1] {
                let vectors = [30, 31, 0, 1]
                let effect = try XCTUnwrap(MacIRNEONStructureLaneMemory(effect: .load,
                    elementBytes: bytes, laneIndex: lane, structureCount: 4,
                    baseRegister: "x12", oldBase: register("x12"),
                    oldVectors: vectors.map { register("v\($0)") },
                    destinations: vectors.map { register("v\($0)", 1) },
                    baseDestination: nil, frameSequence: 0, firstByteSequence: 0))
                let replaced = Set((lane * bytes)..<((lane + 1) * bytes))
                XCTAssertEqual(effect.preservedVectorBytes.count, 16 - bytes)
                XCTAssertTrue(Set(effect.preservedVectorBytes).isDisjoint(with: replaced))
                XCTAssertEqual(Set(effect.preservedVectorBytes).union(replaced), Set(0..<16))
                XCTAssertEqual(effect.orderedBytes.map(\.offset), Array(0..<(4 * bytes)))
                XCTAssertEqual(effect.orderedBytes.map(\.vector), (0..<4).flatMap { member in
                    Array(repeating: member, count: bytes)
                })
                XCTAssertEqual(effect.orderedBytes.map(\.lane), (0..<4).flatMap { _ in
                    Array((lane * bytes)..<((lane + 1) * bytes))
                })
                for base in ["x12", "sp"] {
                    for post in ["", ", #\(4 * bytes)", ", #0x\(String(4 * bytes, radix: 16))", ", x13", ", x12"] {
                        let list = "{v30.\(suffix), v31.\(suffix), v0.\(suffix), v1.\(suffix)}[\(lane)]"
                        let consumers = vectors.enumerated().map { offset, vector in
                            row(0x1004 + UInt64(4 * offset), "str", "q\(vector), [x4]")
                        }
                        let flow = C2MachineFlow(rows: [
                            row(0x1000, "ld4", "\(list), [\(base)]\(post)")]
                            + consumers + [row(0x1014, "ret", "")])
                        XCTAssertNil(flow.error, "\(list) [\(base)]\(post)")
                        var reads = Set(["v30", "v31", "v0", "v1", base])
                        if post == ", x13" { reads.insert("x13") }
                        if post == ", x12" { reads.insert("x12") }
                        var writes = Set(["v30", "v31", "v0", "v1"])
                        if !post.isEmpty { writes.insert(base) }
                        XCTAssertEqual(flow.reads[0], reads)
                        XCTAssertEqual(flow.writes[0], writes)
                        XCTAssertEqual(flow.mustWrites[0], writes)
                        XCTAssertTrue(flow.mayWrites[0].isEmpty)
                        for vector in ["v30", "v31", "v0", "v1"] {
                            XCTAssertEqual(flow.before[0][vector], Set([UInt64(0)]))
                            XCTAssertEqual(flow.before[1][vector], Set([UInt64(0x1000)]))
                        }
                        for (offset, vector) in vectors.enumerated() {
                            XCTAssertEqual(flow.reads[offset + 1], Set(["v\(vector)", "x4"]))
                            XCTAssertEqual(flow.before[offset + 1]["v\(vector)"], Set([UInt64(0x1000)]))
                        }
                        XCTAssertEqual(flow.before[0][base], Set([UInt64(0)]))
                        XCTAssertEqual(flow.before[1][base], Set([post.isEmpty ? UInt64(0) : UInt64(0x1000)]))
                    }
                }
            }
        }
    }

    func testLD4EveryMemberRequiresPhysicalOldAndStrictlyNewerMatchingIdentity() throws {
        let vectors = [30, 31, 0, 1]
        let old = vectors.map { register("v\($0)", 7) }
        let fresh = vectors.map { register("v\($0)", 64) }
        for bytes in [1, 2, 4, 8] {
            func make(_ inputs: [MacIRValue], _ outputs: [MacIRValue]) -> MacIRNEONStructureLaneMemory? {
                .init(effect: .load, elementBytes: bytes, laneIndex: 16 / bytes - 1,
                    structureCount: 4, baseRegister: "x12", oldBase: register("x12", 4),
                    oldVectors: inputs, destinations: outputs, baseDestination: nil,
                    frameSequence: 0, firstByteSequence: 0)
            }
            let effect = try XCTUnwrap(make(old, fresh))
            XCTAssertEqual(effect.oldVectors, old)
            XCTAssertEqual(effect.destinations, fresh)
            XCTAssertNil(make(Array(old.dropLast()), fresh))
            XCTAssertNil(make(old, Array(fresh.dropLast())))
            for (member, vector) in vectors.enumerated() {
                for invalid in [MacIRValue.unknown("unavailable_v\(vector)"),
                                register("q\(vector)", 7), register("v\(vector)", -1),
                                register("v\((vector + 8) % 32)", 7)] {
                    var inputs = old
                    inputs[member] = invalid
                    XCTAssertNil(make(inputs, fresh), "old member \(member), width \(bytes)")
                }
                for invalid in [MacIRValue.unknown("unavailable_v\(vector)"),
                                register("q\(vector)", 64), register("v\((vector + 8) % 32)", 64),
                                register("v\(vector)", 7), register("v\(vector)", 6)] {
                    var outputs = fresh
                    outputs[member] = invalid
                    XCTAssertNil(make(old, outputs), "destination member \(member), width \(bytes)")
                }
                XCTAssertTrue(effect.matches(effect.operation(member), ordinal: member))
                for arguments in [[register("x12", 4)],
                                  [register("x12", 4), fresh[member]],
                                  [old[member], register("x12", 4)],
                                  [register("x12", 4), old[(member + 1) % 4]]] {
                    XCTAssertFalse(effect.matches(.intrinsic(destination: fresh[member],
                        name: "neon_structure_lane_load", arguments: arguments), ordinal: member))
                }
            }
        }
    }

    func testLD4AliasedRegisterPostRequiresTheOldBaseForAllMembers() throws {
        let oldBase = register("x12", 4)
        let newBase = register("x12", 9)
        let vectors = [30, 31, 0, 1]
        let old = vectors.map { register("v\($0)", 7) }
        let fresh = vectors.map { register("v\($0)", 64) }
        let post = try XCTUnwrap(MacIRNEONContiguousRegisterPost(
            incrementRegister: "x12", oldIncrement: oldBase))
        func make(_ increment: MacIRNEONContiguousRegisterPost,
                  _ destination: MacIRValue?) -> MacIRNEONStructureLaneMemory? {
            .init(effect: .load, elementBytes: 8, laneIndex: 1, structureCount: 4,
                baseRegister: "x12", oldBase: oldBase, oldVectors: old, destinations: fresh,
                baseDestination: destination, frameSequence: 0, firstByteSequence: 0,
                registerPost: increment)
        }
        let effect = try XCTUnwrap(make(post, newBase))
        XCTAssertEqual(effect.effectCount, 5)
        XCTAssertEqual(effect.fixedPostDelta, 0)
        XCTAssertEqual(effect.newBase, .binaryExpression(op: "+", left: oldBase, right: oldBase))
        for member in 0..<4 {
            XCTAssertEqual(effect.operation(member), .intrinsic(destination: fresh[member],
                name: "neon_structure_lane_load", arguments: [oldBase, old[member]]))
        }
        XCTAssertEqual(effect.operation(4), .assign(destination: newBase, source: effect.newBase))
        XCTAssertNil(make(post, nil))
        XCTAssertNil(make(post, oldBase))
        let wrong = try XCTUnwrap(MacIRNEONContiguousRegisterPost(
            incrementRegister: "x12", oldIncrement: newBase))
        XCTAssertNil(make(wrong, newBase))
    }

    func testLD4UnknownOrInconsistentLaneEvidenceRemainsRefused() {
        let invalid = [
            "{v0.b, v1.b, v2.b, v3.b}[16], [x9]",
            "{v0.h, v1.h, v2.h, v3.h}[8], [x9]",
            "{v0.s, v1.s, v2.s, v3.s}[4], [x9]",
            "{v0.d, v1.d, v2.d, v3.d}[2], [x9]",
            "{v0.h, v1.s, v2.h, v3.h}[1], [x9]",
            "{v0.h, v1.h, v3.h, v4.h}[1], [x9]",
            "{v0.h, v1.h, v1.h, v2.h}[1], [x9]",
            "{v31.h, v0.h, v1.h, v3.h}[1], [x9]",
            "{v0.h, v1.h, v2.h}[1], [x9]",
            "{v0.h, v1.h, v2.h, v32.h}[1], [x9]",
            "{v00.h, v1.h, v2.h, v3.h}[1], [x9]",
            "{v0.h, v1.h, v2.h, v3.h}[01], [x9]",
            "{v0.h, v1.h, v2.h, v3.h}[?], [x9]",
            "{v0.h, v1.h, v2.h, v3.h}[1], [x31]",
            "{v0.h, v1.h, v2.h, v3.h}[1], [w9]",
            "{v0.h, v1.h, v2.h, v3.h}[1], [x9], #2",
            "{v0.h, v1.h, v2.h, v3.h}[1], [x9], #-8",
            "{v0.h, v1.h, v2.h, v3.h}[1], [x9], w13",
            "{v0.h, v1.h, v2.h, v3.h}[1], [x9], xzr",
            "{v0.h, v1.h, v2.h, v3.h}[1], [x9], sp",
            "{v0.h, v1.h, v2.h, v3.h}[1], [x9, #8]",
            "{v0.h, v1.h, v2.h, v3.h}[1], [x9]!, #8",
            "{v0.h, v1.h, v2.h, v3.h}[1], [x9], #8, x0"
        ]
        for operands in invalid {
            XCTAssertEqual(C2MachineFlow(rows: [row(0x1000, "ld4", operands)]).error,
                           "0x1000: partial vector lane load", operands)
        }
        XCTAssertEqual(C2MachineFlow(rows: [row(0x1000, "ld4",
            "{v0.h-v3.h}[1], [x9]")]).error,
            "0x1000: vector register-list range requires expansion")
        // The retained common memory gate rejects a '-' in the list operand
        // before the lane-specific gate, including a negative lane spelling.
        XCTAssertEqual(C2MachineFlow(rows: [row(0x1000, "ld4",
            "{v0.h, v1.h, v2.h, v3.h}[-1], [x9]")]).error,
            "0x1000: vector register-list range requires expansion")
        for mnemonic in ["ld2", "ld3"] {
            XCTAssertEqual(C2MachineFlow(rows: [row(0x1000, mnemonic,
                "{v0.h, v1.h, v2.h, v3.h}[1], [x9]")]).error,
                "0x1000: partial vector lane load")
        }
    }

    func testLD4DoesNotErasePartialCallPreservationRefusal() {
        for projection in [false, true] {
            let flow = C2MachineFlow(rows: [row(0x1000, "bl", "0x2000"),
                row(0x1004, "ld4", "{v8.h, v9.h, v10.h, v11.h}[1], [x12]"),
                row(0x1008, "str", "q8, [x0]")], permitDOnlyCallProjection: projection)
            XCTAssertEqual(flow.error,
                "call with v8-v15 use requires partial-register reaching definitions")
        }
    }

    func testLD4JoinCarriesEachOldVectorIntoTheNextPartialUpdate() {
        let list = "{v0.b, v1.b, v2.b, v3.b}"
        let flow = C2MachineFlow(rows: [row(0x1000, "cbz", "x4, 0x100c"),
            row(0x1004, "ld4", "\(list)[0], [x9]"), row(0x1008, "b", "0x1010"),
            row(0x100c, "ld4", "\(list)[15], [x9]"),
            row(0x1010, "ld4", "\(list)[3], [x9]"),
            row(0x1014, "str", "q0, [x10]"), row(0x1018, "ret", "")])
        XCTAssertNil(flow.error)
        for vector in ["v0", "v1", "v2", "v3"] {
            XCTAssertEqual(flow.before[4][vector], Set([UInt64(0x1004), UInt64(0x100c)]))
            XCTAssertEqual(flow.before[5][vector], Set([UInt64(0x1010)]))
            XCTAssertTrue(flow.reads[4].contains(vector))
        }
    }

    func testLD4ExactBytesAndSelectedLaneRendererRemainAuthoritative() throws {
        let operands = "{v0.b, v1.b, v2.b, v3.b}[0], [x9]"
        let decoded = InstructionRow(address: 0x1000, bytes: "20 21 60 0d", mnemonic: "ld4",
            operands: operands, hasBreakpoint: false, comment: nil)
        let parsed = try XCTUnwrap(MacIRBuilder.neonStructureLaneMemory(decoded))
        XCTAssertEqual(parsed.elementBytes, 1)
        XCTAssertEqual(parsed.laneIndex, 0)
        XCTAssertEqual(parsed.vectors, ["v0", "v1", "v2", "v3"])
        let disagreeing = InstructionRow(address: 0x1000, bytes: "21 21 60 0d", mnemonic: "ld4",
            operands: operands, hasBreakpoint: false, comment: nil)
        XCTAssertNil(MacIRBuilder.neonStructureLaneMemory(disagreeing))
        let effect = try XCTUnwrap(MacIRNEONStructureLaneMemory(effect: .load,
            elementBytes: 1, laneIndex: 0, structureCount: 4,
            baseRegister: "x9", oldBase: register("x9"),
            oldVectors: (0..<4).map { register("v\($0)") },
            destinations: (0..<4).map { register("v\($0)", 1) },
            baseDestination: nil, frameSequence: 0, firstByteSequence: 0))
        let source = MacIRSourceSpan(address: 0x1000, byteText: decoded.bytes,
            mnemonic: "ld4", operands: operands)
        let effects = (0..<4).map { ordinal in
            MacIRInstruction(source: source, operation: effect.operation(ordinal),
                neonStructureLaneMemory: .init(frame: effect, ordinal: ordinal))
        }
        let consumers = (0..<4).map { ordinal in
            MacIRInstruction(source: row(0x1004 + UInt64(4 * ordinal), "str", "q\(ordinal), [x10]"),
                operation: .store(source: register("v\(ordinal)", 1), address: register("x10")),
                memoryAccess: .init(byteWidth: 16))
        }
        let function = MacIRFunction(name: "ld4_lane_proof", startAddress: 0x1000,
            returnType: "void", instructions: effects + consumers)
        let printer = PseudocodePrinter(options: DecompilerOptions(structureControlFlow: false,
            deadCodeElimination: false, nopElision: false, functionSizeGate: 1024))
        var names = PseudocodeNameContext(function: function)
        names.redundantCompareIndices = printer.redundantCompareIndices(function: function, names: names)
        for ordinal in 0..<4 {
            let old = printer.valueText(for: register("v\(ordinal)"), names: names)
            let new = printer.valueText(for: register("v\(ordinal)", 1), names: names)
            let rendered = printer.render(instruction: effects[ordinal], names: names)
            XCTAssertTrue(rendered.hasPrefix("\(new) = __neon_insert_lane_8_at_0_preserve_other_bytes(\(old), "), rendered)
            XCTAssertTrue(rendered.contains("*(uint8_t *)"), rendered)
            XCTAssertFalse(rendered.contains("zero_upper"), rendered)
        }
        let document = printer.print(function: function)
        for (ordinal, consumer) in consumers.enumerated() {
            let consumerText = printer.render(instruction: consumer, names: names)
            let expected = printer.valueText(for: register("v\(ordinal)", 1), names: names)
            XCTAssertTrue(consumerText.contains("__uint128_t"), consumerText)
            XCTAssertTrue(consumerText.contains(expected), consumerText)
            XCTAssertTrue(document.lines.contains { $0.sourceAddress == consumer.source.address
                && $0.text.contains(expected) })
        }
        // These flags vary refusal accounting only. This authored fixture does
        // not invoke the lifter and is not an owner SSA C2 execution receipt.
        for accounting in [false, true] {
            let result = C2DataflowCensus.analyze(function: function, document: document,
                machine: [source] + consumers.map(\.source), printer: printer, names: names,
                ssaAccountingEnabled: accounting)
            XCTAssertNil(result.skippedReason, "accounting=\(accounting)")
            XCTAssertTrue(result.rows.isEmpty, "accounting=\(accounting)")
        }
    }
}
