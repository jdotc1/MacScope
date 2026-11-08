import Foundation
import XCTest
@testable import MacScope

/// Entry-phi transport regressions (item 1181).
/// These inspect IR and presentation only. They do not execute recovered code
/// and do not establish full SSA, C2, corpus, or application acceptance.
final class EntryPhiTransportLandingTests: XCTestCase {
    private func row(_ address: UInt64, _ bytes: String, _ mnemonic: String,
                     _ operands: String = "") -> InstructionRow {
        .init(address: address, bytes: bytes, mnemonic: mnemonic, operands: operands,
              hasBreakpoint: false, comment: nil, structuredOperands: nil)
    }

    private var addition: [InstructionRow] { [
        row(0x1000, "00 00 01 8b", "add", "x0, x0, x1"),
        row(0x1004, "42 04 00 f1", "subs", "x2, x2, #1"),
        row(0x1008, "c1 ff ff 54", "b.ne", "0x1000"),
        row(0x100c, "c0 03 5f d6", "ret")
    ] }

    private var swap: [InstructionRow] { [
        row(0x1000, "e3 03 00 aa", "mov", "x3, x0"),
        row(0x1004, "e0 03 01 aa", "mov", "x0, x1"),
        row(0x1008, "e1 03 03 aa", "mov", "x1, x3"),
        row(0x100c, "42 04 00 f1", "subs", "x2, x2, #1"),
        row(0x1010, "81 ff ff 54", "b.ne", "0x1000"),
        row(0x1014, "c0 03 5f d6", "ret")
    ] }

    private func entryFunction(_ rows: [InstructionRow], parameterType: String) throws -> MacIRFunction {
        let parameters = try (0..<3).map { index in
            try XCTUnwrap(MacIRFunctionParameter(id: .init(rawValue: "entry-matrix:\(index)"),
                bindingID: .gpr(index), sourcePosition: index,
                abiLocation: .gpr(index: index, carrierWidth: 64),
                type: parameterType, name: "seed\(index)", evidence: .authoritativeUser))
        }
        let plan = try XCTUnwrap(MacIRAuthoritativeParameterPlan(parameters: parameters, isVariadic: false))
        return MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: true).buildFunction(
            name: "entry_matrix", startAddress: 0x1000, authoritativeParameterPlan: plan,
            authoritativeReturnLocation: .void, authoritativeReturnType: "void", instructions: rows)
    }

    private func projectionText(_ operand: String, width: Int) -> String {
        let sign = width == 32 ? "0x80000000" : "0x8000000000000000"
        return "((\(operand) & \(sign)) == 0 ? (int\(width)_t)\(operand) : -1 - (int\(width)_t)(uint\(width)_t)~\(operand))"
    }

    func testSignedStorageNormalizesBothWidthsUnlessExactTypeIsProved() {
        let value: MacIRValue = .temporary(77)
        let sourceTypes: [String?] = [nil, "int32_t", "uint32_t", "int64_t", "uint64_t", "__uint128_t"]
        for width in [32, 64] {
            let target = "int\(width)_t"
            for sourceType in sourceTypes {
                let expected: MacIRValue = sourceType == target ? value : .binaryExpression(
                    op: MacIRBuilder.signedProjectionOperator,
                    left: .unary(op: "(uint\(width)_t)", value: value),
                    right: .immediate(Int64(width)))
                XCTAssertEqual(PseudocodePrinter.phiTransportValue(value, type: target,
                    sourceType: sourceType), expected,
                    "The destination width, not the source width, owns normalization")
            }
        }
        for type in ["uint32_t", "uint64_t", "__uint128_t", "float", "double"] {
            XCTAssertEqual(PseudocodePrinter.phiTransportValue(value, type: type, sourceType: nil), value)
        }
    }

    func testSignedProjectionKeepsTruncationBeforeHighBitDecision() {
        let printer = PseudocodePrinter()
        let function = MacIRFunction(name: "transport_constants", startAddress: 0, instructions: [])
        let names = PseudocodeNameContext(function: function)
        let boundaries: [Int64] = [0, 1, Int64(Int32.max), Int64(Int32.max) + 1,
                                   Int64(UInt32.max), Int64(UInt32.max) + 1,
                                   Int64.max, Int64.min, -1]
        for width in [32, 64] {
            for boundary in boundaries {
                let value = MacIRValue.immediate(boundary)
                let transported = PseudocodePrinter.phiTransportValue(value,
                    type: "int\(width)_t", sourceType: nil)
                let operand = "(uint\(width)_t)(\(printer.valueText(for: value, names: names)))"
                XCTAssertEqual(printer.valueText(for: transported, names: names),
                    projectionText(operand, width: width))
            }
        }
    }

    func testSignedConsumersDoNotTreatUnsignedPhiStorageAsSigned() {
        let printer = PseudocodePrinter()
        let function = MacIRFunction(name: "signed_consumer", startAddress: 0, instructions: [])
        let value: MacIRValue = .temporary(78)
        for width in [32, 64] {
            let projected = MacIRValue.binaryExpression(op: MacIRBuilder.signedProjectionOperator,
                left: value, right: .immediate(Int64(width)))
            var names = PseudocodeNameContext(function: function)
            names.valueTypes[value] = "uint\(width)_t"
            let spelling = printer.valueText(for: value, names: names)
            XCTAssertEqual(printer.valueText(for: projected, names: names),
                projectionText(spelling, width: width))
            names.valueTypes[value] = "int\(width)_t"
            XCTAssertEqual(printer.valueText(for: projected, names: names),
                "(int\(width)_t)(\(spelling))")
        }
    }

    func testTypedEntrySnapshotsAreExactParallelAndSeparateFromBackedges() throws {
        for parameterType in ["int64_t", "uint64_t"] {
            for rows in [addition, swap] {
                let function = try entryFunction(rows, parameterType: parameterType)
                XCTAssertTrue(MacIRBuilder.hasBoundedEntryLoopProof(function))
                let originalInstructions = function.instructions
                let originalPhis = function.phis
                let printer = PseudocodePrinter(options: .init(structureControlFlow: false,
                    deadCodeElimination: false, nopElision: false, functionSizeGate: 1024))
                let document = printer.print(function: function)
                let names = PseudocodeNameContext(function: function)
                let phis = PseudocodePrinter.presentationPhis(function)
                XCTAssertFalse(phis.isEmpty)
                XCTAssertFalse(document.text.contains("__unavailable_cfg_phi"))
                let label = try XCTUnwrap(document.lines.first {
                    $0.text.trimmingCharacters(in: .whitespaces) == "L_1000:"
                })
                let firstMachine = try XCTUnwrap(document.lines.filter {
                    $0.kind == .instruction && $0.sourceAddress != nil
                }.map(\.lineNumber).min())
                var snapshotLines: [Int] = [], writeLines: [Int] = []
                var backedgeSnapshotLines: [Int] = [], backedgeWriteLines: [Int] = []
                let transportTypes = printer.phiTransportSourceTypes(in: function, names: names,
                    phiTypes: phis.map { ($0.destination, "int64_t") },
                    inferPlainScalars: true)
                for phi in phis {
                    XCTAssertEqual(phi.bitWidth, 64)
                    let incoming = try XCTUnwrap(phi.incoming.first { $0.predecessor == .functionEntry })
                    let identity = MacIRPhiEdgeIdentity(blockAddress: phi.blockAddress,
                        predecessor: .functionEntry, destination: phi.destination)
                    let destination = printer.valueText(for: phi.destination, names: names)
                    let declarations = document.lines.filter {
                        $0.kind == .declaration && $0.syntheticPhiEdge == identity
                    }
                    XCTAssertEqual(declarations.count, 1)
                    XCTAssertEqual(declarations.first?.text.trimmingCharacters(in: .whitespaces),
                        "int64_t \(destination);")
                    let copies = document.lines.filter {
                        $0.kind == .instruction && $0.syntheticPhiEdge == identity
                    }
                    XCTAssertEqual(copies.count, 2)
                    guard copies.count == 2 else { continue }
                    let snapshot = copies[0].text.trimmingCharacters(in: .whitespaces)
                    let write = copies[1].text.trimmingCharacters(in: .whitespaces)
                    let prefix = "\(destination) = "
                    XCTAssertTrue(write.hasPrefix(prefix)); XCTAssertTrue(write.hasSuffix(";"))
                    let snapshotName = String(write.dropFirst(prefix.count).dropLast())
                    let input = printer.valueText(for: incoming.value, names: names)
                    let expectedInput = parameterType == "int64_t" ? input
                        : projectionText("(uint64_t)(\(input))", width: 64)
                    XCTAssertEqual(snapshot, "int64_t \(snapshotName) = \(expectedInput);")
                    XCTAssertNotEqual(snapshotName, destination)
                    snapshotLines.append(copies[0].lineNumber)
                    writeLines.append(copies[1].lineNumber)
                    for copy in copies {
                        XCTAssertNil(copy.sourceAddress)
                        XCTAssertLessThan(copy.lineNumber, label.lineNumber)
                        XCTAssertLessThan(copy.lineNumber, firstMachine)
                    }
                    let predecessor = rows[rows.count - 2].address
                    let backedge = MacIRPhiEdgeIdentity(blockAddress: phi.blockAddress,
                        predecessor: .machine(predecessor), destination: phi.destination)
                    let backedgeLines = document.lines.filter {
                        $0.kind == .instruction && $0.syntheticPhiEdge == backedge
                    }
                    let backedgeIncoming = try XCTUnwrap(phi.incoming.first {
                        $0.predecessor == .machine(predecessor)
                    })
                    let firstJoinPhi = try XCTUnwrap(phis.first { $0.blockAddress == phi.blockAddress })
                    let carriesStub = phi == firstJoinPhi
                    let expectedCount = carriesStub ? 4 : 2
                    XCTAssertEqual(backedgeLines.count, expectedCount)
                    XCTAssertTrue(backedgeLines.allSatisfy { $0.lineNumber > firstMachine })
                    guard backedgeLines.count == expectedCount else { continue }
                    let copyOffset = carriesStub ? 1 : 0
                    let backedgeSnapshotLine = backedgeLines[copyOffset]
                    let backedgeWriteLine = backedgeLines[copyOffset + 1]
                    let backedgeSnapshot = backedgeSnapshotLine.text.trimmingCharacters(in: .whitespaces)
                    let backedgeWrite = backedgeWriteLine.text.trimmingCharacters(in: .whitespaces)
                    XCTAssertTrue(backedgeWrite.hasPrefix(prefix)); XCTAssertTrue(backedgeWrite.hasSuffix(";"))
                    let backedgeSnapshotName = String(backedgeWrite.dropFirst(prefix.count).dropLast())
                    let backedgeInput = printer.valueText(for: backedgeIncoming.value, names: names)
                    let expectedBackedgeInput = transportTypes[backedgeIncoming.value] == "int64_t"
                        ? backedgeInput : projectionText("(uint64_t)(\(backedgeInput))", width: 64)
                    XCTAssertEqual(backedgeSnapshot,
                        "int64_t \(backedgeSnapshotName) = \(expectedBackedgeInput);")
                    XCTAssertNotEqual(backedgeSnapshotName, destination)
                    XCTAssertNotEqual(backedgeSnapshotName, snapshotName)
                    XCTAssertLessThan(backedgeSnapshotLine.lineNumber, backedgeWriteLine.lineNumber)
                    backedgeSnapshotLines.append(backedgeSnapshotLine.lineNumber)
                    backedgeWriteLines.append(backedgeWriteLine.lineNumber)
                    for line in backedgeLines { XCTAssertNil(line.sourceAddress) }
                    if carriesStub {
                        XCTAssertEqual(backedgeLines[0].text.trimmingCharacters(in: .whitespaces),
                            "L_edge_0_0:")
                        XCTAssertEqual(backedgeLines[3].text.trimmingCharacters(in: .whitespaces),
                            "goto L_\(String(phi.blockAddress, radix: 16));")
                        XCTAssertLessThan(backedgeLines[0].lineNumber, backedgeSnapshotLine.lineNumber)
                        XCTAssertLessThan(backedgeWriteLine.lineNumber, backedgeLines[3].lineNumber)
                    }
                }
                XCTAssertLessThan(try XCTUnwrap(snapshotLines.max()), try XCTUnwrap(writeLines.min()))
                XCTAssertLessThan(try XCTUnwrap(backedgeSnapshotLines.max()),
                    try XCTUnwrap(backedgeWriteLines.min()))
                XCTAssertEqual(function.instructions, originalInstructions)
                XCTAssertEqual(function.phis, originalPhis)
            }
        }
    }

    func testEmptyAndOrdinaryControlsHaveNoVirtualEntryCopies() {
        let empty = MacIRFunction(name: "empty_control", startAddress: 0, instructions: [])
        let ordinary = MacIRBuilder(explicitCFGEnabled: true, ssaEnabled: true).buildFunction(
            name: "ordinary_control", startAddress: 0x2000,
            authoritativeReturnLocation: .void, authoritativeReturnType: "void",
            instructions: [row(0x2000, "c0 03 5f d6", "ret")])
        for function in [empty, ordinary] {
            XCTAssertFalse(function.phis.contains { phi in
                phi.incoming.contains { $0.predecessor == .functionEntry }
            })
            for structured in [false, true] {
                let document = PseudocodePrinter(options: .init(structureControlFlow: structured,
                    deadCodeElimination: false, nopElision: false, functionSizeGate: 1024))
                    .print(function: function)
                XCTAssertFalse(document.text.contains("__entry_phi_"))
                XCTAssertFalse(document.lines.contains { $0.syntheticPhiEdge?.predecessor == .functionEntry })
            }
        }
    }
}
