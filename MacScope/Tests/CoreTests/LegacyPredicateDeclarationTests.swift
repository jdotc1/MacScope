import Foundation
import XCTest
@testable import MacScope

final class LegacyPredicateDeclarationTests: XCTestCase {
    private func row(_ address: UInt64, _ operation: MacIROperation) -> MacIRInstruction {
        .init(source: .init(address: address, byteText: "", mnemonic: "synthetic", operands: ""), operation: operation)
    }
    private func function() -> MacIRFunction {
        .init(name: "predicate", startAddress: 0x1000, returnType: "void", instructions: [
            row(0x1000, .compareToBool(destination: .temporary(0), condition: "<",
                left: .unary(op: "(double)", value: .immediate(0)),
                right: .unary(op: "(double)", value: .immediate(1)))),
            row(0x1004, .conditionalBranch(condition: "==", left: .temporary(0), right: .immediate(0), target: .immediate(0x1010))),
            row(0x1008, .returnValue(nil)), row(0x1010, .returnValue(nil))])
    }
    private func print(_ function: MacIRFunction, aliases: [String: String] = [:]) -> PseudocodeDocument {
        var options = DecompilerOptions.default
        options.structureControlFlow = false
        return PseudocodePrinter(options: options).print(function: function, registerNameOverrides: aliases)
    }
    func testPredicateHasOneFunctionScopeIntDeclarationAndUnchangedRows() throws {
        let document = print(function())
        let declaration = try XCTUnwrap(document.lines.firstIndex { $0.text == "    int tmp_0;" })
        let assignment = try XCTUnwrap(document.lines.firstIndex { $0.text.contains("tmp_0 = ") })
        XCTAssertEqual(document.lines.filter { $0.text == "    int tmp_0;" }.count, 1)
        XCTAssertEqual(document.lines[declaration].kind, .declaration)
        XCTAssertEqual(document.lines[declaration].source?.address, 0x1000)
        XCTAssertLessThan(declaration, assignment)
        if let label = document.lines.firstIndex(where: { $0.text.trimmingCharacters(in: .whitespaces).hasSuffix(":") }) {
            XCTAssertLessThan(declaration, label)
        }
        XCTAssertTrue(document.text.contains("tmp_0 = (double)(0x0) < (double)(0x1);"), document.text)
        XCTAssertTrue(document.text.contains("if (tmp_0 == 0x0) goto"), document.text)
        if let path = ProcessInfo.processInfo.environment["PREDICATE_SYNTAX_OUTPUT"] {
            guard !FileManager.default.fileExists(atPath: path) else {
                XCTFail("Synthetic output already exists; no test replay permitted")
                return
            }
            try document.text.write(toFile: path, atomically: false, encoding: .utf8)
        }
    }
    func testConflictingWriterAdditionalUseAndSelfReadDecline() {
        var writer = function()
        writer.instructions.insert(row(0xffc, .intrinsic(destination: .temporary(0), name: "opaque", arguments: [])), at: 0)
        var extra = function()
        extra.instructions.append(row(0x1014, .returnValue(.temporary(0))))
        var selfRead = function()
        selfRead.instructions[0].operation = .compareToBool(destination: .temporary(0), condition: "<", left: .temporary(0), right: .immediate(1))
        for candidate in [writer, extra, selfRead] {
            XCTAssertFalse(print(candidate).text.contains("int tmp_0;"))
        }
    }
    func testPrintedLocalAndRegisterAliasCollisionsDecline() {
        var parameter = function()
        parameter.parameters = [.init(index: 0, register: "x0", type: "int64_t", name: "tmp_0")]
        XCTAssertFalse(print(parameter).text.contains("int tmp_0;"))
        var local = function()
        local.localVariables = [.init(offset: -8, name: "tmp_0", type: "double", byteWidth: 8)]
        XCTAssertFalse(print(local).text.contains("int tmp_0;"))
        var alias = function()
        alias.instructions.append(row(0x1014, .assign(destination: .register(name: "x9", version: 1), source: .immediate(1))))
        XCTAssertFalse(print(alias, aliases: ["x9": "tmp_0"]).text.contains("int tmp_0;"))
    }
    func testSSAAndUnknownConditionsDoNotGainDeclarations() {
        var ssa = function(); ssa.ssaEnabled = true
        var unknown = function()
        unknown.instructions[0].operation = .compareToBool(destination: .temporary(0), condition: "opaque", left: .immediate(0), right: .immediate(1))
        XCTAssertFalse(print(ssa).text.contains("int tmp_0;"))
        XCTAssertFalse(print(unknown).text.contains("int tmp_0;"))
        for op in ["==", "!="] {
            var truthiness = function()
            truthiness.instructions[0].operation = .compareToBool(destination: .temporary(0), condition: op, left: .immediate(1), right: .immediate(0))
            XCTAssertFalse(print(truthiness).text.contains("int tmp_0;"))
        }
        var negative = function()
        negative.instructions[0].operation = .compareToBool(destination: .temporary(-1), condition: "<", left: .immediate(0), right: .immediate(1))
        negative.instructions[1].operation = .conditionalBranch(condition: "==", left: .temporary(-1), right: .immediate(0), target: .immediate(0x1010))
        XCTAssertFalse(print(negative).text.contains("int tmp_-1;"))
    }
    func testUnknownReturnContractIsPreserved() {
        var candidate = function()
        candidate.returnType = "int64_t"
        candidate.parameters = [.init(index: 0, register: "x0", type: "int64_t", name: "in_x0")]
        candidate.instructions[2].operation = .returnValue(.unknown("unresolved_return_contract"))
        XCTAssertTrue(print(candidate).text.contains("int tmp_0;"))
        XCTAssertTrue(print(candidate).text.contains("return unresolved_return_contract;"))
        XCTAssertTrue(print(candidate).text.contains("/* ABI inputs:"))
    }
    func testTwoPredicatesHaveDistinctDeclarationsInDefaultAndFlatOutput() {
        var candidate = function()
        candidate.instructions.insert(contentsOf: [
            row(0x1008, .compareToBool(destination: .temporary(1), condition: "<", left: .immediate(0), right: .immediate(1))),
            row(0x100c, .conditionalBranch(condition: "!=", left: .temporary(1), right: .immediate(0), target: .immediate(0x1010)))
        ], at: 2)
        candidate.instructions[4].source.address = 0x1010
        candidate.instructions[5].source.address = 0x1014
        for document in [print(candidate), PseudocodePrinter().print(function: candidate)] {
            XCTAssertEqual(document.lines.filter { $0.text == "    int tmp_0;" }.count, 1)
            XCTAssertEqual(document.lines.filter { $0.text == "    int tmp_1;" }.count, 1)
        }
    }
    func testCooperativeCancellationStillThrowsDuringInventory() {
        enum Cancel: Error { case requested }
        var candidate = function()
        candidate.instructions.append(contentsOf: (0..<128).map {
            row(0x2000 + UInt64($0) * 4, .assign(destination: .register(name: "x8", version: $0), source: .immediate(0)))
        })
        XCTAssertThrowsError(try PseudocodePrinter().print(function: candidate, checkpoint: { throw Cancel.requested }))
    }
    func testSymbolOpaqueCompositeAndResolvedCalleeOwnershipDeclines() {
        for value in [MacIRValue.symbol("tmp_0"), .unknown("tmp_0"),
                      .abiComposite(type: "T", fragments: [.symbol("tmp_0")])] {
            var candidate = function()
            candidate.instructions.append(row(0x1014, .assign(destination: .register(name: "x9", version: 1), source: value)))
            XCTAssertFalse(print(candidate).text.contains("int tmp_0;"))
        }
        let document = PseudocodePrinter().print(function: function(), resolvedIndirectCalls: [
            0x1100: .init(target: 0x2000, name: "tmp_0", slot: "synthetic")])
        XCTAssertFalse(document.text.contains("int tmp_0;"))
    }
    func testSemanticProducerOrConsumerOverridesDecline() {
        // A hidden sidecar output on an unrelated row is also an owner.
        for index in [0, 1, 2] {
            var clobber = function()
            clobber.instructions[index].fpArchitecturalClobber = .control
            XCTAssertFalse(print(clobber).text.contains("int tmp_0;"))
            var environment = function()
            let effect = MacIRFPEnvironmentEffect(type: .binary64,
                left: .immediate(0), right: .immediate(1), numericResult: .temporary(8),
                fpcrInput: .immediate(0), fpsrInput: .immediate(0), fpsrOutput: .temporary(0))
            if index == 2 {
                environment.instructions[index].operation = .intrinsic(destination: effect.numericResult,
                    name: effect.intrinsicName, arguments: [effect.left, effect.right, effect.fpcrInput, effect.fpsrInput])
            }
            environment.instructions[index].fpEnvironment = effect
            XCTAssertFalse(print(environment).text.contains("int tmp_0;"))
        }
    }
}
