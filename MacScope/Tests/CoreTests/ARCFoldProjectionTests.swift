import Foundation
import XCTest
@testable import MacScope

/// E4 slice B: the non-SSA ARC fold projection, its printer wiring and the fold-off golden.
final class ARCFoldProjectionTests: XCTestCase {
    private func reg(_ name: String, _ version: Int) -> MacIRValue { .register(name: name, version: version) }

    private func row(_ address: UInt64, _ operation: MacIROperation, _ mnemonic: String = "mov",
                     comment: String? = nil, operands: String = "") -> MacIRInstruction {
        MacIRInstruction(source: MacIRSourceSpan(address: address, byteText: "", mnemonic: mnemonic,
            operands: operands, comment: comment), operation: operation)
    }

    private func frame(_ name: String, argument: MacIRValue?, returnType: String = "id") throws -> MacIRCallFrame {
        let signature = MacIRCallSignature(target: name, returnType: returnType,
            parameters: [MacIRCallParameter(index: 0, register: "x0", type: "id", name: "obj")])
        let arguments = argument.map { [MacIRCallArgument(location: .gpr(index: 0, carrierWidth: 64),
            role: .fixed(sourcePosition: 0), value: $0)] } ?? []
        return try XCTUnwrap(MacIRCallFrame(target: name, knownSignature: signature, controlInputs: .none,
            arguments: try XCTUnwrap(MacIRCallArguments(arguments))))
    }

    private func call(_ address: UInt64, _ name: String, argument: MacIRValue?, result: MacIRValue?,
                      comment: String? = nil) throws -> MacIRInstruction {
        row(address, .call(frame: try frame(name, argument: argument), result: result), "bl",
            comment: comment, operands: "0x2100")
    }

    private func function(_ rows: [MacIRInstruction], returnValue: MacIRValue? = nil) -> MacIRFunction {
        var value = MacIRFunction(name: "caller", startAddress: 0x1000, returnType: "void",
            callTargets: ["objc_retain", "objc_release"], instructions: rows)
        value.returnValue = returnValue
        return value
    }

    private func identity(_ symbol: String = "objc_retain", role: ARCRole = .retain, count: Bool = false,
                          index: Int = 0, family: ARCFamily = .objc) -> ARCCalleeIdentity {
        ARCCalleeIdentity(family: family, role: role, importSymbol: symbol, libraryName: nil,
                          isCountVariant: count, objectRegisterIndex: index)
    }

    private func fold(_ function: MacIRFunction, _ sites: [UInt64: ARCCalleeIdentity])
        -> (function: MacIRFunction, report: PseudocodeFoldReport) {
        PseudocodePrinter.projectARCFold(function, request: PseudocodeFoldRequest(kinds: [.arc], arcCallSites: sites))
    }

    private func prologue() -> MacIRInstruction {
        row(0x1000, .assign(destination: reg("x19", 1), source: reg("x0", 0)))
    }

    private func ret(_ address: UInt64) -> MacIRInstruction { row(address, .returnValue(nil), "ret") }

    private func calls(in function: MacIRFunction) -> Int {
        function.instructions.filter { if case .call = $0.operation { return true }; return false }.count
    }

    // SPEC-6
    func testResultUnusedReleaseRemoved() throws {
        let original = function([prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: nil), ret(0x1008)])
        let projected = fold(original, [0x1004: identity("objc_release", role: .release)])
        XCTAssertEqual(calls(in: projected.function), 0)
        XCTAssertEqual(projected.function.instructions.map(\.source.address), [0x1000, 0x1008])
        XCTAssertEqual(projected.report.events.count, 1)
        let event = try XCTUnwrap(projected.report.events.first)
        XCTAssertEqual(event.address, 0x1004)
        XCTAssertEqual(event.kind, .arc)
        XCTAssertEqual(event.callee, "objc_release")
        XCTAssertEqual(event.role, .release)
        XCTAssertNil(event.replacedWith)
        XCTAssertEqual(event.anchorAddress, 0x1008)
        XCTAssertEqual(projected.report.counts[.arc], 1)
        XCTAssertTrue(projected.report.refused.isEmpty)
        // An unused returned register is removed too, for every role.
        let withResult = function([prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: reg("x0", 1)), ret(0x1008)])
        let again = fold(withResult, [0x1004: identity("objc_release", role: .release)])
        XCTAssertEqual(calls(in: again.function), 0)
        XCTAssertEqual(again.report.counts[.arc], 1)
    }

    // SPEC-7
    func testResultUsedRetainFoldsToArgument() throws {
        let store = row(0x1008, .store(source: reg("x0", 1), address: reg("x20", 0)), "str")
        let original = function([prologue(),
            try call(0x1004, "objc_retain", argument: reg("x19", 1), result: reg("x0", 1)), store, ret(0x100c)])
        let projected = fold(original, [0x1004: identity()])
        XCTAssertEqual(calls(in: projected.function), 0)
        XCTAssertEqual(projected.function.instructions.count, 3)
        XCTAssertEqual(projected.function.instructions[1].operation,
                       .store(source: reg("x19", 1), address: reg("x20", 0)))
        XCTAssertEqual(projected.function.instructions[1].source, store.source)
        XCTAssertEqual(projected.report.counts[.arc], 1)
        XCTAssertEqual(projected.report.events.first?.replacedWith, "x19_1")
        // The other used-result retain-like roles behave the same way.
        for (symbol, role) in [("objc_autorelease", ARCRole.autorelease),
                               ("objc_retainAutoreleasedReturnValue", .retainAutoreleasedReturn)] {
            let value = function([prologue(),
                try call(0x1004, symbol, argument: reg("x19", 1), result: reg("x0", 1)), store, ret(0x100c)])
            let result = fold(value, [0x1004: identity(symbol, role: role)])
            XCTAssertEqual(result.report.counts[.arc], 1, symbol)
            XCTAssertEqual(result.function.instructions[1].operation,
                           .store(source: reg("x19", 1), address: reg("x20", 0)), symbol)
        }
        // The folded use may sit inside an expression.
        let expression = row(0x1008, .assign(destination: reg("x21", 1),
            source: .binaryExpression(op: "+", left: reg("x0", 1), right: .immediate(8))), "add")
        let nested = fold(function([prologue(),
            try call(0x1004, "objc_retain", argument: reg("x19", 1), result: reg("x0", 1)), expression, ret(0x100c)]),
            [0x1004: identity()])
        XCTAssertEqual(nested.function.instructions[1].operation, .assign(destination: reg("x21", 1),
            source: .binaryExpression(op: "+", left: reg("x19", 1), right: .immediate(8))))
    }

    // SPEC-8
    func testResultUsedUnprovableIsNotFolded() throws {
        func assertRefused(_ original: MacIRFunction, _ sites: [UInt64: ARCCalleeIdentity], reason: String,
                           file: StaticString = #filePath, line: UInt = #line) {
            let projected = fold(original, sites)
            XCTAssertEqual(projected.function.instructions, original.instructions, reason, file: file, line: line)
            XCTAssertEqual(projected.function.returnValue, original.returnValue, reason, file: file, line: line)
            XCTAssertTrue(projected.report.events.isEmpty, reason, file: file, line: line)
            XCTAssertNil(projected.report.counts[.arc], reason, file: file, line: line)
            XCTAssertEqual(projected.report.refused.map(\.reason), [reason], file: file, line: line)
        }
        let useOfX0 = row(0x1008, .store(source: reg("x0", 1), address: reg("x20", 0)), "str")
        // Release forms never fold when their returned register is read.
        assertRefused(function([prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: reg("x0", 1)), useOfX0, ret(0x100c)]),
            [0x1004: identity("objc_release", role: .release)], reason: "result-used-release")
        // _n variants and register helpers with N != 0 fold only when the result is unused (Q9).
        assertRefused(function([prologue(),
            try call(0x1004, "swift_retain_n", argument: reg("x19", 1), result: reg("x0", 1)), useOfX0, ret(0x100c)]),
            [0x1004: identity("swift_retain_n", role: .retain, count: true, family: .swift)],
            reason: "result-used-count-variant")
        assertRefused(function([prologue(),
            try call(0x1004, "objc_retain_x3", argument: reg("x3", 0), result: reg("x0", 1)), useOfX0, ret(0x100c)]),
            [0x1004: identity("objc_retain_x3", role: .retain, index: 3)], reason: "result-used-register-helper")
        // A w0 view of the result is not rewritten.
        let wView = row(0x1008, .assign(destination: reg("w21", 1), source: reg("w0", 1)), "mov")
        assertRefused(function([prologue(),
            try call(0x1004, "objc_retain", argument: reg("x19", 1), result: reg("x0", 1)), wView, ret(0x100c)]),
            [0x1004: identity()], reason: "w0-view")
        // A computed argument is not a simple value to substitute.
        let computed = MacIRValue.binaryExpression(op: "+", left: reg("x19", 1), right: .immediate(8))
        assertRefused(function([prologue(),
            try call(0x1004, "objc_retain", argument: computed, result: reg("x0", 1)), useOfX0, ret(0x100c)]),
            [0x1004: identity()], reason: "argument-not-simple")
        // A read of the version that precedes the call cannot be the call's result.
        let early = row(0x1000, .store(source: reg("x0", 1), address: reg("x20", 0)), "str")
        assertRefused(function([early,
            try call(0x1004, "objc_retain", argument: reg("x19", 1), result: reg("x0", 1)), ret(0x1008)]),
            [0x1004: identity()], reason: "use-before-call")
        // A branch target between the call and the last use blocks the substitution.
        let branch = row(0x1008, .conditionalBranch(condition: "eq", left: reg("x19", 1), right: .immediate(0),
            target: .immediate(0x1010)), "cbz")
        let read = row(0x1010, .store(source: reg("x0", 1), address: reg("x20", 0)), "str")
        assertRefused(function([prologue(),
            try call(0x1004, "objc_retain", argument: reg("x19", 1), result: reg("x0", 1)), branch,
            row(0x100c, .assign(destination: reg("x22", 1), source: .immediate(1))), read, ret(0x1014)]),
            [0x1004: identity()], reason: "branch-target-in-range")
    }

    // SPEC-9
    func testMergedReturnCall() throws {
        // Returned through the function's return value.
        let viaReturnValue = function([prologue(),
            try call(0x1004, "objc_retainAutoreleasedReturnValue", argument: reg("x19", 1), result: reg("x0", 1)),
            ret(0x1008)], returnValue: reg("x0", 1))
        let site: [UInt64: ARCCalleeIdentity] = [0x1004: identity("objc_retainAutoreleasedReturnValue", role: .retainAutoreleasedReturn)]
        let first = fold(viaReturnValue, site)
        XCTAssertEqual(calls(in: first.function), 0)
        XCTAssertEqual(first.function.returnValue, reg("x19", 1))
        XCTAssertEqual(first.report.counts[.arc], 1)
        // Returned through an explicit return row.
        let viaRow = function([prologue(),
            try call(0x1004, "objc_retainAutoreleasedReturnValue", argument: reg("x19", 1), result: reg("x0", 1)),
            row(0x1008, .returnValue(reg("x0", 1)), "ret")])
        let second = fold(viaRow, site)
        XCTAssertEqual(calls(in: second.function), 0)
        if case .returnValue(let returned)? = second.function.instructions.last?.operation {
            XCTAssertEqual(returned, reg("x19", 1))
        } else { XCTFail("last row is not a return") }
        XCTAssertEqual(second.report.counts[.arc], 1)
        // A returned value the rewrite cannot reach keeps the call and says why: never half-folded.
        let both = function([prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: reg("x0", 1)),
            ret(0x1008)], returnValue: reg("x0", 1))
        let refused = fold(both, [0x1004: identity("objc_release", role: .release)])
        XCTAssertEqual(refused.function.instructions, both.instructions)
        XCTAssertEqual(refused.function.returnValue, both.returnValue)
        XCTAssertEqual(refused.report.refused.map(\.reason), ["result-used-release"])
    }

    // SPEC-10 (ruling Q2: reason is `branch-target`)
    func testTransferTargetEventRefused() throws {
        let branch = row(0x1000, .conditionalBranch(condition: "eq", left: reg("x0", 0), right: .immediate(0),
            target: .immediate(0x1008)), "cbz")
        let original = function([branch,
            row(0x1004, .assign(destination: reg("x19", 1), source: reg("x0", 0))),
            try call(0x1008, "objc_release", argument: reg("x19", 1), result: nil), ret(0x100c)])
        let before = original.instructions.flatMap { CFGBuilder.branchTargetAddresses(of: $0.operation) }
        let projected = fold(original, [0x1008: identity("objc_release", role: .release)])
        XCTAssertEqual(projected.function.instructions, original.instructions)
        XCTAssertEqual(projected.report.refused, [FoldRefusal(address: 0x1008, callee: "objc_release",
                                                              reason: "branch-target")])
        XCTAssertNil(projected.report.counts[.arc])
        XCTAssertEqual(projected.function.instructions.flatMap { CFGBuilder.branchTargetAddresses(of: $0.operation) }, before)
    }

    // SPEC-11 (ruling Q1: reason is `ssa-mode`)
    func testSSARefusal() throws {
        var original = function([prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: nil), ret(0x1008)])
        original.ssaEnabled = true
        let projected = fold(original, [0x1004: identity("objc_release", role: .release)])
        XCTAssertEqual(projected.function, original)
        XCTAssertEqual(projected.function.instructions, original.instructions)
        XCTAssertEqual(projected.report.refused, [FoldRefusal(address: nil, callee: nil, reason: "ssa-mode")])
        XCTAssertTrue(projected.report.events.isEmpty)
        XCTAssertNil(projected.report.counts[.arc])
        // Phis, an explicit CFG and unknown operations are refused the same way, with typed reasons.
        var phis = original
        phis.ssaEnabled = false
        phis.phis = [MacIRPhi(blockAddress: 0x1004, destination: reg("x19", 2), bitWidth: 64, incoming: [
            .init(predecessorAddress: 0x1000, value: reg("x19", 1))])]
        XCTAssertEqual(fold(phis, [0x1004: identity("objc_release", role: .release)]).report.refused.map(\.reason),
                       ["phis"])
    }

    // SPEC-12 (analysis comment moves to the next statement, once)
    func testCommentMovesToNextStatement() throws {
        let original = function([prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: nil, comment: "balance the +1"),
            row(0x1008, .assign(destination: reg("x20", 1), source: .immediate(1)), "mov", comment: "existing"),
            ret(0x100c)])
        let projected = fold(original, [0x1004: identity("objc_release", role: .release)])
        let next = try XCTUnwrap(projected.function.instructions.first { $0.source.address == 0x1008 })
        XCTAssertEqual(next.source.comment, "existing [arc-fold 0x1004] balance the +1")
        let event = try XCTUnwrap(projected.report.events.first)
        XCTAssertEqual(event.comment, "balance the +1")
        XCTAssertEqual(event.commentPlacedAt, 0x1008)
        let occurrences = projected.function.instructions.compactMap(\.source.comment)
            .filter { $0.contains("balance the +1") }
        XCTAssertEqual(occurrences.count, 1)
        // A follower that is a branch target is not given the comment: it stays in the event only.
        let branch = row(0x1000, .conditionalBranch(condition: "eq", left: reg("x0", 0), right: .immediate(0),
            target: .immediate(0x1008)), "cbz")
        let targeted = function([branch,
            try call(0x1004, "objc_release", argument: reg("x19", 0), result: nil, comment: "balance the +1"),
            row(0x1008, .assign(destination: reg("x20", 1), source: .immediate(1))), ret(0x100c)])
        let kept = fold(targeted, [0x1004: identity("objc_release", role: .release)])
        XCTAssertEqual(kept.report.counts[.arc], 1)
        XCTAssertNil(kept.function.instructions.first { $0.source.address == 0x1008 }?.source.comment)
        XCTAssertEqual(kept.report.events.first?.comment, "balance the +1")
        XCTAssertNil(kept.report.events.first?.commentPlacedAt)
    }

    // SPEC-13 (ruling Q10: no unplacedComments type; the comment stays inside the event)
    func testCommentUnplacedWhenNoFollower() throws {
        let original = function([prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: nil, comment: "last row")])
        let projected = fold(original, [0x1004: identity("objc_release", role: .release)])
        XCTAssertEqual(projected.function.instructions.map(\.source.address), [0x1000])
        let event = try XCTUnwrap(projected.report.events.first)
        XCTAssertEqual(event.address, 0x1004)
        XCTAssertEqual(event.comment, "last row")
        XCTAssertNil(event.commentPlacedAt)
        XCTAssertNil(event.anchorAddress)
        XCTAssertNil(projected.function.instructions.compactMap(\.source.comment).first { $0.contains("last row") })
    }

    // E4-E2: a fold that removes a call row interacts with E2 authored comments only through the
    // E2 post-pass. Expected values are derived from production code:
    //  - PseudocodePrinter.swift:449 applies userComments to the folded document;
    //  - PseudocodePrinter+UserComments.swift applyingUserComments: a comment is placed above the FIRST
    //    line whose sourceAddress equals its address (placed += 1), else it is appended to unplaced
    //    with reason .excludedFromCode if excluded, .folded if in bodyAddresses, else .noInstruction;
    //  - MacIR.swift:2917/2919 unplacedComments / placedCommentCount.
    private func foldCommentFixture() throws -> MacIRFunction {
        let store = row(0x1008, .store(source: reg("x19", 1), address: reg("x20", 0)), "str")
        return function([prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: nil), store, ret(0x100c)])
    }

    private func commented(_ function: MacIRFunction, _ texts: [UInt64: String], fold: Bool) -> PseudocodeDocument {
        PseudocodePrinter().print(
            function: function,
            fold: fold ? PseudocodeFoldRequest(kinds: [.arc],
                arcCallSites: [0x1004: identity("objc_release", role: .release)]) : nil,
            userComments: PseudocodeUserComments(
                textByAddress: texts, bodyAddresses: Set(function.instructions.map(\.source.address))))
    }

    func testFoldRemovedRowCommentIsReportedUnplaced() throws {
        let original = try foldCommentFixture()
        let document = commented(original, [0x1004: "balance the release"], fold: true)
        XCTAssertEqual(document.foldReport?.counts[.arc], 1)
        XCTAssertFalse(document.text.contains("objc_release("), document.text)
        XCTAssertEqual(document.unplacedComments,
                       [PseudocodeUnplacedComment(address: 0x1004, text: "balance the release", reason: .folded)])
        XCTAssertEqual(document.placedCommentCount, 0)
        XCTAssertFalse(document.text.contains("balance the release"), document.text)
        // No inserted comment line: the only metadata "//" line is the printer's own entry header.
        XCTAssertEqual(document.lines.filter { $0.kind == .metadata && $0.text.contains("//") && $0.sourceAddress == nil }.count,
                       document.lines.filter { $0.text.hasPrefix("    // entry ") || $0.text.hasPrefix("// entry ") }.count,
                       document.text)
    }

    func testControlWithoutFoldPlacesTheCallRowComment() throws {
        let original = try foldCommentFixture()
        let document = commented(original, [0x1004: "balance the release"], fold: false)
        XCTAssertNil(document.foldReport)
        XCTAssertTrue(document.text.contains("objc_release("), document.text)
        XCTAssertTrue(document.unplacedComments.isEmpty, "\(document.unplacedComments)")
        XCTAssertEqual(document.placedCommentCount, 1)
        XCTAssertTrue(document.text.contains("// balance the release"), document.text)
    }

    func testCommentOnKeptRowStaysPlacedWhenAnotherRowFolds() throws {
        let original = try foldCommentFixture()
        let document = commented(original, [0x1004: "balance the release", 0x1008: "keep me"], fold: true)
        XCTAssertEqual(document.unplacedComments,
                       [PseudocodeUnplacedComment(address: 0x1004, text: "balance the release", reason: .folded)])
        XCTAssertEqual(document.placedCommentCount, 1)
        XCTAssertTrue(document.text.contains("// keep me"), document.text)
        XCTAssertFalse(document.text.contains("balance the release"), document.text)
        // The kept comment sits directly above the line sourced at its own address.
        let index = try XCTUnwrap(document.lines.firstIndex { $0.text.contains("// keep me") })
        XCTAssertEqual(document.lines[index + 1].sourceAddress, 0x1008)
    }

    // SPEC-14
    func testCountCountsFoldsNotCandidates() throws {
        let rows: [MacIRInstruction] = [
            prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: reg("x0", 1)),          // folds
            try call(0x1008, "objc_retain", argument: reg("x19", 1), result: reg("x0", 2)),           // folds
            row(0x100c, .store(source: reg("x0", 2), address: reg("x20", 0)), "str"),
            try call(0x1010, "objc_release", argument: reg("x19", 1), result: reg("x0", 3)),          // used release
            row(0x1014, .store(source: reg("x0", 3), address: reg("x21", 0)), "str"),
            row(0x1018, .conditionalBranch(condition: "eq", left: reg("x19", 1), right: .immediate(0),
                target: .immediate(0x1020)), "cbz"),
            row(0x101c, .assign(destination: reg("x23", 1), source: .immediate(1))),
            try call(0x1020, "objc_release", argument: reg("x19", 1), result: nil),                    // branch target
            try call(0x1024, "swift_retain_n", argument: reg("x19", 1), result: reg("x0", 4)),        // used _n
            row(0x1028, .store(source: reg("x0", 4), address: reg("x22", 0)), "str"),
            ret(0x102c),
        ]
        let sites: [UInt64: ARCCalleeIdentity] = [
            0x1004: identity("objc_release", role: .release),
            0x1008: identity(),
            0x1010: identity("objc_release", role: .release),
            0x1020: identity("objc_release", role: .release),
            0x1024: identity("swift_retain_n", role: .retain, count: true, family: .swift),
        ]
        let projected = fold(function(rows), sites)
        XCTAssertEqual(projected.report.counts[.arc], 2)
        XCTAssertEqual(projected.report.events.map(\.address), [0x1004, 0x1008])
        XCTAssertEqual(projected.report.refused.count, 3)
        XCTAssertEqual(projected.report.refused.map(\.reason),
                       ["result-used-release", "branch-target", "result-used-count-variant"])
        XCTAssertEqual(calls(in: projected.function), 3)
        // A call at a site that carries no proof is never touched.
        let unproven = fold(function(rows), [:])
        XCTAssertEqual(unproven.function.instructions, rows)
        XCTAssertTrue(unproven.report.events.isEmpty)
    }

    // SPEC-15: the printer runs the transform for the original and again for the lexical twin and
    // keeps the first report. The twin pass is replayed here at the transform level.
    func testIdempotentTwinRun() throws {
        let store = row(0x1008, .store(source: reg("x0", 1), address: reg("x20", 0)), "str")
        let original = function([prologue(),
            try call(0x1004, "objc_retain", argument: reg("x19", 1), result: reg("x0", 1)), store, ret(0x100c)])
        let request = PseudocodeFoldRequest(kinds: [.arc], arcCallSites: [0x1004: identity()])
        let recorder = PseudocodeFoldRecorder()
        var calls = 0
        let result = RegionalLexicalProof.projecting(original) { input in
            calls += 1
            let folded = PseudocodePrinter.projectARCFold(input, request: request)
            recorder.record(folded.report)
            return folded.function
        }
        XCTAssertEqual(calls, 1)
        let single = try XCTUnwrap(recorder.recorded)
        XCTAssertEqual(single.counts[.arc], 1)
        // Replaying the same transform (the twin) on the same input gives an equal report.
        let twin = PseudocodePrinter.projectARCFold(original, request: request)
        XCTAssertEqual(twin.report, single)
        recorder.record(twin.report)
        XCTAssertEqual(recorder.recorded, single)
        XCTAssertEqual(twin.function, result)
        // The projection is idempotent: folding folded output finds nothing more to do.
        let again = PseudocodePrinter.projectARCFold(result, request: request)
        XCTAssertEqual(again.function.instructions, result.instructions)
        XCTAssertTrue(again.report.events.isEmpty)
    }

    // SPEC-16: record the orphan-declaration behavior.
    func testOrphanDeclarationAfterFold() throws {
        let store = row(0x1008, .store(source: reg("x0", 1), address: reg("x20", 0)), "str")
        let original = function([prologue(),
            try call(0x1004, "objc_retain", argument: reg("x19", 1), result: reg("x0", 1)), store, ret(0x100c)])
        let request = PseudocodeFoldRequest(kinds: [.arc], arcCallSites: [0x1004: identity()])
        let off = PseudocodePrinter().print(function: original)
        let on = PseudocodePrinter().print(function: original, fold: request)
        XCTAssertTrue(off.text.contains("objc_retain("), off.text)
        XCTAssertFalse(on.text.contains("objc_retain("), on.text)
        // Recorded behavior (not gated): the declaration lines that still mention the removed
        // result variable. The renderer derives declarations from the surviving rows.
        let residual = on.lines.filter { $0.text.contains("x0_1") }.map(\.text)
        XCTContext.runActivity(named: "SPEC-16 residual lines mentioning the removed result: \(residual)") { _ in }
        print("SPEC-16 folded text:\n\(on.text)\nSPEC-16 residual: \(residual)")
        XCTAssertEqual(on.foldReport?.counts[.arc], 1)
        XCTAssertLessThan(on.lines.count, off.lines.count)
    }

    // SPEC-1 golden: an absent or empty fold request is byte-identical to the unfolded rendering.
    func testFoldAbsentIsByteIdentical() throws {
        let store = row(0x1008, .store(source: reg("x0", 1), address: reg("x20", 0)), "str")
        let original = function([prologue(),
            try call(0x1004, "objc_retain", argument: reg("x19", 1), result: reg("x0", 1)), store,
            try call(0x100c, "objc_release", argument: reg("x19", 1), result: nil), ret(0x1010)])
        let baseline = PseudocodePrinter().print(function: original)
        XCTAssertTrue(baseline.text.contains("objc_retain("), baseline.text)
        XCTAssertTrue(baseline.text.contains("objc_release("), baseline.text)
        XCTAssertNil(baseline.foldReport)
        // Explicit nil and an empty kinds set are the same rendering as the default.
        let nilFold = PseudocodePrinter().print(function: original, fold: nil)
        XCTAssertEqual(nilFold, baseline)
        XCTAssertEqual(nilFold.text, baseline.text)
        XCTAssertEqual(nilFold.lines.map(\.text), baseline.lines.map(\.text))
        XCTAssertEqual(nilFold.regionTree, baseline.regionTree)
        // A requested fold with no proven call site leaves the text and lines unchanged.
        let noSites = PseudocodePrinter().print(function: original,
            fold: PseudocodeFoldRequest(kinds: [.arc], arcCallSites: [:]))
        XCTAssertEqual(noSites.text, baseline.text)
        XCTAssertEqual(noSites.lines, baseline.lines)
        XCTAssertEqual(noSites.regionTree, baseline.regionTree)
        XCTAssertEqual(noSites.foldReport?.events.count, 0)
        // The throwing overload agrees byte for byte.
        let throwing = try PseudocodePrinter().print(function: original, checkpoint: {})
        XCTAssertEqual(throwing.text, baseline.text)
        XCTAssertEqual(throwing.lines, baseline.lines)
    }

    // SPEC-23
    func testGuiDecompilerOptionsUnchanged() throws {
        // E4 adds no DecompilerOptions field: the fold travels in the request, so GUI output uses
        // the same options value and the same rendering as before.
        let mirror = Mirror(reflecting: DecompilerOptions.default)
        let names = Set(mirror.children.compactMap(\.label))
        XCTAssertFalse(names.contains { $0.lowercased().contains("fold") }, "\(names)")
        let original = function([prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: nil), ret(0x1008)])
        XCTAssertEqual(PseudocodePrinter(options: .default).print(function: original),
                       PseudocodePrinter().print(function: original))
    }

    func testFoldingKeepsSourceSpansOfSurvivingRows() throws {
        let store = row(0x1008, .store(source: reg("x0", 1), address: reg("x20", 0)), "str")
        let original = function([prologue(),
            try call(0x1004, "objc_retain", argument: reg("x19", 1), result: reg("x0", 1)), store, ret(0x100c)])
        let projected = fold(original, [0x1004: identity()])
        XCTAssertEqual(projected.function.instructions.map(\.source),
                       original.instructions.filter { $0.source.address != 0x1004 }.map(\.source))
        XCTAssertEqual(projected.function.callTargets, original.callTargets)
        XCTAssertEqual(projected.function.callSignatures, original.callSignatures)
        XCTAssertEqual(projected.function.name, original.name)
    }

    func testUnknownOperationAndIndirectBranchAreFunctionLevelRefusals() throws {
        let original = function([prologue(),
            try call(0x1004, "objc_release", argument: reg("x19", 1), result: nil),
            row(0x1008, .intrinsic(destination: nil, name: "branch_register", arguments: [reg("x8", 0)]), "br"),
            ret(0x100c)])
        let projected = fold(original, [0x1004: identity("objc_release", role: .release)])
        XCTAssertEqual(projected.function.instructions, original.instructions)
        XCTAssertEqual(projected.report.refused.map(\.reason), ["indirect-branch"])
    }
}
