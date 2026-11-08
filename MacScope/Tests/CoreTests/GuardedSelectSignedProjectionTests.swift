import Foundation
import Darwin
import XCTest
@testable import MacScope

// Authored IR and literal machine rows only.
// Accepted cases are conditional on census projection preserving the marker nodes (N2).
final class GuardedSelectSignedProjectionTests: XCTestCase {
    func testSB1PartnerMarkersWithXInners() { assertAccepted(fixture(1)) }
    func testSB2ImmediatePartner() { assertAccepted(fixture(2)) }
    func testSB3CnegInvertsTheSpelledCondition() { assertAccepted(fixture(3)) }
    func testSB4SignedWCompareWithXSelect() { assertAccepted(fixture(4)) }
    func testSB5SignedRegisterRHSWithXSelect() { assertAccepted(fixture(5)) }
    func testSB6WMarkerCannotDescribeXCompare() { assertRefused(fixture(6), guardID: "old.predicate-projection") }
    func testSB7BareWidth64ContextIsRejected() { assertRefused(fixture(7), guardID: "old.predicate-projection") }
    func testSB8UnsignedImmediateWCompareWithXSelectStaysRejected() { assertRefused(fixture(8), guardID: "old.predicate-projection") }
    func testSB9GAEqualityAndInequalityStayAccepted() {
        assertAccepted(fixture(9))
        assertAccepted(fixture(9, inequality: true))
    }
    func testSB10MarkerMustBindTheComparedRegister() {
        // The marker partner metadata repeats x5 as a printed flag operand.
        // Assert the complete census result, not only its guarded-arm subset.
        for mode in [false, true] {
            let result = analyze(fixture(10), ssaAccountingEnabled: mode)
            XCTAssertEqual(result.skippedReason,
                "guarded select arm needs path-predicate proof; predicate operand provenance is not a direct flag-producer input")
            XCTAssertTrue(result.rows.isEmpty)
            XCTAssertEqual(result.refusalDetails.count, 4)
            XCTAssertEqual(result.refusalDetails.compactMap(\.register), ["x5", "x5", "x1", "x2"])
            XCTAssertEqual(result.refusalDetails.map(\.reason), [
                "predicate operand provenance is not a direct flag-producer input",
                "predicate operand provenance is not a direct flag-producer input",
                "guarded select arm needs path-predicate proof: old-gate-failed",
                "guarded select arm needs path-predicate proof: old-gate-failed"])
            XCTAssertEqual(result.refusalDetails.map { $0.guardedFailure?.guardID },
                [nil, nil, "old.compare-inputs", "old.compare-inputs"])
        }
    }
    func testSB11BareOtherOperandIsRejected() { assertRefused(fixture(11), guardID: "old.predicate-projection") }
    func testSB12ExistingCastShapesKeepTheirVerdicts() {
        assertAccepted(fixture(12))
        assertRefused(fixture(12, wrongSignedness: true), guardID: "old.predicate-projection")
    }
    func testSB13TruncatedMarkerInners() { assertAccepted(fixture(13)) }
    func testSB14UnsignedConditionCannotConsumeSignedMarkers() { assertRefused(fixture(14), guardID: "old.predicate-projection") }
    func testSB15RawXArmsCannotUseTheWidenedBranch() { assertRefused(fixture(15), guardID: "old.predicate-projection") }
    func testSB16LogicalMarkerAndCastTwins() {
        for producer in ["tst", "ands"] {
            for immediate in [false, true] {
                for suffix in ["lt", "le", "gt", "ge"] {
                    assertAccepted(logicalFixture(producer, immediate: immediate, suffix: suffix, marker: true))
                    assertAccepted(logicalFixture(producer, immediate: immediate, suffix: suffix, marker: false))
                }
            }
        }
    }
    func testSB17WNamedInnersWithWSelect() { assertAccepted(fixture(17)) }
    func testSB18WNamedInnersWithXSelect() { assertAccepted(fixture(18)) }
    func testSB19MarkerAroundLiteralIsRejected() { assertRefused(fixture(19), guardID: "old.predicate-projection") }
    func testSB20CastTwinOfWidenedMarker() { assertAccepted(fixture(20)) }
    func testSB21PartnerWidth64ContextIsRejected() { assertRefused(fixture(21), guardID: "old.predicate-projection") }
    func testSB22WrongContextOperatorIsRejected() { assertRefused(fixture(22), guardID: "old.predicate-projection") }
    func testSB23UnsignedRegisterRHSWithXSelectStaysRejected() { assertRefused(fixture(23), guardID: "old.predicate-projection") }
    func testSB24BareWidth32Context() { assertAccepted(fixture(24)) }

    private func assertAccepted(_ function: MacIRFunction,
                                file: StaticString = #filePath, line: UInt = #line) {
        for mode in [false, true] {
            let result = analyze(function, ssaAccountingEnabled: mode)
            XCTAssertNil(result.skippedReason, function.name, file: file, line: line)
            XCTAssertTrue(result.rows.isEmpty, function.name, file: file, line: line)
            XCTAssertTrue(result.refusalDetails.isEmpty, function.name, file: file, line: line)
        }
    }

    private func assertRefused(_ function: MacIRFunction, guardID: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        for mode in [false, true] {
            let result = analyze(function, ssaAccountingEnabled: mode)
            XCTAssertEqual(result.skippedReason, "guarded select arm needs path-predicate proof",
                           function.name, file: file, line: line)
            XCTAssertTrue(result.rows.isEmpty, function.name, file: file, line: line)
            XCTAssertEqual(result.refusalDetails.count, 2, function.name, file: file, line: line)
            XCTAssertEqual(result.refusalDetails.compactMap(\.register), ["x1", "x2"],
                           function.name, file: file, line: line)
            XCTAssertEqual(result.refusalDetails.compactMap { $0.guardedFailure?.guardID },
                           [guardID, guardID], function.name, file: file, line: line)
        }
    }

    private func reg(_ number: Int, _ version: Int) -> MacIRValue {
        .register(name: "x\(number)", version: version)
    }
    private func w(_ number: Int, _ version: Int) -> MacIRValue {
        .register(name: "w\(number)", version: version)
    }
    private func low(_ value: MacIRValue) -> MacIRValue { .unary(op: "(uint32_t)", value: value) }
    private func extended(_ value: MacIRValue) -> MacIRValue { .unary(op: "(uint64_t)", value: low(value)) }
    private func marker(_ value: MacIRValue, width: Int64 = 32,
                        partner: MacIRValue? = nil, contextOperator: String = MacIRBuilder.projectionContextOperator) -> MacIRValue {
        let context: MacIRValue = partner.map {
            .binaryExpression(op: contextOperator, left: .immediate(width), right: $0)
        } ?? .immediate(width)
        return .binaryExpression(op: MacIRBuilder.signedProjectionOperator, left: value, right: context)
    }
    private func instruction(_ address: UInt64, _ mnemonic: String, _ operands: String,
                             _ operation: MacIROperation) -> MacIRInstruction {
        MacIRInstruction(source: MacIRSourceSpan(address: address, byteText: "00 00 00 00",
            mnemonic: mnemonic, operands: operands), operation: operation)
    }
    private func analyze(_ function: MacIRFunction,
                         ssaAccountingEnabled: Bool = false) -> C2DataflowCensus.Analysis {
        let printer = PseudocodePrinter(options: DecompilerOptions(structureControlFlow: false,
            deadCodeElimination: false, nopElision: false, functionSizeGate: 1024))
        let document = printer.print(function: function)
        let projected = MacIRFPEnvironmentPseudocodeProjection.project(function)
        var names = PseudocodeNameContext(function: projected)
        names.redundantCompareIndices = printer.redundantCompareIndices(function: projected, names: names)
        return C2DataflowCensus.analyze(function: projected, document: document,
            machine: function.instructions.map(\.source), printer: printer, names: names,
            ssaAccountingEnabled: ssaAccountingEnabled)
    }

    private func fixture(_ number: Int, inequality: Bool = false,
                         wrongSignedness: Bool = false) -> MacIRFunction {
        let wide = [4, 5, 6, 8, 9, 15, 18, 20, 23].contains(number)
        let prefix = wide ? "x" : "w"
        let immediate = [2, 3, 4, 8, 9, 15, 19, 20].contains(number)
        let unsigned = [8, 14, 23].contains(number)
        let alias = number == 3
        let suffix = alias ? "ge" : (unsigned ? "lo" : (number == 9 ? (inequality ? "ne" : "eq") : (immediate || wide ? "gt" : "lt")))
        let condition = alias || unsigned ? "<" : (number == 9 ? (inequality ? "!=" : "==") : (immediate || wide ? ">" : "<"))
        let comparePrefix = number == 6 ? "x" : "w"
        let literal: Int64 = [2, 3, 19].contains(number) ? 3 : 0
        let namedW = number == 17 || number == 18
        let compareLeft = namedW ? w(3, 0) : reg(3, 0)
        let compareRight: MacIRValue = immediate ? .immediate(literal) : (namedW ? w(4, 0) : reg(4, 0))
        var innerLeft = number == 10 ? reg(5, 0) : compareLeft
        var innerRight = compareRight
        if number == 13 { innerLeft = low(innerLeft); innerRight = low(innerRight) }
        if number == 19 { innerLeft = .immediate(3) }
        let width: Int64 = number == 7 || number == 21 ? 64 : 32
        let bare = number == 7 || number == 24
        var left = marker(innerLeft, width: width, partner: bare ? nil : innerRight,
                          contextOperator: number == 22 ? "+" : MacIRBuilder.projectionContextOperator)
        var right = immediate ? compareRight : marker(innerRight, width: width, partner: bare ? nil : innerLeft)
        if number == 11 { right = innerRight }
        if [8, 9, 12, 20, 23].contains(number) {
            let cast = number == 12 && !wrongSignedness || number == 20 ? "(int32_t)" : "(uint32_t)"
            left = .unary(op: cast, value: compareLeft)
            right = immediate ? compareRight : .unary(op: cast, value: compareRight)
        }
        // W immediate moves make the nested X arms exact readArmLeaf forms.
        // For W selects the same moves give the explicit (uint32_t) X leaves
        // a single reaching definition, not merely an assumed printed input.
        let yesLeaf = wide && number != 15 ? w(1, 1) : reg(1, 1)
        let noLeaf = wide && number != 15 ? w(2, 1) : reg(2, 1)
        let yes = wide ? (number == 15 ? yesLeaf : extended(yesLeaf)) : low(yesLeaf)
        let noRead = alias ? yes : (wide ? (number == 15 ? noLeaf : extended(noLeaf)) : low(noLeaf))
        let no: MacIRValue = alias ? .unary(op: "-", value: noRead) : noRead
        let rows = [
            instruction(0x7b00, "mov", "w1, #0x38", .assign(destination: yesLeaf, source: .immediate(0x38))),
            instruction(0x7b04, "mov", "w2, #0x48", .assign(destination: noLeaf, source: .immediate(0x48))),
            instruction(0x7b08, "cmp", "\(comparePrefix)3, " + (immediate ? "#\(literal)" : "\(comparePrefix)4"),
                .intrinsic(destination: nil, name: "compare", arguments: [compareLeft, compareRight])),
            instruction(0x7b0c, alias ? "cneg" : "csel",
                alias ? "w0, w1, \(suffix)" : "\(prefix)0, \(prefix)1, \(prefix)2, \(suffix)",
                .select(destination: wide ? reg(0, 1) : w(0, 1), condition: condition,
                    left: left, right: right, trueValue: yes, falseValue: no)),
            instruction(0x7b10, "ret", "", .returnValue(nil))]
        return MacIRFunction(name: "guarded_signed_projection_SB\(number)_\(inequality)_\(wrongSignedness)",
                             startAddress: 0x7b00, returnType: "void", instructions: rows)
    }

    private func logicalFixture(_ producer: String, immediate: Bool, suffix: String,
                                marker useMarker: Bool) -> MacIRFunction {
        let lhs = w(3, 0)
        let rhs: MacIRValue = immediate ? .immediate(3) : w(4, 0)
        let logicalValue = MacIRValue.binaryExpression(op: "&", left: lhs, right: rhs)
        let predicateLeft = useMarker ? marker(logicalValue, partner: .immediate(0))
            : .unary(op: "(int32_t)", value: logicalValue)
        let predicateRight: MacIRValue = useMarker ? .immediate(0)
            : .unary(op: "(int32_t)", value: .immediate(0))
        let relation = ["lt": "<", "le": "<=", "gt": ">", "ge": ">="][suffix]!
        let producerOperation: MacIROperation = producer == "ands"
            ? .assign(destination: w(6, 1), source: logicalValue)
            : .intrinsic(destination: nil, name: "compare", arguments: [logicalValue, .immediate(0)])
        let rows = [
            instruction(0x7c00, "mov", "w1, #0x38", .assign(destination: w(1, 1), source: .immediate(0x38))),
            instruction(0x7c04, "mov", "w2, #0x48", .assign(destination: w(2, 1), source: .immediate(0x48))),
            instruction(0x7c08, producer, (producer == "ands" ? "w6, " : "") + "w3, " + (immediate ? "#3" : "w4"), producerOperation),
            instruction(0x7c0c, "csel", "w0, w1, w2, \(suffix)",
                .select(destination: w(0, 1), condition: relation, left: predicateLeft,
                    right: predicateRight, trueValue: w(1, 1), falseValue: w(2, 1))),
            instruction(0x7c10, "ret", "", .returnValue(nil))]
        return MacIRFunction(name: "guarded_logical_projection_\(producer)_\(immediate)_\(suffix)_\(useMarker)",
                             startAddress: 0x7c00, returnType: "void", instructions: rows)
    }
}
