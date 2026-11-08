import XCTest
@testable import MacScope

/// OS2-B2b: resolver outcomes become trailing annotations on Objective-C dispatch calls.
/// With no outcome the output is byte-identical to the unannotated call.
final class PseudocodeObjCMessageRenderTests: XCTestCase {
    private let callAddress: UInt64 = 0x1010
    private let selector = "caller"

    func testEmptyOutcomesAreByteIdentical() throws {
        for target in ["_objc_msgSend", "_puts"] {
            let function = try makeFunction(target: target)
            XCTAssertEqual(PseudocodePrinter().print(function: function, objcMessageNotes: [:]).text,
                           PseudocodePrinter().print(function: function).text)
        }
    }

    func testInstalledAppendsInstanceOwnerComment() throws {
        let function = try makeFunction(target: "_objc_msgSend")
        let base = PseudocodePrinter().print(function: function).text
        let text = render(function, .installed(constraint(side: .instance)))
        XCTAssertTrue(text.contains(" /* -[Calculator caller] */"), text)
        XCTAssertEqual(text.replacingOccurrences(of: " /* -[Calculator caller] */", with: ""), base)
    }

    func testClassSideUsesPlus() throws {
        let function = try makeFunction(target: "_objc_msgSend")
        let text = render(function, .installed(constraint(side: .class)))
        XCTAssertTrue(text.contains(" /* +[Calculator caller] */"), text)
    }

    func testStubSendGetsOwnerCommentOnly() throws {
        let function = try makeFunction(target: "_objc_msgSend$caller", knownSignature: false)
        let base = PseudocodePrinter().print(function: function).text
        let text = render(function, .macIROnly(constraint(side: .instance, kind: .verifiedSelectorStub)))
        XCTAssertTrue(text.contains(" /* -[Calculator caller] */"), text)
        XCTAssertEqual(text.replacingOccurrences(of: " /* -[Calculator caller] */", with: ""), base)
    }

    func testAbstainedAndContradictionAppendReason() throws {
        let function = try makeFunction(target: "_objc_msgSend")
        let base = PseudocodePrinter().print(function: function).text
        let abstained = render(function, .abstained(.receiverUnproven))
        XCTAssertTrue(abstained.contains(" /* objc: not resolved: receiver-unproven */"), abstained)
        XCTAssertEqual(abstained.replacingOccurrences(of: " /* objc: not resolved: receiver-unproven */", with: ""), base)
        let contradiction = render(function, .contradiction(.instructionByteMismatch))
        XCTAssertTrue(contradiction.contains(" /* objc: not resolved: instruction-byte-mismatch */"), contradiction)
    }

    func testNotObjectiveCDispatchReasonAddsNothing() throws {
        let function = try makeFunction(target: "_objc_msgSend")
        XCTAssertEqual(render(function, .abstained(.notObjectiveCDispatch)),
                       PseudocodePrinter().print(function: function).text)
    }

    func testNonCandidateTargetAndOtherAddressAddNothing() throws {
        let plain = try makeFunction(target: "_puts")
        XCTAssertEqual(render(plain, .installed(constraint(side: .instance))),
                       PseudocodePrinter().print(function: plain).text)
        let send = try makeFunction(target: "_objc_msgSend")
        let other = PseudocodePrinter().print(
            function: send,
            objcMessageNotes: [callAddress + 4: "objc: not resolved: receiver-unproven"]).text
        XCTAssertEqual(other, PseudocodePrinter().print(function: send).text)
    }

    // MARK: - Fixtures

    private func render(_ function: MacIRFunction, _ outcome: ObjCMessageConstraintOutcome) -> String {
        PseudocodePrinter().print(
            function: function,
            objcMessageNotes: outcome.pseudocodeNote.map { [callAddress: $0] } ?? [:]).text
    }

    private func constraint(side: ObjCMessageConstraint.MethodSide,
                            kind: ObjCMessageConstraint.DispatchKind = .directMessageSend) -> ObjCMessageConstraint {
        ObjCMessageConstraint(
            callAddress: callAddress, expectedInstructionBytes: [0xfc, 0x0b, 0x00, 0x94],
            directTargetAddress: 0x4000, targetSymbol: "_objc_msgSend", dispatchKind: kind,
            selector: selector, receiverClassName: "Calculator", methodSide: side,
            returnType: "void",
            methodParameters: [.init(name: "self", type: "id"), .init(name: "_cmd", type: "SEL")],
            evidence: .init(enclosingImplementation: 0x1000, methodImplementations: [0x2000],
                            selectorReferenceAddress: 0x3000, ownerDescriptions: ["Calculator"],
                            runtimeTypeEncodings: [], authority: .debugFixed))
    }

    private func makeFunction(target: String, knownSignature: Bool = true) throws -> MacIRFunction {
        let frame: MacIRCallFrame
        if knownSignature, target == "_objc_msgSend" {
            let evidence = try XCTUnwrap(MacIRCallSelectorEvidence(name: selector, selrefAddress: 0x3000))
            let args = try XCTUnwrap(MacIRCallArguments([
                .init(location: .gpr(index: 0, carrierWidth: 64), role: .fixed(sourcePosition: 0),
                      value: .argument(bindingID: .gpr(0))),
                .init(location: .gpr(index: 1, carrierWidth: 64), role: .fixed(sourcePosition: 1),
                      value: .symbol("\"\(selector)\""), selectorEvidence: evidence),
            ]))
            frame = try XCTUnwrap(MacIRCallFrame(
                target: target,
                knownSignature: CallSignatureCatalog.standard.signature(for: target),
                tailCountEvidence: .objectiveCSelectorColonCount(0),
                controlInputs: .none,
                arguments: args))
        } else {
            // Stub and ordinary calls: unknown-role arguments, no catalog signature.
            let scope = try XCTUnwrap(MacIRCallArgumentObservationScope(gprIndices: [0, 2, 3]))
            let args = try XCTUnwrap(MacIRCallArguments([
                .init(location: .gpr(index: 0, carrierWidth: 64), role: .unknown, value: .argument(bindingID: .gpr(0))),
                .init(location: .gpr(index: 2, carrierWidth: 64), role: .unknown, value: .argument(bindingID: .gpr(2))),
                .init(location: .gpr(index: 3, carrierWidth: 64), role: .unknown, value: .argument(bindingID: .gpr(3))),
            ], observationScope: scope))
            frame = try XCTUnwrap(MacIRCallFrame(
                target: target, knownSignature: nil, controlInputs: .none, arguments: args))
        }
        let source = MacIRSourceSpan(address: callAddress, byteText: "fc 0b 00 94", mnemonic: "bl",
                                     operands: target)
        var function = MacIRFunction(
            name: "-[Calculator caller]", startAddress: 0x1000,
            instructions: [.init(source: source, operation: .call(frame: frame, result: nil))])
        function.endAddress = 0x1100
        return function
    }
}
