import Foundation
import XCTest
@testable import MacScope

/// Source-authored expectations.
final class LowHalfVectorReadAfterCallTests: XCTestCase {
    private func row(_ mnemonic: String, _ operands: String) -> InstructionRow {
        .init(address: 0x1000, bytes: "", mnemonic: mnemonic, operands: operands,
              hasBreakpoint: false, comment: nil)
    }

    private func entry() -> BuilderState {
        var state = BuilderState(parameters: [])
        state.permitsNEONBufferCarrier = true
        state.permitsNEONScalarViewCarrier = true
        _ = state.writeRegister("v8")
        return state
    }

    private func capWithEntries(_ state: inout BuilderState, width: Int = 64) {
        state.callResultVectorWidth[8] = width
        for name in ["v8", "q8"] {
            state.callUnavailableRegisterValues.insert(name)
            state.vectorScalarCallUnavailableRegisterValues.insert(name)
        }
    }

    private func arguments(_ mnemonic: String = "umull",
                           _ operands: String = "v18.4s, v3.4h, v8.4h",
                           state: inout BuilderState) throws -> [MacIRValue] {
        let instruction = row(mnemonic, operands)
        let parsed = try XCTUnwrap(MacIRBuilder.neonLaneOperation(
            mnemonic: instruction.mnemonic, operandText: instruction.operands))
        let operation = MacIRBuilder.liftNEONLane(parsed, state: &state)
        guard case let .intrinsic(_, _, values) = operation else {
            XCTFail("Expected lane intrinsic")
            return []
        }
        return values
    }

    func testSC1RegionFlagPreservesLowHalfValueIdentity() throws {
        var state = entry()
        let before = state.readRegister("v8")
        state.invalidateGeneralVectorRegionAtCall(returning: nil)
        let a3 = state.readRegister("v3")
        XCTAssertEqual(try arguments(state: &state), [a3, before])
    }

    func testSC2Cap64WithReconciliationEntriesPreservesLowHalf() throws {
        var state = entry()
        let before = state.readRegister("v8")
        capWithEntries(&state)
        let a3 = state.readRegister("v3")
        XCTAssertEqual(try arguments(state: &state), [a3, before])
    }

    func testSC1bCarrierFalseWithoutCapStaysUnavailable() throws {
        var state = entry()
        state.permitsNEONBufferCarrier = false
        state.invalidateAppleCallerSavedState()
        let a3 = state.readRegister("v3")
        XCTAssertEqual(try arguments(state: &state), [a3, .unknown("unavailable_v8")])
    }

    func testSC2bBareCap64StaysUnavailable() throws {
        var state = entry()
        state.callResultVectorWidth[8] = 64
        let a3 = state.readRegister("v3")
        XCTAssertEqual(try arguments(state: &state), [a3, .unknown("unavailable_upper_v8")])
    }

    func testSC1cCap64WithEntriesDoesNotRequireBufferCarrier() throws {
        var state = entry()
        let before = state.readRegister("v8")
        state.permitsNEONBufferCarrier = false
        capWithEntries(&state)
        let a3 = state.readRegister("v3")
        XCTAssertEqual(try arguments(state: &state), [a3, before])
    }

    func testSC2cBitViewCarrierDoesNotBlockLowHalfRecovery() throws {
        var state = entry()
        let before = state.readRegister("v8")
        capWithEntries(&state)
        state.permitsNEONBitViewCarrier = true
        let a3 = state.readRegister("v3")
        XCTAssertEqual(try arguments(state: &state), [a3, before])
    }

    func testSC3TombstoneWidthStaysUnavailable() throws {
        var state = entry()
        state.callResultVectorWidth[8] = 0
        let a3 = state.readRegister("v3")
        XCTAssertEqual(try arguments(state: &state), [a3, .unknown("unavailable_upper_v8")])
    }

    func testSC4HighHalfMultiplyStaysUnavailable() throws {
        var state = entry()
        state.invalidateGeneralVectorRegionAtCall(returning: nil)
        let a3 = state.readRegister("v3")
        XCTAssertEqual(try arguments("umull2", "v19.4s, v3.8h, v8.8h", state: &state),
                       [a3, .unknown("unavailable_upper_v8")])
    }

    func testSC5IndexedMultiplyStaysUnavailable() throws {
        var state = entry()
        state.invalidateGeneralVectorRegionAtCall(returning: nil)
        let a1 = state.readRegister("v1")
        XCTAssertEqual(try arguments("umull", "v0.4s, v1.4h, v8.h[1]", state: &state),
                       [a1, .unknown("unavailable_upper_v8")])
    }

    func testSC6AccumulatorReadStaysFullWidth() throws {
        var state = entry()
        state.invalidateGeneralVectorRegionAtCall(returning: nil)
        let a1 = state.readRegister("v1")
        let a2 = state.readRegister("v2")
        XCTAssertEqual(try arguments("umlal", "v8.4s, v1.4h, v2.4h", state: &state),
                       [a1, a2, .unknown("unavailable_upper_v8")])
    }

    func testSC7AccumulatingNarrowSourceStaysUnavailable() throws {
        var state = entry()
        state.invalidateGeneralVectorRegionAtCall(returning: nil)
        let a1 = state.readRegister("v1")
        let a0 = state.readRegister("v0")
        XCTAssertEqual(try arguments("umlal", "v0.4s, v1.4h, v8.4h", state: &state),
                       [a1, .unknown("unavailable_upper_v8"), a0])
    }

    func testSC8SignedMultiplyPreservesBothLowHalfSources() throws {
        var state = entry()
        _ = state.writeRegister("v9")
        let before = state.readRegister("v8")
        let before9 = state.readRegister("v9")
        state.invalidateGeneralVectorRegionAtCall(returning: nil)
        XCTAssertEqual(try arguments("smull", "v0.2d, v8.2s, v9.2s", state: &state),
                       [before, before9])
    }

    func testSC9GeneralPurposeMultiplyDoesNotParseAsLaneOperation() {
        XCTAssertNil(MacIRBuilder.neonLaneOperation(mnemonic: "umull", operandText: "x0, w1, w2"))
    }

    func testSC10WholeReadsRemainUnavailableAfterLowHalfRead() throws {
        var state = entry()
        state.invalidateGeneralVectorRegionAtCall(returning: nil)
        _ = try arguments(state: &state)
        XCTAssertEqual(state.readRegister("v8"), .unknown("unavailable_upper_v8"))
        XCTAssertEqual(state.readRegister("q8"), .unknown("unavailable_upper_v8"))
    }

    func testSC11MismatchedArrangementsDoNotParse() {
        XCTAssertNil(MacIRBuilder.neonLaneOperation(mnemonic: "umull", operandText: "v0.4s, v1.8h, v8.8h"))
    }

    func testSC12LaterWriteReadsNewVersion() throws {
        var state = entry()
        let before = state.readRegister("v8")
        state.invalidateGeneralVectorRegionAtCall(returning: nil)
        capWithEntries(&state)
        _ = state.writeRegister("v8")
        let after = state.readRegister("v8")
        let a3 = state.readRegister("v3")
        XCTAssertNotEqual(after, before)
        XCTAssertEqual(try arguments(state: &state), [a3, after])
    }

    func testSC13CompositeCallAndRewriteShape() throws {
        var state = entry()
        let before = state.readRegister("v8")
        _ = state.writeRegister("v10")
        state.invalidateGeneralVectorRegionAtCall(returning: nil)
        _ = state.writeRegister("v10")
        let after10 = state.readRegister("v10")
        let a3 = state.readRegister("v3")
        XCTAssertEqual(try arguments(state: &state), [a3, before])
        XCTAssertEqual(try arguments("umull2", "v19.4s, v3.8h, v10.8h", state: &state), [a3, after10])
    }

    func testSC14PhiEdgeWholeReadRemainsUnavailable() throws {
        var state = entry()
        state.invalidateGeneralVectorRegionAtCall(returning: nil)
        _ = try arguments(state: &state)
        // The phi presentation path reads the whole draft.register, not a low half.
        XCTAssertEqual(state.readRegister("v8"), .unknown("unavailable_upper_v8"))
    }
}
