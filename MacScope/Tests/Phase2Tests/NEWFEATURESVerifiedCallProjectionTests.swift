import Foundation
import XCTest
import NEWFEATURESCore
@testable import MacScope

final class NEWFEATURESVerifiedCallProjectionTests: XCTestCase {
    private let binaryID = UUID()
    private let firstID = UUID()
    private let secondID = UUID()

    private func image(slot: Int = 2, architecture: String = "arm64") throws -> NEWFEATURESImageKey {
        try .init(documentInstance: UUID(), workspaceInstance: UUID(), slot: slot, binaryID: binaryID,
                  ownerGeneration: 1, architecture: architecture, sliceIndex: nil,
                  sha256: String(repeating: "a", count: 64), analysisRevision: 1,
                  analysisInputFingerprintSHA256: String(repeating: "b", count: 64))
    }

    private func function(_ address: UInt64, end: UInt64? = nil, id: UUID? = nil) -> FunctionSummary {
        .init(id: id ?? UUID(), name: "function", startAddress: address,
              endAddress: end ?? address + 0x100, confidence: 1)
    }

    private func instruction(_ address: UInt64 = 0x1000, bytes: String = "00 04 00 94",
                             mnemonic: String = "bl", operands: String = "0x2000") -> InstructionRow {
        .init(address: address, bytes: bytes, mnemonic: mnemonic, operands: operands,
              hasBreakpoint: false, comment: nil)
    }

    private func xref(_ from: UInt64 = 0x1000, _ to: UInt64 = 0x2000) -> XRef {
        .init(id: UUID(), from: from, to: to, kind: XRefKind.call)
    }

    private func projection(functions: [FunctionSummary]? = nil, instructions: [InstructionRow]? = nil,
                            xrefs: [XRef]? = nil) -> FocusedGraphProjection {
        .init(imageSlot: .init(rawValue: 2), ownerBinaryID: binaryID,
              functions: functions ?? [function(0x1000, id: firstID), function(0x2000, id: secondID)],
              basicBlocks: [], instructions: instructions ?? [instruction()],
              controlFlowEdges: [], xrefs: xrefs ?? [xref()], presentationByAddress: [:])
    }

    private func make(_ projection: FocusedGraphProjection, image: NEWFEATURESImageKey? = nil,
                      from: UInt64 = 0x1000, to: UInt64 = 0x2000,
                      operation: NEWFEATURESGraphOperation? = nil,
                      limits: NEWFEATURESCallProjectionLimits = .standard) throws -> NEWFEATURESVerifiedCallProjection {
        try .make(projection: projection, image: image ?? self.image(), sourceAddress: from,
                  destinationAddress: to,
                  operation: operation ?? NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget()),
                  limits: limits)
    }

    private func path(_ input: NEWFEATURESVerifiedCallProjection,
                      maxEdges: Int = 20_000) throws -> NEWFEATURESPathReport {
        let budget = try NEWFEATURESReadBudget(maxEdgeVisits: maxEdges)
        return try NEWFEATURESPathfinder.shortestVerifiedPath(
            from: input.source, to: input.destination, graph: input.graph, budget: budget,
            operation: NEWFEATURESGraphOperation(budget: budget)
        )
    }

    func testRetainedBLWordAndXrefResolveExactFunctionUUIDs() throws {
        let input = try make(projection(), from: 0x1004, to: 0x2008)
        XCTAssertEqual(input.source.address, 0x1000)
        XCTAssertEqual(input.destination.address, 0x2000)
        XCTAssertEqual(input.functionIDsByStart[0x1000], firstID)
        XCTAssertEqual(input.functionIDsByStart[0x2000], secondID)
        XCTAssertEqual(try path(input).path.map(\.address), [0x1000, 0x2000])
        XCTAssertEqual(input.unresolvedObservationCount, 0)
    }

    func testDisplayMnemonicAndOperandCannotProveACall() throws {
        let input = try make(projection(instructions: [instruction(bytes: "1f 20 03 d5")]))
        XCTAssertEqual(try path(input).status, .notFoundInObservedGraph)
        XCTAssertEqual(input.graph.unverifiedEdgeCount, 1)
        XCTAssertEqual(input.unresolvedSamples.first?.reason, .decodedCallEvidenceUnavailable)
    }

    func testCorrectBytesRemainTheWitnessWhenDisplayTextDiffers() throws {
        let input = try make(projection(instructions: [instruction(mnemonic: "display", operands: "symbol")] ))
        XCTAssertEqual(try path(input).status, .found)
    }

    func testDifferentDecodedTargetIsRetainedAsUnverified() throws {
        let input = try make(projection(instructions: [instruction(bytes: "00 08 00 94")]))
        XCTAssertEqual(try path(input).status, .notFoundInObservedGraph)
        XCTAssertEqual(input.unresolvedObservationCount, 1)
    }

    func testDuplicateInstructionAddressCannotSupplyAByteWitness() throws {
        let input = try make(projection(instructions: [instruction(), instruction()]))
        XCTAssertEqual(try path(input).status, .notFoundInObservedGraph)
        XCTAssertEqual(input.graph.unverifiedEdgeCount, 1)
    }

    func testFullInstructionMustHaveTheSameUniqueFunctionOwner() throws {
        let input = try make(projection(functions: [
            function(0x1000, end: 0x1002, id: firstID), function(0x2000, id: secondID),
        ]))
        XCTAssertEqual(try path(input).status, .notFoundInObservedGraph)
        XCTAssertEqual(input.unresolvedSamples.first?.reason, .decodedCallEvidenceUnavailable)
    }

    func testOverlappingEndpointDoesNotChooseTheExactStartPreferentially() throws {
        XCTAssertThrowsError(try make(projection(functions: [
            function(0x1000, end: 0x2100), function(0x2000),
        ]))) { XCTAssertEqual($0 as? NEWFEATURESCallPathFailure, .endpointUnresolved) }
    }

    func testDuplicateUUIDAcrossDisjointRangesIsRefused() throws {
        XCTAssertThrowsError(try make(projection(functions: [
            function(0x1000, id: firstID), function(0x2000, id: firstID),
        ]))) { XCTAssertEqual($0 as? NEWFEATURESCallPathFailure, .invalidFunctionOwnership) }
    }

    func testWrongImageSlotOrOwnerCannotSupplyGraphEvidence() throws {
        XCTAssertThrowsError(try make(projection(), image: image(slot: 0))) {
            XCTAssertEqual($0 as? NEWFEATURESAdmissionFailure, .staleSource)
        }
        var wrongOwner = projection()
        wrongOwner.ownerBinaryID = UUID()
        XCTAssertThrowsError(try make(wrongOwner)) {
            XCTAssertEqual($0 as? NEWFEATURESAdmissionFailure, .staleSource)
        }
    }

    func testFirstIncrementExplicitlyRefusesOtherArchitectures() throws {
        XCTAssertThrowsError(try make(projection(), image: image(architecture: "x86_64"))) {
            XCTAssertEqual($0 as? NEWFEATURESCallPathFailure, .unsupportedArchitecture)
        }
    }

    func testUnresolvedTargetDoesNotDiscardASeparateVerifiedPath() throws {
        let input = try make(projection(instructions: [instruction(), instruction(0x1004, bytes: "ff 07 00 94")],
                                        xrefs: [xref(), xref(0x1004, 0x3000)]))
        XCTAssertEqual(try path(input).status, .found)
        XCTAssertEqual(input.graph.unverifiedEdgeCount, 1)
        XCTAssertEqual(input.unresolvedSamples.first?.reason, .targetOwnershipUnavailable)
        XCTAssertEqual(input.unresolvedSamples.first?.observedTarget, 0x3000)
    }

    func testOrphanDirectCallRemainsVisibleWithoutInventingAXref() throws {
        let input = try make(projection(xrefs: []))
        let report = try path(input)
        XCTAssertEqual(report.status, .notFoundInObservedGraph)
        XCTAssertEqual(report.examinedUnverifiedEdges, 1)
        XCTAssertEqual(input.unresolvedObservationCount, 1)
        XCTAssertEqual(input.unresolvedSamples.first?.reason, .callXrefUnavailable)
        XCTAssertEqual(input.unresolvedSamples.first?.observedTarget, 0x2000)
    }

    func testIndirectCallWithoutXrefRemainsVisible() throws {
        let input = try make(projection(instructions: [instruction(bytes: "00 00 3f d6", mnemonic: "blr")], xrefs: []))
        XCTAssertEqual(try path(input).status, .notFoundInObservedGraph)
        XCTAssertEqual(input.unresolvedObservationCount, 1)
        XCTAssertEqual(input.unresolvedSamples.first?.reason, .indirectTargetUnavailable)
        XCTAssertEqual(input.graph.unverifiedEdgeCount, 1)
    }

    func testAuthenticatedIndirectCallUsesExistingDecoderClassification() throws {
        let input = try make(projection(instructions: [instruction(bytes: "01 08 3f d7", mnemonic: "blraa")], xrefs: []))
        XCTAssertEqual(input.unresolvedObservationCount, 1)
        XCTAssertEqual(input.unresolvedSamples.first?.reason, .indirectTargetUnavailable)
        XCTAssertEqual(try path(input).status, .notFoundInObservedGraph)
    }

    func testInstructionInputLimitAppliesBeforeProjection() throws {
        let limits = NEWFEATURESCallProjectionLimits(maximumFunctions: 10, maximumInstructions: 1,
                                                     maximumXrefs: 10, maximumWork: 1000,
                                                     maximumUnresolvedSamples: 2)
        XCTAssertThrowsError(try make(projection(instructions: [instruction(), instruction(0x1004)]), limits: limits)) {
            XCTAssertEqual($0 as? NEWFEATURESCallPathFailure, .inputLimit)
        }
    }

    func testRangeConstructionConsumesTheSharedProjectionWorkBudget() throws {
        let limits = NEWFEATURESCallProjectionLimits(maximumFunctions: 10, maximumInstructions: 10,
                                                     maximumXrefs: 10, maximumWork: 2,
                                                     maximumUnresolvedSamples: 2)
        XCTAssertThrowsError(try make(projection(), limits: limits)) {
            XCTAssertEqual($0 as? NEWFEATURESCallPathFailure, .inputLimit)
        }
    }

    func testUnresolvedSamplesAreBoundedAndDeterministic() throws {
        let limits = NEWFEATURESCallProjectionLimits(maximumFunctions: 10, maximumInstructions: 10,
                                                     maximumXrefs: 10, maximumWork: 1000,
                                                     maximumUnresolvedSamples: 1)
        let rows = [instruction(0x1008, bytes: "1f 20 03 d5"), instruction(0x1004, bytes: "1f 20 03 d5")]
        let refs = [xref(0x1008), xref(0x1004)]
        let first = try make(projection(instructions: rows, xrefs: refs), limits: limits)
        let second = try make(projection(instructions: Array(rows.reversed()), xrefs: Array(refs.reversed())), limits: limits)
        XCTAssertEqual(first.unresolvedObservationCount, 2)
        XCTAssertEqual(first.unresolvedSamples, second.unresolvedSamples)
        XCTAssertEqual(first.unresolvedSamples.map(\.callSite), [0x1004])
    }

    func testOversizedByteTextCannotBecomeACallWitness() throws {
        let input = try make(projection(instructions: [instruction(bytes: String(repeating: "00 ", count: 100))]))
        XCTAssertEqual(try path(input).status, .notFoundInObservedGraph)
        XCTAssertEqual(input.unresolvedObservationCount, 1)
    }

    func testCancellationAndElapsedTimeApplyBeforeGraphProjection() throws {
        let cancelled = try NEWFEATURESGraphOperation(budget: NEWFEATURESReadBudget(), cancellationRequested: { true })
        XCTAssertThrowsError(try make(projection(), operation: cancelled)) {
            XCTAssertEqual($0 as? NEWFEATURESGraphInterruption, .cancelled)
        }
        let expired = try NEWFEATURESGraphOperation(
            budget: NEWFEATURESReadBudget(maxElapsedSeconds: 1), startedAt: .now.advanced(by: .seconds(-2))
        )
        XCTAssertThrowsError(try make(projection(), operation: expired)) {
            XCTAssertEqual($0 as? NEWFEATURESGraphInterruption, .timedOut)
        }
    }

    func testBoundedRangeLookupCanStopAnOverlapSearch() throws {
        let functions = [function(0x1000, end: 0x4000), function(0x2000, end: 0x2010),
                         function(0x2100, end: 0x2110)]
        let ranges = try FunctionRangeIndex(functions, checking: {})
        var visits = 0
        XCTAssertThrowsError(try ranges.owner(of: 0x3000, checking: {
            visits += 1
            if visits == 4 { throw NEWFEATURESCallPathFailure.inputLimit }
        })) { XCTAssertEqual($0 as? NEWFEATURESCallPathFailure, .inputLimit) }
        XCTAssertEqual(visits, 4)
    }
}
