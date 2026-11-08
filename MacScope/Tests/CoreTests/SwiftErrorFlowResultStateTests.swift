import Foundation
import Testing
@testable import MacScope

struct SwiftErrorFlowResultStateTests {
    // Catches an old task publishing after image/generation replacement.
    @Test func staleGenerationCannotPublish() throws {
        let original = try key()
        var state = SwiftErrorFlowResultState()
        let ticket = state.begin(original)
        state.activate(try key(imageID: original.imageID))
        let accepted = state.publish(report(original), for: ticket)
        #expect(!accepted)
        #expect(state.report == nil)
        #expect(state.phase == .idle)
    }

    // Catches cancellation or restart leaving publication authority alive.
    @Test func cancellationAndRestartRetireRequests() throws {
        let key = try key()
        var state = SwiftErrorFlowResultState()
        let first = state.begin(key)
        let second = state.begin(key)
        let firstAccepted = state.publish(report(key), for: first)
        #expect(!firstAccepted)
        state.cancel()
        let secondAccepted = state.publish(report(key), for: second)
        #expect(!secondAccepted)
        #expect(state.report == nil)
        #expect(state.phase == .cancelled)
    }

    @Test func mismatchedSliceCannotPublish() throws {
        let key = try key()
        var state = SwiftErrorFlowResultState()
        let ticket = state.begin(key)
        let accepted = state.publish(report(try self.key(hash: String(repeating: "b", count: 64))), for: ticket)
        #expect(!accepted)
        #expect(state.report == nil)
    }

    @Test func documentForkRetiresSameImageAndGeneration() throws {
        let original = try key()
        var state = SwiftErrorFlowResultState()
        let ticket = state.begin(original)
        let fork = SwiftErrorFlowSourceKey(imageID: original.imageID, slot: original.slot,
                                           generation: original.generation,
                                           documentInstallationID: UUID(), identity: original.identity)
        state.activate(fork)
        let accepted = state.publish(report(original), for: ticket)
        #expect(!accepted)
        #expect(state.report == nil)
        #expect(state.phase == .idle)
    }

    @Test func acceptedReportRemainsReadOnlyEvidence() throws {
        let key = try key()
        var state = SwiftErrorFlowResultState()
        let ticket = state.begin(key)
        let accepted = state.publish(report(key), for: ticket)
        #expect(accepted)
        #expect(state.phase == .completed)
        #expect(state.report?.sourceReconstructionAllowed == false)
        #expect(state.report?.runtimeReachabilityProven == false)
        state.activate(nil)
        #expect(state.report == nil)
    }

    private func key(imageID: UUID = UUID(), hash: String = String(repeating: "a", count: 64)) throws -> SwiftErrorFlowSourceKey {
        .init(imageID: imageID, slot: .primary, generation: UUID(), documentInstallationID: UUID(),
              identity: try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: 0x0100000c,
                  rawCPUSubtype: 0, selectedSliceSHA256: hash, selectedSliceByteCount: 1024))
    }

    private func report(_ key: SwiftErrorFlowSourceKey) -> SwiftErrorFlowReport {
        .init(status: .analyzed,
              slice: .init(artifactSHA256: key.identity.selectedSliceSHA256, sliceOffset: 0,
                           sliceByteCount: 1024, cpuType: 0x0100000c, cpuSubtype: 0, littleEndian: true),
              declarations: [], edges: [], abstentions: [])
    }
}
