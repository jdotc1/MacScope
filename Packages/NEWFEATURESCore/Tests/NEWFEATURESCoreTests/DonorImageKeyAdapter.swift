import Foundation
@testable import NEWFEATURESCore

extension NEWFEATURESImageKey {
    /// Test-only shorthand that fills the identity dimensions the moved tests do not vary.
    init(slot: Int, binaryID: UUID, sha256: String, analysisRevision: UInt64) throws {
        try self.init(
            documentInstance: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)),
            workspaceInstance: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)),
            slot: slot, binaryID: binaryID, ownerGeneration: 1, architecture: "arm64",
            sliceIndex: nil, sha256: sha256, analysisRevision: analysisRevision,
            analysisInputFingerprintSHA256: String(repeating: "e", count: 64))
    }
}
