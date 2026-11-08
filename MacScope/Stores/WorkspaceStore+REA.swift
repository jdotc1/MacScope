import CryptoKit
import Foundation

extension WorkspaceStore {
    @discardableResult
    func navigateToREAHandler(_ destination: REAUITraceDestination, evidence: REAResultEvidence,
                              image: Phase2ReadImageIdentity) -> Bool {
        guard focusedImageSlot == image.slot,
              phase2ReadLedger.imageIdentity(in: image.slot, snapshot: snapshot) == image,
              evidence.authority.workspaceID == workspaceID,
              evidence.authority.sourceGeneration == image.analysisRevision,
              evidence.operation == REAInspectionOperation.uiResources.rawValue,
              reaResultEvidence.records.contains(evidence),
              REAUITraceProjection.destinations(requestJSON: evidence.requestJSON, responseJSON: evidence.responseJSON)[destination.actionID] == destination,
              let request = (try? JSONSerialization.jsonObject(with: evidence.requestJSON)) as? [String: Any],
              let input = request["input"] as? [String: Any],
              input["targetSHA256"] as? String == evidence.authority.imageSHA256,
              input["snapshotID"] as? String == evidence.authority.snapshotID.uuidString,
              let metadata = input["metadata"] as? [String: Any],
              metadata["targetSHA256"] as? String == evidence.authority.imageSHA256,
              metadata["snapshotID"] as? String == evidence.authority.snapshotID.uuidString,
              let response = (try? JSONSerialization.jsonObject(with: evidence.responseJSON)) as? [String: Any],
              let result = response["result"] as? [String: Any],
              result["snapshotID"] as? String == evidence.authority.snapshotID.uuidString,
              let analysis = result["analysis"] as? [String: Any],
              analysis["target_sha256"] as? String == evidence.authority.imageSHA256,
              let current = snapshot.analysis(in: image.slot),
              let offset = FileAddressMapping.resolvedFileOffset(forVirtualAddress: destination.address, in: snapshot.imageByteMappings(in: image.slot)),
              current.sections.contains(where: { section in
                  section.isExecutable && !section.isZeroFill &&
                  FileAddressMapping.resolvedFileOffset(forVirtualAddress: destination.address,
                      in: FileAddressMapping.verifiedMappings(from: [section], payloadLength: current.imageBytes.count)) == offset
              }),
              snapshot.isExecutableInstructionAddress(ImageAddress(slot: image.slot, address: destination.address)),
              let instruction = current.instructions.first(where: { $0.address == destination.address }),
              !["unknown", ".byte", "unavailable"].contains(instruction.mnemonic)
        else {
            lastIssue = "This candidate is unavailable or no longer matches the current image and analysis."
            return false
        }
        return goToAddress(destination.address, in: image.slot)
    }

    func reaAuthority(imageSHA256: String, snapshotID: UUID) -> REAResultAuthority? {
        guard let bytes = focusedAnalysis?.imageBytes, !bytes.isEmpty,
              REACaptureCommitment.digest(bytes) == imageSHA256,
              let identity = phase2ReadLedger.imageIdentity(in: focusedImageSlot, snapshot: snapshot) else { return nil }
        return REAResultAuthority(workspaceID: workspaceID, imageSHA256: imageSHA256,
            snapshotID: snapshotID, sourceGeneration: identity.analysisRevision,
            resourceSHA256: REAEmbeddedIdentity.resourceSHA256,
            implementationIdentity: REAEmbeddedIdentity.implementationIdentity)
    }

    func publishREAResult(_ candidate: REAResultEvidence) throws {
        guard let current = reaAuthority(imageSHA256: candidate.authority.imageSHA256,
                                         snapshotID: candidate.authority.snapshotID) else {
            throw REAResultEvidenceError.staleAuthority
        }
        var next = reaResultEvidence
        try next.publish(candidate, activeAuthority: current)
        reaResultEvidence = next
        markDocumentMutated()
    }
}
