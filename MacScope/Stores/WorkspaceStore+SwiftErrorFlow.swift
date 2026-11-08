import Foundation

extension WorkspaceStore {
    func swiftErrorFlowKey(in slot: ImageSlot) -> SwiftErrorFlowSourceKey? {
        guard let source = unwindAuditKey(in: slot), source.identity.rawCPUType == 0x0100000c,
              source.identity.rawCPUSubtype == 0 else { return nil }
        return .init(imageID: source.imageID, slot: source.slot, generation: source.generation,
                     documentInstallationID: documentInstallationID,
                     identity: source.identity)
    }

    func startSwiftErrorFlow(in slot: ImageSlot, coordinator: SwiftErrorFlowCoordinator) {
        guard slot == focusedImageSlot, let key = swiftErrorFlowKey(in: slot),
              let binary = snapshot.binary(in: slot), let layout = binary.preferredSegmentLayout,
              let bytes = snapshot.analysis(in: slot)?.imageBytes else {
            coordinator.activate(nil)
            return
        }
        // This matches the existing native audit's retained-input entry point.
        // sourceURL is descriptive: load(retainedBytes:...) never reopens it.
        let sourceURL = URL(fileURLWithPath: binary.path)
        let integrity = binary.artifactIntegrityState
        coordinator.start(key: key) {
            try MachOBinaryLoader().load(retainedBytes: bytes, sourceURL: sourceURL,
                verifiedIdentity: key.identity, layout: layout, integrity: integrity)
        }
    }

    @discardableResult
    func navigateFromSwiftErrorFlow(_ edge: SwiftErrorFlowEdge,
                                   coordinator: SwiftErrorFlowCoordinator) -> Bool {
        guard let key = coordinator.state.key, key.slot == focusedImageSlot,
              swiftErrorFlowKey(in: key.slot) == key,
              coordinator.state.phase == .completed,
              coordinator.state.report?.edges.contains(edge) == true,
              let binary = snapshot.binary(in: key.slot), binary.id == key.imageID,
              binary.artifactIntegrityState == .verified, binary.artifactIdentity == key.identity,
              edge.callAddress >= edge.callerStart,
              edge.callOffset == edge.callAddress - edge.callerStart,
              let layout = binary.preferredSegmentLayout,
              layout.records.filter({ segment in
                  guard segment.initialProtections & 4 != 0, segment.initialProtections & 2 == 0,
                        edge.callAddress >= segment.preferredVMStart else { return false }
                  let displacement = edge.callAddress - segment.preferredVMStart
                  return displacement < min(segment.preferredVMSize, segment.fileSize)
                      && min(segment.preferredVMSize, segment.fileSize) - displacement >= 4
              }).count == 1,
              snapshot.containsLoadedAddress(edge.callAddress, in: key.slot),
              selectAddress(ImageAddress(slot: key.slot, address: edge.callAddress)),
              AIRSHandoffPresenter.selectionReadback(store: self, imageID: key.imageID,
                                                    address: edge.callAddress) else { return false }
        editorMode = snapshot.analysis(in: key.slot)?.instructions.contains {
            $0.address == edge.callAddress
        } == true ? .disassembly : .hex
        showMachOMetadata = false
        return true
    }
}
