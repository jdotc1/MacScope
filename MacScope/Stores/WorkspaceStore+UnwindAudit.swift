import Foundation

extension WorkspaceStore {
    func unwindAuditKey(in slot: ImageSlot, model: UnwindAuditModel = .boundedLoops) -> UnwindAuditResultKey? {
        guard UnwindAuditResultKey.supportsInteractive(model), !isImporting, !isReanalyzing,
              let binary = snapshot.binary(in: slot), binary.artifactIntegrityState == .verified,
              let identity = binary.artifactIdentity, binary.preferredSegmentLayout != nil,
              let analysis = snapshot.analysis(in: slot), !analysis.imageBytes.isEmpty,
              UInt64(analysis.imageBytes.count) == identity.selectedSliceByteCount else { return nil }
        return .init(imageID: binary.id, slot: slot, generation: nativeDecompilerSnapshotRevision,
                     identity: identity, modelID: model.rawValue, configuration: .init())
    }

    func invalidateUnwindAuditIfNeeded() {
        guard let key = unwindAuditCoordinator.state.key else { return }
        guard let model = key.model else {
            unwindAuditCoordinator.activate(nil)
            return
        }
        unwindAuditCoordinator.activate(unwindAuditKey(in: key.slot, model: model))
    }

    @discardableResult
    func startUnwindAudit(in slot: ImageSlot, model: UnwindAuditModel = .boundedLoops) -> Task<Void, Never>? {
        guard slot == focusedImageSlot, let key = unwindAuditKey(in: slot, model: model),
              let binary = snapshot.binary(in: slot), let layout = binary.preferredSegmentLayout,
              let bytes = snapshot.analysis(in: slot)?.imageBytes else {
            unwindAuditCoordinator.activate(nil)
            return nil
        }
        let sourceURL = URL(fileURLWithPath: binary.path)
        let integrity = binary.artifactIntegrityState
        return unwindAuditCoordinator.start(key: key) {
            try MachOBinaryLoader().load(retainedBytes: bytes, sourceURL: sourceURL,
                verifiedIdentity: key.identity, layout: layout, integrity: integrity)
        }
    }

    @discardableResult
    func navigateFromUnwindAudit(_ target: UnwindAuditNavigationTarget) -> Bool {
        guard target.key.slot == focusedImageSlot,
              let model = target.key.model,
              unwindAuditKey(in: target.key.slot, model: model) == target.key,
              unwindAuditCoordinator.state.key == target.key,
              unwindAuditCoordinator.state.phase == .completed,
              unwindAuditCoordinator.state.report?.findings.contains(where: { finding in
                  finding.function.address <= target.address && target.address < finding.endAddress
              }) == true,
              selectAddress(ImageAddress(slot: target.key.slot, address: target.address)) else { return false }
        editorMode = snapshot.analysis(in: target.key.slot)?.instructions.contains {
            $0.address == target.address
        } == true ? .disassembly : .hex
        showMachOMetadata = false
        return true
    }
}
