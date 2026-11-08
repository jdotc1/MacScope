import Foundation

enum EquivalenceCaptureError: Error { case missingOrMismatchedIdentity, unsupportedArchitecture, invalidFunctionExtent }

struct EquivalenceCapturedImage {
    let image: MachOFile
    let identity: RegenerationImageIdentity
    let functions: [FunctionVersionFingerprint]
    let manifestBindings: EquivalenceManifestBindings?
}

enum EquivalenceSnapshotAdapter {
    /// Reuses existing verified selected-slice and analysis identity. No provenance is rehashed.
    static func prepare(snapshot: WorkspaceSnapshot, slot: ImageSlot, budget: RegenerationWorkBudget,
                        includePairingFacts: Bool = false,
                        includeManifestBindings: Bool = false) throws -> EquivalenceCapturedImage {
        try budget.checkpoint()
        guard let binary = snapshot.binary(in: slot), let analysis = snapshot.analysis(in: slot),
              let identity = binary.artifactIdentity, binary.artifactIntegrityState == .verified,
              identity.architectureVariant == .arm64, let fingerprint = analysis.analysisInputFingerprint,
              fingerprint.binaryID == binary.id, fingerprint.imageSlot == slot,
              fingerprint.binaryPath == binary.path, fingerprint.binaryName == binary.name,
              fingerprint.selectedSliceIndex == binary.selectedSliceIndex, fingerprint.artifactIdentity == identity,
              fingerprint.imageBytesSHA256 == identity.selectedSliceSHA256,
              fingerprint.imageByteCount == identity.selectedSliceByteCount,
              UInt64(analysis.imageBytes.count) == identity.selectedSliceByteCount,
              binary.metadata.platformName == nil || binary.metadata.platformName == "macOS" else {
            throw EquivalenceCaptureError.missingOrMismatchedIdentity
        }
        guard analysis.imageBytes.count <= budget.maximumInputBytes else { throw RegenerationWorkBudgetError.inputLimitExceeded }
        var remainingRecords = budget.maximumRecords
        let retainedMetadataCounts = [analysis.objcClasses.count, analysis.objcCategories.count,
            analysis.objcProtocols.count, analysis.swiftTypes.count, analysis.swiftConformances.count]
        let inputCounts = (includePairingFacts
            ? [analysis.functions.count, analysis.symbols.count]
            : [analysis.functions.count]) + retainedMetadataCounts
        for count in inputCounts {
            try budget.checkpoint()
            guard count <= remainingRecords else { throw RegenerationWorkBudgetError.recordLimitExceeded }
            remainingRecords -= count
        }
        // Preserve the already-captured metadata instead of repeating potentially amplified
        // class and Swift descriptor walks. The projection marks these observations unassessed.
        let options = MachOParseOptions(recoverStringLiterals: false, recoverObjectiveCMetadata: false,
                                      recoverSwiftMetadata: false, parseCodeSignature: false, requestedSliceIndex: nil)
        var file = try MachOParser().parse(analysis.imageBytes, options: options)
        file.objectiveCMetadata.classes = analysis.objcClasses
        file.objectiveCMetadata.categories = analysis.objcCategories
        file.objectiveCMetadata.protocols = analysis.objcProtocols
        file.swiftTypes = analysis.swiftTypes
        file.swiftConformances = analysis.swiftConformances
        try budget.checkpoint()
        guard file.architectureName == "arm64" else { throw EquivalenceCaptureError.unsupportedArchitecture }
        let functions: [FunctionVersionFingerprint]
        if includePairingFacts {
            functions = try FunctionVersionFingerprintAdapter.capturedSymbolFingerprints(
                functions: analysis.functions, symbols: analysis.symbols, budget: budget)
        } else {
            functions = try analysis.functions.map { function in
                try budget.checkpoint()
                guard function.endAddress >= function.startAddress else { throw EquivalenceCaptureError.invalidFunctionExtent }
                return FunctionVersionFingerprint(id: function.id.uuidString, address: function.startAddress,
                    symbolName: nil, size: function.endAddress - function.startAddress)
            }
        }
        try budget.checkpoint()
        guard functions.count <= budget.maximumRecords else { throw RegenerationWorkBudgetError.recordLimitExceeded }
        let imageIdentity = RegenerationImageIdentity(imageSlot: slot.rawValue,
            selectedSliceIndex: binary.selectedSliceIndex, architecture: "arm64",
            selectedSliceSHA256: identity.selectedSliceSHA256, analysisFingerprintSHA256: fingerprint.overallSHA256)
        let manifestBindings: EquivalenceManifestBindings?
        if includeManifestBindings {
            let binding = ReconstructionImageBinding(binaryID: binary.id, imageSlot: slot,
                selectedSliceIndex: binary.selectedSliceIndex, architecture: .arm64, machOIdentity: identity)
            let records = try analysis.functions.map { function in
                try budget.checkpoint()
                guard function.endAddress >= function.startAddress else { throw EquivalenceCaptureError.invalidFunctionExtent }
                // Same metadata UUID derivation as the exporter, not binary/source hashing.
                // Duplicate extents deliberately share the base UUID here and remain ambiguous;
                // never guess which exporter alias ordinal corresponds to a captured row.
                return EquivalenceManifestBindings.Function(
                    exportUUID: ReconstructionStableImageAuthority.stableFunctionID(image: binding,
                        analysisFingerprintSHA256: fingerprint.overallSHA256, startAddress: function.startAddress,
                        endAddressExclusive: function.endAddress, boundarySchemaVersion: ReconstructionFunctionCoordinate.schemaVersion),
                    capturedID: function.id.uuidString, address: function.startAddress,
                    size: function.endAddress - function.startAddress)
            }
            manifestBindings = .init(image: imageIdentity, functions: records)
        } else { manifestBindings = nil }
        return EquivalenceCapturedImage(image: file, identity: imageIdentity,
            functions: functions, manifestBindings: manifestBindings)
    }
}
