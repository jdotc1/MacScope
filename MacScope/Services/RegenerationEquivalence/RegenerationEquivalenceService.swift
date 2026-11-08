import Foundation

enum EquivalenceInputError: Error, Equatable {
    case unsupportedArchitecture
    case manifestIdentityMismatch
    case dependencyIdentityMismatch
    case unsupportedManifestSchema
    case invalidManifestDeclaration
    case unsupportedDependencySchema
    case invalidFunctionCoordinate
    case duplicateManifestFunctionID
    case unboundRebuiltAnalysis
}

/// A rebuilt image can have a first sealed slice identity before any analysis exists.
struct RebuiltImageIdentity: Codable, Equatable, Sendable {
    let imageSlot: Int
    let selectedSliceIndex: Int?
    let architecture: String
    let selectedSliceSHA256: String
    let analysisFingerprintSHA256: String?

    init(imageSlot: Int, selectedSliceIndex: Int?, architecture: String, selectedSliceSHA256: String,
         analysisFingerprintSHA256: String?) {
        self.imageSlot = imageSlot; self.selectedSliceIndex = selectedSliceIndex; self.architecture = architecture
        self.selectedSliceSHA256 = selectedSliceSHA256; self.analysisFingerprintSHA256 = analysisFingerprintSHA256
    }

    init(captured: RegenerationImageIdentity) {
        self.init(imageSlot: captured.imageSlot, selectedSliceIndex: captured.selectedSliceIndex,
                  architecture: captured.architecture, selectedSliceSHA256: captured.selectedSliceSHA256,
                  analysisFingerprintSHA256: captured.analysisFingerprintSHA256)
    }
}

struct EquivalenceServiceReport: Codable, Sendable {
    let schemaVersion: Int
    let originalIdentity: RegenerationImageIdentity
    let rebuiltIdentity: RebuiltImageIdentity
    let structure: StructuralReport
    let functionPairing: PairingProjection?
    let originalFunctionSizes: [UInt64]
    let rebuiltFunctionSizes: [UInt64]?
    let functionPairingStatus: String
    let functionStates: [FunctionStateObservation]
    let limitations: [String]
}

struct FunctionStateObservation: Codable, Sendable {
    let originalFunctionUUID: String
    let originalFunctionID: String?
    let state: String
    let declaredAddress: String
    let declaredEndAddressExclusive: String
    let bindingStatus: String
    let rebuiltFunctionID: String?
    let pairingStatus: String
    let authority: String
    var dependencyId: String? = nil
    /// Optional for decoding older reports; new observations always explicitly say false.
    var exclusionApplied: Bool? = nil
}

enum RegenerationEquivalenceService {
    /// The caller must bind each identity to the already-captured, selected image bytes and
    /// parse metadata before calling. This function never opens or executes either binary.
    static func compare(original: MachOFile, rebuilt: MachOFile,
                        originalIdentity: RegenerationImageIdentity, rebuiltIdentity: RebuiltImageIdentity,
                        manifest: RegenerationManifest?, dependencies: DependencyInventory?,
                        originalFunctions: [FunctionVersionFingerprint],
                        rebuiltFunctions: [FunctionVersionFingerprint]?, rebuiltSizes: [UInt64]? = nil,
                        manifestBindings: EquivalenceManifestBindings? = nil,
                        budget: RegenerationWorkBudget) throws -> EquivalenceServiceReport {
        try budget.checkpoint()
        guard originalFunctions.count <= budget.maximumRecords,
              (rebuiltFunctions?.count ?? rebuiltSizes?.count ?? 0) <= budget.maximumRecords - originalFunctions.count else {
            throw RegenerationWorkBudgetError.recordLimitExceeded
        }
        guard original.architectureName == "arm64", rebuilt.architectureName == "arm64",
              originalIdentity.architecture == "arm64", rebuiltIdentity.architecture == "arm64" else {
            throw EquivalenceInputError.unsupportedArchitecture
        }
        if let manifest {
            try ManifestStateBinding.validate(manifest, budget: budget)
            guard manifest.image == originalIdentity else { throw EquivalenceInputError.manifestIdentityMismatch }
        }
        var remainingRecords = budget.maximumRecords
        for count in [originalFunctions.count, rebuiltFunctions?.count ?? rebuiltSizes?.count ?? 0,
                      manifest?.functions.count ?? 0, manifestBindings?.functions.count ?? 0] {
            guard count <= remainingRecords else { throw RegenerationWorkBudgetError.recordLimitExceeded }
            remainingRecords -= count
        }
        if let dependencies {
            guard dependencies.schemaVersion == 1 else { throw EquivalenceInputError.unsupportedDependencySchema }
            guard dependencies.image == originalIdentity else { throw EquivalenceInputError.dependencyIdentityMismatch }
        }
        let dimensions = try MachOStructureProjection.compare(original: original, rebuilt: rebuilt, budget: budget)
        try budget.checkpoint()
        let structure = StructuralReportBuilder.build(original: originalIdentity.selectedSliceSHA256,
                                                      rebuilt: rebuiltIdentity.selectedSliceSHA256,
                                                      dimensions: dimensions)
        if rebuiltFunctions != nil && rebuiltIdentity.analysisFingerprintSHA256 == nil {
            throw EquivalenceInputError.unboundRebuiltAnalysis
        }
        let pairing = try rebuiltFunctions.map { try FunctionPairingProjection.compare(original: originalFunctions, rebuilt: $0, budget: budget) }
        try budget.checkpoint()
        let states = try ManifestStateBinding.observations(manifest: manifest, image: originalIdentity,
            functions: originalFunctions, bindings: manifestBindings, pairing: pairing, budget: budget)
        try budget.checkpoint()
        return .init(schemaVersion: 1, originalIdentity: originalIdentity, rebuiltIdentity: rebuiltIdentity,
                     structure: structure, functionPairing: pairing,
                     originalFunctionSizes: originalFunctions.map(\.size).sorted(),
                     rebuiltFunctionSizes: (rebuiltFunctions?.map(\.size) ?? rebuiltSizes)?.sorted(),
                     functionPairingStatus: pairing == nil ? "unassessed: rebuilt function pairing facts not provided" : "assessed: captured raw symbols and descriptive sizes only; body and control flow unassessed",
                     functionStates: states,
                     limitations: ["Static evidence only; no behavioral equivalence is claimed.",
                                   "The rebuilt image is caller-selected and not proven to derive from the regenerated project.",
                                   "Objective-C and Swift metadata are retained observations; completeness is unassessed.",
                                   "Objective-C ivar offsets and layout sizes are captured static/link-time observations only; runtime layout and ABI equivalence are unassessed.",
                                   "Swift field and enum payload type identity, protocol requirements and full generic signatures are unassessed.",
                                   "Import library ordinals are reported within-image observations from the merged import view, not raw chained encodings or cross-image identities; completeness and ownership are unassessed.",
                                   "Function identifiers apply to their own image; cross-image pairs are evidence-based.",
                                   "BinDiff was not assessed; no optional similarity signal is reported.",
                                   "This report does not carry a source revision or Reconstruction acceptance receipt.",
                                   "Dependency external exclusions are unassessed; an inventory does not apply them."]
                         + (manifest != nil ? ["Manifest states are caller declarations only. External states and dependency IDs do not establish ownership or apply exclusions. Binding or symbol pairing does not verify compilation, acceptance, rebuilt state or behavioral equivalence."] : [])
                         + (manifest == nil ? ["Manifest not supplied; function states are unassessed."] : []))
    }
}
