import Foundation
#if !RG6_MANIFEST_STANDALONE
import XCTest
@testable import MacScope

final class RegenerationManifestStateBindingTests: XCTestCase {
    func testManifestDeclarationBinding() throws { try ManifestBindingScenarios.binding() }
    func testManifestAmbiguityAndPairAssociation() throws { try ManifestBindingScenarios.ambiguity() }
    func testManifestBindingBounds() async throws { try await ManifestBindingScenarios.limits() }
}
#endif

enum ManifestBindingScenarios {
    struct Failure: Error { let message: String }
    static func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
        if !value() { throw Failure(message: message) }
    }
    static let exportID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
    static let captureID = "22222222-2222-4222-8222-222222222222"
    static let rebuiltID = "33333333-3333-4333-8333-333333333333"
    static var image: RegenerationImageIdentity {
        .init(imageSlot: 0, selectedSliceIndex: 2, architecture: "arm64", selectedSliceSHA256: "captured-slice", analysisFingerprintSHA256: "captured-analysis")
    }
    static var function: FunctionVersionFingerprint { .init(id: captureID, address: 16, symbolName: "_raw", size: 8) }
    static var bridge: EquivalenceManifestBindings {
        .init(image: image, functions: [.init(exportUUID: exportID, capturedID: captureID, address: 16, size: 8)])
    }
    static func record(id: UUID = exportID, end: UInt64 = 24, state: RegenerationFunctionState = .accepted) -> RegenerationFunctionRecord {
        .init(imageQualifiedAddress: .init(imageSlot: 0, selectedSliceIndex: 2, imageSHA256: "captured-slice",
            address: RegenerationEncoding.address(16), endAddressExclusive: RegenerationEncoding.address(end)),
            functionUUID: id, name: "display", language: .unknown, stubFile: "stub.c", stubLine: 1, state: state, diagnostics: [])
    }
    static func manifest(_ records: [RegenerationFunctionRecord], image identity: RegenerationImageIdentity = image) -> RegenerationManifest {
        .init(schemaVersion: 1, applicationName: "Synthetic", image: identity, originalDeploymentTarget: nil,
            deploymentTarget: "27.0", dependentLibraries: [], functions: records, resources: [],
            resourceProvenance: .currentBundle, capabilities: nil, diagnostics: [])
    }
    static func pairing(basis: FunctionVersionMatchBasis = .symbolName, duplicate: Bool = false) -> PairingProjection {
        let match = FunctionVersionMatch(oldID: captureID, newID: rebuiltID, oldAddress: 16, newAddress: 128,
            basis: basis, confidence: .high, propagatedFromOldCallerID: nil, propagatedFromNewCallerID: nil,
            differences: [], symbolNameChanged: false)
        return .init(matches: duplicate ? [match, match] : [match], removedIDs: [], addedIDs: [], unresolved: [],
                     originalSizes: [8], rebuiltSizes: [8], assessedEvidence: [], unassessedEvidence: [])
    }
    static func observe(_ records: [RegenerationFunctionRecord], bindings: EquivalenceManifestBindings? = bridge,
                        functions: [FunctionVersionFingerprint] = [function], pairs: PairingProjection? = pairing()) throws -> [FunctionStateObservation] {
        try ManifestStateBinding.observations(manifest: manifest(records), image: image, functions: functions,
            bindings: bindings, pairing: pairs, budget: .start())
    }
    static func binding() throws {
        let result = try observe([record()])[0]
        try require(result.originalFunctionUUID != result.originalFunctionID, "Distinct UUID domains preserved")
        try require(result.originalFunctionID == captureID && result.rebuiltFunctionID == rebuiltID, "Explicit bridge and symbol association")
        try require(result.state == "accepted" && result.authority == "manifestDeclarationOnly", "Accepted remains declared text")
        try require(result.bindingStatus == "boundToCapturedFunction", "Exact binding recorded")
        let forged = try observe([record(id: UUID())])[0]
        try require(forged.originalFunctionID == nil && forged.rebuiltFunctionID == nil, "Same extent cannot substitute for exporter UUID")
        let absent = try observe([record()], bindings: nil)[0]
        try require(absent.originalFunctionID == nil && absent.state == "accepted", "No bridge preserves declaration unbound")
        let extent = try observe([record(end: 28)])[0]
        try require(extent.originalFunctionID == nil, "Exporter UUID alone cannot substitute for extent")
        let changedImage = RegenerationImageIdentity(imageSlot: 0, selectedSliceIndex: 2, architecture: "arm64",
            selectedSliceSHA256: "captured-slice", analysisFingerprintSHA256: "other-analysis")
        do {
            _ = try ManifestStateBinding.observations(manifest: manifest([record()], image: changedImage), image: image,
                functions: [function], bindings: bridge, pairing: pairing(), budget: .start())
            throw Failure(message: "Analysis mismatch admitted")
        } catch EquivalenceInputError.manifestIdentityMismatch {}
    }
    static func ambiguity() throws {
        let duplicates = try observe([record(state: .compiles), record(state: .accepted)])
        try require(duplicates.count == 2 && Set(duplicates.map(\.state)) == Set(["compiles", "accepted"]), "Duplicate declarations preserved")
        try require(duplicates.allSatisfy { $0.originalFunctionID == nil && $0.rebuiltFunctionID == nil }, "Duplicate UUID never first-wins")
        let aliases = try observe([record(), record(id: UUID())])
        try require(aliases.allSatisfy { $0.originalFunctionID == nil }, "Duplicate extent remains ambiguous")
        let capturedAlias = FunctionVersionFingerprint(id: "other-capture", address: 16, symbolName: "_alias", size: 8)
        let captureAmbiguity = try observe([record()], functions: [function, capturedAlias])[0]
        try require(captureAmbiguity.originalFunctionID == nil, "Captured aliases remain ambiguous")
        let duplicateBridge = EquivalenceManifestBindings(image: image, functions: bridge.functions + bridge.functions)
        let bridgeAmbiguity = try observe([record()], bindings: duplicateBridge)[0]
        try require(bridgeAmbiguity.originalFunctionID == nil, "Duplicate bridge remains ambiguous")
        for pairs in [nil, pairing(basis: .normalizedBody), pairing(duplicate: true)] as [PairingProjection?] {
            let result = try observe([record()], pairs: pairs)[0]
            try require(result.originalFunctionID == captureID && result.rebuiltFunctionID == nil, "Original binding separate from proven symbol association")
        }
    }
    static func limits() async throws {
        let small = try RegenerationWorkBudget(deadlineUptimeNanoseconds: UInt64.max, maximumRecords: 3)
        do {
            _ = try ManifestStateBinding.observations(manifest: manifest([record()]), image: image,
                functions: [function], bindings: bridge, pairing: pairing(), budget: small)
            throw Failure(message: "Manifest aggregate record bound bypassed")
        } catch RegenerationWorkBudgetError.recordLimitExceeded {}
        try await Task {
            withUnsafeCurrentTask { $0?.cancel() }
            do {
                _ = try ManifestStateBinding.observations(manifest: manifest([record()]), image: image,
                    functions: [function], bindings: bridge, pairing: pairing(), budget: .start())
                throw Failure(message: "Cancelled binding proceeded")
            } catch is CancellationError {}
        }.value
    }
}
