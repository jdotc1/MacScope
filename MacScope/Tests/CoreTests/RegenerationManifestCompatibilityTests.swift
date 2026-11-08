import Foundation
#if !RG6_MANIFEST_STANDALONE
import XCTest
@testable import MacScope
final class RegenerationManifestCompatibilityTests: XCTestCase {
    func testVersionedDeclarationsAndRejections() throws { try ManifestCompatibilityScenarios.versions() }
    func testExternalDeclarationCannotAuthorizeExclusion() throws { try ManifestCompatibilityScenarios.authority() }
    func testDependencyDeclarationSurvivesBodyFill() throws { try ManifestCompatibilityScenarios.bodyFill() }
}
#endif

enum ManifestCompatibilityScenarios {
    typealias Base = ManifestBindingScenarios
    static func manifest(_ records: [RegenerationFunctionRecord], version: Int = 2) -> RegenerationManifest {
        .init(schemaVersion: version, applicationName: "Compatibility", image: Base.image,
              originalDeploymentTarget: nil, deploymentTarget: "27.0", dependentLibraries: [],
              functions: records, resources: [], resourceProvenance: .currentBundle, capabilities: nil, diagnostics: [])
    }
    static func versions() throws {
        let legacy = try JSONDecoder().decode(RegenerationManifest.self, from: RegenerationEncoding.json(manifest([Base.record(state: .stub)], version: 1)))
        try Base.require(legacy.functions[0].dependencyId == nil, "Legacy optional declaration must be absent")
        try ManifestStateBinding.validate(legacy, budget: .start())
        var external = Base.record(state: .external); external.dependencyId = "declared.package"
        let modern = try JSONDecoder().decode(RegenerationManifest.self, from: RegenerationEncoding.json(manifest([external])))
        try ManifestStateBinding.validate(modern, budget: .start())
        try Base.require(modern.functions == [external], "V2 declaration round trip")
        for invalid in [manifest([external], version: 1), manifest([Base.record(state: .external)], version: 1)] {
            do { try ManifestStateBinding.validate(invalid, budget: .start()); throw Base.Failure(message: "V1 external admitted") }
            catch EquivalenceInputError.invalidManifestDeclaration {}
        }
        var declared = Base.record(state: .stub); declared.dependencyId = "package"
        do { try ManifestStateBinding.validate(manifest([declared], version: 1), budget: .start()); throw Base.Failure(message: "V1 dependency admitted") }
        catch EquivalenceInputError.invalidManifestDeclaration {}
        do { try ManifestStateBinding.validate(manifest([], version: 3), budget: .start()); throw Base.Failure(message: "Future schema admitted") }
        catch EquivalenceInputError.unsupportedManifestSchema {}
        let unknown = String(decoding: try RegenerationEncoding.json(modern), as: UTF8.self).replacingOccurrences(of: "\"external\"", with: "\"futureState\"")
        do { _ = try JSONDecoder().decode(RegenerationManifest.self, from: Data(unknown.utf8)); throw Base.Failure(message: "Unknown state silently accepted") }
        catch DecodingError.dataCorrupted {}
        declared.dependencyId = " "
        do { try ManifestStateBinding.validate(manifest([declared]), budget: .start()); throw Base.Failure(message: "Empty declaration accepted") }
        catch EquivalenceInputError.invalidManifestDeclaration {}
        declared.dependencyId = "12345"
        do { try ManifestStateBinding.validate(manifest([declared]), budget: .init(deadlineUptimeNanoseconds: UInt64.max, maximumInputBytes: 4)); throw Base.Failure(message: "Declaration byte budget bypassed") }
        catch RegenerationWorkBudgetError.inputLimitExceeded {}
    }
    static func authority() throws {
        for dependency in [nil, "unresolved.package"] as [String?] {
            var record = Base.record(state: .external); record.dependencyId = dependency
            let observation = try ManifestStateBinding.observations(manifest: manifest([record]), image: Base.image,
                functions: [Base.function], bindings: Base.bridge, pairing: Base.pairing(), budget: .start())[0]
            try Base.require(observation.originalFunctionID == Base.captureID && observation.state == "external", "Exact declaration binding")
            try Base.require(observation.authority == "manifestDeclarationOnly" && observation.exclusionApplied == false && observation.dependencyId == dependency, "Binding cannot grant exclusion authority")
            let duplicate = try ManifestStateBinding.observations(manifest: manifest([record, record]), image: Base.image,
                functions: [Base.function], bindings: Base.bridge, pairing: nil, budget: .start())
            try Base.require(duplicate.allSatisfy { $0.originalFunctionID == nil && $0.exclusionApplied == false }, "Ambiguous external remains unapplied")
        }
        var mismatch = Base.record(id: UUID(), state: .external); mismatch.dependencyId = "package"
        let result = try ManifestStateBinding.observations(manifest: manifest([mismatch]), image: Base.image,
            functions: [Base.function], bindings: Base.bridge, pairing: nil, budget: .start())[0]
        try Base.require(result.originalFunctionID == nil && result.exclusionApplied == false, "Forged UUID cannot claim ownership")
    }
    static func bodyFill() throws {
        let id = Base.exportID, key = id.uuidString.lowercased().replacingOccurrences(of: "-", with: "")
        let sourcePath = "Sources/C/function_\(key).c"
        var record = RegenerationFunctionRecord(imageQualifiedAddress: Base.record().imageQualifiedAddress,
            functionUUID: id, name: "leaf", language: .c, stubFile: sourcePath, stubLine: 1, state: .stub, diagnostics: [])
        record.dependencyId = "caller.package"
        let original = Data("original stub".utf8), entry = Data("synthetic main".utf8)
        var project = RegenerationRenderedProject(files: [sourcePath: original, "Sources/Support/main.c": entry], manifest: manifest([record]), buildResources: [])
        let symbol = "msrg_recovered_" + key
        let body = RegenerationCBodyPacket.Body(image: Base.image, functionUUID: id,
            address: RegenerationEncoding.address(16), endAddressExclusive: RegenerationEncoding.address(24),
            emittedSymbol: symbol, source: "#include <stdint.h>\n#include <math.h>\n\nint \(symbol)(int value) {\n return value;\n}\n",
            prototypeAuthority: "synthetic explicit prototype", rules: ["EXPLICIT-SOURCE-PROTOTYPE"], producerReceipt: nil)
        try RegenerationCStubFill.apply(.init(schema: "macscope-rg3-c-bodies-v1", bodies: [body]), to: &project)
        try Base.require(project.manifest.functions[0].dependencyId == "caller.package" && project.manifest.functions[0].state == .filled, "RG3 preserves declaration without promoting acceptance")
        try Base.require(project.files["Support/OriginalStubs/function_\(key).c.txt"] == original && project.files["Sources/Support/main.c"] == entry, "No declared dependency removes original source")
    }
}
