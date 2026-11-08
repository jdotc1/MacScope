import Foundation
import XCTest
@testable import MacScope

final class RegenerationCStubFillTests: XCTestCase {
    private let id = UUID(uuidString: "12345678-1234-1234-1234-123456789abc")!
    private func input() -> RegenerationProjectInput {
        .init(applicationName: "BoundC", image: .init(imageSlot: 0, selectedSliceIndex: 0,
            architecture: "arm64", selectedSliceSHA256: String(repeating: "a", count: 64),
            analysisFingerprintSHA256: String(repeating: "b", count: 64)),
            functions: [.init(functionUUID: id, address: 4096, endAddress: 4112,
                name: "_leaf", language: .unknown)], originalDeploymentTarget: "27.0",
            dependentLibraries: [], referenceFiles: [:], diagnostics: [])
    }
    private func body(image: RegenerationImageIdentity? = nil, missingIdentity: Bool = false,
                      sourceSuffix: String = "") -> RegenerationCBodyPacket.Body {
        let symbol = "msrg_recovered_12345678123412341234123456789abc"
        return .init(image: missingIdentity ? nil : image ?? input().image, functionUUID: id,
            address: RegenerationEncoding.address(4096), endAddressExclusive: RegenerationEncoding.address(4112),
            emittedSymbol: symbol, source: "#include <stdint.h>\n#include <math.h>\n\nint \(symbol)(int value) {\n return value;\n}\n" + sourceSuffix,
            prototypeAuthority: "explicit synthetic prototype", rules: ["EXPLICIT-SOURCE-PROTOTYPE"],
            producerReceipt: "producer-syntax-reference")
    }
    private func packet(_ values: [RegenerationCBodyPacket.Body]) -> RegenerationCBodyPacket {
        .init(schema: "macscope-rg3-c-bodies-v1", bodies: values)
    }
    func testBoundSourceIsFilledExactlyOnceAndOriginalStubAndMainArePreserved() throws {
        var project = try RegenerationProjectRenderer.render(input())
        let old = project.manifest.functions[0]
        let original = project.files[old.stubFile]
        let main = project.files["Sources/Support/main.c"]
        let candidate = body()
        try RegenerationCStubFill.apply(packet([candidate]), to: &project)
        let record = project.manifest.functions[0]
        let evidence = try XCTUnwrap(record.cBody)
        XCTAssertEqual(record.state, .filled)
        XCTAssertEqual(project.files[evidence.sourceFile], Data(candidate.source.utf8))
        XCTAssertEqual(project.files[evidence.originalStubFile], original)
        XCTAssertEqual(project.files["Sources/Support/main.c"], main)
        XCTAssertEqual(evidence.compilation, "not-established-by-consumer")
        XCTAssertEqual(evidence.runtimeEquivalence, "NOT_ESTABLISHED")
        let include = try XCTUnwrap(String(data: project.files[old.stubFile]!, encoding: .utf8))
        XCTAssertTrue(include.contains("#include \"../../Decompiled/C/"))
        XCTAssertFalse(include.contains("__builtin_trap"))
        let spec = try JSONSerialization.jsonObject(with: project.files["project.yml"]!) as! [String: Any]
        XCTAssertNotNil(spec["targets"])
        let decoded = try JSONDecoder().decode(RegenerationManifest.self, from: project.files["REGEN-MANIFEST.json"]!)
        XCTAssertEqual(decoded.functions, project.manifest.functions)
    }
    func testMissingOrDifferentCapturedIdentityRetainsStub() throws {
        for candidate in [body(missingIdentity: true), body(image: .init(imageSlot: 1, selectedSliceIndex: 0,
            architecture: "arm64", selectedSliceSHA256: input().image.selectedSliceSHA256,
            analysisFingerprintSHA256: input().image.analysisFingerprintSHA256))] {
            var project = try RegenerationProjectRenderer.render(input())
            let original = project.files[project.manifest.functions[0].stubFile]
            try RegenerationCStubFill.apply(packet([candidate]), to: &project)
            XCTAssertEqual(project.manifest.functions[0].state, .stub)
            XCTAssertEqual(project.files[project.manifest.functions[0].stubFile], original)
            XCTAssertTrue(project.manifest.diagnostics.contains { $0.contains("RG3 refused") })
        }
    }
    func testDuplicateAndAdditionalGlobalDefinitionFailAtomically() throws {
        for candidates in [[body(), body()], [body(sourceSuffix: "int unexpected(void) { return 0; }\n")]] {
            var project = try RegenerationProjectRenderer.render(input())
            let originalFiles = project.files
            XCTAssertThrowsError(try RegenerationCStubFill.apply(packet(candidates), to: &project))
            XCTAssertEqual(project.files, originalFiles)
        }
    }
    func testObjCAndSwiftAreNotReplaced() throws {
        for language in [RegenerationLanguage.objc, .swift] {
            var value = input(); value.functions[0].language = language
            var project = try RegenerationProjectRenderer.render(value)
            try RegenerationCStubFill.apply(packet([body()]), to: &project)
            XCTAssertEqual(project.manifest.functions[0].state, .stub)
        }
    }
    func testRequestCarriesCapturedIdentityAndNoCompileAuthority() throws {
        let project = try RegenerationProjectRenderer.render(input())
        let request = try JSONDecoder().decode(RegenerationCStubFill.Request.self,
            from: project.files["C-BODY-REQUEST.json"]!)
        XCTAssertEqual(request.image, input().image)
        XCTAssertEqual(request.functions[0].functionUUID, id)
        XCTAssertEqual(request.functions[0].address, RegenerationEncoding.address(4096))
        XCTAssertEqual(request.functions[0].emittedSymbol, body().emittedSymbol)
        XCTAssertNil(project.manifest.functions[0].cBody)
    }
    func testCallerStatusCannotPromoteCompilationOrAcceptance() throws {
        var object = try JSONSerialization.jsonObject(with: RegenerationEncoding.json(packet([body()]))) as! [String: Any]
        var bodies = object["bodies"] as! [[String: Any]]
        bodies[0]["state"] = "accepted"; bodies[0]["passed"] = true
        object["bodies"] = bodies
        let packet = try JSONDecoder().decode(RegenerationCBodyPacket.self, from: JSONSerialization.data(withJSONObject: object))
        var project = try RegenerationProjectRenderer.render(input())
        try RegenerationCStubFill.apply(packet, to: &project)
        XCTAssertEqual(project.manifest.functions[0].state, .filled)
    }
    func testActualProducerPacketWithBothHelpersMatchesNativeConsumer() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/RG3")
        let request = try JSONDecoder().decode(RegenerationCStubFill.Request.self,
            from: Data(contentsOf: root.appendingPathComponent("request.json")))
        let candidate = try JSONDecoder().decode(RegenerationCBodyPacket.self,
            from: Data(contentsOf: root.appendingPathComponent("packet.json")))
        let function = try XCTUnwrap(request.functions.first)
        let value = RegenerationProjectInput(applicationName: "SyntheticProducerContract", image: request.image,
            functions: [.init(functionUUID: function.functionUUID,
                address: try XCTUnwrap(UInt64(function.address.dropFirst(2), radix: 16)),
                endAddress: try XCTUnwrap(UInt64(function.endAddressExclusive.dropFirst(2), radix: 16)),
                name: function.name, language: function.language)], originalDeploymentTarget: "27.0",
            dependentLibraries: [], referenceFiles: [:], diagnostics: ["Synthetic binding; not real image authority."])
        var project = try RegenerationProjectRenderer.render(value)
        try RegenerationCStubFill.apply(candidate, to: &project)
        let record = try XCTUnwrap(project.manifest.functions.first)
        XCTAssertEqual(record.state, .filled)
        let path = try XCTUnwrap(record.cBody?.sourceFile)
        XCTAssertEqual(project.files[path], Data(candidate.bodies[0].source.utf8))
        XCTAssertEqual(record.cBody?.runtimeEquivalence, "NOT_ESTABLISHED")
    }

}
