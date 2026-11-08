import Foundation
import XCTest
@testable import NEWFEATURESCore

final class DriverKitTests: XCTestCase {
    private let sha = String(repeating: "c", count: 64)
    private let fixtureBinaryID = UUID(uuidString: "11223344-5566-7788-99aa-bbccddeeff00")!

    private func observed(
        _ name: String,
        parent: String? = nil,
        size: UInt64 = 32,
        release: Int? = 25,
        slot: Int = 0
    ) throws -> NEWFEATURESObservedDriverClass {
        let image = try NEWFEATURESImageKey(slot: slot, binaryID: fixtureBinaryID, sha256: sha, analysisRevision: 1)
        let source = try NEWFEATURESProvenance(
            source: .classMetadata, sourceID: "fixture.class_table",
            sourceSHA256: sha, observationAddress: 0x1000
        )
        return NEWFEATURESObservedDriverClass(
            image: image, name: name, parentName: parent,
            metadataAddress: 0x1000, sizeBytes: size, recordedSDKRelease: release,
            recordedSDKBuildIdentifier: "Xcode27.fixture",
            vtables: [], provenance: source
        )
    }

    private func wire(_ catalog: NEWFEATURESDriverKitCatalog) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        var result = try! encoder.encode(catalog)
        result.append(0x0a)
        return result
    }

    private func admitted(_ catalog: NEWFEATURESDriverKitCatalog) -> NEWFEATURESTrustedSDKAdmission {
        NEWFEATURESTrustedSDKAdmission(
            release: catalog.release, buildIdentifier: catalog.sdkBuildIdentifier,
            pinnedCatalogSHA256: NEWFEATURESDriverKitReconstruction.catalogWireDigest(wire(catalog)),
            sourceHeaderTreeSHA256: String(repeating: "d", count: 64)
        )
    }

    func testExactSDKAllowsFields() throws {
        let catalog = NEWFEATURESDriverKitCatalog(
            release: 25, sdkBuildIdentifier: "Xcode27.fixture",
            classes: [
                NEWFEATURESSDKClass(name: "IOService", parentName: nil, sizeBytes: 16, fields: []),
                NEWFEATURESSDKClass(name: "MyDriver", parentName: "IOService", sizeBytes: 32, fields: [
                    NEWFEATURESDriverKitField(name: "queue", typeName: "IOQueue*", offsetBytes: 16, sizeBytes: 8),
                ]),
            ],
            messages: [.init(id: 123, name: "IOService_Start_ID")]
        )
        let records = [try observed("IOService", size: 16), try observed("MyDriver", parent: "IOService")]
        let report = try NEWFEATURESDriverKitReconstruction.reconstruct(
            observed: records, sdk: catalog, admission: admitted(catalog),
            canonicalCatalogJSON: wire(catalog)
        )
        XCTAssertEqual(report.classes.count, 2)
        XCTAssertEqual(report.classes.last?.status, .sdkSizeConcordant)
        XCTAssertEqual(report.classes.last?.applicableFields.first?.name, "queue")
    }

    func testSDKSizeMismatchAbstainsFromFields() throws {
        let catalog = NEWFEATURESDriverKitCatalog(
            release: 25, sdkBuildIdentifier: "Xcode27.fixture",
            classes: [.init(name: "MyDriver", parentName: nil, sizeBytes: 64, fields: [
                .init(name: "field", typeName: "int", offsetBytes: 8, sizeBytes: 4),
            ])],
            messages: []
        )
        let result = try NEWFEATURESDriverKitReconstruction.reconstruct(
            observed: [observed("MyDriver", size: 32)], sdk: catalog,
            admission: admitted(catalog), canonicalCatalogJSON: wire(catalog)
        )
        XCTAssertEqual(result.classes[0].status, .sdkSizeMismatch)
        XCTAssertTrue(result.classes[0].applicableFields.isEmpty)
    }

    func testObservedHierarchyCycleIsRefused() throws {
        XCTAssertThrowsError(try NEWFEATURESDriverKitReconstruction.reconstruct(
            observed: [observed("A", parent: "B"), observed("B", parent: "A")], sdk: nil
        ))
    }

    func testUnknownKernelMessageNeverGuessed() throws {
        let catalog = NEWFEATURESDriverKitCatalog(
            release: 25, sdkBuildIdentifier: "Xcode27.fixture", classes: [],
            messages: [.init(id: 3, name: "KnownCall_ID")]
        )
        let image = try NEWFEATURESImageKey(slot: 0, binaryID: UUID(), sha256: sha, analysisRevision: 1)
        let unknown = NEWFEATURESKernelMessageObservation(
            image: image, callSite: 0x2000, messageID: 999, recordedSDKRelease: 25,
            recordedSDKBuildIdentifier: "Xcode27.fixture"
        )
        let accepted = try NEWFEATURESDriverKitReconstruction.admitOnce(
            catalog, canonicalBytes: wire(catalog), against: admitted(catalog)
        )
        XCTAssertEqual(
            NEWFEATURESDriverKitReconstruction.resolveKernelMessage(
                unknown, admitted: accepted
            ),
            .unknown
        )
        let incompatible = NEWFEATURESKernelMessageObservation(
            image: image, callSite: 0x2000, messageID: 3, recordedSDKRelease: 24,
            recordedSDKBuildIdentifier: "Xcode27.fixture"
        )
        XCTAssertEqual(
            NEWFEATURESDriverKitReconstruction.resolveKernelMessage(
                incompatible, admitted: accepted
            ),
            .incompatibleSDK
        )
    }

    func testSameClassNameAcrossImagesNotConfused() throws {
        let report = try NEWFEATURESDriverKitReconstruction.reconstruct(
            observed: [observed("IOService", slot: 0), observed("IOService", slot: 1)], sdk: nil
        )
        XCTAssertEqual(report.classes.count, 2)
        XCTAssertNotEqual(report.classes[0].observed.image, report.classes[1].observed.image)
    }

    func testSDKCycleAndOverlapsRefused() throws {
        let cyclic = NEWFEATURESDriverKitCatalog(
            release: 25, sdkBuildIdentifier: "Xcode27.fixture",
            classes: [
                .init(name: "A", parentName: "B", sizeBytes: 32, fields: []),
                .init(name: "B", parentName: "A", sizeBytes: 32, fields: []),
            ], messages: []
        )
        XCTAssertThrowsError(try NEWFEATURESDriverKitReconstruction.validateCatalog(cyclic))
        let overlap = NEWFEATURESDriverKitCatalog(
            release: 25, sdkBuildIdentifier: "Xcode27.fixture",
            classes: [.init(name: "A", parentName: nil, sizeBytes: 32, fields: [
                .init(name: "x", typeName: "int", offsetBytes: 8, sizeBytes: 8),
                .init(name: "y", typeName: "int", offsetBytes: 12, sizeBytes: 8),
            ])], messages: []
        )
        XCTAssertThrowsError(try NEWFEATURESDriverKitReconstruction.validateCatalog(overlap))
    }

    func testSelfAssertedSDKWithoutPinCannotProjectFields() throws {
        let catalog = NEWFEATURESDriverKitCatalog(
            release: 25, sdkBuildIdentifier: "Xcode27.fixture",
            classes: [.init(name: "Driver", parentName: nil, sizeBytes: 32,
                            fields: [.init(name: "fake", typeName: "int", offsetBytes: 8, sizeBytes: 4)])],
            messages: []
        )
        let untrusted = try NEWFEATURESDriverKitReconstruction.reconstruct(
            observed: [observed("Driver")], sdk: catalog
        )
        XCTAssertEqual(untrusted.classes.first?.status, .sdkNotAdmitted)
        XCTAssertEqual(untrusted.classes.first?.applicableFields.isEmpty, true)
    }

    func testPythonCanonicalWireDigestAndCrossLanguageAdmission() throws {
        let path = try XCTUnwrap(Bundle.module.url(
            forResource: "python-golden-catalog", withExtension: "json"
        ))
        let source = try Data(contentsOf: path)
        XCTAssertEqual(NEWFEATURESDriverKitReconstruction.catalogWireDigest(source),
                       "b673965fa3d93a4f481d45bf8dc9016d7397e2ccf5a0a9a12ec13e0b78dca834")
        let decoded = try JSONDecoder().decode(NEWFEATURESDriverKitCatalog.self, from: source)
        let trusted = NEWFEATURESTrustedSDKAdmission(
            release: 25, buildIdentifier: "Xcode27.fixture",
            pinnedCatalogSHA256: "b673965fa3d93a4f481d45bf8dc9016d7397e2ccf5a0a9a12ec13e0b78dca834",
            sourceHeaderTreeSHA256: String(repeating: "f", count: 64)
        )
        XCTAssertNoThrow(try NEWFEATURESDriverKitReconstruction.admitOnce(
            decoded, canonicalBytes: source, against: trusted
        ))
    }
}
