import Foundation
import XCTest
@testable import MacScope

final class AIRSHandoffImportTests: XCTestCase {
    private let digest = String(repeating: "a", count: 64)
    private let uuid = UUID(uuidString: "05248e60-94e1-3e6d-9843-d8a437797d1b")!

    private func document(start: String = "0x1010", end: String = "0x1020",
                          relativeStart: String = "0x10", relativeEnd: String = "0x20", checkedPC: String = "0x1014") throws -> Data {
        let object: [String: Any] = [
            "schema_version": 1, "report_kind": "airs.macscope_handoff",
            "integration_status": "proposed_export_contract",
            "image": ["display_name": "owned", "architecture": "arm64", "cpu_subtype": 0,
                      "container_sha256": digest, "slice_sha256": digest,
                      "slice_offset": 0, "slice_size": 256,
                      "uuid": uuid.uuidString, "preferred_base": "0x1000"],
            "selection": ["finding_id": "airsf-" + digest, "function_name": "_owned",
                          "address_space": "preferred_vm",
                          "vm_range": ["start": start, "end": end],
                          "image_relative_range": ["start": relativeStart, "end": relativeEnd]],
            "finding": ["verdict": "inconsistency", "coverage": "compact", "mode": "frame",
                        "reason_codes": ["caller_state_mismatch"],
                        "scope": "synchronous_call_sites", "checked_pcs": [checkedPC],
                        "evidence": [["code": "caller_state_mismatch", "message": "SP differs",
                                      "address": checkedPC, "expected": "entry SP", "observed": "entry SP-16"]],
                        "limitations": ["Bounded synchronous call-site model"]],
            "source_analysis": ["name": "AIRS", "version": "0.1.0",
                                "analysis_model_version": "arm64-bounded-loop-calls-v29"],
            "requirements": ["Verify selected-slice identity."]
        ]
        return try JSONSerialization.data(withJSONObject: object)
    }

    private func binary(digest: String? = nil, uuid: UUID? = nil,
                        verified: Bool = true, executable: Bool = true) throws -> BinaryImage {
        let identity = try MachOSliceArtifactIdentity(
            uuid: uuid ?? self.uuid, rawCPUType: MachOConstants.cpuTypeARM64,
            rawCPUSubtype: 0, selectedSliceSHA256: digest ?? self.digest,
            selectedSliceByteCount: 256)
        let layout = try MachOPreferredSegmentLayout(records: [
            .init(name: "__TEXT", preferredVMStart: 0x1000, preferredVMSize: 256,
                  sliceRelativeFileOffset: 0, fileSize: 256,
                  initialProtections: executable ? 5 : 1)
        ], selectedSliceByteCount: 256)
        return BinaryImage(id: UUID(), name: "owned", path: "/owned", kind: "Mach-O",
                           architecture: "arm64", artifactIdentity: identity,
                           preferredSegmentLayout: layout,
                           artifactIntegrityState: verified ? .verified : .unavailable)
    }

    func testExactSliceAndRangeAdmitStaticNavigation() throws {
        let handoff = try AIRSHandoffImport.parse(document())
        XCTAssertEqual(try handoff.destinationAddress(binary: binary()), 0x1010)
        XCTAssertEqual(handoff.checkedPCs, [0x1014])
        XCTAssertEqual(handoff.evidence.first?.observed, "entry SP-16")
    }

    func testIdentityAndExecutableRangeFailuresPrecedeNavigation() throws {
        let handoff = try AIRSHandoffImport.parse(document())
        XCTAssertThrowsError(try handoff.destinationAddress(binary: binary(digest: String(repeating: "b", count: 64))))
        XCTAssertThrowsError(try handoff.destinationAddress(binary: binary(uuid: UUID())))
        XCTAssertThrowsError(try handoff.destinationAddress(binary: binary(verified: false)))
        XCTAssertThrowsError(try handoff.destinationAddress(binary: binary(executable: false)))
        for (key, value) in [("architecture", "arm64e" as Any),
                             ("cpu_subtype", 2 as Any), ("slice_size", 128 as Any)] {
            var root = try XCTUnwrap(JSONSerialization.jsonObject(with: document()) as? [String: Any])
            var image = try XCTUnwrap(root["image"] as? [String: Any])
            image[key] = value
            root["image"] = image
            let changed = try AIRSHandoffImport.parse(JSONSerialization.data(withJSONObject: root))
            XCTAssertThrowsError(try changed.destinationAddress(binary: binary()))
        }
        var root = try XCTUnwrap(JSONSerialization.jsonObject(with: document()) as? [String: Any])
        var image = try XCTUnwrap(root["image"] as? [String: Any])
        image["uuid"] = NSNull()
        root["image"] = image
        let noUUID = try AIRSHandoffImport.parse(JSONSerialization.data(withJSONObject: root))
        XCTAssertEqual(try noUUID.destinationAddress(binary: binary()), 0x1010)
    }

    func testMalformedAndMismatchedRangesDecline() throws {
        XCTAssertThrowsError(try AIRSHandoffImport.parse(document(start: "0x1020", end: "0x1010")))
        var missingUUID = try XCTUnwrap(JSONSerialization.jsonObject(with: document()) as? [String: Any])
        var image = try XCTUnwrap(missingUUID["image"] as? [String: Any])
        image.removeValue(forKey: "uuid")
        missingUUID["image"] = image
        XCTAssertThrowsError(try AIRSHandoffImport.parse(JSONSerialization.data(withJSONObject: missingUUID)))
        let mismatch = try AIRSHandoffImport.parse(document(relativeStart: "0x11"))
        XCTAssertThrowsError(try mismatch.destinationAddress(binary: binary()))
        let outside = try AIRSHandoffImport.parse(document(start: "0x10f8", end: "0x1108",
                                                            relativeStart: "0xf8", relativeEnd: "0x108", checkedPC: "0x10fc"))
        XCTAssertThrowsError(try outside.destinationAddress(binary: binary()))
    }

    func testNavigationRecordRetainsQualifiedProvenance() throws {
        let image = try binary()
        let record = try AIRSHandoffImport.parse(document()).navigationRecord(binary: image)
        XCTAssertEqual(record.address, 0x1010)
        XCTAssertEqual(record.binaryID, image.id)
        XCTAssertEqual(record.handoff.mode, "frame")
        XCTAssertEqual(record.handoff.reasonCodes, ["caller_state_mismatch"])
        XCTAssertEqual(record.handoff.sourceName, "AIRS")
        XCTAssertEqual(record.handoff.sourceVersion, "0.1.0")
        XCTAssertEqual(record.handoff.model, "arm64-bounded-loop-calls-v29")
        XCTAssertEqual(record.handoff.requirements, ["Verify selected-slice identity."])
        XCTAssertEqual(record.handoff.displayName, "owned")
        XCTAssertEqual(record.handoff.containerSHA256, digest)
        XCTAssertEqual(record.handoff.sliceOffset, 0)
    }

    func testBoundedReadRequiresRegularFile() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("handoff.json")
        try document().write(to: file)
        XCTAssertEqual(try AIRSHandoffImport.read(from: file).name, "_owned")
        XCTAssertThrowsError(try AIRSHandoffImport.read(from: directory))
        try Data(repeating: 32, count: 1_048_577).write(to: file)
        XCTAssertThrowsError(try AIRSHandoffImport.read(from: file))
    }
}
