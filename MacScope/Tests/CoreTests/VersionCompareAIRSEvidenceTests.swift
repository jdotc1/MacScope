import Foundation
import XCTest
@testable import MacScope

/// Authored values only: no binary admission, file I/O or provenance verification.
enum VersionCompareAIRSFixture {
    static let workspace = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
    static func report(_ verdicts: [String] = ["agreement"], model: String = "fixture-v1",
                       subtype: Int32 = 0, named: Bool = true) throws -> UnwindAuditReport {
        let identity = try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: 0x0100000c,
            rawCPUSubtype: subtype, selectedSliceSHA256: String(repeating: "a", count: 64),
            selectedSliceByteCount: 4096)
        let findings = verdicts.enumerated().map { index, verdict in
            let address = UInt64(0x1000 + index * 0x40)
            return UnwindAuditFinding(identity: identity,
                function: .init(id: "f\(index)", address: address,
                    symbolName: named ? "_owned\(index)" : nil, size: 0x40),
                endAddress: address + 0x40, verdict: verdict, coverage: "compact",
                mode: "frameless", scope: "fixture_scope", reasonCodes: ["fixture_reason"],
                checkedPCs: [address], evidence: [.init(code: "fixture", message: "Original evidence")],
                limitations: ["Synthetic observation"], instructionCount: 16)
        }
        return .init(identity: identity, analysisModelVersion: model, findings: findings)
    }

    static func record(_ report: UnwindAuditReport, id: UUID = UUID()) throws -> AIRSEvidenceRecord {
        .init(id: id, workspaceID: workspace, source: .nativeUnwind, sourceImageID: UUID(),
              nativeRequestID: UUID(), createdAt: Date(timeIntervalSince1970: 1),
              rawPayload: try JSONEncoder().encode(report))
    }

    static func imported() throws -> AIRSEvidenceRecord {
        let digest = String(repeating: "a", count: 64)
        let object: [String: Any] = [
            "schema_version": 1, "report_kind": "airs.macscope_handoff",
            "integration_status": "proposed_export_contract",
            "image": ["display_name": "authored", "architecture": "arm64", "cpu_subtype": 0,
                      "container_sha256": digest, "slice_sha256": digest, "slice_offset": 0,
                      "slice_size": 4096, "uuid": NSNull(), "preferred_base": "0x1000"],
            "selection": ["finding_id": "airsf-" + digest, "function_name": "_authored",
                          "address_space": "preferred_vm", "vm_range": ["start": "0x1010", "end": "0x1020"],
                          "image_relative_range": ["start": "0x10", "end": "0x20"]],
            "finding": ["verdict": "unresolved", "coverage": "none", "mode": "unknown",
                        "reason_codes": ["unsupported"], "scope": "metadata_only",
                        "checked_pcs": ["0x1010"], "evidence": [], "limitations": ["Authored fixture"]],
            "source_analysis": ["name": "AIRS", "version": "fixture", "analysis_model_version": "fixture-v1"],
            "requirements": ["Verify identity"]
        ]
        return .init(id: UUID(), workspaceID: workspace, source: .importedHandoff,
            sourceImageID: nil, nativeRequestID: nil, createdAt: Date(timeIntervalSince1970: 1),
            rawPayload: try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
    }
}

final class VersionCompareAIRSEvidenceTests: XCTestCase {
    func testUnresolvedBindingsSortBeforeResolvedAndRecomputeWithoutChangingEvidence() throws {
        let firstID = try XCTUnwrap(UUID(uuidString: "00000000-0000-0000-0000-000000000010"))
        let secondID = try XCTUnwrap(UUID(uuidString: "00000000-0000-0000-0000-000000000011"))
        let thirdID = try XCTUnwrap(UUID(uuidString: "00000000-0000-0000-0000-000000000012"))
        let report = try VersionCompareAIRSFixture.report()
        let records = try [thirdID, firstID, secondID].map { try VersionCompareAIRSFixture.record(report, id: $0) }
        let inventory = try VersionCompareAIRSEvidenceInventory.build(.init(records: records),
            workspaceID: VersionCompareAIRSFixture.workspace)
        XCTAssertEqual(inventory.orderedEntries { $0.id == firstID }.map(\.id), [secondID, thirdID, firstID])
        XCTAssertEqual(inventory.orderedEntries { _ in true }.map(\.id), [firstID, secondID, thirdID])
        XCTAssertEqual(inventory.orderedEntries { _ in false }.map(\.id), [firstID, secondID, thirdID])
        XCTAssertEqual(inventory.entries.map(\.record), records.sorted { $0.id.uuidString < $1.id.uuidString })
    }

    func testInventoryPreservesSourceBytesAndEveryVerdictIncludingZeroDenominator() throws {
        let populated = try VersionCompareAIRSFixture.record(.init(
            identity: VersionCompareAIRSFixture.report().identity,
            analysisModelVersion: "historical-model",
            findings: VersionCompareAIRSFixture.report(["agreement", "unresolved", "inconsistency"]).findings))
        let empty = try VersionCompareAIRSFixture.record(VersionCompareAIRSFixture.report([]))
        let envelope = AIRSEvidenceEnvelope(records: [populated, empty])
        let inventory = try VersionCompareAIRSEvidenceInventory.build(envelope, workspaceID: VersionCompareAIRSFixture.workspace)
        let first = try XCTUnwrap(inventory.entries.first { $0.id == populated.id })
        XCTAssertEqual(first.record, populated)
        XCTAssertEqual(first.report?.analysisModelVersion, "historical-model")
        XCTAssertEqual(first.coverage, .init(total: 3, agreement: 1, inconsistency: 1, unresolved: 1))
        XCTAssertEqual(first.orderedFindings.map(\.verdict), ["unresolved", "inconsistency", "agreement"])
        let zero = try XCTUnwrap(inventory.entries.first { $0.id == empty.id })
        XCTAssertEqual(zero.coverage, .init(total: 0, agreement: 0, inconsistency: 0, unresolved: 0))
        XCTAssertEqual(envelope.records, [populated, empty])
    }

    func testImportedSingleFindingIsInventoriedButNeverBecomesNativeReport() throws {
        let imported = try VersionCompareAIRSFixture.imported()
        let native = try VersionCompareAIRSFixture.record(VersionCompareAIRSFixture.report())
        let inventory = try VersionCompareAIRSEvidenceInventory.build(.init(records: [native, imported]),
            workspaceID: VersionCompareAIRSFixture.workspace)
        XCTAssertEqual(inventory.entries.count, 2)
        XCTAssertEqual(inventory.nativeEntries.map(\.id), [native.id])
        let entry = try XCTUnwrap(inventory.entries.first { $0.id == imported.id })
        XCTAssertNil(entry.report)
        XCTAssertNil(entry.coverage)
        XCTAssertEqual(entry.importedVerdict, "unresolved")
        XCTAssertEqual(entry.record.rawPayload, imported.rawPayload)
    }

    func testMalformedIrrelevantRecordAndWrongWorkspaceRefuseWholeInventory() throws {
        let valid = try VersionCompareAIRSFixture.record(VersionCompareAIRSFixture.report())
        for source in [AIRSEvidenceRecord.Source.nativeUnwind, .importedHandoff] {
            let bad = AIRSEvidenceRecord(id: UUID(), workspaceID: VersionCompareAIRSFixture.workspace,
                source: source, sourceImageID: UUID(),
                nativeRequestID: source == .nativeUnwind ? UUID() : nil,
                createdAt: Date(), rawPayload: Data("{}".utf8))
            XCTAssertThrowsError(try VersionCompareAIRSEvidenceInventory.build(.init(records: [valid, bad]),
                workspaceID: VersionCompareAIRSFixture.workspace))
        }
        XCTAssertThrowsError(try VersionCompareAIRSEvidenceInventory.build(.init(records: [valid]), workspaceID: UUID())) {
            XCTAssertEqual($0 as? AIRSEvidenceError, .wrongWorkspace)
        }
    }

    func testEveryConfigurationLimitMismatchPreservesEvidenceAndRefusesSameVerdict() throws {
        let original = try VersionCompareAIRSFixture.report(["agreement", "unresolved", "inconsistency"])
        let limits: [WritableKeyPath<UnwindAuditLimits, Int>] = [
            \.maxInstructions, \.maxSteps, \.maxPaths, \.maxObservations, \.maxEvidence
        ]
        for limit in limits {
            var current = original
            current.configuration[keyPath: limit] += 1
            let before = try VersionCompareAIRSFixture.record(original)
            let after = try VersionCompareAIRSFixture.record(current)
            let inventory = try VersionCompareAIRSEvidenceInventory.build(.init(records: [before, after]),
                workspaceID: VersionCompareAIRSFixture.workspace)
            let result = try UnwindAuditComparator.compare(baseline: original, current: current)
            XCTAssertTrue(result.modelCompatible)
            XCTAssertTrue(result.configurationChanged)
            XCTAssertEqual(result.changes.map(\.change), [.incompatible, .incompatible, .incompatible])
            XCTAssertEqual(result.changes.map(\.beforeVerdict), ["agreement", "unresolved", "inconsistency"])
            XCTAssertEqual(result.changes.map(\.afterVerdict), result.changes.map(\.beforeVerdict))
            XCTAssertEqual(result.baselineIdentity, original.identity)
            XCTAssertEqual(result.currentIdentity, current.identity)
            XCTAssertEqual(inventory.entries.first { $0.id == before.id }?.record, before)
            XCTAssertEqual(inventory.entries.first { $0.id == after.id }?.record, after)
            for entry in inventory.nativeEntries {
                XCTAssertEqual(entry.coverage, .init(total: 3, agreement: 1, inconsistency: 1, unresolved: 1))
            }
        }
    }

    func testMatchingPartitionsAndIncompatibleReportsKeepBothCoverageDenominators() throws {
        let old = try VersionCompareAIRSFixture.report(["unresolved", "agreement"], named: false)
        let new = try VersionCompareAIRSFixture.report(["inconsistency"], model: "different", named: false)
        let result = try UnwindAuditComparator.compare(baseline: old, current: new)
        XCTAssertFalse(result.modelCompatible)
        XCTAssertEqual(result.matching.removedIDs, ["f0", "f1"])
        XCTAssertEqual(result.matching.addedIDs, ["f0"])
        XCTAssertEqual(VersionCompareAIRSCoverage(old), .init(total: 2, agreement: 1, inconsistency: 0, unresolved: 1))
        XCTAssertEqual(VersionCompareAIRSCoverage(new), .init(total: 1, agreement: 0, inconsistency: 1, unresolved: 0))
        XCTAssertTrue(result.changes.isEmpty)
    }
}
