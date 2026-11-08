import Foundation
import XCTest
@testable import MacScope

final class RegenerationDependencyInventoryTests: XCTestCase {
    private let identity = RegenerationImageIdentity(imageSlot: 0, selectedSliceIndex: nil,
        architecture: "arm64", selectedSliceSHA256: String(repeating: "a", count: 64),
        analysisFingerprintSHA256: String(repeating: "b", count: 64))

    func testUnresolvedRpathAndSpoofedSystemPathNeverBecomeConfirmed() {
        let loads = [DependencyLoad(path: "@rpath/F.framework/F", kind: "weak", currentVersion: "4", compatibilityVersion: "2"),
                     DependencyLoad(path: "/System/Library/../../tmp/not-system.dylib", kind: "required", currentVersion: "1", compatibilityVersion: "1")]
        let inventory = DependencyInventoryBuilder.build(image: identity, loads: loads, frameworks: [], diagnostics: [])
        XCTAssertEqual(inventory.dependencies.count, 2)
        XCTAssertTrue(inventory.dependencies.allSatisfy { $0.confidence == "candidate" && $0.functions.isEmpty && $0.emitAs == "none" })
        XCTAssertTrue(inventory.dependencies.contains { $0.evidence.first?.detail == "load kind: weak" })
    }

    func testFrameworkVersionsAndUnknownPackageVersionRemainDistinct() throws {
        let framework = DependencyFramework(path: "Contents/Frameworks/F.framework", identifier: "example.F",
                                            releaseVersion: "2.1", buildVersion: "45")
        let result = DependencyInventoryBuilder.build(image: identity, loads: [], frameworks: [framework], diagnostics: [])
        let item = try XCTUnwrap(result.dependencies.first)
        XCTAssertEqual(item.version, "2.1")
        XCTAssertEqual(item.bundleBuildVersion, "45")
        XCTAssertNil(item.versionRange)
        XCTAssertNil(item.dylibCurrentVersion)
        let data = try JSONEncoder().encode(result)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let rows = try XCTUnwrap(json["dependencies"] as? [[String: Any]])
        XCTAssertTrue(rows[0]["versionRange"] is NSNull)
    }

    func testModuleHintsAreProbableWithoutFunctionOwnership() {
        let entry = KnownDependency(name: "swift-log", modules: ["Logging"], bundleIDs: [],
            sourceURL: "https://github.com/apple/swift-log/blob/main/Package.swift",
            packageURL: "https://github.com/apple/swift-log", license: "Apache-2.0",
            licenseURL: "https://github.com/apple/swift-log/blob/main/LICENSE.txt")
        let table = KnownDependencyTable(schemaVersion: 1, dependencies: [entry])
        let report = ModuleAwareInventory.build(image: identity, loads: [], frameworks: [], modules: ["Logging", "Logging"], table: table, diagnostics: [])
        XCTAssertEqual(report.dependencies.count, 1)
        XCTAssertEqual(report.dependencies.first?.confidence, "probable")
        XCTAssertEqual(report.dependencies.first?.functions, [])
        XCTAssertEqual(report.dependencies.first?.emitAs, "none")
        XCTAssertEqual(report.dependencies.first?.evidence.first?.location, "selected image: Swift metadata")
        XCTAssertTrue(report.dependencies.first?.evidence.first?.detail.contains(entry.sourceURL) == true)
    }

    func testInventoryOrderingDoesNotDependOnObservationOrder() throws {
        let a = DependencyLoad(path: "/usr/lib/libA.dylib", kind: "required", currentVersion: "1", compatibilityVersion: "1")
        let b = DependencyLoad(path: "@rpath/B", kind: "weak", currentVersion: "2", compatibilityVersion: "1")
        let left = DependencyInventoryBuilder.build(image: identity, loads: [a, b], frameworks: [], diagnostics: ["z", "a"])
        let right = DependencyInventoryBuilder.build(image: identity, loads: [b, a], frameworks: [], diagnostics: ["a", "z"])
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        XCTAssertEqual(try encoder.encode(left), try encoder.encode(right))
    }

    func testBoundedInventoryStopsWhenAmbiguousCandidatesExceedRecordLimit() throws {
        let entries = ["First", "Second"].map { name in
            KnownDependency(name: name, modules: ["Shared"], bundleIDs: [], sourceURL: name,
                            packageURL: name, license: "", licenseURL: "")
        }
        let budget = try RegenerationWorkBudget(deadlineUptimeNanoseconds: UInt64.max, maximumRecords: 1)
        XCTAssertThrowsError(try ModuleAwareInventory.buildBounded(image: identity, loads: [], frameworks: [],
            modules: ["Shared"], table: .init(schemaVersion: 1, dependencies: entries), diagnostics: [], budget: budget)) {
            XCTAssertEqual($0 as? RegenerationWorkBudgetError, .recordLimitExceeded)
        }
    }

    func testBoundedInventoryRejectsExpiredWork() throws {
        let budget = try RegenerationWorkBudget(deadlineUptimeNanoseconds: 1)
        XCTAssertThrowsError(try ModuleAwareInventory.buildBounded(image: identity, loads: [], frameworks: [],
            modules: ["Shared"], table: .init(schemaVersion: 1, dependencies: []), diagnostics: [], budget: budget)) {
            XCTAssertEqual($0 as? RegenerationWorkBudgetError, .deadlineExceeded)
        }
    }

}
