import XCTest
@testable import MacScope

final class RegenerationProgressTests: XCTestCase {
    func testEmptyFolderHasThreeIndependentMissingStates() throws {
        let folder = try temporaryFolder()
        defer { try? FileManager.default.removeItem(at: folder) }
        let projection = RegenerationProgressProjection(export: RegenerationExportFolderLoader().load(folder: folder))
        XCTAssertEqual(projection.files.map(\.state), [.notProducedYet, .notProducedYet, .notProducedYet])
        XCTAssertTrue(projection.functions.isEmpty)
        XCTAssertEqual(projection.emptyMessage, "No regeneration export loaded")
    }

    private func temporaryFolder() throws -> URL {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder
    }
}

extension RegenerationProgressTests {
    func testRG1AndMixedDependenciesPreserveExactStateCounts() throws {
        let first = projection("rg1-only")
        XCTAssertEqual(first.stateCounts[.stub], 7)
        XCTAssertEqual(first.functions.count, 7)
        XCTAssertEqual(first.stateCounts[.external], 0)
        XCTAssertEqual(first.files.map(\.state), [.loaded, .notProducedYet, .notProducedYet])
        let mixed = projection("dependencies-mixed")
        XCTAssertEqual(mixed.stateCounts[.external], 1)
        XCTAssertEqual(mixed.dependencyGroups.map(\.confidence), [.confirmed, .probable, .candidate])
        XCTAssertEqual(mixed.dependencyGroups.map { $0.dependencies.reduce(0) { $0 + $1.claimedFunctionCount } }, [1, 0, 0])
        XCTAssertEqual(mixed.functions.first { $0.imageQualifiedAddress == "Demo:0x1050" }?.state, .stub)
        XCTAssertEqual(mixed.functions.first { $0.imageQualifiedAddress == "Demo:0x1060" }?.state, .stub)
        XCTAssertTrue(mixed.findings.isEmpty)
    }

    func testFullExportHasExactFiveStatesAndLanguageMatrix() throws {
        let full = projection("full-export")
        XCTAssertEqual(full.stateCounts, [.stub: 3, .external: 1, .filled: 1, .compiles: 1, .accepted: 1])
        XCTAssertEqual(full.languageCounts, [.c: 3, .objc: 2, .swift: 2])
        let matrix = RegenerationFunctionState.allCases.map { state in
            RegenerationLanguage.allCases.map { full.count(state: state, language: $0) }
        }
        XCTAssertEqual(matrix, [[0, 1, 2], [1, 0, 0], [0, 1, 0], [0, 0, 1], [1, 0, 0]])
        XCTAssertEqual(full.files.map(\.state), [.loaded, .loaded, .loaded])
        XCTAssertEqual(full.dimensions.map(\.dimension), RegenerationDimensionName.allCases)
        XCTAssertEqual(full.dimensions.count, 16)
        XCTAssertEqual(full.resourceStatusCounts, [.copied: 1, .converted: 2, .partial: 1, .refused: 1])
        XCTAssertEqual(full.resourceEquivalenceCounts, [.equal: 1, .different: 1, .notChecked: 1])
        XCTAssertEqual(full.notAttemptedResourceCount, 2)
        XCTAssertEqual(full.functionStates, ["stub": 3, "external": 1, "filled": 1, "compiles": 1, "accepted": 1, "unpaired": 0])
        for dimension in full.dimensions.prefix(14) {
            XCTAssertEqual(dimension.status, .measured)
            XCTAssertEqual(dimension.matched, 99)
            XCTAssertEqual(dimension.missingInRebuilt, 1)
            XCTAssertEqual(dimension.extraInRebuilt, 0)
            XCTAssertEqual(dimension.differing, 0)
            XCTAssertEqual(dimension.score, 0.99)
        }
        let unmeasured = full.dimensions[14]
        XCTAssertEqual(unmeasured.dimension, .swiftEnumCases)
        XCTAssertEqual(unmeasured.status, .notMeasured)
        XCTAssertEqual(unmeasured.notMeasuredReason, "No enum metadata in synthetic input")
        XCTAssertNil(unmeasured.score)
        XCTAssertEqual([unmeasured.matched, unmeasured.missingInRebuilt, unmeasured.extraInRebuilt, unmeasured.differing], [0, 0, 0, 0])
        let functions = full.dimensions[15]
        XCTAssertEqual(functions.dimension, .functions)
        XCTAssertEqual([functions.matched, functions.missingInRebuilt, functions.extraInRebuilt, functions.differing], [1, 3, 1, 2])
        XCTAssertEqual(try XCTUnwrap(functions.score), 1.0 / 7.0, accuracy: 1e-14)
        XCTAssertTrue(full.findings.isEmpty)
    }

    func testRulesProduceNamedFindingsWithoutRepairingRecords() throws {
        for rule in 1...6 {
            let result = projection("rule-\(rule)")
            XCTAssertEqual(Set(result.findings.map(\.code)), ["rule\(rule)"], "fixture rule \(rule)")
        }
        XCTAssertEqual(Set(projection("report-unmatched").findings.map(\.code)), ["reportIdentity"])
        let outside = projection("system-framework-outside")
        XCTAssertTrue(outside.findings.isEmpty)
        XCTAssertEqual(outside.dependencyGroups.flatMap(\.dependencies).first { $0.id == "system-framework" }?.claimedFunctionCount, 0)
    }

    func testDuplicateDependencyIDsRemainUnresolvable() throws {
        let result = projection("duplicate-id")
        XCTAssertEqual(result.stateCounts[.external], 1)
        XCTAssertEqual(result.findings.filter { $0.code == "rule7" }.count, 1)
        XCTAssertEqual(result.findings.filter { $0.code == "rule3" }.count, 1)
        XCTAssertEqual(result.findings.filter { $0.code == "rule6" }.count, 1)
        XCTAssertEqual(Set(result.findings.map(\.code)), ["rule3", "rule6", "rule7"])
    }

    func testInconsistentExternalCountsRecordedStateAndReportsDisagreement() throws {
        let result = projection("rule-3")
        XCTAssertEqual(result.stateCounts, [.stub: 3, .external: 1, .filled: 1, .compiles: 1, .accepted: 1])
        XCTAssertEqual(result.findings.map(\.code), ["rule3"])
        XCTAssertEqual(result.dependencyGroups.flatMap(\.dependencies).reduce(0) { $0 + $1.claimedFunctionCount }, 0)
    }

    func testV1ExternalAndDependencyIDAreFindingsAndRecordsRemainCounted() throws {
        let folder = try copiedFixture("dependencies-mixed")
        defer { try? FileManager.default.removeItem(at: folder) }
        try mutateJSON(folder, file: "REGEN-MANIFEST.json") { $0["schemaVersion"] = 1 }
        let result = RegenerationProgressProjection(export: RegenerationExportFolderLoader().load(folder: folder))
        XCTAssertEqual(result.files[0].state, .loaded)
        XCTAssertEqual(result.functions.count, projection("dependencies-mixed").functions.count)
        XCTAssertEqual(Set(result.findings.map(\.code)), ["manifestV1"])
    }

    func testUnknownEnumAndVersionAreDistinctLoadStatesWithCoordinates() throws {
        let folder = try copiedFixture("full-export")
        defer { try? FileManager.default.removeItem(at: folder) }
        try mutateJSON(folder, file: "REGEN-MANIFEST.json") { object in
            var functions = object["functions"] as! [[String: Any]]
            functions[0]["state"] = "verified"
            object["functions"] = functions
        }
        var result = RegenerationProgressProjection(export: RegenerationExportFolderLoader().load(folder: folder))
        XCTAssertEqual(result.files[0].state, .unsupportedValue(file: "REGEN-MANIFEST.json", field: "$.functions[0].state", value: "verified"))
        XCTAssertEqual(result.files[1].state, .loaded)
        XCTAssertEqual(result.files[2].state, .loaded)
        try mutateJSON(folder, file: "REGEN-MANIFEST.json") { $0["schemaVersion"] = 3 }
        result = RegenerationProgressProjection(export: RegenerationExportFolderLoader().load(folder: folder))
        XCTAssertEqual(result.files[0].state, .unsupportedVersion(file: "REGEN-MANIFEST.json", field: "$.schemaVersion", value: "3"))
    }

    func testTruncationReportsMalformedAndPreservesOtherFiles() throws {
        let folder = try copiedFixture("full-export")
        defer { try? FileManager.default.removeItem(at: folder) }
        try Data(#"{"schemaVersion":2,"functions":["#.utf8).write(to: folder.appendingPathComponent("REGEN-MANIFEST.json"))
        let result = RegenerationProgressProjection(export: RegenerationExportFolderLoader().load(folder: folder))
        guard case let .malformed(file, path, message) = result.files[0].state else { return XCTFail("Expected malformed JSON") }
        XCTAssertEqual(file, "REGEN-MANIFEST.json")
        XCTAssertEqual(path, "$")
        XCTAssertFalse(message.isEmpty)
        XCTAssertEqual(result.files[1].state, .loaded)
        XCTAssertEqual(result.files[2].state, .loaded)
    }

    func testSymlinkEscapeAndOversizeAreSeparateRefusals() throws {
        let folder = try temporaryFolder()
        let outside = try temporaryFolder()
        defer {
            try? FileManager.default.removeItem(at: folder)
            try? FileManager.default.removeItem(at: outside)
        }
        let target = outside.appendingPathComponent("manifest.json")
        try Data("{}".utf8).write(to: target)
        let linked = folder.appendingPathComponent("REGEN-MANIFEST.json")
        try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: target)
        var result = RegenerationProgressProjection(export: RegenerationExportFolderLoader().load(folder: folder))
        guard case .refusedSymlink = result.files[0].state else { return XCTFail("Expected escaping symlink refusal") }
        try FileManager.default.removeItem(at: linked)
        try Data("12345".utf8).write(to: linked)
        result = RegenerationProgressProjection(export: RegenerationExportFolderLoader(maximumFileBytes: 4).load(folder: folder))
        XCTAssertEqual(result.files[0].state, .refusedOversize(file: "REGEN-MANIFEST.json", bytes: 5, limit: 4))
    }

    func testDirectoryAtFilePathIsUnreadableWithoutBlockingOtherFiles() throws {
        let folder = try temporaryFolder()
        defer { try? FileManager.default.removeItem(at: folder) }
        try FileManager.default.createDirectory(at: folder.appendingPathComponent("DEPENDENCIES.json"), withIntermediateDirectories: false)
        let result = RegenerationProgressProjection(export: RegenerationExportFolderLoader().load(folder: folder))
        guard case .unreadable = result.files[1].state else { return XCTFail("Expected unreadable directory") }
        XCTAssertEqual(result.files[0].state, .notProducedYet)
        XCTAssertEqual(result.files[2].state, .notProducedYet)
    }

    func testFullSliceIdentityAloneAllowsNavigation() throws {
        let export = RegenerationExportFolderLoader().load(folder: fixture("full-export"))
        let uuid = "00000000-0000-0000-0000-000000000001"
        let hash = String(repeating: "a", count: 64)
        let full = RegenerationProgressProjection(export: export, openImages: [.init(imageName: "Demo", uuid: uuid, sliceSha256: hash)])
        let function = try XCTUnwrap(full.functions.first)
        XCTAssertTrue(full.navigation(for: function).canNavigate)
        XCTAssertEqual(full.navigation(for: function).status, .fullMatch)
        let wrong = RegenerationProgressProjection(export: export, openImages: [.init(imageName: "Demo", uuid: uuid, sliceSha256: String(repeating: "b", count: 64))])
        XCTAssertFalse(wrong.navigation(for: function).canNavigate)
        XCTAssertEqual(wrong.navigation(for: function).status, .mismatch)
        XCTAssertTrue(wrong.navigation(for: function).reason.contains("slice SHA-256"))
        let uuidOnly = RegenerationProgressProjection(export: export, openImages: [.init(imageName: "Demo", uuid: uuid, sliceSha256: nil)])
        XCTAssertFalse(uuidOnly.navigation(for: function).canNavigate)
        XCTAssertEqual(uuidOnly.navigation(for: function).status, .uuidOnly)
        XCTAssertTrue(uuidOnly.navigation(for: function).reason.contains("UUID-only"))
        XCTAssertFalse(RegenerationProgressProjection(export: export).navigation(for: function).canNavigate)
    }

    func testProjectionIsEqualAcrossLoadsAndPermutedRecordOrder() throws {
        let folder = try copiedFixture("full-export")
        defer { try? FileManager.default.removeItem(at: folder) }
        let loader = RegenerationExportFolderLoader()
        let first = RegenerationProgressProjection(export: loader.load(folder: folder))
        XCTAssertEqual(first, RegenerationProgressProjection(export: loader.load(folder: folder)))
        try mutateJSON(folder, file: "REGEN-MANIFEST.json") { object in
            object["functions"] = (object["functions"] as! [[String: Any]]).reversed().map { $0 }
            object["resources"] = (object["resources"] as! [[String: Any]]).reversed().map { $0 }
        }
        try mutateJSON(folder, file: "DEPENDENCIES.json") { object in
            object["dependencies"] = (object["dependencies"] as! [[String: Any]]).reversed().map { $0 }
        }
        try mutateJSON(folder, file: "Equivalence/STRUCTURE-REPORT.json") { object in
            object["dimensions"] = (object["dimensions"] as! [[String: Any]]).reversed().map { $0 }
        }
        XCTAssertEqual(first, RegenerationProgressProjection(export: loader.load(folder: folder)))
    }

    func testHundredThousandFunctionsProjectAndPageWithoutDroppingRows() throws {
        let folder = try copiedFixture("rg1-only")
        defer { try? FileManager.default.removeItem(at: folder) }
        try mutateJSON(folder, file: "REGEN-MANIFEST.json") { object in
            let template = (object["functions"] as! [[String: Any]])[0]
            object["functions"] = (0..<100_000).map { index -> [String: Any] in
                var function = template
                function["imageQualifiedAddress"] = "Demo:0x" + String(index + 0x1000, radix: 16)
                function["functionUUID"] = "generated-\(index)"
                function["name"] = "scale_\(index)"
                function["language"] = index.isMultiple(of: 2) ? "c" : "swift"
                return function
            }
        }
        let result = RegenerationProgressProjection(export: RegenerationExportFolderLoader().load(folder: folder))
        XCTAssertEqual(result.functions.count, 100_000)
        XCTAssertEqual(result.stateCounts[.stub], 100_000)
        XCTAssertEqual(result.page().functions.count, 500)
        XCTAssertEqual(result.page().pageCount, 200)
        XCTAssertEqual(result.page(pageIndex: 199).functions.count, 500)
        XCTAssertEqual(result.page(state: .stub, language: .swift).totalCount, 50_000)
        XCTAssertEqual(result.page(state: .accepted).totalCount, 0)
        XCTAssertEqual(result.page(search: "scale_99999").functions.map(\.name), ["scale_99999"])
        XCTAssertEqual(result.page(search: "Demo:0x1969f").functions.count, 1)
        XCTAssertTrue(result.findings.isEmpty)
    }

    func testMemoMatchesDirectConstructionForExistingFixturesAndNavigation() throws {
        let memo = RegenerationProjectionMemo()
        let empty = memo.projection(export: .empty, openImages: [])
        XCTAssertEqual(empty, RegenerationProgressProjection(export: .empty))
        XCTAssertEqual(empty.emptyMessage, "No regeneration export loaded")
        XCTAssertTrue(empty.functions.isEmpty)
        for name in ["full-export", "rg1-only", "report-unmatched", "dependencies-mixed",
                     "system-framework-outside", "duplicate-id"] + (1...6).map({ "rule-\($0)" }) {
            let export = RegenerationExportFolderLoader().load(folder: fixture(name))
            let result = memo.projection(export: export, openImages: [])
            XCTAssertEqual(result, projection(name))
            if name == "rg1-only" {
                XCTAssertEqual(result.functions.count, 7)
                XCTAssertEqual(result.stateCounts[.stub], 7)
            }
            if name == "report-unmatched" {
                XCTAssertEqual(Set(result.findings.map(\.code)), ["reportIdentity"])
            }
        }
        let export = RegenerationExportFolderLoader().load(folder: fixture("full-export"))
        let uuid = "00000000-0000-0000-0000-000000000001"
        let cases: [(String?, RegenerationNavigation.Status, Bool)] = [
            (String(repeating: "a", count: 64), .fullMatch, true),
            (String(repeating: "b", count: 64), .mismatch, false),
            (nil, .uuidOnly, false),
        ]
        for (hash, status, allowed) in cases {
            let images = [RegenerationOpenImage(imageName: "Demo", uuid: uuid, sliceSha256: hash)]
            let result = memo.projection(export: export, openImages: images)
            XCTAssertEqual(result, RegenerationProgressProjection(export: export, openImages: images))
            XCTAssertEqual(result.stateCounts, [.stub: 3, .external: 1, .filled: 1, .compiles: 1, .accepted: 1])
            let function = try XCTUnwrap(result.functions.first)
            XCTAssertEqual(result.navigation(for: function).status, status)
            XCTAssertEqual(result.navigation(for: function).canNavigate, allowed)
        }
    }

    func testMemoBuildsOncePerConsecutiveValueInput() {
        let memo = RegenerationProjectionMemo()
        for _ in 0..<5 {
            XCTAssertEqual(memo.projection(export: .empty, openImages: []), RegenerationProgressProjection(export: .empty))
        }
        XCTAssertEqual(memo.buildCount, 1)
        var changed = RegenerationLoadedExport.empty
        changed.files[0] = RegenerationExportFile(name: "REGEN-MANIFEST.json",
                                                  state: .unsupportedVersion(file: "REGEN-MANIFEST.json", field: "$.schemaVersion", value: "3"))
        let next = memo.projection(export: changed, openImages: [])
        XCTAssertEqual(next, RegenerationProgressProjection(export: changed))
        XCTAssertEqual(next.files[0].state, .unsupportedVersion(file: "REGEN-MANIFEST.json", field: "$.schemaVersion", value: "3"))
        XCTAssertEqual(memo.buildCount, 2)
        let images = [RegenerationOpenImage(imageName: "Demo", uuid: "id", sliceSha256: "new-slice")]
        XCTAssertEqual(memo.projection(export: changed, openImages: images),
                       RegenerationProgressProjection(export: changed, openImages: images))
        XCTAssertEqual(memo.buildCount, 3)
        XCTAssertEqual(memo.projection(export: .empty, openImages: []), RegenerationProgressProjection(export: .empty))
        XCTAssertEqual(memo.buildCount, 4) // Single-entry, not a history of previously seen inputs.
    }

    func testMemoRejectsEqualCountExportReplacementAndImageReordering() {
        let memo = RegenerationProjectionMemo()
        var first = RegenerationLoadedExport.empty
        first.files[0] = RegenerationExportFile(name: "first.json", state: .notProducedYet)
        var second = first
        second.files[0] = RegenerationExportFile(name: "second.json", state: .notProducedYet)
        XCTAssertNotEqual(first, second)
        XCTAssertEqual(first.files.count, second.files.count)
        let old = memo.projection(export: first, openImages: [])
        let current = memo.projection(export: second, openImages: [])
        XCTAssertEqual(old.functions.count, current.functions.count)
        XCTAssertNotEqual(old, current)
        XCTAssertEqual(current.files[0].name, "second.json")
        XCTAssertEqual(current, RegenerationProgressProjection(export: second))
        XCTAssertEqual(memo.buildCount, 2)
        let a = RegenerationOpenImage(imageName: "A", uuid: "same", sliceSha256: nil)
        let b = RegenerationOpenImage(imageName: "B", uuid: "same", sliceSha256: nil)
        let ordered = memo.projection(export: second, openImages: [a, b])
        let reversed = memo.projection(export: second, openImages: [b, a])
        XCTAssertNotEqual(ordered, reversed)
        XCTAssertEqual(reversed.openImages.map(\.imageName), ["B", "A"])
        XCTAssertEqual(reversed, RegenerationProgressProjection(export: second, openImages: [b, a]))
        XCTAssertEqual(memo.buildCount, 4)
    }

    private func fixture(_ name: String) -> URL {
        TestSourceRoot.url.appendingPathComponent("MacScope/Tests/CoreTests/Resources/RegenerationFixtures/RegenerationFixtures.bundle/\(name)")
    }

    private func projection(_ name: String) -> RegenerationProgressProjection {
        RegenerationProgressProjection(export: RegenerationExportFolderLoader().load(folder: fixture(name)))
    }

    private func copiedFixture(_ name: String) throws -> URL {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.copyItem(at: fixture(name), to: folder)
        return folder
    }

    private func mutateJSON(_ folder: URL, file: String, mutation: (inout [String: Any]) -> Void) throws {
        let url = folder.appendingPathComponent(file)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        mutation(&object)
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: url)
    }
}
