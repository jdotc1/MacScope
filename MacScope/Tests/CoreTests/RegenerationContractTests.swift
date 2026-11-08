import CryptoKit
import Foundation
import XCTest

final class RegenerationContractTests: XCTestCase {
    private let resourceRoot = TestSourceRoot.url.appendingPathComponent("MacScope/Tests/CoreTests/Resources")

    func testFrozenSchemaCopiesHaveExpectedDigests() throws {
        let expected = [
            "regen-manifest.v2.schema.json": "1b8bca65a23a9042c66482f4b9b1d6d504e83019c532ba062e399d816271e5f0",
            "dependencies.v1.schema.json": "dc1cca47bd84b6870738890995129da94673bb7384d94f22edb31cef1b3f856d",
            "structure-report.v1.schema.json": "8eec3e157ca6247938c8e6e9bc2dda8493360f7528d08d4b0a5e80ca859e5e1c",
        ]
        for name in expected.keys.sorted() {
            let data = try Data(contentsOf: resourceRoot.appendingPathComponent("RegenerationContracts/" + name))
            let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            XCTAssertEqual(actual, expected[name], name)
        }
    }

    func testEveryCheckedInFixtureFileValidatesAgainstItsFrozenSchema() throws {
        let root = resourceRoot.appendingPathComponent("RegenerationFixtures/RegenerationFixtures.bundle")
        let mapping = ["REGEN-MANIFEST.json": "regen-manifest.v2.schema.json",
                       "DEPENDENCIES.json": "dependencies.v1.schema.json",
                       "STRUCTURE-REPORT.json": "structure-report.v1.schema.json"]
        let enumerator = try XCTUnwrap(FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil))
        let files = enumerator.compactMap { $0 as? URL }.filter { $0.pathExtension == "json" }.sorted { $0.path < $1.path }
        XCTAssertEqual(files.count, 33)
        for file in files {
            let name = try XCTUnwrap(mapping[file.lastPathComponent])
            let schema = try Data(contentsOf: resourceRoot.appendingPathComponent("RegenerationContracts/" + name))
            XCTAssertNoThrow(try RegenerationContractValidator.validate(Data(contentsOf: file), schema: schema), file.path)
        }
    }

    func testTypeArraysAndNullDoNotConfuseBooleanWithInteger() throws {
        let schema = #"{"type":["integer","null"]}"#
        try validate("null", schema)
        try validate("4", schema)
        assertRejected("true", schema, path: "$")
        assertRejected("4.5", schema, path: "$")
        assertRejected(#""4""#, schema, path: "$")
        try validate("true", #"{"type":"boolean"}"#)
        assertRejected("1", #"{"type":"boolean"}"#, path: "$")
        try validate("1.25", #"{"type":"number"}"#)
    }

    func testEnumAndConstUseJSONValueEquality() throws {
        try validate(#""stub""#, #"{"enum":["stub","external"]}"#)
        assertRejected(#""verified""#, #"{"enum":["stub","external"]}"#, path: "$")
        try validate("2", #"{"const":2}"#)
        assertRejected("3", #"{"const":2}"#, path: "$")
        assertRejected("true", #"{"const":1}"#, path: "$")
    }

    func testRequiredPropertiesAndArrayItemsReportFirstJSONPath() throws {
        let schema = #"{"type":"object","required":["records"],"properties":{"records":{"type":"array","items":{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}}}}"#
        try validate(#"{"records":[{"name":"one","unknown":42}],"extra":true}"#, schema)
        assertRejected("{}", schema, path: "$.records")
        assertRejected(#"{"records":[{"name":4}]}"#, schema, path: "$.records[0].name")
        assertRejected(#"{"records":{}}"#, schema, path: "$.records")
    }

    func testPatternAndArrayBoundsAreEnforced() throws {
        let schema = #"{"type":"array","minItems":1,"maxItems":2,"items":{"type":"string","pattern":"^[^:]+:0x[0-9a-f]+$"}}"#
        try validate(#"["Demo:0x10"]"#, schema)
        assertRejected("[]", schema, path: "$")
        assertRejected(#"["Demo:0x1","Demo:0x2","Demo:0x3"]"#, schema, path: "$")
        assertRejected(#"["Demo:0xAB"]"#, schema, path: "$[0]")
    }

    func testLocalDefinitionsAndConditionalBranches() throws {
        let schema = ##"{"$defs":{"row":{"type":"object","required":["external"],"allOf":[{"if":{"properties":{"external":{"const":true}},"required":["external"]},"then":{"required":["dependencyId"],"properties":{"dependencyId":{"type":"string"}}},"else":{"properties":{"dependencyId":{"type":"null"}}}}]}},"type":"array","items":{"$ref":"#/$defs/row"}}"##
        try validate(#"[{"external":true,"dependencyId":"dep"},{"external":false,"dependencyId":null}]"#, schema)
        assertRejected(#"[{"external":true}]"#, schema, path: "$[0].dependencyId")
        assertRejected(#"[{"external":false,"dependencyId":"dep"}]"#, schema, path: "$[0].dependencyId")
    }

    func testNotRequiredRejectsEvenANullProperty() throws {
        let schema = #"{"type":"object","not":{"required":["dependencyId"]}}"#
        try validate("{}", schema)
        assertRejected(#"{"dependencyId":null}"#, schema, path: "$")
    }

    func testFormatIsAnnotationOnly() throws {
        try validate(#""synthetic date""#, #"{"type":"string","format":"date-time"}"#)
    }

    func testFrozenManifestRejectsV1ExternalAndV1DependencyId() throws {
        let schema = try Data(contentsOf: resourceRoot.appendingPathComponent("RegenerationContracts/regen-manifest.v2.schema.json"))
        let url = resourceRoot.appendingPathComponent("RegenerationFixtures/RegenerationFixtures.bundle/full-export/REGEN-MANIFEST.json")
        var manifest = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        manifest["schemaVersion"] = 1
        XCTAssertThrowsError(try RegenerationContractValidator.validate(JSONSerialization.data(withJSONObject: manifest), schema: schema))
        var functions = try XCTUnwrap(manifest["functions"] as? [[String: Any]])
        functions = functions.filter { ($0["state"] as? String) != "external" }
        functions[0]["dependencyId"] = NSNull()
        manifest["functions"] = functions
        XCTAssertThrowsError(try RegenerationContractValidator.validate(JSONSerialization.data(withJSONObject: manifest), schema: schema))
    }

    private func validate(_ json: String, _ schema: String) throws {
        try RegenerationContractValidator.validate(Data(json.utf8), schema: Data(schema.utf8))
    }

    private func assertRejected(_ json: String, _ schema: String, path: String,
                                file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try validate(json, schema), file: file, line: line) { error in
            XCTAssertEqual((error as? RegenerationContractValidator.Failure)?.path, path, file: file, line: line)
        }
    }
}
