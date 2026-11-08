import XCTest
#if canImport(MacScope)
@testable import MacScope

final class SwiftOutcomeWitnessV1Tests: XCTestCase {
    private let call: SwiftOutcomeJSON = .object(["call_pc": .string("0x1000"), "test_pc": .string("0x1004"), "success_pc": .string("0x1008"), "error_pc": .string("0x100c"), "error_region": .object(["join_pc": .string("0x1010"), "instructions": .array([.object(["pc": .string("0x100c")])]), "success_interval": .object(["instructions": .array([.object(["pc": .string("0x1008")])])])])])
    func testVB01SourceModels() throws {
        let expected: SwiftOutcomeJSON = .object(["edge": .string("swift-sync-error-edges-v37"), "return_choice": .string("swift-return-choice-v45"), "region": .string("swift-sync-error-region-v24"), "incoming": .string("swift-region-direct-entries-v7"), "presentation": .string("swift-structural-presentation-v10"), "success_result": .string("swift-success-result-v24"), "success_constant": .string("swift-success-constant-v17"), "error_constant": .string("swift-error-constant-v19"), "flag_entry": .string("swift-compare-flag-entries-v1")])
        XCTAssertEqual(try sourceModels("legacy"), expected)
        var methods = expected; methods["edge"] = .string("swift-sync-error-edges-v38"); methods["return_choice"] = .string("swift-return-choice-v46"); methods["declaration"] = .string("swift-throwing-declarations-v1")
        XCTAssertEqual(try sourceModels("methods"), methods)
    }
    func testVB02UnknownProfile() {
        let value = buildOutcomeWitness(image: SwiftOutcomeImage(SwiftOutcomeTestFixture.request()), function: SwiftOutcomeTestFixture.caller, call: call, modelProfile: "future")
        let expected: SwiftOutcomeJSON = .object(["schema_version": .integer(1), "model_version": .string("swift-outcome-witness-v1"), "validation_model_version": .string("swift-outcome-validation-v1"), "source_reconstruction_allowed": .bool(false), "call_return_proven": .bool(false), "runtime_branch_proven": .bool(false), "handler_semantics_proven": .bool(false), "status": .string("unresolved"), "reason": .string("witness_input"), "details_complete": .bool(false)])
        XCTAssertEqual(value, expected)
    }
    func testVB03GraphAndIdentity() {
        let value = buildOutcomeWitness(image: SwiftOutcomeImage(SwiftOutcomeTestFixture.request()), function: SwiftOutcomeTestFixture.caller, call: call)
        XCTAssertEqual(value["status"], SwiftOutcomeJSON.string("unresolved")); XCTAssertEqual(value["reason"], SwiftOutcomeJSON.string("validation_required"))
        XCTAssertEqual(value["witness_id"], SwiftOutcomeJSON.string("swift-outcome-witness-v1:" + String(repeating: "ab", count: 32) + ":0x1000:0x1000"))
        let nodes: SwiftOutcomeJSON = .array([.object(["id": .string("call"), "pc": .string("0x1000")]), .object(["id": .string("test"), "pc": .string("0x1004")]), .object(["id": .string("success"), "pc": .string("0x1008")]), .object(["id": .string("error"), "pc": .string("0x100c")]), .object(["id": .string("join"), "pc": .string("0x1010")])])
        XCTAssertEqual(value["graph"]["nodes"], nodes)
        let expected: [SwiftOutcomeJSON] = [.array([.string("call"), .string("test"), .string("0x1000")]), .array([.string("test"), .string("success"), .string("0x1004")]), .array([.string("test"), .string("error"), .string("0x1004")]), .array([.string("error"), .string("join"), .string("0x100c")]), .array([.string("success"), .string("join"), .string("0x1008")])]
        XCTAssertEqual(value["graph"]["edges"].array!.map { .array([$0["from"], $0["to"], $0["provenance_pc"]]) }, expected)
        for edge in value["graph"]["edges"].array! { XCTAssertEqual(edge["relationship"], SwiftOutcomeJSON.string("recorded_structural")) }
        XCTAssertEqual(value["accounting"], SwiftOutcomeJSON.object(["nodes": .integer(5), "edges": .integer(5)]))
    }
    func testVB04BoundedCopy() throws {
        XCTAssertThrowsError(try boundedCopy(.string(String(repeating: "x", count: 2049)))) { XCTAssertEqual($0 as? SwiftOutcomeError, SwiftOutcomeError(code: "witness_string_limit")) }
        let eight: SwiftOutcomeJSON = .array([.array([.array([.array([.array([.array([.array([.array([.integer(1)])])])])])])])])
        XCTAssertEqual(try boundedCopy(eight), eight)
        XCTAssertThrowsError(try boundedCopy(.array([eight]))) { XCTAssertEqual($0 as? SwiftOutcomeError, SwiftOutcomeError(code: "witness_memory_limit")) }
    }
    func testWitnessV1ExcludesPresentationAndFailsEmptyInterval() {
        var evidence = call; evidence["presentation"] = .object(["status": .string("eligible_structural_only")]); evidence["outcome_witness"] = .null
        let value = buildOutcomeWitness(image: SwiftOutcomeImage(SwiftOutcomeTestFixture.request()), function: SwiftOutcomeTestFixture.caller, call: evidence)
        XCTAssertNil(value["evidence"].object?["presentation"]); XCTAssertNil(value["evidence"].object?["outcome_witness"])
        evidence["error_region"]["instructions"] = .array([])
        let invalid = buildOutcomeWitness(image: SwiftOutcomeImage(SwiftOutcomeTestFixture.request()), function: SwiftOutcomeTestFixture.caller, call: evidence)
        XCTAssertEqual(invalid["reason"], SwiftOutcomeJSON.string("list index out of range")); XCTAssertEqual(invalid["details_complete"], SwiftOutcomeJSON.bool(false))
    }
    func testWitnessV1EscapedBudget() throws {
        XCTAssertThrowsError(try boundedCopy(.object(["text": .string(String(repeating: "é", count: 100))]), limits: WitnessLimits(maxBytes: 200))) { XCTAssertEqual($0 as? SwiftOutcomeError, SwiftOutcomeError(code: "witness_output_limit")) }
    }
    func testWitnessV1MalformedIntervalReason() {
        var value = call; value["error_region"]["instructions"] = .null
        let result = buildOutcomeWitness(image: SwiftOutcomeImage(SwiftOutcomeTestFixture.request()), function: SwiftOutcomeTestFixture.caller, call: value)
        XCTAssertEqual(result["reason"], SwiftOutcomeJSON.string("'NoneType' object is not subscriptable"))
    }

    func testTP9PortableBoundedCopy() throws {
        let original: SwiftOutcomeJSON = .object(["status":.string("unresolved"),"a":.array([.integer(1),.null])])
        XCTAssertEqual(try boundedCopy(original),original)
        XCTAssertEqual(original,.object(["status":.string("unresolved"),"a":.array([.integer(1),.null])]))
        XCTAssertThrowsError(try boundedCopy(.object(["text":.string(String(repeating:"é",count:100))]), limits:WitnessLimits(maxBytes:200))) { error in
            XCTAssertEqual((error as? SwiftOutcomeError)?.code,String("witness_output_limit"))
        }
    }
}
#endif
