import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope

enum SwiftOutcomeTestFixture {
    static let caller = SwiftErrorFlowFunction(start: 0x1000, endExclusive: 0x1010, boundarySource: "lc_function_starts")
    static let callee = SwiftErrorFlowFunction(start: 0x1010, endExclusive: 0x1014, boundarySource: "lc_function_starts")
    static func request(words: [UInt32] = [0x94000004, 0xb5000055, 0xd65f03c0, 0xd65f03c0, 0xd65f03c0],
                        subtype: UInt32 = 0, functions: [SwiftErrorFlowFunction] = [caller, callee]) -> SwiftErrorFlowRequest {
        SwiftErrorFlowRequest(slice: .init(artifactSHA256: String(repeating: "ab", count: 32), sliceOffset: 0x4000, sliceByteCount: 0x2000, cpuType: 0x0100000c, cpuSubtype: subtype, littleEndian: true),
            code: .init(baseAddress: 0x1000, sliceRelativeFileOffset: 0x200, sectionOrdinal: 1, hasEmbeddedData: false, hasRelocations: false, words: words), functions: functions, symbols: [])
    }
    static let callsite: SwiftOutcomeJSON = .object([
        "status": .string("admitted_callsite"), "call_pc": .integer(4096), "callee_pc": .integer(4112),
        "provenance": .object([
            "call": .object(["pc": .integer(4096), "word": .integer(2483027972), "slice_file_offset": .integer(512), "container_file_offset": .integer(16896)]),
            "callee_entry": .object(["pc": .integer(4112), "word": .integer(3596551104), "slice_file_offset": .integer(528), "container_file_offset": .integer(16912)])]),
        "declaration": .object(["status": .string("syntax_admitted")]),
        "abi": .object(["status": .string("admitted"), "profile": .string("swift6-arm64-sync-untyped-research-v1"), "error_register": .string("x21"), "evidence": .object(["lowering": .object(["qualification_id": .string("q1")])])])])
    static func produce(_ callsite: SwiftOutcomeJSON = callsite, request: SwiftErrorFlowRequest = request(),
                        limits: BroadWitnessLimits = BroadWitnessLimits(), profile: String = "broad-v1") -> SwiftOutcomeJSON {
        buildBroadSwiftWitness(image: SwiftOutcomeImage(request), function: request.functions[0], callsite: callsite, limits: limits, profile: profile)
    }
    static func cfg(_ request: SwiftErrorFlowRequest = request(), function: SwiftErrorFlowFunction = caller,
                    limits: SwiftCFGLimits = SwiftCFGLimits()) throws -> SwiftOutcomeJSON {
        try buildSwiftCFG(image: SwiftOutcomeImage(request), function: function, limits: limits)
    }
}

final class SwiftOutcomeCFGTests: XCTestCase {
    func testCF01CompleteStructureAndOffsets() throws {
        let value = try SwiftOutcomeTestFixture.cfg()
        XCTAssertEqual(value["status"], SwiftOutcomeJSON.string("eligible_structural_only")); XCTAssertEqual(value["completeness"]["complete"], SwiftOutcomeJSON.bool(true))
        XCTAssertEqual(value["accounting"]["retained_words"], SwiftOutcomeJSON.integer(4)); XCTAssertEqual(value["accounting"]["blocks"], SwiftOutcomeJSON.integer(4)); XCTAssertEqual(value["accounting"]["edges"], SwiftOutcomeJSON.integer(5))
        let expected: [SwiftOutcomeJSON] = [
            .array([.string("0x1000"), .string("0x1004"), .string("call_return_candidate")]),
            .array([.string("0x1004"), .string("0x100c"), .string("conditional_taken")]),
            .array([.string("0x1004"), .string("0x1008"), .string("conditional_fallthrough")]),
            .array([.string("0x1008"), .null, .string("return")]), .array([.string("0x100c"), .null, .string("return")])]
        XCTAssertEqual(value["edges"].array!.map { .array([$0["source_pc"], $0["target_pc"], $0["kind"]]) }, expected)
        XCTAssertEqual(value["returns"].array!.map { $0["pc"] }, [SwiftOutcomeJSON.string("0x1008"), .string("0x100c")])
        let row = value["blocks"].array![1]["instructions"].array![0]
        XCTAssertEqual(row["word"], SwiftOutcomeJSON.string("0xb5000055")); XCTAssertEqual(row["slice_offset"], SwiftOutcomeJSON.string("0x204")); XCTAssertEqual(row["container_offset"], SwiftOutcomeJSON.string("0x4204")); XCTAssertEqual(row["kind"], SwiftOutcomeJSON.string("xcbnz"))
    }
    func testCF02UnsupportedArchitecture() throws {
        let request = SwiftOutcomeTestFixture.request(subtype: 2), value = try SwiftOutcomeTestFixture.cfg(SwiftOutcomeTestFixture.request(subtype: 2))
        XCTAssertEqual(SwiftOutcomeImage(request).architecture, String("unsupported")); XCTAssertEqual(value["status"], SwiftOutcomeJSON.string("declined")); XCTAssertEqual(value["reason"], SwiftOutcomeJSON.string("ordinary_arm64_required")); XCTAssertEqual(value["completeness"]["complete"], SwiftOutcomeJSON.bool(false))
    }
    func testCF03FinalFallthrough() throws {
        let function = SwiftErrorFlowFunction(start: 0x1000, endExclusive: 0x1004, boundarySource: "lc_function_starts")
        let value = try SwiftOutcomeTestFixture.cfg(SwiftOutcomeTestFixture.request(words: [0xd503201f], functions: [function]), function: function)
        XCTAssertEqual(value["status"], SwiftOutcomeJSON.string("blocked")); XCTAssertEqual(value["reason"], SwiftOutcomeJSON.string("fallthrough_outside_function"))
    }
    func testCF04ExactMembership() throws {
        let disjoint = SwiftErrorFlowFunction(start: 0x2000, endExclusive: 0x2004, boundarySource: "lc_function_starts")
        let disjointResult = try SwiftOutcomeTestFixture.cfg(function: disjoint)
        XCTAssertEqual(disjointResult["reason"], SwiftOutcomeJSON.string("exact_function_membership_required")); XCTAssertEqual(disjointResult["status"], SwiftOutcomeJSON.string("blocked"))
        let overlap = SwiftErrorFlowFunction(start: 0x1000, endExclusive: 0x100c, boundarySource: "lc_function_starts")
        let overlapResult = try SwiftOutcomeTestFixture.cfg(function: overlap)
        XCTAssertEqual(overlapResult["reason"], SwiftOutcomeJSON.string("overlapping_function_membership")); XCTAssertEqual(overlapResult["status"], SwiftOutcomeJSON.string("blocked"))
        let other = SwiftErrorFlowFunction(start: 0x1000, endExclusive: 0x1010, boundarySource: "other")
        let result = try SwiftOutcomeTestFixture.cfg(SwiftOutcomeTestFixture.request(functions: [other, SwiftOutcomeTestFixture.callee]), function: other)
        XCTAssertEqual(result["status"], SwiftOutcomeJSON.string("declined")); XCTAssertEqual(result["reason"], SwiftOutcomeJSON.string("exact_lc_function_starts_required"))
    }
    func testCF05Limits() throws {
        let blocks = try SwiftOutcomeTestFixture.cfg(limits: SwiftCFGLimits(maxBlocks: 0))
        let words = try SwiftOutcomeTestFixture.cfg(limits: SwiftCFGLimits(maxRetainedWords: 3))
        XCTAssertEqual(blocks["reason"], SwiftOutcomeJSON.string("blocks_limit")); XCTAssertEqual(blocks["status"], SwiftOutcomeJSON.string("blocked"))
        XCTAssertEqual(words["reason"], SwiftOutcomeJSON.string("retained_words_limit")); XCTAssertEqual(words["status"], SwiftOutcomeJSON.string("blocked"))
    }
    func testCF06UnknownWord() throws {
        let function = SwiftErrorFlowFunction(start: 0x1000, endExclusive: 0x1004, boundarySource: "lc_function_starts")
        let value = try SwiftOutcomeTestFixture.cfg(SwiftOutcomeTestFixture.request(words: [0], functions: [function]), function: function)
        XCTAssertEqual(value["status"], SwiftOutcomeJSON.string("unresolved")); XCTAssertEqual(value["reason"], SwiftOutcomeJSON.string("unclassified_instruction_edges"))
        XCTAssertEqual(value["blocks"].array![0]["instructions"].array![0]["unresolved_reason"], SwiftOutcomeJSON.string("unsupported_instruction"))
        XCTAssertEqual(value["edges"].array![0]["kind"], SwiftOutcomeJSON.string("unresolved"))
    }
    func testCFGExactWorkAndDepth() throws {
        let value = try SwiftOutcomeTestFixture.cfg()
        // 2 members + 1 section + 4 words + 5 edges + 4 row assignments + 5 attachments + 4 DFS visits.
        XCTAssertEqual(value["accounting"]["work"], SwiftOutcomeJSON.integer(25))
        XCTAssertEqual(value["accounting"]["max_discovery_depth"], SwiftOutcomeJSON.integer(3))
        XCTAssertEqual(try SwiftOutcomeTestFixture.cfg(limits: SwiftCFGLimits(maxDepth: 2))["reason"], SwiftOutcomeJSON.string("depth_limit"))
    }
    func testCFGExceptionAndBackwardBranch() throws {
        let function = SwiftErrorFlowFunction(start: 0x1000, endExclusive: 0x1008, boundarySource: "lc_function_starts")
        let value = try SwiftOutcomeTestFixture.cfg(SwiftOutcomeTestFixture.request(words: [0xd4200000, 0x17ffffff], functions: [function]), function: function)
        XCTAssertEqual(value["status"], SwiftOutcomeJSON.string("eligible_structural_only"))
        XCTAssertEqual(value["exception_transfers"].array!.count, Int(1)); XCTAssertEqual(value["exception_transfers"].array![0]["resume_proven"], SwiftOutcomeJSON.bool(false))
        XCTAssertEqual(value["edges"].array![1]["target_pc"], SwiftOutcomeJSON.string("0x1000")); XCTAssertEqual(value["edges"].array![1]["kind"], SwiftOutcomeJSON.string("branch"))
    }
    func testImageLittleEndianAndBoundedMapping() throws {
        let image = SwiftOutcomeImage(SwiftOutcomeTestFixture.request())
        let expected: Data = Data([0x00, 0x00, 0x94, 0x55, 0x00])
        XCTAssertEqual(try image.bytesAt(address: 0x1001, size: 5), expected)
        XCTAssertThrowsError(try image.bytesAt(address: 0x1000, size: -1)) { XCTAssertEqual($0 as? SwiftOutcomeError, SwiftOutcomeError(code: "negative_size")) }
        XCTAssertThrowsError(try image.bytesAt(address: 0x2000, size: 4)) { XCTAssertEqual($0 as? SwiftOutcomeError, SwiftOutcomeError(code: "unmapped_address")) }
    }
}
#endif
