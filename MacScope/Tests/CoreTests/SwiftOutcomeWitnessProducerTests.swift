import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope

final class SwiftOutcomeWitnessProducerTests: XCTestCase {
    private func missing(_ value: SwiftOutcomeJSON, _ expected: [String], file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(value["completeness"]["missing"], SwiftOutcomeJSON.array(expected.map(SwiftOutcomeJSON.string)), file: file, line: line)
    }
    private func changed(_ key: String, _ value: SwiftOutcomeJSON) -> SwiftOutcomeJSON {
        var record = SwiftOutcomeTestFixture.callsite; record[key] = value; return record
    }
    func testPW01CandidateConstants() {
        let value = SwiftOutcomeTestFixture.produce()
        XCTAssertEqual(value["model_version"], SwiftOutcomeJSON.string("swift-outcome-witness-v2")); XCTAssertEqual(value["validation_model"], SwiftOutcomeJSON.string("swift-outcome-validation-v2"))
        XCTAssertEqual(value["status"], SwiftOutcomeJSON.string("unresolved")); XCTAssertEqual(value["eligible"], SwiftOutcomeJSON.bool(false))
        let expected: SwiftOutcomeJSON = .array([.string("candidate_requires_independent_validation"), .string("research_only"), .string("runtime_call_return_unproven"), .string("paths_structural_only"), .string("dominance_and_exclusivity_unproven"), .string("source_reconstruction_forbidden")])
        XCTAssertEqual(value["limitations"], expected)
    }
    func testPW02UnsupportedProfile() {
        let value = SwiftOutcomeTestFixture.produce(profile: "broad-large-v1")
        missing(value, ["unsupported_profile"]); XCTAssertEqual(value["completeness"]["complete"], SwiftOutcomeJSON.bool(false))
        XCTAssertEqual(value["reason"], SwiftOutcomeJSON.string("candidate_facts_incomplete")); XCTAssertEqual(value["source_models"], SwiftOutcomeJSON.object([:])); XCTAssertEqual(value["profile"], SwiftOutcomeJSON.string("broad-large-v1"))
    }
    func testPW03AdmissionStatus() {
        let value = SwiftOutcomeTestFixture.produce(changed("status", .string("not_admitted")))
        missing(value, ["callsite_not_admitted"])
        let expected: SwiftOutcomeJSON = .object(["edge": .string("swift-broad-error-flow-v1"), "witness": .string("swift-outcome-witness-v2"), "validation": .string("swift-outcome-validation-v2"), "cfg": .string("swift-bounded-structural-cfg-v1"), "value": .string("swift-outcome-values-v1")])
        XCTAssertEqual(value["source_models"], expected); XCTAssertEqual(value["post_call"]["status"], SwiftOutcomeJSON.string("unknown")); XCTAssertEqual(value["post_call"]["reason"], SwiftOutcomeJSON.string("not_examined"))
    }
    func testPW04InputTypesAndAlignment() {
        missing(SwiftOutcomeTestFixture.produce(.array([])), ["callsite_object_required"])
        missing(SwiftOutcomeTestFixture.produce(changed("call_pc", .string("4096"))), ["integer_call_addresses_required"])
        missing(SwiftOutcomeTestFixture.produce(changed("call_pc", .integer(4098))), ["call_address_range"])
    }
    func testPW05Membership() {
        missing(SwiftOutcomeTestFixture.produce(changed("call_pc", .integer(8192))), ["caller_membership"])
        missing(SwiftOutcomeTestFixture.produce(changed("callee_pc", .integer(4116))), ["callee_membership"])
    }
    func testPW06DirectCallRequired() {
        let value = SwiftOutcomeTestFixture.produce(changed("call_pc", .integer(4100)))
        missing(value, ["direct_bl_required"]); XCTAssertEqual(value["identity"]["call_pc"], SwiftOutcomeJSON.string("0x1004")); XCTAssertEqual(value["call"], SwiftOutcomeJSON.object([:]))
    }
    func testPW07RawTargetAndProvenance() {
        var record = SwiftOutcomeTestFixture.callsite; record["provenance"]["call"]["word"] = .integer(2483027973)
        missing(SwiftOutcomeTestFixture.produce(record), ["call_provenance_mismatch"])
        missing(SwiftOutcomeTestFixture.produce(request: SwiftOutcomeTestFixture.request(words: [0x94000005, 0xb5000055, 0xd65f03c0, 0xd65f03c0, 0xd65f03c0])), ["raw_call_target_mismatch"])
    }
    func testPW08DeclarationQualification() {
        let value = SwiftOutcomeTestFixture.produce(changed("declaration", .object(["status": .string("other")])))
        missing(value, ["declaration_unqualified"]); XCTAssertEqual(value["call"]["pc"], SwiftOutcomeJSON.string("0x1000")); XCTAssertEqual(value["call"]["word"], SwiftOutcomeJSON.string("0x94000004")); XCTAssertEqual(value["call"]["callee_pc"], SwiftOutcomeJSON.string("0x1010"))
    }
    func testPW09IdentityAndCounts() {
        let value = SwiftOutcomeTestFixture.produce(), digest = String(repeating: "ab", count: 32)
        XCTAssertEqual(value["reason"], SwiftOutcomeJSON.string("validation_required"))
        XCTAssertEqual(value["completeness"], SwiftOutcomeJSON.object(["complete": .bool(true), "missing": .array([])]))
        let expected: SwiftOutcomeJSON = .object(["slice_sha256": .string(digest), "container_sha256": .string(digest), "slice_offset": .string("0x4000"), "slice_size": .string("0x2000"), "architecture": .string("arm64"), "uuid": .null, "preferred_base": .string("0xe00"), "slice_index": .null, "container_slice_count": .null, "cpu_subtype": .integer(0), "caller": .object(["start_pc": .string("0x1000"), "end_pc_exclusive": .string("0x1010"), "boundary_source": .string("lc_function_starts")]), "callee": .object(["start_pc": .string("0x1010"), "end_pc_exclusive": .string("0x1014"), "boundary_source": .string("lc_function_starts")]), "call_pc": .string("0x1000")])
        XCTAssertEqual(value["identity"], expected); XCTAssertEqual(value["cfg"]["model"], SwiftOutcomeJSON.string("swift-bounded-structural-cfg-v1"))
        XCTAssertEqual(value["call"]["pc"], SwiftOutcomeJSON.string("0x1000")); XCTAssertEqual(value["call"]["word"], SwiftOutcomeJSON.string("0x94000004")); XCTAssertEqual(value["call"]["callee_pc"], SwiftOutcomeJSON.string("0x1010"))
        for (key, number) in [("instructions", 4), ("blocks", 4), ("edges", 5), ("value_steps", 0)] { XCTAssertEqual(value["accounting"][key], SwiftOutcomeJSON.integer(Int128(number))) }
    }
    func testPW10PostCallAndPartition() {
        let value = SwiftOutcomeTestFixture.produce()
        let expectedPost: SwiftOutcomeJSON = .object(["status": .string("candidate"), "reason": .string("qualified_error_alias_zero_test"), "test_pc": .string("0x1004"), "test_word": .string("0xb5000055"), "test_register": .string("x21"), "error_successor_pc": .string("0x100c"), "success_successor_pc": .string("0x1008"), "trace": .array([.string("0x1004")])])
        XCTAssertEqual(value["post_call"], expectedPost)
        let expectedRegions: SwiftOutcomeJSON = .object(["status": .string("structural_candidates"), "success_entry_pc": .string("0x1008"), "error_entry_pc": .string("0x100c"), "paths": .array([.object(["outcome": .string("success"), "entry_pc": .string("0x1008"), "reachability": .string("unproven")]), .object(["outcome": .string("error"), "entry_pc": .string("0x100c"), "reachability": .string("unproven")])]), "partition": .object(["success_only_pcs": .array([.string("0x1008")]), "error_only_pcs": .array([.string("0x100c")]), "shared_pcs": .array([]), "unreachable_pcs": .array([.string("0x1000"), .string("0x1004")])]), "tails": .array([.object(["pc": .string("0x1008"), "kind": .string("return"), "outcome": .string("success")]), .object(["pc": .string("0x100c"), "kind": .string("return"), "outcome": .string("error")])])])
        XCTAssertEqual(value["regions"], expectedRegions)
        XCTAssertEqual(value["value_facts"]["seed"], SwiftOutcomeJSON.object(["register": .string("x21"), "kind": .string("register_copy"), "origin": .string("abi_post_call_error:x21"), "width": .integer(64)]))
        XCTAssertEqual(value["value_facts"]["observations"], SwiftOutcomeJSON.array([]))
    }
    func testPW11StableSeed() {
        var record = SwiftOutcomeTestFixture.callsite; record["abi"]["profile"] = .string("swift6-arm64-sync-untyped-stable-research-v2")
        let value = SwiftOutcomeTestFixture.produce(record)
        XCTAssertEqual(value["value_facts"]["seed"]["origin"], SwiftOutcomeJSON.string("raw_post_call_register:x21"))
        XCTAssertEqual(value["post_call"]["test_pc"], SwiftOutcomeJSON.string("0x1004")); XCTAssertEqual(value["completeness"]["complete"], SwiftOutcomeJSON.bool(true))
        let expectedPost: SwiftOutcomeJSON = .object(["status": .string("candidate"), "reason": .string("qualified_error_alias_zero_test"), "test_pc": .string("0x1004"), "test_word": .string("0xb5000055"), "test_register": .string("x21"), "error_successor_pc": .string("0x100c"), "success_successor_pc": .string("0x1008"), "trace": .array([.string("0x1004")])])
        XCTAssertEqual(value["post_call"], expectedPost)
        let expectedRegions: SwiftOutcomeJSON = .object(["status": .string("structural_candidates"), "success_entry_pc": .string("0x1008"), "error_entry_pc": .string("0x100c"), "paths": .array([.object(["outcome": .string("success"), "entry_pc": .string("0x1008"), "reachability": .string("unproven")]), .object(["outcome": .string("error"), "entry_pc": .string("0x100c"), "reachability": .string("unproven")])]), "partition": .object(["success_only_pcs": .array([.string("0x1008")]), "error_only_pcs": .array([.string("0x100c")]), "shared_pcs": .array([]), "unreachable_pcs": .array([.string("0x1000"), .string("0x1004")])]), "tails": .array([.object(["pc": .string("0x1008"), "kind": .string("return"), "outcome": .string("success")]), .object(["pc": .string("0x100c"), "kind": .string("return"), "outcome": .string("error")])])])
        XCTAssertEqual(value["regions"], expectedRegions)
        XCTAssertEqual(value["value_facts"]["observations"], SwiftOutcomeJSON.array([]))
    }
    func testPW12DuplicatedABIRefusal() {
        let value = SwiftOutcomeTestFixture.produce(changed("abi", .object(["status": .string("unavailable")])))
        missing(value, ["abi_unqualified", "abi_unqualified"]); XCTAssertEqual(value["completeness"]["complete"], SwiftOutcomeJSON.bool(false)); XCTAssertEqual(value["reason"], SwiftOutcomeJSON.string("candidate_facts_incomplete"))
        XCTAssertEqual(value["post_call"]["reason"], SwiftOutcomeJSON.string("abi_unqualified")); XCTAssertEqual(value["regions"]["status"], SwiftOutcomeJSON.string("unknown")); XCTAssertEqual(value["cfg"]["model"], SwiftOutcomeJSON.string("swift-bounded-structural-cfg-v1"))
    }
    func testPW13CFGDecline() {
        let value = SwiftOutcomeTestFixture.produce(request: SwiftOutcomeTestFixture.request(subtype: 2))
        missing(value, ["cfg_ordinary_arm64_required"]); XCTAssertEqual(value["cfg"]["status"], SwiftOutcomeJSON.string("declined"))
    }
    func testPW14WorkAndOutputLimits() throws {
        missing(SwiftOutcomeTestFixture.produce(limits: try BroadWitnessLimits(maxWork: 2)), ["witness_work_limit"])
        let value = SwiftOutcomeTestFixture.produce(limits: try BroadWitnessLimits(maxBytes: 1000))
        XCTAssertEqual(value["reason"], SwiftOutcomeJSON.string("candidate_facts_incomplete"))
        XCTAssertEqual(value["completeness"], SwiftOutcomeJSON.object(["complete": .bool(false), "missing": .array([.string("witness_output_limit")])]))
        XCTAssertEqual(value["cfg"], SwiftOutcomeJSON.object([:])); XCTAssertEqual(value["call"], SwiftOutcomeJSON.object([:]))
        XCTAssertEqual(value["post_call"]["status"], SwiftOutcomeJSON.string("unknown")); XCTAssertEqual(value["post_call"]["reason"], SwiftOutcomeJSON.string("witness_output_limit")); XCTAssertEqual(value["regions"]["status"], SwiftOutcomeJSON.string("unknown")); XCTAssertEqual(value["accounting"]["encoded_bytes"], SwiftOutcomeJSON.integer(0))
        XCTAssertEqual(value["identity"], SwiftOutcomeTestFixture.produce()["identity"])
    }
    func testPW15EncodedFixedPoint() throws {
        let value = SwiftOutcomeTestFixture.produce()
        XCTAssertEqual(value["accounting"]["encoded_bytes"], SwiftOutcomeJSON.integer(Int128(try SwiftOutcomeWitnessCodec.encode(value).count)))
    }
    func testPW16OtherRegisterControl() {
        let value = SwiftOutcomeTestFixture.produce(request: SwiftOutcomeTestFixture.request(words: [0x94000004, 0xb5000054, 0xd65f03c0, 0xd65f03c0, 0xd65f03c0]))
        missing(value, ["post_call_control_without_error_test"]); XCTAssertEqual(value["post_call"]["status"], SwiftOutcomeJSON.string("unknown")); XCTAssertEqual(value["post_call"]["reason"], SwiftOutcomeJSON.string("post_call_control_without_error_test")); XCTAssertEqual(value["post_call"]["trace"], SwiftOutcomeJSON.array([.string("0x1004")]))
        XCTAssertEqual(value["completeness"]["complete"], SwiftOutcomeJSON.bool(false)); XCTAssertEqual(value["reason"], SwiftOutcomeJSON.string("candidate_facts_incomplete")); XCTAssertEqual(value["regions"]["status"], SwiftOutcomeJSON.string("unknown"))
    }
    func testPW17CFGRefusalPrecedesWindow() {
        let value = SwiftOutcomeTestFixture.produce(request: SwiftOutcomeTestFixture.request(words: [0x94000004, 0, 0xd65f03c0, 0xd65f03c0, 0xd65f03c0]))
        missing(value, ["cfg_unclassified_instruction_edges"]); XCTAssertEqual(value["cfg"]["status"], SwiftOutcomeJSON.string("unresolved")); XCTAssertEqual(value["post_call"]["reason"], SwiftOutcomeJSON.string("not_examined"))
    }
    func testProducerMalformedNestedContainerReasons() {
        for key in ["provenance", "declaration", "abi"] {
            missing(SwiftOutcomeTestFixture.produce(changed(key, .null)), ["'NoneType' object has no attribute 'get'"])
        }
        var record = SwiftOutcomeTestFixture.callsite; record["abi"]["evidence"] = .array([])
        missing(SwiftOutcomeTestFixture.produce(record), ["'list' object has no attribute 'get'"])
        record = SwiftOutcomeTestFixture.callsite; record["provenance"]["call"] = .integer(1)
        missing(SwiftOutcomeTestFixture.produce(record), ["'int' object has no attribute 'get'"])
    }
    func testProducerMappingFailureUsesDonorCaughtMessage() {
        let caller = SwiftErrorFlowFunction(start: 0x2000, endExclusive: 0x2010, boundarySource: "lc_function_starts")
        let request = SwiftOutcomeTestFixture.request(functions: [caller, SwiftOutcomeTestFixture.callee])
        missing(SwiftOutcomeTestFixture.produce(changed("call_pc", .integer(8192)), request: request), ["No section contains VM range 0x2000+0x4"])
    }

    // New synthetic fixtures retain the same identity/ABI syntax as fixture F.
    private func script(_ words: [UInt32], callIndex: Int = 0) -> SwiftOutcomeJSON {
        let calleePC = UInt64(0x1000 + (words.count - 1) * 4)
        let caller = SwiftErrorFlowFunction(start: 0x1000, endExclusive: calleePC, boundarySource: "lc_function_starts")
        let callee = SwiftErrorFlowFunction(start: calleePC, endExclusive: calleePC + 4, boundarySource: "lc_function_starts")
        let request = SwiftOutcomeTestFixture.request(words: words, functions: [caller, callee])
        var call = SwiftOutcomeTestFixture.callsite
        call["call_pc"] = .integer(Int128(0x1000 + callIndex * 4)); call["callee_pc"] = .integer(Int128(calleePC))
        call["provenance"]["call"]["word"] = .integer(Int128(words[callIndex]))
        call["provenance"]["call"]["pc"] = call["call_pc"]
        call["provenance"]["call"]["slice_file_offset"] = .integer(Int128(0x200 + callIndex * 4))
        call["provenance"]["call"]["container_file_offset"] = .integer(Int128(0x4200 + callIndex * 4))
        call["provenance"]["callee_entry"]["pc"] = .integer(Int128(calleePC))
        call["provenance"]["callee_entry"]["slice_file_offset"] = .integer(Int128(0x200 + (words.count - 1) * 4))
        call["provenance"]["callee_entry"]["container_file_offset"] = .integer(Int128(0x4200 + (words.count - 1) * 4))
        return SwiftOutcomeTestFixture.produce(call, request: request)
    }
    func testProducerCompareZeroEQAndNE() {
        let cases: [(UInt32, String, String, String)] = [(0x54000040, "eq", "0x1010", "0x100c"), (0x54000041, "ne", "0x100c", "0x1010")]
        for (branch, condition, success, error) in cases {
            let value = script([0x94000005, 0xf10002bf, branch, 0xd65f03c0, 0xd65f03c0, 0xd65f03c0])
            XCTAssertEqual(value["post_call"]["test_kind"], SwiftOutcomeJSON.string("cmp_zero_bcond")); XCTAssertEqual(value["post_call"]["test_condition"], SwiftOutcomeJSON.string(condition))
            XCTAssertEqual(value["post_call"]["comparison_pc"], SwiftOutcomeJSON.string("0x1004")); XCTAssertEqual(value["post_call"]["test_pc"], SwiftOutcomeJSON.string("0x1008")); XCTAssertEqual(value["post_call"]["success_successor_pc"], SwiftOutcomeJSON.string(success)); XCTAssertEqual(value["post_call"]["error_successor_pc"], SwiftOutcomeJSON.string(error))
        }
    }
    func testProducerBranchFollowAndCycle() {
        let followed = script([0x94000005, 0x14000001, 0xb5000055, 0xd65f03c0, 0xd65f03c0, 0xd65f03c0])
        XCTAssertEqual(followed["post_call"]["trace"], SwiftOutcomeJSON.array([.string("0x1004"), .string("0x1008")]))
        XCTAssertEqual(followed["post_call"]["status"], SwiftOutcomeJSON.string("candidate"))
        let cycle = script([0x94000003, 0x14000000, 0xd65f03c0, 0xd65f03c0])
        missing(cycle, ["post_call_cycle"]); XCTAssertEqual(cycle["post_call"]["trace"], SwiftOutcomeJSON.array([.string("0x1004")]))
    }
    func testProducerComparisonMustBeAdjacent() {
        let value = script([0x94000005, 0xf10002bf, 0xd503201f, 0xd65f03c0, 0xd65f03c0, 0xd65f03c0])
        missing(value, ["comparison_branch_not_adjacent_or_supported"])
    }
    func testProducerFramePrefixAndSpillReload() {
        let value = script([0xd10043ff, 0x94000006, 0xf90007f5, 0xf94007f3, 0xb5000053, 0xd65f03c0, 0xd65f03c0, 0xd65f03c0], callIndex: 1)
        XCTAssertEqual(value["post_call"]["status"], SwiftOutcomeJSON.string("candidate")); XCTAssertEqual(value["post_call"]["test_register"], SwiftOutcomeJSON.string("x19"))
        XCTAssertEqual(value["accounting"]["value_steps"], SwiftOutcomeJSON.integer(2))
        let observations = value["value_facts"]["observations"].array!
        let expectedSlot: SwiftOutcomeJSON = .object(["stack_slot": .integer(-8), "epoch": .integer(1), "kind": .string("stack_slot"), "origin": .string("abi_post_call_error:x21")])
        XCTAssertTrue(observations[0]["origins"].array!.contains(expectedSlot))
    }
    func testProducerUnknownFrameForgetsOnlyKnownWrites() {
        let value = script([0x14000001, 0x94000006, 0xf94003f3, 0xb5000055, 0xd65f03c0, 0xd65f03c0, 0xd65f03c0, 0xd65f03c0], callIndex: 1)
        XCTAssertEqual(value["post_call"]["status"], SwiftOutcomeJSON.string("candidate")); XCTAssertEqual(value["post_call"]["test_register"], SwiftOutcomeJSON.string("x21"))
        XCTAssertEqual(value["accounting"]["value_steps"], SwiftOutcomeJSON.integer(1))
        let expected: SwiftOutcomeJSON = .array([.object(["register": .string("x21"), "kind": .string("register_copy"), "origin": .string("abi_post_call_error:x21")])])
        XCTAssertEqual(value["value_facts"]["observations"].array![0]["origins"], expected)
    }
    func testProducerSharedTailAndExactWork() {
        let shared = script([0x94000005, 0xb5000055, 0x14000002, 0x14000001, 0xd65f03c0, 0xd65f03c0])
        XCTAssertEqual(shared["regions"]["partition"]["shared_pcs"], SwiftOutcomeJSON.array([.string("0x1010")]))
        XCTAssertEqual(shared["regions"]["tails"], SwiftOutcomeJSON.array([.object(["pc": .string("0x1010"), "kind": .string("return"), "outcome": .string("shared")])]))
        // 3 metadata + 25 CFG + 1 window + 5 partition edges + 2 reach visits.
        XCTAssertEqual(SwiftOutcomeTestFixture.produce()["accounting"]["work"], SwiftOutcomeJSON.integer(36))
    }
}
#endif
