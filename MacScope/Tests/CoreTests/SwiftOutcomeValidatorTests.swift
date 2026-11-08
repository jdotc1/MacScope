import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope
final class SwiftOutcomeValidatorTests: XCTestCase {
    func testUC01_manually_chosen_qualified_fixture() throws {
        let r = try OutcomeFixture.manual().validate()
        XCTAssertEqual(r["status"],.string("eligible_structural_only")); XCTAssertEqual(r["eligible"],.bool(true))
        XCTAssertEqual(r["reason"],.string("independent_bounded_byte_replay")); XCTAssertEqual(r["call_return_proven"],.bool(false)); XCTAssertEqual(r["source_reconstruction_allowed"],.bool(false))
        XCTAssertEqual(r["return_observations"].array?.first?["value"],.array([.string("call_result"),.string("0x1000"),.integer(64)]))
    }
    func testUC02_unknown_registry_even_if_caller_claims_admitted() throws {
        let f = try OutcomeFixture.manual(); let r = validateBroadSwiftWitness(image:f.image,function:f.function,candidate:f.candidate)
        XCTAssertEqual(r["reason"],.string("abi_qualification_unknown")); XCTAssertEqual(r["status"],.string("unresolved")); XCTAssertEqual(r["eligible"],.bool(false))
    }
    private func attack(_ path: String,_ value: SwiftOutcomeJSON, file: StaticString = #filePath,line: UInt = #line) throws {
        var f = try OutcomeFixture.manual(); OutcomeFixture.assign(&f.candidate,path.components(separatedBy:"."),value)
        XCTAssertEqual(f.validate()["eligible"],.bool(false),path,file:file,line:line)
    }
    func testUC03_model_version() throws { try attack("model_version",.string("swift-outcome-witness-v1")) }
    func testUC03_validation_model() throws { try attack("validation_model",.string("v1")) }
    func testUC03_profile() throws { try attack("profile",.string("methods")) }
    func testUC03_eligible() throws { try attack("eligible",.bool(true)) }
    func testUC03_status() throws { try attack("status",.string("eligible_structural_only")) }
    func testUC03_source_models_value() throws { try attack("source_models.value",.string("fake")) }
    func testUC03_identity_slice_sha256() throws { try attack("identity.slice_sha256",.string("other")) }
    func testUC03_identity_container_sha256() throws { try attack("identity.container_sha256",.string("other")) }
    func testUC03_identity_slice_offset() throws { try attack("identity.slice_offset",.string("0x1000")) }
    func testUC03_identity_slice_size() throws { try attack("identity.slice_size",.string("0x3ff")) }
    func testUC03_identity_architecture() throws { try attack("identity.architecture",.string("arm64e")) }
    func testUC03_identity_cpu_subtype() throws { try attack("identity.cpu_subtype",.bool(true)) }
    func testUC03_identity_caller_start() throws { try attack("identity.caller.start_pc",.string("0x1004")) }
    func testUC03_identity_caller_end() throws { try attack("identity.caller.end_pc_exclusive",.string("0x100c")) }
    func testUC03_identity_callee_start() throws { try attack("identity.callee.start_pc",.string("0x1014")) }
    func testUC03_identity_callee_end() throws { try attack("identity.callee.end_pc_exclusive",.string("0x101c")) }
    func testUC03_identity_boundary_source() throws { try attack("identity.caller.boundary_source",.string("symbol")) }
    func testUC03_identity_call_pc() throws { try attack("identity.call_pc",.string("0x1002")) }
    func testUC03_call_pc() throws { try attack("call.pc",.string("0x1004")) }
    func testUC03_call_word() throws { try attack("call.word",.string("0x94000005")) }
    func testUC03_call_callee_pc() throws { try attack("call.callee_pc",.string("0x1014")) }
    func testUC03_call_provenance_offset() throws { try attack("call.provenance.call.slice_file_offset",.string("0x104")) }
    func testUC03_call_provenance_entry() throws { try attack("call.provenance.callee_entry.word",.string("0x00000000")) }
    func testUC03_declaration_name() throws { try attack("call.declaration.identity.function_name",.string("evil")) }
    func testUC03_declaration_status() throws { try attack("call.declaration.status",.string("syntax_unresolved")) }
    func testUC03_qualification() throws { try attack("call.abi.evidence.lowering.qualification_id",.string("forged")) }
    func testUC03_error_register() throws { try attack("call.abi.error_register",.string("x20")) }
    func testUC03_abi_profile() throws { try attack("call.abi.profile",.string("universal")) }
    func testUC03_research_only() throws { try attack("call.abi.research_only",.bool(false)) }
    func testUC03_abi_status() throws { try attack("call.abi.status",.string("unresolved")) }
    func testUC03_cfg_word() throws { try attack("cfg.blocks.0.instructions.0.word",.string("0x94000005")) }
    func testUC03_cfg_predecessors() throws { try attack("cfg.blocks.1.predecessors",.array([])) }
    func testUC03_cfg_target() throws { try attack("cfg.edges.1.target_pc",.string("0x1008")) }
    func testUC03_cfg_returns() throws { try attack("cfg.returns",.array([])) }
    func testUC03_cfg_calls() throws { try attack("cfg.call_return_candidates",.array([])) }
    func testUC03_cfg_complete() throws { try attack("cfg.completeness.complete",.bool(false)) }
    func testUC03_cfg_edge_count() throws { try attack("cfg.accounting.edges",.integer(4)) }
    func testUC03_cfg_model() throws { try attack("cfg.model",.string("fake")) }
    func testUC03_test_pc() throws { try attack("post_call.test_pc",.string("0x1008")) }
    func testUC03_test_word() throws { try attack("post_call.test_word",.string("0xb5000055")) }
    func testUC03_test_register() throws { try attack("post_call.test_register",.string("x20")) }
    func testUC03_error_successor() throws { try attack("post_call.error_successor_pc",.string("0x100c")) }
    func testUC03_trace() throws { try attack("post_call.trace",.array([])) }
    func testUC03_post_status() throws { try attack("post_call.status",.string("unknown")) }
    func testUC03_region_outcome() throws { try attack("regions.paths.0.outcome",.string("error")) }
    func testUC03_region_tails() throws { try attack("regions.tails",.array([])) }
    func testUC03_region_success() throws { try attack("regions.success_entry_pc",.string("0x1008")) }
    func testUC03_seed_register() throws { try attack("value_facts.seed.register",.string("x0")) }
    func testUC03_seed_width() throws { try attack("value_facts.seed.width",.integer(32)) }
    func testUC03_observations() throws { try attack("value_facts.observations",.array([.object([:])])) }
    func testUC03_complete() throws { try attack("completeness.complete",.bool(false)) }
    func testUC03_call_return_proven() throws { try attack("call_return_proven",.bool(true)) }
    func testUC04_changed_raw_bytes_geometry_symbols() throws {
        let mutations: [(Int,Int,UInt64)] = [(256,4,0x94000005),(260,4,0xb5000055),(264,4,0xd63f0200),(272,4,0xd503201f),(0,4,0),(4,4,0),(8,4,2),(16,4,50),(36,4,0),(128,8,0x1004),(136,8,28),(144,4,260),(516,1,14),(517,1,2),(518,2,0x200),(520,8,0x1014),(900,1,0x84),(903,1,1)]
        for (offset,width,value) in mutations { var f = try OutcomeFixture.manual(); var d=f.image.data; OutcomeFixture.put(&d,offset,width,value); f.image=f.image.copy(data:d); XCTAssertEqual(f.validate()["eligible"],.bool(false),"offset \(offset)") }
    }
    func testUC05_limits_no_false_eligible() throws {
        let limits = try [BroadWitnessLimits(maxInstructions:0),BroadWitnessLimits(maxBlocks:0),BroadWitnessLimits(maxEdges:0),BroadWitnessLimits(maxWork:0),BroadWitnessLimits(maxDepth:0),BroadWitnessLimits(maxStateEntries:0),BroadWitnessLimits(maxBytes:0),BroadWitnessLimits(maxContainerItems:0),BroadWitnessLimits(postCallWindow:0)]
        for limit in limits { XCTAssertEqual(try OutcomeFixture.manual().validate(limits:limit)["eligible"],.bool(false)) }
    }
    func testUC06_coordinated_polarity_and_all_retained_facts_cannot_reuse_old_image_custody() throws {
        var f=try OutcomeFixture.manual(); var d=f.image.data; OutcomeFixture.put(&d,260,4,0xb5000055)
        func rewrite(_ v: SwiftOutcomeJSON) -> SwiftOutcomeJSON {
            if let array=v.array { return .array(array.map(rewrite)) }
            guard var object=v.object else { return v }
            if object["pc"] == .string("0x1004"), object["word"] != nil { object["word"] = .string("0xb5000055"); if object["kind"] == .string("xcbz") { object["kind"] = .string("xcbnz") } }
            return .object(object.mapValues(rewrite))
        }
        f.candidate=rewrite(f.candidate); f.candidate["post_call"]["test_word"] = .string("0xb5000055"); f.candidate["post_call"]["error_successor_pc"] = .string("0x100c"); f.candidate["post_call"]["success_successor_pc"] = .string("0x1008")
        f.candidate["regions"]["success_entry_pc"] = .string("0x1008"); f.candidate["regions"]["error_entry_pc"] = .string("0x100c")
        f.candidate["regions"]["paths"] = try OutcomeFixture.json(#"{"paths":[{"outcome":"success","entry_pc":"0x1008","reachability":"unproven"},{"outcome":"error","entry_pc":"0x100c","reachability":"unproven"}]}"#)["paths"]
        OutcomeFixture.finish(&f.candidate); f.image=f.image.copy(data:d)
        XCTAssertEqual(f.validate()["reason"],.string("image_admission_custody"))
    }
    func testUC06_unadmitted_manually_constructed_image_cannot_claim_existing_digest() throws {
        var f=try OutcomeFixture.manual(); f.image=OutcomeFixture.image(f.image.data,admitted:false); XCTAssertEqual(f.validate()["reason"],.string("image_admission_custody"))
    }
    func testUC07_partial_truncated_and_hostile_objects() throws {
        for size in [0,31,200,260,520,902] { var f=try OutcomeFixture.manual(); f.image=f.image.copy(data:Data(f.image.data.prefix(size))); XCTAssertEqual(f.validate()["eligible"],.bool(false)) }
        let hostile: [SwiftOutcomeJSON] = [.object([:]),.null,.array([]),.object(["loop":.null])]; for bad in hostile { var f=try OutcomeFixture.manual(); f.candidate=bad; XCTAssertEqual(f.validate()["eligible"],.bool(false)) }
    }
    func testUC08_coordinated_call_change_cannot_use_old_source_receipt() throws {
        var f=try OutcomeFixture.manual(); var d=f.image.data; OutcomeFixture.put(&d,256,4,0x94000005); f.image=f.image.copy(data:d)
        f.candidate["call"]["word"] = .string("0x94000005"); f.candidate["call"]["callee_pc"] = .string("0x1014"); f.candidate["identity"]["callee"]["start_pc"] = .string("0x1014")
        XCTAssertEqual(f.validate()["eligible"],.bool(false))
    }
    func testUC12_all_four_new_identity_coordinates_match_admitted_image() throws {
        let f=try OutcomeFixture.manual(); XCTAssertEqual(f.validate()["eligible"],.bool(true)); XCTAssertEqual(f.candidate["identity"]["uuid"],.null); XCTAssertEqual(f.candidate["identity"]["preferred_base"],.string("0xf00")); XCTAssertEqual(f.candidate["identity"]["slice_index"],.integer(0)); XCTAssertEqual(f.candidate["identity"]["container_slice_count"],.integer(1))
    }
    func testUC12_new_coordinates_and_explicit_nullable_uuid_are_mandatory() throws {
        let cases: [(String,SwiftOutcomeJSON)] = [("uuid",.string("forged-uuid")),("preferred_base",.string("0x1000")),("slice_index",.integer(1)),("slice_index",.bool(false)),("container_slice_count",.integer(2)),("container_slice_count",.bool(true))]
        for (key,value) in cases { var f=try OutcomeFixture.manual(); f.candidate["identity"][key]=value; XCTAssertEqual(f.validate()["reason"],.string("image_identity")) }
        var f=try OutcomeFixture.manual(); var identity=f.candidate["identity"].object!; identity.removeValue(forKey:"uuid"); f.candidate["identity"] = .object(identity); XCTAssertEqual(f.validate()["reason"],.string("image_identity"))
    }
    func testUC20_dictionary_order_and_duplicate_key() throws {
        var f=try OutcomeFixture.manual(); let rows=f.candidate.object!; f.candidate = .object(Dictionary(uniqueKeysWithValues:rows.sorted {$0.key < $1.key})); var other=f; other.candidate = .object(Dictionary(uniqueKeysWithValues:rows.sorted {$0.key > $1.key})); XCTAssertEqual(f.candidate,other.candidate)
        XCTAssertEqual(SwiftOutcomeWitnessCodec.canonicalBytes(f.validate()),SwiftOutcomeWitnessCodec.canonicalBytes(other.validate()))
        XCTAssertThrowsError(try SwiftOutcomeWitnessCodec.parse(Data(#"{"status":"unresolved","status":"unresolved"}"#.utf8))) { XCTAssertEqual($0 as? SwiftOutcomeError,SwiftOutcomeError(code:"duplicate_json_key")) }
    }
    func testUC20_unrepresentable_counter() throws {
        var f=try OutcomeFixture.manual(); f.candidate["accounting"]["instructions"] = .integer(Int128(Int.max)+1)
        let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(false)); XCTAssertEqual(r["reason"],.string("candidate_accounting"))
    }
    func testUC21_exact_result_shape() throws {
        let r=try OutcomeFixture.manual().validate()
        let keys: Set<String> = ["model_version","status","reason","eligible","facts","eligibility_scope","value_fact_status","symbolic_return_values_complete","completeness","accounting","runtime_branch_proven","call_return_proven","error_state_proven","source_reconstruction_allowed","handler_semantics_proven","exclusive_entry_proven","limitations","fact_statuses","return_observations","exception_observations","exception_resume_proven","external_exception_handling_unmodeled","region_partition"]
        XCTAssertEqual(Set(r.object!.keys),keys); XCTAssertEqual(r["model_version"],.string("swift-outcome-validation-v2"))
        XCTAssertEqual(Set(r["accounting"].object!.keys),Set(["work","instructions","edges","states","image_initial_work","image_work_charged_here","image_ledger_reused"]))
        XCTAssertNoThrow(try SwiftOutcomeWitnessCodec.preflight(r)); XCTAssertNoThrow(try SwiftOutcomeWitnessCodec.parse(SwiftOutcomeWitnessCodec.canonicalBytes(r)))
    }
    func testUC22_registry_injection() throws {
        XCTAssertNotNil(SwiftOutcomeABIRegistry.frozen.qualification(id:"owned-initial-v1-O-transform-int"))
        let f=try OutcomeFixture.manual(); XCTAssertNil(SwiftOutcomeABIRegistry.frozen.qualification(id:"manual-reviewed")); XCTAssertEqual(f.validate()["eligible"],.bool(true))
        let wrong=SwiftOutcomeABIRegistry([OutcomeFixture.qualification(f.image,digest:"other")])
        XCTAssertEqual(validateBroadSwiftWitness(image:f.image,function:f.function,candidate:f.candidate,registry:wrong)["eligible"],.bool(false))
    }
}
#endif

#if canImport(MacScope)
extension SwiftOutcomeValidatorTests {
    func testUC04b_fresh_admission_word_mutations() throws {
        let cases: [(Int,UInt64)] = [(256,0x94000005),(260,0xb5000055),(264,0xd63f0200),(272,0xd503201f)]
        for (offset,value) in cases {
            var f=try OutcomeFixture.manual(); var data=f.image.data; OutcomeFixture.put(&data,offset,4,value); f.image=OutcomeFixture.image(data)
            f.candidate["identity"]["slice_sha256"] = .string(f.image.sliceSHA256); f.candidate["identity"]["container_sha256"] = .string(f.image.containerSHA256)
            XCTAssertTrue(f.image.hasValidAdmission); XCTAssertEqual(f.validate()["eligible"],.bool(false),"offset \(offset)")
        }
    }
}
#endif

#if canImport(MacScope)
extension SwiftOutcomeValidatorTests {
    // Required-key and .get receiver regressions use literal donor catch results.
    func testUC07_missing_identity_preserves_keyerror_refusal() throws {
        var fixture = try OutcomeFixture.manual()
        var object = try XCTUnwrap(fixture.candidate.object)
        object.removeValue(forKey: "identity"); fixture.candidate = .object(object)
        let result = fixture.validate()
        XCTAssertEqual(result["status"], .string("declined"))
        XCTAssertEqual(result["reason"], .string("malformed_candidate_or_image"))
        XCTAssertEqual(result["eligible"], .bool(false))
        XCTAssertEqual(result["accounting"]["instructions"], .integer(0))
        XCTAssertEqual(result["fact_statuses"]["identity"], .string("unchecked"))
        XCTAssertNil(result.object?["return_observations"])
    }
    func testUC07_missing_post_call_preserves_keyerror_refusal() throws {
        var fixture = try OutcomeFixture.manual()
        var object = try XCTUnwrap(fixture.candidate.object)
        object.removeValue(forKey: "post_call"); fixture.candidate = .object(object)
        let result = fixture.validate()
        XCTAssertEqual(result["status"], .string("declined"))
        XCTAssertEqual(result["reason"], .string("malformed_candidate_or_image"))
        XCTAssertEqual(result["eligible"], .bool(false))
        XCTAssertEqual(result["fact_statuses"]["cfg"], .string("checked"))
        XCTAssertEqual(result["fact_statuses"]["post_call"], .string("unchecked"))
        XCTAssertNil(result.object?["return_observations"])
    }
    func testUC07_nonobject_cfg_preserves_get_receiver_refusal() throws {
        let hostile: [SwiftOutcomeJSON] = [.null, .array([]), .integer(0), .string("cfg")]
        for bad in hostile {
            var fixture = try OutcomeFixture.manual(); fixture.candidate["cfg"] = bad
            let result = fixture.validate()
            XCTAssertEqual(result["status"], .string("declined"))
            XCTAssertEqual(result["reason"], .string("malformed_candidate_or_image"))
            XCTAssertEqual(result["eligible"], .bool(false))
            XCTAssertEqual(result["fact_statuses"]["abi"], .string("checked"))
            XCTAssertEqual(result["fact_statuses"]["cfg"], .string("unchecked"))
            XCTAssertNil(result.object?["return_observations"])
        }
    }
}
#endif

#if canImport(MacScope)
extension SwiftOutcomeValidatorTests {
    func testUC07_nonzero_data_start_index_preserves_raw_reads() throws {
        var fixture = try OutcomeFixture.manual()
        var prefixed = Data([0]); prefixed.append(fixture.image.data)
        let sliced: Data = prefixed.dropFirst()
        XCTAssertEqual(sliced.startIndex, 1)
        fixture.image = OutcomeFixture.image(sliced)
        let result = fixture.validate()
        XCTAssertEqual(result["status"], .string("eligible_structural_only"))
        XCTAssertEqual(result["reason"], .string("independent_bounded_byte_replay"))
        XCTAssertEqual(result["eligible"], .bool(true))
        XCTAssertEqual(result["return_observations"].array?.first?["value"],
                       .array([.string("call_result"), .string("0x1000"), .integer(64)]))
    }
}
#endif
