import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope
extension OutcomeFixture {
    static func stableRecord(_ key: String, selectedSlice: String = "fresh synthetic non-owned source", entryPC: UInt64 = 0x1020, wordCount: Int = 3) -> SwiftOutcomeJSON {
        let r=SwiftOutcomeABIRegistry.frozen; let storage=r.stableStorageCapabilities[key]!
        let observation: SwiftOutcomeJSON = .object(["mode":.string("distinct_nonzero_gpr_copy"),"register":.string("x21"),"scope":.string("instruction_effects_if_normal_return_not_incoming_state_or_object_type"),"entry_pc":.string("0x"+String(entryPC,radix:16)),"return_pc":.null,"word_count":.integer(Int128(wordCount)),"preserves_incoming_x21":.null,"incoming_state_proven":.bool(false),"error_object_type_proven":.bool(false)])
        let lower: SwiftOutcomeJSON = .object([
            "qualification_id":.string(storage.evidenceID),"source_evidence_id":.string("owned-v2-fixed-initial-lowering-observations"),"source_sha256":.string(r.v2Source),"compiler":.string(r.compiler),"target":.string("arm64-apple-macosx14.0"),"selected_source_sha256":r.ownedSourceBySlice[selectedSlice].map { .string($0) } ?? .null,"selected_slice_sha256":.string(selectedSlice),"reference_slice_sha256":.string(r.v2Slices.sorted()[0]),"public_abi_references":.array(r.abiReferences.map { .string($0) }),
            "observations":.array(r.stableLoweringObservations.map { .object(["pc":.string("0x"+String($0.pc,radix:16)),"raw_bytes":.string($0.bytesHex),"meaning":.string($0.note),"source_case":.string($0.sourceCase)]) }),"specialization":.null,"assumption":.string("explicit_selected_swift6_stable_arm64_sync_untyped"),"compiler_verified":.bool(false),"error_object_type_proven":.bool(false),"callee_error_transport_observation":.string("mov_to_x21_from_distinct_nonzero_gpr_presence"),"callee_error_observation":observation])
        return .object(["status":.string("admitted"),"profile":.string("swift6-arm64-sync-untyped-stable-research-v2"),"error_register":.string("x21"),"research_only":.bool(true),"compiler_verified":.bool(false),"profile_assumption":.string("explicit_selected_swift6_stable_arm64_sync_untyped"),"result_storage":storage.json,"result_type":.string(key),"result_location":storage.locations.first.map { .string($0) } ?? .null,"argument_storage":.array([]),"argument_locations":.array([]),"receiver_location":.null,"evidence":.object(["lowering":lower])])
    }
    static func stable(prefix: UInt32 = 0xd2800015) throws -> Value {
        var f=try expanded([(prefix,prefix == 0xd503201f ? "nop" : "movz"),(0,"bl"),(0xb4000055,"xcbz"),(0xd65f03c0,"ret"),(0xd65f03c0,"ret")],branches:[2:[4,3]],success:4,error:3,callIndex:1)
        var data=f.image.data; let target=f.image.functions[1].start
        for (i,w) in [UInt32(0xaa0003f5),0xd2800020,0xd65f03c0].enumerated() { put(&data,256+Int(target-0x1000)+4*i,4,UInt64(w)) }
        f.image=image(data,count:5); f.candidate["identity"]["slice_sha256"] = .string(f.image.sliceSHA256); f.candidate["identity"]["container_sha256"] = .string(f.image.containerSHA256)
        f.candidate["call"]["provenance"]["callee_entry"]["word"] = .string("0xaa0003f5")
        f.candidate["call"]["abi"] = stableRecord("Swift.Int",selectedSlice:f.image.sliceSHA256,entryPC:target,wordCount:4)
        f.candidate["value_facts"]["seed"]["origin"] = .string("raw_post_call_register:x21")
        f.candidate["call"]["abi"]["argument_storage"] = .array([.object(["type":.string("Swift.Int"),"locations":.array([.string("x0")]),"evidence_id":.string("swift-stable-v2-int"),"inout":.bool(false)])])
        f.candidate["call"]["abi"]["argument_locations"] = .array([.array([.string("x0")])]); finish(&f.candidate); return f
    }
}
final class SwiftOutcomeValidatorStableTests: XCTestCase {
    func testUC24_selected_stable_rule_is_independently_checked_end_to_end() throws {
        let r=try OutcomeFixture.stable().validate(); XCTAssertEqual(r["eligible"],.bool(true)); XCTAssertEqual(r["compiler_verified"],.bool(false)); XCTAssertEqual(r["call_return_proven"],.bool(false)); XCTAssertEqual(r["abi_assumption"],.string("explicit_selected_swift6_stable_arm64_sync_untyped"))
    }
    func testUC24_unknown_incoming_state_permits_only_explicit_conditional_roles() throws {
        let r=try OutcomeFixture.stable(prefix:0xd503201f).validate(); XCTAssertEqual(r["eligible"],.bool(true)); XCTAssertEqual(r["caller_error_state"],.string("unproven_profile_precondition")); XCTAssertEqual(r["outcome_scope"],.string("byte_zero_nonzero_geometry_with_conditional_abi_roles")); XCTAssertTrue(r["outcome_preconditions"].array!.contains(.string("incoming_x21_zero_required_by_selected_convention"))); XCTAssertEqual(r["error_state_proven"],.bool(false)); XCTAssertEqual(r["runtime_branch_proven"],.bool(false))
    }
    func testUC24_known_nonzero_incoming_state_is_contradictory() throws {
        let r=try OutcomeFixture.stable(prefix:0xd2800035).validate(); XCTAssertEqual(r["eligible"],.bool(false)); XCTAssertEqual(r["status"],.string("blocked")); XCTAssertEqual(r["reason"],.string("caller_error_contract_contradiction"))
    }
    func testUC24_old_semantic_seed_cannot_validate_under_selected_stable_profile() throws {
        var f=try OutcomeFixture.stable(); XCTAssertEqual(f.candidate["value_facts"]["seed"]["origin"],.string("raw_post_call_register:x21")); f.candidate["value_facts"]["seed"]["origin"] = .string("abi_post_call_error:x21")
        let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(false)); XCTAssertEqual(r["reason"],.string("value_seed"))
    }
    private func privateWeak(kind: UInt64 = 0x1e, desc: UInt64 = 0x80, aliases: Int = 1) throws -> OutcomeFixture.Value {
        var f=try OutcomeFixture.manual(); var data=f.image.data
        let symbol="_$s10BroadOwned0A9Owner0363V15broad_case_0363ySis5Int32V_s6UInt64VSixtKSzRzlFZSi_Tt3g5"
        OutcomeFixture.text(&data,769,symbol+"\0"); OutcomeFixture.put(&data,204,4,UInt64(symbol.utf8.count+2)); OutcomeFixture.put(&data,196,4,UInt64(aliases))
        for i in 0..<aliases { let offset=512+16*i; OutcomeFixture.put(&data,offset,4,1); OutcomeFixture.put(&data,offset+4,1,kind); OutcomeFixture.put(&data,offset+5,1,1); OutcomeFixture.put(&data,offset+6,2,desc); OutcomeFixture.put(&data,offset+8,8,0x1010) }
        for i in 0..<4 { data[960+i]=data[900+i] }; OutcomeFixture.put(&data,216,4,960)
        f.image=OutcomeFixture.image(data); f.candidate["identity"]["slice_sha256"] = .string(f.image.sliceSHA256); f.candidate["identity"]["container_sha256"] = .string(f.image.containerSHA256)
        f.candidate["call"]["declaration"] = .object(["status":.string("syntax_admitted"),"identity":parseBroadSwiftDeclaration(symbol).identity?.json ?? .null,"reason":.null]); return f
    }
    func testUC26_sole_raw_private_weak_specialization_reaches_independent_abi_check() throws {
        let r=try privateWeak().validate(); XCTAssertEqual(r["facts"]["call"],.string("checked_direct_target_and_exact_symbol_syntax")); XCTAssertEqual(r["eligible"],.bool(false)); XCTAssertEqual(r["reason"],.string("abi_tuple_identity"))
    }
    func testUC26_other_visibility_and_all_entry_aliases_remain_rejected() throws {
        let cases: [(UInt64,UInt64,Int,String)] = [(0x1e,0,1,"symbol_visibility"),(0x1f,0x80,1,"symbol_visibility"),(0x1e,0x80,2,"symbol_aliases")]
        for (kind,desc,aliases,reason) in cases { let r=try privateWeak(kind:kind,desc:desc,aliases:aliases).validate(); XCTAssertEqual(r["eligible"],.bool(false)); XCTAssertEqual(r["reason"],.string(reason)) }
    }
    func testUC26_unmodeled_value_operator_has_raw_diagnostic_within_result_cap() throws {
        let f=try OutcomeFixture.expanded([(0,"bl"),(0xb4000075,"xcbz"),(0x9ac00800,"xudiv"),(0xd65f03c0,"ret"),(0xd65f03c0,"ret")],branches:[1:[4,2]],success:4,error:2)
        let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(false)); XCTAssertEqual(r["reason"],.string("value_transfer_unqualified")); XCTAssertEqual(r["unresolved_instruction"],.object(["pc":.string("0x1008"),"word":.string("0x9ac00800"),"kind":.string("xudiv")]))
        XCTAssertLessThanOrEqual(Data(SwiftOutcomeWitnessCodec.render(r,spaced:true).utf8).count,BroadWitnessLimits().maxBytes)
    }
    func testUC26_unknown_constant_writeback_return_is_explicit_unknown() throws {
        let f=try OutcomeFixture.expanded([(0,"bl"),(0xb4000055,"xcbz"),(0xd65f03c0,"ret"),(0xd284001d,"movz"),(0xa8c10ba1,"ldp"),(0xaa1d03e0,"mov"),(0xd65f03c0,"ret")],branches:[1:[3,2]],success:3,error:2)
        let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(true)); let success=r["return_observations"].array!.first {$0["arm"] == .string("success")}!
        XCTAssertEqual(success["value"],.array([.string("unknown"),.integer(64)])); XCTAssertEqual(success["raw_error_register_value"],.array([.string("error_result"),.string("0x1000"),.integer(64)])); XCTAssertEqual(success["runtime_propagation_proven"],.bool(false)); XCTAssertEqual(success["source_handler_proven"],.bool(false))
    }
    func testUC26_writeback_error_alias_cannot_qualify_selected_zero_test() throws {
        var f=try OutcomeFixture.expanded([(0,"bl"),(0xaa1503fd,"mov"),(0xa8c10ba1,"ldp"),(0xb400005d,"xcbz"),(0xd65f03c0,"ret"),(0xd65f03c0,"ret")],branches:[3:[5,4]],success:5,error:4)
        f.candidate["post_call"]["test_register"] = .string("x29"); let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(false)); XCTAssertEqual(r["reason"],.string("error_register_alias"))
    }
}
#endif
