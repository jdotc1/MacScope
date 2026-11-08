import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope

// Independent direct-seam counterpart of stable_manual_record/check_storage.
enum OutcomeStableHelper {
    static func record(_ key: String, selectedSlice: String = "fresh synthetic non-owned source", entryPC: UInt64 = 0x1020, wordCount: Int = 3) throws -> SwiftOutcomeJSON {
        let r = SwiftOutcomeABIRegistry.frozen
        let cap = try XCTUnwrap(r.stableStorageCapabilities[key])
        return .object([
            "status":.string("admitted"),"profile":.string("swift6-arm64-sync-untyped-stable-research-v2"),
            "error_register":.string("x21"),"research_only":.bool(true),"compiler_verified":.bool(false),
            "profile_assumption":.string("explicit_selected_swift6_stable_arm64_sync_untyped"),
            "result_storage":cap.json,"result_type":.string(key),"result_location":cap.locations.first.map(SwiftOutcomeJSON.string) ?? .null,
            "argument_storage":.array([]),"argument_locations":.array([]),"receiver_location":.null,
            "evidence":.object(["lowering":.object([
                "qualification_id":.string(cap.evidenceID),"source_evidence_id":.string("owned-v2-fixed-initial-lowering-observations"),
                "source_sha256":.string(r.v2Source),"compiler":.string(r.compiler),"target":.string("arm64-apple-macosx14.0"),
                "selected_source_sha256":r.ownedSourceBySlice[selectedSlice].map(SwiftOutcomeJSON.string) ?? .null,
                "selected_slice_sha256":.string(selectedSlice),"reference_slice_sha256":.string(try XCTUnwrap(r.v2Slices.sorted().first)),
                "public_abi_references":.array(r.abiReferences.map(SwiftOutcomeJSON.string)),
                "observations":.array(r.stableLoweringObservations.map { .object(["pc":.string("0x"+String($0.pc,radix:16)),"raw_bytes":.string($0.bytesHex),"meaning":.string($0.note),"source_case":.string($0.sourceCase)]) }),
                "specialization":.null,"assumption":.string("explicit_selected_swift6_stable_arm64_sync_untyped"),"compiler_verified":.bool(false),
                "error_object_type_proven":.bool(false),"callee_error_transport_observation":.string("mov_to_x21_from_distinct_nonzero_gpr_presence"),
                "callee_error_observation":.object(["mode":.string("distinct_nonzero_gpr_copy"),"register":.string("x21"),
                    "scope":.string("instruction_effects_if_normal_return_not_incoming_state_or_object_type"),
                    "entry_pc":.string("0x"+String(entryPC,radix:16)),"return_pc":.null,"word_count":.integer(Int128(wordCount)),
                    "preserves_incoming_x21":.null,"incoming_state_proven":.bool(false),"error_object_type_proven":.bool(false)])])])])
    }
    static func check(_ key: String, _ words: [UInt32], mutate: (inout SwiftOutcomeJSON) throws -> Void = { _ in }) throws -> (storage: SwiftOutcomeJSON, callerErrorState: SwiftOutcomeJSON) {
        let parsed = try XCTUnwrap(parseBroadSwiftDeclaration("_$s4Test3fooyS2iKF").identity)
        let node: SwiftBroadType
        if key == "Optional<Swift.Int>" { node = SwiftBroadType("Optional",arguments:[SwiftBroadType("Swift.Int")]) }
        else if key == "Tuple<Swift.Int,Swift.Bool>" { node = SwiftBroadType("Tuple",arguments:[SwiftBroadType("Swift.Int"),SwiftBroadType("Swift.Bool")]) }
        else { node = SwiftBroadType(key) }
        let decl = SwiftBroadCallableIdentity(symbol:parsed.symbol,module:parsed.module,context:parsed.context,
            callableKind:parsed.callableKind,functionName:parsed.functionName,parameterLabels:parsed.parameterLabels,
            parameterTypes:[],resultType:node,throwsFlag:parsed.throwsFlag,genericParameterCounts:parsed.genericParameterCounts,
            genericRequirements:parsed.genericRequirements,originalCallableKind:parsed.originalCallableKind,specialization:parsed.specialization)
        let caller = SwiftErrorFlowFunction(start:0x1000,endExclusive:0x1010,boundarySource:"lc_function_starts")
        let callee = SwiftErrorFlowFunction(start:0x1020,endExclusive:UInt64(0x1020+4*words.count),boundarySource:"lc_function_starts")
        var raw = Data(repeating:0,count:4*words.count)
        for (i,word) in words.enumerated() { OutcomeFixture.put(&raw,4*i,4,UInt64(word)) }
        let image = SwiftOutcomeValidatorImage.unadmitted(data:raw,path:"direct stable seam",sliceSHA256:"fresh synthetic non-owned source",containerSHA256:"unused",architecture:"arm64",cpuSubtype:0,uuid:nil,fileType:2,preferredBase:0,sliceOffset:0,sliceSize:UInt64(raw.count),sliceIndex:nil,containerSliceCount:nil,sections:[],functions:[caller,callee])
        var abi = try record(key,wordCount:words.count); try mutate(&abi)
        let result = try validateSwiftOutcomeStableABI(image:image,function:caller,callee:callee,callPC:0x1004,declaration:decl,abi:abi,
            read: { pc,n in
                let offset = pc-0x1020
                guard offset >= 0 && n >= 0 && offset <= raw.count-n else { throw SwiftOutcomeValidatorStop(reason:"test_extent",status:"unresolved") }
                return raw.subdata(in:offset..<offset+n)
            },mapped: { pc,_ in Int(pc) },instruction: { pc in try decodeSwiftOutcomeInstruction(word:0xd2800015,address:pc) },charge:{ _ in },limits:BroadWitnessLimits())
        XCTAssertEqual(result.storage,try XCTUnwrap(SwiftOutcomeABIRegistry.frozen.stableStorageCapabilities[key]).json)
        XCTAssertEqual(result.callerErrorState,.string("unproven_profile_precondition"))
        return result
    }
}

final class SwiftOutcomeValidatorHelperTests: XCTestCase {
    private func refuses(_ body: () throws -> Void) {
        XCTAssertThrowsError(try body()) { XCTAssertTrue($0 is SwiftOutcomeValidatorStop) }
    }
    func testUC24_eight_distinct_selected_storage_forms_independent_raw_patterns() throws {
        let cases: [(String,[UInt32])] = [("Swift.Void",[0xaa0003f5,0xd65f03c0]),("Swift.Int8",[0xaa0003f5,0x52800020,0xd65f03c0]),
            ("Swift.UInt16",[0xaa0003f5,0x52800040,0xd65f03c0]),("Swift.Int64",[0xaa0003f5,0xd2800060,0xd65f03c0]),
            ("Swift.Bool",[0xaa0003f5,0x52800020,0xd65f03c0]),("Swift.Float",[0xaa0003f5,0x1e270000,0xd65f03c0]),
            ("Swift.Double",[0xaa0003f5,0x9e620000,0xd65f03c0]),("Optional<Swift.Int>",[0xaa0003f5,0xd2800020,0x52800001,0xd65f03c0]),
            ("Tuple<Swift.Int,Swift.Bool>",[0xaa0003f5,0xd2800020,0x52800001,0xd65f03c0])]
        for (key,words) in cases { _ = try OutcomeStableHelper.check(key,words) }
    }
    func testUC24_forged_storage_profile_and_source_evidence_refused() {
        let attacks: [([String],SwiftOutcomeJSON)] = [(["compiler_verified"],.bool(true)),(["result_storage","bit_width"],.integer(64)),
            (["evidence","lowering","source_sha256"],.string("forged")),(["evidence","lowering","qualification_id"],.string("caller-made")),
            (["evidence","lowering","observations"],.array([]))]
        for (path,value) in attacks { refuses { _ = try OutcomeStableHelper.check("Swift.Int8",[0xaa0003f5,0x52800020,0xd65f03c0]) { OutcomeFixture.assign(&$0,path,value) } } }
    }
    func testUC24_frozen_compiler_and_target_evidence_are_exact_metadata() throws {
        _ = try OutcomeStableHelper.check("Swift.Int16",[0xaa0003f5,0x52800020,0xd65f03c0])
        for (key,value) in [("compiler","caller-made"),("target","arm64e-apple-macosx14.0")] {
            refuses { _ = try OutcomeStableHelper.check("Swift.Int16",[0xaa0003f5,0x52800020,0xd65f03c0]) { $0["evidence"]["lowering"][key] = .string(value) } }
        }
    }
    func testUC24_presence_preconditions_and_family_are_checked_without_semantic_upgrade() throws {
        func selected(_ abi: inout SwiftOutcomeJSON) {
            abi["profile_preconditions"] = .array(["well_formed_swift_stable_arm64_calling_convention","synchronous_untyped_throws","caller_supplies_error_register_state_required_by_convention"].map(SwiftOutcomeJSON.string))
            abi["family"] = .string("free")
            abi["family_evidence"] = .object(["source_sha256":.null,"compiled_target_pc":.string("0x1020"),"direct_call_pc":.string("0x1004"),"scope":.string("source_lineage_plus_exact_emitted_target_not_runtime_dispatch")])
            abi["caller_error_observations"] = .object(["clear_instruction_pcs":.array([.string("0x1000")]),"test_instruction_pcs":.array([]),"incoming_state_proven":.bool(false),"scope":.string("instruction_presence_not_path_or_state_proof")])
        }
        _ = try OutcomeStableHelper.check("Swift.Int32",[0xaa0003f5,0x52800020,0xd65f03c0],mutate:selected)
        let attacks: [(String,SwiftOutcomeJSON)] = [("profile_preconditions",.array([])),("family",.string("extension"))]
        for (key,value) in attacks {
            refuses { _ = try OutcomeStableHelper.check("Swift.Int32",[0xaa0003f5,0x52800020,0xd65f03c0]) { selected(&$0); $0[key] = value } }
        }
    }
    func testUC24_result_and_error_transport_are_separate_required_byte_facts() {
        for words in [[0xd2800020,0xd65f03c0],[0xaa0003f5,0xd65f03c0]] as [[UInt32]] { refuses { _ = try OutcomeStableHelper.check("Swift.Int64",words) } }
    }
    func testUC24_precall_frame_alias_cannot_overwrite_main_call_result_seed() throws {
        let f = try OutcomeFixture.expanded([(0x910003e0,"add"),(0,"bl"),(0xb4000055,"xcbz"),(0xd65f03c0,"ret"),(0xd65f03c0,"ret")],branches:[2:[4,3]],success:4,error:3,callIndex:1)
        let r = f.validate(); XCTAssertEqual(r["eligible"],.bool(true))
        XCTAssertEqual(r["return_observations"].array?.first?["value"],.array([.string("call_result"),.string("0x1004"),.integer(64)]))
    }
    func testUC24_opaque_call_does_not_preserve_sp_origin() throws {
        let state = SwiftOutcomeScalarReplay(callPC:0x1000,limits:BroadWitnessLimits())
        for word in [0x94000001,0x910003e0] as [UInt32] { try state.step(decodeSwiftOutcomeInstruction(word:word,address:0x1004)) }
        XCTAssertNil(state.stackPointer); XCTAssertNil(state.registers[0])
    }
    func testUC24_retained_expression_budget_is_charged_before_append() throws {
        var tree: SwiftOutcomeJSON = .array([.string("call_result"),.string("0x1000"),.integer(64)])
        for _ in 0..<8 { tree = .array([.string("add"),tree,tree,.integer(64)]) }
        let limits = try BroadWitnessLimits(maxBytes:1000)
        refuses { _ = try swiftOutcomeRetentionCost(tree,limits:limits) }
    }
    func testUC25_original_three_formal_registers_are_used_before_control() throws {
        XCTAssertTrue(try swiftOutcomeFormalPrefixInputs([0xa9be4ff4,0x910003fd,0x92400009,0x8b210129,0x8b020134,0x540001ca],locations:["x0","w1","x2"]))
    }
    func testUC25_clobbered_formal_register_is_not_recovered_from_later_use() throws {
        XCTAssertFalse(try swiftOutcomeFormalPrefixInputs([0xd2800002,0x92400009,0x8b210129,0x8b020134],locations:["x0","w1","x2"]))
    }
    func testUC25_simd_store_data_cannot_attest_integer_formals() throws {
        XCTAssertFalse(try swiftOutcomeFormalPrefixInputs([0x3d8003e0,0x3d8007e1,0xd65f03c0],locations:["x0","x1"]))
    }
    func testUC25_signed_load_is_destination_write_not_source_store() {
        let e = swiftOutcomePrefixOperandEffects(0x398003e0)
        XCTAssertFalse(e.reads.contains(0)); XCTAssertTrue(e.writes.contains(0)); XCTAssertTrue(e.known)
    }
    func testUC25_memory_writeback_invalidates_base_origin() {
        for word in [0xf8410401,0xa8c10401] as [UInt32] { XCTAssertTrue(swiftOutcomePrefixOperandEffects(word).writes.contains(0)) }
    }
    func testUC25_bc_cond_stops_physical_formal_walk() throws {
        XCTAssertFalse(try swiftOutcomeFormalPrefixInputs([0x54000010,0xaa0003e1],locations:["x0"]))
    }
    func testUC25_unknown_instruction_stops_prefix_instead_of_preserving_unseen_inputs() throws {
        XCTAssertFalse(try swiftOutcomeFormalPrefixInputs([0xffffffff,0xaa0003e1],locations:["x0"]))
    }
    func testUC25_self_and_zero_error_moves_do_not_corroborate_object_transport() {
        XCTAssertFalse(swiftOutcomeIsErrorTransportInstruction(0xaa1503f5)); XCTAssertFalse(swiftOutcomeIsErrorTransportInstruction(0xaa1f03f5)); XCTAssertTrue(swiftOutcomeIsErrorTransportInstruction(0xaa0003f5))
    }
    func testUC25_only_store_encodings_corroborate_indirect_result_buffer() {
        for word in [0xf9800100,0x39800100,0x39c00100,0xf9400100,0x3dc00100] as [UInt32] { XCTAssertFalse(swiftOutcomeIsDirectResultStore(word)) }
        for word in [0xf9000100,0x39000100,0xa9000500,0x3d800100] as [UInt32] { XCTAssertTrue(swiftOutcomeIsDirectResultStore(word)) }
    }
    func testUC25_visible_zero_does_not_promote_suffix_to_dominance_proof() throws {
        let f = try OutcomeFixture.stable(); let r = f.validate()
        XCTAssertEqual(r["eligible"],.bool(true)); XCTAssertEqual(r["caller_error_state"],.string("unproven_profile_precondition")); XCTAssertEqual(r["error_state_proven"],.bool(false))
    }
    func testUC25_non_sp_writeback_does_not_establish_formal_prefix_evidence() throws {
        XCTAssertFalse(try swiftOutcomeFormalPrefixInputs([0xf8410401,0xaa0003e2],locations:["x0"]))
    }
    func testUC25_result_store_qualification_excludes_writeback_and_pair_load() {
        for word in [0xa9400500,0xa9800500,0xa8800500] as [UInt32] { XCTAssertFalse(swiftOutcomeIsDirectResultStore(word)) }
    }
    func testUC25_reserved_integer_encodings_cannot_attest_formal_reads() throws {
        for word in [0x0b00fc00,0x8bc00000,0x8b201c00,0x0b206000,0x11800000,0x73400000,0x33008000,0x32800000,0x52c00000,0x12400000,0x1200fc00,0x0a008000] as [UInt32] {
            XCTAssertFalse(swiftOutcomePrefixOperandEffects(word).known)
            XCTAssertFalse(try swiftOutcomeFormalPrefixInputs([word,0xaa0003e1],locations:["x0"]))
        }
    }
    func testUC25_allocated_nonflag_shift_and_extend_forms_keep_real_inputs() throws {
        for word in [0x0b007c01,0x8b00fc01,0x8b201001,0x0a00fc01|0x80000000] as [UInt32] { XCTAssertTrue(try swiftOutcomeFormalPrefixInputs([word],locations:["x0"])) }
    }
    func testUC25_reserved_memory_operand_forms_do_not_attest_input() {
        for word in [0x39c00100|0x80000000,0x7d800100,0xec000100,0x68000500] as [UInt32] { XCTAssertFalse(swiftOutcomePrefixOperandEffects(word).known) }
    }
    func testUC26_exact_authored_leaf_preserves_only_the_register_not_its_input_value() throws {
        XCTAssertTrue(try swiftOutcomeIndependentLeafPreservesX21([0x7200005f,0x528000a3,0x1a850083,0x0b020060,0xd65f03c0]))
    }
    func testUC26_leaf_predicate_refuses_controls_unknown_and_every_gpr21_write() throws {
        for word in [0x14000000,0x94000000,0x54000000,0xd4200020,0xffffffff,0x0b00fc00,0xd2800015,0x1e260015,0xf94007f5,0xa94057f4,0xf8008ea0] as [UInt32] { XCTAssertFalse(try swiftOutcomeIndependentLeafPreservesX21([word,0xd65f03c0])) }
        XCTAssertFalse(try swiftOutcomeIndependentLeafPreservesX21([0xd65f03c0,0xd65f03c0]))
    }
    func testUC26_fp21_and_integer_store21_are_reads_of_different_banks() throws {
        // ar4a refuses FP forms (decoder_form_missing), so the leaf check fails closed instead of proving x21 preserved.
        XCTAssertFalse(try swiftOutcomeIndependentLeafPreservesX21([0x1e270015,0xf90007f5,0xd65f03c0]))
    }
    func testUC26_copy_mode_metadata_cannot_claim_leaf_or_incoming_state() throws {
        let words: [UInt32] = [0xaa0003f5,0x528002e0,0xd65f03c0]
        _ = try OutcomeStableHelper.check("Swift.UInt32",words)
        let attacks: [(String,SwiftOutcomeJSON)] = [("mode",.string("preserved_x21_leaf")),("return_pc",.string("0x1028")),("preserves_incoming_x21",.bool(true)),("incoming_state_proven",.bool(true)),("word_count",.integer(2))]
        for (key,value) in attacks { refuses { _ = try OutcomeStableHelper.check("Swift.UInt32",words) { $0["evidence"]["lowering"]["callee_error_observation"][key] = value } } }
    }
    func testUC26_leaf_error_observation_is_independently_recomputed_and_scope_checked() throws {
        func leaf(_ abi: inout SwiftOutcomeJSON) {
            abi["evidence"]["lowering"]["callee_error_observation"] = .object(["mode":.string("preserved_x21_leaf"),"register":.string("x21"),"scope":.string("instruction_effects_if_normal_return_not_incoming_state_or_object_type"),"entry_pc":.string("0x1020"),"return_pc":.string("0x1024"),"word_count":.integer(2),"preserves_incoming_x21":.bool(true),"incoming_state_proven":.bool(false),"error_object_type_proven":.bool(false)])
            abi["evidence"]["lowering"]["callee_error_transport_observation"] = .string("x21_preserved_by_exact_straightline_leaf_effects")
        }
        _ = try OutcomeStableHelper.check("Swift.Int",[0xd2800060,0xd65f03c0],mutate:leaf)
        refuses { _ = try OutcomeStableHelper.check("Swift.Int",[0xd2800060,0xd65f03c0]) { leaf(&$0); $0["evidence"]["lowering"]["callee_error_observation"]["incoming_state_proven"] = .bool(true) } }
    }
}
#endif
