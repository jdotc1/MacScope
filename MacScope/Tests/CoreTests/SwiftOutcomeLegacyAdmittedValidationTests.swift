import Foundation
import XCTest
@testable import MacScope

final class SwiftOutcomeLegacyAdmittedValidationTests: XCTestCase {
    private struct Fixture {
        var bytes: Data
        var witness: SwiftOutcomeJSON
        let caller = SwiftErrorFlowFunction(start: 0x1000,endExclusive: 0x1040,boundarySource: "lc_function_starts")
        var image: SwiftOutcomeLegacyAdmittedImage {
            SwiftOutcomeLegacyAdmittedImage(data: bytes,sliceSHA256: "owned-slice",containerSHA256: "owned-container",architecture: "arm64",cpuSubtype: 0,uuid: "owned-uuid",sliceOffset: 0x200,sliceSize: 512,preferredBase: 0xf00,
                sections: [.init(address: 0x1000,size: 68,fileOffset: 0x100,executable: true,flags: 0,segment: "__TEXT",name: "__text")],
                functions: [caller,.init(start: 0x1040,endExclusive: 0x1044,boundarySource: "lc_function_starts")])
        }
        func validate(limits: WitnessLimits = WitnessLimits()) -> SwiftOutcomeJSON {
            validateSwiftOutcomeLegacyAdmitted(image: image,function: caller,witness: witness,limits: limits)
        }
    }
    private func put(_ bytes: inout Data,_ offset: Int,_ value: UInt64,_ count: Int = 4) {
        for i in 0..<count { bytes[offset + i] = UInt8(truncatingIfNeeded: value >> (i * 8)) }
    }
    private func fixture() -> Fixture {
        // Literal already-admitted selected slice. No Mach-O loader is invoked.
        var bytes = Data(repeating: 0,count: 512)
        put(&bytes,0,0xfeedfacf); put(&bytes,4,0x0100000c); put(&bytes,16,1); put(&bytes,20,24)
        put(&bytes,32,2); put(&bytes,36,24); put(&bytes,40,0x180); put(&bytes,44,2); put(&bytes,48,0x1a0); put(&bytes,52,64)
        let words: [UInt32] = [0x94000010,0xb40000b5,0xaa1503e0,0x94000010,0x92800000,0x14000002,0xd2800000,0xa9427bfd,0xa94157f6,0x9100c3ff,0xd65f03c0,0xd65f03c0,0xd65f03c0,0xd65f03c0,0xd65f03c0,0xd65f03c0,0xd65f03c0]
        for (i,word) in words.enumerated() { put(&bytes,0x100 + i * 4,UInt64(word)) }
        // Two literal nlist_64 rows, both N_SECT|N_EXT in section 1.
        put(&bytes,0x180,1); put(&bytes,0x184,15,1); put(&bytes,0x185,1,1); put(&bytes,0x188,0x1000,8)
        put(&bytes,0x190,24); put(&bytes,0x194,15,1); put(&bytes,0x195,1,1); put(&bytes,0x198,0x1040,8)
        let callerName = Array("_$s4Demo6handleyS2iF".utf8), calleeName = Array("_$s4Demo5parseyS2iKF".utf8)
        for (i,b) in callerName.enumerated() { bytes[0x1a1 + i] = b }
        for (i,b) in calleeName.enumerated() { bytes[0x1b8 + i] = b }
        func row(_ pc: String,_ word: String,_ kind: String) -> SwiftOutcomeJSON { .object(["pc": .string(pc),"word": .string(word),"kind": .string(kind)]) }
        var errorCall = row("0x100c","0x94000010","bl"); errorCall["call_target_pc"] = .string("0x104c"); errorCall["semantics"] = .string("opaque_call")
        var jump = row("0x1014","0x14000002","b"); jump["target_pc"] = .string("0x101c")
        let errors = [row("0x1008","0xaa1503e0","mov"),errorCall,row("0x1010","0x92800000","movn"),jump]
        let success = [row("0x1018","0xd2800000","movz")]
        let tail = [row("0x101c","0xa9427bfd","ldp"),row("0x1020","0xa94157f6","ldp"),row("0x1024","0x9100c3ff","add"),row("0x1028","0xd65f03c0","ret")]
        let ledger: SwiftOutcomeJSON = .object(["caller_scan_complete": .bool(true),"scanned_word_count": .integer(16),"status": .string("no_unexpected_direct_entries"),"unexpected_entry_count": .integer(0),"unclassified_word_count": .integer(0),"unexpected_entries": .array([]),"unclassified_words": .array([]),"entry_details_complete": .bool(true),"unclassified_details_complete": .bool(true)])
        let region: SwiftOutcomeJSON = .object(["status": .string("structural_region_candidate"),"start_pc": .string("0x1008"),"end_pc_exclusive": .string("0x1018"),"join_pc": .string("0x101c"),"instructions": .array(errors),"call_return_proven": .bool(false),"join_reachability_proven": .bool(false),"opaque_call_count": .integer(1),"incoming_validation": ledger,
            "success_interval": .object(["start_pc": .string("0x1018"),"end_pc_exclusive": .string("0x101c"),"instructions": .array(success)]),
            "shared_epilogue": .object(["start_pc": .string("0x101c"),"end_pc_exclusive": .string("0x102c"),"restore_state_proven": .bool(false),"instructions": .array(tail)])])
        func fact(_ path: String,_ bits: String,_ rows: [SwiftOutcomeJSON]) -> SwiftOutcomeJSON {
            .object(["status": .string("constant_register_candidate"),"call_pc": .string("0x1000"),path + "_pc": .string(path == "error" ? "0x1008" : "0x1018"),"return_pc": .string("0x1028"),"register": .string("x0"),"bit_width": .integer(64),"constant_bits": .string(bits),"source_reconstruction_allowed": .bool(false),"runtime_value_proven": .bool(false),"exclusive_path_proven": .bool(false),"caller_return_type_proven": .bool(false),"instructions": .array(rows)])
        }
        let sc = fact("success","0x0000000000000000",success + tail), ec = fact("error","0xffffffffffffffff",errors + tail)
        func descriptor(_ bits: String) -> SwiftOutcomeJSON { .object(["kind": .string("constant_bits"),"bit_width": .integer(64),"constant_bits": .string(bits)]) }
        let condition: SwiftOutcomeJSON = .object(["test_pc": .string("0x1004"),"register": .string("x21"),"error_when": .string("nonzero")])
        let choice: SwiftOutcomeJSON = .object(["status": .string("structural_choice_candidate"),"call_pc": .string("0x1000"),"return_pc": .string("0x1028"),"condition": condition,"success": descriptor("0x0000000000000000"),"error": descriptor("0xffffffffffffffff"),"same_constant_bits": .bool(false),"source_reconstruction_allowed": .bool(false),"runtime_value_proven": .bool(false),"exclusive_path_proven": .bool(false),"caller_return_type_proven": .bool(false),"call_return_proven": .bool(false),"handler_semantics_proven": .bool(false)])
        let callee: SwiftOutcomeJSON = .object(["symbol": .string("_$s4Demo5parseyS2iKF"),"image_offset": .string("0x140"),"module": .string("Demo"),"name": .string("parse"),"parameters": .array([.string("Swift.Int")]),"result": .string("Swift.Int"),"convention": .string("swift_sync_untyped_throws"),"error_register": .string("x21"),"source": .string("exact_external_symbol_grammar")])
        let unused: SwiftOutcomeJSON = .object(["status": .string("declined"),"source_reconstruction_allowed": .bool(false),"runtime_value_proven": .bool(false),"exclusive_path_proven": .bool(false),"caller_return_type_proven": .bool(false),"instructions": .array([])])
        let c: SwiftOutcomeJSON = .object(["status": .string("recovered_candidate"),"caller_pc": .string("0x1000"),"call_pc": .string("0x1000"),"call_image_offset": .string("0x100"),"call_word": .string("0x94000010"),"callee_pc": .string("0x1040"),"callee": callee,"test_pc": .string("0x1004"),"success_pc": .string("0x1018"),"error_pc": .string("0x1008"),"tested_register": .string("x21"),"window": .array([row("0x1004","0xb40000b5","xcbz")]),"error_region": region,"success_constant": sc,"error_constant": ec,"success_result": unused,"return_choice": choice])
        let nodes: [SwiftOutcomeJSON] = [("call","0x1000"),("test","0x1004"),("success","0x1018"),("error","0x1008"),("join","0x101c")].map { .object(["id": .string($0.0),"pc": .string($0.1)]) }
        let edges: [SwiftOutcomeJSON] = [("call","test","0x1000"),("test","success","0x1004"),("test","error","0x1004"),("error","join","0x1014"),("success","join","0x1018")].map { .object(["from": .string($0.0),"to": .string($0.1),"provenance_pc": .string($0.2),"relationship": .string("recorded_structural")]) }
        var f = Fixture(bytes: bytes,witness: .null)
        // Literal source models, independent of the implementation's model helper.
        let sources: SwiftOutcomeJSON = .object(["edge": .string("swift-sync-error-edges-v37"),"return_choice": .string("swift-return-choice-v45"),"region": .string("swift-sync-error-region-v24"),"incoming": .string("swift-region-direct-entries-v7"),"presentation": .string("swift-structural-presentation-v10"),"success_result": .string("swift-success-result-v24"),"success_constant": .string("swift-success-constant-v17"),"error_constant": .string("swift-error-constant-v19"),"flag_entry": .string("swift-compare-flag-entries-v1")])
        // Literal donor identity record, independent of the adapter helper.
        let identity: SwiftOutcomeJSON = .object([
            "architecture": .string("arm64"), "cpu_subtype": .integer(0),
            "uuid": .string("owned-uuid"), "slice_sha256": .string("owned-slice"),
            "container_sha256": .string("owned-container"), "slice_offset": .integer(512),
            "slice_size": .integer(512), "preferred_base": .string("0xf00")])
        f.witness = .object(["schema_version": .integer(1),"model_version": .string("swift-outcome-witness-v1"),"validation_model_version": .string("swift-outcome-validation-v1"),"model_profile": .string("legacy"),"source_models": sources,"image": identity,"caller": .object(["start_pc": .string("0x1000"),"end_pc_exclusive": .string("0x1040"),"boundary_source": .string("lc_function_starts")]),"witness_id": .string("swift-outcome-witness-v1:owned-slice:0x1000:0x1000"),"status": .string("unresolved"),"source_reconstruction_allowed": .bool(false),"runtime_branch_proven": .bool(false),"call_return_proven": .bool(false),"handler_semantics_proven": .bool(false),"evidence": c,"graph": .object(["nodes": .array(nodes),"edges": .array(edges)])])
        return f
    }
    private func set(_ object: inout SwiftOutcomeJSON,_ path: [String],_ value: SwiftOutcomeJSON) {
        guard let key = path.first else { object = value; return }
        var child = object[key]; set(&child,Array(path.dropFirst()),value); object[key] = child
    }
    private func check(_ path: [String],_ value: SwiftOutcomeJSON,_ reason: String? = nil, file: StaticString = #filePath,line: UInt = #line) {
        var f = fixture(); set(&f.witness,path,value); let result = f.validate()
        XCTAssertNotEqual(result["status"],.string("eligible_structural_only"),file: file,line: line)
        if let reason { XCTAssertEqual(result["reason"],.string(reason),file: file,line: line) }
    }
    func testPositive() {
        let f = fixture()
        XCTAssertEqual(f.image.identity, f.witness["image"])
        let result = f.validate()
        XCTAssertEqual(result["status"],.string("eligible_structural_only")); XCTAssertEqual(result["reason"],.string("bounded_facts_checked"))
        XCTAssertEqual(result["details_complete"],.bool(true)); XCTAssertEqual(result["call_return_proven"],.bool(false))
        XCTAssertEqual(result["checked_instruction_count"],.integer(11)); XCTAssertEqual(result["instruction_mappings"].array?.count,11)
        XCTAssertEqual(result["source_steps"],.integer(1)); XCTAssertEqual(result["symbol_records"],.integer(2)); XCTAssertEqual(result["caller_words"],.integer(16))
        XCTAssertEqual(result["local_steps"],.integer(52)); XCTAssertEqual(result["work_steps"],.integer(71))
        XCTAssertEqual(result["facts"]["values"],.string("independently_replayed"))
    }
    func testMutationMatrix() {
        for (key,bad) in [("call_pc","0x0"),("call_word","0x94000001"),("callee_pc","0x0"),("success_pc","0x1008"),("tested_register","x20")] { check(["evidence",key],.string(bad)) }
        for key in ["architecture","cpu_subtype","uuid","slice_sha256","container_sha256","slice_offset","slice_size","preferred_base"] { check(["image",key],.null,"selected_image_mismatch") }
    }
    func testValueAndChoiceCoordinatedMutation() {
        for path in ["success","error"] {
            var f = fixture(); f.witness["evidence"][path + "_constant"]["constant_bits"] = .string("0x0000000000000063")
            f.witness["evidence"]["return_choice"][path]["constant_bits"] = .string("0x0000000000000063")
            XCTAssertEqual(f.validate()["reason"],.string("constant_mismatch"))
        }
    }
    func testIncompleteUnknownAndSideEntry() {
        var f = fixture(); put(&f.bytes,0x12c,0xffffffff)
        XCTAssertEqual(f.validate()["status"],.string("unresolved")); XCTAssertEqual(f.validate()["reason"],.string("caller_scan_unclassified"))
        f = fixture(); put(&f.bytes,0x12c,0x17fffff7)
        XCTAssertEqual(f.validate()["status"],.string("blocked")); XCTAssertEqual(f.validate()["reason"],.string("unexpected_direct_entries"))
    }
    func testBudgetsAndMalformed() throws {
        let f = fixture()
        for limits in [try WitnessLimits(maxSteps: 0),try WitnessLimits(maxInstructions: 0),try WitnessLimits(maxCallerWords: 0),try WitnessLimits(maxNodes: 0),try WitnessLimits(maxEdges: 0),try WitnessLimits(maxBytes: 0),try WitnessLimits(maxContainerItems: 0),try WitnessLimits(maxDepth: 0)] {
            XCTAssertNotEqual(f.validate(limits: limits)["status"],.string("eligible_structural_only"))
        }
        for value in [SwiftOutcomeJSON.null,.array([]),.object([:]),.object(["model_version": .array([])])] {
            var changed = f; changed.witness = value
            XCTAssertNotEqual(changed.validate()["status"],.string("eligible_structural_only"))
        }
        let exhausted = f.validate(limits: try WitnessLimits(maxSteps: 0))
        XCTAssertEqual(exhausted["local_steps"],.integer(1)); XCTAssertEqual(exhausted["reason"],.string("witness_work_limit")); XCTAssertEqual(exhausted["details_complete"],.bool(false))
    }
    func testIntervalAndGraph() {
        var f = fixture(); var rows = f.witness["evidence"]["error_region"]["instructions"].array!
        rows[0]["word"] = .string("0xd503201f"); f.witness["evidence"]["error_region"]["instructions"] = .array(rows)
        XCTAssertEqual(f.validate()["reason"],.string("instruction_word_mismatch"))
        check(["evidence","error_region","join_pc"],.string("0x0"),"interval_geometry")
        check(["evidence","return_choice","return_pc"],.string("0x0"),"choice_mismatch")
        check(["evidence","error_region","incoming_validation","caller_scan_complete"],.bool(false),"caller_ledger_incomplete")
        check(["graph","edges"],.array([]),"graph_mismatch")
    }
    func testDeterministicAndImmutable() throws {
        let f = fixture(), before = fixture().witness, first = fixture().validate()
        XCTAssertEqual(f.witness,before); XCTAssertEqual(first,f.validate()); XCTAssertEqual(first["model_version"],.string("swift-outcome-validation-v1"))
        XCTAssertEqual(f.witness,try boundedCopy(f.witness))
    }
    func testReviewCompleteModelsProofsAndEscapedBudget() throws {
        for key in ["edge","return_choice","region","incoming","presentation","success_result","success_constant","error_constant","flag_entry"] { check(["source_models",key],.string("future"),"source_models") }
        check(["runtime_branch_proven"],.bool(true),"retained_proof_scope")
        for key in ["success_constant","error_constant","success_result"] { check(["evidence",key,"runtime_value_proven"],.bool(true),"retained_proof_scope") }
        XCTAssertThrowsError(try boundedCopy(.object(["text": .string(String(repeating: "é",count: 100))]),limits: WitnessLimits(maxBytes: 200)))
        let result = fixture().validate(limits: try WitnessLimits(maxTotalWork: 1))
        XCTAssertEqual(result["reason"],.string("witness_total_work_limit")); XCTAssertEqual(result["work_steps"],.integer(1))
    }
    private func rewriteJump(_ value: SwiftOutcomeJSON) -> SwiftOutcomeJSON {
        if var obj = value.object {
            if obj["pc"] == .string("0x1014") && obj["word"] != nil {
                obj["word"] = .string("0xd503201f"); if obj["kind"] != nil { obj["kind"] = .string("nop") }; obj.removeValue(forKey: "target_pc")
            }
            for key in Array(obj.keys) { obj[key] = rewriteJump(obj[key]!) }
            return .object(obj)
        }
        if let rows = value.array { return .array(rows.map(rewriteJump)) }
        return value
    }
    func testCoordinatedSkippingArmFallthroughIsRefused() {
        var f = fixture(); put(&f.bytes,0x114,0xd503201f); f.witness = rewriteJump(f.witness)
        XCTAssertEqual(f.validate()["reason"],.string("skipping_arm_join_branch"))
    }
    func testRetainedProofsTargetsAndPresentation() {
        check(["evidence","error_region","incoming_validation","exclusive_entry_proven"],.bool(true),"retained_proof_scope")
        check(["evidence","error_constant","handler_semantics_proven"],.bool(true),"retained_proof_scope")
        var f = fixture(), rows = fixture().witness["evidence"]["error_region"]["instructions"].array!
        rows[1]["call_target_pc"] = .string("0x0"); f.witness["evidence"]["error_region"]["instructions"] = .array(rows)
        XCTAssertEqual(f.validate()["reason"],.string("retained_target_mismatch"))
        check(["evidence","presentation"],.object(["status": .string("eligible_structural_only")]),"unvalidated_presentation")
        XCTAssertNil(fixture().witness["evidence"].object?["presentation"])
    }
    func testMalformedNestedContainersAndEmptyBuilderInterval() {
        for key in ["error_region","return_choice","success_constant","success_result","error_constant"] {
            for bad in [SwiftOutcomeJSON.null,.array([]),.integer(1)] { check(["evidence",key],bad) }
        }
        // Existing builder operates on the request image. This uses only literal words.
        let f = fixture(); var c = f.witness["evidence"]; c["error_region"]["instructions"] = .array([])
        let image = SwiftOutcomeImage(SwiftErrorFlowRequest(slice: .init(artifactSHA256: "owned",sliceOffset: 0,sliceByteCount: 4,cpuType: 0x0100000c,cpuSubtype: 0,littleEndian: true),code: .init(baseAddress: 0x1000,sliceRelativeFileOffset: 0,sectionOrdinal: 1,hasEmbeddedData: false,hasRelocations: false,words: [0x94000010]),functions: [f.caller],symbols: []))
        XCTAssertEqual(buildOutcomeWitness(image: image,function: f.caller,call: c)["status"],.string("unresolved"))
    }
    func testRetainedLedgerUnselectedFactsAndRawSymbolBounds() {
        check(["evidence","error_region","incoming_validation","unexpected_entries"],.array([.null]),"retained_ledger_mismatch")
        check(["evidence","success_result","status"],.string("preserved_register_candidate"),"conflicting_success_values")
        check(["evidence","return_choice","same_constant_bits"],.bool(true),"choice_equality")
        var f = fixture(); put(&f.bytes,0x194,14,1)
        XCTAssertEqual(f.validate()["reason"],.string("callee_visibility"))
        f = fixture(); put(&f.bytes,40,0xffffffff)
        XCTAssertEqual(f.validate()["reason"],.string("malformed_or_incomplete_evidence"))
    }
    func testLegacyBooleanIntegerEqualityIsLocalAndProofsStayStrict() {
        var f = fixture()
        f.witness["image"]["cpu_subtype"] = .bool(false)
        f.witness["evidence"]["error_region"]["opaque_call_count"] = .bool(true)
        f.witness["evidence"]["error_region"]["incoming_validation"]["unexpected_entry_count"] = .bool(false)
        f.witness["evidence"]["error_region"]["incoming_validation"]["unclassified_word_count"] = .bool(false)
        f.witness["evidence"]["return_choice"]["same_constant_bits"] = .integer(0)
        XCTAssertEqual(f.validate()["status"],.string("eligible_structural_only"))
        f.witness["runtime_branch_proven"] = .integer(0)
        XCTAssertEqual(f.validate()["reason"],.string("retained_proof_scope"))
    }
    private func remove(_ object: inout SwiftOutcomeJSON,_ path: [String]) {
        guard let key = path.first, var obj = object.object else { return }
        if path.count == 1 { obj.removeValue(forKey: key) }
        else if var child = obj[key] { remove(&child,Array(path.dropFirst())); obj[key] = child }
        object = .object(obj)
    }
    func testMissingRequiredKeysDifferFromPresentNull() {
        let pairs: [([String],String)] = [
            (["evidence"],"call_container"),(["evidence","call_pc"],"invalid_address"),
            (["evidence","window"],"interval_details_incomplete"),
            (["evidence","error_region","start_pc"],"invalid_address"),
            (["evidence","error_region","instructions"],"interval_details_incomplete"),
            (["evidence","error_region","success_interval","start_pc"],"invalid_address"),
            (["evidence","error_region","success_interval","instructions"],"interval_details_incomplete"),
            (["evidence","error_region","shared_epilogue","end_pc_exclusive"],"invalid_address"),
            (["evidence","error_region","shared_epilogue","instructions"],"interval_details_incomplete"),
            (["evidence","callee"],"callee_declaration_mismatch")]
        for (path,nullReason) in pairs {
            var f = fixture(); remove(&f.witness,path)
            XCTAssertEqual(f.validate()["status"],.string("unresolved")); XCTAssertEqual(f.validate()["reason"],.string("malformed_or_incomplete_evidence"),path.joined(separator: "."))
            check(path,.null,nullReason)
        }
        for path in [["evidence","error_region"],["evidence","return_choice"],["evidence","success_constant"],["evidence","error_constant"]] {
            var f = fixture(); remove(&f.witness,path)
            XCTAssertEqual(f.validate()["reason"],.string("malformed_or_incomplete_evidence"))
            check(path,.null,"malformed_or_incomplete_evidence")
        }
    }
    func testMalformedLedgerAndUnhashableProfile() {
        for bad in [SwiftOutcomeJSON.null,.array([]),.integer(1)] {
            check(["evidence","error_region","incoming_validation"],bad,"malformed_or_incomplete_evidence")
        }
        for bad in [SwiftOutcomeJSON.array([]),.object([:])] { check(["model_profile"],bad,"malformed_or_incomplete_evidence") }
        for bad in [SwiftOutcomeJSON.null,.integer(1),.bool(false),.string("unknown")] { check(["model_profile"],bad,"source_models") }
    }

}
