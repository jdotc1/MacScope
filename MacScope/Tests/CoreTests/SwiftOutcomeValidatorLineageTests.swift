import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope

final class SwiftOutcomeValidatorLineageTests: XCTestCase {
    private let selected = "35f5565c675d9d4c328e310bfc1adaa2bd58afc8b3905bd888f009cd03f7cd76"
    private func changed(_ d: SwiftBroadCallableIdentity, result: SwiftBroadType? = nil,
        parameters: [SwiftBroadType]? = nil, throwing: Bool? = nil, kind: String? = nil,
        context: [SwiftBroadContext]? = nil) -> SwiftBroadCallableIdentity {
        SwiftBroadCallableIdentity(symbol:d.symbol,module:d.module,context:context ?? d.context,
            callableKind:kind ?? d.callableKind,functionName:d.functionName,parameterLabels:d.parameterLabels,
            parameterTypes:parameters ?? d.parameterTypes,resultType:result ?? d.resultType,throwsFlag:throwing ?? d.throwsFlag,
            genericParameterCounts:d.genericParameterCounts,genericRequirements:d.genericRequirements,
            originalCallableKind:d.originalCallableKind,specialization:d.specialization)
    }
    private func declaration(_ symbol: String = "_$s4Test3fooyS2iKF") throws -> SwiftBroadCallableIdentity {
        try XCTUnwrap(parseBroadSwiftDeclaration(symbol).identity)
    }
    private func remove(_ abi: inout SwiftOutcomeJSON, _ key: String) {
        var lower = abi["evidence"]["lowering"].object!; lower.removeValue(forKey:key)
        abi["evidence"]["lowering"] = .object(lower)
    }
    private func family(_ source: String) -> SwiftOutcomeJSON {
        .object(["source_sha256":.string(source),"compiled_target_pc":.string("0x1020"),"direct_call_pc":.string("0x1004"),"scope":.string("source_lineage_plus_exact_emitted_target_not_runtime_dispatch")])
    }
    private func check(_ key: String, words: [UInt32], selectedSlice: String = "fresh synthetic non-owned source",
        decl supplied: SwiftBroadCallableIdentity? = nil, entry: UInt64 = 0x1020,
        callerEnd: UInt64 = 0x1010, callPC: UInt64 = 0x1004,
        instruction: (UInt64) throws -> SwiftOutcomeInstruction = { try decodeSwiftOutcomeInstruction(word:0xd2800015,address:$0) },
        mutate: (inout SwiftOutcomeJSON) throws -> Void = { _ in }
    ) throws -> (storage: SwiftOutcomeJSON, state: SwiftOutcomeJSON, reads: [[Int]]) {
        let decl: SwiftBroadCallableIdentity
        if let supplied { decl = supplied }
        else { decl = changed(try declaration(),result:SwiftBroadType(key),parameters:[]) }
        var abi = try OutcomeStableHelper.record(key,selectedSlice:selectedSlice,entryPC:entry,wordCount:words.count)
        try mutate(&abi)
        var raw = Data(repeating:0,count:words.count*4)
        for (i,w) in words.enumerated() { OutcomeFixture.put(&raw,i*4,4,UInt64(w)) }
        let caller = SwiftErrorFlowFunction(start:0x1000,endExclusive:callerEnd,boundarySource:"lc_function_starts")
        let callee = SwiftErrorFlowFunction(start:entry,endExclusive:entry+UInt64(raw.count),boundarySource:"lc_function_starts")
        let image = SwiftOutcomeValidatorImage.unadmitted(data:raw,path:"direct lineage seam",sliceSHA256:selectedSlice,containerSHA256:"unused",architecture:"arm64",cpuSubtype:0,uuid:nil,fileType:2,preferredBase:0,sliceOffset:0,sliceSize:UInt64(raw.count),sliceIndex:nil,containerSliceCount:nil,sections:[],functions:[caller,callee])
        var reads: [[Int]] = []
        let result = try validateSwiftOutcomeStableABI(image:image,function:caller,callee:callee,callPC:callPC,declaration:decl,abi:abi,read:{ pc,n in
            reads.append([pc,n]); let offset = pc-Int(entry)
            guard offset >= 0, n >= 0, n <= raw.count, offset <= raw.count-n else { throw SwiftOutcomeValidatorStop(reason:"test_extent") }
            return raw.subdata(in:offset..<offset+n)
        },mapped:{ pc,_ in Int(pc) },instruction:instruction,charge:{ _ in },limits:BroadWitnessLimits())
        XCTAssertEqual(result.storage,try XCTUnwrap(SwiftOutcomeABIRegistry.frozen.stableStorageCapabilities[key]).json)
        XCTAssertEqual(result.callerErrorState,.string("unproven_profile_precondition"))
        return (result.storage,result.callerErrorState,reads)
    }
    private func refuses(_ body: () throws -> Void, reason: String? = nil) {
        XCTAssertThrowsError(try body()) { error in
            guard let stop = error as? SwiftOutcomeValidatorStop else { return XCTFail("Expected validator stop") }
            if let reason { XCTAssertEqual(stop.reason,reason) }
        }
    }
    func testUC26_second_selected_custom_storage_uses_its_actual_source_without_reference_pc_reads() throws {
        let r = SwiftOutcomeABIRegistry.frozen
        let source = try XCTUnwrap(r.ownedSourceBySlice[selected]); XCTAssertNotEqual(source,r.v2Source)
        let result = try check("BroadOwned.BroadSmall",words:[0xaa0003f5,0xa9000500,0xd65f03c0],selectedSlice:selected, mutate: {
            $0["family"] = .string("free"); $0["family_evidence"] = self.family(source)
        })
        XCTAssertEqual(result.reads,[[0x1020,12]])
    }
    func testUC26_selected_and_reference_lineage_cannot_be_swapped_or_omitted() throws {
        let r = SwiftOutcomeABIRegistry.frozen, actual = try XCTUnwrap(SwiftOutcomeABIRegistry.frozen.ownedSourceBySlice[selected])
        let changes: [(String,SwiftOutcomeJSON)] = [("selected_source_sha256",.string(r.v2Source)),("selected_slice_sha256",.string(try XCTUnwrap(r.v2Slices.sorted().first))),("source_sha256",.string(actual)),("reference_slice_sha256",.string(selected)),("selected_source_sha256",.null)]
        for (key,value) in changes { refuses { _ = try check("Swift.Int",words:[0xaa0003f5,0xd2800020,0xd65f03c0],selectedSlice:selected, mutate: { $0["evidence"]["lowering"][key] = value }) } }
        for key in ["selected_source_sha256","selected_slice_sha256"] { refuses { _ = try check("Swift.Int",words:[0xaa0003f5,0xd2800020,0xd65f03c0],selectedSlice:selected, mutate: { self.remove(&$0,key) }) } }
    }
    func testUC26_second_family_source_cannot_claim_primary_lineage() {
        refuses { _ = try check("Swift.Int",words:[0xaa0003f5,0xd2800020,0xd65f03c0],selectedSlice:selected, mutate: {
            $0["family"] = .string("free"); $0["family_evidence"] = self.family(SwiftOutcomeABIRegistry.frozen.v2Source)
        }) }
    }
    func testUC26_second_generic_rule_still_requires_real_formal_reads_and_tag_store() throws {
        let decl = try declaration("_$s10BroadOwned0A9Owner0340V15broad_case_0340yAA0A3TagOSb_s5UInt8VxtKSzRzlFZSi_Tt3g5")
        let spec = try XCTUnwrap(decl.specialization)
        let source = try XCTUnwrap(SwiftOutcomeABIRegistry.frozen.ownedSourceBySlice[selected])
        let words: [UInt32] = [0x92400009,0x8b210129,0x8b020134,0xaa0003f5,0x39000109,0xd65f03c0]
        func mutate(_ abi: inout SwiftOutcomeJSON) {
            abi["evidence"]["lowering"]["specialization"] = spec.json
            let rows = [("Swift.Bool","w0","swift-stable-v2-bool"),("Swift.UInt8","w1","swift-stable-v2-uint8"),("Swift.Int","x2","swift-stable-v2-int")]
            abi["argument_storage"] = .array(rows.map { .object(["type":.string($0.0),"locations":.array([.string($0.1)]),"evidence_id":.string($0.2),"inout":.bool(false)]) })
            abi["argument_locations"] = .array([.array([.string("w0")]),.array([.string("w1")]),.array([.string("x2")])])
            abi["family"] = .string("concrete_generic_specialization"); abi["family_evidence"] = family(source)
        }
        let result = try check("BroadOwned.BroadTag",words:words,selectedSlice:selected,decl:decl,mutate:mutate)
        XCTAssertEqual(result.storage["category"],.string("resilient_tag_enum")); XCTAssertEqual(result.reads,[[0x1020,24]])
        refuses { _ = try check("BroadOwned.BroadTag",words:[0xd2800002]+Array(words.dropFirst()),selectedSlice:selected,decl:decl,mutate:mutate) }
    }
    func testUC26_unowned_selected_source_none_is_explicit_and_does_not_grant_custom_storage() throws {
        _ = try check("Swift.UInt8",words:[0xaa0003f5,0x52800020,0xd65f03c0])
        refuses { _ = try check("Swift.UInt8",words:[0xaa0003f5,0x52800020,0xd65f03c0], mutate: { self.remove(&$0,"selected_source_sha256") }) }
        refuses { _ = try check("BroadOwned.BroadSmall",words:[0xaa0003f5,0xa9000500,0xd65f03c0]) }
    }
    func testUC26_midframe_abi_suffix_has_unknown_sp_and_retains_nonzero_refusal() throws {
        func run(_ last: UInt32) throws -> SwiftOutcomeJSON {
            try check("Swift.Int",words:[0xaa0003f5,0xd2800020,0xd65f03c0],entry:0x1200,callerEnd:0x1100,callPC:0x10f0,instruction:{ pc in
                try decodeSwiftOutcomeInstruction(word:pc == 0x1070 ? 0xb90033e0 : (pc == 0x10ec ? last : 0xd503201f),address:pc)
            }).state
        }
        XCTAssertEqual(try run(0xd2800015),.string("unproven_profile_precondition"))
        refuses({ _ = try run(0xd2800035) },reason:"caller_error_contract_contradiction")
    }
    func testUC26_private_ordinary_class_static_is_narrow_direct_throwing_implementation() throws {
        let d = try declaration("_$s10BroadOwned0A9Owner0296C15broad_case_0296AA0A9ReferenceCyKFZ")
        XCTAssertTrue(swiftOutcomeSymbolVisibilityAllowed(kind:30,desc:0,declaration:d,callKind:"bl"))
        let variants: [(Int,Int,SwiftBroadCallableIdentity,String)] = [(30,0,d,"b"),(14,0,d,"bl"),(30,0,changed(d,throwing:false),"bl"),(30,0,changed(d,kind:"class_instance_method"),"bl"),(30,0,changed(d,context:[]),"bl"),(30,0x80,d,"bl")]
        for (kind,desc,decl,call) in variants { XCTAssertFalse(swiftOutcomeSymbolVisibilityAllowed(kind:kind,desc:desc,declaration:decl,callKind:call)) }
    }
    func testUC26_private_weak_visibility_requires_exact_flags_bl_and_concrete_bindings() throws {
        let concrete = try declaration("_$s10BroadOwned0A9Owner0363V15broad_case_0363ySis5Int32V_s6UInt64VSixtKSzRzlFZSi_Tt3g5"), ordinary = try declaration()
        XCTAssertTrue(swiftOutcomeSymbolVisibilityAllowed(kind:0x1e,desc:0x80,declaration:concrete,callKind:"bl"))
        let variants: [(Int,Int,SwiftBroadCallableIdentity,String)] = [(0x1e,0,concrete,"bl"),(0x1e,0x81,concrete,"bl"),(0x1e,0x80,ordinary,"bl"),(0x1e,0x80,concrete,"b"),(0xf,0x80,ordinary,"bl")]
        for (kind,desc,decl,call) in variants { XCTAssertFalse(swiftOutcomeSymbolVisibilityAllowed(kind:kind,desc:desc,declaration:decl,callKind:call)) }
    }
    func testUC26_unrelated_indirect_parent_is_skipped_but_matching_raw_chain_is_exact() throws {
        var data = Data(repeating:0,count:256)
        for (offset,value) in [(0,32),(4,60),(32,17),(36,1),(40,168),(64,17),(68,28),(72,73),(96,0),(100,0),(104,24)] { OutcomeFixture.put(&data,offset,4,UInt64(value)) }
        OutcomeFixture.text(&data,128,"Test\0"); OutcomeFixture.text(&data,145,"Owner\0"); OutcomeFixture.text(&data,208,"Other\0")
        let sections = [SwiftNominalSectionInput(segment:"__TEXT",name:"__swift5_types",address:0x2000,end:0x2008,size:8,offset:0,flags:0),SwiftNominalSectionInput(segment:"__TEXT",name:"__const",address:0x2008,end:0x2100,size:248,offset:8,flags:0)]
        let decl = SwiftNominalDeclarationInput(module:"Test",context:[("Owner","struct")])
        func replay() throws -> SwiftOutcomeJSON { try replaySwiftNominalContext(declaration:decl,sections:sections,read:{ off,n in data.subdata(in:off..<off+n) },limits:BroadWitnessLimits()) }
        let result = try replay(), record = try XCTUnwrap(result["records"].array?.first)
        XCTAssertEqual(result["entry_pc"],.string("0x2004")); XCTAssertEqual(record["name_pc"],.string("0x2091"))
        XCTAssertEqual(record["raw_descriptor"],.string(data[64..<92].map { String(format:"%02x",$0) }.joined()))
        XCTAssertEqual(record["raw_name"],.string("4f776e657200"))
        OutcomeFixture.put(&data,68,4,1); refuses { _ = try replay() }
    }
}
#endif
