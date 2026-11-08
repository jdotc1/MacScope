import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope
final class SwiftOutcomeValidatorBreadthTests: XCTestCase {
    private func brkFixture() throws -> OutcomeFixture.Value {
        try OutcomeFixture.expanded([(0,"bl"),(0xb4000075,"xcbz"),(0xd4200020,"brk"),(0xd65f03c0,"ret"),(0xd65f03c0,"ret")],branches:[1:[4,2]],success:4,error:2)
    }
    private func observation(_ pc: String,_ registers: [String] = ["x21"]) -> SwiftOutcomeJSON {
        .object(["pc":.string(pc),"origins":.array(registers.map { .object(["register":.string($0),"kind":.string("register_copy"),"origin":.string("abi_post_call_error:x21")]) })])
    }
    func testUC15_brk_is_external_terminal_without_return_or_fallthrough_claim() throws {
        let r=try brkFixture().validate(); XCTAssertEqual(r["eligible"],.bool(true))
        XCTAssertEqual(r["exception_observations"],.array([.object(["arm":.string("error"),"pc":.string("0x1008"),"exception":.string("breakpoint"),"resume_proven":.bool(false)])]))
        XCTAssertTrue(r["return_observations"].array!.allSatisfy {$0["arm"] != .string("error")}); XCTAssertEqual(r["exception_resume_proven"],.bool(false))
    }
    func testUC15_exception_handling_cannot_be_claimed_modeled() throws {
        var f=try brkFixture(); f.candidate["cfg"]["external_exception_handling_unmodeled"] = .bool(false)
        let r=f.validate(); XCTAssertEqual(r["reason"],.string("cfg_exception_facts")); XCTAssertEqual(r["eligible"],.bool(false))
    }
    func testUC15_forged_exception_word_and_resume_claim_cannot_validate() throws {
        let attacks: [(String,SwiftOutcomeJSON)] = [("cfg.exception_transfers.0.word",.string("0xd4200040")),("cfg.exception_transfers.0.resume_proven",.bool(true)),("cfg.edges.3.target_pc",.string("0x100c"))]
        for (path,value) in attacks { var f=try brkFixture(); OutcomeFixture.assign(&f.candidate,path.components(separatedBy:"."),value); XCTAssertEqual(f.validate()["eligible"],.bool(false)) }
    }
    func testUC16_cmp_eq_zero_and_shared_tail() throws {
        let f=try OutcomeFixture.expanded([(0,"bl"),(0xf10002bf,"xsubs"),(0x54000060,"bcond"),(0xd2800020,"movz"),(0x14000002,"b"),(0xd2800040,"movz"),(0xd65f03c0,"ret")],branches:[2:[5,3],4:[6]],success:5,error:3,comparison:1)
        let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(true)); XCTAssertEqual(r["return_observations"].array!.map {$0["value"]},[.array([.string("constant"),.integer(2),.integer(64)]),.array([.string("constant"),.integer(1),.integer(64)])]); XCTAssertEqual(r["region_partition"]["shared_pcs"],.array([.string("0x1018")]))
    }
    func testUC16_cmp_ne_polarity() throws {
        let f=try OutcomeFixture.expanded([(0,"bl"),(0xf10002bf,"xsubs"),(0x54000041,"bcond"),(0xd65f03c0,"ret"),(0xd65f03c0,"ret")],branches:[2:[4,3]],success:3,error:4,comparison:1)
        XCTAssertEqual(f.validate()["eligible"],.bool(true))
    }
    func testUC17_postcall_result_clobber_flows_to_return() throws {
        let f=try OutcomeFixture.expanded([(0,"bl"),(0xaa1503e0,"mov"),(0xb4000055,"xcbz"),(0xd65f03c0,"ret"),(0xd65f03c0,"ret")],branches:[2:[4,3]],success:4,error:3,observations:[observation("0x1004",["x0","x21"])])
        let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(true)); XCTAssertEqual(r["return_observations"].array?[0]["value"].array?.first,.string("error_result"))
    }
    func testUC17_postcall_unknown_clobber_cannot_report_call_result() throws {
        let f=try OutcomeFixture.expanded([(0,"bl"),(0xaa0103e0,"mov"),(0xb4000055,"xcbz"),(0xd65f03c0,"ret"),(0xd65f03c0,"ret")],branches:[2:[4,3]],success:4,error:3,observations:[observation("0x1004")])
        let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(true)); XCTAssertEqual(r["value_fact_status"],.string("checked_with_explicit_unknowns")); XCTAssertEqual(r["symbolic_return_values_complete"],.bool(false)); XCTAssertEqual(r["return_observations"].array?[0]["value"],.array([.string("unknown"),.integer(64)])); XCTAssertEqual(r["eligibility_scope"],.string("checked_structural_facts_only")); XCTAssertEqual(r["call_return_proven"],.bool(false))
    }
    func testUC17_narrow_wide_arm_preserves_transformation() throws {
        let f=try OutcomeFixture.expanded([(0,"bl"),(0xb4000095,"xcbz"),(0x2a0003e1,"wmov"),(0xaa0103e0,"mov"),(0xd65f03c0,"ret"),(0xd65f03c0,"ret")],branches:[1:[5,2]],success:5,error:2)
        let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(true)); XCTAssertEqual(r["return_observations"].array?[1]["value"].array?.first,.string("zero_extend"))
    }
    func testUC18_postcall_direct_hop_over_unreachable_return() throws {
        let f=try OutcomeFixture.expanded([(0,"bl"),(0x14000002,"b"),(0xd65f03c0,"ret"),(0xb4000055,"xcbz"),(0xd65f03c0,"ret"),(0xd65f03c0,"ret")],branches:[1:[3],3:[5,4]],success:5,error:4)
        let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(true)); XCTAssertTrue(r["region_partition"]["unreachable_pcs"].array!.contains(.string("0x1008")))
    }
    func testUC18_multiple_conditional_return_arms() throws {
        let f=try OutcomeFixture.expanded([(0,"bl"),(0xb40000d5,"xcbz"),(0xb4000060,"xcbz"),(0xd2800020,"movz"),(0xd65f03c0,"ret"),(0xd2800040,"movz"),(0xd65f03c0,"ret"),(0xd65f03c0,"ret")],branches:[1:[7,2],2:[5,3]],success:7,error:2)
        let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(true)); XCTAssertEqual(r["return_observations"].array?.count,3)
    }
    func testUC18_stack_result_restore_shared_tail() throws {
        let f=try OutcomeFixture.expanded([(0,"bl"),(0xd10043ff,"sub"),(0xf90003e0,"xstr"),(0xb4000055,"xcbz"),(0x14000002,"b"),(0xd503201f,"nop"),(0xf94003e0,"xldr"),(0x910043ff,"add"),(0xd65f03c0,"ret")],branches:[3:[5,4],4:[6]],success:5,error:4,observations:[observation("0x1004"),observation("0x1008")])
        XCTAssertEqual(f.validate()["return_observations"].array?[1]["value"],.array([.string("call_result"),.string("0x1000"),.integer(64)]))
    }
    func testUC18_cycle_remains_explicitly_unresolved() throws {
        let f=try OutcomeFixture.expanded([(0,"bl"),(0xb4000055,"xcbz"),(0x14000000,"b"),(0xd65f03c0,"ret")],branches:[1:[3,2],2:[2]],success:3,error:2)
        let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(false)); XCTAssertEqual(r["reason"],.string("cyclic_or_external_arm"))
    }
    func testUC18_scalar_arithmetic_keeps_derived_result() throws {
        let f=try OutcomeFixture.expanded([(0,"bl"),(0xb4000075,"xcbz"),(0x91000400,"add"),(0xd65f03c0,"ret"),(0xd65f03c0,"ret")],branches:[1:[4,2]],success:4,error:2)
        let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(true)); XCTAssertEqual(r["return_observations"].array?[1]["value"].array?.first,.string("add"))
    }
    func testUC19_fresh_admission_stale_raw_call_fact_is_rejected() throws {
        var f=try OutcomeFixture.expanded([(0,"bl"),(0xb4000055,"xcbz"),(0xd65f03c0,"ret"),(0xd65f03c0,"ret")],branches:[1:[3,2]],success:3,error:2)
        var data=f.image.data; OutcomeFixture.put(&data,260,4,0xb5000055); f.image=OutcomeFixture.image(data)
        f.candidate["identity"]["slice_sha256"] = .string(f.image.sliceSHA256); f.candidate["identity"]["container_sha256"] = .string(f.image.containerSHA256)
        let r=f.validate(); XCTAssertEqual(r["eligible"],.bool(false)); XCTAssertEqual(r["reason"],.string("cfg_replay_mismatch"))
    }
}
#endif
