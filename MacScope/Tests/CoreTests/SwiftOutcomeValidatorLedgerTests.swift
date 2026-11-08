import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope
final class SwiftOutcomeValidatorLedgerTests: XCTestCase {
    func testUC09_raw_directory_charged_once_for_distinct_witness_requests_without_hash() throws {
        let f=try OutcomeFixture.manual(); let before=SwiftOutcomeImageLedger.factoryCallCount
        let ledger=createIndependentSwiftImageLedger(f.image); let first=f.validate(ledger:ledger)
        var second=f; second.candidate["limitations"] = .array([.string("research_only"),.string("separate_request")]); OutcomeFixture.finish(&second.candidate)
        let result=second.validate(ledger:ledger)
        XCTAssertEqual(SwiftOutcomeImageLedger.factoryCallCount-before,1); XCTAssertGreaterThan(ledger.initialWorkSteps,0)
        for r in [first,result] {
            XCTAssertEqual(r["eligible"],.bool(true)); XCTAssertEqual(r["accounting"]["image_initial_work"],.integer(Int128(ledger.initialWorkSteps)))
            XCTAssertEqual(r["accounting"]["image_work_charged_here"],.integer(0)); XCTAssertEqual(r["accounting"]["image_ledger_reused"],.bool(true))
        }
    }
    func testUC09_standalone_reports_separate_directory_and_witness_budgets() throws {
        let r=try OutcomeFixture.manual().validate(); XCTAssertEqual(r["eligible"],.bool(true))
        XCTAssertEqual(r["accounting"]["image_work_charged_here"],r["accounting"]["image_initial_work"])
        XCTAssertGreaterThan(r["accounting"]["image_work_charged_here"].integer ?? 0,0); XCTAssertEqual(r["accounting"]["image_ledger_reused"],.bool(false))
    }
    func testUC10_directory_is_for_exact_image_object_not_an_equal_copy() throws {
        var f=try OutcomeFixture.manual(); let ledger=createIndependentSwiftImageLedger(f.image)
        f.image=f.image.copy(path:"another path",data:f.image.data); XCTAssertTrue(f.image.hasValidAdmission)
        XCTAssertEqual(f.validate(ledger:ledger)["reason"],.string("independent_image_ledger_custody"))
    }
    func testUC10_serialized_lookalike_and_copied_ledger_are_not_capabilities() throws {
        struct Fake { let status: String }
        let f=try OutcomeFixture.manual(); let ledger=createIndependentSwiftImageLedger(f.image)
        let dictionary: [String:SwiftOutcomeJSON] = ["status":.string("ready"),"initial_work_steps":.integer(Int128(ledger.initialWorkSteps))]
        let fakes: [Any] = [dictionary,Fake(status:"ready"),ledger.copy()]; for fake in fakes { XCTAssertEqual(f.validate(ledger:fake)["reason"],.string("independent_image_ledger_custody")) }
    }
    func testUC11_source_change_cannot_reuse_a_directory_or_mint_without_admission() throws {
        var f=try OutcomeFixture.manual(); let ledger=createIndependentSwiftImageLedger(f.image); var data=f.image.data; data[256] ^= 1; f.image=f.image.copy(data:data)
        XCTAssertEqual(createIndependentSwiftImageLedger(f.image).reason,"image_admission_custody"); XCTAssertEqual(f.validate(ledger:ledger)["eligible"],.bool(false))
    }
    func testUC11_factory_limits_and_partial_directories_never_validate() throws {
        let f=try OutcomeFixture.manual()
        for budget in [0,20,100] { let ledger=createIndependentSwiftImageLedger(f.image,maxWork:budget); XCTAssertNotEqual(ledger.status,"ready"); XCTAssertLessThanOrEqual(ledger.initialWorkSteps,budget); XCTAssertEqual(f.validate(ledger:ledger)["eligible"],.bool(false)) }
        for budget in [-1,262145] { XCTAssertNotEqual(createIndependentSwiftImageLedger(f.image,maxWork:budget).status,"ready") }
    }
}
#endif
