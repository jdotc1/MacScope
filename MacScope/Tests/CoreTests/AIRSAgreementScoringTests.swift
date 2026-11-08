import XCTest
@testable import MacScope

/// Pure scorer tests over authored traces. No AIRS output, executable or receipt is read or produced.
final class AIRSAgreementScoringTests: XCTestCase {
    private typealias Scorer = AIRSAgreementScorer
    private let manifest: [UInt64] = (1...21).map { UInt64($0) * 0x1000 }

    private func side(_ admitted: Bool?, _ fields: [String: String] = [:], reason: String? = nil) -> Scorer.Side {
        .init(admitted: admitted, fields: fields, reason: reason)
    }

    /// 20 selected keys: ten unwind, ten Swift. All jointly admitted and equal unless a test changes them.
    private func trace(receipt: Bool = true, mutate: (inout [Scorer.Record]) -> Void = { _ in }) -> Scorer.Trace {
        let selection = Array(manifest.prefix(20))
        var records = selection.enumerated().map { index, function -> Scorer.Record in
            let isUnwind = index < 10
            let fields = isUnwind ? ["verdict": "agreement", "checkedPCs": "0x\(String(function, radix: 16))"]
                                  : ["edges": "1", "successAddress": "0x\(String(function + 8, radix: 16))"]
            return .init(key: .init(kind: isUnwind ? .unwind : .swiftErrorFlow, function: function),
                         macscope: side(true, fields), airs: side(true, fields))
        }
        mutate(&records)
        return .init(sourceManifest: manifest, selection: selection, freshRunReceipt: receipt,
                     modelMappingSupplied: true, records: records)
    }

    func testSelectionIsPrecommitted() {
        XCTAssertTrue(Scorer.score(trace()).passed)
        var tempting = trace()
        tempting.selection[3] = manifest[20]
        XCTAssertEqual(Scorer.score(tempting).status, .invalid("selectionNotPrecommitted"))
        var reordered = trace()
        reordered.selection.reverse()
        XCTAssertEqual(Scorer.score(reordered).status, .invalid("selectionNotPrecommitted"))
        var short = trace()
        short.sourceManifest = Array(manifest.prefix(19))
        XCTAssertEqual(Scorer.score(short).status, .notComplete("fewerThan20SourceFunctions"))
    }

    func testSavedOracleCannotPass() {
        let result = Scorer.score(trace(receipt: false))
        XCTAssertEqual(result.status, .notComparable("missingFreshRunReceipt"))
        XCTAssertFalse(result.passed)
        var unmapped = trace()
        unmapped.modelMappingSupplied = false
        XCTAssertEqual(Scorer.score(unmapped).status, .notComparable("modelCoverageMismatch"))
    }

    func testAgreementUsesEveryJointKey() {
        let swiftKeys = manifest.prefix(20).dropFirst(10)
        let result = Scorer.score(trace { records in
            // One jointly admitted mismatch and one one-sided key; all remaining keys agree.
            records[12].airs = side(true, ["edges": "1", "successAddress": "0xdead"])
            records[14].airs = side(false, reason: "airsAbstained")
        })
        XCTAssertFalse(result.passed)
        XCTAssertEqual(result.status, .fail)
        XCTAssertEqual(result.disagreements.count, 1)
        XCTAssertEqual(result.count(.macscopeOnly), 1)
        XCTAssertEqual(result.count(.agreement), 18)
        XCTAssertEqual(result.jointlyAdmitted, 19)
        XCTAssertEqual(result.disagreements.first?.key.function, Array(swiftKeys)[2])
        // The one-sided key never enters the agreement denominator and never hides the disagreement.
        let clean = Scorer.score(trace { $0[14].airs = side(false, reason: "airsAbstained") })
        XCTAssertTrue(clean.passed)
        XCTAssertEqual(clean.count(.macscopeOnly), 1)
    }

    func testJointAdmissionFloorIsNotVacuous() {
        let vacuous = Scorer.score(trace { records in
            for index in records.indices { records[index].airs = side(false) }
        })
        XCTAssertFalse(vacuous.passed)
        XCTAssertEqual(vacuous.jointlyAdmitted, 0)
        XCTAssertEqual(vacuous.status, .notComplete("jointAdmissionFloor"))
    }

    func testDisagreementRetainsBothOutputs() throws {
        let result = Scorer.score(trace { records in
            records[11].macscope = side(true, ["edges": "1", "successAddress": "0xb008"])
            records[11].airs = side(true, ["edges": "1", "successAddress": "0xb00c"])
        })
        let record = try XCTUnwrap(result.disagreements.first)
        XCTAssertEqual(record.key.function, manifest[11])
        XCTAssertEqual(record.macscope.fields["successAddress"], "0xb008")
        XCTAssertEqual(record.airs.fields["successAddress"], "0xb00c")
        XCTAssertEqual(record.differingFields, ["successAddress"])
        XCTAssertFalse(result.passed)
    }
}
