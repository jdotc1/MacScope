import Foundation
import XCTest
@testable import MacScope

// Authored, unrun. Proves selection, interval/error/nesting semantics, request
// grouping, fixed names and the closed record field types; no latency assertion.
final class MCPRequestTimingTests: XCTestCase {
    private enum Deliberate: Error { case stop }
    private final class Counter: MCPRequestTimingObserver, @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func record(_ record: MCPRequestTimingRecord) {
            lock.lock(); count += 1; lock.unlock()
        }
        var calls: Int { lock.lock(); defer { lock.unlock() }; return count }
    }

    // Type-presence: absent at the pin; expected not to compile there.
    func testNewTimingTypePresence() {
        XCTAssertEqual(MCPRequestTiming.disabled.measure(.admit) { 7 }, 7)
    }

    // New seam unit oracle: explicit opt-in must be required, not inferred.
    func testDisabledCallsNeitherObserverNorObserverFactory() {
        let counter = Counter()
        var factoryCalls = 0
        func observer() -> any MCPRequestTimingObserver {
            factoryCalls += 1
            return counter
        }
        let selected = MCPRequestTiming.selected(environment: [:], observer: observer())
        XCTAssertEqual(selected.withRequest { selected.measure(.admit) { 9 } }, 9)
        XCTAssertEqual(counter.calls, 0)
        XCTAssertEqual(factoryCalls, 0)
        for value in ["", "0", "true", "yes"] {
            let disabled = MCPRequestTiming.selected(
                environment: [MCPRequestTiming.environmentKey: value], observer: observer())
            disabled.measure(.write) {}
        }
        XCTAssertEqual(counter.calls, 0)
        XCTAssertEqual(factoryCalls, 0)
        let sink = MCPRequestTimingRecorder()
        let off = MCPRequestTiming.selected(environment: [:], observer: sink)
        off.measure(.catalogBuild) {}
        XCTAssertEqual(sink.records, [])
    }

    // New seam unit oracle: separate standalone intervals have increasing ordinals.
    func testEnabledOrderOffsetsAndThrowingBody() {
        let recorder = MCPRequestTimingRecorder()
        let timing = MCPRequestTiming.selected(
            environment: [MCPRequestTiming.environmentKey: "1"], observer: recorder)
        timing.measure(.admit) {}
        timing.measure(.decode) {}
        XCTAssertThrowsError(try timing.measure(.encode) { throw Deliberate.stop })
        let records = recorder.records
        XCTAssertEqual(records.map(\.stage), [.admit, .decode, .encode])
        XCTAssertEqual(records.map(\.requestOrdinal), [1, 2, 3])
        for record in records {
            XCTAssertGreaterThanOrEqual(record.start, .zero)
            XCTAssertLessThanOrEqual(record.start, record.end)
        }
        XCTAssertLessThanOrEqual(records[0].end, records[1].start)
    }

    // New seam unit oracle: delivery is completion-order; nested stages share a request.
    func testNestedIntervalsAreBothRecordedUnderOneRequest() throws {
        let recorder = MCPRequestTimingRecorder()
        let timing = MCPRequestTiming(observer: recorder)
        XCTAssertThrowsError(try timing.withRequest {
            try MCPRequestTiming.current.measure(.dispatch) {
                try MCPRequestTiming.current.measure(.execute) { throw Deliberate.stop }
            }
        })
        let records = recorder.records
        XCTAssertEqual(records.map(\.stage), [.execute, .dispatch])
        XCTAssertEqual(records.map(\.requestOrdinal), [1, 1])
        XCTAssertLessThanOrEqual(records[1].start, records[0].start)
        XCTAssertLessThanOrEqual(records[0].end, records[1].end)
    }

    func testAsyncBodyAndThrowStillRecord() async {
        let recorder = MCPRequestTimingRecorder()
        let timing = MCPRequestTiming(observer: recorder)
        let value = await timing.measure(.decode) { () async -> Int in 11 }
        XCTAssertEqual(value, 11)
        do {
            try await timing.measure(.execute) { () async throws -> Void in throw Deliberate.stop }
            XCTFail("Expected the body's error")
        } catch { XCTAssertTrue(error is Deliberate) }
        XCTAssertEqual(recorder.records.map(\.stage), [.decode, .execute])
        XCTAssertEqual(recorder.records.map(\.requestOrdinal), [1, 2])
        for record in recorder.records { XCTAssertLessThanOrEqual(record.start, record.end) }
    }

    func testConcurrentIntervalsHaveUniqueOrdinalsAndNoLostRecords() {
        let recorder = MCPRequestTimingRecorder()
        let timing = MCPRequestTiming(observer: recorder)
        DispatchQueue.concurrentPerform(iterations: 17) { _ in
            timing.measure(.catalog) {}
        }
        let records = recorder.records
        XCTAssertEqual(records.count, 17)
        XCTAssertEqual(Set(records.map(\.requestOrdinal)), Set((1...17).map(UInt64.init)))
        XCTAssertTrue(records.allSatisfy { $0.stage == .catalog && $0.start <= $0.end })
    }

    // Authored, unrun: the isolated parameter keeps a MainActor caller and its
    // non-Sendable local result on that actor through both async overloads.
    @MainActor
    func testAsyncOverloadsPreserveCallerIsolation() async {
        final class LocalBox { var value = 0 }
        let box = LocalBox()
        let recorder = MCPRequestTimingRecorder()
        let timing = MCPRequestTiming(observer: recorder)
        let returned = await timing.withRequest(isolation: #isolation) {
            await MCPRequestTiming.current.measure(.execute, isolation: #isolation) {
                () async -> LocalBox in
                MainActor.preconditionIsolated()
                box.value += 1
                return box
            }
        }
        XCTAssertTrue(returned === box)
        XCTAssertEqual(box.value, 1)
        XCTAssertEqual(recorder.records.map(\.stage), [.execute])
        XCTAssertEqual(recorder.records.map(\.requestOrdinal), [1])
        let disabledReturn = await MCPRequestTiming.disabled.measure(.write, isolation: #isolation) {
            () async -> LocalBox in
            MainActor.preconditionIsolated()
            return box
        }
        XCTAssertTrue(disabledReturn === box)
        XCTAssertEqual(recorder.records.count, 1)
    }

    func testClosedStageAndRecordShape() {
        XCTAssertEqual(Set(MCPRequestStage.allCases.map(\.rawValue)),
                       ["admit", "decode", "catalog", "dispatch", "execute", "encode", "write", "catalogBuild"])
        let expected = ["MCPAdmit", "MCPDecode", "MCPCatalog", "MCPDispatch",
                        "MCPExecute", "MCPEncode", "MCPWrite", "MCPCatalogBuild"]
        XCTAssertEqual(MCPRequestStage.allCases.map { String(describing: $0.signpostName) }, expected)
        let record = MCPRequestTimingRecord(stage: .admit, start: .zero, end: .zero, requestOrdinal: 1)
        let children = Array(Mirror(reflecting: record).children)
        XCTAssertEqual(children.compactMap(\.label), ["stage", "start", "end", "requestOrdinal"])
        XCTAssertEqual(children.count, 4)
        for child in children {
            XCTAssertTrue(child.value is MCPRequestStage || child.value is Duration || child.value is UInt64)
            XCTAssertFalse(child.value is String)
            XCTAssertFalse(child.value is Data)
        }
    }
}
