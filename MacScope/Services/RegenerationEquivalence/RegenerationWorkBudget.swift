import Foundation

enum RegenerationWorkBudgetError: Error, Equatable { case invalidLimit, deadlineExceeded, inputLimitExceeded, recordLimitExceeded }

/// One monotonic deadline and shared hard bounds across capture, comparison and report rendering.
struct RegenerationWorkBudget: Sendable {
    let deadlineUptimeNanoseconds: UInt64
    let maximumRecords: Int
    let maximumInputBytes: Int
    let maximumOutputBytes: Int

    init(deadlineUptimeNanoseconds: UInt64, maximumRecords: Int = 100_000,
         maximumInputBytes: Int = 512 * 1_024 * 1_024, maximumOutputBytes: Int = 64 * 1_024 * 1_024) throws {
        guard maximumRecords > 0, maximumRecords <= 100_000,
              maximumInputBytes > 0, maximumInputBytes <= 512 * 1_024 * 1_024,
              maximumOutputBytes > 0, maximumOutputBytes <= 64 * 1_024 * 1_024 else {
            throw RegenerationWorkBudgetError.invalidLimit
        }
        self.deadlineUptimeNanoseconds = deadlineUptimeNanoseconds
        self.maximumRecords = maximumRecords; self.maximumInputBytes = maximumInputBytes
        self.maximumOutputBytes = maximumOutputBytes
    }

    static func start(durationNanoseconds: UInt64 = 30_000_000_000) throws -> RegenerationWorkBudget {
        guard durationNanoseconds > 0, durationNanoseconds <= 30_000_000_000 else { throw RegenerationWorkBudgetError.invalidLimit }
        let (deadline, overflow) = DispatchTime.now().uptimeNanoseconds.addingReportingOverflow(durationNanoseconds)
        guard !overflow else { throw RegenerationWorkBudgetError.invalidLimit }
        return try .init(deadlineUptimeNanoseconds: deadline)
    }

    func checkpoint() throws {
        try Task.checkCancellation()
        guard DispatchTime.now().uptimeNanoseconds < deadlineUptimeNanoseconds else { throw RegenerationWorkBudgetError.deadlineExceeded }
    }
}
