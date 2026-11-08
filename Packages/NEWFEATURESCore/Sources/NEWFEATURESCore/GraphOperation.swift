import Foundation

public enum NEWFEATURESGraphInterruption: Error, Equatable, Sendable {
    case cancelled
    case timedOut
}

/// Create before capturing/projecting graph input and carry the same deadline through
/// construction, traversal and serialization. This value confers no source authority.
public struct NEWFEATURESGraphOperation: Sendable {
    private let deadline: ContinuousClock.Instant
    private let cancellationRequested: @Sendable () -> Bool

    public init(
        budget: NEWFEATURESReadBudget,
        startedAt: ContinuousClock.Instant = .now,
        cancellationRequested: @escaping @Sendable () -> Bool = { false }
    ) {
        deadline = startedAt.advanced(by: .seconds(budget.maxElapsedSeconds))
        self.cancellationRequested = cancellationRequested
    }

    public func checkpoint() throws {
        if Task<Never, Never>.isCancelled || cancellationRequested() {
            throw NEWFEATURESGraphInterruption.cancelled
        }
        if ContinuousClock.now >= deadline {
            throw NEWFEATURESGraphInterruption.timedOut
        }
    }
}

/// Construction limits are independent of the smaller visited-function/edge budgets.
/// They apply before allocation, deduplication or sorting of supplied observations.
public struct NEWFEATURESGraphInputLimits: Equatable, Sendable {
    public let maxFunctions: Int
    public let maxEdges: Int

    public static let standard = Self(functions: 100_000, edges: 200_000)

    public init(maxFunctions: Int, maxEdges: Int) throws {
        guard (1...100_000).contains(maxFunctions), (0...1_000_000).contains(maxEdges) else {
            throw NEWFEATURESError.invalidPolicy
        }
        self.init(functions: maxFunctions, edges: maxEdges)
    }

    private init(functions: Int, edges: Int) {
        maxFunctions = functions
        maxEdges = edges
    }
}
