import Foundation

public enum NEWFEATURESPathStatus: String, Codable, Sendable {
    case found
    case notFoundInObservedGraph
    case functionLimit
    case depthLimit
    case edgeVisitLimit
    case cancelled
    case timedOut
}

public enum NEWFEATURESGraphOutputFailure: Error, Equatable, Sendable {
    case byteLimit
}

public struct NEWFEATURESPathReport: Encodable, Equatable, Sendable {
    public let source: NEWFEATURESFunctionKey
    public let destination: NEWFEATURESFunctionKey
    public let status: NEWFEATURESPathStatus
    public let path: [NEWFEATURESFunctionKey]
    public let visitedFunctions: Int
    public let visitedEdges: Int
    public let examinedUnverifiedEdges: Int
    public let observedUnverifiedEdges: Int

    private enum CodingKeys: String, CodingKey {
        case source, destination, status, path, visitedFunctions, visitedEdges
        case examinedUnverifiedEdges, observedUnverifiedEdges
    }

    private struct QualifiedAddress: Encodable {
        let image: NEWFEATURESImageKey
        let address: String

        init(_ function: NEWFEATURESFunctionKey) {
            image = function.image
            address = "0x" + String(function.address, radix: 16)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(QualifiedAddress(source), forKey: .source)
        try values.encode(QualifiedAddress(destination), forKey: .destination)
        try values.encode(status, forKey: .status)
        try values.encode(path.map(QualifiedAddress.init), forKey: .path)
        try values.encode(visitedFunctions, forKey: .visitedFunctions)
        try values.encode(visitedEdges, forKey: .visitedEdges)
        try values.encode(examinedUnverifiedEdges, forKey: .examinedUnverifiedEdges)
        try values.encode(observedUnverifiedEdges, forKey: .observedUnverifiedEdges)
    }

    /// At most 500 bounded identity values can be encoded. Transport size is checked
    /// independently of traversal work, before an app owner may publish the bytes.
    public func encoded(maximumUTF8Bytes: Int, operation: NEWFEATURESGraphOperation) throws -> Data {
        guard maximumUTF8Bytes > 0 else { throw NEWFEATURESError.invalidPolicy }
        try operation.checkpoint()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(self)
        try operation.checkpoint()
        guard data.count <= maximumUTF8Bytes else { throw NEWFEATURESGraphOutputFailure.byteLimit }
        return data
    }
}

public enum NEWFEATURESTraversalLimit: String, Codable, Sendable {
    case none
    case depth
    case functionCount
    case edgeVisits
    case cancelled
    case timedOut
}

public struct NEWFEATURESTraversalResult: Sendable {
    public let orderedFunctions: [NEWFEATURESFunctionKey]
    public let depthByFunction: [NEWFEATURESFunctionKey: Int]
    public let edgeVisits: Int
    public let limit: NEWFEATURESTraversalLimit
    public let excludedUnverifiedEdges: Int

    /// Completeness concerns only the traversable observed graph, never runtime reachability.
    public var isCompleteWithinObservedGraph: Bool { limit == .none }
}

public enum NEWFEATURESPathfinder {
    public static func shortestVerifiedPath(
        from source: NEWFEATURESFunctionKey,
        to destination: NEWFEATURESFunctionKey,
        graph: NEWFEATURESGraphSnapshot,
        budget: NEWFEATURESReadBudget,
        operation: NEWFEATURESGraphOperation
    ) throws -> NEWFEATURESPathReport {
        guard graph.contains(source), graph.contains(destination) else {
            throw NEWFEATURESError.malformedGraph("path endpoint absent or stale")
        }
        let walk = try NEWFEATURESGraphWalk.run(
            root: source, destination: destination, graph: graph, budget: budget, operation: operation
        )
        let status: NEWFEATURESPathStatus
        switch walk.limit {
        case .none: status = walk.found ? .found : .notFoundInObservedGraph
        case .depth: status = .depthLimit
        case .functionCount: status = .functionLimit
        case .edgeVisits: status = .edgeVisitLimit
        case .cancelled: status = .cancelled
        case .timedOut: status = .timedOut
        }
        return NEWFEATURESPathReport(
            source: source, destination: destination, status: status, path: walk.path,
            visitedFunctions: walk.order.count, visitedEdges: walk.visits,
            examinedUnverifiedEdges: walk.unverified, observedUnverifiedEdges: graph.unverifiedEdgeCount
        )
    }
}

public enum NEWFEATURESCallGraphTraversal {
    public static func expand(
        root: NEWFEATURESFunctionKey,
        graph: NEWFEATURESGraphSnapshot,
        budget: NEWFEATURESReadBudget,
        operation: NEWFEATURESGraphOperation
    ) throws -> NEWFEATURESTraversalResult {
        guard graph.contains(root) else { throw NEWFEATURESError.malformedGraph("root absent or stale") }
        let walk = try NEWFEATURESGraphWalk.run(
            root: root, destination: nil, graph: graph, budget: budget, operation: operation
        )
        return NEWFEATURESTraversalResult(
            orderedFunctions: walk.order, depthByFunction: walk.depth,
            edgeVisits: walk.visits, limit: walk.limit, excludedUnverifiedEdges: walk.unverified
        )
    }
}

private struct NEWFEATURESGraphWalk {
    var order: [NEWFEATURESFunctionKey]
    var depth: [NEWFEATURESFunctionKey: Int]
    var visits = 0
    var unverified = 0
    var limit: NEWFEATURESTraversalLimit = .none
    var found = false
    var path: [NEWFEATURESFunctionKey] = []

    static func run(root: NEWFEATURESFunctionKey, destination: NEWFEATURESFunctionKey?,
                    graph: NEWFEATURESGraphSnapshot, budget: NEWFEATURESReadBudget,
                    operation: NEWFEATURESGraphOperation) throws -> Self {
        var result = Self(order: [root], depth: [root: 0])
        var parents: [NEWFEATURESFunctionKey: NEWFEATURESFunctionKey] = [:]
        var head = 0
        do {
            try operation.checkpoint()
            if root == destination {
                result.found = true
                result.path = [root]
                return result
            }
            while head < result.order.count {
                try operation.checkpoint()
                let node = result.order[head]
                head += 1
                guard let depth = result.depth[node] else {
                    throw NEWFEATURESError.malformedGraph("missing traversal depth")
                }
                for edge in graph.observations(from: node.address) {
                    try operation.checkpoint()
                    guard result.visits < budget.maxEdgeVisits else {
                        result.limit = .edgeVisits
                        return result
                    }
                    result.visits += 1
                    guard edge.confidence.isTraversable else {
                        result.unverified += 1
                        continue
                    }
                    guard let neighbour = edge.callee else {
                        throw NEWFEATURESError.malformedGraph("traversable observation without a callee")
                    }
                    guard result.depth[neighbour] == nil else { continue }
                    // Boundary inspections still consume edge work. No contains/filter pass
                    // is allowed to examine an unbounded fan-out outside the counter.
                    guard depth < budget.maxDepth else {
                        result.limit = .depth
                        continue
                    }
                    guard result.order.count < budget.maxFunctions else {
                        result.limit = .functionCount
                        return result
                    }
                    parents[neighbour] = node
                    result.depth[neighbour] = depth + 1
                    result.order.append(neighbour)
                    if neighbour == destination {
                        var path = [neighbour]
                        var current = neighbour
                        while let previous = parents[current] {
                            try operation.checkpoint()
                            path.append(previous)
                            current = previous
                        }
                        result.path = Array(path.reversed())
                        result.found = true
                        result.limit = .none
                        return result
                    }
                }
            }
            try operation.checkpoint()
        } catch NEWFEATURESGraphInterruption.cancelled {
            result.limit = .cancelled
        } catch NEWFEATURESGraphInterruption.timedOut {
            result.limit = .timedOut
        }
        return result
    }
}
