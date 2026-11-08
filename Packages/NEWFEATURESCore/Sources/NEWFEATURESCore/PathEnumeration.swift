import Foundation

/// One verified call site backing a hop. Only traversable confidences appear here.
public struct NEWFEATURESHopSite: Hashable, Sendable {
    public let callSite: UInt64
    public let confidence: NEWFEATURESCallConfidence
}

/// One caller-to-callee step with every retained verified call site (sorted, capped).
public struct NEWFEATURESEvidencedHop: Hashable, Sendable {
    public let caller: NEWFEATURESFunctionKey
    public let callee: NEWFEATURESFunctionKey
    public let sites: [NEWFEATURESHopSite]
    /// Number of verified sites between the pair, which can exceed `sites.count`.
    public let siteCount: Int
}

public enum NEWFEATURESEnumerationCut: String, Sendable {
    case pathLimit
    case edgeVisitLimit
    case cancelled
    case timedOut
}

public struct NEWFEATURESPathEnumeration: Sendable {
    /// Simple paths ordered by hop count, then by callee addresses; stable for a given graph.
    public let paths: [[NEWFEATURESEvidencedHop]]
    /// nil when every simple path within `maxDepth` was found.
    public let cut: NEWFEATURESEnumerationCut?
    public let maxDepth: Int
    public let edgeVisits: Int
    public let maxEdgeVisits: Int
    public let maxPaths: Int
    public let observedUnverifiedEdges: Int

    public var isComplete: Bool { cut == nil }
}

public enum NEWFEATURESPathEnumerator {
    public static let maximumSitesPerHop = 8

    /// Enumerates simple verified paths. Unverified observations are never traversed.
    /// Work is charged per examined edge against `budget.maxEdgeVisits`.
    public static func enumerate(
        from source: NEWFEATURESFunctionKey,
        to destination: NEWFEATURESFunctionKey,
        graph: NEWFEATURESGraphSnapshot,
        maxDepth: Int,
        maxPaths: Int,
        budget: NEWFEATURESReadBudget,
        operation: NEWFEATURESGraphOperation
    ) throws -> NEWFEATURESPathEnumeration {
        guard (0...16).contains(maxDepth), (1...10_000).contains(maxPaths) else {
            throw NEWFEATURESError.invalidPolicy
        }
        guard graph.contains(source), graph.contains(destination) else {
            throw NEWFEATURESError.malformedGraph("path endpoint absent or stale")
        }
        var found: [[NEWFEATURESEvidencedHop]] = []
        var visits = 0
        var cut: NEWFEATURESEnumerationCut?

        struct Hop {
            var callee: NEWFEATURESFunctionKey
            var sites: [NEWFEATURESHopSite]
            var siteCount: Int
        }
        struct Frame {
            var node: NEWFEATURESFunctionKey
            var hops: [Hop]
            var next: Int
        }
        var successorCache: [UInt64: [Hop]] = [:]
        func successors(of node: NEWFEATURESFunctionKey) -> [Hop] {
            if let cached = successorCache[node.address] { return cached }
            var order: [NEWFEATURESFunctionKey] = []
            var grouped: [NEWFEATURESFunctionKey: [NEWFEATURESHopSite]] = [:]
            for observation in graph.observations(from: node.address) where observation.confidence.isTraversable {
                guard let callee = observation.callee else { continue }
                if grouped[callee] == nil { order.append(callee) }
                grouped[callee, default: []].append(
                    NEWFEATURESHopSite(callSite: observation.callSite, confidence: observation.confidence))
            }
            let hops = order.sorted().map { callee -> Hop in
                let sites = grouped[callee, default: []].sorted { $0.callSite < $1.callSite }
                return Hop(callee: callee, sites: Array(sites.prefix(maximumSitesPerHop)), siteCount: sites.count)
            }
            successorCache[node.address] = hops
            return hops
        }

        do {
            try operation.checkpoint()
            if source == destination {
                found.append([])
            } else {
                var onPath: Set<NEWFEATURESFunctionKey> = [source]
                var stack = [Frame(node: source, hops: successors(of: source), next: 0)]
                var trail: [(caller: NEWFEATURESFunctionKey, hop: Hop)] = []
                search: while !stack.isEmpty {
                    try operation.checkpoint()
                    var frame = stack.removeLast()
                    if frame.next >= frame.hops.count {
                        onPath.remove(frame.node)
                        if !trail.isEmpty { trail.removeLast() }
                        continue
                    }
                    let hop = frame.hops[frame.next]
                    frame.next += 1
                    stack.append(frame)
                    guard visits < budget.maxEdgeVisits else { cut = .edgeVisitLimit; break search }
                    visits += 1
                    if onPath.contains(hop.callee) || trail.count >= maxDepth { continue }
                    if hop.callee == destination {
                        let steps = trail + [(frame.node, hop)]
                        found.append(steps.map {
                            NEWFEATURESEvidencedHop(caller: $0.caller, callee: $0.hop.callee,
                                                    sites: $0.hop.sites, siteCount: $0.hop.siteCount)
                        })
                        if found.count >= maxPaths { cut = .pathLimit; break search }
                        continue
                    }
                    guard trail.count + 1 < maxDepth else { continue }
                    onPath.insert(hop.callee)
                    trail.append((frame.node, hop))
                    stack.append(Frame(node: hop.callee, hops: successors(of: hop.callee), next: 0))
                }
            }
        } catch NEWFEATURESGraphInterruption.cancelled {
            cut = .cancelled
        } catch NEWFEATURESGraphInterruption.timedOut {
            cut = .timedOut
        }
        let ordered = found.sorted { lhs, rhs in
            if lhs.count != rhs.count { return lhs.count < rhs.count }
            for (a, b) in zip(lhs, rhs) where a.callee != b.callee { return a.callee < b.callee }
            return false
        }
        return NEWFEATURESPathEnumeration(
            paths: ordered, cut: cut, maxDepth: maxDepth, edgeVisits: visits,
            maxEdgeVisits: budget.maxEdgeVisits, maxPaths: maxPaths,
            observedUnverifiedEdges: graph.unverifiedEdgeCount
        )
    }
}
