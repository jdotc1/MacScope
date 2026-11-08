import Foundation

public enum NEWFEATURESCallConfidence: String, Codable, Hashable, Sendable {
    case confirmedDirect
    case provenIndirect
    case unverified

    public var isTraversable: Bool { self != .unverified }
}

/// The caller and site are known, but no exact callee can be established. This is
/// retained as a nontraversable observation rather than a fabricated function key.
public struct NEWFEATURESUnresolvedCallEdge: Hashable, Sendable {
    public let caller: NEWFEATURESFunctionKey
    public let callSite: UInt64
    public let observedTarget: UInt64?

    public init(caller: NEWFEATURESFunctionKey, callSite: UInt64, observedTarget: UInt64? = nil) {
        self.caller = caller
        self.callSite = callSite
        self.observedTarget = observedTarget
    }
}

struct NEWFEATURESGraphObservation: Hashable, Sendable {
    let callerAddress: UInt64
    let callSite: UInt64
    let callee: NEWFEATURESFunctionKey?
    let observedTarget: UInt64?
    let confidence: NEWFEATURESCallConfidence
}

/// Inert observations: the app must establish decoded-call evidence and exact function
/// ownership before assigning a traversable confidence. Decoding does not establish it.
public struct NEWFEATURESCallEdge: Hashable, Codable, Sendable {
    public let caller: NEWFEATURESFunctionKey
    public let callee: NEWFEATURESFunctionKey
    public let callSite: UInt64
    public let confidence: NEWFEATURESCallConfidence

    public init(caller: NEWFEATURESFunctionKey, callee: NEWFEATURESFunctionKey,
                callSite: UInt64, confidence: NEWFEATURESCallConfidence) {
        self.caller = caller
        self.callee = callee
        self.callSite = callSite
        self.confidence = confidence
    }
}

/// A bounded, single-image graph. All identity dimensions must agree; bare addresses
/// from another image or analysis generation are never joined into this snapshot.
public struct NEWFEATURESGraphSnapshot: Sendable {
    public let image: NEWFEATURESImageKey
    public let functions: [NEWFEATURESFunctionKey]
    public let observedEdgeCount: Int
    public let unverifiedEdgeCount: Int
    private let addresses: Set<UInt64>
    private let adjacency: [UInt64: [NEWFEATURESGraphObservation]]

    private struct CallSite: Hashable {
        let caller: UInt64
        let address: UInt64
    }

    public init(
        functions: [NEWFEATURESFunctionKey],
        edges: [NEWFEATURESCallEdge],
        unresolvedEdges: [NEWFEATURESUnresolvedCallEdge] = [],
        operation: NEWFEATURESGraphOperation,
        limits: NEWFEATURESGraphInputLimits = .standard
    ) throws {
        try operation.checkpoint()
        guard let image = functions.first?.image, functions.count <= limits.maxFunctions,
              edges.count <= limits.maxEdges,
              unresolvedEdges.count <= limits.maxEdges - edges.count else {
            throw NEWFEATURESError.malformedGraph("input size limit")
        }

        var addresses: Set<UInt64> = []
        addresses.reserveCapacity(functions.count)
        for function in functions {
            try operation.checkpoint()
            guard function.image == image else {
                throw NEWFEATURESError.malformedGraph("mixed image or analysis identity")
            }
            guard addresses.insert(function.address).inserted else {
                throw NEWFEATURESError.malformedGraph("duplicate function address")
            }
        }

        var directTargets: [CallSite: UInt64] = [:]
        var indirectSites: Set<CallSite> = []
        var uniqueEdges: Set<NEWFEATURESGraphObservation> = []
        uniqueEdges.reserveCapacity(edges.count + unresolvedEdges.count)
        var adjacency: [UInt64: [NEWFEATURESGraphObservation]] = [:]
        var unverified = 0
        for edge in edges {
            try operation.checkpoint()
            guard edge.caller.image == image, edge.callee.image == image,
                  addresses.contains(edge.caller.address), addresses.contains(edge.callee.address) else {
                throw NEWFEATURESError.malformedGraph("edge without exact single-image function identity")
            }
            let site = CallSite(caller: edge.caller.address, address: edge.callSite)
            switch edge.confidence {
            case .confirmedDirect:
                guard !indirectSites.contains(site),
                      directTargets[site].map({ $0 == edge.callee.address }) ?? true else {
                    throw NEWFEATURESError.malformedGraph("contradictory verified call site")
                }
                directTargets[site] = edge.callee.address
            case .provenIndirect:
                guard directTargets[site] == nil else {
                    throw NEWFEATURESError.malformedGraph("contradictory verified call site")
                }
                indirectSites.insert(site)
            case .unverified:
                break
            }
            let observation = NEWFEATURESGraphObservation(
                callerAddress: edge.caller.address, callSite: edge.callSite, callee: edge.callee,
                observedTarget: edge.callee.address, confidence: edge.confidence
            )
            if uniqueEdges.insert(observation).inserted {
                adjacency[edge.caller.address, default: []].append(observation)
                if !edge.confidence.isTraversable { unverified += 1 }
            }
        }
        for edge in unresolvedEdges {
            try operation.checkpoint()
            guard edge.caller.image == image, addresses.contains(edge.caller.address) else {
                throw NEWFEATURESError.malformedGraph("unresolved call without exact caller identity")
            }
            let observation = NEWFEATURESGraphObservation(
                callerAddress: edge.caller.address, callSite: edge.callSite, callee: nil,
                observedTarget: edge.observedTarget, confidence: .unverified
            )
            if uniqueEdges.insert(observation).inserted {
                adjacency[edge.caller.address, default: []].append(observation)
                unverified += 1
            }
        }

        // Retain distinct call sites, including unverified observations. Traversal charges
        // every examined edge instead of doing an unmetered post-traversal filter.
        for address in Array(adjacency.keys) {
            try operation.checkpoint()
            guard var outgoing = adjacency[address] else { continue }
            try outgoing.sort {
                try operation.checkpoint()
                let lhsTarget = $0.callee?.address ?? $0.observedTarget ?? .max
                let rhsTarget = $1.callee?.address ?? $1.observedTarget ?? .max
                if lhsTarget != rhsTarget { return lhsTarget < rhsTarget }
                if $0.callSite != $1.callSite { return $0.callSite < $1.callSite }
                if ($0.callee == nil) != ($1.callee == nil) { return $0.callee != nil }
                if ($0.observedTarget == nil) != ($1.observedTarget == nil) { return $0.observedTarget != nil }
                return $0.confidence.rawValue < $1.confidence.rawValue
            }
            adjacency[address] = outgoing
        }
        var ordered = functions
        try ordered.sort {
            try operation.checkpoint()
            return $0.address < $1.address
        }
        try operation.checkpoint()
        self.image = image
        self.functions = ordered
        self.addresses = addresses
        self.adjacency = adjacency
        observedEdgeCount = uniqueEdges.count
        unverifiedEdgeCount = unverified
    }

    public func contains(_ function: NEWFEATURESFunctionKey) -> Bool {
        function.image == image && addresses.contains(function.address)
    }

    func observations(from address: UInt64) -> [NEWFEATURESGraphObservation] {
        adjacency[address] ?? []
    }
}
