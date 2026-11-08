import Foundation

public enum NetworkEndpointExtractor {
    /// Interpret a single existing binary string. The caller supplies an actual static reference.
    /// Query values, fragments, URL user-info and the original string are never retained.
    public static func candidate(from value: String, reference: StaticCodeReference) -> StaticEndpointCandidate? {
        guard value.utf8.count <= 4096 else { return nil }
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if let components = URLComponents(string: text),
           ProxymanPrivacy.isSupportedScheme(components.scheme?.lowercased() ?? ""),
           let rawHost = components.host {
            let host = rawHost.lowercased()
            guard NetworkStaticSnapshot.isHost(host), components.port.map({ (1...65535).contains($0) }) ?? true else { return nil }
            let path = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
            return .init(reference: reference, host: host, path: ProxymanPrivacy.minimizedPath(path),
                         scheme: components.scheme?.lowercased(), port: components.port)
        }
        if NetworkStaticSnapshot.isHost(text.lowercased()), text.contains("."),
           !text.contains(" ") {
            return .init(reference: reference, host: text.lowercased())
        }
        if text.hasPrefix("/"), !text.hasPrefix("//"), !text.contains(" "),
           let components = URLComponents(string: text) {
            return .init(reference: reference, path: ProxymanPrivacy.minimizedPath(components.percentEncodedPath))
        }
        return nil
    }
}

public struct NetworkCorrelationEngine: Sendable {
    public let maximumFindings: Int
    public init(maximumFindings: Int = 256) { self.maximumFindings = max(1, min(512, maximumFindings)) }

    public func correlate(static snapshot: NetworkStaticSnapshot, flows: [NetworkFlowSummary],
                          details: [NetworkFlowDetail] = [], runtime: [NetworkRuntimeReference] = []) throws -> NetworkCorrelationResult {
        try snapshot.validate()
        guard flows.count <= 100, details.count <= 100, runtime.count <= 256 else { throw InvestigationError.bounds }
        for observation in runtime {
            guard observation.identity == snapshot.identity,
                  observation.processID > 0, observation.capturedAt.timeIntervalSince1970.isFinite,
                  observation.flowIdentityDigest.map(InvestigationDigest.isValid) ?? true else {
                throw InvestigationError.staleAuthority
            }
        }
        guard Set(flows.map(\.reference)).count == flows.count,
              Set(details.map(\.summary.reference)).count == details.count,
              details.allSatisfy({ detail in flows.contains { $0.reference == detail.summary.reference } })
        else { throw InvestigationError.invalidInput }
        let fields = Dictionary(uniqueKeysWithValues: details.map { ($0.summary.reference, Set($0.responseFieldNames)) })
        var findings: [NetworkCorrelationFinding] = []
        var limited = false
        for flow in flows {
            guard flow.requestTime.timeIntervalSince1970.isFinite,
                  NetworkStaticSnapshot.isHost(flow.host),
                  InvestigationDigest.isValid(flow.reference.identityDigest) else {
                throw InvestigationError.invalidInput
            }
            for candidate in snapshot.candidates {
                let host = candidate.host.map { $0 == flow.host } ?? false
                var path = candidate.path.map { $0 == flow.path && $0 != "/"
                    && !$0.contains(":redacted") && !flow.path.contains(":redacted") } ?? false
                // A known, conflicting host must not be rescued by a generic matching path/key.
                if let expectedHost = candidate.host, expectedHost != flow.host { continue }
                if let scheme = candidate.scheme, scheme != flow.scheme { continue }
                if candidate.port != nil || candidate.scheme != nil {
                    func effectivePort(_ port: Int?, scheme: String?) -> Int? {
                        port ?? ((scheme == "https" || scheme == "wss") ? 443 : ((scheme == "http" || scheme == "ws") ? 80 : nil))
                    }
                    if let expected = effectivePort(candidate.port, scheme: candidate.scheme) {
                        if let observed = flow.port {
                            if expected != observed { continue }
                        } else { path = false }
                    }
                }
                let keyOverlap = !(Set(candidate.responseFieldNames).intersection(fields[flow.reference] ?? [])).isEmpty
                guard host || path || (keyOverlap && candidate.host == nil && candidate.path == nil) else { continue }
                guard findings.count < maximumFindings else { limited = true; continue }

                var basis: [NetworkCorrelationBasis] = []
                if host && path { basis.append(.exactHostAndPath) }
                else if host { basis.append(.hostOnly) }
                else if path { basis.append(.pathOnly) }
                if keyOverlap { basis.append(.responseFieldOverlap) }
                if candidate.reference.source == .crossReference { basis.append(.staticCrossReference) }
                let functionRuntime = runtime.filter {
                    guard let address = candidate.reference.functionAddress else { return false }
                    return $0.kind != .userAction && $0.functionAddress == address
                }
                let linkedRuntime = functionRuntime.filter { $0.flowIdentityDigest == flow.reference.identityDigest }
                let temporalRuntime = functionRuntime.filter {
                    abs($0.capturedAt.timeIntervalSince(flow.requestTime)) <= 2
                }
                if !functionRuntime.isEmpty { basis.append(.runtimeFunctionObservation) }
                if !linkedRuntime.isEmpty { basis.append(.explicitRuntimeFlowLink) }
                if !temporalRuntime.isEmpty { basis.append(.temporalAssociation) }
                var strength: NetworkEvidenceStrength = host && path ? .plausibleHypothesis : .weakAssociation
                var explanation = host && path
                    ? "An embedded endpoint matches this captured host and path. Execution and response consumption by the referenced function are not demonstrated."
                    : "A shared endpoint component or field name is a candidate association. It does not identify the function that issued this request."
                if host && path && !linkedRuntime.isEmpty {
                    strength = .stronglySupported
                    explanation = "The endpoint match is corroborated by an app-supplied runtime trace linking this flow identity to the referenced function. End-to-end value propagation remains unproven."
                }
                if let method = candidate.method {
                    if method == flow.method { basis.append(.methodAgreement) }
                    else {
                        basis.append(.methodConflict)
                        strength = .contradicted
                        explanation = "The expected static method conflicts with this observation. This candidate does not explain this request as currently specified; other requests or code paths remain possible."
                    }
                }
                var limitations = ["Heuristic correlation; no calibrated probability is assigned.",
                                   "A captured response is an observation in Proxyman, not proof of an unmodified remote-server response.",
                                   "Vendor application names and process IDs alone do not authenticate the selected binary."]
                if !temporalRuntime.isEmpty && linkedRuntime.isEmpty {
                    limitations.append("Temporal proximity does not prove causality or request ownership.")
                }
                switch flow.ruleInfluence {
                case .unknown: limitations.append("Local interception-rule influence is unknown.")
                case .possible: limitations.append("Existing rules may have influenced this response.")
                case .vendorReportedApplied: limitations.append("Proxyman reports a matching/applied debugging tool; experimental influence must be reviewed.")
                case .vendorReportedNone: limitations.append("No rule influence was reported for this flow; this is not a global exclusion of modifications.")
                }
                let relevantRuntime = (linkedRuntime + temporalRuntime).map(\.id)
                findings.append(.init(flow: flow.reference, staticReference: candidate.reference,
                    runtimeIDs: Array(Set(relevantRuntime)).sorted { $0.uuidString < $1.uuidString },
                    strength: strength, basis: basis, explanation: explanation, limitations: limitations))
            }
        }
        var limitations = [
            "Static references describe recovered code structure, not observed execution.",
            "Flow IDs are transient; original captures remain in Proxyman.",
            "No matching flow never establishes absence of application network behavior.",
            "Missing observations may reflect proxy bypass, TLS inspection gaps, certificate pinning, QUIC, other transports, an incomplete interval, or different operating conditions.",
        ]
        if !snapshot.isComplete { limitations.append("Static candidates are a bounded selection and may omit endpoints or callers.") }
        if limited { limitations.append("The finding limit was reached; additional candidate associations were omitted.") }
        let hypotheses = findings.filter { $0.strength == .plausibleHypothesis }.prefix(16).map {
            NetworkHypothesis(statement: "The referenced function may participate in the observed endpoint workflow.",
                supportingFindingIDs: [$0.id],
                requiredObservation: "Collect an authorized runtime call observation and a flow-correlated trace, then compare the actual response-decoding path. Any traffic-changing experiment requires a separate human approval.")
        }
        return .init(findings: findings, hypotheses: hypotheses, limitations: limitations)
    }

    /// Static potential callers only; bounded breadth-first traversal handles cycles deterministically.
    public func relatedFunctions(to address: UInt64, in snapshot: NetworkStaticSnapshot,
                                 maximumDepth: Int = 3, maximumFunctions: Int = 64) throws -> [UInt64] {
        try snapshot.validate()
        guard (0...5).contains(maximumDepth), (1...128).contains(maximumFunctions) else { throw InvestigationError.bounds }
        var visited: Set<UInt64> = [address]
        var frontier = [address]
        var result: [UInt64] = []
        for _ in 0..<maximumDepth {
            let frontierSet = Set(frontier)
            let candidates = Set(snapshot.callEdges.filter { frontierSet.contains($0.callee) }.map(\.caller)).sorted()
            frontier = []
            for caller in candidates where !visited.contains(caller) {
                guard result.count < maximumFunctions else { return result }
                visited.insert(caller); frontier.append(caller); result.append(caller)
            }
            if frontier.isEmpty { break }
        }
        return result
    }
}

public enum NetworkCaptureAssessment: String, Codable, Sendable {
    case connectionUnavailable, recordingUnknown, recordingStopped, recordingWithNoMatchingObservations
    case matchingConnectionMetadata, matchingHTTPObservations, matchingTrafficVisibilityUnknown, statusNotQueried

    public static func assess(status: ProxymanEnvironmentStatus?, flows: [NetworkFlowSummary]) -> Self {
        // Historical flows can coexist with recording off. Recording status is shown separately.
        if !flows.isEmpty {
            if flows.contains(where: { $0.tlsVisibility == .plaintextHTTP || $0.tlsVisibility == .decryptedHTTP }) {
                return .matchingHTTPObservations
            }
            return flows.allSatisfy { $0.tlsVisibility == .connectionMetadataOnly }
                ? .matchingConnectionMetadata : .matchingTrafficVisibilityUnknown
        }
        guard let status else { return .statusNotQueried }
        switch status.recording {
        case .recording: return .recordingWithNoMatchingObservations
        case .stopped: return .recordingStopped
        case .unknown: return .recordingUnknown
        }
    }
}
