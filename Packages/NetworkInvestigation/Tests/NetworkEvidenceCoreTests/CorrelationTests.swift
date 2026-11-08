import Foundation
import Testing
@testable import NetworkEvidenceCore

@Suite struct CorrelationTests {
    @Test func URLSchemeAndPortAreNotLostInEndpointCorrelation() throws {
        let context = try identity(), reference = candidate(context).reference
        let extracted = try #require(NetworkEndpointExtractor.candidate(
            from: "https://api.example.invalid:8443/flags?token=discarded", reference: reference))
        #expect(extracted.scheme == "https")
        #expect(extracted.port == 8443)
        let snapshot = try NetworkStaticSnapshot(identity: context, candidates: [extracted])
        let engine = NetworkCorrelationEngine()
        #expect(try engine.correlate(static: snapshot, flows: [flow(port: 8443)]).findings.count == 1)
        #expect(try engine.correlate(static: snapshot, flows: [flow()]).findings.isEmpty)
        #expect(try engine.correlate(static: snapshot, flows: [flow(port: nil)]).findings.first?.strength == .weakAssociation)
        #expect(try engine.correlate(static: snapshot, flows: [flow(scheme: "http", port: 8443)]).findings.isEmpty)
        let defaultPort = try #require(NetworkEndpointExtractor.candidate(
            from: "https://api.example.invalid/flags", reference: reference))
        let defaults = try NetworkStaticSnapshot(identity: context, candidates: [defaultPort])
        #expect(try engine.correlate(static: defaults, flows: [flow(port: 443)]).findings.count == 1)
    }
    @Test func exactEndpointRemainsHypothesisWithoutRuntime() throws {
        let context = try identity()
        let result = try NetworkCorrelationEngine().correlate(
            static: .init(identity: context, candidates: [candidate(context)]), flows: [flow()])
        #expect(result.findings.count == 1)
        #expect(result.findings[0].strength == .plausibleHypothesis)
        #expect(!result.findings.contains { $0.strength == .directlyObserved })
        #expect(result.findings[0].basis.contains(.staticCrossReference))
    }
    @Test func hostOnlyAndPathOnlyAreWeak() throws {
        let context = try identity()
        for c in [candidate(context, path: nil), candidate(context, host: nil)] {
            let result = try NetworkCorrelationEngine().correlate(static: .init(identity: context, candidates: [c]), flows: [flow()])
            #expect(result.findings.first?.strength == .weakAssociation)
        }
    }
    @Test func conflictingHostCannotBeRescuedByPath() throws {
        let context = try identity()
        let result = try NetworkCorrelationEngine().correlate(
            static: .init(identity: context, candidates: [candidate(context, host: "other.example.invalid")]), flows: [flow()])
        #expect(result.findings.isEmpty)
    }
    @Test func methodConflictIsExplicit() throws {
        let context = try identity()
        let result = try NetworkCorrelationEngine().correlate(
            static: .init(identity: context, candidates: [candidate(context, method: "POST")]), flows: [flow()])
        #expect(result.findings.first?.strength == .contradicted)
        #expect(result.findings.first?.basis.contains(.methodConflict) == true)
    }
    @Test func timestampsAndVendorPIDDoNotProveDataflow() throws {
        let context = try identity()
        let observed = flow(source: .vendorReported(name: "Target", processID: 123))
        let runtime = NetworkRuntimeReference(identity: context, debuggerSessionID: UUID(), processID: 123,
            capturedAt: fixtureDate, functionAddress: 0x1000, kind: .functionCall)
        let result = try NetworkCorrelationEngine().correlate(
            static: .init(identity: context, candidates: [candidate(context)]), flows: [observed], runtime: [runtime])
        #expect(result.findings[0].strength == .plausibleHypothesis)
        #expect(result.findings[0].basis.contains(.temporalAssociation))
        #expect(result.findings[0].limitations.contains { $0.contains("does not prove causality") })
    }
    @Test func explicitTraceCanCorroborateButNotProveValueConsumption() throws {
        let context = try identity(), observed = flow()
        let runtime = NetworkRuntimeReference(identity: context, debuggerSessionID: UUID(), processID: 123,
            capturedAt: fixtureDate, functionAddress: 0x1000, kind: .functionCall,
            flowIdentityDigest: observed.reference.identityDigest)
        let result = try NetworkCorrelationEngine().correlate(
            static: .init(identity: context, candidates: [candidate(context)]), flows: [observed], runtime: [runtime])
        #expect(result.findings[0].strength == .stronglySupported)
        #expect(result.findings[0].explanation.contains("remains unproven"))
    }
    @Test func staleBinaryRuntimeIsRejected() throws {
        let context = try identity()
        let runtime = NetworkRuntimeReference(identity: try identity(), debuggerSessionID: UUID(),
            processID: 123, capturedAt: fixtureDate, functionAddress: 0x1000, kind: .functionCall)
        #expect(throws: InvestigationError.staleAuthority) {
            try NetworkCorrelationEngine().correlate(static: .init(identity: context, candidates: [candidate(context)]),
                                                       flows: [flow()], runtime: [runtime])
        }
    }
    @Test func missingFlowsPreserveAlternativeExplanations() throws {
        let context = try identity()
        let result = try NetworkCorrelationEngine().correlate(static: .init(identity: context, candidates: [candidate(context)]), flows: [])
        #expect(result.findings.isEmpty)
        #expect(result.limitations.contains { $0.contains("never establishes absence") })
        #expect(result.limitations.contains { $0.contains("QUIC") })
    }
    @Test func multipleFunctionsRemainMultipleCandidates() throws {
        let context = try identity()
        let result = try NetworkCorrelationEngine().correlate(static: .init(identity: context,
            candidates: [candidate(context, function: 0x1000), candidate(context, function: 0x3000)]), flows: [flow()])
        #expect(result.findings.count == 2)
        #expect(Set(result.findings.map(\.staticReference.functionAddress)).count == 2)
    }
    @Test func appliedRulesAreNotUnmodifiedRemoteResponses() throws {
        let context = try identity()
        let result = try NetworkCorrelationEngine().correlate(static: .init(identity: context, candidates: [candidate(context)]),
            flows: [flow(rules: .vendorReportedApplied(["maplocal"]))])
        #expect(result.findings[0].limitations.contains { $0.contains("debugging tool") })
    }
    @Test func redactedRouteEqualityIsNotExactPathEvidence() throws {
        let context = try identity()
        let result = try NetworkCorrelationEngine().correlate(static: .init(identity: context,
            candidates: [candidate(context, path: "/users/:redacted")]), flows: [flow(path: "/users/:redacted")])
        #expect(result.findings[0].strength == .weakAssociation)
        #expect(!result.findings[0].basis.contains(.exactHostAndPath))
    }
    @Test func fieldOverlapIsExplicitAndBoundToSelectedFlow() throws {
        let context = try identity(), observed = flow()
        let result = try NetworkCorrelationEngine().correlate(static: .init(identity: context,
            candidates: [candidate(context, keys: ["enabled"])]), flows: [observed],
            details: [.init(summary: observed, responseFieldNames: ["enabled"])])
        #expect(result.findings[0].basis.contains(.responseFieldOverlap))
    }
    @Test func callGraphTraversalIsBoundedAndCycleSafe() throws {
        let context = try identity()
        let snapshot = try NetworkStaticSnapshot(identity: context, candidates: [candidate(context)], callEdges: [
            .init(caller: 2, callee: 1), .init(caller: 3, callee: 2), .init(caller: 1, callee: 3),
            .init(caller: 4, callee: 2),
        ])
        #expect(try NetworkCorrelationEngine().relatedFunctions(to: 1, in: snapshot) == [2, 3, 4])
        #expect(try NetworkCorrelationEngine().relatedFunctions(to: 1, in: snapshot, maximumFunctions: 1) == [2])
    }
    @Test func extractionOmitsCredentialsQueryAndFragment() throws {
        let context = try identity()
        let c = NetworkEndpointExtractor.candidate(from: "https://alice:SECRET@api.example.invalid/flags?token=SECRET#private",
                                                  reference: candidate(context).reference)
        #expect(c?.host == "api.example.invalid")
        #expect(c?.path == "/flags")
        let data = try JSONEncoder().encode(c)
        #expect(!String(decoding: data, as: UTF8.self).contains("SECRET"))
        #expect(NetworkEndpointExtractor.candidate(from: "javascript:alert(1)", reference: candidate(context).reference) == nil)
    }
    @Test func captureStatesRemainDistinct() {
        let id = UUID()
        #expect(NetworkCaptureAssessment.assess(status: nil, flows: []) == .statusNotQueried)
        #expect(NetworkCaptureAssessment.assess(status: nil, flows: [flow()]) == .matchingHTTPObservations)
        #expect(NetworkCaptureAssessment.assess(status: nil, flows: [flow(tls: .unknown)]) == .matchingTrafficVisibilityUnknown)
        #expect(NetworkCaptureAssessment.assess(status: .init(connectionID: id, observedAt: fixtureDate, recording: .stopped), flows: []) == .recordingStopped)
        #expect(NetworkCaptureAssessment.assess(status: .init(connectionID: id, observedAt: fixtureDate, recording: .recording), flows: []) == .recordingWithNoMatchingObservations)
        #expect(NetworkCaptureAssessment.assess(status: .init(connectionID: id, observedAt: fixtureDate), flows: [flow(tls: .connectionMetadataOnly)]) == .matchingConnectionMetadata)
    }
    @Test func userActionDoesNotBecomeStrongFunctionExecutionEvidence() throws {
        let context = try identity(), observed = flow()
        let event = NetworkRuntimeReference(identity: context, debuggerSessionID: UUID(), processID: 123,
            capturedAt: fixtureDate, functionAddress: 0x1000, kind: .userAction,
            flowIdentityDigest: observed.reference.identityDigest)
        let result = try NetworkCorrelationEngine().correlate(
            static: .init(identity: context, candidates: [candidate(context)]), flows: [observed], runtime: [event])
        #expect(result.findings.first?.strength != .stronglySupported)
        #expect(result.findings.first?.basis.contains(.runtimeFunctionObservation) == false)
    }
}
