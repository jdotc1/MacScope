import Foundation
@testable import NetworkEvidenceCore

let fixtureDate = Date(timeIntervalSince1970: 1_800_000_000)
let fixtureSHA = String(repeating: "a", count: 64)

func identity(workspaceID: UUID = UUID(), documentID: UUID = UUID(), installationID: UUID = UUID(),
              imageSlot: Int = 0, binarySHA256: String = fixtureSHA) throws -> WorkspaceInvestigationIdentity {
    try .init(workspaceID: workspaceID, documentID: documentID, installationID: installationID,
              binaryID: UUID(), imageSlot: imageSlot, architecture: "arm64", binarySHA256: binarySHA256,
              analysisGenerationID: UUID(), analysisSHA256: String(repeating: "b", count: 64))
}

func changingInstallation(_ value: WorkspaceInvestigationIdentity) throws -> WorkspaceInvestigationIdentity {
    try .init(workspaceID: value.workspaceID, documentID: value.documentID, installationID: UUID(),
              binaryID: value.binaryID, imageSlot: value.imageSlot, architecture: value.architecture,
              sliceIndex: value.sliceIndex, binarySHA256: value.binarySHA256,
              analysisGenerationID: UUID(), analysisSHA256: value.analysisSHA256)
}

func candidate(_ context: WorkspaceInvestigationIdentity, host: String? = "api.example.invalid",
               path: String? = "/flags", method: String? = nil, function: UInt64 = 0x1000,
               keys: [String] = []) -> StaticEndpointCandidate {
    .init(reference: .init(binarySHA256: context.binarySHA256, imageSlot: context.imageSlot,
                           address: 0x2000, functionAddress: function, functionName: "loadFlags", source: .crossReference),
          host: host, path: path, method: method, responseFieldNames: keys)
}

func flow(connectionID: UUID = UUID(), batchID: UUID = UUID(), scopeID: UUID = UUID(),
          host: String = "api.example.invalid", path: String = "/flags", method: String = "GET",
          scheme: String = "https", port: Int? = 443,
          tls: NetworkTLSVisibility = .decryptedHTTP, rules: NetworkRuleInfluence = .unknown,
          source: NetworkSourceAttribution = .unknown) -> NetworkFlowSummary {
    .init(reference: .init(connectionID: connectionID, batchID: batchID, scopeID: scopeID,
                          vendorFlowID: "42", identityDigest: String(repeating: "c", count: 64)),
          requestTime: fixtureDate, observedAt: fixtureDate, method: method, scheme: scheme,
          host: host, path: path, port: port, statusCode: 200, durationMilliseconds: 12, responseContentType: "application/json",
          source: source, tlsVisibility: tls, ruleInfluence: rules, bodyAvailability: .available)
}
