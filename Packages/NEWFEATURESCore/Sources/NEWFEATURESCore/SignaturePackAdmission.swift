import CryptoKit
import Foundation

/// An independently defined MacScope pack, NOT a parser for proprietary third-party
/// FLIRT .sig/.pat formats. The existing FunctionSignatureMatcher owns matching.
public struct NEWFEATURESSignaturePackManifest: Codable, Sendable {
    public let schemaVersion: Int
    public let architecture: String
    public let producer: String
    public let sourceCommit: String
    public let payloadSHA256: String
    public let payloadBytes: Int

    public init(
        schemaVersion: Int,
        architecture: String,
        producer: String,
        sourceCommit: String,
        payloadSHA256: String,
        payloadBytes: Int
    ) {
        self.schemaVersion = schemaVersion
        self.architecture = architecture
        self.producer = producer
        self.sourceCommit = sourceCommit
        self.payloadSHA256 = payloadSHA256
        self.payloadBytes = payloadBytes
    }
}

public struct NEWFEATURESAdmittedSignaturePayload: Sendable {
    public let data: Data
    public let sha256: String
    public let producer: String
}

/// Independently pinned local source-tree/corpus policy. Not read from the
/// arbitrary pack under inspection. Does not replace FunctionSignatureDatabase
/// predicate/collision validation at the real MacScope integration point.
public struct NEWFEATURESTrustedSignaturePin: Sendable {
    public let producer: String
    public let sourceCommit: String
    public let payloadSHA256: String

    public init(producer: String, sourceCommit: String, payloadSHA256: String) {
        self.producer = producer
        self.sourceCommit = sourceCommit
        self.payloadSHA256 = payloadSHA256
    }
}

public enum NEWFEATURESSignaturePackAdmission {
    public static let maximumPayloadBytes = 32 * 1_024 * 1_024

    public static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public static func admit(
        payload: Data,
        manifest: NEWFEATURESSignaturePackManifest,
        trustedPins: [NEWFEATURESTrustedSignaturePin]
    ) throws -> NEWFEATURESAdmittedSignaturePayload {
        guard manifest.schemaVersion == 1, manifest.architecture == "arm64",
              manifest.payloadBytes == payload.count,
              (1...maximumPayloadBytes).contains(payload.count),
              !manifest.producer.isEmpty, manifest.producer.utf8.count <= 256,
              trustedPins.contains(where: {
                  $0.producer == manifest.producer &&
                  $0.sourceCommit == manifest.sourceCommit &&
                  $0.payloadSHA256 == manifest.payloadSHA256
              }),
              manifest.sourceCommit.utf8.count == 40,
              manifest.sourceCommit.utf8.allSatisfy({
                  (48...57).contains($0) || (97...102).contains($0)
              }) else {
            throw NEWFEATURESError.malformedFact("signature pack authority")
        }
        let observed = digest(payload)
        guard observed == manifest.payloadSHA256 else {
            throw NEWFEATURESError.malformedFact("signature pack digest")
        }
        // The production adapter must decode this payload to its existing
        // FunctionSignatureDatabase and run that model's full validator.
        return NEWFEATURESAdmittedSignaturePayload(data: payload, sha256: observed, producer: manifest.producer)
    }
}
