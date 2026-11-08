import CryptoKit
import Foundation

// MacScopeApp adapter; current target flags implicitly import MacScopeAnalysisCore.
// This does not replace the existing model, matcher, corpus or standard singleton.
struct FunctionSignatureBundleManifest: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let architecture: String
    let producer: String
    let sourceCommit: String
    let payloadSHA256: String
    let payloadBytes: Int
}

/// App policy supplied independently of the bundle. Never decode this from a pack.
struct FunctionSignatureBundleTrustedPin: Hashable, Sendable {
    let producer: String
    let sourceCommit: String
    let payloadSHA256: String
}

enum FunctionSignatureBundleError: Error, Equatable {
    case productionPinUnavailable
    case authorityMismatch
    case payloadLength
    case digestMismatch
    case wireHeader
    case countLimit
    case truncatedPayload
    case trailingBytes
    case invalidUTF8
    case invalidPredicates([FunctionSignatureValidationIssue])
}

/// Opaque, immutable, in-process digest-bound receipt. It is not Codable and has
/// no caller-accessible initializer. It owns a detached immutable payload and its validated models.
final class FunctionSignatureBundleReceipt: Sendable {
    let manifest: FunctionSignatureBundleManifest
    let database: FunctionSignatureDatabase
    let matcher: FunctionSignatureMatcher
    private let retainedPayload: Data

    fileprivate init(payload: Data, manifest: FunctionSignatureBundleManifest,
                     database: FunctionSignatureDatabase, matcher: FunctionSignatureMatcher) {
        self.retainedPayload = payload
        self.manifest = manifest
        self.database = database
        self.matcher = matcher
    }
}

struct FunctionSignatureBundleConsumer: Sendable {
    private let trustedPins: Set<FunctionSignatureBundleTrustedPin>

    /// No shipped corpus is promoted into independently attested provenance.
    static let production = FunctionSignatureBundleConsumer(independentTrustedPins: [])

    /// The caller is the app's trusted configuration boundary, never the manifest
    /// decoder. The supplied source closure has no approved production pin source.
    init(independentTrustedPins: Set<FunctionSignatureBundleTrustedPin>) {
        trustedPins = independentTrustedPins
    }

    var isAvailable: Bool { !trustedPins.isEmpty }

    /// Fresh admission only. A caller retaining a receipt must call reuse instead;
    /// there is deliberately no automatic revalidation fallback from that path.
    func admitNewPayload(_ payload: Data, manifest: FunctionSignatureBundleManifest) throws
        -> FunctionSignatureBundleReceipt {
        try validateAuthority(manifest)
        guard (12...FunctionSignatureBundleCodec.maximumPayloadBytes).contains(payload.count),
              manifest.payloadBytes == payload.count else { throw FunctionSignatureBundleError.payloadLength }
        // Detach from caller-owned or bridged mutable storage before the one digest.
        let retainedPayload = Data(Array(payload))
        let observed = SHA256.hash(data: retainedPayload).map { String(format: "%02x", $0) }.joined()
        guard observed == manifest.payloadSHA256 else { throw FunctionSignatureBundleError.digestMismatch }
        let database = try FunctionSignatureBundleCodec.decode(retainedPayload)
        let matcher = FunctionSignatureMatcher(database: database)
        // Identical repeated identity/predicate rows keep the matcher's existing
        // deduplication issue and one usable record. No malformed row is dropped.
        let invalid = matcher.validationIssues.filter { $0.reason != .duplicatePredicate }
        guard invalid.isEmpty else { throw FunctionSignatureBundleError.invalidPredicates(invalid) }
        return .init(payload: retainedPayload, manifest: manifest, database: database, matcher: matcher)
    }

    /// Rechecks current independent policy, but neither hashes bytes nor reruns
    /// matcher validation. No payload parameter exists to substitute changed data.
    func reuse(_ receipt: FunctionSignatureBundleReceipt) throws -> FunctionSignatureBundleReceipt {
        try validateAuthority(receipt.manifest)
        return receipt
    }

    private func validateAuthority(_ manifest: FunctionSignatureBundleManifest) throws {
        guard !trustedPins.isEmpty else { throw FunctionSignatureBundleError.productionPinUnavailable }
        guard manifest.schemaVersion == Int(FunctionSignatureDatabase.currentSchemaVersion),
              manifest.architecture == "arm64",
              (12...FunctionSignatureBundleCodec.maximumPayloadBytes).contains(manifest.payloadBytes),
              !manifest.producer.isEmpty, manifest.producer.utf8.count <= 256,
              !manifest.producer.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
              Self.isLowerHex(manifest.sourceCommit, count: 40),
              Self.isLowerHex(manifest.payloadSHA256, count: 64),
              trustedPins.contains(.init(producer: manifest.producer, sourceCommit: manifest.sourceCommit,
                                        payloadSHA256: manifest.payloadSHA256)) else {
            throw FunctionSignatureBundleError.authorityMismatch
        }
    }

    private static func isLowerHex(_ value: String, count: Int) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}
