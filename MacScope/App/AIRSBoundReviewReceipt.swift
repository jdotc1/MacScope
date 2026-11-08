import Darwin
import Foundation

/// A local claim about one terminal import attempt. It is not a recovery-semantics
/// attestation and is never written automatically or used to replay navigation.
struct AIRSBoundReviewReceipt {
    enum ExportFailure: LocalizedError {
        case invalidDestination
        case invalidDiagnostic
        case exists
        case writeFailed

        var errorDescription: String? {
            switch self {
            case .invalidDestination: "Choose a new local receipt file outside app resources and source inputs."
            case .invalidDiagnostic: "The receipt diagnostic exceeds the 4096-byte limit."
            case .exists: "The receipt file already exists; choose a new name."
            case .writeFailed: "The acknowledgment could not be saved."
            }
        }
    }

    let id: UUID
    let bytes: Data

    static func rejected(_ failure: AIRSBoundReviewImport.Failure,
                         request: AIRSBoundReviewImport? = nil,
                         diagnostic: String) throws -> Self {
        let destinationFailures: Set<AIRSBoundReviewImport.Failure> = [
            .identityUnavailable, .imageIdentityMismatch, .addressMappingMismatch, .staleDestination
        ]
        guard !destinationFailures.contains(failure) || request != nil else { throw ExportFailure.writeFailed }
        let sourceBound = destinationFailures.contains(failure)
        let outcome = failure == .readFailed ? "error" : "rejected"
        let admission = sourceBound ? "source_bound" : "not_validated"
        return try terminal(outcome: outcome, code: failure.rawValue, admission: admission,
                            request: sourceBound ? request : nil, diagnostic: diagnostic)
    }

    static func cancelled(request: AIRSBoundReviewImport,
                          destination: AIRSBoundReviewDestination) throws -> Self {
        try terminal(outcome: "cancelled", code: "user_cancelled", admission: "destination_verified",
                     request: request, destination: destination,
                     diagnostic: "The user cancelled before navigation.")
    }

    static func navigated(request: AIRSBoundReviewImport,
                          destination: AIRSBoundReviewDestination,
                          selectedImageID: UUID, selectedAddress: UInt64) throws -> Self {
        guard selectedImageID == destination.imageID,
              selectedAddress == destination.address else { throw ExportFailure.writeFailed }
        let navigation: Phase2ProductionJSONValue = .object([
            "requested_start": .string("0x" + String(destination.address, radix: 16)),
            "selected_start": .string("0x" + String(selectedAddress, radix: 16)),
            "selected_image_id": .string(selectedImageID.uuidString.lowercased())
        ])
        return try terminal(outcome: "navigated", code: "navigation_completed",
                            admission: "destination_verified", request: request,
                            destination: destination, navigation: navigation,
                            diagnostic: "The selected image and preferred address read back as requested.")
    }

    static func navigationFailed(request: AIRSBoundReviewImport,
                                 destination: AIRSBoundReviewDestination) throws -> Self {
        try terminal(outcome: "error", code: "navigation_failed", admission: "destination_verified",
                     request: request, destination: destination,
                     diagnostic: "The selected image and preferred address did not read back as requested.")
    }

    private static func terminal(outcome: String, code: String, admission: String,
                                 request: AIRSBoundReviewImport?,
                                 destination: AIRSBoundReviewDestination? = nil,
                                 navigation: Phase2ProductionJSONValue? = nil,
                                 diagnostic: String) throws -> Self {
        guard diagnostic.utf8.count <= 4_096 else { throw ExportFailure.invalidDiagnostic }
        let id = UUID()
        let timestamp = ISO8601DateFormatter()
        timestamp.formatOptions = [.withInternetDateTime]
        if let utc = TimeZone(secondsFromGMT: 0) { timestamp.timeZone = utc }
        let bundle = Bundle.main
        let consumer: Phase2ProductionJSONValue = .object([
            "bundle_id": .string(bundle.bundleIdentifier ?? "com.jeff.machscope"),
            "version": .string(bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unavailable"),
            "build": .string(bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unavailable"),
            "source_revision": .null,
            "build_provenance_state": .string("unavailable")
        ])
        let correlation: Phase2ProductionJSONValue = request.map {
            .object(["request_id": .string($0.requestID.uuidString.lowercased()),
                     "sha256": .string($0.requestSHA256),
                     "byte_count": .number(String($0.requestBytes.count))])
        } ?? .null
        let source: Phase2ProductionJSONValue = request?.sourceDescriptor.wire ?? .null
        let record: Phase2ProductionJSONValue = .object([
            "report_kind": .string("airs.macscope_bound_acknowledgment"),
            "schema_version": .number("1"),
            "acknowledgment_id": .string(id.uuidString.lowercased()),
            "request": correlation,
            "untrusted_request_id": .null,
            "source_report": source,
            "finding_id": request.map { .string($0.findingID) } ?? .null,
            "consumer": consumer,
            "profile": request == nil ? .null : .string(AIRSBoundReviewImport.profile),
            "completed_at": .string(timestamp.string(from: Date())),
            "outcome": .string(outcome),
            "code": .string(code),
            "admission": .string(admission),
            "destination": destination?.wire ?? .null,
            "navigation": navigation ?? .null,
            "semantics": .string("source_reported_not_consumer_verified"),
            "diagnostic": .string(diagnostic)
        ])
        let bytes = record.canonicalJSONBytes()
        guard bytes.count <= 1_048_576 else { throw ExportFailure.writeFailed }
        return Self(id: id, bytes: bytes)
    }

    /// Exclusive creation keeps source/archive inputs and any prior attempt immutable.
    /// A caller chooses the location explicitly; failure never claims a saved receipt.
    func export(to url: URL, protecting inputs: [URL]) throws {
        guard url.isFileURL, !url.lastPathComponent.isEmpty, !inputs.isEmpty else {
            throw ExportFailure.invalidDestination
        }
        let parent = url.deletingLastPathComponent().resolvingSymlinksInPath().standardizedFileURL
        let destination = parent.appendingPathComponent(url.lastPathComponent).standardizedFileURL
        let app = Bundle.main.bundleURL.resolvingSymlinksInPath().standardizedFileURL.path
        guard !Self.isInside(destination.path, root: app),
              inputs.allSatisfy({
                  !Self.isInside(destination.path, root: $0.resolvingSymlinksInPath().standardizedFileURL.path)
              }) else {
            throw ExportFailure.invalidDestination
        }
        // Publish only after the entire file is durable. A hard link in the same
        // directory creates the final name exclusively, with no partial receipt
        // visible at that name and no overwrite of an earlier attempt.
        let temporary = parent.appendingPathComponent(".airs-bound-\(UUID().uuidString).tmp")
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode_t(0o600))
        guard descriptor >= 0 else { throw ExportFailure.writeFailed }
        var descriptorOpen = true
        defer {
            if descriptorOpen { _ = close(descriptor) }
            _ = unlink(temporary.path)
        }
        let written = bytes.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return false }
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), raw.count - offset)
                if count <= 0 { return false }
                offset += count
            }
            return true
        }
        guard written, fsync(descriptor) == 0 else { throw ExportFailure.writeFailed }
        let closeResult = close(descriptor)
        descriptorOpen = false
        guard closeResult == 0 else { throw ExportFailure.writeFailed }
        guard link(temporary.path, destination.path) == 0 else {
            if errno == EEXIST { throw ExportFailure.exists }
            throw ExportFailure.writeFailed
        }
    }

    private static func isInside(_ path: String, root: String) -> Bool {
        path == root || path.hasPrefix(root + "/")
    }
}

/// A terminal-only source-admission path while verified whole-container identity
/// has no workspace owner. The caller may explicitly export `receipt` afterward;
/// this path cannot issue cancellation or navigation success.
struct AIRSBoundReviewTerminalAttempt {
    let admittedRequest: AIRSBoundReviewImport?
    let receipt: AIRSBoundReviewReceipt

    static func withoutContainerAuthority(bytes: Data) throws -> Self {
        try finish { try AIRSBoundReviewImport.parse(bytes) }
    }

    static func withoutContainerAuthority(fileURL: URL) throws -> Self {
        try finish { try AIRSBoundReviewImport.read(from: fileURL) }
    }

    private static func finish(_ importRequest: () throws -> AIRSBoundReviewImport) throws -> Self {
        do {
            let request = try importRequest()
            return Self(admittedRequest: request,
                        receipt: try AIRSBoundReviewReceipt.rejected(
                            .identityUnavailable, request: request,
                            diagnostic: "Verified whole-container and selected-slice offset authority is unavailable."))
        } catch let failure as AIRSBoundReviewImport.Failure {
            return Self(admittedRequest: nil,
                        receipt: try AIRSBoundReviewReceipt.rejected(
                            failure, diagnostic: failure.errorDescription ?? "Bound review admission failed."))
        }
    }
}
