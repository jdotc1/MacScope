import CryptoKit
import Darwin
import Foundation

/// The stronger AIRS transport is admitted independently of the manual-v1 JSON import.
/// The original report and request payloads remain byte-for-byte available for a receipt.
struct AIRSBoundReviewImport {
    static let kind = "airs.macscope_bound_request"
    static let profile = "exact_artifact_source_report_navigation_v1"
    static let maximumArchiveBytes = 32 * 1_024 * 1_024
    static let maximumRequestBytes = 1_048_576

    enum Failure: String, Error, LocalizedError {
        case readFailed = "read_failed"
        case malformedTransport = "malformed_transport"
        case attachmentIdentityMismatch = "attachment_identity_mismatch"
        case unsupportedContract = "unsupported_contract"
        case profileLimit = "profile_limit"
        case invalidSourceReport = "invalid_source_report"
        case unsupportedConfiguration = "unsupported_configuration"
        case findingNotUnique = "finding_not_unique"
        case configurationMismatch = "configuration_mismatch"
        case projectionMismatch = "projection_mismatch"
        case identityUnavailable = "identity_unavailable"
        case imageIdentityMismatch = "image_identity_mismatch"
        case addressMappingMismatch = "address_mapping_mismatch"
        case staleDestination = "stale_destination"
        case navigationFailed = "navigation_failed"

        var errorDescription: String? { "AIRS bound review: \(rawValue.replacingOccurrences(of: "_", with: " "))." }
    }

    struct Descriptor {
        let attachmentID: UUID
        let sha256: String
        let byteCount: Int

        var wire: Phase2ProductionJSONValue {
            .object(["attachment_id": .string(attachmentID.uuidString.lowercased()),
                     "sha256": .string(sha256), "byte_count": .number(String(byteCount))])
        }
    }

    let requestID: UUID
    let requestSHA256: String
    let requestBytes: Data
    let sourceDescriptor: Descriptor
    let sourceBytes: Data
    let findingID: String
    let configurationRecorded: Bool
    private let handoff: AIRSHandoffImport
    var findingStart: UInt64 { handoff.start }
    /// Read-only presentation of the already source-bound projection; never re-import as manual v1.
    var sourceReportedFinding: AIRSHandoffImport { handoff }

    func destination(binary: BinaryImage) throws -> AIRSBoundReviewDestination {
        guard binary.artifactIntegrityState == .verified,
              let identity = binary.artifactIdentity,
              binary.preferredSegmentLayout != nil,
              let witness = binary.containerAdmissionWitness,
              witness.selectedSliceIdentity == identity else { throw Failure.identityUnavailable }
        guard witness.containerSHA256 == handoff.containerSHA256,
              witness.sliceOffset == handoff.sliceOffset,
              witness.sliceSize == handoff.sliceSize else { throw Failure.imageIdentityMismatch }
        let address: UInt64
        do { address = try handoff.destinationAddress(binary: binary) }
        catch AIRSHandoffImport.Failure.missingVerifiedImage { throw Failure.identityUnavailable }
        catch AIRSHandoffImport.Failure.imageMismatch { throw Failure.imageIdentityMismatch }
        catch { throw Failure.addressMappingMismatch }
        return AIRSBoundReviewDestination(binary: binary, identity: identity,
                                          witness: witness, preferredBase: handoff.preferredBase,
                                          address: address)
    }

    static func read(from url: URL) throws -> Self {
        guard url.isFileURL else { throw Failure.readFailed }
        let descriptor = open(url.path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw Failure.readFailed }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? file.close() }
        var before = stat()
        guard fstat(descriptor, &before) == 0, before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              before.st_size >= 0 else { throw Failure.readFailed }
        guard before.st_size <= off_t(maximumArchiveBytes) else { throw Failure.profileLimit }
        var bytes = Data()
        while bytes.count <= maximumArchiveBytes {
            let piece: Data
            do { piece = try file.read(upToCount: min(65_536, maximumArchiveBytes + 1 - bytes.count)) ?? Data() }
            catch { throw Failure.readFailed }
            if piece.isEmpty { break }
            bytes.append(piece)
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              bytes.count == Int(before.st_size), bytes.count <= maximumArchiveBytes,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw Failure.readFailed }
        return try parse(bytes)
    }

    static func parse(_ data: Data) throws -> Self {
        guard !data.isEmpty else { throw Failure.malformedTransport }
        guard data.count <= maximumArchiveBytes else { throw Failure.profileLimit }
        let archive: [String: Node]
        do { archive = try object(try json(data), keys: ["kind", "schemaVersion", "attachments", "components"]) }
        catch Failure.profileLimit { throw Failure.profileLimit }
        catch { throw Failure.malformedTransport }
        guard (try? text(archive["kind"])) == "airs.review",
              (try? integer(archive["schemaVersion"])) == 1 else {
            throw Failure.unsupportedContract
        }
        guard let components = archive["components"]?.arrayValue, components.isEmpty,
              let items = archive["attachments"]?.arrayValue, items.count == 2 else {
            throw Failure.malformedTransport
        }
        let attachments = try items.map(attachment)
        guard attachments[0].descriptor.attachmentID != attachments[1].descriptor.attachmentID,
              let request = attachments.first(where: { $0.kind == kind }),
              let source = attachments.first(where: { $0.kind == "airs.audit" }) else {
            throw Failure.unsupportedContract
        }
        guard request.bytes.count <= maximumRequestBytes else { throw Failure.profileLimit }

        let root: [String: Node]
        do {
            root = try object(try json(request.bytes), keys: ["report_kind", "schema_version", "request_id", "profile",
                                                               "source_report", "finding_id", "configuration", "projection"])
        } catch Failure.profileLimit { throw Failure.profileLimit }
        catch { throw Failure.malformedTransport }
        guard (try? text(root["report_kind"])) == kind,
              (try? integer(root["schema_version"])) == 1,
              (try? text(root["profile"])) == profile,
              let requestID = try? uuid(root["request_id"]),
              let findingID = try? text(root["finding_id"]),
              findingID.range(of: "^airsf-[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw Failure.unsupportedContract
        }
        let declaredSource = try descriptor(root["source_report"])
        guard declaredSource.attachmentID == source.descriptor.attachmentID,
              declaredSource.sha256 == source.descriptor.sha256,
              declaredSource.byteCount == source.descriptor.byteCount else {
            throw Failure.attachmentIdentityMismatch
        }
        let (expectedProjection, expectedConfiguration) = try projectedReport(source.bytes, findingID: findingID)
        guard supportedProjectionNumbers(expectedProjection) else { throw Failure.profileLimit }
        guard let configuration = root["configuration"], equal(configuration, expectedConfiguration) else {
            throw Failure.configurationMismatch
        }
        guard let projection = root["projection"], equal(projection, expectedProjection) else {
            throw Failure.projectionMismatch
        }
        let projectionBytes = projection.canonicalJSONBytes()
        guard projectionBytes.count <= maximumRequestBytes else { throw Failure.profileLimit }
        let handoff: AIRSHandoffImport
        do { handoff = try AIRSHandoffImport.parse(projectionBytes) }
        catch { throw Failure.profileLimit }
        let recorded = expectedConfiguration.objectValue?["state"]?.stringValue == "recorded"
        return Self(requestID: requestID, requestSHA256: request.descriptor.sha256,
                    requestBytes: request.bytes, sourceDescriptor: source.descriptor,
                    sourceBytes: source.bytes, findingID: findingID,
                    configurationRecorded: recorded, handoff: handoff)
    }

    private typealias Node = Phase2ProductionJSONValue
    private struct Attachment {
        let kind: String
        let descriptor: Descriptor
        let bytes: Data
    }

    private static func json(_ bytes: Data) throws -> Node {
        do {
            let value = try Phase2StrictJSONParser().parse(bytes, limits: .init(maximumBytes: maximumArchiveBytes,
                                                                                maximumDepth: 96,
                                                                                maximumTokens: 400_000,
                                                                                maximumMembersAndElements: 100_000))
            guard stringsWithinBudget(value) else { throw Failure.profileLimit }
            return value
        } catch let failure as Phase2StrictJSONError {
            switch failure {
            case .byteLimitExceeded, .depthLimitExceeded, .tokenLimitExceeded, .memberLimitExceeded:
                throw Failure.profileLimit
            default: throw Failure.malformedTransport
            }
        }
    }

    private static func stringsWithinBudget(_ value: Node) -> Bool {
        switch value {
        case .string(let text): return text.utf8.count <= 1_048_576
        case .array(let values): return values.allSatisfy(stringsWithinBudget)
        case .object(let fields):
            return fields.allSatisfy { $0.key.utf8.count <= 1_048_576 && stringsWithinBudget($0.value) }
        case .number, .bool, .null: return true
        }
    }

    private static func object(_ node: Node?, keys: Set<String>? = nil) throws -> [String: Node] {
        guard let value = node?.objectValue, keys == nil || Set(value.keys) == keys else { throw Failure.malformedTransport }
        return value
    }

    private static func text(_ node: Node?, max: Int = 256) throws -> String {
        guard let value = node?.stringValue, value.utf8.count <= max else { throw Failure.malformedTransport }
        return value
    }

    private static func integer(_ node: Node?, positive: Bool = false) throws -> UInt64 {
        guard case .number(let token) = node, !token.isEmpty,
              token.utf8.allSatisfy({ (48...57).contains($0) }),
              let number = UInt64(token), !positive || number > 0 else { throw Failure.malformedTransport }
        return number
    }

    private static func uuid(_ node: Node?) throws -> UUID {
        guard let value = UUID(uuidString: try text(node)) else { throw Failure.malformedTransport }
        return value
    }

    private static func digest(_ node: Node?) throws -> String {
        let value = try text(node)
        guard value.utf8.count == 64,
              value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw Failure.malformedTransport
        }
        return value
    }

    private static func hex(_ node: Node?) throws -> UInt64 {
        let value = try text(node)
        guard value.range(of: "^0x[0-9a-f]{1,16}$", options: .regularExpression) != nil,
              let number = UInt64(value.dropFirst(2), radix: 16) else { throw Failure.invalidSourceReport }
        return number
    }

    private static func descriptor(_ node: Node?) throws -> Descriptor {
        let value = try object(node, keys: ["attachment_id", "sha256", "byte_count"])
        let size = try integer(value["byte_count"])
        guard let count = Int(exactly: size) else { throw Failure.profileLimit }
        return try Descriptor(attachmentID: uuid(value["attachment_id"]), sha256: digest(value["sha256"]), byteCount: count)
    }

    private static func attachment(_ node: Node) throws -> Attachment {
        let fields = try object(node, keys: ["id", "kind", "schemaVersion", "mediaType", "sha256", "byteCount", "chunks"])
        guard try integer(fields["schemaVersion"]) == 1,
              try text(fields["mediaType"]) == "application/json",
              let chunks = fields["chunks"]?.arrayValue, chunks.count <= 64 else { throw Failure.unsupportedContract }
        let count = try integer(fields["byteCount"])
        guard count <= UInt64(maximumArchiveBytes) else { throw Failure.profileLimit }
        var payload = Data()
        for chunk in chunks {
            let encoded = try text(chunk, max: ((512 * 1_024 + 2) / 3) * 4)
            guard let decoded = Data(base64Encoded: encoded), !decoded.isEmpty,
                  decoded.count <= 512 * 1_024 else { throw Failure.malformedTransport }
            guard decoded.count <= Int(count) - payload.count else { throw Failure.attachmentIdentityMismatch }
            payload.append(decoded)
        }
        guard payload.count == Int(count) else { throw Failure.attachmentIdentityMismatch }
        let declared = try digest(fields["sha256"])
        guard sha256(payload) == declared else { throw Failure.attachmentIdentityMismatch }
        return try Attachment(kind: text(fields["kind"]),
                              descriptor: Descriptor(attachmentID: uuid(fields["id"]), sha256: declared,
                                                     byteCount: payload.count), bytes: payload)
    }

    private static func sha256(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    /// Swift String equality is normalization-aware; the protocol compares decoded scalars.
    private static func equal(_ lhs: Node, _ rhs: Node) -> Bool {
        switch (lhs, rhs) {
        case (.string(let a), .string(let b)): a.utf8.elementsEqual(b.utf8)
        case (.number(let a), .number(let b)): a == b
        case (.bool(let a), .bool(let b)): a == b
        case (.null, .null): true
        case (.array(let a), .array(let b)): a.count == b.count && zip(a, b).allSatisfy { equal($0.0, $0.1) }
        case (.object(let a), .object(let b)):
            a.count == b.count && a.allSatisfy { key, value in
                guard let otherKey = b.keys.first(where: { $0.utf8.elementsEqual(key.utf8) }),
                      let other = b[otherKey] else { return false }
                return equal(value, other)
            }
        default: false
        }
    }

    /// The producer's copied projection can serialize only nonnegative UInt64
    /// numbers. Decline an additive floating-point/negative extension explicitly.
    private static func supportedProjectionNumbers(_ value: Node) -> Bool {
        switch value {
        case .number(let token): return (try? integer(.number(token))) != nil
        case .array(let values): return values.allSatisfy(supportedProjectionNumbers)
        case .object(let fields): return fields.values.allSatisfy(supportedProjectionNumbers)
        case .string, .bool, .null: return true
        }
    }

    private static let requirements = [
        "Verify architecture and selected-slice SHA-256 before applying an address to an open image.",
        "Use UUID as additional image identity when present; a matching filename is insufficient.",
        "Addresses are preferred unslid VM addresses; apply a verified runtime slide only in a runtime-aware adapter.",
        "This export defines a proposed adapter contract. It does not assume an existing MacScope GUI deep link or import command."
    ]

    private static func projectedReport(_ bytes: Data, findingID: String) throws -> (Node, Node) {
        let report: [String: Node]
        do { report = try object(try json(bytes)) }
        catch Failure.profileLimit { throw Failure.profileLimit }
        catch { throw Failure.invalidSourceReport }
        guard (try? integer(report["schema_version"])) == 1,
              report["report_kind"]?.stringValue == "airs.audit",
              let image = report["image"]?.objectValue,
              let generator = report["generator"]?.objectValue,
              let findings = report["findings"]?.arrayValue,
              findings.count <= 50_000,
              (try? text(generator["name"])) != nil,
              (try? text(generator["version"])) != nil,
              (try? text(generator["analysis_model_version"])) != nil else { throw Failure.invalidSourceReport }
        let configuration: Node
        if let recorded = report["analysis_config"] {
            guard let value = recorded.objectValue, Set(value.keys) == ["limits"],
                  let limits = value["limits"]?.objectValue,
                  limits.values.allSatisfy({ (try? integer($0)) != nil }) else {
                throw Failure.unsupportedConfiguration
            }
            configuration = .object(["state": .string("recorded"), "value": recorded])
        } else { configuration = .object(["state": .string("not_recorded")]) }
        guard (try? text(image["display_name"], max: 65_536)) != nil,
              ["arm64", "arm64e"].contains(image["architecture"]?.stringValue ?? ""),
              ["execute", "dylib", "bundle"].contains(image["file_type"]?.stringValue ?? ""),
              image["path"] == nil || image["path"] == .null || image["path"]?.stringValue != nil,
              (try? digest(image["container_sha256"])) != nil,
              (try? digest(image["slice_sha256"])) != nil,
              (try? integer(image["cpu_subtype"])) != nil,
              (try? integer(image["slice_offset"])) != nil,
              (try? integer(image["slice_size"], positive: true)) != nil,
              let base = try? hex(image["preferred_base"]),
              image["uuid"] == nil || image["uuid"] == .null || (try? uuid(image["uuid"])) != nil else {
            throw Failure.invalidSourceReport
        }
        let sourceLimitations = report["limitations"]?.arrayValue
        guard let sourceLimitations, sourceLimitations.allSatisfy({ $0.stringValue != nil }),
              let ranges = report["metadata_ranges"]?.arrayValue,
              let issues = report["issues"]?.arrayValue,
              let summary = report["summary"]?.objectValue,
              report["source_annotations"] == nil else { throw Failure.invalidSourceReport }

        let model = generator["analysis_model_version"]?.stringValue ?? ""
        var seen = Set<String>(), selected: [String: Node]?
        var counts = ["agreement": 0, "inconsistency": 0, "unresolved": 0]
        var checkedTotal = 0
        for node in findings {
            guard let finding = node.objectValue,
                  let id = finding["id"]?.stringValue,
                  id.range(of: "^airsf-[0-9a-f]{64}$", options: .regularExpression) != nil else {
                throw Failure.invalidSourceReport
            }
            guard seen.insert(id).inserted else { throw Failure.findingNotUnique }
            guard let function = finding["function"]?.objectValue,
                  (try? text(function["name"], max: 65_536)) != nil,
                  (try? text(function["boundary_source"])) != nil,
                  let start = try? hex(function["address"]),
                  let end = try? hex(function["end_address"]),
                  let offset = try? hex(function["image_offset"]),
                  let size = try? integer(function["size"], positive: true),
                  start >= base, end > start, end - start == size, start - base == offset,
                  let verdict = finding["verdict"]?.stringValue, counts[verdict] != nil,
                  ["compact", "dwarf_reference", "dwarf_evaluated", "none", "unavailable"].contains(finding["coverage"]?.stringValue ?? ""),
                  ["frame", "frameless", "dwarf", "pauth_frame", "none", "unknown"].contains(finding["mode"]?.stringValue ?? ""),
                  ["synchronous_call_sites", "modeled_leaf_body", "metadata_only"].contains(finding["scope"]?.stringValue ?? ""),
                  (try? integer(finding["instruction_count"])) != nil,
                  let pcs = finding["checked_pcs"]?.arrayValue,
                  pcs.allSatisfy({ (try? hex($0)).map({ start <= $0 && $0 < end }) == true }),
                  let reasons = finding["reason_codes"]?.arrayValue,
                  reasons.allSatisfy({ $0.stringValue != nil }),
                  let limitations = finding["limitations"]?.arrayValue,
                  limitations.allSatisfy({ $0.stringValue != nil }),
                  let evidence = finding["evidence"]?.arrayValue,
                  evidence.allSatisfy({ row in
                      guard let entry = row.objectValue,
                            entry["code"]?.stringValue != nil,
                            entry["message"]?.stringValue != nil else { return false }
                      for key in ["expected", "observed"] {
                          if entry[key] != nil && entry[key] != .null && entry[key]?.stringValue == nil { return false }
                      }
                      return entry["address"] == nil || entry["address"] == .null || (try? hex(entry["address"])) != nil
                  }) else { throw Failure.invalidSourceReport }
            let coverage = finding["coverage"]?.stringValue ?? ""
            let mode = finding["mode"]?.stringValue ?? ""
            let scope = finding["scope"]?.stringValue ?? ""
            let encoding: UInt64?
            if finding["encoding"] == nil || finding["encoding"] == .null { encoding = nil }
            else {
                guard let value = try? hex(finding["encoding"]), value <= UInt32.max else { throw Failure.invalidSourceReport }
                encoding = value
            }
            if verdict != "unresolved" && (pcs.isEmpty || scope == "metadata_only" ||
                 !["compact", "dwarf_reference", "dwarf_evaluated"].contains(coverage) ||
                 (coverage == "compact" && (encoding ?? 0) == 0)) {
                throw Failure.invalidSourceReport
            }
            if model == "arm64-linear-v1" && coverage == "dwarf_evaluated" { throw Failure.invalidSourceReport }
            if verdict != "unresolved" && knownSemanticModels.contains(model) {
                let subtype = try integer(image["cpu_subtype"])
                guard image["architecture"]?.stringValue == "arm64", subtype & 0x00ff_ffff <= 1 else {
                    throw Failure.invalidSourceReport
                }
                if model != "arm64-linear-v1" && model != "arm64-linear-dwarf-v2" && subtype > 1 {
                    throw Failure.invalidSourceReport
                }
                let dwarf = model != "arm64-linear-v1" && mode == "dwarf"
                if dwarf {
                    guard subtype <= 1, coverage == "dwarf_evaluated", function["boundary_source"]?.stringValue == "lc_function_starts",
                          let encoding, encoding & 0x0f00_0000 == 0x0300_0000 else {
                        throw Failure.invalidSourceReport
                    }
                } else {
                    guard coverage == "compact", function["boundary_source"]?.stringValue == "lc_function_starts",
                          let encoding else { throw Failure.invalidSourceReport }
                    let expected: UInt64 = mode == "frame" ? 0x0400_0000 : 0x0200_0000
                    let expectedScope = mode == "frame" ? "synchronous_call_sites" : "modeled_leaf_body"
                    guard ["frame", "frameless"].contains(mode), scope == expectedScope,
                          encoding & 0x0f00_0000 == expected else { throw Failure.invalidSourceReport }
                    let allowed: UInt64 = 0xff00_001f | (mode == "frameless" ? 0x00ff_f000 : 0)
                    guard encoding & ~allowed == 0, encoding & 0x0000_0f00 == 0,
                          mode != "frameless" || encoding & 0x1f == 0 else { throw Failure.invalidSourceReport }
                }
            }
            if id == findingID { selected = finding }
            counts[verdict, default: 0] += 1
            checkedTotal += pcs.count
        }
        guard let finding = selected, let function = finding["function"]?.objectValue else { throw Failure.findingNotUnique }
        var previousEnd: UInt64 = 0
        for row in ranges {
            guard let entry = row.objectValue,
                  let start = try? hex(entry["start"]), let end = try? hex(entry["end"]),
                  start >= previousEnd, end > start,
                  let encoding = try? hex(entry["encoding"]), encoding <= UInt32.max,
                  ["frame", "frameless", "dwarf", "pauth_frame", "none", "unknown"].contains(entry["mode"]?.stringValue ?? "") else { throw Failure.invalidSourceReport }
            previousEnd = end
        }
        guard issues.allSatisfy({ row in
            guard let issue = row.objectValue, issue["code"]?.stringValue != nil,
                  issue["message"]?.stringValue != nil else { return false }
            return issue["offset"] == nil || issue["offset"] == .null || (try? integer(issue["offset"])) != nil
        }) else { throw Failure.invalidSourceReport }
        let expectedCounts = ["function_count": findings.count, "agreement_count": counts["agreement", default: 0],
                              "inconsistency_count": counts["inconsistency", default: 0], "unresolved_count": counts["unresolved", default: 0],
                              "metadata_entry_count": ranges.count, "checked_pc_count": checkedTotal]
        guard expectedCounts.allSatisfy({ (try? integer(summary[$0.key])) == UInt64($0.value) }) else {
            throw Failure.invalidSourceReport
        }
        let relativeStart = try hex(function["image_offset"])
        let size = try integer(function["size"], positive: true)
        let (relativeEnd, overflow) = relativeStart.addingReportingOverflow(size)
        guard !overflow else { throw Failure.invalidSourceReport }
        let imageKeys = ["display_name", "uuid", "architecture", "cpu_subtype", "container_sha256", "slice_sha256",
                         "slice_offset", "slice_size", "preferred_base"]
        let findingKeys = ["verdict", "coverage", "mode", "scope", "reason_codes", "checked_pcs", "evidence", "limitations"]
        let projection: Node = .object([
            "schema_version": .number("1"), "report_kind": .string("airs.macscope_handoff"),
            "integration_status": .string("proposed_export_contract"),
            "image": .object(Dictionary(uniqueKeysWithValues: imageKeys.map { ($0, image[$0] ?? .null) })),
            "selection": .object(["finding_id": .string(findingID), "function_name": function["name"] ?? .null,
                                  "address_space": .string("preferred_vm"),
                                  "vm_range": .object(["start": function["address"] ?? .null,
                                                       "end": function["end_address"] ?? .null]),
                                  "image_relative_range": .object(["start": function["image_offset"] ?? .null,
                                                                    "end": .string("0x" + String(relativeEnd, radix: 16))])]),
            "finding": .object(Dictionary(uniqueKeysWithValues: findingKeys.map { ($0, finding[$0] ?? .null) })),
            "source_analysis": .object(generator),
            "requirements": .array(requirements.map(Node.string))
        ])
        guard projection.canonicalJSONBytes().count <= maximumRequestBytes else { throw Failure.profileLimit }
        return (projection, configuration)
    }

    private static let knownSemanticModels: Set<String> = [
        "arm64-linear-v1", "arm64-linear-dwarf-v2", "arm64-bounded-cfg-v3",
        "arm64-bounded-calls-v4", "arm64-bounded-dwarf-cfg-v5", "arm64-bounded-returns-v6",
        "arm64-bounded-teardowns-v7", "arm64-bounded-suffixes-v8", "arm64-bounded-conditional-v9",
        "arm64-bounded-conditions-v10", "arm64-bounded-flags-v11", "arm64-bounded-register-flags-v12",
        "arm64-bounded-shifted-flags-v13", "arm64-bounded-extended-flags-v14", "arm64-bounded-logical-flags-v15",
        "arm64-bounded-logical-immediate-v16", "arm64-bounded-nonflag-immediate-v17",
        "arm64-bounded-nonflag-register-v18", "arm64-bounded-carry-v19",
        "arm64-bounded-conditional-compare-v20", "arm64-bounded-conditional-select-v21",
        "arm64-bounded-bitfield-v22", "arm64-bounded-extract-v23", "arm64-bounded-variable-shift-v24",
        "arm64-bounded-multiply-v25", "arm64-bounded-widening-multiply-v26",
        "arm64-bounded-high-multiply-v27", "arm64-bounded-loops-v28", "arm64-bounded-loop-calls-v29",
        "arm64-bounded-cfa-register-v30", "arm64-bounded-sequential-loops-v31"
    ]
}
