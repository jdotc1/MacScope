import Foundation
import NEWFEATURESCore

/// Typed, bounded read result only. Register under the current explicit MCP
/// allowlist after source-acceptance tests; this file does NOT self-register.
enum NEWFEATURESScriptValueProjection {
    /// Matches NEWFEATURESReadBudget.maxFunctions' upper bound; totals are always reported.
    static let maximumReportedFunctions = 500

    static func path(
        _ result: NEWFEATURESPathReport,
        admission: NEWFEATURESLedgerAdmission,
        currentLedgerAdmission: Bool
    ) -> ScriptValue {
        guard currentLedgerAdmission,
              result.source.image == admission.image,
              result.destination.image == admission.image else {
            return .object([
                "status": .string("source-or-publication-admission-revoked"),
                "path": .array([]),
            ])
        }
        return .object([
            "status": .string(result.status.rawValue),
            "visitedFunctions": .int(Int64(result.visitedFunctions)),
            "visitedEdges": .int(Int64(result.visitedEdges)),
            "source": function(result.source),
            "destination": function(result.destination),
            "pathLength": .int(Int64(result.path.count)),
            "path": .array(result.path.prefix(maximumReportedFunctions).map(function)),
            "pathTruncated": .bool(result.path.count > maximumReportedFunctions),
            "claim": .string("path through verified observed call references only"),
        ])
    }

    /// Recheck against the current Phase2 ledger AT the publication boundary,
    /// even after the coordinator's last internal ledger check.
    static func recursive(
        _ report: NEWFEATURESRecursiveReport,
        currentLedgerAdmission: Bool
    ) -> ScriptValue {
        guard currentLedgerAdmission, report.internallyValidatedAtReturn,
              report.termination != .sourceChanged else {
            return .object([
                "termination": .string("source-or-publication-admission-revoked"),
                "acceptedNativeFunctions": .int(0),
                "results": .array([]),
            ])
        }
        // Separate from NEWFEATURESCore's raw UTF-8 work budget: JSON escaping may
        // substantially increase text bytes. Leave headroom below the existing
        // MCP ~4 MiB inner payload cap for keys/metadata and transport framing.
        let encoder = JSONEncoder()
        var serializedTextBytes = 0
        for result in report.results {
            guard let text = result.text else { continue }
            guard let count = try? encoder.encode(text).count,
                  count <= 2_097_152 - serializedTextBytes else {
                return .object([
                    "termination": .string("mcp-serialized-output-limit"),
                    "acceptedNativeFunctions": .int(0),
                    "results": .array([]),
                ])
            }
            serializedTextBytes += count
        }
        return .object([
            "termination": .string(report.termination.rawValue),
            "traversalLimit": .string(report.traversal.limit.rawValue),
            "excludedUnverifiedEdges": .int(Int64(report.traversal.excludedUnverifiedEdges)),
            "acceptedNativeFunctions": .int(Int64(report.acceptedNativeFunctionCount)),
            "totalResults": .int(Int64(report.results.count)),
            "resultsTruncated": .bool(report.results.count > maximumReportedFunctions),
            "results": .array(report.results.prefix(maximumReportedFunctions).map { result in
                .object([
                    "function": function(result.function),
                    "outcome": .string(result.outcome.rawValue),
                    "backend": .string(result.backend.rawValue),
                    "text": result.text.map(ScriptValue.string) ?? .null,
                    "reason": result.reason.map(ScriptValue.string) ?? .null,
                ])
            }),
            "claim": .string("not a proof of complete whole-program decompilation"),
        ])
    }

    private static func function(_ function: NEWFEATURESFunctionKey) -> ScriptValue {
        .object([
            "imageSlot": .int(Int64(function.image.slot)),
            "imageID": .string(function.image.binaryID.uuidString),
            "sha256": .string(function.image.sha256),
            "analysisRevision": .string(String(function.image.analysisRevision)),
            "address": .string("0x" + String(function.address, radix: 16)),
        ])
    }
}
