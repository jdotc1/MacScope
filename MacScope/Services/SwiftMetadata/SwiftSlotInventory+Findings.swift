import Foundation

extension LoaderFinding {
    /// Stable code for a Swift witness slot scope the loader could not prove (R-Q11).
    static let swiftWitnessSlotInventoryIncompleteCode = "swiftWitnessSlotInventoryIncomplete"
    /// At most this many per-scope findings per image; the remainder is summarised in one finding.
    static let maxSlotInventoryFindings = 64

    /// One finding per withheld scope, carrying scope kind, reason and VA extent. Emitted only for an
    /// image that carries Swift witness metadata (`__swift5_proto`), because only then does a withheld
    /// scope withhold a witness. `message` uses enum vocabulary and numbers only.
    static func slotInventoryFindings(_ inventory: SwiftSlotInventory, hasWitnessMetadata: Bool) -> [LoaderFinding] {
        guard hasWitnessMetadata else { return [] }
        var findings: [LoaderFinding] = []
        for scope in inventory.withheld.prefix(maxSlotInventoryFindings) {
            findings.append(finding(for: scope))
        }
        let rest = inventory.withheld.count - maxSlotInventoryFindings
        if rest > 0 {
            findings.append(LoaderFinding(
                category: .metadataParseIssue, code: swiftWitnessSlotInventoryIncompleteCode, address: 0,
                message: "Swift witness slots withheld in \(rest) further scopes (scope-count only)."))
        }
        return findings
    }

    /// A cache projection never receives an inventory (R-Q2a).
    static func cacheWithheldFinding(address: UInt64) -> LoaderFinding {
        finding(for: SwiftSlotInventory.Withheld(scope: .cacheWithheld, reason: .cacheImage, extent: nil),
                address: address)
    }

    private static func finding(for scope: SwiftSlotInventory.Withheld, address: UInt64? = nil) -> LoaderFinding {
        let extentText: String
        if let extent = scope.extent {
            extentText = "0x\(String(extent.lowerBound, radix: 16))-0x\(String(extent.upperBound, radix: 16))"
        } else {
            extentText = "whole image"
        }
        return LoaderFinding(
            category: .metadataParseIssue, code: swiftWitnessSlotInventoryIncompleteCode,
            address: address ?? scope.extent?.lowerBound ?? 0,
            message: "Swift witness slots withheld: scope=\(scope.scope.rawValue) "
                + "reason=\(scope.reason.rawValue) extent=\(extentText).")
    }
}
