// Original to this item (AR3, NF09). Lossless projection of a report page to ScriptValue with exact byte sizing.
// Items are whole: an observation or finding is never split, and a page is cut early by the byte cap with a named
// pageByteLimit adjunct rather than by silently dropping rows. Integers wider than 53 bits and every exact key are
// carried as strings or tagged objects so no JSON number can lose a bit. This is a projection only: there is no
// Codable conformance and no archive or wire promise.

import Foundation

extension ComponentEvidenceSecurityDelta {
    enum Pager {
        static let pageByteCap = 196_608
        static let defaultLimit = 100
        static let maximumLimit = 256
        static let maximumCursorBytes = 1024
        static let diagnosticCeiling = 4096

        enum Section: String, Sendable { case observations, findings }

        struct Page: Sendable, Equatable {
            let items: [ScriptValue]
            let nextCursor: String?
            let total: Int
            let byteCount: Int
            /// Set when the byte cap, not the requested limit, ended this page early.
            let byteLimited: Bool
        }

        // MARK: Projection

        static func text(_ key: ExactKey) -> ScriptValue {
            .object(["utf8": .string(key.utf8.base64EncodedString())])
        }

        static func value(_ value: Value) -> ScriptValue {
            func tagged(_ type: String, _ payload: ScriptValue) -> ScriptValue { .object(["type": .string(type), "value": payload]) }
            switch value {
            case .boolean(let flag): return tagged("boolean", .bool(flag))
            case .signed(let number): return tagged("signed", .string(String(number)))
            case .unsigned(let number): return tagged("unsigned", .string(String(number)))
            case .normalizedInteger(let digits): return tagged("normalizedInteger", .string(digits))
            case .realBits(let bits): return tagged("realBits", .string(String(bits, radix: 16)))
            case .string(let key): return tagged("string", text(key))
            case .data(let data): return tagged("data", .string(data.base64EncodedString()))
            case .dateBits(let bits): return tagged("dateBits", .string(String(bits, radix: 16)))
            case .array(let items): return tagged("array", .array(items.map(Self.value)))
            case .dictionary(let entries):
                return tagged("dictionary", .array(entries.map { .object(["key": text($0.key), "value": Self.value($0.value)]) }))
            }
        }

        static func reason(_ reason: Reason) -> ScriptValue {
            .object(["code": .string(String(describing: reason.code)), "diagnostic": .string(reason.diagnostic)])
        }

        static func reference(_ reference: EvidenceReference) -> ScriptValue {
            var object: [String: ScriptValue] = [
                "side": .string(reference.side == .previous ? "previous" : "current"),
                "inventoryID": .string(reference.inventoryID.uuidString),
                "category": .string(String(describing: reference.category)),
                "relativeSource": text(reference.relativeSource),
            ]
            if let id = reference.componentID { object["componentID"] = .string(id.uuidString) }
            if let architecture = reference.architecture { object["architecture"] = .string(architecture) }
            if let key = reference.evidenceKey { object["evidenceKey"] = text(key) }
            if let slice = reference.slice {
                object["slice"] = .object(["cpuType": .string(String(slice.cpuType)), "cpuSubtype": .string(String(slice.cpuSubtype)),
                                           "headerMagic": .string(String(slice.headerMagic)), "index": .int(Int64(slice.index)),
                                           "offset": .string(String(slice.offset)), "size": .string(String(slice.size))])
            }
            return .object(object)
        }

        static func observation(_ row: Observation) -> ScriptValue {
            var object: [String: ScriptValue] = [
                "id": .int(Int64(row.id.ordinal)), "category": .string(String(describing: row.category)),
                "componentPath": text(row.componentPath), "subject": text(row.subject),
                "disposition": .string(row.disposition.rawValue), "previousState": .string(row.previousState.rawValue),
                "currentState": .string(row.currentState.rawValue), "evidence": .array(row.evidence.map(reference)),
                "limitations": .array(row.limitations.map(reason)),
            ]
            if let previous = row.previousValue { object["previousValue"] = value(previous) }
            if let current = row.currentValue { object["currentValue"] = value(current) }
            return .object(object)
        }

        static func finding(_ finding: Finding) -> ScriptValue {
            .object(["id": .int(Int64(finding.id.ordinal)), "kind": .string(finding.kind.rawValue),
                     "disposition": .string(finding.disposition.rawValue), "title": .string(finding.title),
                     "explanation": .string(finding.explanation),
                     "observationIDs": .array(finding.observationIDs.map { .int(Int64($0.ordinal)) }),
                     "evidence": .array(finding.evidence.map(reference)), "limitations": .array(finding.limitations.map(reason))])
        }

        // MARK: Cursor

        static func cursor(report: UUID, section: Section, offset: Int) -> String {
            "\(report.uuidString).\(section.rawValue).\(offset)"
        }

        static func parse(cursor: String, report: UUID, section: Section) throws -> Int {
            guard cursor.utf8.count <= maximumCursorBytes else { throw Refusal.make(.malformedInput) }
            let parts = cursor.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count == 3, let id = UUID(uuidString: String(parts[0])), parts[1] == Substring(section.rawValue),
                  let offset = Int(parts[2]), offset >= 0 else { throw Refusal.make(.malformedInput) }
            guard id == report else { throw Refusal.make(.staleCursor) }
            return offset
        }

        // MARK: Paging

        static func page(report: Report, section: Section, cursor: String? = nil, limit: Int? = nil) throws -> Page {
            let size = limit ?? defaultLimit
            guard (1...maximumLimit).contains(size) else { throw Refusal.make(.invalidOptions) }
            let total = section == .observations ? report.observations.count : report.findings.count
            let start = try cursor.map { try parse(cursor: $0, report: report.reportID, section: section) } ?? 0
            guard start <= total else { throw Refusal.make(.outOfBounds) }
            var items: [ScriptValue] = []
            var bytes = 2
            var index = start
            var byteLimited = false
            while index < total, items.count < size {
                let item = section == .observations ? observation(report.observations[index]) : finding(report.findings[index])
                let width = (try? item.jsonData().count) ?? Int.max
                let next = bytes + width + (items.isEmpty ? 0 : 1)
                if next > pageByteCap {
                    if items.isEmpty { throw Refusal.make(.pageByteLimit) }
                    byteLimited = true
                    break
                }
                items.append(item); bytes = next; index += 1
            }
            let more = index < total
            return Page(items: items, nextCursor: more ? Self.cursor(report: report.reportID, section: section, offset: index) : nil,
                        total: total, byteCount: bytes, byteLimited: byteLimited)
        }

        /// The fixed fallback: a bounded diagnostic that never carries the report body.
        static func diagnostic(for refusal: Refusal) -> ScriptValue {
            var object: [String: ScriptValue] = ["refused": .bool(true), "code": .string(refusal.code.rawValue)]
            if let side = refusal.side { object["side"] = .string(side == .previous ? "previous" : "current") }
            if let kind = refusal.underlyingKind { object["underlyingKind"] = .string(String(describing: kind).prefix(64).description) }
            return .object(object)
        }
    }
}
