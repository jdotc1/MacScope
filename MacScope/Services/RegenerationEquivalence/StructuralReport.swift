import Foundation

struct StructuralDimensionInput: Sendable {
    let name: String
    let original: [StructuralRecord]
    let rebuilt: [StructuralRecord]
    let available: Bool
}

struct StructuralDimensionResult: Codable, Equatable, Sendable {
    let name: String
    let comparison: StructuralResult?
    let status: String
    let unassessedOriginal: [StructuralRecord]
    let unassessedRebuilt: [StructuralRecord]
}

struct StructuralReport: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let original: String
    let rebuilt: String
    let dimensions: [StructuralDimensionResult]
}

enum StructuralMarkdown {
    /// Treat recovered binary metadata as text, never Markdown or HTML.
    static func escape(_ value: String) -> String {
        value.unicodeScalars.map { scalar -> String in
            switch scalar.value {
            case 38: return "&amp;"
            case 60: return "&lt;"
            case 62: return "&gt;"
            case 32...126:
                let character = String(scalar)
                return "\\`*_{}[]()#+-.!|".contains(character) ? "\\" + character : character
            default: return "\\u{\(String(scalar.value, radix: 16))}"
            }
        }.joined()
    }
}

enum StructuralReportBuilder {
    static func build(original: String, rebuilt: String, dimensions: [StructuralDimensionInput]) -> StructuralReport {
        let groups = Dictionary(grouping: dimensions, by: \.name)
        func ordered(_ records: [StructuralRecord]) -> [StructuralRecord] {
            records.sorted { ($0.key, $0.value == nil ? 0 : 1, $0.value ?? "") < ($1.key, $1.value == nil ? 0 : 1, $1.value ?? "") }
        }
        let results = groups.keys.sorted().map { name in
            let entries = groups[name] ?? []
            guard entries.count == 1, let input = entries.first else {
                return StructuralDimensionResult(name: name, comparison: nil, status: "unassessed: duplicate dimension",
                    unassessedOriginal: ordered(entries.flatMap(\.original)), unassessedRebuilt: ordered(entries.flatMap(\.rebuilt)))
            }
            guard input.available else {
                return StructuralDimensionResult(name: name, comparison: nil, status: "unassessed: unavailable",
                    unassessedOriginal: ordered(input.original), unassessedRebuilt: ordered(input.rebuilt))
            }
            return StructuralDimensionResult(name: name,
                comparison: StructuralComparison.compare(original: input.original, rebuilt: input.rebuilt),
                status: "assessed", unassessedOriginal: [], unassessedRebuilt: [])
        }
        return .init(schemaVersion: 1, original: original, rebuilt: rebuilt, dimensions: results)
    }

    static func markdown(_ report: StructuralReport) -> String {
        func safe(_ value: String) -> String { StructuralMarkdown.escape(value) }
        var lines = ["# Static structure comparison", "", "This report does not establish behavioral equivalence.", "",
                     "| Dimension | Matched | Missing | Extra | Differing | Unassessed | Score |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
        for dimension in report.dimensions {
            guard let c = dimension.comparison else {
                lines.append("| \(safe(dimension.name)) | — | — | — | — | — | N/A |")
                continue
            }
            let score = c.score.map { String(format: "%.1f%%", $0 * 100) } ?? "N/A"
            lines.append("| \(safe(dimension.name)) | \(c.matched.count) | \(c.missing.count) | \(c.extra.count) | \(c.differing.count) | \(c.unassessed.count) | \(score) |")
        }
        for dimension in report.dimensions {
            lines.append("")
            lines.append("## " + safe(dimension.name))
            guard let c = dimension.comparison else {
                lines.append(safe(dimension.status))
                for item in dimension.unassessedOriginal { lines.append("- Original observation: \(safe(item.key)) = \(safe(item.value ?? "unknown"))") }
                for item in dimension.unassessedRebuilt { lines.append("- Rebuilt observation: \(safe(item.key)) = \(safe(item.value ?? "unknown"))") }
                continue
            }
            for item in c.matched { lines.append("- Matched: \(safe(item.key)) = \(safe(item.value ?? "unknown"))") }
            for item in c.missing { lines.append("- Missing in rebuilt: \(safe(item.key)) = \(safe(item.value ?? "unknown"))") }
            for item in c.extra { lines.append("- Extra in rebuilt: \(safe(item.key)) = \(safe(item.value ?? "unknown"))") }
            for item in c.differing { lines.append("- Differing: \(safe(item.key)); original \(safe(item.original)); rebuilt \(safe(item.rebuilt))") }
            for item in c.unassessed {
                func values(_ records: [StructuralRecord]) -> String {
                    records.map { safe($0.value ?? "unknown") }.joined(separator: ", ")
                }
                lines.append("- Unassessed: \(safe(item.key)); \(safe(item.reason)); original [\(values(item.original))]; rebuilt [\(values(item.rebuilt))]")
            }
        }
        lines.append("")
        return lines.joined(separator: "\n")
    }
}
