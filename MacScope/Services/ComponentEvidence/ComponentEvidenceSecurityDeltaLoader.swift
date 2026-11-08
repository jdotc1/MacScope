// Original to this item (AR3, NF06). Compares the load-command declarations of one architecture of one component.
// Dependency commands (load, weak, reexport, upward, lazy) are a multiset keyed by command, path, versions and flags:
// load order is not a security fact. Install name and run paths are ordered lists compared by position. Any row
// the loader cannot interpret makes the whole architecture unresolved: nothing is guessed.

import Foundation

extension ComponentEvidenceSecurityDelta {
    enum LoaderDelta {
        private static let dependencyCommands: Set<String> = ["load", "weak", "reexport", "upward", "lazy"]
        private static let orderedCommands: [String] = ["installName", "rpath"]

        private struct Parsed {
            var dependencies: [String: Int] = [:]
            var ordered: [String: [String]] = [:]
        }

        private static func text(_ value: EntitlementValue?) -> String? {
            if case .string(let text)? = value { return text }
            return nil
        }

        private static func parse(_ dictionary: EntitlementDictionary) -> Parsed? {
            guard case .array(let rows)? = dictionary["commands"] else { return nil }
            var parsed = Parsed()
            for row in rows {
                guard case .dictionary(let fields) = row, let command = text(fields["command"]),
                      let path = text(fields["path"]) else { return nil }
                if dependencyCommands.contains(command) {
                    let current = text(fields["currentVersion"]) ?? "-"
                    let compatibility = text(fields["compatibilityVersion"]) ?? "-"
                    var flags = "-"
                    if case .unsignedInteger(let number)? = fields["useFlags"] { flags = String(number) }
                    parsed.dependencies["\(command)|\(path)|\(current)|\(compatibility)|\(flags)", default: 0] += 1
                } else if orderedCommands.contains(command) {
                    parsed.ordered[command, default: []].append(path)
                } else {
                    return nil
                }
            }
            return parsed
        }

        /// Rows for one architecture. An uninterpretable payload yields one unresolved row for the architecture.
        static func rows(previous: EntitlementDictionary, current: EntitlementDictionary) -> [EntitlementDelta.Row] {
            guard let old = parse(previous), let new = parse(current) else {
                return [EntitlementDelta.Row(key: ExactKey(text: "[loader]"), kind: .unresolved, previous: nil, current: nil,
                                             reason: .loaderInterpretationUnavailable)]
            }
            var rows: [EntitlementDelta.Row] = []
            for key in Set(old.dependencies.keys).union(new.dependencies.keys).sorted(by: { $0.utf8.lexicographicallyPrecedes($1.utf8) }) {
                let a = old.dependencies[key] ?? 0, b = new.dependencies[key] ?? 0
                let kind: EntitlementDelta.Kind = a == b ? .unchanged : (a == 0 ? .added : (b == 0 ? .removed : .changed))
                rows.append(EntitlementDelta.Row(key: ExactKey(text: "dependency:" + key), kind: kind,
                                                 previous: a == 0 ? nil : .unsigned(UInt64(a)),
                                                 current: b == 0 ? nil : .unsigned(UInt64(b)), reason: nil))
            }
            for command in orderedCommands {
                let a = old.ordered[command] ?? [], b = new.ordered[command] ?? []
                for index in 0..<max(a.count, b.count) {
                    let left = index < a.count ? a[index] : nil, right = index < b.count ? b[index] : nil
                    let kind: EntitlementDelta.Kind = left == right ? .unchanged : (left == nil ? .added : (right == nil ? .removed : .changed))
                    rows.append(EntitlementDelta.Row(key: ExactKey(text: "\(command)[\(index)]"), kind: kind,
                                                     previous: left.map { .string(ExactKey(text: $0)) },
                                                     current: right.map { .string(ExactKey(text: $0)) }, reason: nil))
                }
            }
            return rows
        }
    }
}
