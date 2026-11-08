import Foundation

/// Renders localized tables without loading application code. Compile-back comparison is separate.
struct LocalizationRoundTripConverter: ResourceRoundTripConverting {
    let sourceLanguage: String

    func convert(path: String, files: [String: Data]) throws -> ResourceRoundTripCandidate {
        guard RegenerationEncoding.relativePath(path), !sourceLanguage.isEmpty,
              let descriptor = Self.descriptor(path) else {
            throw RegenerationError.invalidInput("expected a localized strings table")
        }
        let selected = files.keys.filter {
            guard let other = Self.descriptor($0) else { return false }
            return other.prefix == descriptor.prefix && other.table == descriptor.table
        }.sorted()
        var strings: [String: [String: Any]] = [:]
        var gaps: [String] = []
        var seenLocaleKinds = Set<String>()
        for original in selected {
            guard let location = Self.descriptor(original), let data = files[original], data.count <= 8_388_608,
                  let values = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  values.count <= 50_000 else {
                throw RegenerationError.invalidInput("invalid or oversized localization table")
            }
            guard seenLocaleKinds.insert(location.locale + ":" + location.kind).inserted else {
                throw RegenerationError.invalidInput("duplicate locale/table input")
            }
            if location.locale == "Base" {
                gaps.append("\(original): Base localization needs an explicit development-language binding.")
                continue
            }
            for key in values.keys.sorted() {
                let unit: [String: Any]?
                if location.kind == "strings", let text = values[key] as? String {
                    unit = ["stringUnit": ["state": "translated", "value": text]]
                } else if location.kind == "stringsdict", let rule = values[key] as? [String: Any] {
                    unit = Self.plural(rule)
                } else { unit = nil }
                guard let unit else {
                    gaps.append("\(original): unsupported value for key \(RegenerationEncoding.annotation(key)).")
                    continue
                }
                var entry = strings[key] ?? [:]
                var localizations = entry["localizations"] as? [String: Any] ?? [:]
                if localizations[location.locale] != nil {
                    gaps.append("\(original): overlapping strings/stringsdict key \(RegenerationEncoding.annotation(key)).")
                    continue
                }
                localizations[location.locale] = unit
                entry["localizations"] = localizations
                strings[key] = entry
            }
        }
        let output = (descriptor.prefix.isEmpty ? "" : descriptor.prefix + "/") + descriptor.table + ".xcstrings"
        let catalog: [String: Any] = ["sourceLanguage": sourceLanguage, "version": "1.0", "strings": strings]
        let data = try JSONSerialization.data(withJSONObject: catalog, options: [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]) + Data([10])
        return .init(record: .init(compiledPaths: selected, sourcePath: output, converter: "localization-v1",
            status: .partial, equivalence: .init(outcome: .notRun, tool: "xcstringstool", receiptPath: nil),
            diagnostics: gaps + ["Compile-back equivalence has not been checked."]),
            sourceFiles: [output: data], conversionComplete: gaps.isEmpty)
    }

    private static func plural(_ rule: [String: Any]) -> [String: Any]? {
        guard let format = rule["NSStringLocalizedFormatKey"] as? String,
              rule.count == 2, let variable = rule.keys.first(where: { $0 != "NSStringLocalizedFormatKey" }),
              format == "%#@\(variable)@", let values = rule[variable] as? [String: Any],
              values["NSStringFormatSpecTypeKey"] as? String == "NSStringPluralRuleType",
              let type = values["NSStringFormatValueTypeKey"] as? String,
              ["d", "ld", "lld", "u", "lu", "llu"].contains(type), values["other"] is String else { return nil }
        let categories: Set<String> = ["zero", "one", "two", "few", "many", "other"]
        var variants: [String: Any] = [:]
        for (key, value) in values where !key.hasPrefix("NSStringFormat") {
            guard categories.contains(key), let text = value as? String else { return nil }
            variants[key] = ["stringUnit": ["state": "translated", "value": text]]
        }
        guard values.keys.allSatisfy({ categories.contains($0) || $0 == "NSStringFormatSpecTypeKey" || $0 == "NSStringFormatValueTypeKey" }) else { return nil }
        return ["stringUnit": ["state": "translated", "value": format],
                "substitutions": [variable: ["argNum": 1, "formatSpecifier": type, "variations": ["plural": variants]]]]
    }

    private static func descriptor(_ path: String) -> (prefix: String, table: String, locale: String, kind: String)? {
        guard RegenerationEncoding.relativePath(path) else { return nil }
        let parts = path.split(separator: "/").map(String.init)
        guard parts.count >= 2 else { return nil }
        let localePart = parts[parts.count - 2], name = parts[parts.count - 1]
        let url = URL(fileURLWithPath: name), kind = url.pathExtension
        guard localePart.hasSuffix(".lproj"), ["strings", "stringsdict"].contains(kind),
              localePart.count > 6, !url.deletingPathExtension().lastPathComponent.isEmpty else { return nil }
        return (parts.dropLast(2).joined(separator: "/"), url.deletingPathExtension().lastPathComponent,
                String(localePart.dropLast(6)), kind)
    }
}
