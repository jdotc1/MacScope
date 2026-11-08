import Foundation

/// Why one export file could not be decoded. Coordinates are JSON paths such as
/// `$.functions[3].state`; an unknown enum value or newer version is never coerced.
enum RegenerationDecodeFailure: Error, Equatable {
    case malformed(path: String, message: String)
    case unsupportedVersion(path: String, value: String)
    case unsupportedValue(path: String, value: String)
}

/// Hand-written decoders over `JSONSerialization` output. Unknown fields are ignored; every field
/// the reader uses is checked and reports the first problem with its JSON path.
enum RegenerationExportDecoder {
    static func parse(_ data: Data) throws -> [String: Any] {
        let value: Any
        do {
            value = try JSONSerialization.jsonObject(with: data, options: [])
        } catch {
            let ns = error as NSError
            let detail = ns.userInfo[NSDebugDescriptionErrorKey] as? String ?? ns.localizedDescription
            throw RegenerationDecodeFailure.malformed(path: "$", message: detail)
        }
        return try object(value, "$")
    }

    static func manifest(_ root: [String: Any]) throws -> RegenerationProgressManifest {
        let version = try schemaVersion(root, supported: [1, 2])
        let app = try object(try required(root, "app", "$"), "$.app")
        let images = try array(try required(app, "images", "$.app"), "$.app.images").enumerated().map { index, raw in
            let path = "$.app.images[\(index)]"
            let item = try object(raw, path)
            return RegenerationProgressImage(
                imageName: try string(try required(item, "imageName", path), path + ".imageName"),
                uuid: try string(try required(item, "uuid", path), path + ".uuid"),
                architecture: try string(try required(item, "architecture", path), path + ".architecture"),
                sha256: try string(try required(item, "sha256", path), path + ".sha256")
            )
        }
        let functions = try array(try required(root, "functions", "$"), "$.functions").enumerated().map { index, raw in
            try function(raw, "$.functions[\(index)]")
        }
        let resources = try array(try required(root, "resources", "$"), "$.resources").enumerated().map { index, raw in
            try resource(raw, "$.resources[\(index)]")
        }
        return RegenerationProgressManifest(
            schemaVersion: version,
            appName: try string(try required(app, "name", "$.app"), "$.app.name"),
            images: images, functions: functions, resources: resources
        )
    }

    static func dependencies(_ root: [String: Any]) throws -> RegenerationProgressDependencies {
        _ = try schemaVersion(root, supported: [1])
        let list = try array(try required(root, "dependencies", "$"), "$.dependencies").enumerated().map { index, raw in
            let path = "$.dependencies[\(index)]"
            let item = try object(raw, path)
            return RegenerationProgressDependency(
                id: try string(try required(item, "id", path), path + ".id"),
                name: try string(try required(item, "name", path), path + ".name"),
                kind: try enumValue(try required(item, "kind", path), path + ".kind"),
                version: try optionalString(item["version"], path + ".version"),
                confidence: try enumValue(try required(item, "confidence", path), path + ".confidence"),
                functions: try array(try required(item, "functions", path), path + ".functions").enumerated().map {
                    try string($0.element, path + ".functions[\($0.offset)]")
                },
                emitAs: try enumValue(try required(item, "emitAs", path), path + ".emitAs")
            )
        }
        return RegenerationProgressDependencies(dependencies: list)
    }

    static func structureReport(_ root: [String: Any]) throws -> RegenerationProgressStructureReport {
        _ = try schemaVersion(root, supported: [1])
        let dimensions = try array(try required(root, "dimensions", "$"), "$.dimensions").enumerated().map { index, raw in
            try dimension(raw, "$.dimensions[\(index)]")
        }
        var states: [String: Int]?
        if let raw = root["functionStates"], !(raw is NSNull) {
            let object = try object(raw, "$.functionStates")
            var parsed: [String: Int] = [:]
            for key in object.keys.sorted() { parsed[key] = try int(object[key], "$.functionStates." + key) }
            states = parsed
        }
        return RegenerationProgressStructureReport(
            original: try reportInput(try required(root, "original", "$"), "$.original"),
            rebuilt: try reportInput(try required(root, "rebuilt", "$"), "$.rebuilt"),
            dimensions: dimensions,
            functionStates: states
        )
    }

    // MARK: Records

    private static func function(_ raw: Any, _ path: String) throws -> RegenerationProgressFunction {
        let item = try object(raw, path)
        return RegenerationProgressFunction(
            imageQualifiedAddress: try string(try required(item, "imageQualifiedAddress", path), path + ".imageQualifiedAddress"),
            functionUUID: try string(try required(item, "functionUUID", path), path + ".functionUUID"),
            name: try optionalString(item["name"], path + ".name"),
            language: try enumValue(try required(item, "language", path), path + ".language"),
            stubFile: try optionalString(item["stubFile"], path + ".stubFile"),
            stubLine: try optionalInt(item["stubLine"], path + ".stubLine"),
            state: try enumValue(try required(item, "state", path), path + ".state"),
            dependencyId: try optionalString(item["dependencyId"], path + ".dependencyId"),
            hasDependencyIdKey: item["dependencyId"] != nil
        )
    }

    private static func resource(_ raw: Any, _ path: String) throws -> RegenerationProgressResource {
        let item = try object(raw, path)
        var equivalence: RegenerationResourceEquivalence?
        var receipt: String?
        if let raw = item["equivalence"], !(raw is NSNull) {
            let block = try object(raw, path + ".equivalence")
            equivalence = try enumValue(try required(block, "result", path + ".equivalence"), path + ".equivalence.result")
            receipt = try optionalString(block["receiptPath"], path + ".equivalence.receiptPath")
        }
        return RegenerationProgressResource(
            compiledPath: try string(try required(item, "compiledPath", path), path + ".compiledPath"),
            sourcePath: try optionalString(item["sourcePath"], path + ".sourcePath"),
            converter: try optionalString(item["converter"], path + ".converter"),
            status: try enumValue(try required(item, "status", path), path + ".status"),
            equivalence: equivalence,
            receiptPath: receipt
        )
    }

    private static func dimension(_ raw: Any, _ path: String) throws -> RegenerationDimensionResult {
        let item = try object(raw, path)
        var outcomes: [RegenerationItemOutcome: Int] = [:]
        for (index, entry) in try array(try required(item, "items", path), path + ".items").enumerated() {
            let itemPath = path + ".items[\(index)]"
            let outcome: RegenerationItemOutcome = try enumValue(
                try required(try object(entry, itemPath), "outcome", itemPath), itemPath + ".outcome"
            )
            outcomes[outcome, default: 0] += 1
        }
        var score: Double?
        if let value = item["score"], !(value is NSNull) { score = try number(value, path + ".score") }
        return RegenerationDimensionResult(
            dimension: try enumValue(try required(item, "dimension", path), path + ".dimension"),
            status: try enumValue(try required(item, "status", path), path + ".status"),
            notMeasuredReason: try optionalString(item["notMeasuredReason"], path + ".notMeasuredReason"),
            matched: try int(try required(item, "matched", path), path + ".matched"),
            missingInRebuilt: try int(try required(item, "missingInRebuilt", path), path + ".missingInRebuilt"),
            extraInRebuilt: try int(try required(item, "extraInRebuilt", path), path + ".extraInRebuilt"),
            differing: try int(try required(item, "differing", path), path + ".differing"),
            score: score,
            listedMissing: outcomes[.missingInRebuilt] ?? 0,
            listedExtra: outcomes[.extraInRebuilt] ?? 0,
            listedDiffering: outcomes[.differing] ?? 0
        )
    }

    private static func reportInput(_ raw: Any, _ path: String) throws -> RegenerationProgressReportInput {
        let item = try object(raw, path)
        return RegenerationProgressReportInput(
            path: try string(try required(item, "path", path), path + ".path"),
            sliceSha256: try string(try required(item, "sliceSha256", path), path + ".sliceSha256"),
            architecture: try string(try required(item, "architecture", path), path + ".architecture"),
            uuid: try string(try required(item, "uuid", path), path + ".uuid")
        )
    }

    // MARK: Primitives

    private static func schemaVersion(_ root: [String: Any], supported: Set<Int>) throws -> Int {
        let raw = try required(root, "schemaVersion", "$")
        guard let value = integer(raw) else {
            throw RegenerationDecodeFailure.malformed(path: "$.schemaVersion", message: "expected an integer")
        }
        guard supported.contains(value) else {
            throw RegenerationDecodeFailure.unsupportedVersion(path: "$.schemaVersion", value: String(value))
        }
        return value
    }

    private static func required(_ object: [String: Any], _ key: String, _ path: String) throws -> Any {
        guard let value = object[key] else {
            throw RegenerationDecodeFailure.malformed(path: path + "." + key, message: "missing required property")
        }
        return value
    }

    private static func object(_ value: Any, _ path: String) throws -> [String: Any] {
        guard let result = value as? [String: Any] else {
            throw RegenerationDecodeFailure.malformed(path: path, message: "expected an object")
        }
        return result
    }

    private static func array(_ value: Any, _ path: String) throws -> [Any] {
        guard let result = value as? [Any] else {
            throw RegenerationDecodeFailure.malformed(path: path, message: "expected an array")
        }
        return result
    }

    private static func string(_ value: Any, _ path: String) throws -> String {
        guard let result = value as? String else {
            throw RegenerationDecodeFailure.malformed(path: path, message: "expected a string")
        }
        return result
    }

    private static func optionalString(_ value: Any?, _ path: String) throws -> String? {
        guard let value, !(value is NSNull) else { return nil }
        return try string(value, path)
    }

    private static func isBoolean(_ number: NSNumber) -> Bool { CFGetTypeID(number) == CFBooleanGetTypeID() }

    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, !isBoolean(number), !CFNumberIsFloatType(number) else { return nil }
        return number.intValue
    }

    private static func int(_ value: Any?, _ path: String) throws -> Int {
        guard let result = integer(value) else {
            throw RegenerationDecodeFailure.malformed(path: path, message: "expected an integer")
        }
        return result
    }

    private static func optionalInt(_ value: Any?, _ path: String) throws -> Int? {
        guard let value, !(value is NSNull) else { return nil }
        return try int(value, path)
    }

    private static func number(_ value: Any, _ path: String) throws -> Double {
        guard let number = value as? NSNumber, !isBoolean(number) else {
            throw RegenerationDecodeFailure.malformed(path: path, message: "expected a number")
        }
        return number.doubleValue
    }

    private static func enumValue<E: RawRepresentable>(_ value: Any, _ path: String) throws -> E where E.RawValue == String {
        let text = try string(value, path)
        guard let result = E(rawValue: text) else {
            throw RegenerationDecodeFailure.unsupportedValue(path: path, value: text)
        }
        return result
    }
}
