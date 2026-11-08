import CoreData
import Foundation

struct CoreDataRoundTripConverter {
    struct RenderedModel: Sendable {
        let contents: Data
        let gaps: [String]
    }

    /// Public model descriptions are read as schema; no persistent store or application class
    /// is created. Unsupported schema features keep the compiled model as the build resource.
    func render(_ model: NSManagedObjectModel) throws -> RenderedModel {
        guard model.entities.count <= 2_000 else { throw RegenerationError.invalidInput("model exceeds entity limit") }
        var gaps: [String] = [], children: [String] = []
        var attrs = ["type": "com.apple.IDECoreDataModeler.DataModel", "documentVersion": "1.0", "sourceLanguage": "Objective-C"]
        if model.versionIdentifiers.count == 1, let identifier = model.versionIdentifiers.first as? String {
            attrs["userDefinedModelVersionIdentifier"] = identifier
        } else if !model.versionIdentifiers.isEmpty { gaps.append("Multiple or non-string model version identifiers are unsupported.") }
        if model.localizationDictionary?.isEmpty == false { gaps.append("Model localization dictionary has no source representation in this converter.") }
        for entity in model.entities.sorted(by: { ($0.name ?? "") < ($1.name ?? "") }) {
            guard let name = entity.name, !name.isEmpty else { throw RegenerationError.invalidInput("unnamed model entity") }
            var fields: [String] = []
            var attributes = ["name": name, "isAbstract": Self.yes(entity.isAbstract)]
            attributes["representedClassName"] = entity.managedObjectClassName
            if let parent = entity.superentity?.name { attributes["parentEntity"] = parent }
            attributes["versionHashModifier"] = entity.versionHashModifier
            attributes["renamingIdentifier"] = entity.renamingIdentifier
            guard entity.properties.count <= 2_000 else { throw RegenerationError.invalidInput("entity exceeds property limit") }
            for property in entity.properties.sorted(by: { $0.name < $1.name }) where property.entity === entity {
                var values = ["name": property.name, "optional": Self.yes(property.isOptional), "transient": Self.yes(property.isTransient)]
                values["versionHashModifier"] = property.versionHashModifier
                values["renamingIdentifier"] = property.renamingIdentifier
                if !property.validationPredicates.isEmpty || !property.validationWarnings.isEmpty {
                    gaps.append("\(name).\(property.name): validation predicates/warnings require source reconstruction.")
                }
                var extras = try userInfo(property.userInfo, gaps: &gaps, owner: name + "." + property.name)
                if let attribute = property as? NSAttributeDescription {
                    guard let kind = Self.attributeName(attribute.attributeType) else {
                        gaps.append("\(name).\(property.name): unsupported attribute type \(attribute.attributeType.rawValue).")
                        continue
                    }
                    if attribute is NSDerivedAttributeDescription || attribute is NSCompositeAttributeDescription {
                        gaps.append("\(name).\(property.name): derived/composite source is unsupported.")
                    }
                    values["attributeType"] = kind
                    values["allowsExternalBinaryDataStorage"] = Self.yes(attribute.allowsExternalBinaryDataStorage)
                    values["preservesValueInHistoryOnDeletion"] = Self.yes(attribute.preservesValueInHistoryOnDeletion)
                    values["allowsCloudEncryption"] = Self.yes(attribute.allowsCloudEncryption)
                    values["valueTransformerName"] = attribute.valueTransformerName
                    if attribute.attributeType == .transformableAttributeType { values["customClassName"] = attribute.attributeValueClassName }
                    if let value = attribute.defaultValue {
                        if let string = value as? String { values["defaultValueString"] = string }
                        else if let number = value as? NSNumber { values["defaultValueString"] = number.stringValue }
                        else { gaps.append("\(name).\(property.name): unsupported default value representation.") }
                    }
                    fields.append(try ResourceXML.element("attribute", attributes: values, children: extras))
                } else if let relationship = property as? NSRelationshipDescription {
                    guard let destination = relationship.destinationEntity?.name else {
                        gaps.append("\(name).\(property.name): relationship has no named destination."); continue
                    }
                    values["destinationEntity"] = destination
                    values["toMany"] = Self.yes(relationship.isToMany)
                    values["ordered"] = Self.yes(relationship.isOrdered)
                    values["minCount"] = String(relationship.minCount)
                    values["maxCount"] = String(relationship.maxCount)
                    let rules: [NSDeleteRule: String] = [.noActionDeleteRule: "No Action", .nullifyDeleteRule: "Nullify", .cascadeDeleteRule: "Cascade", .denyDeleteRule: "Deny"]
                    guard let rule = rules[relationship.deleteRule] else { throw RegenerationError.invalidInput("unknown relationship delete rule") }
                    values["deletionRule"] = rule
                    values["inverseName"] = relationship.inverseRelationship?.name
                    values["inverseEntity"] = relationship.inverseRelationship?.entity.name
                    fields.append(try ResourceXML.element("relationship", attributes: values, children: extras))
                } else if let fetched = property as? NSFetchedPropertyDescription, let request = fetched.fetchRequest {
                    if let requestXML = try fetch(request, name: nil, gaps: &gaps) { extras.append(requestXML) }
                    fields.append(try ResourceXML.element("fetchedProperty", attributes: values, children: extras))
                } else { gaps.append("\(name).\(property.name): unsupported property description.") }
            }
            fields += try userInfo(entity.userInfo, gaps: &gaps, owner: name)
            if !entity.indexes.isEmpty { gaps.append("\(name): fetch index source is unsupported.") }
            // The SDK imports this legacy property as nonoptional; Core Data also permits its
            // unset ObjC value to be nil. KVC reads that public property without forcing it.
            if entity.value(forKey: "coreSpotlightDisplayNameExpression") as? NSExpression != nil {
                gaps.append("\(name): Spotlight display expression source is unsupported.")
            }
            var constraints: [String] = []
            for constraint in entity.uniquenessConstraints {
                let names = constraint.compactMap { ($0 as? String) ?? ($0 as? NSPropertyDescription)?.name }
                guard names.count == constraint.count else { gaps.append("\(name): unsupported uniqueness constraint."); continue }
                constraints.append(try ResourceXML.element("uniquenessConstraint", attributes: [:],
                    children: try names.map { try ResourceXML.element("constraint", attributes: ["value": $0]) }))
            }
            if !constraints.isEmpty { fields.append(try ResourceXML.element("uniquenessConstraints", attributes: [:], children: constraints)) }
            children.append(try ResourceXML.element("entity", attributes: attributes, children: fields))
        }
        for configuration in model.configurations.sorted() {
            let members = (model.entities(forConfigurationName: configuration) ?? []).compactMap(\.name).sorted()
            children.append(try ResourceXML.element("configuration", attributes: ["name": configuration],
                children: try members.map { try ResourceXML.element("memberEntity", attributes: ["name": $0]) }))
        }
        for (name, request) in model.fetchRequestTemplatesByName.sorted(by: { $0.key < $1.key }) {
            if let xml = try fetch(request, name: name, gaps: &gaps) { children.append(xml) }
        }
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
            + (try ResourceXML.element("model", attributes: attrs, children: children)) + "\n"
        return .init(contents: Data(xml.utf8), gaps: gaps)
    }

    func convert(path: String, originalRoot: URL) throws -> ResourceRoundTripCandidate {
        guard RegenerationEncoding.relativePath(path), ["mom", "momd"].contains((path as NSString).pathExtension.lowercased()) else {
            throw RegenerationError.invalidInput("expected a compiled Core Data model")
        }
        let original = originalRoot.appendingPathComponent(path)
        let isVersioned = original.pathExtension.lowercased() == "momd"
        let sourcePath = (path as NSString).deletingPathExtension + (isVersioned ? ".xcdatamodeld" : ".xcdatamodel")
        let versions: [URL]
        var current: String?
        if isVersioned {
            versions = try FileManager.default.contentsOfDirectory(at: original, includingPropertiesForKeys: [.isRegularFileKey])
                .filter { $0.pathExtension == "mom" }.sorted { $0.lastPathComponent < $1.lastPathComponent }
            let infoURL = original.appendingPathComponent("VersionInfo.plist")
            if FileManager.default.fileExists(atPath: infoURL.path),
               let info = try PropertyListSerialization.propertyList(from: Data(contentsOf: infoURL), format: nil) as? [String: Any],
               let version = info["NSManagedObjectModel_CurrentVersionName"] as? String {
                current = version
            }
        } else { versions = [original] }
        guard !versions.isEmpty, versions.count <= 128 else { throw RegenerationError.invalidInput("model has no supported versions or exceeds limit") }
        var sources: [String: Data] = [:], gaps: [String] = []
        for version in versions {
            guard let model = NSManagedObjectModel(contentsOf: version) else { throw RegenerationError.invalidInput("compiled model could not be read") }
            let output = try render(model)
            let leaf = isVersioned ? version.deletingPathExtension().lastPathComponent + ".xcdatamodel" : ""
            sources[sourcePath + (leaf.isEmpty ? "" : "/" + leaf) + "/contents"] = output.contents
            gaps += output.gaps
        }
        if isVersioned {
            if let current, versions.contains(where: { $0.deletingPathExtension().lastPathComponent == current }) {
                sources[sourcePath + "/.xccurrentversion"] = try PropertyListSerialization.data(
                    fromPropertyList: ["_XCCurrentVersionName": current + ".xcdatamodel"], format: .xml, options: 0)
            } else { gaps.append("Current model version is missing or cannot be bound to a compiled version.") }
        }
        return .init(record: .init(compiledPaths: [path], sourcePath: sourcePath, converter: "core-data-v1", status: .partial,
            equivalence: .init(outcome: .notRun, tool: "momc", receiptPath: nil),
            diagnostics: gaps + ["Compile-back equivalence has not been checked."]), sourceFiles: sources, conversionComplete: gaps.isEmpty)
    }

    private func userInfo(_ values: [AnyHashable: Any]?, gaps: inout [String], owner: String) throws -> [String] {
        guard let values, !values.isEmpty else { return [] }
        var entries: [String] = []
        for (key, value) in values.sorted(by: { String(describing: $0.key) < String(describing: $1.key) }) {
            guard let key = key as? String, let value = value as? String else {
                gaps.append("\(owner): non-string user info cannot be represented in model XML."); continue
            }
            entries.append(try ResourceXML.element("entry", attributes: ["key": key, "value": value]))
        }
        return [try ResourceXML.element("userInfo", attributes: [:], children: entries)]
    }

    private func fetch(_ request: NSFetchRequest<NSFetchRequestResult>, name: String?, gaps: inout [String]) throws -> String? {
        guard let entity = request.entityName else { gaps.append("Fetch request has no named entity."); return nil }
        var attrs = ["entity": entity]
        attrs["name"] = name
        attrs["predicateString"] = request.predicate?.predicateFormat
        if request.fetchLimit != 0 || request.fetchOffset != 0 || request.fetchBatchSize != 0
            || request.resultType != .managedObjectResultType || !request.includesSubentities
            || !request.includesPropertyValues || !request.includesPendingChanges || request.returnsDistinctResults
            || !request.returnsObjectsAsFaults || request.propertiesToFetch != nil || request.propertiesToGroupBy != nil
            || request.havingPredicate != nil || request.relationshipKeyPathsForPrefetching?.isEmpty == false {
            gaps.append("Fetch request \(name ?? "fetched property") has settings without supported XML mapping.")
        }
        let children = try (request.sortDescriptors ?? []).map { descriptor -> String in
            guard let key = descriptor.key else { throw RegenerationError.invalidInput("block-based sort descriptor is unsupported") }
            return try ResourceXML.element("sortDescriptor", attributes: ["key": key, "ascending": Self.yes(descriptor.ascending)])
        }
        return try ResourceXML.element("fetchRequest", attributes: attrs, children: children)
    }

    private static func yes(_ value: Bool) -> String { value ? "YES" : "NO" }
    private static func attributeName(_ value: NSAttributeType) -> String? {
        switch value {
        case .integer16AttributeType: "Integer 16"
        case .integer32AttributeType: "Integer 32"
        case .integer64AttributeType: "Integer 64"
        case .decimalAttributeType: "Decimal"
        case .doubleAttributeType: "Double"
        case .floatAttributeType: "Float"
        case .stringAttributeType: "String"
        case .booleanAttributeType: "Boolean"
        case .dateAttributeType: "Date"
        case .binaryDataAttributeType: "Binary"
        case .UUIDAttributeType: "UUID"
        case .URIAttributeType: "URI"
        case .transformableAttributeType: "Transformable"
        default: nil
        }
    }
}
