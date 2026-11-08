import CoreData
import CoreFoundation
import Foundation

/// Entity hashes are necessary but not sufficient: this also compares public schema, defaults,
/// relationships, fetch requests, configurations and identifiers, without evaluating expressions.
enum CoreDataModelSignature {
    static func encode(_ model: NSManagedObjectModel) throws -> Data {
        var entities: [String: Any] = [:]
        for entity in model.entities {
            guard let name = entity.name, entities[name] == nil else { throw RegenerationError.invalidInput("ambiguous model entity name") }
            var properties: [String: Any] = [:]
            for property in entity.properties where property.entity === entity {
                var value: [String: Any] = ["optional": property.isOptional, "transient": property.isTransient,
                    "versionHash": property.versionHash.base64EncodedString(), "versionHashModifier": null(property.versionHashModifier),
                    "renamingIdentifier": null(property.renamingIdentifier), "userInfo": try canonical(property.userInfo),
                    "validationPredicates": property.validationPredicates.map(\.predicateFormat),
                    "validationWarnings": try canonical(property.validationWarnings),
                    "indexedBySpotlight": property.isIndexedBySpotlight,
                    "legacyIndexed": (property.value(forKey: "indexed") as? NSNumber)?.boolValue ?? false,
                    "storedInExternalRecord": (property.value(forKey: "storedInExternalRecord") as? NSNumber)?.boolValue ?? false]
                if let attribute = property as? NSAttributeDescription {
                    value["kind"] = "attribute"; value["attributeType"] = attribute.attributeType.rawValue
                    value["valueClass"] = null(attribute.attributeValueClassName)
                    value["default"] = try canonical(attribute.defaultValue)
                    value["transformer"] = null(attribute.valueTransformerName)
                    value["externalBinaryStorage"] = attribute.allowsExternalBinaryDataStorage
                    value["historyValue"] = attribute.preservesValueInHistoryOnDeletion
                    value["cloudEncryption"] = attribute.allowsCloudEncryption
                    if attribute is NSDerivedAttributeDescription || attribute is NSCompositeAttributeDescription {
                        throw RegenerationError.invalidInput("derived/composite model signature is unsupported")
                    }
                } else if let relationship = property as? NSRelationshipDescription {
                    value["kind"] = "relationship"; value["destination"] = null(relationship.destinationEntity?.name)
                    value["inverse"] = null(relationship.inverseRelationship?.name)
                    value["inverseEntity"] = null(relationship.inverseRelationship?.entity.name)
                    value["minimum"] = relationship.minCount; value["maximum"] = relationship.maxCount
                    value["toMany"] = relationship.isToMany; value["ordered"] = relationship.isOrdered
                    value["deleteRule"] = relationship.deleteRule.rawValue
                } else if let fetched = property as? NSFetchedPropertyDescription {
                    value["kind"] = "fetched"
                    value["request"] = try fetched.fetchRequest.map(fetch) ?? NSNull()
                } else { throw RegenerationError.invalidInput("unmodeled Core Data property") }
                properties[property.name] = value
            }
            let indexes = entity.indexes.map { index -> [String: Any] in
                ["name": index.name, "predicate": null(index.partialIndexPredicate?.predicateFormat),
                 "elements": index.elements.map { ["property": null($0.propertyName), "type": $0.collationType.rawValue, "ascending": $0.isAscending] }]
            }.sorted { ($0["name"] as? String ?? "") < ($1["name"] as? String ?? "") }
            let constraints = entity.uniquenessConstraints.map { constraint in
                constraint.map { ($0 as? String) ?? ($0 as? NSPropertyDescription)?.name ?? "<unsupported>" }
            }
            guard entity.value(forKey: "coreSpotlightDisplayNameExpression") as? NSExpression == nil else {
                throw RegenerationError.invalidInput("Spotlight expression signature is unsupported")
            }
            entities[name] = ["class": null(entity.managedObjectClassName), "abstract": entity.isAbstract,
                "parent": null(entity.superentity?.name), "versionHashModifier": null(entity.versionHashModifier),
                "renamingIdentifier": null(entity.renamingIdentifier), "userInfo": try canonical(entity.userInfo),
                "properties": properties, "indexes": indexes, "uniquenessConstraints": constraints]
        }
        var configurations: [String: Any] = [:]
        for name in model.configurations { configurations[name] = (model.entities(forConfigurationName: name) ?? []).compactMap(\.name).sorted() }
        var fetches: [String: Any] = [:]
        for (name, request) in model.fetchRequestTemplatesByName { fetches[name] = try fetch(request) }
        let versionIdentifiers = try model.versionIdentifiers.map { try canonical($0.base) }
            .sorted { String(describing: $0) < String(describing: $1) }
        let result: [String: Any] = ["entities": entities,
            "entityVersionHashesByName": model.entityVersionHashesByName.mapValues { $0.base64EncodedString() },
            "configurations": configurations, "fetchRequests": fetches,
            "versionIdentifiers": versionIdentifiers, "localization": try canonical(model.localizationDictionary)]
        guard JSONSerialization.isValidJSONObject(result) else { throw RegenerationError.invalidInput("model signature is not representable") }
        return try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private static func fetch(_ request: NSFetchRequest<NSFetchRequestResult>) throws -> [String: Any] {
        ["entity": null(request.entityName), "predicate": null(request.predicate?.predicateFormat),
         "sort": (request.sortDescriptors ?? []).map { ["key": null($0.key), "ascending": $0.ascending,
             "selector": null($0.selector.map(NSStringFromSelector))] },
         "limit": request.fetchLimit, "offset": request.fetchOffset, "batchSize": request.fetchBatchSize,
         "resultType": request.resultType.rawValue, "includesSubentities": request.includesSubentities,
         "includesPropertyValues": request.includesPropertyValues, "includesPendingChanges": request.includesPendingChanges,
         "returnsObjectsAsFaults": request.returnsObjectsAsFaults, "returnsDistinctResults": request.returnsDistinctResults,
         "propertiesToFetch": try canonical(request.propertiesToFetch), "propertiesToGroupBy": try canonical(request.propertiesToGroupBy),
         "havingPredicate": null(request.havingPredicate?.predicateFormat),
         "prefetch": request.relationshipKeyPathsForPrefetching ?? []]
    }

    private static func null(_ value: Any?) -> Any { value ?? NSNull() }

    private static func canonical(_ value: Any?) throws -> Any {
        guard let value else { return NSNull() }
        if let string = value as? String { return string }
        if let decimal = value as? NSDecimalNumber { return ["decimal": decimal.stringValue] }
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue }
            let type = String(cString: number.objCType)
            if ["f", "d"].contains(type) { return ["float64bits": String(number.doubleValue.bitPattern, radix: 16)] }
            return ["integer": number.stringValue]
        }
        if let data = value as? Data { return ["data": data.base64EncodedString()] }
        if let date = value as? Date { return ["dateBits": String(date.timeIntervalSinceReferenceDate.bitPattern, radix: 16)] }
        if let uuid = value as? UUID { return ["uuid": uuid.uuidString.lowercased()] }
        if let url = value as? URL { return ["url": url.absoluteString] }
        if let array = value as? [Any] { return try array.map(canonical) }
        if let dictionary = value as? [AnyHashable: Any] {
            var result: [String: Any] = [:]
            for (key, item) in dictionary {
                guard let key = key as? String else { throw RegenerationError.invalidInput("model dictionary has a non-string key") }
                result[key] = try canonical(item)
            }
            return result
        }
        if let property = value as? NSPropertyDescription { return ["property": property.name] }
        throw RegenerationError.invalidInput("unmodeled Core Data schema value")
    }
}
