import CryptoKit
import Foundation

public enum NEWFEATURESDriverKitReconstruction {
    public static let maxClasses = 20_000
    public static let maxVTablesPerClass = 32
    public static let maxVTableEntries = 4_096
    public static let maxClassBytes: UInt64 = 16 * 1_024 * 1_024
    public static let maxTotalVTableEntries = 200_000
    public static let maxTotalFields = 200_000
    public static let maxTotalStringBytes = 8 * 1_024 * 1_024

    private struct ScopedName: Hashable {
        let image: NEWFEATURESImageKey
        let name: String
    }

    public static func validateCatalog(_ catalog: NEWFEATURESDriverKitCatalog) throws {
        guard catalog.schemaVersion == 1,
              (20...25).contains(catalog.release), catalog.architecture == "arm64",
              validName(catalog.sdkBuildIdentifier), catalog.classes.count <= maxClasses,
              catalog.messages.count <= 50_000 else {
            throw NEWFEATURESError.malformedFact("unsupported DriverKit SDK identity or catalog limits")
        }
        var names = Set<String>()
        var fieldsSeen = 0
        var stringBytes = 0
        for record in catalog.classes {
            guard validName(record.name), names.insert(record.name).inserted,
                  record.sizeBytes > 0, record.sizeBytes <= maxClassBytes,
                  record.parentName == nil || validName(record.parentName!) else {
                throw NEWFEATURESError.malformedFact("duplicate/invalid SDK class")
            }
            var fields = Set<String>()
            fieldsSeen += record.fields.count
            stringBytes += record.name.utf8.count
            if let parent = record.parentName { stringBytes += parent.utf8.count }
            guard fieldsSeen <= maxTotalFields, stringBytes <= maxTotalStringBytes else {
                throw NEWFEATURESError.malformedFact("SDK field/string budget")
            }
            for field in record.fields {
                stringBytes += field.name.utf8.count + field.typeName.utf8.count
                guard validName(field.name), validName(field.typeName),
                      fields.insert(field.name).inserted,
                      field.sizeBytes > 0, field.offsetBytes <= record.sizeBytes,
                      field.sizeBytes <= record.sizeBytes - field.offsetBytes else {
                    throw NEWFEATURESError.malformedFact("out-of-bounds/duplicate SDK field")
                }
            }
            guard stringBytes <= maxTotalStringBytes else {
                throw NEWFEATURESError.malformedFact("SDK string budget")
            }
            let ordered = record.fields.sorted { $0.offsetBytes < $1.offsetBytes }
            for pair in zip(ordered, ordered.dropFirst()) {
                guard pair.0.offsetBytes + pair.0.sizeBytes <= pair.1.offsetBytes else {
                    throw NEWFEATURESError.malformedFact("overlapping SDK fields (union not modeled)")
                }
            }
        }
        let catalogByName = Dictionary(uniqueKeysWithValues: catalog.classes.map { ($0.name, $0) })
        try validateParentChains(
            Array(catalogByName.keys),
            parent: { catalogByName[$0]?.parentName },
            label: "SDK inheritance cycle"
        )
        for child in catalog.classes {
            if let parent = child.parentName, let supertype = catalogByName[parent] {
                guard child.sizeBytes >= supertype.sizeBytes else {
                    throw NEWFEATURESError.malformedFact("SDK child smaller than parent")
                }
                for field in child.fields where field.offsetBytes < supertype.sizeBytes {
                    throw NEWFEATURESError.malformedFact("field overlaps inherited SDK layout")
                }
            }
        }
        var messageIDs = Set<UInt64>()
        for message in catalog.messages {
            guard validName(message.name), messageIDs.insert(message.id).inserted else {
                throw NEWFEATURESError.malformedFact("duplicate/invalid IORPC ID")
            }
        }
    }

    public static func reconstruct(
        observed: [NEWFEATURESObservedDriverClass],
        sdk: NEWFEATURESDriverKitCatalog?,
        admission: NEWFEATURESTrustedSDKAdmission? = nil,
        canonicalCatalogJSON: Data? = nil
    ) throws -> NEWFEATURESDriverKitReport {
        guard observed.count <= maxClasses else {
            throw NEWFEATURESError.malformedFact("too many observed classes")
        }
        if let sdk { try validateCatalog(sdk) }
        let admitted = if let sdk, let admission, let canonicalCatalogJSON {
            admit(sdk, canonicalBytes: canonicalCatalogJSON, against: admission)
        } else {
            false
        }
        var byName: [ScopedName: NEWFEATURESObservedDriverClass] = [:]
        var totalVTableEntries = 0
        var totalStringBytes = 0
        for item in observed {
            let scoped = ScopedName(image: item.image, name: item.name)
            guard validName(item.name), byName[scoped] == nil,
                  item.parentName == nil || validName(item.parentName!),
                  item.sizeBytes > 0, item.sizeBytes <= maxClassBytes,
                  item.provenance.source == .classMetadata,
                  item.provenance.sourceSHA256 == item.image.sha256,
                  item.vtables.count <= maxVTablesPerClass else {
                throw NEWFEATURESError.malformedFact("untrusted class identity or bounds")
            }
            totalStringBytes += item.name.utf8.count
            if let parent = item.parentName { totalStringBytes += parent.utf8.count }
            if let build = item.recordedSDKBuildIdentifier {
                guard validName(build) else {
                    throw NEWFEATURESError.malformedFact("unbounded observed SDK build identifier")
                }
                totalStringBytes += build.utf8.count
            }
            var vtableAddresses = Set<UInt64>()
            for table in item.vtables {
                totalVTableEntries += table.entries.count
                guard table.address > 0, vtableAddresses.insert(table.address).inserted,
                      table.entries.count <= maxVTableEntries,
                      totalVTableEntries <= maxTotalVTableEntries else {
                    throw NEWFEATURESError.malformedFact("vtable address/count")
                }
                var slots = Set<Int>()
                for entry in table.entries {
                    totalStringBytes += entry.symbolName?.utf8.count ?? 0
                    guard entry.slot >= 0, entry.slot < maxVTableEntries,
                          entry.targetAddress > 0, slots.insert(entry.slot).inserted,
                          entry.symbolName == nil || validName(entry.symbolName!) else {
                        throw NEWFEATURESError.malformedFact("invalid/duplicate vtable slot")
                    }
                }
            }
            guard totalStringBytes <= maxTotalStringBytes else {
                throw NEWFEATURESError.malformedFact("observed string budget")
            }
            byName[scoped] = item
        }
        // Linear-time parent coloring, scoped to the SAME image owner.
        try validateParentChains(
            Array(byName.keys),
            parent: { key in
                guard let parent = byName[key]?.parentName else { return nil }
                let scoped = ScopedName(image: key.image, name: parent)
                return byName[scoped] == nil ? nil : scoped
            },
            label: "OSMetaClass inheritance cycle"
        )
        for (key, item) in byName {
            if let parent = item.parentName,
               let parentRecord = byName[ScopedName(image: key.image, name: parent)],
               parentRecord.sizeBytes > item.sizeBytes {
                throw NEWFEATURESError.malformedFact("child smaller than parent")
            }
        }
        let sdkMap = Dictionary(uniqueKeysWithValues: (sdk?.classes ?? []).map { ($0.name, $0) })
        var unknownParents = Set<NEWFEATURESUnknownDriverParent>()
        let projections = observed.sorted {
            if $0.image != $1.image { return $0.image < $1.image }
            return $0.name < $1.name
        }.map { item -> NEWFEATURESDriverClassProjection in
            let parentAbsent = item.parentName.map {
                byName[ScopedName(image: item.image, name: $0)] == nil &&
                    !(admitted && sdkMap[$0] != nil)
            } ?? false
            if parentAbsent, let parent = item.parentName {
                unknownParents.insert(.init(image: item.image, name: parent))
            }
            let sdkType = sdk.flatMap { catalog -> NEWFEATURESSDKClass? in
                guard admitted, item.recordedSDKRelease == catalog.release,
                      item.recordedSDKBuildIdentifier == catalog.sdkBuildIdentifier else { return nil }
                return sdkMap[item.name]
            }
            let status: NEWFEATURESClassLayoutStatus
            let fields: [NEWFEATURESDriverKitField]
            if sdk != nil && !admitted {
                status = .sdkNotAdmitted
                fields = []
            } else if parentAbsent {
                status = .unobservedParent
                fields = []
            } else if let sdkType {
                if sdkType.parentName != item.parentName {
                    status = .sdkHierarchyMismatch
                    fields = []
                } else if sdkType.sizeBytes != item.sizeBytes {
                    status = .sdkSizeMismatch
                    fields = []
                } else {
                    status = .sdkSizeConcordant
                    fields = sdkType.fields.sorted {
                        if $0.offsetBytes != $1.offsetBytes { return $0.offsetBytes < $1.offsetBytes }
                        return $0.name < $1.name
                    }
                }
            } else {
                status = .observedWithoutSDK
                fields = []
            }
            return NEWFEATURESDriverClassProjection(observed: item, status: status, applicableFields: fields)
        }
        return NEWFEATURESDriverKitReport(
            classes: projections,
            unknownParents: unknownParents.sorted {
                if $0.image != $1.image { return $0.image < $1.image }
                return $0.name < $1.name
            }
        )
    }

    public static func admitOnce(
        _ catalog: NEWFEATURESDriverKitCatalog,
        canonicalBytes: Data,
        against trusted: NEWFEATURESTrustedSDKAdmission
    ) throws -> NEWFEATURESAdmittedDriverKitCatalog {
        guard admit(catalog, canonicalBytes: canonicalBytes, against: trusted) else {
            throw NEWFEATURESError.malformedFact("SDK catalog not independently admitted")
        }
        return NEWFEATURESAdmittedDriverKitCatalog(
            catalog: catalog, digest: catalogWireDigest(canonicalBytes)
        )
    }

    public static func resolveKernelMessage(
        _ observation: NEWFEATURESKernelMessageObservation,
        admitted: NEWFEATURESAdmittedDriverKitCatalog
    ) -> NEWFEATURESKernelMessageResolution {
        guard observation.recordedSDKRelease == admitted.release,
              observation.recordedSDKBuildIdentifier == admitted.buildIdentifier,
              admitted.architecture == "arm64" else { return .incompatibleSDK }
        guard let named = admitted.messageNames[observation.messageID] else {
            return .unknown
        }
        return .named(named)
    }

    private static func validName(_ string: String) -> Bool {
        !string.isEmpty && string.utf8.count <= 256 &&
            string.unicodeScalars.allSatisfy { $0.value >= 32 && $0.value != 127 }
    }

    /// SHA-256 over EXACT producer wire bytes, including Python tool's final
    /// newline. Never reserialize and hash Swift JSONEncoder output instead.
    public static func catalogWireDigest(_ canonicalBytes: Data) -> String {
        SHA256.hash(data: canonicalBytes).map { String(format: "%02x", $0) }.joined()
    }

    public static func admit(
        _ catalog: NEWFEATURESDriverKitCatalog,
        canonicalBytes: Data,
        against trusted: NEWFEATURESTrustedSDKAdmission
    ) -> Bool {
        guard (try? validateCatalog(catalog)) != nil,
              trusted.release == catalog.release,
              trusted.buildIdentifier == catalog.sdkBuildIdentifier,
              trusted.sourceHeaderTreeSHA256.utf8.count == 64,
              trusted.sourceHeaderTreeSHA256.utf8.allSatisfy({
                  (48...57).contains($0) || (97...102).contains($0)
              }),
              canonicalBytes.count <= 32 * 1_024 * 1_024,
              canonicalBytes.last == 0x0a,
              catalogWireDigest(canonicalBytes) == trusted.pinnedCatalogSHA256,
              let decoded = try? JSONDecoder().decode(NEWFEATURESDriverKitCatalog.self, from: canonicalBytes),
              (try? validateCatalog(decoded)) != nil else { return false }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        // Compare typed meaning using the same Swift serializer, but hash
        // the original Python canonical bytes, never these normalized bytes.
        guard let expected = try? encoder.encode(catalog),
              let actual = try? encoder.encode(decoded) else { return false }
        return expected == actual
    }

    /// Iterative graph coloring: O(nodes), no recursive Swift call-stack growth.
    private static func validateParentChains<Key: Hashable>(
        _ nodes: [Key],
        parent: (Key) -> Key?,
        label: String
    ) throws {
        var color: [Key: UInt8] = [:]
        for start in nodes where color[start] == nil {
            var chain: [Key] = []
            var current: Key? = start
            while let node = current {
                if color[node] == 2 { break }
                if color[node] == 1 {
                    throw NEWFEATURESError.malformedFact(label)
                }
                color[node] = 1
                chain.append(node)
                current = parent(node)
            }
            for node in chain { color[node] = 2 }
        }
    }
}
