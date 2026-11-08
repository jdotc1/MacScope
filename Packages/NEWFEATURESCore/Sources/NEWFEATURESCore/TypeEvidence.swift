import Foundation

public enum NEWFEATURESLanguage: String, Codable, Sendable {
    case swift
    case objectiveC
    case objectiveCPlusPlus
    case cpp
    case rust
    case go
    case driverKit
}

public struct NEWFEATURESTypeKey: Hashable, Codable, Sendable, Comparable {
    public let image: NEWFEATURESImageKey
    public let language: NEWFEATURESLanguage
    public let declarationID: String

    public init(image: NEWFEATURESImageKey, language: NEWFEATURESLanguage, declarationID: String) {
        self.image = image
        self.language = language
        self.declarationID = declarationID
    }

    public static func < (lhs: Self, rhs: Self) -> Bool {
        if lhs.image != rhs.image { return lhs.image < rhs.image }
        if lhs.language.rawValue != rhs.language.rawValue {
            return lhs.language.rawValue < rhs.language.rawValue
        }
        return lhs.declarationID < rhs.declarationID
    }
}

public struct NEWFEATURESTypeMember: Hashable, Codable, Sendable {
    public let name: String
    public let typeName: String
    public let bitOffset: UInt64?
    public let bitWidth: UInt64?

    public init(name: String, typeName: String, bitOffset: UInt64? = nil, bitWidth: UInt64? = nil) {
        self.name = name
        self.typeName = typeName
        self.bitOffset = bitOffset
        self.bitWidth = bitWidth
    }
}

public struct NEWFEATURESClassType: Codable, Sendable {
    public let key: NEWFEATURESTypeKey
    public let displayName: String
    public let superclass: NEWFEATURESTypeKey?
    public let members: [NEWFEATURESTypeMember]
    public let methods: [String]
    public let provenance: NEWFEATURESProvenance

    public init(
        key: NEWFEATURESTypeKey,
        displayName: String,
        superclass: NEWFEATURESTypeKey?,
        members: [NEWFEATURESTypeMember],
        methods: [String],
        provenance: NEWFEATURESProvenance
    ) {
        self.key = key
        self.displayName = displayName
        self.superclass = superclass
        self.members = members
        self.methods = methods
        self.provenance = provenance
    }
}

/// A language-neutral, immutable class view. "Unknown" is not a valid type
/// declaration; errors remain explicit until a real SDK/metadata fact exists.
public struct NEWFEATURESTypeIndex: Sendable {
    private let types: [NEWFEATURESTypeKey: NEWFEATURESClassType]

    /// SDK digests must come from the app-owned, pinned SDKTypeArchive receipt,
    /// never from an untrusted type record's own header string.
    public init(
        _ declarations: [NEWFEATURESClassType],
        trustedSDKHeaderDigests: Set<String> = []
    ) throws {
        guard declarations.count <= 100_000 else {
            throw NEWFEATURESError.malformedFact("type count")
        }
        var built: [NEWFEATURESTypeKey: NEWFEATURESClassType] = [:]
        var memberTotal = 0, methodTotal = 0
        for record in declarations {
            memberTotal += record.members.count
            methodTotal += record.methods.count
            guard record.key.declarationID.utf8.count <= 256,
                  !record.key.declarationID.isEmpty,
                  record.displayName.utf8.count <= 512,
                  !record.displayName.isEmpty,
                  record.members.count <= 8_192,
                  record.methods.count <= 16_384,
                  memberTotal <= 200_000, methodTotal <= 200_000,
                  built[record.key] == nil,
                  (record.provenance.source == .sdkHeader
                   ? trustedSDKHeaderDigests.contains(record.provenance.sourceSHA256)
                   : record.provenance.sourceSHA256 == record.key.image.sha256) else {
                throw NEWFEATURESError.malformedFact("duplicate/untrusted class declaration")
            }
            var memberNames = Set<String>()
            var ranges: [(UInt64, UInt64)] = []
            for member in record.members {
                guard !member.name.isEmpty, member.name.utf8.count <= 256,
                      !member.typeName.isEmpty, member.typeName.utf8.count <= 512,
                      memberNames.insert(member.name).inserted else {
                    throw NEWFEATURESError.malformedFact("duplicate/invalid member")
                }
                if let offset = member.bitOffset, let width = member.bitWidth {
                    guard width > 0, width <= 128, offset <= UInt64.max - width else {
                        throw NEWFEATURESError.malformedFact("invalid bit offset/width")
                    }
                    ranges.append((offset, offset + width))
                } else if member.bitOffset != nil || member.bitWidth != nil {
                    throw NEWFEATURESError.malformedFact("incomplete bitfield layout")
                }
            }
            // Deliberately do not infer unions from overlapping field names.
            ranges.sort { $0.0 < $1.0 }
            for pair in zip(ranges, ranges.dropFirst()) where pair.0.1 > pair.1.0 {
                throw NEWFEATURESError.malformedFact("overlapping typed bitfields")
            }
            for method in record.methods where method.isEmpty || method.utf8.count > 512 {
                throw NEWFEATURESError.malformedFact("invalid method")
            }
            built[record.key] = record
        }
        for record in declarations {
            if let superclass = record.superclass {
                guard superclass.image == record.key.image, built[superclass] != nil else {
                    throw NEWFEATURESError.malformedFact("unresolved/cross-image superclass")
                }
            }
        }
        var color: [NEWFEATURESTypeKey: UInt8] = [:]
        for key in built.keys where color[key] == nil {
            var chain: [NEWFEATURESTypeKey] = []
            var current: NEWFEATURESTypeKey? = key
            while let node = current {
                if color[node] == 2 { break }
                if color[node] == 1 { throw NEWFEATURESError.malformedFact("type inheritance cycle") }
                color[node] = 1
                chain.append(node)
                current = built[node]?.superclass
            }
            for node in chain { color[node] = 2 }
        }
        types = built
    }

    public func classes(image: NEWFEATURESImageKey) -> [NEWFEATURESClassType] {
        types.values.filter { $0.key.image == image }.sorted { $0.key < $1.key }
    }

    public func classInfo(_ key: NEWFEATURESTypeKey) -> NEWFEATURESClassType? { types[key] }

    public func members(_ key: NEWFEATURESTypeKey) -> [NEWFEATURESTypeMember]? {
        types[key]?.members
    }
}
