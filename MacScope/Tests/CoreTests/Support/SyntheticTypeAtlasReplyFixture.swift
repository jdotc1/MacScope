import Foundation
@testable import MacScope

/// DERIVED anonymous shape/length fixture; authored, unrun. Numeric manifests encode
/// lengths, counts, nullable fields and flags, never source names or addresses.
/// Raw Swift members are deliberately synthetic no-layout counterparts of their
/// Objective-C members. The real link builder performs all sharing and link creation.
enum SyntheticTypeAtlasReplyFixture {
    private enum Invalid: Error { case manifest }

    private static func numbers(_ text: String) throws -> [Int] {
        try text.split(separator: ",").map {
            guard let value = Int($0) else { throw Invalid.manifest }
            return value
        }
    }

    private static func pairs(_ text: String) throws -> [Int: Int] {
        var result: [Int: Int] = [:]
        for token in text.split(separator: ",") {
            let fields = token.split(separator: ":")
            guard fields.count == 2, let key = Int(fields[0]), let value = Int(fields[1]) else {
                throw Invalid.manifest
            }
            result[key] = value
        }
        return result
    }

    /// Exact ASCII byte length, distinct within each relevant row/name namespace.
    private static func text(_ count: Int, ordinal: Int) -> String {
        precondition(count >= 3)
        let suffix = String(ordinal, radix: 36, uppercase: true)
        precondition(suffix.utf8.count <= count)
        return String(repeating: "Q", count: count - suffix.utf8.count) + suffix
    }

    private static func optionalText(_ count: Int, ordinal: Int) -> String? {
        guard count >= 0 else { return nil }
        // Non-name type spellings may be only two bytes long.
        let suffix = String(ordinal % 36, radix: 36, uppercase: true)
        return String(repeating: "Z", count: max(0, count - 1)) + suffix
    }

    /// All generated addresses use a separate synthetic range, with 11-byte hex text.
    private static func address(_ row: Int, _ field: Int, _ ordinal: Int = 0) -> UInt64 {
        0x700000000 + UInt64(row * 100_000 + field * 1_000 + ordinal)
    }

    private static let nameLengths = [26,29,19,30,30,29,31,36,32,34,19,23,28,39,35,25,39,32,18,67,16,29,19,9,8,21,12,14,11,14,20,16,14,3,17,8,18,18,17,19,24,20,22,8,11,16,27,23,13,27,20,7,19]
    private static let partners = [27,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51]
    private static let instanceSizes = [800,8,16,24,8,272,80,104,280,144,56,32,16,72,64,24,160,56,34,16]
    private static let userCounts = [0,1,1,1,1,1,1,0,1,1,0,1,1,1,1,1,1,1,1,1]
    private static let swiftSuperclassLengths = [21,-1,-1,-1,-1,-1,-1,17,10,21,17,21,21,21,21,21,12,12,21,21,21,12,21,21,12,-1]
    private static let conformanceLengths: [Int: [Int]] = [
        0:[16],5:[16],6:[16],7:[16],8:[16],9:[16],11:[21],12:[12],13:[16],14:[16],16:[16],17:[16],
        20:[8],22:[8],23:[8],25:[8],26:[8],
        29:[35,16,20,9,8,21],30:[35,16,20,9,21,8],31:[35,16,20,9,21,8],
        32:[35,16,20,9,8,21],33:[35,16,20,9,21,8],
    ]

    // Each method-name length is retained, in row order. All 688 are named methods.
    private static let methodNameLengths = [
        "19,23,11,15,15,19,11,13,18,17,21,20,17,16,17,19,20,16,12,11,16,16,12,11,21,20,18,17,23,23,17,15,10,14,16,17,12,16,11,10,15,18,12,12,23,14,13",
        "13,12,13,14,14",
        "8,12,14,16,21,15,14,14,13",
        "11,15,11,13,23,14,13",
        "5,14,14",
        "15,19,14,18,14,18,10,14,19,23,12,16,9,13,12,16,11,15,11,15,13,17,12,16,14,18,13,17,11,13,14,14,16,13,20,13,6,15,15,17,16,12,12,23,14,13",
        "15,19,14,18,10,14,11,13,31,16,12,12,23,14,13",
        "13,17,14,18,13,17,16,20,18,22,13,17,13,17,15,19,11,13,11,11,13,12,12,23,14,13",
        "14,18,15,19,11,13,12,12,12,23,14,13",
        "7,11,11,15,18,22,13,17,15,19,15,19,10,14,12,16,11,13,13,13,12,13,12,12,23,14,13",
        "4,13",
        "41,30,25,9,12,12,18,15,4,13",
        "8,11,23,14,13",
        "9,13,10,14,10,14,9,13,9,13,9,13,9,13,11,13,11,23,14,13",
        "8,12,10,14,11,13,17,21,7,12,12,23,14,13",
        "4,13",
        "16,20,13,17,13,17,21,25,18,22,6,10,9,13,6,10,11,15,7,11,9,13,12,16,12,16,11,15,6,10,11,13,16,16,13,23,14,13",
        "12,16,10,14,11,13,13,12,12,23,14,13",
        "4,13", "",
        "18,37,37,24,24,40,25,28,35,35,35,55,55,36,44,40,40,57,31,39,39,56,49,49,66,66,30,70,33,32,43,43,34,34,16,16,15,14,19,19,20,20,16,22,21,23,16,22,29,33,21,18,26,23,26,25,25,24,30,29,29,28,30",
        "31", "27,27,30,30,33,33",
        "4,10,12,24,10,10,10,10,11,11,16,28,8,14,15,37,37,23,22,29,29,27,17,23,28,30,29,29,36,20,32,32,15,15,41,41,30,30,38,38,41,41,22,22,28,28,34,34,52,52,35,35,25,25,41,41,31,31,27,27,30,30,17,17,34,34,25,25,24,24,25,25,35,35,47,47,39,39,51,51,43,43,62,62,55,55,63,63,42,42,61,61,54,54,62,62,63,63,64,64,8,8,19,15,27,44,44,44,44,66,66,67,67,66,66,67,67,26,29,39,39,32,32,32,43,43,38,38,63,63,8,8,14,14,25,25,11,9,9,25,25,38,38,43,43,29,29,47,47,54,54,21,39,39,69,69,15,11,43,43,30,36,36,24,33,24,30,24,24,31,31,37,37,23,18,41,41,33,33,39,39,46,46,52,52,24,34,28,27,35,39,37,36,36,33,33,30,30,27,27,19,19,40,40,19,19,40,40,16,16,37,37,39,39,32,32,24,24,43,43,52,52,35,35,23,23,23,33,33,78,64",
        "8,4,10,5,4,16,16,27,27,38,38,7,14,14,16,16,19,19,19,19,6,7,11,11,4,11,16",
        "27,21,21,21,22,25,34,28,30,22,52,48,48,20,29,61,61,41,41,38,37,45,52,52,56,34,34,31,53,31,30,20,19,22,21,28,27,28,27,22,21,25,37,35,46,43",
        "74,74,16,78,80,93,85,85,94,94,70,70",
    ]
    private static let selectorCounts = [
        "6:12,9:2,10:2,31:1,44:12,45:15", "2:1,3:1,4:15", "1:1,2:15,7:1", "2:12,4:12,5:15", "1:1,2:15",
        "28:12,43:12,44:15", "6:12,8:1,12:12,13:15", "16:12,23:12,24:15", "4:12,9:12,10:15", "16:12,24:12,25:15",
        "0:5", "8:5", "1:12,2:12,3:15", "14:12,17:12,18:15", "4:12,6:2,7:2,11:12,12:15", "0:5",
        "30:12,35:12,36:15", "4:12,9:12,10:15", "0:5", "", "", "0:1", "", "0:1", "", "", "",
    ]

    // count, initial flags cycling 18/19/20; later flags default to 16.
    private static let vtables: [Int: (Int, Int, String, String)] = [
        27:(116,63,"96:18,97:19,98:20","64,65,66,67,68,69,70,73,74,75,84,85,86,87,88,89,90,91,93,94,95,99,100,101,102,103,104,105,106,107,108,109,110,112,114,115"),
        35:(3,3,"",""),36:(6,6,"",""),37:(2,0,"","0"),
        38:(106,84,"","87,88,89,90,91,92,94,95,97,103,104,105"),
        39:(26,18,"","18,21,22,23,24,25"),40:(41,30,"","30,31,34,35,36,38,39,40"),
        41:(54,48,"","48,50,51,52,53"),42:(57,42,"","42,43,44,45,46,47,49,52,53,54,55,56"),
        43:(17,15,"15:1","16"),44:(19,9,"","11,12"),45:(3,3,"",""),46:(25,24,"","24"),
        47:(17,9,"","10,13,14,15,16"),48:(6,0,"",""),49:(62,57,"","57,58,59,60,61"),
        50:(22,15,"","15,16,18,19,20,21"),51:(17,15,"15:1",""),52:(1,0,"0:1",""),
    ]

    // name length, type length (-1 nil), offset (-1 nil), size (-1 nil),
    // evidence (0 unknown / 1 descriptor), linked Swift type length (-1 nil).
    private static let memberShapes: [Int: String] = [
        0:"7,-1,-1,-1,0,5;11,-1,-1,8,0,7;9,-1,-1,8,0,3;9,-1,-1,-1,0,5;7,-1,-1,-1,0,5;14,-1,-1,16,0,6;12,-1,-1,8,0,8;15,-1,-1,16,0,6;13,-1,-1,8,0,8;16,-1,-1,8,0,8;17,-1,-1,8,0,8;16,-1,-1,8,0,8;17,-1,-1,16,0,6;12,-1,-1,8,0,8;12,-1,-1,16,0,6;10,-1,-1,8,0,8;13,-1,-1,8,0,8;14,-1,-1,8,0,8;13,-1,-1,8,0,8;14,-1,-1,16,0,6;11,-1,-1,8,0,8;11,-1,-1,16,0,6;9,-1,-1,8,0,8;11,-1,-1,8,0,8;13,-1,-1,8,0,8;12,-1,-1,8,0,8;13,-1,-1,16,0,6;12,-1,-1,8,0,8;12,-1,-1,16,0,6;10,-1,-1,8,0,8;12,-1,-1,8,0,8;14,-1,-1,8,0,8;13,-1,-1,8,0,8;14,-1,-1,16,0,6;13,-1,-1,8,0,8;13,-1,-1,16,0,6;11,-1,-1,8,0,8;13,-1,-1,8,0,8;15,-1,-1,8,0,8;14,-1,-1,8,0,8;15,-1,-1,16,0,6;14,-1,-1,8,0,8;14,-1,-1,16,0,6;12,-1,-1,8,0,8;14,-1,-1,8,0,8;16,-1,-1,8,0,8;15,-1,-1,8,0,8;16,-1,-1,16,0,6;15,-1,-1,8,0,8;15,-1,-1,16,0,6;13,-1,-1,8,0,8;15,-1,-1,8,0,8;17,-1,-1,8,0,8;16,-1,-1,8,0,8;17,-1,-1,16,0,6;14,-1,-1,8,0,8;14,-1,-1,16,0,6;12,-1,-1,8,0,8;14,-1,-1,8,0,8;16,-1,-1,8,0,8;15,-1,-1,8,0,8;16,-1,-1,16,0,6;14,-1,-1,8,0,8;14,-1,-1,16,0,6;12,-1,-1,8,0,8;14,-1,-1,8,0,8;16,-1,-1,8,0,8;15,-1,-1,8,0,8;16,-1,-1,16,0,6;19,10,-1,8,0,-1;11,21,-1,8,0,-1;15,21,-1,8,0,-1;11,-1,-1,8,0,-1;12,-1,-1,8,0,-1;10,-1,-1,8,0,-1;10,-1,-1,8,0,-1;10,-1,-1,8,0,-1;10,-1,-1,8,0,-1;10,-1,-1,8,0,-1;14,-1,-1,8,0,-1;10,-1,-1,8,0,-1;15,-1,-1,8,0,-1;5,-1,-1,8,0,-1",
        2:"8,2,8,8,1,-1",3:"14,-1,8,8,1,-1;11,9,16,8,1,-1",
        5:"13,-1,8,16,1,6;13,-1,24,8,1,3;13,-1,32,8,1,8;14,-1,40,8,1,8;14,-1,48,8,1,8;13,-1,56,8,1,8;13,-1,64,8,1,8;13,-1,72,8,1,8;10,-1,80,8,1,8;11,-1,88,8,1,8;10,-1,96,8,1,8;4,-1,104,8,1,9;9,-1,112,16,1,6;9,-1,128,8,1,3;11,-1,136,8,1,7;14,-1,144,1,1,4;6,-1,145,1,1,4;15,21,152,8,1,-1;14,13,160,8,1,-1;14,15,168,8,1,-1;10,11,176,8,1,-1;19,19,184,8,1,-1;12,32,192,8,1,19;9,10,200,8,1,-1;12,10,208,8,1,-1;11,10,216,8,1,-1;11,10,224,8,1,-1;13,10,232,8,1,-1;12,10,240,8,1,-1;14,14,248,8,1,-1;13,12,256,8,1,-1;15,-1,264,8,1,-1",
        6:"15,13,8,8,1,-1;14,13,16,8,1,-1;10,12,24,8,1,-1;11,-1,32,8,1,7;15,-1,40,16,1,6;15,-1,56,16,1,6;15,-1,72,8,1,-1",
        7:"11,-1,8,4,1,6;11,-1,12,4,1,6;13,-1,16,4,1,6;7,-1,-1,-1,0,3;11,-1,-1,8,0,7;13,13,-1,8,0,-1;14,14,-1,8,0,-1;13,12,-1,8,0,-1;16,10,-1,8,0,-1;18,10,-1,8,0,-1;13,10,-1,8,0,-1;13,10,-1,8,0,-1;15,21,-1,8,0,-1;15,-1,-1,8,0,-1",
        8:"11,-1,8,8,1,7;12,-1,16,16,1,6;12,-1,32,8,1,8;12,-1,40,16,1,6;12,-1,56,8,1,8;7,-1,64,16,1,6;7,-1,80,16,1,6;5,-1,96,16,1,6;6,-1,112,16,1,6;6,-1,128,16,1,6;8,-1,144,16,1,6;5,-1,160,16,1,6;10,-1,176,16,1,6;11,-1,192,16,1,6;9,-1,208,16,1,6;8,-1,224,16,1,6;8,-1,240,16,1,6;14,12,256,8,1,-1;15,15,264,8,1,-1;15,-1,272,8,1,-1",
        9:"14,-1,8,8,1,12;18,-1,16,16,1,6;15,-1,32,16,1,6;9,-1,48,16,1,6;16,-1,64,8,1,8;11,-1,72,8,1,7;7,13,80,8,1,-1;11,14,88,8,1,-1;18,12,96,8,1,-1;13,13,104,8,1,-1;15,13,112,8,1,-1;15,13,120,8,1,-1;10,10,128,8,1,-1;12,10,136,8,1,-1",
        10:"9,-1,-1,-1,0,4;9,-1,-1,16,0,6;12,-1,-1,16,0,6;4,-1,-1,8,0,3;10,-1,-1,8,0,8",
        11:"12,-1,8,8,1,-1;15,-1,16,8,1,-1;9,-1,24,8,1,3",12:"7,-1,8,8,1,-1",
        13:"11,-1,8,8,1,7;9,13,16,8,1,-1;10,10,24,8,1,-1;10,10,32,8,1,-1;9,13,40,8,1,-1;9,13,48,8,1,-1;9,13,56,8,1,-1;9,13,64,8,1,-1",
        14:"11,-1,8,8,1,7;14,-1,16,8,1,8;14,-1,24,16,1,6;8,13,40,8,1,-1;10,12,48,8,1,-1;15,-1,56,8,1,-1",
        15:"14,-1,8,16,1,6",
        16:"9,-1,8,8,1,6;10,-1,16,4,1,5;9,-1,24,8,1,6;10,-1,32,4,1,6;16,13,40,8,1,-1;13,13,48,8,1,-1;13,15,56,8,1,-1;21,13,64,8,1,-1;18,13,72,8,1,-1;6,13,80,8,1,-1;9,13,88,8,1,-1;6,10,96,8,1,-1;11,10,104,8,1,-1;7,10,112,8,1,-1;9,10,120,8,1,-1;12,10,128,8,1,-1;12,10,136,8,1,-1;11,15,144,8,1,-1;6,13,152,8,1,-1",
        17:"12,-1,8,16,1,6;9,-1,24,8,1,3;11,-1,32,8,1,7;12,14,40,8,1,-1;10,12,48,8,1,-1",
        18:"8,-1,8,8,1,10;17,-1,16,8,1,-1;18,-1,24,8,1,-1;14,-1,32,1,1,4;8,-1,33,1,1,4",
        29:"9,-1,-1,-1,0,-1",30:"9,-1,-1,-1,0,-1",31:"9,-1,-1,-1,0,-1",32:"9,-1,-1,-1,0,-1",33:"9,-1,-1,-1,0,-1",
    ]

    // name length, attribute UTF-8 length, quotation count. Five attributes have
    // two quotation characters; replacing them preserves both JSON escape levels.
    private static let propertyShapes: [Int: String] = [
        23:"4,16,2;10,6,0;12,23,2;24,12,0;8,6,0;8,6,0;8,6,0;8,6,0;9,6,0;9,6,0;16,6,0;28,6,0;8,6,0;14,6,0;15,6,0;35,6,0;35,6,0;23,6,0;22,6,0;26,6,0;26,6,0;27,6,0;17,6,0;23,6,0;28,6,0;30,6,0;26,6,0;26,6,0;36,6,0;20,6,0;26,6,0;29,6,0;36,6,0;36,6,0;11,6,0;9,6,0;9,6,0;21,6,0;15,6,0;11,15,2;24,6,0;30,6,0;23,6,0;18,6,0;24,6,0;34,6,0;28,6,0;27,6,0;35,4,0;37,6,0",
        24:"4,6,0;10,6,0;11,16,2;16,16,2",
    ]

    static func entries() throws -> [TypeAtlasEntry] {
        var result: [TypeAtlasEntry] = []
        for row in 0..<53 {
            let kind: TypeAtlasKind = row < 20 ? .objcClass : row < 27 ? .objcProtocol
                : (29...33).contains(row) ? .swiftStruct : .swiftClass
            let name: String
            if row < partners.count {
                let partner = partners[row]
                let component = text(nameLengths[partner], ordinal: partner)
                name = "_TtC5Synth\(component.utf8.count)\(component)"
            } else if row == 19 {
                name = "_Tt" + text(nameLengths[row] - 3, ordinal: row)
            } else { name = text(nameLengths[row], ordinal: row) }
            var entry = TypeAtlasEntry(id: .init(slot: .primary, kind: kind, key: .address(address(row, 0))),
                kind: kind, name: name, superclass: nil, members: [], conformances: [],
                methods: [], users: [], evidence: .descriptor)
            for (ordinal, encoded) in (memberShapes[row] ?? "").split(separator: ";").enumerated() {
                let shape = try numbers(String(encoded))
                guard shape.count == 6 else { throw Invalid.manifest }
                entry.members.append(TypeAtlasMember(name: text(shape[0], ordinal: ordinal),
                    type: optionalText(shape[1], ordinal: ordinal),
                    offset: shape[2] < 0 ? nil : UInt64(shape[2]),
                    evidence: shape[4] == 0 ? .unknown : .descriptor,
                    size: shape[3] < 0 ? nil : UInt64(shape[3])))
            }
            entry.conformances = (conformanceLengths[row] ?? []).enumerated().map { text($0.element, ordinal: $0.offset) }
            if row < 20 {
                entry.instanceSize = UInt64(instanceSizes[row])
                entry.users = (0..<userCounts[row]).map { address(row, 1, $0) }
            }
            if row < 27 {
                let users = try pairs(selectorCounts[row])
                entry.methods = try numbers(methodNameLengths[row]).enumerated().map { ordinal, length in
                    let optional: Bool? = row < 20 ? nil : [20,25,26].contains(row)
                        || (row == 22 && ordinal >= 4) || (row == 23 && ordinal >= 229)
                        || (row == 24 && ordinal == 26)
                    return TypeAtlasMethod(name: text(length, ordinal: ordinal),
                        implementation: row < 20 ? address(row, 2, ordinal) : nil,
                        selectorUsers: (0..<(users[ordinal] ?? 0)).map { address(row, 3, ordinal * 20 + $0) },
                        isOptionalRequirement: optional)
                }
            }
            if kind == .objcProtocol {
                entry.declaredProperties = try (propertyShapes[row] ?? "").split(separator: ";").enumerated().map { ordinal, encoded in
                    let shape = try numbers(String(encoded))
                    guard shape.count == 3 else { throw Invalid.manifest }
                    return ObjCProperty(name: text(shape[0], ordinal: ordinal),
                        attributes: String(repeating: "R", count: shape[1] - shape[2]) + String(repeating: "\"", count: shape[2]))
                }
            }
            if row >= 27 {
                entry.qualifiedName = ((28...33).contains(row) ? "Syn." : "Synth.") + name
                entry.swiftSuperclass = optionalText(swiftSuperclassLengths[row - 27], ordinal: row)
                entry.isGeneric = false
                entry.isPrivateOrLocal = row == 52
                entry.isImportedCType = (28...33).contains(row)
                entry.hasUnassignedSwiftConformanceRecords = true
                if kind == .swiftClass { entry.swiftMethodTableResolved = row != 28 && row != 34 }
                if let shape = vtables[row] {
                    let exceptions = try pairs(shape.2)
                    let implementations = Set(try numbers(shape.3))
                    entry.methods = (0..<shape.0).map { ordinal in
                        let flags = UInt32(ordinal < shape.1 ? 18 + ordinal % 3 : exceptions[ordinal] ?? 16)
                        let implementation = implementations.contains(ordinal) ? address(row, 4, ordinal) : nil
                        let metadata = SwiftMetadataMethod(source: .vtable, index: UInt64(ordinal),
                            descriptorAddress: address(row, 5, ordinal), implementation: implementation, flags: flags)
                        return TypeAtlasMethod(name: metadata.name, implementation: implementation,
                            isClassMethod: metadata.isInstance == false, swiftMetadata: metadata)
                    }
                }
                if kind == .swiftStruct {
                    entry.swiftConformanceMethods = entry.conformances.enumerated().map { ordinal, name in
                        TypeAtlasConformanceMethods(protocolName: name, descriptorAddress: address(row, 6, ordinal), methods: nil)
                    }
                }
            }
            result.append(entry)
        }
        // Reconstruct synthetic raw Swift layout, then let the production linker
        // generate all partner IDs, counts and membersListedOn fields.
        for objcRow in partners.indices {
            let swiftRow = partners[objcRow]
            let shapes = try (memberShapes[objcRow] ?? "").split(separator: ";").map { try numbers(String($0)) }
            result[swiftRow].members = result[objcRow].members.enumerated().map { ordinal, member in
                TypeAtlasMember(name: member.name, type: optionalText(shapes[ordinal][5], ordinal: ordinal),
                    offset: nil, evidence: .unknown)
            }
        }
        return result
    }
}
