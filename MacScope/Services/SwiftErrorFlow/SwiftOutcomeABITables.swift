import Foundation

// Frozen donor swift_abi_profiles.py:68-86; the registry is a value, not candidate evidence.
struct SwiftOutcomeLoweringObservation: Sendable {
    let evidenceID: String
    let sliceSHA256: String
    let sourceSHA256: String
    let compiler: String
    let target: String
    let optimization: String
    let symbol: String
    let parameterTypes: [String]
    let resultType: String
    let parameterLocations: [String]
    let resultLocation: String
    let observations: [(pc: UInt64, bytesHex: String, note: String)]
    let sourceCapture: String
    let disassemblyCapture: String
    let callableKind: String
    let context: [(name: String, kind: String)]
    let receiverLocation: String?

    init(evidenceID: String, sliceSHA256: String, sourceSHA256: String, compiler: String,
         target: String, optimization: String, symbol: String, parameterTypes: [String],
         resultType: String, parameterLocations: [String], resultLocation: String,
         observations: [(pc: UInt64, bytesHex: String, note: String)], sourceCapture: String,
         disassemblyCapture: String, callableKind: String = "free_function",
         context: [(name: String, kind: String)] = [], receiverLocation: String? = nil) {
        self.evidenceID = evidenceID; self.sliceSHA256 = sliceSHA256; self.sourceSHA256 = sourceSHA256
        self.compiler = compiler; self.target = target; self.optimization = optimization; self.symbol = symbol
        self.parameterTypes = parameterTypes; self.resultType = resultType
        self.parameterLocations = parameterLocations; self.resultLocation = resultLocation
        self.observations = observations; self.sourceCapture = sourceCapture; self.disassemblyCapture = disassemblyCapture
        self.callableKind = callableKind; self.context = context; self.receiverLocation = receiverLocation
    }
}

struct SwiftOutcomeStorageCapability: Sendable {
    let evidenceID: String
    let category: String
    let locations: [String]
    let bitWidth: Int?
    let indirect: Bool
    let layoutBytes: Int?
    let signed: Bool?

    init(_ evidenceID: String, _ category: String, _ locations: [String], _ bitWidth: Int?,
         indirect: Bool = false, layoutBytes: Int? = nil, signed: Bool? = nil) {
        self.evidenceID = evidenceID; self.category = category; self.locations = locations
        self.bitWidth = bitWidth; self.indirect = indirect; self.layoutBytes = layoutBytes; self.signed = signed
    }
    var json: SwiftOutcomeJSON {
        .object(["evidence_id": .string(evidenceID), "category": .string(category),
                 "locations": .array(locations.map { .string($0) }),
                 "bit_width": bitWidth.map { .integer(Int128($0)) } ?? .null,
                 "indirect": .bool(indirect), "layout_bytes": layoutBytes.map { .integer(Int128($0)) } ?? .null,
                 "signed": signed.map { .bool($0) } ?? .null])
    }
}

struct SwiftOutcomeABIRegistry: Sendable {
    private let qualifications: [String: SwiftOutcomeLoweringObservation]
    init(_ qualifications: [SwiftOutcomeLoweringObservation]) {
        // A duplicate injected identifier has the same last-value semantics as a Python dictionary.
        var rows: [String: SwiftOutcomeLoweringObservation] = [:]
        for row in qualifications { rows[row.evidenceID] = row }
        self.qualifications = rows
    }
    func qualification(id: String) -> SwiftOutcomeLoweringObservation? { qualifications[id] }

    var syncProfileIdentifier: String { "swift6-arm64-sync-untyped-research-v1" }
    var syncARM64Swift6: SwiftOutcomeJSON { Self.syncProfile }
    var stableStorageCapabilities: [String: SwiftOutcomeStorageCapability] { Self.storage }
    var stableLoweringObservations: [(pc: UInt64, bytesHex: String, note: String, sourceCase: String)] { Self.stableObservations }
    var v2Slices: Set<String> { Self.referenceSlices }
    var v2Source: String { Self.referenceSource }
    var abiReferences: [String] { Self.references }
    var compiler: String { Self.compilerIdentity }
    var ownedSourceBySlice: [String: String] { Self.ownedSources }

    private static let syncProfile: SwiftOutcomeJSON = .object([
        "identifier": .string("swift6-arm64-sync-untyped-research-v1"), "architecture": .string("arm64"),
        "language_mode": .string("6"), "execution": .string("synchronous"),
        "error_convention": .string("ordinary_untyped_throws"), "error_register": .string("x21"),
        "research_only": .bool(true), "async_supported": .bool(false), "typed_throws_supported": .bool(false),
        "witness_dispatch_supported": .bool(false), "virtual_dispatch_supported": .bool(false),
        "unproved_generics_supported": .bool(false)])
    private static let references = [
        "https://github.com/swiftlang/swift/blob/main/docs/ABI/CallingConventionSummary.rst",
        "https://github.com/swiftlang/swift/blob/main/docs/ABI/CallingConvention.rst",
        "https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h",
        "https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h"]
    private static let compilerIdentity = "Apple Swift 6.4.2 (swiftlang-6.4.2.1.9 clang-2100.4.1.1)"
    private static let initialSource = "8bbf3cb29081cc00045b62df203944101f9340716db8dae3eff628dddab60894"
    private static let referenceSource = "611642c714017e9e404d201d6346f0b323a5c13752132f03f01e65dd9703ae18"
    private static let secondSource = "ca091dde5345cda398ef78f95b6969abd0736acd508961a705654c9bedffb5cf"
    private static let referenceSlices: Set<String> = [
        "4b64cd20639936c261573c00a339d4f2e3f9105d530fdb9ed3848097cd7d5ba6",
        "d2503590aac4ecdb74158ebe11864d3bb1491c17bb171b26f94ac5f3cf37202f",
        "50a122aeda215ff81cc26d32559c05ecf0190a02ea1a4db338bcb35951fc6b88"]
    private static let ownedSources: [String: String] = [
        "4b64cd20639936c261573c00a339d4f2e3f9105d530fdb9ed3848097cd7d5ba6": referenceSource,
        "d2503590aac4ecdb74158ebe11864d3bb1491c17bb171b26f94ac5f3cf37202f": referenceSource,
        "50a122aeda215ff81cc26d32559c05ecf0190a02ea1a4db338bcb35951fc6b88": referenceSource,
        "35f5565c675d9d4c328e310bfc1adaa2bd58afc8b3905bd888f009cd03f7cd76": secondSource,
        "df089ae590af31adb53dd119c40eee667d333b8f8874f46615cc98c3007a96b9": secondSource,
        "450a078fb5260574736b8b7daf0792ed92b52c4c2b374af45d123b01b5c9b974": secondSource]
    private static let storage: [String: SwiftOutcomeStorageCapability] = [
        "Swift.Int": .init("swift-stable-v2-int", "integer", ["x0"], 64, signed: true),
        "Swift.UInt": .init("swift-stable-v2-uint", "integer", ["x0"], 64, signed: false),
        "Swift.Int8": .init("swift-stable-v2-int8", "integer", ["x0"], 8, signed: true),
        "Swift.UInt8": .init("swift-stable-v2-uint8", "integer", ["x0"], 8, signed: false),
        "Swift.Int16": .init("swift-stable-v2-int16", "integer", ["x0"], 16, signed: true),
        "Swift.UInt16": .init("swift-stable-v2-uint16", "integer", ["x0"], 16, signed: false),
        "Swift.Int32": .init("swift-stable-v2-int32", "integer", ["x0"], 32, signed: true),
        "Swift.UInt32": .init("swift-stable-v2-uint32", "integer", ["x0"], 32, signed: false),
        "Swift.Int64": .init("swift-stable-v2-int64", "integer", ["x0"], 64, signed: true),
        "Swift.UInt64": .init("swift-stable-v2-uint64", "integer", ["x0"], 64, signed: false),
        "Swift.Bool": .init("swift-stable-v2-bool", "boolean", ["x0"], 1),
        "Swift.Void": .init("swift-stable-v2-void", "void", [], 0),
        "Swift.Float": .init("swift-stable-v2-float", "floating_point", ["s0"], 32),
        "Swift.Double": .init("swift-stable-v2-double", "floating_point", ["d0"], 64),
        "Optional<Swift.Int>": .init("swift-stable-v2-optional-int", "optional_integer", ["x0", "w1"], nil),
        "Tuple<Swift.Int,Swift.Bool>": .init("swift-stable-v2-tuple-int-bool", "tuple", ["x0", "w1"], nil),
        "BroadOwned.BroadSmall": .init("owned-v2-resilient-small", "resilient_struct", ["indirect x8"], nil, indirect: true, layoutBytes: 16),
        "BroadOwned.BroadLarge": .init("owned-v2-resilient-large", "resilient_struct", ["indirect x8"], nil, indirect: true, layoutBytes: 64),
        "BroadOwned.BroadPayload": .init("owned-v2-resilient-payload", "resilient_payload_enum", ["indirect x8"], nil, indirect: true, layoutBytes: 8),
        "BroadOwned.BroadTag": .init("owned-v2-resilient-tag", "resilient_tag_enum", ["indirect x8"], nil, indirect: true, layoutBytes: 1),
        "BroadOwned.BroadReference": .init("owned-v2-reference", "class_reference", ["x0"], 64)]
    private static let stableObservations: [(pc: UInt64, bytesHex: String, note: String, sourceCase: String)] = [
        (0x1a88, "c0035fd6", "Void return", "broad_case_0023"),
        (0x1c58, "60720051", "Int8 result w0", "broad_case_0025"),
        (0x12f8, "0001271e", "Float result s0", "broad_case_0012"),
        (0x26a4, "0001629e", "Double conversion result d0", "broad_case_0036"),
        (0x2828, "e1179f1a", "Optional<Int> tag w1 alongside x0", "broad_case_0037"),
        (0x28f4, "092900a9", "resilient small result store through x8", "broad_case_0038"),
        (0x2a24, "000d803d", "resilient large result vector store through x8", "broad_case_0039"),
        (0x1598, "090100f9", "single-payload enum result through x8", "broad_case_0017"),
        (0x2c54, "09010039", "resilient tag result byte through x8", "broad_case_0041"),
        (0x1c720, "01010012", "tuple Bool field w1 alongside x0", "broad_case_0341"),
        (0x2ed0, "140800f9", "reference object accessed through return x0", "broad_case_0043"),
        (0x1c4f0, "3401028b", "concrete generic Int remains explicit x2", "broad_case_0340")]

    static let frozen = SwiftOutcomeABIRegistry([
        .init(evidenceID: "owned-initial-v1-O-transform-int",
              sliceSHA256: "ebdc1bbab109b9721a1024aa29210bf9ddd33589f833a7204faecc8e81d32857",
              sourceSHA256: initialSource, compiler: compilerIdentity, target: "arm64-apple-macosx14.0", optimization: "-O",
              symbol: "$s10BroadOwned15broad_transformyS2iKF", parameterTypes: ["Swift.Int"], resultType: "Swift.Int",
              parameterLocations: ["x0"], resultLocation: "x0",
              observations: [(0xbe0, "1f0014eb", "Int argument comparison in x0"),
                             (0xc0c, "f50300aa", "ordinary error assigned to x21"),
                             (0xc1c, "0004008b", "Int success result in x0")],
              sourceCapture: "broad-swift-initial-v1/BroadOwned.swift:3-5",
              disassemblyCapture: "broad-swift-initial-v1/objdump-O.txt:18-44"),
        .init(evidenceID: "owned-initial-v1-Onone-transform-int",
              sliceSHA256: "051cd7cab111884c8d2b53dc1ef06920948e9ba5b72e6e6e21dc9161c47b9230",
              sourceSHA256: initialSource, compiler: compilerIdentity, target: "arm64-apple-macosx14.0", optimization: "-Onone",
              symbol: "$s10BroadOwned15broad_transformyS2iKF", parameterTypes: ["Swift.Int"], resultType: "Swift.Int",
              parameterLocations: ["x0"], resultLocation: "x0",
              observations: [(0xc70, "e00f00f9", "Int argument saved from x0"),
                             (0xcbc, "f50300aa", "ordinary error assigned to x21"),
                             (0xcf0, "007d099b", "Int success result in x0")],
              sourceCapture: "broad-swift-initial-v1/BroadOwned.swift:3-5",
              disassemblyCapture: "broad-swift-initial-v1/objdump-Onone.txt:34-76"),
        .init(evidenceID: "owned-initial-v1-O-struct0080",
              sliceSHA256: "ebdc1bbab109b9721a1024aa29210bf9ddd33589f833a7204faecc8e81d32857",
              sourceSHA256: initialSource, compiler: compilerIdentity, target: "arm64-apple-macosx14.0", optimization: "-O",
              symbol: "$s10BroadOwned0A9Owner0080V15broad_case_0080ySis5Int32V_SbSdtKF",
              parameterTypes: ["Swift.Int32", "Swift.Bool", "Swift.Double"], resultType: "Swift.Int",
              parameterLocations: ["w0", "x1", "d0"], resultLocation: "x0",
              observations: [(0x74ec, "880240f9", "indirect value receiver addressed by x20"),
                             (0x74f0, "29004092", "Bool argument bit in x1"),
                             (0x74f4, "29c1208b", "Int32 argument in w0"),
                             (0x74f8, "0a00789e", "Double argument in d0"),
                             (0x7530, "f50300aa", "ordinary error assigned to x21"),
                             (0x7540, "804e0191", "Int success result in x0"),
                             (0x757c, "150080d2c9ffff97b50000b4", "caller clears x21, direct calls, tests x21")],
              sourceCapture: "broad-swift-initial-v1/BroadOwned.swift:1127-1135",
              disassemblyCapture: "broad-swift-initial-v1/objdump-O.txt:7235-7295",
              callableKind: "struct_instance_method", context: [("BroadOwner0080", "struct")], receiverLocation: "indirect x20"),
        .init(evidenceID: "owned-initial-v1-O-enum0180",
              sliceSHA256: "ebdc1bbab109b9721a1024aa29210bf9ddd33589f833a7204faecc8e81d32857",
              sourceSHA256: initialSource, compiler: compilerIdentity, target: "arm64-apple-macosx14.0", optimization: "-O",
              symbol: "$s10BroadOwned0A9Owner0180O15broad_case_0180ySis5Int32V_SbSdtKF",
              parameterTypes: ["Swift.Int32", "Swift.Bool", "Swift.Double"], resultType: "Swift.Int",
              parameterLocations: ["w0", "x1", "d0"], resultLocation: "x0",
              observations: [(0x102f0, "880240f9", "indirect enum receiver addressed by x20"),
                             (0x102f4, "29004092", "Bool argument bit in x1"),
                             (0x102f8, "29c1208b", "Int32 argument in w0"),
                             (0x102fc, "0a00789e", "Double argument in d0"),
                             (0x10338, "f50300aa", "ordinary error assigned to x21"),
                             (0x10348, "00dd0291", "Int success result in x0"),
                             (0x10384, "150080d2c8ffff97b50000b4", "caller clears x21, direct calls, tests x21")],
              sourceCapture: "broad-swift-initial-v1/BroadOwned.swift:2727-2736",
              disassemblyCapture: "broad-swift-initial-v1/objdump-O.txt:16924-16998",
              callableKind: "enum_instance_method", context: [("BroadOwner0180", "enum")], receiverLocation: "indirect x20"),
        .init(evidenceID: "owned-initial-v1-O-class0249",
              sliceSHA256: "ebdc1bbab109b9721a1024aa29210bf9ddd33589f833a7204faecc8e81d32857",
              sourceSHA256: initialSource, compiler: compilerIdentity, target: "arm64-apple-macosx14.0", optimization: "-O",
              symbol: "$s10BroadOwned0A9Owner0249C15broad_case_0249ySis5Int32V_S2itKF",
              parameterTypes: ["Swift.Int32", "Swift.Int", "Swift.Int"], resultType: "Swift.Int",
              parameterLocations: ["w0", "x1", "x2"], resultLocation: "x0",
              observations: [(0x16fb8, "28c0208b", "Int32 w0 and Int x1 arguments"),
                             (0x16fbc, "890a40f9", "class reference receiver in x20"),
                             (0x16fc0, "0801028b", "Int argument in x2"),
                             (0x16fc8, "00f103f1", "Int success result in x0"),
                             (0x16ff8, "f50300aa", "ordinary error assigned to x21"),
                             (0x17058, "150080d2d4ffff97b50000b4", "caller clears x21, direct calls, tests x21")],
              sourceCapture: "broad-swift-initial-v1/BroadOwned.swift:3886-3894",
              disassemblyCapture: "broad-swift-initial-v1/objdump-O.txt:24353-24411",
              callableKind: "class_instance_method", context: [("BroadOwner0249", "class")], receiverLocation: "reference x20")])
}
