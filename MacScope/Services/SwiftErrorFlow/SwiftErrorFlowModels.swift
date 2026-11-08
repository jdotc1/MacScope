// Native-v1 structural Swift error-flow evidence. Independent of DWARF/LSDA.
// Inputs are producer-verified facts, not an admission parser or authentication.

public struct SwiftErrorFlowSliceIdentity: Codable, Equatable, Sendable {
    public var artifactSHA256: String
    public var sliceOffset: UInt64
    public var sliceByteCount: UInt64
    public var cpuType: UInt32
    public var cpuSubtype: UInt32
    public var littleEndian: Bool
    public init(artifactSHA256: String, sliceOffset: UInt64, sliceByteCount: UInt64, cpuType: UInt32, cpuSubtype: UInt32, littleEndian: Bool) {
        self.artifactSHA256 = artifactSHA256; self.sliceOffset = sliceOffset; self.sliceByteCount = sliceByteCount
        self.cpuType = cpuType; self.cpuSubtype = cpuSubtype; self.littleEndian = littleEndian
    }
}

public struct SwiftErrorFlowCode: Codable, Equatable, Sendable {
    public var baseAddress: UInt64
    public var sliceRelativeFileOffset: UInt64
    public var sectionOrdinal: UInt8
    public var hasEmbeddedData: Bool
    public var hasRelocations: Bool
    public var words: [UInt32]
    public init(baseAddress: UInt64, sliceRelativeFileOffset: UInt64, sectionOrdinal: UInt8, hasEmbeddedData: Bool, hasRelocations: Bool, words: [UInt32]) {
        self.baseAddress = baseAddress; self.sliceRelativeFileOffset = sliceRelativeFileOffset; self.sectionOrdinal = sectionOrdinal
        self.hasEmbeddedData = hasEmbeddedData; self.hasRelocations = hasRelocations; self.words = words
    }
}

public struct SwiftErrorFlowFunction: Codable, Equatable, Sendable {
    public var start: UInt64
    public var endExclusive: UInt64
    /// Only the exact admitted LC_FUNCTION_STARTS source is accepted in native-v1.
    public var boundarySource: String
    public init(start: UInt64, endExclusive: UInt64, boundarySource: String) {
        self.start = start; self.endExclusive = endExclusive; self.boundarySource = boundarySource
    }
}

public struct SwiftErrorFlowSymbol: Codable, Equatable, Sendable {
    public var address: UInt64
    public var name: String
    public var nType: UInt8
    public var nDesc: UInt16
    public var sectionOrdinal: UInt8
    public init(address: UInt64, name: String, nType: UInt8, nDesc: UInt16, sectionOrdinal: UInt8) {
        self.address = address; self.name = name; self.nType = nType; self.nDesc = nDesc; self.sectionOrdinal = sectionOrdinal
    }
}

public struct SwiftErrorFlowRequest: Codable, Equatable, Sendable {
    public var slice: SwiftErrorFlowSliceIdentity
    public var code: SwiftErrorFlowCode
    public var functions: [SwiftErrorFlowFunction]
    /// All defined section-symbol aliases at supplied entries, not display winners.
    public var symbols: [SwiftErrorFlowSymbol]
    public init(slice: SwiftErrorFlowSliceIdentity, code: SwiftErrorFlowCode, functions: [SwiftErrorFlowFunction], symbols: [SwiftErrorFlowSymbol]) {
        self.slice = slice; self.code = code; self.functions = functions; self.symbols = symbols
    }
}

public enum SwiftErrorFlowModel: String, Sendable {
    case nativeV1 = "macscope-swift-error-flow-native-v1"
    case registerCopiesV2 = "macscope-swift-error-flow-native-v2-register-copies"
}

public enum SwiftErrorFlowStatus: String, Codable, Sendable { case analyzed, rejected }
public struct SwiftErrorFlowDeclaration: Codable, Equatable, Sendable {
    public let address: UInt64
    public let symbol: String
    public let module: String
    public let name: String
    public let parameters: [String]
    public let result: String
}
public struct SwiftErrorFlowEdge: Codable, Equatable, Sendable {
    public let callerStart: UInt64
    public let callAddress: UInt64
    public let calleeAddress: UInt64
    public let symbol: String
    public let testAddress: UInt64
    public let comparisonAddress: UInt64?
    public let successAddress: UInt64
    public let errorAddress: UInt64
    /// All four offsets below are relative to callerStart (never slice/file offsets).
    /// Navigation must validate the matching live VA mapping independently.
    public let callOffset: UInt64
    public let testOffset: UInt64
    public let successOffset: UInt64
    public let errorOffset: UInt64
    public let testKind: String
    /// Sequential raw words from BL through the accepted test, inclusive.
    public let evidenceWords: [UInt32]
    /// Present only for the opt-in register-copy model. Register 31 is never an alias.
    public let testedRegister: UInt8?

    init(callerStart: UInt64, callAddress: UInt64, calleeAddress: UInt64, symbol: String,
         testAddress: UInt64, comparisonAddress: UInt64?, successAddress: UInt64, errorAddress: UInt64,
         callOffset: UInt64, testOffset: UInt64, successOffset: UInt64, errorOffset: UInt64,
         testKind: String, evidenceWords: [UInt32], testedRegister: UInt8? = nil) {
        self.callerStart = callerStart; self.callAddress = callAddress; self.calleeAddress = calleeAddress
        self.symbol = symbol; self.testAddress = testAddress; self.comparisonAddress = comparisonAddress
        self.successAddress = successAddress; self.errorAddress = errorAddress
        self.callOffset = callOffset; self.testOffset = testOffset
        self.successOffset = successOffset; self.errorOffset = errorOffset
        self.testKind = testKind; self.evidenceWords = evidenceWords; self.testedRegister = testedRegister
    }
}
public struct SwiftErrorFlowAbstention: Codable, Equatable, Sendable {
    public let code: String
    public let address: UInt64?
}
public struct SwiftErrorFlowReport: Encodable, Equatable, Sendable {
    public let model: String
    public let sourceReconstructionAllowed = false
    public let runtimeReachabilityProven = false
    public let status: SwiftErrorFlowStatus
    public let slice: SwiftErrorFlowSliceIdentity
    public let declarations: [SwiftErrorFlowDeclaration]
    public let edges: [SwiftErrorFlowEdge]
    public let abstentions: [SwiftErrorFlowAbstention]

    init(model: SwiftErrorFlowModel = .nativeV1, status: SwiftErrorFlowStatus,
         slice: SwiftErrorFlowSliceIdentity, declarations: [SwiftErrorFlowDeclaration],
         edges: [SwiftErrorFlowEdge], abstentions: [SwiftErrorFlowAbstention]) {
        self.model = model.rawValue; self.status = status; self.slice = slice
        self.declarations = declarations; self.edges = edges; self.abstentions = abstentions
    }
}
