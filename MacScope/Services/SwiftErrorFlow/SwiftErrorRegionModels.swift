// Structural intervals and caller-local direct-entry observations only.
// Produced in-process from the same request as the underlying native-v2 edges.

public enum SwiftErrorRegionStatus: String, Encodable, Sendable {
    case candidate = "structural_region_candidate"
    case declined
}

public enum SwiftErrorRegionDecline: String, Encodable, Sendable {
    case unsupportedLayout = "unsupported_error_region_layout"
    case wordBudgetExceeded = "error_region_budget"
    case outsideCallerScan = "error_region_outside_scanned_prefix"
    case postcallEntriesNotClear = "compare_flag_entries_not_clear"
    case unmodeledInstruction = "error_region_instruction_unmodeled"
    case unmodeledControlFlow = "error_region_control_flow_unmodeled"
    case invalidCallTarget = "error_region_call_target_invalid"
}

public struct SwiftErrorRegionWord: Encodable, Equatable, Sendable {
    public let address: UInt64
    public let word: UInt32
    public let kind: String
    public let targetAddress: UInt64?
    /// A BL target is retained without callee identity, behavior or return evidence.
    public let opaqueCall: Bool
}

public enum SwiftErrorEntryStatus: String, Encodable, Sendable {
    case unexpected = "unexpected_direct_entries"
    case unresolved
    case noUnexpected = "no_unexpected_direct_entries"
}

public enum SwiftErrorEntryScope: String, Encodable, Sendable {
    case region = "caller_local_direct_edges_into_error_interval"
    case postcallWindow = "caller_local_direct_edges_into_postcall_window"
}

public struct SwiftErrorEntryValidation: Encodable, Equatable, Sendable {
    public let scope: SwiftErrorEntryScope
    public let status: SwiftErrorEntryStatus
    public let protectedStartAddress: UInt64
    public let protectedEndExclusive: UInt64
    public let callerStart: UInt64
    public let callerWordCount: Int
    public let scannedWordCount: Int
    public let callerScanComplete: Bool
    /// Counts cover the inspected caller prefix, never an uninspected suffix.
    public let unexpectedEntryCount: Int
    public let unexpectedEntries: [SwiftErrorRegionWord]
    public let entryDetailsComplete: Bool
    public let unclassifiedWordCount: Int
    public let unclassifiedWords: [SwiftErrorRegionWord]
    public let unclassifiedDetailsComplete: Bool
    public let exclusiveEntryProven = false
    public let flagStateProven = false
}

public struct SwiftErrorRegionResult: Encodable, Equatable, Sendable {
    public let edge: SwiftErrorFlowEdge
    public let status: SwiftErrorRegionStatus
    public let reason: SwiftErrorRegionDecline?
    /// Only populated for an admitted structural interval; the join is excluded.
    public let startAddress: UInt64?
    public let endExclusive: UInt64?
    public let joinAddress: UInt64?
    /// A declined interval may retain its inspected prefix, including the refusal word.
    public let instructions: [SwiftErrorRegionWord]
    public let opaqueCallCount: Int
    public let postcallWindow: SwiftErrorEntryValidation
    /// No region-entry claim is made for declined intervals.
    public let incomingEntries: SwiftErrorEntryValidation?
    public let callReturnProven = false
    public let joinReachabilityProven = false
    public let sourceReconstructionAllowed = false
    public let runtimeReachabilityProven = false
}

public struct SwiftErrorRegionReport: Encodable, Equatable, Sendable {
    public let model = "macscope-swift-error-region-native-v1"
    public let entryModel = "macscope-swift-region-direct-entries-native-v1"
    /// Unchanged edge analysis, including rejected inputs and edge abstentions.
    public let edgeReport: SwiftErrorFlowReport
    public let recoveredEdgeCount: Int
    public let omittedRegionCount: Int
    public let regionDetailsComplete: Bool
    public let callerScanCount: Int
    public let scannedWordCount: Int
    public let regions: [SwiftErrorRegionResult]
    public let sourceReconstructionAllowed = false
    public let runtimeReachabilityProven = false
}
