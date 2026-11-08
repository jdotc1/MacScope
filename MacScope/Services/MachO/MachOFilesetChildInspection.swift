import Foundation

/// Container-relative declarations only. This is not a MachOFile or a verified child image.
struct MachOFilesetChildInspection: Codable, Sendable {
    enum CommandCoverage: String, Codable, Equatable, Sendable {
        case segmentAndSections
        case uuid
        case envelopeOnly
    }
    struct Command: Codable, Sendable {
        let ordinal: Int
        let parentFileOffset: UInt64
        let offsetFromChildHeader: UInt64
        let command: UInt32
        let byteCount: UInt32
        let coverage: CommandCoverage
    }
    struct Section: Codable, Sendable {
        let segmentCommandOffset: UInt64
        let recordParentFileOffset: UInt64
        let sectionName: String
        let segmentName: String
        let virtualAddress: UInt64
        let virtualSize: UInt64
        /// Retained even for zero-fill, where it is not a physical byte location.
        let rawFileOffset: UInt32
        /// Nil for VM-only zero-fill; no payload bytes are read by this inspector.
        let parentFileOffset: UInt64?
        let fileByteCount: UInt64?
        let isZeroFill: Bool
        let alignmentExponent: UInt32
        let flags: UInt32
        let sectionType: UInt32
        /// Uninterpreted relocation descriptors, not admitted relocation payloads.
        let relocationOffset: UInt32
        let relocationCount: UInt32
        let reserved1: UInt32
        let reserved2: UInt32
        let reserved3: UInt32
    }
    let identity: MachOFilesetIndex.Identity
    let header: MachOFilesetIndex.Header
    let childUUID: UUID?
    let headerAndCommandsByteCount: UInt64
    let segments: [MachOFilesetIndex.Segment]
    let commands: [Command]
    let sections: [Section]
    /// Retains the index's conservative whole-entry warning, not exclusive ownership.
    let sharesOrOverlapsAnotherEntry: Bool
    let semanticCoverage: String
}

enum MachOFilesetChildInspectionError: Error, Equatable {
    case selectorMismatch
    case limit(String)
    case malformed(String, parentOffset: UInt64)
}

struct MachOFilesetChildInspectionLimits: Sendable {
    var maximumInputBytes = 64 * 1_024 * 1_024
    var maximumCommands = 1_024
    var maximumCommandBytes = 1 * 1_024 * 1_024
    var maximumSections = 8_192
    var maximumNameBytes = 256 * 1_024
    var maximumSectionComparisons = 65_536
    var maximumOutputBytes = 2 * 1_024 * 1_024
    /// Independently bounds grounding over ALL entries, not just the selected child.
    var indexLimits = MachOFilesetIndexLimits()

    func validate() throws {
        let hard = Self()
        for (value, ceiling) in [
            (maximumInputBytes, hard.maximumInputBytes),
            (maximumCommands, hard.maximumCommands),
            (maximumCommandBytes, hard.maximumCommandBytes),
            (maximumSections, hard.maximumSections),
            (maximumNameBytes, hard.maximumNameBytes),
            (maximumSectionComparisons, hard.maximumSectionComparisons),
            (maximumOutputBytes, hard.maximumOutputBytes)
        ] {
            guard value > 0, value <= ceiling else {
                throw MachOFilesetChildInspectionError.limit("configuration")
            }
        }
        // The existing index parser validates its own stricter-only limits before work.
    }
}
