import Foundation

/// Offline, pure scorer for one closed, owner-recorded AIRS agreement trace. It reads values only: there is no
/// process, network, retry or "run again" API here, and a missing fact is a result, never a repair request.
enum AIRSAgreementScorer {
    enum Kind: String, Sendable { case unwind, swiftErrorFlow }

    struct Key: Hashable, Sendable {
        var kind: Kind
        var function: UInt64
    }

    /// One engine's recorded answer for one key. `admitted == nil` means the record is missing or unknown.
    struct Side: Equatable, Sendable {
        var admitted: Bool?
        var fields: [String: String]
        var reason: String?
    }

    struct Record: Sendable {
        var key: Key
        var macscope: Side?
        var airs: Side?
    }

    struct Trace: Sendable {
        var sourceManifest: [UInt64]
        var selection: [UInt64]
        var freshRunReceipt: Bool
        var modelMappingSupplied: Bool
        var records: [Record]
    }

    enum Classification: String, Sendable {
        case agreement, disagreement, airsOnly, macscopeOnly, bothAbstain, notComparable
    }

    struct Disagreement: Equatable, Sendable {
        var key: Key
        var macscope: Side
        var airs: Side
        var differingFields: [String]
    }

    enum Status: Equatable, Sendable {
        case pass
        case fail
        case notComplete(String)
        case notComparable(String)
        case invalid(String)
    }

    struct Result: Sendable {
        var status: Status
        var classifications: [Key: Classification]
        var disagreements: [Disagreement]
        var jointlyAdmitted: Int
        var passed: Bool { status == .pass }

        func count(_ value: Classification) -> Int { classifications.values.filter { $0 == value }.count }
    }

    static let selectionSize = 20

    static func score(_ trace: Trace) -> Result {
        func empty(_ status: Status) -> Result { Result(status: status, classifications: [:], disagreements: [], jointlyAdmitted: 0) }
        let ordered = Array(Set(trace.sourceManifest)).sorted()
        guard ordered.count >= selectionSize else { return empty(.notComplete("fewerThan20SourceFunctions")) }
        guard trace.selection == Array(ordered.prefix(selectionSize)) else { return empty(.invalid("selectionNotPrecommitted")) }
        guard trace.freshRunReceipt else { return empty(.notComparable("missingFreshRunReceipt")) }
        guard trace.modelMappingSupplied else { return empty(.notComparable("modelCoverageMismatch")) }

        var classes: [Key: Classification] = [:]
        var disagreements: [Disagreement] = []
        var jointUnwind = 0, jointSwift = 0
        for record in trace.records where trace.selection.contains(record.key.function) {
            guard let ms = record.macscope, let airs = record.airs, let a = ms.admitted, let b = airs.admitted else {
                classes[record.key] = .notComparable
                continue
            }
            switch (a, b) {
            case (true, true):
                if record.key.kind == .unwind { jointUnwind += 1 } else if (ms.fields["edges"].flatMap { Int($0) } ?? 0) > 0 { jointSwift += 1 }
                let names = Set(ms.fields.keys).union(airs.fields.keys).sorted().filter { ms.fields[$0] != airs.fields[$0] }
                if names.isEmpty { classes[record.key] = .agreement } else {
                    classes[record.key] = .disagreement
                    disagreements.append(Disagreement(key: record.key, macscope: ms, airs: airs, differingFields: names))
                }
            case (false, true): classes[record.key] = .airsOnly
            case (true, false): classes[record.key] = .macscopeOnly
            case (false, false): classes[record.key] = .bothAbstain
            }
        }
        let joint = classes.values.filter { $0 == .agreement || $0 == .disagreement }.count
        var result = Result(status: .fail, classifications: classes, disagreements: disagreements, jointlyAdmitted: joint)
        if classes.values.contains(.notComparable) {
            result.status = .notComparable("unexplainedNotComparableRecord")
        } else if jointUnwind < 1 || jointSwift < 1 {
            result.status = .notComplete("jointAdmissionFloor")
        } else if disagreements.isEmpty {
            result.status = .pass
        }
        return result
    }
}
