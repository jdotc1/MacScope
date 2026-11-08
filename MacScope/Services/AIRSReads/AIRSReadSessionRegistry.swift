import Combine
import Foundation

/// One live workspace's retained AR0 read state. Epochs only ever move forward by replacement, so an
/// away-and-back focus change still retires old cursors. Callbacks only retire authority; fresh values
/// are captured at the next MainActor admission after the underlying assignment.
@MainActor
final class AIRSReadEntry {
    static let maximumReports = 4

    let id = UUID()
    weak var owner: AnyObject?
    let installationID: UUID
    private(set) var focusEpoch = UUID()
    private(set) var sourceEpoch = UUID()
    private(set) var reportStateEpoch = UUID()
    private(set) var reports: [AIRSReadReport] = []
    let swift = AIRSSwiftReadCoordinator()
    var subscriptions: [AnyCancellable] = []

    init(owner: AnyObject, installationID: UUID) {
        self.owner = owner
        self.installationID = installationID
    }

    var epochs: AIRSEpochs { .init(focus: focusEpoch, source: sourceEpoch, reportState: reportStateEpoch) }

    func noteFocusChange() {
        focusEpoch = UUID()
        reports.removeAll()
        pruneUse()
    }

    func noteSourceChange() {
        sourceEpoch = UUID()
        reports.removeAll()
        pruneUse()
        censuses.removeAll()
        swift.invalidate()
    }

    /// A report-state change retires every retained report bound to an older epoch, Swift reports included,
    /// so a first call can never serve a report whose cursors are already fenced out.
    func noteReportStateChange() {
        reportStateEpoch = UUID()
        let current = reportStateEpoch
        reports.removeAll { $0.command == AIRSMCPReads.unwindCommand || $0.reportStateEpoch != current }
        pruneUse()
    }

    func report(id: UUID) -> AIRSReadReport? { reports.first { $0.id == id } }

    func discard(id: UUID) { reports.removeAll { $0.id == id }; pruneUse() }

    /// Per retained report: recency, and whether the last page served from it still carries a cursor.
    private var useClock = 0
    private var use: [UUID: (tick: Int, liveCursor: Bool)] = [:]
    private func pruneUse() { use = use.filter { key, _ in reports.contains { $0.id == key } } }

    /// Record that a page was served from a retained report; `liveCursor` is whether it issued a nextCursor.
    func noteServed(id: UUID, liveCursor: Bool) {
        guard use[id] != nil else { return }
        useClock += 1
        use[id] = (useClock, liveCursor)
    }

    /// One metadata-only census per source generation and slot; never recomputed by a page.
    private var censuses: [String: AIRSCensus] = [:]
    private(set) var censusCaptureCount = 0
    private static func censusKey(_ generation: UUID, _ slot: Int) -> String { "\(generation.uuidString)/\(slot)" }
    func cachedCensus(generation: UUID, slot: Int) -> AIRSCensus? { censuses[Self.censusKey(generation, slot)] }
    func retainCensus(_ census: AIRSCensus, generation: UUID, slot: Int) {
        censusCaptureCount += 1
        if censuses.count >= Self.maximumReports { censuses.removeAll() }
        censuses[Self.censusKey(generation, slot)] = census
    }

    func report(command: String, modelID: String, filterToken: String, slot: Int) -> AIRSReadReport? {
        reports.first { $0.command == command && $0.modelID == modelID && $0.filterToken == filterToken && $0.imageSlot == slot }
    }

    /// Retain a report whose first page issued a cursor. At the cap the least recently used report with no
    /// outstanding cursor is evicted, else the least recently used report overall (an abandoned cursor must
    /// not lock out new reads). The evicted report's cursor then gets the ordinary staleCursor refusal.
    func retain(_ report: AIRSReadReport) {
        if reports.count >= Self.maximumReports {
            func tick(_ r: AIRSReadReport) -> Int { use[r.id]?.tick ?? 0 }
            let finished = reports.filter { use[$0.id]?.liveCursor != true }
            if let victim = (finished.isEmpty ? reports : finished).min(by: { tick($0) < tick($1) }) {
                discard(id: victim.id)
            }
        }
        reports.append(report)
        useClock += 1
        use[report.id] = (useClock, true)
    }
}

struct AIRSEpochs: Equatable, Sendable {
    var focus: UUID
    var source: UUID
    var reportState: UUID
}

/// Weak-owner registry of at most four live entries. An entry is bound to the document installation
/// that created it; a new installation replaces it.
@MainActor
final class AIRSReadSessionRegistry {
    static let maximumEntries = 4
    static let shared = AIRSReadSessionRegistry()

    private var entries: [ObjectIdentifier: AIRSReadEntry] = [:]

    var liveEntryCount: Int { prune(); return entries.count }

    private func prune() {
        for (key, entry) in entries where entry.owner == nil { entry.subscriptions.removeAll(); entries[key] = nil }
    }

    /// nil when four other live owners already hold entries (refused, never evicted).
    func entry(owner: AnyObject, installationID: UUID,
               subscribe: @MainActor (AIRSReadEntry) -> [AnyCancellable]) -> AIRSReadEntry? {
        prune()
        let key = ObjectIdentifier(owner)
        if let existing = entries[key] {
            if existing.installationID == installationID { return existing }
            existing.subscriptions.removeAll()
            // Retire the old installation's coordinator. The detached work cannot be cancelled; this only
            // suppresses its result so it is never published or served to the new entry.
            existing.swift.invalidate()
            entries[key] = nil
        }
        guard entries.count < Self.maximumEntries else { return nil }
        let entry = AIRSReadEntry(owner: owner, installationID: installationID)
        entry.subscriptions = subscribe(entry)
        entries[key] = entry
        return entry
    }
}
