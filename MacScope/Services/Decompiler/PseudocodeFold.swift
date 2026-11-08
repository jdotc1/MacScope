import Foundation

/// E4: opt-in presentation folds. A fold is a pure projection of the rendered function; the
/// MacIR model, source spans and recovered facts are never changed. Fold off is byte-identical.
public enum PseudocodeFoldKind: String, Hashable, Sendable, CaseIterable {
    case arc
}

/// The ARC runtime family a resolved import belongs to.
public enum ARCFamily: String, Hashable, Sendable { case objc, swift }

public enum ARCRole: String, Hashable, Sendable {
    case retain, release, autorelease, retainAutoreleasedReturn
}

/// Callee identity proven from the import tables, never from rendered name text.
public struct ARCCalleeIdentity: Hashable, Sendable {
    public let family: ARCFamily
    public let role: ARCRole
    /// The import symbol with one leading underscore removed, e.g. `objc_retain`.
    public let importSymbol: String
    public let libraryName: String?
    /// `_n` variants carry a count in x1.
    public let isCountVariant: Bool
    /// The register index that holds the object (`objc_retain_xN` takes it in xN).
    public let objectRegisterIndex: Int

    public init(family: ARCFamily, role: ARCRole, importSymbol: String, libraryName: String?,
                isCountVariant: Bool, objectRegisterIndex: Int) {
        self.family = family
        self.role = role
        self.importSymbol = importSymbol
        self.libraryName = libraryName
        self.isCountVariant = isCountVariant
        self.objectRegisterIndex = objectRegisterIndex
    }
}

public struct PseudocodeFoldRequest: Hashable, Sendable {
    public var kinds: Set<PseudocodeFoldKind>
    /// Unsymbolized `bl` row address -> proven ARC callee identity.
    public var arcCallSites: [UInt64: ARCCalleeIdentity]

    public init(kinds: Set<PseudocodeFoldKind>, arcCallSites: [UInt64: ARCCalleeIdentity] = [:]) {
        self.kinds = kinds
        self.arcCallSites = arcCallSites
    }

    public var isEmpty: Bool { kinds.isEmpty }
}

public struct FoldedEvent: Hashable, Sendable {
    public var address: UInt64
    public var kind: PseudocodeFoldKind
    public var callee: String
    public var role: ARCRole
    /// For a used result: the value every read of the result was replaced with.
    public var replacedWith: String?
    /// The removed row's analysis comment, when it had one.
    public var comment: String?
    /// The surviving row that now carries that comment, nil when it stays only here.
    public var commentPlacedAt: UInt64?
    /// The surviving row that follows the removed one, used to place the event in a page.
    public var anchorAddress: UInt64?
    /// The rendered line number (1-based) of the first line sourced at `anchorAddress`.
    public var beforeLine: Int?

    public init(address: UInt64, kind: PseudocodeFoldKind, callee: String, role: ARCRole,
                replacedWith: String? = nil, comment: String? = nil, commentPlacedAt: UInt64? = nil,
                anchorAddress: UInt64? = nil, beforeLine: Int? = nil) {
        self.address = address
        self.kind = kind
        self.callee = callee
        self.role = role
        self.replacedWith = replacedWith
        self.comment = comment
        self.commentPlacedAt = commentPlacedAt
        self.anchorAddress = anchorAddress
        self.beforeLine = beforeLine
    }
}

public struct FoldRefusal: Hashable, Sendable {
    public var address: UInt64?
    public var callee: String?
    public var reason: String

    public init(address: UInt64?, callee: String?, reason: String) {
        self.address = address
        self.callee = callee
        self.reason = reason
    }
}

public struct PseudocodeFoldReport: Hashable, Sendable {
    public var events: [FoldedEvent] = []
    public var refused: [FoldRefusal] = []
    /// Fold kind -> number of folded events.
    public var counts: [PseudocodeFoldKind: Int] = [:]

    public init(events: [FoldedEvent] = [], refused: [FoldRefusal] = []) {
        self.events = events
        self.refused = refused
        var counts: [PseudocodeFoldKind: Int] = [:]
        for event in events { counts[event.kind, default: 0] += 1 }
        self.counts = counts
    }
}

/// Collects the report of the first projection call only. The lexical-twin pass runs the same
/// transform again, and a second report would double-count the same rows.
final class PseudocodeFoldRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var report: PseudocodeFoldReport?

    func record(_ candidate: PseudocodeFoldReport) {
        lock.lock(); defer { lock.unlock() }
        if report == nil { report = candidate }
    }

    var recorded: PseudocodeFoldReport? {
        lock.lock(); defer { lock.unlock() }
        return report
    }
}
