import Foundation

/// VI3 slice E (DESIGN section 2.5; RULINGS Q5 (a)): the in-memory read witness log.
///
/// A bounded ring of the code-serving reads a session has answered. `record-callee-outcome examined`
/// needs an entry for the callee (same image slot, same function start) taken at the store's current
/// analysis generation. The log is never persisted: a new process, or a ring overflow, loses the
/// witness and the outcome is refused with `examinedWithoutWitness` until the callee is read again.
///
/// Only `instructions` (function-selected), `decompile`, `basic-blocks` and `function-facts` append.
/// A call list (`callees`, `callers`, `call-graph`, `xrefs`) is not code and never does.
struct CalleeReadWitnessLog: Equatable, Sendable {
    static let defaultCapacity = 4_096

    /// The commands that witness. A reply from any other command never appends.
    static let witnessingCommands: [String] = ["instructions", "decompile", "basic-blocks", "function-facts"]

    struct Entry: Equatable, Sendable {
        let imageSlot: Int
        let functionStart: UInt64
        let command: String
        let generation: UUID
        /// Per-log monotonic, starting at 1.
        let sequence: UInt64
    }

    let capacity: Int
    private var ring: [Entry] = []
    private var head = 0
    private var lastSequence: UInt64 = 0

    init(capacity: Int = CalleeReadWitnessLog.defaultCapacity) {
        self.capacity = max(1, capacity)
    }

    var count: Int { ring.count }

    /// Appends one entry for a successful read; the oldest entry is dropped when the ring is full.
    @discardableResult
    mutating func append(imageSlot: Int, functionStart: UInt64, command: String, generation: UUID) -> Entry {
        lastSequence += 1
        let entry = Entry(imageSlot: imageSlot, functionStart: functionStart, command: command,
                          generation: generation, sequence: lastSequence)
        if ring.count < capacity {
            ring.append(entry)
        } else {
            ring[head] = entry
            head = (head + 1) % capacity
        }
        return entry
    }

    /// The newest entry for this slot and function start whose generation equals `generation`.
    func latest(imageSlot: Int, functionStart: UInt64, generation: UUID) -> Entry? {
        var best: Entry?
        for entry in ring where entry.imageSlot == imageSlot && entry.functionStart == functionStart
            && entry.generation == generation {
            if best == nil || entry.sequence > best!.sequence { best = entry }
        }
        return best
    }
}
