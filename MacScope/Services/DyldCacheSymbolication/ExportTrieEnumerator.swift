import Foundation

/// Every name an image exports at a code address, sorted by (address, name bytes).
struct ExportedNames: Sendable {
    var addresses: [UInt64] = []
    var names: [[UInt8]] = []

    var retainedBytes: Int { addresses.count * 8 + names.reduce(0) { $0 + $1.count + 32 } }

    /// Names at exactly `address`, sorted bytewise, without duplicates.
    func names(at address: UInt64) -> [[UInt8]] {
        var low = lowerBound(address)
        var result: [[UInt8]] = []
        while low < addresses.count, addresses[low] == address {
            if result.last != names[low] { result.append(names[low]) }
            low += 1
        }
        return result
    }

    /// The first export address strictly inside (start, end), if any.
    func firstAddress(after start: UInt64, before end: UInt64) -> UInt64? {
        var index = upperBound(start)
        while index < addresses.count, addresses[index] < end {
            if addresses[index] > start { return addresses[index] }
            index += 1
        }
        return nil
    }

    private func lowerBound(_ value: UInt64) -> Int {
        var low = 0, high = addresses.count
        while low < high {
            let mid = (low + high) / 2
            if addresses[mid] < value { low = mid + 1 } else { high = mid }
        }
        return low
    }

    private func upperBound(_ value: UInt64) -> Int {
        var low = 0, high = addresses.count
        while low < high {
            let mid = (low + high) / 2
            if addresses[mid] <= value { low = mid + 1 } else { high = mid }
        }
        return low
    }
}

/// The result of enumerating one image's export tries. Incompleteness and malformation are
/// carried as values so a memoized failure is never mistaken for an empty export list.
enum ExportEnumeration: Sendable {
    case entries(ExportedNames)
    case incomplete(SymbolicationBound)
    case malformed(String)
}

/// Bounded enumeration of every code export in a trie: iterative DFS with an explicit stack, each
/// node visited at most once (a revisit is malformed), every ULEB and offset range-checked.
/// Unlike `DyldSharedCacheParser.exportNames`, a bound that is hit is a typed `incomplete`.
enum ExportTrieEnumerator {
    struct Cancelled: Error {}

    static func enumerate(
        tries: [Data], loadAddress: UInt64, limits: DyldCacheSymbolicationLimits, isCancelled: () -> Bool
    ) throws -> ExportEnumeration {
        var entries: [(address: UInt64, name: [UInt8])] = []
        var nodes = 0
        var trieBytes = 0
        var retained = 0
        for trie in tries {
            guard trie.count <= limits.maximumTrieBytes - trieBytes else { return .incomplete(.trieBytes) }
            trieBytes += trie.count
            let reader = LittleEndianReader(trie)
            let size = trie.count
            var visited = Set<Int>()
            var name: [UInt8] = []
            var stack: [(node: Int, labelStart: Int, labelLength: Int, prefix: Int)] = [(0, 0, 0, 0)]
            while let item = stack.popLast() {
                nodes += 1
                guard nodes <= limits.maximumTrieNodes else { return .incomplete(.trieNodes) }
                if nodes % limits.cancellationCheckInterval == 0, isCancelled() { throw Cancelled() }
                if name.count > item.prefix { name.removeSubrange(item.prefix...) }
                if item.labelLength > 0 {
                    guard name.count + item.labelLength <= limits.maximumExportNameBytes else {
                        return .malformed("export name longer than \(limits.maximumExportNameBytes) bytes")
                    }
                    for index in 0..<item.labelLength {
                        guard let byte = reader.byte(item.labelStart + index) else { return .malformed("edge label outside the trie") }
                        name.append(byte)
                    }
                }
                guard item.node >= 0, item.node < size else { return .malformed("node offset outside the trie") }
                guard visited.insert(item.node).inserted else { return .malformed("trie node reached twice") }
                var cursor = item.node
                guard let terminalSize = uleb(reader, &cursor, limit: size) else { return .malformed("terminal size ULEB is truncated") }
                guard terminalSize <= UInt64(size - cursor) else { return .malformed("terminal extends past the trie") }
                let terminalEnd = cursor + Int(terminalSize)
                if terminalSize > 0 {
                    switch decode(reader, start: cursor, end: terminalEnd) {
                    case .failure(let detail): return .malformed(detail)
                    case .skip: break
                    case .code(let offset):
                        guard !name.isEmpty else { return .malformed("terminal at the trie root has no name") }
                        let (address, overflow) = loadAddress.addingReportingOverflow(offset)
                        guard !overflow else { return .malformed("export address overflows") }
                        guard entries.count < limits.maximumExportEntries else { return .incomplete(.exportEntries) }
                        guard name.count <= limits.maximumRetainedNameBytes - retained else { return .incomplete(.retainedNameBytes) }
                        retained += name.count
                        entries.append((address, name))
                    }
                }
                cursor = terminalEnd
                guard cursor < size, let childCount = reader.byte(cursor) else { return .malformed("child count outside the trie") }
                cursor += 1
                for _ in 0..<Int(childCount) {
                    let labelStart = cursor
                    while cursor < size, reader.byte(cursor) != 0 { cursor += 1 }
                    guard cursor < size else { return .malformed("edge label is unterminated") }
                    let labelLength = cursor - labelStart
                    cursor += 1
                    guard labelLength > 0 else { return .malformed("edge label is empty") }
                    guard let child = uleb(reader, &cursor, limit: size), child < UInt64(size) else {
                        return .malformed("child offset is truncated or outside the trie")
                    }
                    stack.append((Int(child), labelStart, labelLength, name.count))
                }
            }
        }
        entries.sort { $0.address != $1.address ? $0.address < $1.address : $0.name.lexicographicallyPrecedes($1.name) }
        return .entries(ExportedNames(addresses: entries.map(\.address), names: entries.map(\.name)))
    }

    private enum Terminal {
        case code(UInt64)
        /// Reexport, absolute and thread-local terminals carry no code address in this image.
        case skip
        case failure(String)
    }

    private static func decode(_ reader: LittleEndianReader, start: Int, end: Int) -> Terminal {
        var cursor = start
        guard let flags = uleb(reader, &cursor, limit: end) else { return .failure("terminal flags are truncated") }
        guard flags & ~0x1f == 0, flags & 0x3 != 3 else { return .failure("unsupported terminal flags") }
        if flags & 0x8 != 0 {
            return flags & 0x10 == 0 ? .skip : .failure("reexport combined with stub-and-resolver")
        }
        guard var value = uleb(reader, &cursor, limit: end) else { return .failure("terminal address is truncated") }
        if flags & 0x10 != 0 {
            // Wire order in the shared cache is resolver first, then stub; the exported name binds to the stub.
            guard let stub = uleb(reader, &cursor, limit: end) else { return .failure("stub offset is truncated") }
            value = stub
        }
        guard cursor == end else { return .failure("terminal payload does not end at the terminal end") }
        return flags & 0x3 == 0 ? .code(value) : .skip
    }

    private static func uleb(_ reader: LittleEndianReader, _ cursor: inout Int, limit: Int) -> UInt64? {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        while true {
            guard cursor < limit, let byte = reader.byte(cursor) else { return nil }
            cursor += 1
            let payload = UInt64(byte & 0x7f)
            if shift >= 64 || (shift == 63 && payload > 1) { return nil }
            result |= payload << shift
            if byte & 0x80 == 0 { return result }
            shift += 7
        }
    }
}
