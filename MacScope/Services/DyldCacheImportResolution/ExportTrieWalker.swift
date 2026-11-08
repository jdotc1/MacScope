import Foundation

/// One export-trie terminal, decoded but not interpreted. Flag constants (mach-o/loader.h):
/// kind bits 0x3 (0 regular, 1 thread-local, 2 absolute), weak-definition 0x4, reexport 0x8,
/// stub-and-resolver 0x10.
struct ExportTerminal: Equatable, Sendable {
    enum Kind: Equatable, Sendable {
        case regular, threadLocal, absolute
    }
    enum Payload: Equatable, Sendable {
        case address(UInt64)
        /// `importedName` is empty when the reexport keeps the same spelling.
        case reexport(ordinal: UInt64, importedName: [UInt8])
        /// Wire order in the shared cache is resolver first, then stub (proven against the dyld_info
        /// oracle for libsystem_platform `__platform_strcmp`: resolver 0x94B8, stub 0x9A0).
        case stubAndResolver(stubOffset: UInt64, resolverOffset: UInt64)
    }
    var flags: UInt64
    var kind: Kind
    var isWeakDefinition: Bool
    var payload: Payload
}

enum ExportTrieWalkResult: Equatable, Sendable {
    case terminal(ExportTerminal)
    /// The exact symbol bytes are provably not in this trie: a well-formed walk ended without a match.
    case noEdge
    /// The trie is not well formed along the path that was walked. Never reported as absence.
    case malformed(String)
    /// Flags the walker does not understand (unknown kind bits, reserved bits).
    case unsupportedFlags(UInt64)
}

/// Iterative, exact-key export trie walker. Visits at most `symbol.count + 1` nodes, range-checks
/// every ULEB and edge read against the trie, and consumes no input it was not asked to match.
enum ExportTrieWalker {
    static func walk(
        trie: Data,
        symbol: [UInt8],
        workUnits: inout UInt64
    ) -> ExportTrieWalkResult {
        let reader = LittleEndianReader(trie)
        let size = trie.count
        guard size > 0 else { return .malformed("empty export trie") }
        var nodeOffset = 0
        var matched = 0
        var nodes = 0
        while true {
            nodes += 1
            workUnits &+= 1
            guard nodes <= symbol.count + 1 else { return .malformed("export trie visits more nodes than the symbol has bytes") }
            guard nodeOffset >= 0, nodeOffset < size else { return .malformed("export trie node offset outside the trie") }
            var cursor = nodeOffset
            guard let terminalSize = uleb(reader, &cursor, limit: size) else { return .malformed("terminal size ULEB is truncated") }
            guard terminalSize <= UInt64(size - cursor) else { return .malformed("terminal extends past the trie") }
            let terminalStart = cursor
            let terminalEnd = cursor + Int(terminalSize)
            if matched == symbol.count {
                guard terminalSize > 0 else { return .noEdge }
                return decodeTerminal(reader, start: terminalStart, end: terminalEnd, workUnits: &workUnits)
            }
            cursor = terminalEnd
            guard cursor < size, let childCount = reader.byte(cursor) else { return .malformed("child count is outside the trie") }
            cursor += 1
            var next: Int?
            var children = 0
            while children < Int(childCount) {
                children += 1
                // Edge label: NUL-terminated bytes, then the child node offset (ULEB).
                let labelStart = cursor
                while cursor < size, reader.byte(cursor) != 0 { cursor += 1 }
                guard cursor < size else { return .malformed("edge label is unterminated") }
                let labelLength = cursor - labelStart
                cursor += 1
                guard labelLength > 0 else { return .malformed("edge label is empty") }
                guard let childOffset = uleb(reader, &cursor, limit: size) else { return .malformed("child offset ULEB is truncated") }
                workUnits &+= UInt64(labelLength)
                if next == nil, labelLength <= symbol.count - matched {
                    var equal = true
                    for index in 0..<labelLength where reader.byte(labelStart + index) != symbol[matched + index] {
                        equal = false
                        break
                    }
                    if equal {
                        guard childOffset < UInt64(size) else { return .malformed("child offset outside the trie") }
                        next = Int(childOffset)
                        matched += labelLength
                    }
                }
                if next != nil { break }
            }
            guard let next else { return .noEdge }
            nodeOffset = next
        }
    }

    private static func decodeTerminal(
        _ reader: LittleEndianReader, start: Int, end: Int, workUnits: inout UInt64
    ) -> ExportTrieWalkResult {
        var cursor = start
        guard let flags = uleb(reader, &cursor, limit: end) else { return .malformed("terminal flags are truncated") }
        workUnits &+= UInt64(end - start)
        let kindBits = flags & 0x3
        guard kindBits <= 2 else { return .unsupportedFlags(flags) }
        let kind: ExportTerminal.Kind = kindBits == 0 ? .regular : kindBits == 1 ? .threadLocal : .absolute
        let isWeak = flags & 0x4 != 0
        let payload: ExportTerminal.Payload
        if flags & 0x8 != 0 {
            guard flags & 0x10 == 0 else { return .unsupportedFlags(flags) }
            guard let ordinal = uleb(reader, &cursor, limit: end) else { return .malformed("reexport ordinal is truncated") }
            var name: [UInt8] = []
            var terminated = false
            while cursor < end, let byte = reader.byte(cursor) {
                cursor += 1
                if byte == 0 { terminated = true; break }
                name.append(byte)
            }
            // dyld stores the imported-name C string inside the terminal; an absent string is an
            // empty (same-spelling) rename. A string that runs off the terminal is malformed.
            guard terminated || name.isEmpty else { return .malformed("reexport imported name is unterminated") }
            payload = .reexport(ordinal: ordinal, importedName: name)
        } else {
            guard let value = uleb(reader, &cursor, limit: end) else { return .malformed("terminal address is truncated") }
            if flags & 0x10 != 0 {
                // The first ULEB of a stub-and-resolver terminal is the resolver function; the second
                // is the exported stub. The stub is the address a caller binds to.
                guard let stub = uleb(reader, &cursor, limit: end) else { return .malformed("stub offset is truncated") }
                payload = .stubAndResolver(stubOffset: stub, resolverOffset: value)
            } else {
                payload = .address(value)
            }
        }
        return .terminal(ExportTerminal(flags: flags, kind: kind, isWeakDefinition: isWeak, payload: payload))
    }

    /// ULEB128 limited to 64 bits; nil when it runs past `limit` or overflows.
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
