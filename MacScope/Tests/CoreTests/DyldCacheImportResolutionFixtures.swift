import Foundation
@testable import MacScope

/// Crafted dyld shared cache bytes for the DC1 slice B matrix. Writes a main file (header,
/// mapping, image catalog, path strings), a text sub-cache holding every image's mach header and
/// load commands, and a linkedit sub-cache holding every export trie, so that trie lookups must
/// cross files the same way the real cache does. File-system based, in a temporary directory.
enum SynthTerminal {
    case regular(UInt64)
    case threadLocal(UInt64)
    case absolute(UInt64)
    case weak(UInt64)
    case reexport(ordinal: UInt64, name: String)
    /// Real shared-cache wire order: resolver ULEB first, then stub (dyld_info oracle, libsystem_platform).
    case stubWire(stub: UInt64, resolver: UInt64)
    case raw([UInt8])

    var bytes: [UInt8] {
        switch self {
        case .regular(let v): return SynthUleb.encode(0) + SynthUleb.encode(v)
        case .threadLocal(let v): return SynthUleb.encode(1) + SynthUleb.encode(v)
        case .absolute(let v): return SynthUleb.encode(2) + SynthUleb.encode(v)
        case .weak(let v): return SynthUleb.encode(4) + SynthUleb.encode(v)
        case .reexport(let ordinal, let name): return SynthUleb.encode(8) + SynthUleb.encode(ordinal) + Array(name.utf8) + [0]
        case .stubWire(let stub, let resolver): return SynthUleb.encode(0x10) + SynthUleb.encode(resolver) + SynthUleb.encode(stub)
        case .raw(let bytes): return bytes
        }
    }
}

enum SynthUleb {
    static func encode(_ value: UInt64) -> [UInt8] {
        var value = value
        var out: [UInt8] = []
        repeat {
            var byte = UInt8(value & 0x7f)
            value >>= 7
            if value != 0 { byte |= 0x80 }
            out.append(byte)
        } while value != 0
        return out
    }
}

/// Builds a real, prefix-sharing export trie from (name, terminal) pairs.
enum SynthTrie {
    private final class Node {
        var terminal: [UInt8]?
        var children: [(label: [UInt8], node: Node)] = []
        var offset = 0
    }

    static func build(_ exports: [(String, SynthTerminal)]) -> [UInt8] {
        let root = Node()
        for (name, terminal) in exports { insert(root, Array(name.utf8)[...], terminal.bytes) }
        var order: [Node] = []
        var stack = [root]
        while let node = stack.popLast() {
            order.append(node)
            stack.append(contentsOf: node.children.map(\.node).reversed())
        }
        var changed = true
        var passes = 0
        while changed, passes < 64 {
            changed = false
            passes += 1
            var offset = 0
            for node in order {
                if node.offset != offset { node.offset = offset; changed = true }
                offset += encoded(node).count
            }
        }
        return order.flatMap { encoded($0) }
    }

    private static func encoded(_ node: Node) -> [UInt8] {
        var out: [UInt8] = []
        if let terminal = node.terminal {
            out += SynthUleb.encode(UInt64(terminal.count)) + terminal
        } else {
            out.append(0)
        }
        out.append(UInt8(node.children.count))
        for child in node.children {
            out += child.label + [0] + SynthUleb.encode(UInt64(child.node.offset))
        }
        return out
    }

    private static func insert(_ node: Node, _ name: ArraySlice<UInt8>, _ terminal: [UInt8]) {
        if name.isEmpty {
            node.terminal = terminal
            return
        }
        for index in node.children.indices {
            let label = node.children[index].label
            var common = 0
            while common < label.count, common < name.count, label[common] == name[name.startIndex + common] { common += 1 }
            guard common > 0 else { continue }
            if common < label.count {
                let split = Node()
                split.children = [(Array(label[common...]), node.children[index].node)]
                node.children[index] = (Array(label[..<common]), split)
            }
            insert(node.children[index].node, name[(name.startIndex + common)...], terminal)
            return
        }
        let leaf = Node()
        node.children.append((Array(name), leaf))
        insert(leaf, [], terminal)
    }
}

struct SynthImage {
    enum DepKind { case load, weak, reexport, upward }
    var path: String
    /// Raw catalog and LC_ID_DYLIB bytes when the path is not valid UTF-8.
    var rawPath: [UInt8]?
    var uuidByte: UInt8 = 0
    var dependencies: [(String, DepKind)] = []
    /// Terminals for the LC_DYLD_EXPORTS_TRIE trie.
    var exports: [(String, SynthTerminal)] = []
    /// Terminals for an additional LC_DYLD_INFO_ONLY trie (nil: no such command).
    var infoExports: [(String, SynthTerminal)]?
    var rawExportsTrie: [UInt8]?
    var idNameOverride: String?
    var machMagic: UInt32 = 0xfeedfacf
    var extraNoopCommands = 0
    var pathBytes: [UInt8] { rawPath ?? Array(path.utf8) }
}

struct SynthCache {
    var architecture = "arm64e"
    var images: [SynthImage]
    var subCacheUUIDMismatch = false
    var omitLinkeditFile = false
    var overlappingMappings = false
    var duplicateCatalogPath = false
}

enum SynthCacheWriter {
    static let base: UInt64 = 0x1_8000_0000
    static let textBase: UInt64 = 0x1_8010_0000
    static let linkeditBase: UInt64 = 0x1_8020_0000
    static let header = 0x240
    static let imageStride = 0x1000
    /// The images' __LINKEDIT segment claims this file offset for VM `linkeditBase`.
    static let linkeditSegmentFileOffset: UInt64 = 0x4000
    static let mainUUID = [UInt8](repeating: 0xA1, count: 16)
    static let textUUID = [UInt8](repeating: 0xB2, count: 16)
    static let linkeditUUID = [UInt8](repeating: 0xC3, count: 16)

    static func loadAddress(ofImage index: Int) -> UInt64 { textBase + UInt64((index + 1) * imageStride) }

    static func write(_ cache: SynthCache, into directory: URL) throws -> URL {
        let name = "dyld_shared_cache_\(cache.architecture)"
        let mainURL = directory.appendingPathComponent(name)

        // Linkedit file: one trie per image (and per extra trie), 16-aligned; header at the front.
        var linkedit = [UInt8](repeating: 0, count: header + 32)
        var exportsSlot: [SynthTrieSlot?] = []
        var infoSlot: [SynthTrieSlot?] = []
        func place(_ bytes: [UInt8]) -> SynthTrieSlot {
            while linkedit.count % 16 != 0 { linkedit.append(0) }
            let at = linkedit.count
            linkedit += bytes
            return SynthTrieSlot(vm: linkeditBase + UInt64(at), size: bytes.count, segmentFileOffset: linkeditSegmentFileOffset + UInt64(at))
        }
        for image in cache.images {
            if let raw = image.rawExportsTrie {
                exportsSlot.append(place(raw))
            } else if image.exports.isEmpty && image.infoExports != nil {
                exportsSlot.append(nil)
            } else {
                exportsSlot.append(place(SynthTrie.build(image.exports)))
            }
            infoSlot.append(image.infoExports.map { place(SynthTrie.build($0)) })
        }
        while linkedit.count % 16 != 0 { linkedit.append(0) }
        linkedit += [UInt8](repeating: 0, count: 64)

        // Text file: header + mapping + each image's mach header and commands at a fixed stride.
        var text = [UInt8](repeating: 0, count: (cache.images.count + 2) * imageStride)
        for (index, image) in cache.images.enumerated() {
            let blob = imageBlob(image, exports: exportsSlot[index], info: infoSlot[index], linkeditSize: linkedit.count)
            precondition(blob.count <= imageStride)
            let at = (index + 1) * imageStride
            text.replaceSubrange(at..<at + blob.count, with: blob)
        }

        // Main file: header, mapping, image array, sub-cache entries, then path strings.
        let subSuffixes = [".01", ".02"]
        let imagesAt = header + 32
        let entriesAt = imagesAt + cache.images.count * 32
        let pathsAt = entriesAt + subSuffixes.count * 56
        var pathBytes: [UInt8] = []
        var pathOffsets: [Int] = []
        for (index, image) in cache.images.enumerated() {
            let path = (cache.duplicateCatalogPath && index == 1) ? cache.images[0].pathBytes : image.pathBytes
            pathOffsets.append(pathsAt + pathBytes.count)
            pathBytes += path + [0]
        }
        var main = [UInt8](repeating: 0, count: pathsAt) + pathBytes
        let mainSize = main.count

        func put32(_ buffer: inout [UInt8], _ at: Int, _ value: UInt32) {
            for i in 0..<4 { buffer[at + i] = UInt8((value >> (8 * UInt32(i))) & 0xff) }
        }
        func put64(_ buffer: inout [UInt8], _ at: Int, _ value: UInt64) {
            for i in 0..<8 { buffer[at + i] = UInt8((value >> (8 * UInt64(i))) & 0xff) }
        }
        func fillHeader(_ buffer: inout [UInt8], arch: String, uuid: [UInt8], mappingAddress: UInt64, mappingSize: UInt64) {
            let magic = Array("dyld_v1  \(arch)".utf8)
            for (i, b) in magic.enumerated() { buffer[i] = b }
            put32(&buffer, 16, UInt32(header))
            put32(&buffer, 20, 1)
            for (i, b) in uuid.enumerated() { buffer[0x58 + i] = b }
            put64(&buffer, 0xE0, base)
            put64(&buffer, header, mappingAddress)
            put64(&buffer, header + 8, mappingSize)
            put64(&buffer, header + 16, 0)
            put32(&buffer, header + 24, 5)
            put32(&buffer, header + 28, 5)
        }
        fillHeader(&main, arch: cache.architecture, uuid: mainUUID, mappingAddress: base, mappingSize: UInt64(mainSize))
        put32(&main, 0x1C0, UInt32(imagesAt))
        put32(&main, 0x1C4, UInt32(cache.images.count))
        put32(&main, 0x188, UInt32(entriesAt))
        put32(&main, 0x18C, UInt32(subSuffixes.count))
        for (index, _) in cache.images.enumerated() {
            let record = imagesAt + index * 32
            put64(&main, record, loadAddress(ofImage: index))
            put32(&main, record + 24, UInt32(pathOffsets[index]))
        }
        let subUUIDs = [textUUID, cache.subCacheUUIDMismatch ? [UInt8](repeating: 0xEE, count: 16) : linkeditUUID]
        for (index, suffix) in subSuffixes.enumerated() {
            let entry = entriesAt + index * 56
            for (i, b) in subUUIDs[index].enumerated() { main[entry + i] = b }
            put64(&main, entry + 16, index == 0 ? textBase - base : linkeditBase - base)
            for (i, b) in Array(suffix.utf8).enumerated() { main[entry + 24 + i] = b }
        }

        // The sub-cache headers carry the real UUIDs (the mismatch case only changes the entry).
        fillHeader(&text, arch: cache.architecture, uuid: textUUID, mappingAddress: textBase, mappingSize: UInt64(text.count))
        let linkeditMappingBase = cache.overlappingMappings ? textBase : linkeditBase
        fillHeader(&linkedit, arch: cache.architecture, uuid: linkeditUUID, mappingAddress: linkeditMappingBase,
                   mappingSize: UInt64(linkedit.count))

        try Data(main).write(to: mainURL)
        try Data(text).write(to: URL(fileURLWithPath: mainURL.path + ".01"))
        if !cache.omitLinkeditFile {
            try Data(linkedit).write(to: URL(fileURLWithPath: mainURL.path + ".02"))
        }
        return mainURL
    }

    private static func imageBlob(
        _ image: SynthImage, exports: SynthTrieSlot?, info: SynthTrieSlot?, linkeditSize: Int
    ) -> [UInt8] {
        var commands: [[UInt8]] = []
        func u32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8((v >> (8 * UInt32($0))) & 0xff) } }
        func u64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8((v >> (8 * UInt64($0))) & 0xff) } }
        func dylibCommand(_ cmd: UInt32, _ name: [UInt8]) -> [UInt8] {
            var body = name + [0]
            while (24 + body.count) % 8 != 0 { body.append(0) }
            return u32(cmd) + u32(UInt32(24 + body.count)) + u32(24) + u32(0) + u32(0) + u32(0) + body
        }
        commands.append(dylibCommand(0xd, image.idNameOverride.map { Array($0.utf8) } ?? image.pathBytes))
        commands.append(u32(0x1b) + u32(24) + [UInt8](repeating: image.uuidByte, count: 16))
        for (dep, kind) in image.dependencies {
            let cmd: UInt32 = kind == .load ? 0xc : kind == .weak ? 0x8000_0018 : kind == .reexport ? 0x8000_001f : 0x8000_0023
            commands.append(dylibCommand(cmd, Array(dep.utf8)))
        }
        // __LINKEDIT segment: fileoff is deliberately not the VM offset so the vmaddr/fileoff
        // translation (as in a real split cache) is exercised.
        var segName = Array("__LINKEDIT".utf8)
        while segName.count < 16 { segName.append(0) }
        commands.append(u32(0x19) + u32(72) + segName + u64(SynthCacheWriter.linkeditBase) + u64(UInt64(linkeditSize))
                        + u64(SynthCacheWriter.linkeditSegmentFileOffset) + u64(UInt64(linkeditSize)) + u32(1) + u32(1) + u32(0) + u32(0))
        if let exports {
            commands.append(u32(0x8000_0033) + u32(16) + u32(UInt32(exports.segmentFileOffset)) + u32(UInt32(exports.size)))
        }
        if let info {
            var cmd = u32(0x8000_0022) + u32(48)
            for _ in 0..<8 { cmd += u32(0) }
            cmd += u32(UInt32(info.segmentFileOffset)) + u32(UInt32(info.size))
            commands.append(cmd)
        }
        for _ in 0..<image.extraNoopCommands { commands.append(u32(0x2a) + u32(16) + u64(0)) }
        let body = commands.flatMap { $0 }
        return u32(image.machMagic) + u32(0x0100_000c) + u32(0) + u32(6) + u32(UInt32(commands.count))
            + u32(UInt32(body.count)) + u32(0) + u32(0) + body
    }
}

struct SynthTrieSlot { var vm: UInt64; var size: Int; var segmentFileOffset: UInt64 }
