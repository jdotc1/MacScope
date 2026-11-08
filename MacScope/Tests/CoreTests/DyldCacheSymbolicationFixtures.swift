import Foundation
@testable import MacScope

/// Crafted dyld shared cache bytes for the DC2-2 matrix. Same three-file shape as the DC1
/// fixture (main, a text sub-cache holding every image's mach header, a linkedit sub-cache
/// holding tries and function starts) but each image also declares segments and sections, and the
/// main header can carry an `imagesText` UUID array. Reuses `SynthTrie`, `SynthTerminal` and
/// `SynthUleb` from DyldCacheImportResolutionFixtures.
struct SymSection {
    var name: String
    var offset: UInt64
    var size: UInt64
    var flags: UInt32
}

struct SymSegment {
    var name: String
    var offset: UInt64
    var size: UInt64
    var protection: UInt32
    var sections: [SymSection] = []
}

enum SymStarts {
    /// Function starts as image offsets (ULEB deltas from the image base, zero terminator, padding).
    case offsets([UInt64])
    case absent
    case empty
    case raw([UInt8])
}

struct SymImage {
    var path: String
    var uuid: [UInt8]
    var segments: [SymSegment] = SymImage.defaultSegments
    var exports: [(String, SynthTerminal)] = []
    var rawExportTrie: [UInt8]?
    var starts: SymStarts = .absent
    /// imagesText UUID; nil means the same as `uuid`.
    var textInfoUUID: [UInt8]?
    var machMagic: UInt32 = 0xfeedfacf

    static let instructions: UInt32 = 0x8000_0400
    static let stubs: UInt32 = 0x8000_0408

    /// __TEXT (r--) plus __TEXT_EXEC (r-x) at image offset 0x1000 with a text section, a stub
    /// section and a second text section.
    static let defaultSegments: [SymSegment] = [
        SymSegment(name: "__TEXT", offset: 0, size: 0x400, protection: 1,
                   sections: [SymSection(name: "__cstring", offset: 0x200, size: 0x100, flags: 2)]),
        SymSegment(name: "__TEXT_EXEC", offset: 0x1000, size: 0x4000, protection: 5, sections: [
            SymSection(name: "__text", offset: 0x1000, size: 0x1800, flags: instructions),
            SymSection(name: "__auth_stubs", offset: 0x2800, size: 0x100, flags: stubs),
            SymSection(name: "__text_b", offset: 0x3000, size: 0x200, flags: instructions),
        ]),
    ]
}

struct SymCache {
    var images: [SymImage]
    var mainUUID = SymCacheWriter.mainUUID
    var includeTextInfo = false
    /// Written at header 0x190..0x1A0 (the declared local-symbol companion UUID); nil leaves zeros.
    var symbolFileUUID: [UInt8]? = nil
}

enum SymCacheWriter {
    static let base: UInt64 = 0x1_8000_0000
    static let textBase: UInt64 = 0x1_8010_0000
    static let linkeditBase: UInt64 = 0x1_8020_0000
    static let header = 0x240
    static let imageStride = 0x10000
    static let linkeditSegmentFileOffset: UInt64 = 0x4000
    static let mainUUID = [UInt8](repeating: 0xA1, count: 16)
    static let textUUID = [UInt8](repeating: 0xB2, count: 16)
    static let linkeditUUID = [UInt8](repeating: 0xC3, count: 16)

    static func loadAddress(ofImage index: Int) -> UInt64 { textBase + UInt64((index + 1) * imageStride) }

    private static func u32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8((v >> (8 * UInt32($0))) & 0xff) } }
    private static func u64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8((v >> (8 * UInt64($0))) & 0xff) } }

    static func write(_ cache: SymCache, into directory: URL) throws -> URL {
        let mainURL = directory.appendingPathComponent("dyld_shared_cache_arm64e")

        var linkedit = [UInt8](repeating: 0, count: header + 32)
        func place(_ bytes: [UInt8]) -> (offset: UInt64, size: Int) {
            while linkedit.count % 16 != 0 { linkedit.append(0) }
            let at = linkedit.count
            linkedit += bytes
            return (linkeditSegmentFileOffset + UInt64(at), bytes.count)
        }
        var tries: [(offset: UInt64, size: Int)?] = []
        var starts: [(offset: UInt64, size: Int)?] = []
        for image in cache.images {
            if let raw = image.rawExportTrie {
                tries.append(place(raw))
            } else if image.exports.isEmpty {
                tries.append(nil)
            } else {
                tries.append(place(SynthTrie.build(image.exports)))
            }
            switch image.starts {
            case .absent:
                starts.append(nil)
            case .empty:
                starts.append((linkeditSegmentFileOffset, 0))
            case .raw(let bytes):
                starts.append(place(bytes))
            case .offsets(let offsets):
                var payload: [UInt8] = []
                var previous: UInt64 = 0
                for offset in offsets {
                    payload += SynthUleb.encode(offset - previous)
                    previous = offset
                }
                payload.append(0)
                while payload.count % 8 != 0 { payload.append(0) }
                starts.append(place(payload))
            }
        }
        while linkedit.count % 16 != 0 { linkedit.append(0) }
        linkedit += [UInt8](repeating: 0, count: 64)

        var text = [UInt8](repeating: 0, count: (cache.images.count + 2) * imageStride)
        for (index, image) in cache.images.enumerated() {
            let blob = imageBlob(image, loadAddress: loadAddress(ofImage: index), trie: tries[index],
                                 starts: starts[index], linkeditSize: linkedit.count)
            precondition(blob.count <= imageStride)
            let at = (index + 1) * imageStride
            text.replaceSubrange(at..<at + blob.count, with: blob)
        }

        let subSuffixes = [".01", ".02"]
        let imagesAt = header + 32
        let entriesAt = imagesAt + cache.images.count * 32
        let textInfoAt = entriesAt + subSuffixes.count * 56
        let pathsAt = textInfoAt + cache.images.count * 32
        var pathBytes: [UInt8] = []
        var pathOffsets: [Int] = []
        for image in cache.images {
            pathOffsets.append(pathsAt + pathBytes.count)
            pathBytes += Array(image.path.utf8) + [0]
        }
        var main = [UInt8](repeating: 0, count: pathsAt) + pathBytes
        let mainSize = main.count

        func put32(_ buffer: inout [UInt8], _ at: Int, _ value: UInt32) {
            buffer.replaceSubrange(at..<at + 4, with: u32(value))
        }
        func put64(_ buffer: inout [UInt8], _ at: Int, _ value: UInt64) {
            buffer.replaceSubrange(at..<at + 8, with: u64(value))
        }
        func fillHeader(_ buffer: inout [UInt8], uuid: [UInt8], mappingAddress: UInt64, mappingSize: UInt64) {
            for (i, b) in Array("dyld_v1  arm64e".utf8).enumerated() { buffer[i] = b }
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
        fillHeader(&main, uuid: cache.mainUUID, mappingAddress: base, mappingSize: UInt64(mainSize))
        if let declared = cache.symbolFileUUID { main.replaceSubrange(0x190..<0x1A0, with: declared) }
        put32(&main, 0x1C0, UInt32(imagesAt))
        put32(&main, 0x1C4, UInt32(cache.images.count))
        put32(&main, 0x188, UInt32(entriesAt))
        put32(&main, 0x18C, UInt32(subSuffixes.count))
        for (index, image) in cache.images.enumerated() {
            let record = imagesAt + index * 32
            put64(&main, record, loadAddress(ofImage: index))
            put32(&main, record + 24, UInt32(pathOffsets[index]))
            if cache.includeTextInfo {
                let info = textInfoAt + index * 32
                main.replaceSubrange(info..<info + 16, with: image.textInfoUUID ?? image.uuid)
                put64(&main, info + 16, loadAddress(ofImage: index))
                put32(&main, info + 28, UInt32(pathOffsets[index]))
            }
        }
        if cache.includeTextInfo {
            put64(&main, 0x88, UInt64(textInfoAt))
            put64(&main, 0x90, UInt64(cache.images.count))
        }
        for (index, suffix) in subSuffixes.enumerated() {
            let entry = entriesAt + index * 56
            for (i, b) in (index == 0 ? textUUID : linkeditUUID).enumerated() { main[entry + i] = b }
            put64(&main, entry + 16, index == 0 ? textBase - base : linkeditBase - base)
            for (i, b) in Array(suffix.utf8).enumerated() { main[entry + 24 + i] = b }
        }
        fillHeader(&text, uuid: textUUID, mappingAddress: textBase, mappingSize: UInt64(text.count))
        fillHeader(&linkedit, uuid: linkeditUUID, mappingAddress: linkeditBase, mappingSize: UInt64(linkedit.count))

        try Data(main).write(to: mainURL)
        try Data(text).write(to: URL(fileURLWithPath: mainURL.path + ".01"))
        try Data(linkedit).write(to: URL(fileURLWithPath: mainURL.path + ".02"))
        return mainURL
    }

    private static func imageBlob(
        _ image: SymImage, loadAddress: UInt64, trie: (offset: UInt64, size: Int)?,
        starts: (offset: UInt64, size: Int)?, linkeditSize: Int
    ) -> [UInt8] {
        func fixed16(_ name: String) -> [UInt8] {
            var bytes = Array(name.utf8)
            while bytes.count < 16 { bytes.append(0) }
            return bytes
        }
        var commands: [[UInt8]] = []
        var body = Array(image.path.utf8) + [0]
        while (24 + body.count) % 8 != 0 { body.append(0) }
        commands.append(u32(0xd) + u32(UInt32(24 + body.count)) + u32(24) + u32(0) + u32(0) + u32(0) + body)
        commands.append(u32(0x1b) + u32(24) + image.uuid)
        for segment in image.segments {
            let size = 72 + 80 * segment.sections.count
            var command = u32(0x19) + u32(UInt32(size)) + fixed16(segment.name) + u64(loadAddress + segment.offset)
                + u64(segment.size) + u64(0) + u64(0) + u32(7) + u32(segment.protection)
                + u32(UInt32(segment.sections.count)) + u32(0)
            for section in segment.sections {
                command += fixed16(section.name) + fixed16(segment.name) + u64(loadAddress + section.offset) + u64(section.size)
                    + u32(0) + u32(0) + u32(0) + u32(0) + u32(section.flags) + u32(0) + u32(0) + u32(0)
            }
            commands.append(command)
        }
        commands.append(u32(0x19) + u32(72) + fixed16("__LINKEDIT") + u64(linkeditBase) + u64(UInt64(linkeditSize))
                        + u64(linkeditSegmentFileOffset) + u64(UInt64(linkeditSize)) + u32(1) + u32(1) + u32(0) + u32(0))
        if let trie {
            commands.append(u32(0x8000_0033) + u32(16) + u32(UInt32(trie.offset)) + u32(UInt32(trie.size)))
        }
        if let starts {
            commands.append(u32(0x26) + u32(16) + u32(UInt32(starts.offset)) + u32(UInt32(starts.size)))
        }
        let bodyBytes = commands.flatMap { $0 }
        return u32(image.machMagic) + u32(0x0100_000c) + u32(0) + u32(6) + u32(UInt32(commands.count))
            + u32(UInt32(bodyBytes.count)) + u32(0) + u32(0) + bodyBytes
    }
}
