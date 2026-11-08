// Adapted from the AIRS component evidence core at donor commit fa5a2f3128da9134969055cebea145e2ca144214.
// Original relative path: native/Sources/AIRSCore/ComponentMetadataReader.swift (strictUniversalSlices,
// thin-header, build-version and dylib-command parsing).
// License: MIT, Copyright (c) 2026 Jeffrey D. Cooney; the notice is in ThirdParty/AIRS/LICENSE.
// Adaptations: every signature-capture field, branch, method and helper type removed; immutable configuration and
// result with function-local parsing state; reads come from a caller-supplied positional source charged to the
// shared ledger; typed failures; byte-key architectures. Extension point for later per-slice work (comment only):
// the per-slice location boundary sits immediately after the load-command range validation in parseThin.

import Foundation

extension ComponentEvidence {
    /// One validated slice with its declared facts. Fields are kept exact; unknown labels are not interpreted.
    struct Slice: Sendable, Equatable {
        let index: Int
        let cpuType: UInt32
        let cpuSubtype: UInt32
        let headerMagic: UInt32
        let offset: UInt64
        let size: UInt64
        let isUniversal: Bool
        let architecture: ExactUTF8Key
        let minimumOS: String?
        let loadDeclarations: [ComponentLoadDeclaration]
    }

    /// Slices are empty whenever `failure` is set; consumed bytes are final either way.
    struct MetadataReadResult: Sendable, Equatable {
        let consumedBytes: Int
        let slices: [Slice]
        let failure: EvidenceError?
        var architectures: [ExactUTF8Key] { slices.map(\.architecture) }
        var minimums: [ArchitectureMinimum] {
            slices.compactMap { slice in slice.minimumOS.map { ArchitectureMinimum(architecture: slice.architecture, minimum: $0) } }
        }
    }

    struct ArchitectureMinimum: Sendable, Hashable {
        let architecture: ExactUTF8Key
        let minimum: String
    }

    /// Immutable configuration. All parsing state is local to one call.
    struct ComponentMetadataReader: Sendable {
        static let maximumSlices = 64
        static let maximumLoadCommands = 4096
        static let maximumCommandString = 4096
        let captureLoadCommands: Bool
        init(captureLoadCommands: Bool = false) { self.captureLoadCommands = captureLoadCommands }

        /// Reads through `source(offset, count)`, charging every attempt to `ledger` before the call.
        func read(size: UInt64, range: PathRange, ledger: inout ReadLedger,
                  source: (UInt64, Int) throws -> [UInt8]) -> MetadataReadResult {
            let start = ledger.used
            var slices: [Slice] = []
            var failure: EvidenceError?
            var working = ledger
            do {
                slices = try withoutActuallyEscaping(source) { escaping in
                    var parser = Parser(size: size, range: range, capture: captureLoadCommands, ledger: working, source: escaping)
                    defer { working = parser.ledger }
                    return try parser.parse()
                }
            } catch let error as EvidenceError {
                failure = error
            } catch is CancellationError {
                failure = .cancelled
            } catch {
                failure = .malformedMetadata(nil, range, .truncated)
            }
            ledger = working
            return MetadataReadResult(consumedBytes: ledger.used - start, slices: failure == nil ? slices : [], failure: failure)
        }

        // MARK: Function-local parser

        private struct Parser {
            let size: UInt64
            let range: PathRange
            let capture: Bool
            var ledger: ReadLedger
            let source: (UInt64, Int) throws -> [UInt8]
            var loadRecords = 0

            init(size: UInt64, range: PathRange, capture: Bool, ledger: ReadLedger, source: @escaping (UInt64, Int) throws -> [UInt8]) {
                self.size = size; self.range = range; self.capture = capture; self.ledger = ledger; self.source = source
            }

            func bad(_ reason: MetadataReason) -> EvidenceError { .malformedMetadata(nil, range, reason) }

            mutating func read(offset: UInt64, count: Int, end: UInt64) throws -> [UInt8] {
                if Task.isCancelled { throw EvidenceError.cancelled }
                guard count >= 0, offset <= end, UInt64(count) <= end - offset, offset <= UInt64(Int64.max) else {
                    throw bad(.truncated)
                }
                guard ledger.charge(count) else { throw EvidenceError.budgetExceeded(.headerBytes, range) }
                return try source(offset, count)
            }

            func number(_ bytes: [UInt8], _ start: Int, _ width: Int = 4, little: Bool) -> UInt64 {
                (0..<width).reduce(UInt64(0)) { $0 | UInt64(bytes[start + $1]) << UInt64((little ? $1 : width - 1 - $1) * 8) }
            }

            mutating func parse() throws -> [Slice] {
                guard size > 0 else { throw bad(.emptyImage) }
                let first = try read(offset: 0, count: min(8, Int(min(size, 8))), end: size)
                guard first.count >= 4 else { throw bad(.truncated) }
                let magic = number(first, 0, little: false)
                var layout: [(cpu: UInt32, subtype: UInt32, offset: UInt64, size: UInt64)] = []
                let universal = [0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca].contains(magic)
                if universal {
                    guard first.count == 8 else { throw bad(.truncated) }
                    let little = [0xbebafeca, 0xbfbafeca].contains(magic), wide = [0xcafebabf, 0xbfbafeca].contains(magic)
                    let count = Int(number(first, 4, little: little)), stride = wide ? 32 : 20
                    guard count > 0, count <= ComponentMetadataReader.maximumSlices else { throw bad(.badUniversalLayout) }
                    let table = try read(offset: 8, count: count * stride, end: size)
                    let tableEnd = UInt64(8 + count * stride)
                    var seen = Set<UInt64>()
                    for index in 0..<count {
                        let base = index * stride
                        let cpu = UInt32(number(table, base, little: little)), subtype = UInt32(number(table, base + 4, little: little))
                        let offset = number(table, base + 8, wide ? 8 : 4, little: little)
                        let length = number(table, base + (wide ? 16 : 12), wide ? 8 : 4, little: little)
                        let alignment = number(table, base + (wide ? 24 : 16), little: little)
                        guard offset >= tableEnd, offset <= size, length > 0, length <= size - offset,
                              alignment <= 15, offset & ((UInt64(1) << alignment) - 1) == 0 else { throw bad(.badUniversalLayout) }
                        guard seen.insert(UInt64(cpu) << 32 | UInt64(subtype & 0x00ffffff)).inserted else { throw bad(.duplicateArchitecture) }
                        if wide, number(table, base + 28, little: little) != 0 { throw bad(.nonzeroReserved) }
                        layout.append((cpu, subtype, offset, length))
                    }
                    let ordered = layout.sorted { $0.offset < $1.offset }
                    for (previous, next) in zip(ordered, ordered.dropFirst()) where next.offset < previous.offset + previous.size {
                        throw bad(.overlappingSlices)
                    }
                } else {
                    layout = [(0, 0, 0, size)]
                }
                var slices: [Slice] = []
                var seenArchitectures = Set<ExactUTF8Key>()
                for (index, entry) in layout.enumerated() {
                    let slice = try parseThin(index: index, cpu: entry.cpu, subtype: entry.subtype, offset: entry.offset,
                                              size: entry.size, universal: universal)
                    guard seenArchitectures.insert(slice.architecture).inserted else { throw bad(.duplicateArchitecture) }
                    slices.append(slice)
                }
                return slices
            }

            static func version(_ value: UInt64) -> String { "\((value >> 16) & 0xffff).\((value >> 8) & 0xff).\(value & 0xff)" }

            mutating func parseThin(index: Int, cpu tableCPU: UInt32, subtype tableSubtype: UInt32, offset: UInt64,
                                    size sliceSize: UInt64, universal: Bool) throws -> Slice {
                let end = offset + sliceSize
                let prefix = try read(offset: offset, count: 4, end: end)
                let magic = number(prefix, 0, little: false)
                guard [0xcffaedfe, 0xfeedfacf, 0xcefaedfe, 0xfeedface].contains(magic) else { throw bad(.unsupportedMagic) }
                let little = [0xcffaedfe, 0xcefaedfe].contains(magic), wide = [0xcffaedfe, 0xfeedfacf].contains(magic)
                let headerSize = wide ? 32 : 28
                let header = try read(offset: offset, count: headerSize, end: end)
                let cpu = UInt32(number(header, 4, little: little)), subtype = UInt32(number(header, 8, little: little))
                guard !universal || (cpu == tableCPU && subtype == tableSubtype) else { throw bad(.architectureDisagreement) }
                guard (cpu & 0x03000000 != 0) == wide else { throw bad(.abiWidthMismatch) }
                guard [2, 6, 8].contains(number(header, 12, little: little)) else { throw bad(.unsupportedFileType) }
                let count = Int(number(header, 16, little: little)), commandBytes = Int(clamping: number(header, 20, little: little))
                guard count <= ComponentMetadataReader.maximumLoadCommands, count <= commandBytes / 8,
                      UInt64(headerSize) + UInt64(commandBytes) <= sliceSize else { throw bad(.loadCommandBounds) }
                let commands = try read(offset: offset + UInt64(headerSize), count: commandBytes, end: end)
                let architecture = Self.label(cpu: cpu, subtype: subtype)
                var position = 0, minimum: String?, platformCommands = 0
                var loads: [ComponentLoadDeclaration] = []
                for _ in 0..<count {
                    guard position <= commands.count - 8 else { throw bad(.loadCommandBounds) }
                    let cmd = number(commands, position, little: little), length = Int(clamping: number(commands, position + 4, little: little))
                    guard length >= 8, length % (wide ? 8 : 4) == 0, length <= commands.count - position else { throw bad(.badCommandSize) }
                    if capture {
                        let dylibs: [UInt64: ComponentLoadDeclaration.Command] = [
                            0xc: .load, 0x80000018: .weak, 0x8000001f: .reexport, 0x80000023: .upward, 0x20: .lazy, 0xd: .installName]
                        if let name = dylibs[cmd] {
                            guard length >= 24 else { throw bad(.badDylibCommand) }
                            let stringOffset = Int(clamping: number(commands, position + 8, little: little))
                            let alternate = [UInt64(0xc), 0x80000018].contains(cmd) && number(commands, position + 12, little: little) == 0x1a741800
                            guard !alternate || (length >= 28 && stringOffset == 28) else { throw bad(.badDylibCommand) }
                            let path = try commandString(commands, position: position, length: length, offset: stringOffset, minimum: alternate ? 28 : 24)
                            loads.append(.init(architecture: architecture, command: name, path: path,
                                currentVersion: Self.version(number(commands, position + 16, little: little)),
                                compatibilityVersion: Self.version(number(commands, position + 20, little: little)),
                                useFlags: alternate ? UInt32(number(commands, position + 24, little: little)) : nil))
                        } else if cmd == 0x8000001c {
                            guard length >= 12 else { throw bad(.badDylibCommand) }
                            let path = try commandString(commands, position: position, length: length,
                                offset: Int(clamping: number(commands, position + 8, little: little)), minimum: 12)
                            loads.append(.init(architecture: architecture, command: .rpath, path: path))
                        }
                        guard loads.count <= ComponentMetadataReader.maximumLoadCommands - loadRecords else { throw bad(.loadRecordBudget) }
                    }
                    if [UInt64(0x32), 0x24, 0x25, 0x2f, 0x30].contains(cmd) {
                        platformCommands += 1
                        guard platformCommands == 1 else { throw bad(.ambiguousPlatform) }
                    }
                    var found: String?
                    if cmd == 0x32 {
                        guard length >= 24 else { throw bad(.badBuildVersion) }
                        let tools = number(commands, position + 20, little: little)
                        guard tools <= UInt64((length - 24) / 8) else { throw bad(.badBuildVersion) }
                        if number(commands, position + 8, little: little) == 1 { found = Self.version(number(commands, position + 12, little: little)) }
                    } else if cmd == 0x24 {
                        guard length >= 16 else { throw bad(.badBuildVersion) }
                        found = Self.version(number(commands, position + 8, little: little))
                    }
                    if [UInt64(0x25), 0x2f, 0x30].contains(cmd) { guard length >= 16 else { throw bad(.badBuildVersion) } }
                    if let found {
                        guard minimum == nil else { throw bad(.ambiguousPlatform) }
                        minimum = found
                    }
                    position += length
                }
                guard position == commands.count else { throw bad(.loadCommandBounds) }
                loadRecords += loads.count
                return Slice(index: index, cpuType: cpu, cpuSubtype: subtype, headerMagic: UInt32(magic), offset: offset,
                             size: sliceSize, isUniversal: universal, architecture: architecture, minimumOS: minimum, loadDeclarations: loads)
            }

            static func label(cpu: UInt32, subtype: UInt32) -> ExactUTF8Key {
                switch (cpu, subtype) {
                case (0x0100000c, 0): return ExactUTF8Key("arm64")
                case (0x0100000c, 2): return ExactUTF8Key("arm64e")
                case (0x01000007, 3): return ExactUTF8Key("x86_64")
                case (0x01000007, 8): return ExactUTF8Key("x86_64h")
                case (7, 3): return ExactUTF8Key("i386")
                default: return ExactUTF8Key("cpu0x" + String(cpu, radix: 16) + "/subtype0x" + String(subtype, radix: 16))
                }
            }

            func commandString(_ bytes: [UInt8], position: Int, length: Int, offset: Int, minimum: Int) throws -> ExactUTF8Key {
                guard offset >= minimum, offset < length,
                      let end = bytes[(position + offset)..<(position + length)].firstIndex(of: 0),
                      end - (position + offset) <= ComponentMetadataReader.maximumCommandString,
                      String(bytes: bytes[(position + offset)..<end], encoding: .utf8) != nil else { throw bad(.badCommandString) }
                return ExactUTF8Key(rawBytes: Array(bytes[(position + offset)..<end]))
            }
        }
    }
}
