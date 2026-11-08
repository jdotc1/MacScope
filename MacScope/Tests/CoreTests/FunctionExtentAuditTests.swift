import Foundation
import XCTest
@testable import MacScope

final class FunctionExtentAuditTests: XCTestCase {
    private let code = Data([
        0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
        0x40, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6
    ])

    private func analyze(_ fixture: ExtentAuditMachO) throws -> WorkspaceSnapshot {
        let url = try fixture.write()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        return try AnalysisEngine().analyze(url: url)
    }

    // Fails without symbol seeding: the external second symbol names no discovered boundary.
    func testExternalSectionSymbolSplitsFramelessFunctions() throws {
        let fixture = ExtentAuditMachO.make(code: code,
            symbols: [("_first", 0, 0x0f), ("_second", 8, 0x0f)])
        let snapshot = try analyze(fixture)
        XCTAssertEqual(snapshot.functions.map(\.startAddress), [fixture.baseAddress, fixture.baseAddress + 8])
        XCTAssertEqual(snapshot.functions.first?.endAddress, fixture.baseAddress + 8)
        XCTAssertEqual(snapshot.functions.first?.confidence, 0.7)
        XCTAssertEqual(snapshot.functions.last?.endAddress, fixture.baseAddress + 16)
        XCTAssertEqual(snapshot.functions.last?.name, "_second")
        XCTAssertEqual(snapshot.functions.last?.confidence, 0.66)
    }

    // Fails without symbol seeding: a local N_SECT start is also ignored.
    func testLocalSectionSymbolSplitsFramelessFunctions() throws {
        let fixture = ExtentAuditMachO.make(code: code,
            symbols: [("_first", 0, 0x0f), ("local_second", 8, 0x0e)])
        let snapshot = try analyze(fixture)
        XCTAssertEqual(snapshot.functions.map(\.startAddress), [fixture.baseAddress, fixture.baseAddress + 8])
        XCTAssertEqual(snapshot.functions.first?.endAddress, fixture.baseAddress + 8)
        XCTAssertEqual(snapshot.functions.last?.name, "local_second")
        XCTAssertEqual(snapshot.functions.last?.confidence, 0.66)
    }

    // Positive controls: all pass at the pin and after FIX.
    func testControlNoSymbolsKeepsOneFunction() throws {
        let fixture = ExtentAuditMachO.make(code: code)
        let snapshot = try analyze(fixture)
        XCTAssertEqual(snapshot.functions.map(\.startAddress), [fixture.baseAddress])
        XCTAssertEqual(snapshot.functions.first?.endAddress, fixture.baseAddress + 16)
    }

    func testControlMisalignedSymbolDoesNotSplit() throws {
        let fixture = ExtentAuditMachO.make(code: code, symbols: [("_inside_instruction", 6, 0x0f)])
        let snapshot = try analyze(fixture)
        XCTAssertEqual(snapshot.functions.map(\.startAddress), [fixture.baseAddress])
        XCTAssertEqual(snapshot.functions.first?.endAddress, fixture.baseAddress + 16)
    }

    func testControlSectionEndSymbolDoesNotSplit() throws {
        let fixture = ExtentAuditMachO.make(code: code, symbols: [("_past_code", 16, 0x0f)])
        let snapshot = try analyze(fixture)
        XCTAssertEqual(snapshot.functions.map(\.startAddress), [fixture.baseAddress])
        XCTAssertEqual(snapshot.functions.first?.endAddress, fixture.baseAddress + 16)
    }

    func testControlTemporaryLabelsDoNotSplit() throws {
        for name in ["ltmp1", "Linternal"] {
            let fixture = ExtentAuditMachO.make(code: code, symbols: [(name, 8, 0x0e)])
            let snapshot = try analyze(fixture)
            XCTAssertEqual(snapshot.functions.map(\.startAddress), [fixture.baseAddress])
            XCTAssertEqual(snapshot.functions.first?.endAddress, fixture.baseAddress + 16)
        }
    }
}

private struct ExtentAuditMachO {
    let bytes: Data
    let baseAddress: UInt64

    /// `symbols` (name, code offset, n_type) adds an LC_SYMTAB of typed symbols
    /// after the code; with none, the bytes are exactly the original symbol-less fixture.
    static func make(code: Data, symbols: [(name: String, offset: Int, nType: UInt8)] = []) -> ExtentAuditMachO {
        let headerSize = 32
        let segmentCommandSize = 72 + 80
        let mainCommandSize = 24
        let symtabCommandSize = symbols.isEmpty ? 0 : 24
        let loadCommandsSize = segmentCommandSize + mainCommandSize + symtabCommandSize
        let codeOffset = headerSize + loadCommandsSize
        let imageBase: UInt64 = 0x1_0000_0000
        let codeAddress = imageBase + UInt64(codeOffset)
        let textFileSize = UInt64(codeOffset + code.count)

        var bytes = Data()
        // mach_header_64
        bytes.le32(0xfeedfacf)
        bytes.le32(UInt32(bitPattern: MachOConstants.cpuTypeARM64))
        bytes.le32(0)
        bytes.le32(MachOConstants.fileTypeExecute)
        bytes.le32(symbols.isEmpty ? 2 : 3) // ncmds
        bytes.le32(UInt32(loadCommandsSize))
        bytes.le32(0)
        bytes.le32(0)

        // LC_SEGMENT_64 __TEXT
        bytes.le32(MachOConstants.loadCommandSegment64)
        bytes.le32(UInt32(segmentCommandSize))
        bytes.cString("__TEXT", length: 16)
        bytes.le64(imageBase)
        bytes.le64(textFileSize)
        bytes.le64(0)
        bytes.le64(textFileSize)
        bytes.le32(5)                       // maxprot
        bytes.le32(5)                       // initprot
        bytes.le32(1)                       // nsects
        bytes.le32(0)                       // flags

        // section __text
        bytes.cString("__text", length: 16)
        bytes.cString("__TEXT", length: 16)
        bytes.le64(codeAddress)
        bytes.le64(UInt64(code.count))
        bytes.le32(UInt32(codeOffset))
        bytes.le32(2)                       // align
        bytes.le32(0)
        bytes.le32(0)
        bytes.le32(
            MachOConstants.sectionAttributePureInstructions
                | MachOConstants.sectionAttributeSomeInstructions
        )
        bytes.le32(0)
        bytes.le32(0)
        bytes.le32(0)

        // LC_MAIN
        bytes.le32(MachOConstants.loadCommandMain)
        bytes.le32(UInt32(mainCommandSize))
        bytes.le64(UInt64(codeOffset))
        bytes.le64(0)

        // LC_SYMTAB (optional): nlist_64 records then the string table, after the code.
        var stringTable = Data([0])
        var nameOffsets: [UInt32] = []
        for symbol in symbols {
            nameOffsets.append(UInt32(stringTable.count))
            stringTable.append(contentsOf: Array(symbol.name.utf8) + [0])
        }
        let symbolOffset = (codeOffset + code.count + 7) & ~7
        let stringOffset = symbolOffset + symbols.count * 16
        if !symbols.isEmpty {
            bytes.le32(MachOConstants.loadCommandSymtab)
            bytes.le32(UInt32(symtabCommandSize))
            bytes.le32(UInt32(symbolOffset))
            bytes.le32(UInt32(symbols.count))
            bytes.le32(UInt32(stringOffset))
            bytes.le32(UInt32(stringTable.count))
        }

        precondition(bytes.count == codeOffset)
        bytes.append(code)
        if !symbols.isEmpty {
            bytes.append(contentsOf: repeatElement(0, count: symbolOffset - bytes.count))
            for (index, symbol) in symbols.enumerated() {
                bytes.le32(nameOffsets[index])
                bytes.append(symbol.nType)
                bytes.append(1)             // n_sect: __text
                bytes.append(contentsOf: [0, 0]) // n_desc
                bytes.le64(codeAddress + UInt64(symbol.offset))
            }
            bytes.append(stringTable)
        }
        return ExtentAuditMachO(bytes: bytes, baseAddress: codeAddress)
    }

    func write() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
            .appendingPathComponent("ExtentAuditMachO")
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try bytes.write(to: url)
        return url
    }
}

private extension Data {
    mutating func le32(_ value: UInt32) {
        var v = value.littleEndian
        Swift.withUnsafeBytes(of: &v) { append(contentsOf: $0) }
    }

    mutating func le64(_ value: UInt64) {
        var v = value.littleEndian
        Swift.withUnsafeBytes(of: &v) { append(contentsOf: $0) }
    }

    mutating func cString(_ string: String, length: Int) {
        var field = Array(string.utf8.prefix(length))
        field.append(contentsOf: repeatElement(0, count: length - field.count))
        append(contentsOf: field)
    }
}
