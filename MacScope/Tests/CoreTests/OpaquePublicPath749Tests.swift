import Foundation
import XCTest
@testable import MacScope

final class OpaquePublicPath749Tests: XCTestCase {
    private func check(_ id: String, descriptor: UInt64, typeref: UInt64,
                       parentWord: UInt32, underlyingWord: UInt32,
                       rebases: [UInt64: UInt64], accepted: Bool,
                       file: StaticString = #filePath, line: UInt = #line) {
        // Literal file layout, not a pointer resolver or arithmetic oracle.
        var bytes = [UInt8](repeating: 0, count: 32)
        func putWord(_ word: UInt32, at offset: Int) {
            bytes[offset] = UInt8(truncatingIfNeeded: word)
            bytes[offset + 1] = UInt8(truncatingIfNeeded: word >> 8)
            bytes[offset + 2] = UInt8(truncatingIfNeeded: word >> 16)
            bytes[offset + 3] = UInt8(truncatingIfNeeded: word >> 24)
        }
        putWord(0x00010004, at: 0)
        putWord(parentWord, at: 4)
        putWord(underlyingWord, at: 8)
        // module flags and parent at 12...19 stay zero; name field at 20.
        putWord(4, at: 20)
        bytes[24] = 0x4d // M, followed by NUL at 25
        bytes[26] = 0x53; bytes[27] = 0x69 // Si, NUL at 28
        let sections: [SwiftMetadataParser.Section] = [
            .init(name: "__const", address: descriptor, fileOffset: 0, size: 12,
                  isExecutable: false, isZeroFill: false, segmentName: "__TEXT"),
            .init(name: "module748", address: 0x100, fileOffset: 12, size: 14,
                  isExecutable: false, isZeroFill: false, segmentName: "__DATA"),
            .init(name: "__swift5_typeref", address: typeref, fileOffset: 26, size: 3,
                  isExecutable: false, isZeroFill: false, segmentName: "__TEXT")
        ]
        let parser = SwiftMetadataParser(data: Data(bytes), sections: sections, rebaseTargets: rebases)
        let report = parser.parseOpaqueTypeDescriptorsReport()
        XCTAssertTrue(report.diagnostics.isEmpty, id, file: file, line: line)
        XCTAssertTrue(report.symbolicReferenceKinds.isEmpty, id, file: file, line: line)
        XCTAssertTrue(report.accessorReferenceAddresses.isEmpty, id, file: file, line: line)
        XCTAssertTrue(report.callSiteDescriptorAddresses.isEmpty, id, file: file, line: line)
        XCTAssertEqual(report.descriptorAddresses, accepted ? [descriptor] : [], id, file: file, line: line)
        XCTAssertEqual(report.structuralDescriptorAddresses, accepted ? [descriptor] : [], id, file: file, line: line)
        XCTAssertEqual(report.records.count, accepted ? 1 : 0, id, file: file, line: line)
        guard accepted, let record = report.records.first else { return }
        XCTAssertEqual(record.descriptorAddress, descriptor, id, file: file, line: line)
        XCTAssertEqual(record.parentQualifiedName, "M", id, file: file, line: line)
        XCTAssertEqual(record.requirementCount, 0, id, file: file, line: line)
        XCTAssertEqual(record.underlyingTypes.count, 1, id, file: file, line: line)
        XCTAssertEqual(record.underlyingTypes.first?.mangledTypeName, "Si", id, file: file, line: line)
        // typeName is demangler-dependent; there is no model target-VA field.
    }

    func testSNEG_ZERO() {
        check("SNEG-ZERO", descriptor: 16, typeref: 0, parentWord: 1,
              underlyingWord: 0xffffffe8, rebases: [20: 256], accepted: true)
    }
    func testSPOS() {
        check("SPOS", descriptor: 16, typeref: 48, parentWord: 1,
              underlyingWord: 0x18, rebases: [20: 256], accepted: true)
    }
    func testSHIGH_NEG() {
        check("SHIGH-NEG", descriptor: UInt64.max - 19, typeref: UInt64.max - 31, parentWord: 1,
              underlyingWord: 0xffffffec, rebases: [UInt64.max - 15: 256], accepted: true)
    }
    func testUOVER_BAIT() {
        check("UOVER-BAIT", descriptor: UInt64.max - 19, typeref: 20, parentWord: 1,
              underlyingWord: 0x20, rebases: [UInt64.max - 15: 256], accepted: false)
    }
    func testUUNDER_BAIT() {
        check("UUNDER-BAIT", descriptor: 0, typeref: UInt64.max - 7, parentWord: 1,
              underlyingWord: 0xfffffff0, rebases: [4: 256], accepted: false)
    }
    func testUZERO() {
        check("UZERO", descriptor: 16, typeref: 48, parentWord: 1,
              underlyingWord: 0, rebases: [20: 256, 24: 48], accepted: false)
    }
    func testPZERO() {
        check("PZERO", descriptor: 16, typeref: 48, parentWord: 0,
              underlyingWord: 0x18, rebases: [20: 256], accepted: false)
    }
    func testPTAG1_MISS() {
        check("PTAG1-MISS", descriptor: 16, typeref: 48, parentWord: 1,
              underlyingWord: 0x18, rebases: [:], accepted: false)
    }
    func testPTAG3() {
        check("PTAG3", descriptor: 16, typeref: 48, parentWord: 3,
              underlyingWord: 0x18, rebases: [22: 256, 23: 272], accepted: true)
    }
    func testPDIRECT() {
        check("PDIRECT", descriptor: 16, typeref: 48, parentWord: 0xec,
              underlyingWord: 0x18, rebases: [256: 272], accepted: true)
    }
    func testPOVER_BAIT() {
        check("POVER-BAIT", descriptor: UInt64.max - 19, typeref: UInt64.max - 31, parentWord: 0x21,
              underlyingWord: 0xffffffec, rebases: [16: 256], accepted: false)
    }
    func testPUNDER_BAIT() {
        check("PUNDER-BAIT", descriptor: 0, typeref: 48, parentWord: 0xfffffff9,
              underlyingWord: 0x28, rebases: [UInt64.max - 3: 256], accepted: false)
    }
}
