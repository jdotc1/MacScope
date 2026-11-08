import Foundation
import XCTest
@testable import MacScope

final class ObjCMethodListIMPAuditTests: XCTestCase {
    private struct Image {
        var bytes: [UInt8]
        init(size: Int = 0x2000) {
            bytes = [UInt8](repeating: 0, count: size)
            u64(0, 0x1040)
            u64(8, 0x1180)
            u64(0x40, 0x10c0)
            u64(0x60, 0x1083)
            u64(0x98, 0x1500)
            u64(0xe0, 0x1100)
            u64(0x118, 0x1500)
            u64(0x180, 0x1520)
            u64(0x188, 0x1040)
            string(0x500, "Owner")
            string(0x520, "Extra")
            string(0x800, "first")
            string(0x820, "second:")
            u64(0x900, 0x1800)
            u64(0x908, 0x1820)
            string(0xa00, "v16@0:8")
            u32(0xe00, 0xd65f03c0)
            u32(0xe10, 0xd65f03c0)
        }
        mutating func u32(_ offset: Int, _ value: UInt32) {
            for i in 0..<4 { bytes[offset + i] = UInt8(truncatingIfNeeded: value >> (8 * i)) }
        }
        mutating func u64(_ offset: Int, _ value: UInt64) {
            for i in 0..<8 { bytes[offset + i] = UInt8(truncatingIfNeeded: value >> (8 * i)) }
        }
        mutating func string(_ offset: Int, _ value: String) {
            let value = Array((value + "\0").utf8)
            bytes.replaceSubrange(offset..<offset + value.count, with: value)
        }
        mutating func relative(_ field: Int, _ target: Int) {
            u32(field, UInt32(bitPattern: Int32(target - field)))
        }
        mutating func list(_ offset: Int, small: Bool, stride: Int, count: Int = 2) {
            u32(offset, UInt32(stride) | (small ? 0x8000_0000 : 0))
            u32(offset + 4, UInt32(count))
            for i in 0..<count {
                let entry = offset + 8 + i * stride
                let second = i == count - 1 && count > 1
                if small {
                    relative(entry, second ? 0x908 : 0x900)
                    relative(entry + 4, 0xa00)
                    relative(entry + 8, second ? 0xe10 : 0xe00)
                } else {
                    u64(entry, second ? 0x1820 : 0x1800)
                    u64(entry + 8, 0x1a00)
                    u64(entry + 16, second ? 0x1e10 : 0x1e00)
                }
            }
        }
        func parser() -> ObjCClassParser {
            ObjCClassParser(data: Data(bytes), sections: [
                .init(address: 0x1000, fileOffset: 0, size: 8, name: "__objc_classlist"),
                .init(address: 0x1008, fileOffset: 8, size: 8, name: "__objc_catlist"),
                .init(address: 0x1010, fileOffset: 0x10, size: UInt64(bytes.count - 0x10), name: "__objc_const")
            ], rebaseTargets: [:], bindNames: [:])
        }
    }

    private func assertPair(_ methods: [ObjCMethod], classMethod: Bool = false,
                            file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(methods.map(\.selector), ["first", "second:"], file: file, line: line)
        XCTAssertEqual(methods.map(\.implementation), [0x1e00, 0x1e10], file: file, line: line)
        XCTAssertEqual(methods.map(\.isClassMethod), [classMethod, classMethod], file: file, line: line)
    }

    // Fails before: both valid four-byte-aligned class lists are discarded.
    func testFourByteAlignedClassAndMetaclassLists() throws {
        var image = Image()
        image.u64(0xa0, 0x1204)
        image.u64(0x120, 0x1304)
        image.list(0x204, small: true, stride: 12)
        image.list(0x304, small: true, stride: 12)
        let cls = try XCTUnwrap(image.parser().parseClasses().first)
        assertPair(cls.instanceMethods)
        assertPair(cls.classMethods, classMethod: true)
    }

    // Fails before: plain category pointers also lose address bit 2.
    func testFourByteAlignedCategoryLists() throws {
        var image = Image()
        image.u64(0x190, 0x1204)
        image.u64(0x198, 0x1304)
        image.list(0x204, small: true, stride: 12)
        image.list(0x304, small: true, stride: 12)
        let category = try XCTUnwrap(image.parser().parseCategories().first)
        XCTAssertEqual(category.className, "Owner")
        XCTAssertEqual(category.name, "Extra")
        assertPair(category.instanceMethods)
        assertPair(category.classMethods, classMethod: true)
    }

    // Fails before: the member cap truncates without a coverage diagnostic.
    func testMethodCountCapReportsUnrecoveredEntries() throws {
        let count = 65_537
        var image = Image(size: 0x1000 + 8 + count * 12)
        image.u64(0xa0, 0x2000)
        image.list(0x1000, small: true, stride: 12, count: count)
        var parser = image.parser()
        let log = MetadataParseDiagnosticLog()
        parser.diagnosticLog = log
        let methods = try XCTUnwrap(parser.parseClasses().first).instanceMethods
        XCTAssertEqual(methods.count, 65_536)
        XCTAssertEqual(log.entries.first { $0.grade == .abandonedList }?.address, 0x2000)
        XCTAssertTrue(log.entries.contains { $0.message.contains("1 entries were not recovered") })
    }


    // Fails before: a cache list-of-lists cap is silent.
    func testCacheSublistCapReportsUnrecoveredLists() throws {
        var image = Image(size: 0x5000)
        image.u32(0x1000, 8)
        image.u32(0x1004, 513)
        for i in 0..<513 {
            let field = 0x1008 + i * 8
            let offset = UInt64(bitPattern: Int64(0x3000 - field)) & 0x0000_ffff_ffff_ffff
            image.u64(field, offset << 16)
        }
        image.u32(0x3000, 0xc000_000c)
        image.u32(0x3004, 1)
        image.u32(0x3008, 0)
        image.relative(0x3010, 0xe00)
        image.u64(0x708, 0x800)
        var parser = image.parser()
        parser.cachePointerBase = 0x1000
        parser.rebaseTargets = [0x1000: 0x1040, 0x1040: 0, 0x1060: 0x1080,
                                0x1098: 0x1500, 0x10a0: 0x2001]
        parser.sections.append(.init(address: 0x1700, fileOffset: 0x700, size: 16, name: "__objc_scoffs"))
        let log = MetadataParseDiagnosticLog()
        parser.diagnosticLog = log
        let methods = try XCTUnwrap(parser.parseClasses().first).instanceMethods
        XCTAssertEqual(methods.count, 512)
        XCTAssertEqual(log.entries.first { $0.grade == .abandonedList }?.address, 0x2000)
        XCTAssertTrue(log.entries.contains { $0.message.contains("1 sublists were not recovered") })
    }

    // Fails before: comments exist at both category IMPs, but neither is a function boundary.
    func testCategoryOnlyRelativeIMPsSeedFunctionStarts() throws {
        let fixture = MachOFixture.makeExecutableWithCategoryOnlyRelativeIMPs()
        let parsed = try MachOParser().parse(fixture.bytes)
        XCTAssertTrue(parsed.functionStarts.isEmpty)
        let category = try XCTUnwrap(parsed.objectiveCMetadata.categories.first)
        let targets = (category.instanceMethods + category.classMethods).compactMap(\.implementation)
        XCTAssertEqual(Set(targets), [fixture.baseAddress + 0x20, fixture.baseAddress + 0x30])
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("objc-imp-\(UUID().uuidString)")
        try fixture.bytes.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let snapshot = try AnalysisEngine().analyze(url: url)
        for target in targets {
            XCTAssertTrue(snapshot.functions.contains { $0.startAddress == target })
            XCTAssertTrue(snapshot.instructions.first { $0.address == target }?.comment?
                .contains("Objective C implementation of") == true)
        }
    }

    private func u32(_ bytes: inout Data, _ offset: Int, _ value: UInt32) {
        for i in 0..<4 { bytes[offset + i] = UInt8(truncatingIfNeeded: value >> (8 * i)) }
    }
    private func u64(_ bytes: inout Data, _ offset: Int, _ value: UInt64) {
        for i in 0..<8 { bytes[offset + i] = UInt8(truncatingIfNeeded: value >> (8 * i)) }
    }
    private func cacheMethods(_ bytes: Data) throws -> [ObjCMethod] {
        let loaded = try DyldSharedCacheBinaryLoader().loadFromBytes(bytes, name: "cache", path: "/tmp/cache")
        return try XCTUnwrap(loaded.objcClasses.first).instanceMethods
    }

    // Fails before: the remaining valid occurrence lends its IMP to the unresolved occurrence.
    func testCacheDuplicateSelectorDoesNotBorrowAnIMP() throws {
        var bytes = DyldMetadataFixture.make()
        u32(&bytes, 0x1984, 2)
        u32(&bytes, 0x1990, 0x100000) // First "run" IMP is unmapped.
        u32(&bytes, 0x1994, 0x20)     // Second "run" uses the same selector.
        u32(&bytes, 0x1998, 0x30)
        u32(&bytes, 0x199c, UInt32(bitPattern: Int32(0x800 - 0x99c)))
        let methods = try cacheMethods(bytes)
        XCTAssertEqual(methods.map(\.selector), ["run", "run"])
        XCTAssertTrue(methods.allSatisfy { $0.implementation == nil })
    }

    // Fails before: unsigned addition loses a valid selector below the shared base.
    func testCacheDirectSelectorUsesSignedOffset() throws {
        var bytes = DyldMetadataFixture.make()
        u32(&bytes, 0x1988, UInt32(bitPattern: Int32(-0x80))) // base+0xb00 -> base+0xa80 ("Pair").
        let method = try XCTUnwrap(try cacheMethods(bytes).first)
        XCTAssertEqual(method.selector, "Pair")
        XCTAssertEqual(method.implementation, DyldMetadataFixture.base + 0x800)
    }

    // Fails before: cache membership, not the unused historical flag, selects direct names.
    func testCacheDirectSelectorDoesNotRequireHeaderFlag() throws {
        var bytes = DyldMetadataFixture.make()
        u32(&bytes, 0x1980, 0x8000_000c)
        let method = try XCTUnwrap(try cacheMethods(bytes).first)
        XCTAssertEqual(method.selector, "run")
        XCTAssertEqual(method.implementation, DyldMetadataFixture.base + 0x800)
    }

    // Fails before: both the metadata walk and loader enrichment mask away bit 2.
    func testCacheFourByteAlignedListRetainsItsIMP() throws {
        var bytes = DyldMetadataFixture.make()
        let old = bytes.subdata(in: 0x1980..<0x1994)
        bytes.replaceSubrange(0x1984..<0x1998, with: old)
        u32(&bytes, 0x1980, 0)
        u32(&bytes, 0x1994, UInt32(bitPattern: Int32(0x800 - 0x994)))
        u64(&bytes, 0x1960, 0x984 | (184 << 52))
        let method = try XCTUnwrap(try cacheMethods(bytes).first)
        XCTAssertEqual(method.selector, "run")
        XCTAssertEqual(method.implementation, DyldMetadataFixture.base + 0x800)
    }

    // Positive controls: pass at the pin and after FIX.
    func testControlBigListPairsTwoSelectorsWithTheirOwnIMPs() throws {
        var image = Image()
        image.u64(0xa0, 0x1200)
        image.list(0x200, small: false, stride: 24)
        assertPair(try XCTUnwrap(image.parser().parseClasses().first).instanceMethods)
    }

    func testControlSmallListPairsTwoNonzeroIMPs() throws {
        var image = Image()
        image.u64(0xa0, 0x1200)
        image.list(0x200, small: true, stride: 12)
        assertPair(try XCTUnwrap(image.parser().parseClasses().first).instanceMethods)
    }

    func testControlZeroRelativeIMPAbstains() throws {
        var image = Image()
        image.u64(0xa0, 0x1200)
        image.list(0x200, small: true, stride: 12, count: 1)
        image.u32(0x210, 0)
        let methods = try XCTUnwrap(image.parser().parseClasses().first).instanceMethods
        XCTAssertEqual(methods.count, 1)
        XCTAssertNil(methods.first?.implementation)
        XCTAssertTrue(methods.compactMap(\.implementation).isEmpty)
    }
}
