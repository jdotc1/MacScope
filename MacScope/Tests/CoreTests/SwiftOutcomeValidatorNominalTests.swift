import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope

final class SwiftOutcomeValidatorNominalTests: XCTestCase {
    private func put(_ data: inout Data, _ off: Int, _ value: Int64, _ count: Int = 4) {
        let bits = UInt64(bitPattern:value)
        for i in 0..<count { data[off+i] = UInt8(truncatingIfNeeded:bits >> (8*i)) }
    }
    private func section(_ name: String, _ address: UInt64, _ end: UInt64, _ size: UInt64, _ offset: Int) -> SwiftNominalSectionInput {
        SwiftNominalSectionInput(segment:"__TEXT",name:name,address:address,end:end,size:size,offset:offset,flags:0)
    }
    private func fixture(_ kind: Int = 17) -> (Data,[SwiftNominalSectionInput]) {
        var data = Data(repeating:0,count:256)
        put(&data,0,32); put(&data,32,Int64(kind)); put(&data,36,60); put(&data,40,104)
        put(&data,96,0); put(&data,100,0); put(&data,104,24)
        data.replaceSubrange(128..<133,with:Array("Test\0".utf8))
        data.replaceSubrange(144..<150,with:Array("Owner\0".utf8))
        return (data,[section("__swift5_types",0x2000,0x2004,4,0),section("__const",0x2004,0x2100,252,4)])
    }
    private func readContext(_ data: Data, _ sections: [SwiftNominalSectionInput], kind: String = "struct") throws -> (SwiftOutcomeJSON,Int,[(Int,Int)]) {
        var work = 0, reads: [(Int,Int)] = []
        func charge(_ n: Int) throws {
            work += n
            if work > 65536 { throw SwiftOutcomeValidatorStop(reason:"test_nominal_work_limit",status:"unresolved") }
        }
        let result = try replaySwiftNominalContext(declaration:SwiftNominalDeclarationInput(module:"Test",context:[("Owner",kind)]),sections:sections,read: { offset,n in
            try charge(n+1); reads.append((offset,n))
            guard offset >= 0 && n >= 0 && offset <= data.count-n else { throw SwiftOutcomeValidatorStop(reason:"test_extent",status:"unresolved") }
            return data.subdata(in:offset..<offset+n)
        },limits:BroadWitnessLimits(),charge:charge)
        return (result,work,reads)
    }
    private func field(_ result: SwiftOutcomeJSON, _ name: String) -> SwiftOutcomeJSON? {
        guard case .object(let root) = result, case .array(let records)? = root["records"],
              let first = records.first, case .object(let row) = first else { return nil }
        return row[name]
    }
    private func expect(_ reason: String, _ data: Data, _ sections: [SwiftNominalSectionInput]) {
        XCTAssertThrowsError(try readContext(data,sections)) { error in
            XCTAssertEqual((error as? SwiftOutcomeValidatorStop)?.reason,reason)
            XCTAssertEqual((error as? SwiftOutcomeValidatorStop)?.status,"unresolved")
        }
    }
    // UC13; donor NominalReplayTests.
    func testUC13_primary_nominal_kinds_from_independent_descriptor_bytes() throws {
        for (kind,name) in [(16,"class"),(17,"struct"),(18,"enum")] {
            let (data,sections) = fixture(kind)
            _ = try readContext(data,sections,kind:name)
        }
    }
    func testUC13_nominal_descriptor_mutations() {
        let attacks: [(Int,Int64,Int)] = [(0,0,4),(0,33,4),(32,0x80|17,4),(32,0x10000|17,4),
            (32,1,4),(36,0,4),(36,-4,4),(36,1,4),(40,0,4),(40,900,4),
            (96,17,4),(100,4,4),(128,88,1),(144,88,1)]
        for (offset,value,count) in attacks {
            var (data,sections) = fixture(); put(&data,offset,value,count)
            XCTAssertThrowsError(try readContext(data,sections)) { XCTAssertTrue($0 is SwiftOutcomeValidatorStop) }
        }
    }
    private func stringFixture(_ raw: [UInt8], _ size: Int) -> (Data,[SwiftNominalSectionInput]) {
        var data = Data(repeating:0,count:800)
        put(&data,0,32); put(&data,32,17); put(&data,36,60); put(&data,40,104)
        put(&data,96,0); put(&data,100,0); put(&data,104,24)
        data.replaceSubrange(128..<133,with:Array("Test\0".utf8))
        data.replaceSubrange(144..<144+raw.count,with:raw)
        return (data,[section("__swift5_types",0x2000,0x2004,4,0),section("__const",0x2004,0x2090,140,4),
            section("__cstring",0x2090,0x2090+UInt64(size),UInt64(size),144),
            section("__after",0x2090+UInt64(size),0x2300,UInt64(0x270-size),144+size)])
    }
    // UC26; donor BoundedNominalCStringTests.
    func testUC26_final_section_byte_nul_is_retained_exactly() throws {
        let (data,sections) = stringFixture(Array("Owner\0".utf8),6)
        let (result,_,reads) = try readContext(data,sections)
        XCTAssertEqual(field(result,"raw_name"),.string("4f776e657200"))
        XCTAssertTrue(reads.allSatisfy { !($0.0 == 144 && $0.1 > 6) })
    }
    func testUC26_cstring_cannot_cross_mapping_even_to_adjacent_nul() {
        let (data,sections) = stringFixture(Array("Owner\0".utf8),3)
        expect("nominal_name_extent",data,sections)
    }
    func testUC26_malformed_and_unterminated_names_stay_unresolved() {
        let attacks: [([UInt8],Int,String)] = [([0],1,"nominal_empty_name"),([255,0],2,"nominal_name_encoding"),
            (Array(repeating:65,count:256)+[0],257,"nominal_name_limit")]
        for (raw,size,reason) in attacks { let (data,sections) = stringFixture(raw,size); expect(reason,data,sections) }
    }
    func testUC26_many_unrelated_names_have_bounded_directory_and_chunk_work() throws {
        let count = 441, descriptorOffset = 2048, nameOffset = 18000
        var data = Data(repeating:0,count:33000)
        for i in 0..<count {
            let entry = 0x2000+4*i, descriptor = 0x10000+32*i, name = 0x20000+32*i
            put(&data,4*i,Int64(descriptor-entry))
            let parent = i == count-1 ? 0x10000+32*count-(descriptor+4) : 1
            put(&data,descriptorOffset+32*i,17); put(&data,descriptorOffset+32*i+4,Int64(parent))
            put(&data,descriptorOffset+32*i+8,Int64(name-(descriptor+8)))
            let raw = Array((i == count-1 ? "Owner" : String(format:"UnrelatedOwner_%04d",i)).utf8) + [UInt8(0)]
            data.replaceSubrange(nameOffset+32*i..<nameOffset+32*i+raw.count,with:raw)
        }
        let module = 0x10000+32*count, moduleName = 0x20000+32*count
        put(&data,descriptorOffset+32*count,0); put(&data,descriptorOffset+32*count+4,0)
        put(&data,descriptorOffset+32*count+8,Int64(moduleName-(module+8)))
        data.replaceSubrange(nameOffset+32*count..<nameOffset+32*count+5,with:Array("Test\0".utf8))
        var sections = [section("__swift5_types",0x2000,UInt64(0x2000+4*count),UInt64(4*count),0),
            section("__const",0x10000,UInt64(module+16),UInt64(32*count+16),descriptorOffset),
            section("__cstring",0x20000,UInt64(moduleName+32),UInt64(32*(count+1)),nameOffset)]
        for i in 0..<20 { sections.append(section("__other\(i)",UInt64(0x30000+0x1000*i),UInt64(0x30008+0x1000*i),8,0)) }
        let (result,work,reads) = try readContext(data,sections)
        XCTAssertLessThan(work,Int(40000)); XCTAssertLessThan(reads.count,Int(2000))
        XCTAssertEqual(field(result,"raw_name"),.string("4f776e657200"))
        let off = descriptorOffset+32*(count-1)
        let expected = data[off..<off+28].map { String(format:"%02x",$0) }.joined()
        XCTAssertEqual(field(result,"raw_descriptor"),.string(expected))
    }
}
#endif
