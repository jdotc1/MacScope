import Foundation
import XCTest
@testable import MacScope

/// Crafted fixtures only. Key names are the ones Apple documents in "Interpreting the JSON
/// format of a crash report": osVersion{build,train,releaseType}, usedImages[]{path,arch,source},
/// frames[]{symbolLocation}.
final class CrashReportSystemFieldsTests: XCTestCase {
    private func body(os: String = "", source: String = "", symbolLocation: String = "") -> String {
        """
        {"procName":"Fixture","faultingThread":0,\(os)
         "threads":[{"frames":[{"imageIndex":0,"imageOffset":32,"symbol":"s"\(symbolLocation)},
                               {"imageIndex":1,"imageOffset":64}]}],
         "usedImages":[
          {"name":"Fixture","uuid":"12345678-1234-1234-1234-123456789ABC","base":4294967296,"size":4096\(source)},
          {"name":"libsystem_c.dylib","uuid":"AAAAAAAA-1234-1234-1234-123456789ABC","base":6442450944,"size":8192,
           "path":"/usr/lib/system/libsystem_c.dylib","arch":"arm64e","source":"S"}]}
        """
    }
    private func parse(_ text: String) throws -> CrashReport { try CrashReport.parse(Data(text.utf8)) }

    private let os = "\"osVersion\":{\"train\":\"macOS 27.3\",\"build\":\"26C5035r\",\"releaseType\":\"Beta\",\"isEmbedded\":false},"

    func testBareJSONDecodesDocumentedKeys() throws {
        let report = try parse(body(os: os, source: ",\"source\":\"P\",\"path\":\"/x/Fixture\",\"arch\":\"arm64\"",
                                    symbolLocation: ",\"symbolLocation\":12"))
        XCTAssertEqual(report.osVersion, CrashReportOSVersion(build: "26C5035r", train: "macOS 27.3", releaseType: "Beta"))
        XCTAssertEqual(report.images[0].source, .process)
        XCTAssertEqual(report.images[0].path, "/x/Fixture")
        XCTAssertEqual(report.images[0].arch, "arm64")
        XCTAssertEqual(report.images[1].source, .sharedCache)
        XCTAssertEqual(report.threads[0].frames[0].symbolLocation, 12)
        XCTAssertNil(report.threads[0].frames[1].symbolLocation)
        XCTAssertEqual(report.threads[0].frames[0].reportedSymbol, "s")
    }

    func testIPSEnvelopeDecodesDocumentedKeys() throws {
        let text = "{\"bug_type\":\"309\",\"app_name\":\"Meta\"}\n" + body(os: os, symbolLocation: ",\"symbolLocation\":0")
        let report = try parse(text)
        XCTAssertEqual(report.processName, "Fixture")
        XCTAssertEqual(report.osVersion?.build, "26C5035r")
        XCTAssertEqual(report.threads[0].frames[0].symbolLocation, 0)
        XCTAssertEqual(report.images[1].source, .sharedCache)
    }

    func testAbsentNewKeysParseAsLegacyWithoutFailing() throws {
        let legacy = """
        {"procName":"Fixture","threads":[{"frames":[{"imageIndex":0,"imageOffset":32,"symbol":"s"}]}],
         "usedImages":[{"name":"Fixture","uuid":"12345678-1234-1234-1234-123456789ABC","base":4294967296,"size":4096}]}
        """
        let report = try parse(legacy)
        XCTAssertNil(report.osVersion)
        XCTAssertNil(report.images[0].source)
        XCTAssertNil(report.images[0].path)
        XCTAssertNil(report.images[0].arch)
        XCTAssertNil(report.threads[0].frames[0].symbolLocation)
        XCTAssertEqual(report.runtimeAddress(of: report.threads[0].frames[0]), 0x1_0000_0020)
        // An osVersion object with every key absent is also not a failure.
        XCTAssertNil(try parse(body(os: "\"osVersion\":{},")).osVersion?.build)
    }

    func testPresentButInvalidNewFieldsAreTypedMalformed() {
        let cases: [(String, String)] = [
            (body(source: ",\"source\":\"Z\""), "usedImages.source"),
            (body(source: ",\"source\":\"SS\""), "usedImages.source"),
            (body(source: ",\"source\":\"\""), "usedImages.source"),
            (body(os: "\"osVersion\":{\"build\":\"\"},"), "osVersion.build"),
            (body(os: "\"osVersion\":{\"train\":\"\(String(repeating: "x", count: 129))\"},"), "osVersion.train"),
        ]
        for (text, key) in cases {
            XCTAssertThrowsError(try parse(text), key) { error in
                guard case CrashReport.ParseError.invalidField(let reported) = error else {
                    return XCTFail("expected invalidField for \(key), got \(error)")
                }
                XCTAssertEqual(reported, key)
            }
        }
        // Wrong JSON types for new keys are also refused (as .malformed by the typed decode).
        for text in [body(os: "\"osVersion\":{\"build\":5},"), body(os: "\"osVersion\":\"26C\","),
                     body(symbolLocation: ",\"symbolLocation\":-1"), body(symbolLocation: ",\"symbolLocation\":1.5"),
                     body(source: ",\"source\":7")] {
            XCTAssertThrowsError(try parse(text), text) { error in
                guard let parseError = error as? CrashReport.ParseError else { return XCTFail("untyped \(error)") }
                if case .malformed = parseError { return }
                XCTFail("expected malformed, got \(parseError)")
            }
        }
    }

    func testWorkspaceMatchAndResolveAreUnchangedByNewFields() throws {
        let report = try parse(body(os: os, source: ",\"source\":\"P\"", symbolLocation: ",\"symbolLocation\":9"))
        let context = CrashReportImageContext(uuid: "12345678123412341234123456789abc", preferredBase: 0x1000,
            mappedRanges: [0x1000..<0x2000],
            symbols: [CrashReportSymbol(name: "fn", address: 0x1010, endAddress: 0x1030)])
        let result = report.resolve(report.threads[0].frames[0], against: context)
        XCTAssertEqual(result.address, 0x1020)
        XCTAssertEqual(result.symbol, "fn")
        let none = report.match(report.threads[0].frames[1], contexts: [context])
        XCTAssertNil(none.contextIndex)
    }
}
