import Foundation
import XCTest
@testable import MacScope

final class RegenerationScriptingIntegrationTests: XCTestCase {
    func testNativeUserRecordConversionPreservesArgumentsAndRejectsMalformedRecords() throws {
        var error: NSDictionary?
        let script = try XCTUnwrap(NSAppleScript(source: "{|outputDirectory|:\"/tmp/Quoted λ\", |enabled|:true, |count|:3, |nested|:{|names|:{\"one\", \"two\"}}, |absent|:missing value}"))
        let descriptor = script.executeAndReturnError(&error)
        XCTAssertNil(error)
        let record = try XCTUnwrap(MacScopeScriptRecord.scriptingUserDefinedRecord(with: descriptor))
        guard case let .object(fields) = AppleScriptArgumentBridge.scriptValue(from: record) else {
            return XCTFail("Expected object")
        }
        XCTAssertEqual(fields["outputDirectory"] ?? fields["outputdirectory"], .string("/tmp/Quoted λ"))
        XCTAssertEqual(fields["enabled"], .bool(true))
        XCTAssertEqual(fields["count"], .int(3))
        XCTAssertEqual(fields["nested"], .object(["names": .array([.string("one"), .string("two")])]))
        XCTAssertEqual(fields["absent"], .null)
        XCTAssertNil(MacScopeScriptRecord.scriptingUserDefinedRecord(with: NSAppleEventDescriptor(string: "wrong")))
        let malformed = NSAppleEventDescriptor.record()
        let odd = NSAppleEventDescriptor.list()
        odd.insert(NSAppleEventDescriptor(string: "dangling"), at: 1)
        malformed.setDescriptor(odd, forKeyword: 0x75737266)
        XCTAssertNil(MacScopeScriptRecord.scriptingUserDefinedRecord(with: malformed))
        let exact = NSAppleEventDescriptor.record()
        let pairs = NSAppleEventDescriptor.list()
        pairs.insert(NSAppleEventDescriptor(string: "large"), at: 1)
        var number = Int64.max
        let integer = withUnsafeBytes(of: &number) { NSAppleEventDescriptor(descriptorType: 0x636f6d70, data: Data($0)) }
        pairs.insert(try XCTUnwrap(integer), at: 2)
        exact.setDescriptor(pairs, forKeyword: 0x75737266)
        XCTAssertEqual(MacScopeScriptRecord.scriptingUserDefinedRecord(with: exact)?.value, .object(["large": .int(Int64.max)]))
    }
    func testGenericAppleScriptReplyMatchesDeclaredJSONTextWithoutChangingTypedVerbs() throws {
        let object: ScriptValue = .object(["ok": .bool(true), "stubCount": .int(3),
            "name": .string("Quoted \"name\" — λ"), "items": .array([.null, .double(2.5)])])
        for value in [object, .string("scalar"), .int(7), .bool(false), .null] {
            let reply = try XCTUnwrap(AppleScriptArgumentBridge.cocoaReply(from: value,
                command: "run command") as? String)
            XCTAssertEqual(try ScriptValue.decode(Data(reply.utf8)), value)
        }
        let record = try AppleScriptArgumentBridge.cocoaReply(from: object, command: "get info")
        XCTAssertTrue(record is [String: Any])
        XCTAssertEqual(AppleScriptArgumentBridge.scriptValue(from: record), object)
        XCTAssertThrowsError(try AppleScriptArgumentBridge.cocoaReply(from: .double(.nan),
            command: "run command"))
    }

    @MainActor
    func testLegacyCLIExportRefusesBeforeOpeningOrHashingLaunchBinary() throws {
        let script = Data(#"[{"command":"export-project","arguments":{"appPath":"/Users\u{2F}example/Developer/MacScope/NoSuch.app","outputDirectory":"/Users\u{2F}example/Developer/MacScope/no-export-created"}}]"#.utf8)
        XCTAssertThrowsError(try CLIRunner.execute(scriptData: script,
            binaryURL: URL(fileURLWithPath: "/Users\u{2F}example/Developer/MacScope/no-binary-opened"))) { error in
            guard case ScriptingError.invalidArgument(let message) = error else {
                XCTFail("Expected pre-load export refusal, got \(error)"); return
            }
            XCTAssertTrue(message.contains("captured workspace"))
        }
    }

    @MainActor
    func testExistingLiveAppleScriptVerbAdmitsExportWithoutGeneralMCPExposure() throws {
        let arguments: ScriptValue = .object(["appPath": .string("/Users\u{2F}example/Developer/MacScope/Example.app"),
            "outputDirectory": .string("/Users\u{2F}example/Developer/MacScope/NewExport")])
        let translated = try AppleScriptCommandTranslator.translate(command: "run command", parameters: [
            "command": .string("export-project"), "arguments": arguments])
        XCTAssertEqual(translated.command, "export-project")
        XCTAssertEqual(translated.arguments, arguments)
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validate(command: "export-project", arguments: arguments))
    }
}
