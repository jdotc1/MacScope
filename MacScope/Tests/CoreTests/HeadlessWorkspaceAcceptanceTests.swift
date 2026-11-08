import Foundation
import XCTest
@testable import MacScope

final class HeadlessWorkspaceAcceptanceTests: XCTestCase {
    @MainActor
    func testRejectsAmbiguousAndUnsafeRequestsBeforeAnyOperation() throws {
        let invalid = [
            #"{"action":"terminal","workspace":"relative.mscope","output":"/tmp/new"}"#,
            #"{"action":"terminal","workspace":"/tmp/a.mscope","output":"/tmp/a.mscope/new"}"#,
            #"{"action":"terminal","workspace":"/tmp/a.mscope","output":"/tmp/new","prompt":"unexpected"}"#,
            #"{"action":"rea","workspace":"/tmp/a.mscope","output":"/tmp/new"}"#,
            #"{"action":"inspect","workspace":"/tmp/a.mscope","output":"/tmp/new","unknown":true}"#,
            #"{"action":"inspect","action":"terminal","workspace":"/tmp/a.mscope","output":"/tmp/new"}"#
        ]
        for json in invalid {
            XCTAssertThrowsError(try HeadlessWorkspaceAcceptance.Request.decode(Data(json.utf8)), json)
        }
    }

    @MainActor
    func testAdmissionKeepsExplicitReadAndMutationModes() throws {
        for action in ["inspect", "terminal", "reopen"] {
            let data = try ScriptValue.object([
                "action": .string(action), "workspace": .string("/tmp/test.mscope"),
                "output": .string("/tmp/new-result")
            ]).jsonData()
            let request = try HeadlessWorkspaceAcceptance.Request.decode(data)
            XCTAssertEqual(request.action, action)
            XCTAssertNil(request.prompt)
            XCTAssertEqual(request.workspace.pathExtension, "mscope")
        }
    }

    @MainActor
    func testVerifiedCheckpointAdmissionRequiresAnAbsoluteExpectationAndOnlyThatAction() throws {
        let valid = try ScriptValue.object([
            "action": .string("verified-checkpoint"), "workspace": .string("/tmp/test.mscope"),
            "output": .string("/tmp/new-result"), "expectation": .string("/tmp/expect.json")
        ]).jsonData()
        let request = try HeadlessWorkspaceAcceptance.Request.decode(valid)
        XCTAssertEqual(request.action, "verified-checkpoint")
        XCTAssertEqual(request.expectation?.lastPathComponent, "expect.json")
        XCTAssertNil(request.prompt)

        let invalid = [
            // missing, relative or non-string expectation
            #"{"action":"verified-checkpoint","workspace":"/tmp/a.mscope","output":"/tmp/new"}"#,
            #"{"action":"verified-checkpoint","workspace":"/tmp/a.mscope","output":"/tmp/new","expectation":"e.json"}"#,
            #"{"action":"verified-checkpoint","workspace":"/tmp/a.mscope","output":"/tmp/new","expectation":7}"#,
            // a raw binary replay is not a verified claim: only .mscope packages are admitted
            #"{"action":"verified-checkpoint","workspace":"/tmp/a.out","output":"/tmp/new","expectation":"/tmp/e.json"}"#,
            // a prompt does not belong to this action
            #"{"action":"verified-checkpoint","workspace":"/tmp/a.mscope","output":"/tmp/new","expectation":"/tmp/e.json","prompt":"x"}"#,
            // other actions must not carry an expectation
            #"{"action":"inspect","workspace":"/tmp/a.mscope","output":"/tmp/new","expectation":"/tmp/e.json"}"#,
            #"{"action":"verified-checkpoint","workspace":"/tmp/a.mscope","output":"/tmp/a.mscope/new","expectation":"/tmp/e.json"}"#
        ]
        for json in invalid {
            XCTAssertThrowsError(try HeadlessWorkspaceAcceptance.Request.decode(Data(json.utf8)), json)
        }
    }
}
