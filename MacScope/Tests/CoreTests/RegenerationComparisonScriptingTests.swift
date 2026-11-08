import Foundation
import XCTest
@testable import MacScope

final class RegenerationComparisonScriptingTests: XCTestCase {
    @MainActor
    func testCapturedComparisonUsesLiveAppleScriptWithoutHeadlessExposure() throws {
        let arguments: ScriptValue = .object(["originalImage": .int(0), "rebuiltImage": .int(1),
            "outputDirectory": .string("/Users\u{2F}example/Developer/MacScope/NewComparison")])
        let translated = try AppleScriptCommandTranslator.translate(command: "run command", parameters: [
            "command": .string("compare-rebuild"), "arguments": arguments])
        XCTAssertEqual(translated.command, "compare-rebuild")
        XCTAssertEqual(translated.arguments, arguments)
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validate(command: "compare-rebuild", arguments: arguments))
    }

    @MainActor
    func testSynchronousRegistryRefusesComparisonWithoutStartingWork() throws {
        let snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        let store = WorkspaceStore(workspaceName: "Comparison", snapshot: snapshot,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let api = WorkspaceScriptingAPI(store: store)
        let arguments: ScriptValue = .object(["originalImage": .int(0), "rebuiltImage": .int(1),
            "outputDirectory": .string("/Users\u{2F}example/Developer/MacScope/NewComparison")])
        XCTAssertThrowsError(try api.execute("compare-rebuild", arguments: arguments)) { error in
            guard case ScriptingError.invalidArgument(let message) = error else {
                return XCTFail("Expected asynchronous-only refusal")
            }
            XCTAssertTrue(message.contains("asynchronous"))
        }
    }

}
