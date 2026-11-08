import XCTest
@testable import MacScope

@MainActor
final class NEWFEATURESMCPRegistrationTests: XCTestCase {
    private let readName = NEWFEATURESMCPReads.callPathCommand

    private func surface(store: WorkspaceStore? = nil, hasImage: Bool = true) -> NavigatorSurface {
        NavigatorSurface(
            resolveImage: { raw in
                switch raw {
                case .int(0), .string("0"): return hasImage ? .primary : nil
                default: return nil
                }
            },
            state: { _ in nil }, generationKey: { _ in "g" }, image: { _ in nil },
            accept: { _, _ in nil }, revert: { _, _, _ in nil }, store: store)
    }

    private func arguments(_ extra: [String: ScriptValue] = [:]) -> ScriptValue {
        .object(["imageSlot": .int(0), "source": .string("0x1000"), "target": .string("0x2000")]
            .merging(extra) { _, new in new })
    }

    func testRegisteredInHeadlessAuthorityAndCatalog() throws {
        XCTAssertTrue(NavigatorMCPCommands.handles(readName))
        XCTAssertTrue(NavigatorMCPCommands.attachable.contains(readName))
        let info = try XCTUnwrap(NavigatorMCPCommands.info(readName))
        XCTAssertFalse(info.mutates)
        XCTAssertTrue(info.summary.contains("call-path"))
        XCTAssertEqual(NavigatorMCPCommands.requiredArguments(for: readName), ["imageSlot", "source", "target"])
        XCTAssertTrue(HeadlessAutomationAuthority.availableCommands.contains { $0.name == readName })
        XCTAssertNoThrow(try HeadlessAutomationAuthority.validate(command: readName, arguments: arguments()))
    }

    func testMissingSourceIsNamedArgumentError() {
        let bad: [String: ScriptValue] = ["imageSlot": .int(0), "target": .string("0x2000")]
        XCTAssertThrowsError(try NavigatorMCPCommands.validateDiagnosed(command: readName, fields: bad)) { error in
            XCTAssertEqual((error as? ToolArgumentError)?.refusal.field, "source")
        }
    }

    func testUnknownImageIsBoundedTypedAbsence() async throws {
        let result = try await NavigatorMCPCommands.executeAsync(
            command: readName, arguments: arguments(), surface: surface(hasImage: false))
        XCTAssertEqual(result["absent"]?["reason"]?.stringValue, "noSuchImage")
    }

    func testMissingStoreOrSessionIsTypedRefusalWithoutRawFallback() async throws {
        for store in [nil, WorkspaceStore(workspaceName: "Reg", snapshot: AnalysisEngine.previewSnapshot(),
                                          engine: AnalysisEngine())] {
            let built = surface(store: store)
            let async = try await NavigatorMCPCommands.executeAsync(
                command: readName, arguments: arguments(), surface: built)
            let inline = try NavigatorMCPCommands.execute(command: readName, arguments: arguments(), surface: built)
            XCTAssertEqual(async["error"]?.stringValue, "refused")
            XCTAssertEqual(async["refusal"]?["detail"]?.stringValue, "document session unavailable")
            XCTAssertEqual(inline, async)
        }
    }

    func testUnknownImageIsTypedAbsenceOnTheInlinePathToo() throws {
        let result = try NavigatorMCPCommands.execute(
            command: readName, arguments: arguments(), surface: surface(hasImage: false))
        XCTAssertEqual(result["absent"]?["reason"]?.stringValue, "noSuchImage")
    }
}
