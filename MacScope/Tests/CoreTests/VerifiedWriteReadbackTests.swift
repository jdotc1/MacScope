import Foundation
import XCTest
@testable import MacScope

@MainActor
final class VerifiedWriteReadbackTests: XCTestCase {
    private func arguments(_ field: VerifiedAnnotationField, _ text: String, address: UInt64 = 0x1000) -> ScriptValue {
        .object(["address": .hex(address), field.rawValue: .string(text)])
    }
    private func command(_ field: VerifiedAnnotationField) -> String { field == .name ? "rename" : "set-comment" }
    private func request(_ field: VerifiedAnnotationField, _ text: String) -> ScriptValue {
        .object(["jsonrpc": .string("2.0"), "id": .int(1), "method": .string("tools/call"),
                 "params": .object(["name": .string(command(field)), "arguments": arguments(field, text)])])
    }
    private func content(_ envelope: ScriptValue) throws -> ScriptValue {
        let text = try XCTUnwrap(envelope["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
        return try ScriptValue.decode(Data(text.utf8))
    }

    func testRequestedEqualsObservedAndLegacyFieldsRemain() throws {
        let store = VerifiedAnnotationTestFixture.store()
        let api = WorkspaceScriptingAPI(store: store)
        for field in VerifiedAnnotationField.allCases {
            let result = try api.execute(command(field), arguments: arguments(field, "  accepted  "))
            XCTAssertEqual(result["ok"], .bool(true))
            XCTAssertEqual(result["address"], .hex(0x1000))
            if field == .name { XCTAssertEqual(result["name"], .string("  accepted  ")) }
            XCTAssertEqual(result["requested"], .string("accepted"))
            XCTAssertEqual(result["observed"], result["requested"])
            XCTAssertEqual(result["verification"], .string("candidateReadbackVerified"))
            XCTAssertEqual(field.value(in: try XCTUnwrap(store.snapshot.addressOverrides[.primary(0x1000)])), "accepted")
        }
    }

    func testMultibyteLimitsUseNormalizedUTF8Bytes() throws {
        for field in VerifiedAnnotationField.allCases {
            let store = VerifiedAnnotationTestFixture.store()
            let api = WorkspaceScriptingAPI(store: store)
            let atLimit = String(repeating: "é", count: field.maximumUTF8Bytes / 2)
            let accepted = try api.execute(command(field), arguments: arguments(field, "  " + atLimit + "  "))
            XCTAssertEqual(accepted["observed"], .string(atLimit))
            let before = store.snapshot.addressOverrides
            let rejected = try api.execute(command(field), arguments: arguments(field, atLimit + "é"))
            XCTAssertEqual(rejected["ok"], .bool(false))
            XCTAssertEqual(rejected["verification"]?["code"], .string("valueTooLarge"))
            XCTAssertEqual(rejected["verification"]?["stage"], .string("normalize"))
            XCTAssertEqual(store.snapshot.addressOverrides, before)
        }
    }

    func testWhitespaceAndEmptyClearWithNullReadback() throws {
        for text in ["", " \n\t "] {
            let store = VerifiedAnnotationTestFixture.store()
            let api = WorkspaceScriptingAPI(store: store)
            for field in VerifiedAnnotationField.allCases {
                let result = try api.execute(command(field), arguments: arguments(field, text))
                XCTAssertEqual(result["requested"], .null)
                XCTAssertEqual(result["observed"], .null)
                XCTAssertEqual(result["verification"], .string("candidateReadbackVerified"))
            }
            XCTAssertEqual(store.snapshot.addressOverrides[.primary(0x1000)]?.tag, "target")
        }
    }

    func testInjectedReadbackMismatchRestoresWorkspaceAndProtectedDigest() throws {
        #if DEBUG
        for field in VerifiedAnnotationField.allCases {
            let store = VerifiedAnnotationTestFixture.store()
            let before = store.snapshot.addressOverrides
            let projection = try store.readAnnotationProjection(at: .primary(0x1000))
            store.verifiedAnnotationReadbackTestHook = { after in field.set("wrong readback", in: &after.target) }
            let result = try WorkspaceScriptingAPI(store: store).execute(command(field), arguments: arguments(field, "new"))
            XCTAssertEqual(result["ok"], .bool(false))
            XCTAssertEqual(result["requested"], .string("new"))
            XCTAssertEqual(result["observed"], .string("wrong readback"))
            XCTAssertEqual(result["verification"]?["stage"], .string("readback"))
            XCTAssertEqual(result["verification"]?["restored"], .bool(true))
            XCTAssertNotNil(result["verification"]?["recoveryHint"]?.stringValue)
            XCTAssertEqual(store.snapshot.addressOverrides, before)
            XCTAssertEqual(try store.readAnnotationProjection(at: .primary(0x1000)).protectedDigest, projection.protectedDigest)
            store.undoManager.undo()
            XCTAssertEqual(store.snapshot.addressOverrides, before, "Undo must not expose a failed candidate")
        }
        #endif
    }

    func testProtectedFieldMismatchRestoresRequestedField() throws {
        #if DEBUG
        let store = VerifiedAnnotationTestFixture.store()
        let before = store.snapshot.addressOverrides
        store.verifiedAnnotationReadbackTestHook = { $0.protectedDigest = "injected-different-digest" }
        let result = try WorkspaceScriptingAPI(store: store).execute("rename", arguments: arguments(.name, "new"))
        XCTAssertEqual(result["verification"]?["stage"], .string("protected-fields"))
        XCTAssertEqual(result["verification"]?["restored"], .bool(true))
        XCTAssertEqual(store.snapshot.addressOverrides, before)
        #endif
    }

    func testEventGroupedUndoKeepsOwnerGroupAndActionName() throws {
        #if DEBUG
        for mismatch in [false, true] {
            let store = VerifiedAnnotationTestFixture.store()
            let before = store.snapshot.addressOverrides
            let manager = store.undoManager
            manager.groupsByEvent = true
            manager.beginUndoGrouping()
            let ownerLevel = manager.groupingLevel
            var observedLevel: Int?
            store.verifiedAnnotationReadbackTestHook = { after in
                observedLevel = manager.groupingLevel
                if mismatch { after.target.customName = "wrong" }
            }
            let result = try WorkspaceScriptingAPI(store: store).execute("rename", arguments: arguments(.name, "new"))
            XCTAssertEqual(observedLevel, ownerLevel, "The existing event group owns the whole request")
            XCTAssertEqual(result["ok"], .bool(!mismatch))
            while manager.groupingLevel > 0 { manager.endUndoGrouping() }
            manager.groupsByEvent = false
            XCTAssertEqual(manager.undoActionName, "Rename")
            manager.undo()
            XCTAssertEqual(store.snapshot.addressOverrides, before)
        }
        #endif
    }

    func testInteriorAddressKeepsLegacyWriteWithoutVerificationClaim() throws {
        let store = VerifiedAnnotationTestFixture.store()
        for field in VerifiedAnnotationField.allCases {
            let result = try WorkspaceScriptingAPI(store: store).execute(command(field), arguments: arguments(field, "interior", address: 0x1004))
            XCTAssertEqual(result["ok"], .bool(true))
            XCTAssertEqual(result["verification"]?["code"], .string("unsupportedTarget"))
            XCTAssertEqual(field.value(in: try XCTUnwrap(store.snapshot.addressOverrides[.primary(0x1004)])), "interior")
        }
        XCTAssertEqual(store.snapshot.addressOverrides[.primary(0x1000)]?.customName, "before")
    }

    func testCollidingVirtualAddressesRemainBoundToPrimaryDespiteFocus() throws {
        let store = VerifiedAnnotationTestFixture.store()
        let siblingKey = ImageAddress(slot: VerifiedAnnotationTestFixture.sibling, address: 0x1000)
        let siblingBefore = store.snapshot.addressOverrides[siblingKey]
        store.focusImage(VerifiedAnnotationTestFixture.sibling)
        for field in VerifiedAnnotationField.allCases {
            let result = try WorkspaceScriptingAPI(store: store).execute(command(field), arguments: arguments(field, "primary edit"))
            XCTAssertEqual(result["verification"], .string("candidateReadbackVerified"))
            XCTAssertEqual(store.snapshot.addressOverrides[siblingKey], siblingBefore)
            XCTAssertEqual(field.value(in: try XCTUnwrap(store.snapshot.addressOverrides[.primary(0x1000)])), "primary edit")
        }
    }

    func testSynchronousMCPReturnsTypedFailureWithIsError() throws {
        #if DEBUG
        let store = VerifiedAnnotationTestFixture.store()
        store.verifiedAnnotationReadbackTestHook = { $0.target.customName = "wrong" }
        let envelope = try XCTUnwrap(MCPServer(api: WorkspaceScriptingAPI(store: store)).handle(request(.name, "new")))
        XCTAssertEqual(envelope["result"]?["isError"], .bool(true))
        let result = try content(envelope)
        XCTAssertEqual(result["verification"]?["code"], .string("candidateMismatch"))
        XCTAssertEqual(result["verification"]?["stage"], .string("readback"))
        #endif
    }

    func testAsyncMCPAndAttachedRouteCarryReadback() async throws {
        let store = VerifiedAnnotationTestFixture.store()
        let server = MCPServer(api: WorkspaceScriptingAPI(store: store))
        let response = await server.handleMessageAsync(try request(.comment, "mcp comment").jsonData())
        let bytes = try XCTUnwrap(response)
        let envelope = try ScriptValue.decode(bytes)
        XCTAssertEqual(envelope["result"]?["isError"], .bool(false))
        XCTAssertEqual(try content(envelope)["observed"], .string("mcp comment"))
        let attached = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) })
        attached.setConsent(.allowed)
        let result = try await attached.execute("rename", arguments(.name, "attached"))
        XCTAssertEqual(result["observed"], .string("attached"))
        XCTAssertEqual(result["verification"], .string("candidateReadbackVerified"))
        #if DEBUG
        store.verifiedAnnotationReadbackTestHook = { $0.target.customComment = "wrong" }
        let failedResponse = await server.handleMessageAsync(try request(.comment, "new").jsonData())
        let failedBytes = try XCTUnwrap(failedResponse)
        let failed = try ScriptValue.decode(failedBytes)
        XCTAssertEqual(failed["result"]?["isError"], .bool(true))
        XCTAssertEqual(try content(failed)["verification"]?["restored"], .bool(true))
        #endif
    }
}
