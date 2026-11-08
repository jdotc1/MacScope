import Foundation
import XCTest
@testable import MacScope

// VA4 slice F: the read-only `verified-checkpoint` script/MCP command. The command runs the pure
// checkpoint reader over the LIVE store it is given. A store that wrote the receipts holds the
// writer's installation ID, which the reader reports as `installationNotFresh`; so these tests
// run the command on a store restored from the saved package (a fresh installation), exactly the
// state of an app that reopened the document. Every reply says process "same": it is never the
// fresh-process proof (slice G stays NOT RUN).
#if DEBUG
@MainActor
final class VerifiedCheckpointCommandTests: XCTestCase {
    private let command = "verified-checkpoint"

    // MARK: Fixtures

    private func operation(_ request: VerifiedAnnotationCommitRequest, key: ImageAddress,
                           baseline: String? = nil) -> VerifiedCheckpointExpectation.Operation {
        let before = request.receipt.before.revision
        return .init(operationID: request.operationID, requestDigest: request.receipt.requestDigest,
                     decision: request.isAccepted ? .accepted : .rejected, slot: key.slot.rawValue,
                     address: key.address, field: "name", requested: request.requested ?? "verified-name",
                     baseline: baseline, imageSHA256: nil, beforeRevision: before,
                     afterRevision: request.isAccepted ? before + 1 : nil)
    }

    private func expectation(_ h: VCSession, _ operations: [VerifiedCheckpointExpectation.Operation])
        -> VerifiedCheckpointExpectation {
        .init(schemaVersion: 1, workspaceID: h.store.workspaceID, documentID: h.store.documentID,
              writerInstallationIDs: [h.store.documentInstallationID],
              writerProcessID: ProcessInfo.processInfo.processIdentifier, operations: operations)
    }

    private func value(_ expectation: VerifiedCheckpointExpectation) throws -> ScriptValue {
        try ScriptValue.decode(JSONEncoder().encode(expectation))
    }

    private func reader(_ location: WorkspaceDocumentLocation) throws -> WorkspaceStore {
        let fresh = try WorkspaceDocumentLocation.canonicalized(from: location.canonicalURL)
        let store = try WorkspaceStore.restoredPackage(from: fresh.canonicalURL)
        store.recents = VCQuietRecents()
        return store
    }

    private func run(_ store: WorkspaceStore, _ arguments: [String: ScriptValue]) throws -> ScriptValue {
        try WorkspaceScriptingAPI(store: store).execute(command, arguments: .object(arguments))
    }

    private func outcomes(_ reply: ScriptValue) -> [String: String] {
        var result: [String: String] = [:]
        for row in reply["operations"]?.arrayValue ?? [] {
            if let id = row["operationID"]?.stringValue, let code = row["outcome"]?.stringValue { result[id] = code }
        }
        return result
    }

    private func refusal(_ body: () throws -> ScriptValue, file: StaticString = #filePath, line: UInt = #line)
        -> MCPToolRefusal? {
        do {
            _ = try body()
            XCTFail("expected a typed refusal", file: file, line: line)
            return nil
        } catch ScriptingError.structuredRefusal(let refusal) {
            return refusal
        } catch {
            XCTFail("expected a structured refusal, got \(error)", file: file, line: line)
            return nil
        }
    }

    private func commit(_ h: VCSession, accepted: Bool = true, name: String = "verified-name",
                        key: ImageAddress? = nil) async throws -> VerifiedAnnotationCommitRequest {
        let req = try h.request(name: name, accepted: accepted, key: key)
        let outcome = await h.session.commitVerifiedAnnotation(req)
        XCTAssertTrue(outcome.isCommitted, outcome.description)
        return req
    }

    // MARK: (a) confirmed

    func testConfirmedCommitIsReportedConfirmedForItsOperationID() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let req = try await commit(h)
        let live = try reader(h.location)
        let reply = try run(live, ["expectation": value(expectation(h, [operation(req, key: h.key)]))])
        XCTAssertEqual(outcomes(reply), [req.operationID.uuidString: "confirmed"], "\(reply)")
        XCTAssertEqual(reply["allOperationsPass"], .bool(true))
        XCTAssertEqual(reply["packageOutcome"], .null)
        XCTAssertEqual(reply["passed"], .bool(false), "same process is never the literal acceptance")
        XCTAssertEqual(reply["processIsolated"], .bool(false))
        // An explicit matching imageSlot is admitted.
        let slotted = try run(live, ["expectation": value(expectation(h, [operation(req, key: h.key)])),
                                     "imageSlot": .int(Int64(h.key.slot.rawValue))])
        XCTAssertEqual(outcomes(slotted), [req.operationID.uuidString: "confirmed"])
    }

    // MARK: (b) rejected recorded

    func testRejectedRecordedOperationReportsItsOwnCode() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let req = try await commit(h, accepted: false)
        let reply = try run(reader(h.location), ["expectation": value(expectation(h, [operation(req, key: h.key)]))])
        XCTAssertEqual(outcomes(reply), [req.operationID.uuidString: "rejectedRecorded"], "\(reply)")
        XCTAssertEqual(reply["allOperationsPass"], .bool(true))
    }

    // MARK: (c) unknown operation

    func testUnknownOperationIDGetsItsTypedOutcome() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let real = try await commit(h)
        var ghost = operation(real, key: h.key)
        ghost = .init(operationID: UUID(), requestDigest: ghost.requestDigest, decision: .accepted,
                      slot: ghost.slot, address: ghost.address &+ 4, field: "name", requested: "ghost-name",
                      baseline: nil, imageSHA256: nil, beforeRevision: 1, afterRevision: 2)
        let reply = try run(reader(h.location),
                            ["expectation": value(expectation(h, [operation(real, key: h.key), ghost]))])
        let found = outcomes(reply)
        XCTAssertEqual(found[real.operationID.uuidString], "confirmed")
        XCTAssertEqual(found[ghost.operationID.uuidString], "operationAbsent", "\(reply)")
        XCTAssertEqual(reply["allOperationsPass"], .bool(false))
    }

    // MARK: (d) malformed and over-limit expectations

    func testMalformedOrOverLimitExpectationIsATypedRefusal() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let req = try await commit(h)
        let live = try reader(h.location)
        let good = expectation(h, [operation(req, key: h.key)])

        XCTAssertThrowsError(try run(live, [:])) {
            XCTAssertEqual($0 as? ScriptingError, .missingArgument("expectation"))
        }
        XCTAssertEqual(refusal { try self.run(live, ["expectation": .string("nope")]) }?.code, .malformedInput)
        XCTAssertEqual(refusal { try self.run(live, ["expectation": .object(["schemaVersion": .int(1)])]) }?.code,
                       .malformedInput)
        // Wrong schema version: decoded, then rejected by validate().
        let wrongVersion = VerifiedCheckpointExpectation(schemaVersion: 2, workspaceID: good.workspaceID, documentID: good.documentID,
                             writerInstallationIDs: good.writerInstallationIDs,
                             writerProcessID: good.writerProcessID, operations: good.operations)
        let versionRefusal = refusal { try self.run(live, ["expectation": try self.value(wrongVersion)]) }
        XCTAssertEqual(versionRefusal?.code, .malformedInput)
        XCTAssertEqual(versionRefusal?.detail, "expectation-schema-version")
        // Over-limit: too many operations (and too many bytes) are out of bounds.
        let template = operation(req, key: h.key)
        let many = (0..<(VerifiedCheckpointBounds.maximumOperations + 1)).map { _ in
            VerifiedCheckpointExpectation.Operation(
                operationID: UUID(), requestDigest: template.requestDigest, decision: .accepted, slot: template.slot,
                address: template.address, field: "name", requested: "x", baseline: nil, imageSHA256: nil,
                beforeRevision: 0, afterRevision: 1)
        }
        let big = refusal { try self.run(live, ["expectation": try self.value(self.expectation(h, many))]) }
        XCTAssertEqual(big?.code, .outOfBounds)
        XCTAssertNotNil(big?.maximum)
        // Empty operations list.
        XCTAssertEqual(refusal { try self.run(live, ["expectation": try self.value(self.expectation(h, []))]) }?.detail,
                       "expectation-no-operations")
        // imageSlot that the expectation does not name, and a malformed imageSlot.
        let wrongSlot = refusal { try self.run(live, ["expectation": try self.value(good),
                                                      "imageSlot": .int(Int64(h.key.slot.rawValue + 1))]) }
        XCTAssertEqual(wrongSlot?.code, .malformedInput)
        XCTAssertEqual(wrongSlot?.field, "imageSlot")
        XCTAssertEqual(refusal { try self.run(live, ["expectation": try self.value(good), "imageSlot": .int(-1)]) }?.field,
                       "imageSlot")
    }

    // MARK: (e) read-only

    func testCommandLeavesGenerationJournalAndUndoStackUnchanged() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let req = try await commit(h)
        let live = try reader(h.location)
        let before = VCFixture.dump(live)
        let generation = live.snapshot.analysisGenerationID
        let canUndo = live.undoManager.canUndo
        let undoName = live.undoManager.undoActionName
        for _ in 0..<2 {
            _ = try run(live, ["expectation": value(expectation(h, [operation(req, key: h.key)]))])
        }
        XCTAssertEqual(VCFixture.dump(live), before)
        XCTAssertEqual(live.snapshot.analysisGenerationID, generation)
        XCTAssertEqual(live.undoManager.canUndo, canUndo)
        XCTAssertEqual(live.undoManager.undoActionName, undoName)
        // A refusal changes nothing either.
        _ = refusal { try self.run(live, ["expectation": .string("bad")]) }
        XCTAssertEqual(VCFixture.dump(live), before)
        let registered = WorkspaceScriptingAPI.availableCommands.first { $0.name == command }
        XCTAssertEqual(registered?.mutates, false)
    }

    // MARK: (f) MCP catalog

    func testMCPCatalogListsTheCommandAndDropsNoneOfTheExistingOnes() {
        let names = Set(HeadlessAutomationAuthority.availableCommands.map(\.name))
        XCTAssertTrue(names.contains(command))
        // Commands that existed before this slice (a representative cross-section of every group).
        let existing = ["call-graph", "call-path", "add-bookmark", "annotation-gaps", "callees", "callers", "commands",
                        "decompile", "functions", "info", "instructions", "read-bytes", "read-evidence", "rename",
                        "save-workspace", "open-workspace", "search", "set-comment", "set-names", "set-types",
                        "strings", "symbols", "undo-last", "xrefs", "indirect-call-targets", "function-facts",
                        "make-array", "patch-bytes", "reconstruction-jobs", "stack-locals"]
        for name in existing { XCTAssertTrue(names.contains(name), "dropped \(name)") }
        for entry in NavigatorMCPCommands.catalog { XCTAssertTrue(names.contains(entry.name), entry.name) }
        let info = HeadlessAutomationAuthority.availableCommands.first { $0.name == command }
        XCTAssertEqual(info?.mutates, false)
        XCTAssertEqual(Set(info?.arguments ?? []), ["expectation", "imageSlot"])
        let schema = info.map { HeadlessAutomationAuthority.inputSchema(for: $0) }
        XCTAssertEqual(schema?["required"], .array([.string("expectation")]))
        XCTAssertEqual(schema?["properties"]?["expectation"]?["type"], .string("object"))
        XCTAssertTrue(MCPAttachExecutor.attachCommands.contains(command))
        XCTAssertTrue(HeadlessAutomationAuthority.availableCommands.map(\.name).contains(command))
    }

    // MARK: (g) process and generation disclosure

    func testReplySaysProcessSameAndCarriesTheGeneration() async throws {
        let h = try await VCSession(test: self)
        defer { h.session.close() }
        let req = try await commit(h)
        let live = try reader(h.location)
        let capture = ScriptingGenerationCapture()
        let reply = try ScriptingGenerationCapture.$current.withValue(capture) {
            try run(live, ["expectation": value(expectation(h, [operation(req, key: h.key)]))])
        }
        XCTAssertEqual(reply["process"], .string("same"))
        XCTAssertEqual(reply["readOnly"], .bool(true))
        XCTAssertEqual(reply["generation"], .string(live.snapshot.analysisGenerationID.uuidString))
        XCTAssertEqual(capture.generation, live.snapshot.analysisGenerationID)
        XCTAssertEqual(reply["readerProcessID"], .int(Int64(ProcessInfo.processInfo.processIdentifier)))
        XCTAssertNotNil(reply["bounds"]?["maximumOperations"])
    }
}
#endif
