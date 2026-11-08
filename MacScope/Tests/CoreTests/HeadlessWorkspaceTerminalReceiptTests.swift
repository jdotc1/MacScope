import Foundation
import XCTest
@testable import MacScope

final class HeadlessWorkspaceTerminalReceiptTests: XCTestCase {
    @MainActor
    func testCV01FiniteReceiptRoundTrips() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("terminal-receipt-CV01-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let receipt = ScriptValue.object(["passed": .bool(true), "stage": .string("complete")])

        let reason: String? = HeadlessWorkspaceTerminalAcceptance.writeReceipt(
            receipt, fileName: "RESULT.json", root: root, stage: "complete", originalError: ""
        )

        XCTAssertNil(reason)
        let decoded = try ScriptValue.decode(Data(contentsOf: root.appendingPathComponent("RESULT.json")))
        XCTAssertEqual(decoded, receipt)
    }

    @MainActor
    func testCV02NonFiniteReceiptWritesExactFallback() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("terminal-receipt-CV02-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let receipt = ScriptValue.object([
            "passed": .bool(false), "stage": .string("stop"), "bad": .double(.nan)
        ])

        let reason = try XCTUnwrap(HeadlessWorkspaceTerminalAcceptance.writeReceipt(
            receipt, fileName: "RESULT.json", root: root, stage: "stop", originalError: "line one\nline two"
        ))

        XCTAssertTrue(reason.hasPrefix("JSON encoding refused a non-finite number at"))
        let decoded = try ScriptValue.decode(Data(contentsOf: root.appendingPathComponent("RESULT.json")))
        let expected = ScriptValue.object([
            "passed": .bool(false),
            "stage": .string("stop"),
            "error": .string("line one\nline two"),
            "receiptWriteFailure": .string(reason),
            "evidenceScope": .string("minimal finite diagnostic; full receipt could not be written")
        ])
        XCTAssertEqual(decoded, expected)
    }

    @MainActor
    func testCV03MissingRootReturnsFailureWithoutCreatingDirectory() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("terminal-receipt-CV03-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let absent = root.appendingPathComponent("absent", isDirectory: true)
        let receipt = ScriptValue.object([
            "passed": .bool(false), "stage": .string("stop"), "bad": .double(.nan)
        ])

        let reason: String? = HeadlessWorkspaceTerminalAcceptance.writeReceipt(
            receipt, fileName: "RESULT.json", root: absent, stage: "stop", originalError: "boom"
        )

        XCTAssertNotNil(reason)
        XCTAssertFalse(FileManager.default.fileExists(atPath: absent.path))
    }

    @MainActor
    func testCV04NestedInfinityPreservesRefusalReason() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("terminal-receipt-CV04-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let receipt = ScriptValue.object([
            "a": .object(["b": .array([.double(.infinity)])])
        ])

        let reason = try XCTUnwrap(HeadlessWorkspaceTerminalAcceptance.writeReceipt(
            receipt, fileName: "RESULT.json", root: root, stage: "stop", originalError: "boom"
        ))

        XCTAssertTrue(reason.contains("non-finite number"))
        let decoded = try ScriptValue.decode(Data(contentsOf: root.appendingPathComponent("RESULT.json")))
        XCTAssertEqual(decoded["receiptWriteFailure"], .string(reason))
    }

    @MainActor
    func testCV05BothReceiptNamesAreWritten() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("terminal-receipt-CV05-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let receipt = ScriptValue.object(["passed": .bool(true), "stage": .string("complete")])

        let beforeReason: String? = HeadlessWorkspaceTerminalAcceptance.writeReceipt(
            receipt, fileName: "FAILURE-before-cleanup.json", root: root, stage: "stop", originalError: "boom"
        )
        let finalReason: String? = HeadlessWorkspaceTerminalAcceptance.writeReceipt(
            receipt, fileName: "RESULT.json", root: root, stage: "stop", originalError: "boom"
        )

        XCTAssertNil(beforeReason)
        XCTAssertNil(finalReason)
        let names = try FileManager.default.contentsOfDirectory(atPath: root.path).sorted()
        let expected: [String] = ["FAILURE-before-cleanup.json", "RESULT.json"]
        XCTAssertEqual(names, expected)
    }

    @MainActor
    func testCV06FallbackReplacesStaleReceipt() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("terminal-receipt-CV06-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("stale".utf8).write(to: root.appendingPathComponent("RESULT.json"))
        let receipt = ScriptValue.object([
            "passed": .bool(false), "stage": .string("stop"), "bad": .double(.nan)
        ])

        let reason = try XCTUnwrap(HeadlessWorkspaceTerminalAcceptance.writeReceipt(
            receipt, fileName: "RESULT.json", root: root, stage: "stop", originalError: "line one\nline two"
        ))

        let decoded = try ScriptValue.decode(Data(contentsOf: root.appendingPathComponent("RESULT.json")))
        XCTAssertEqual(decoded["passed"], .bool(false))
        XCTAssertEqual(decoded["receiptWriteFailure"], .string(reason))
    }

    @MainActor
    func testCV07FallbackLeavesOnlyResultFile() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("terminal-receipt-CV07-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let receipt = ScriptValue.object([
            "passed": .bool(false), "stage": .string("stop"), "bad": .double(.nan)
        ])

        let reason: String? = HeadlessWorkspaceTerminalAcceptance.writeReceipt(
            receipt, fileName: "RESULT.json", root: root, stage: "stop", originalError: "line one\nline two"
        )

        XCTAssertNotNil(reason)
        let names = try FileManager.default.contentsOfDirectory(atPath: root.path).sorted()
        let expected: [String] = ["RESULT.json"]
        XCTAssertEqual(names, expected)
    }
}
