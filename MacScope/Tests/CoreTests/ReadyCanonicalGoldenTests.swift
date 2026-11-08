import Foundation
import XCTest
@testable import MacScope

final class ReadyCanonicalGoldenTests: XCTestCase {
    private func scratch<T>(_ body: (URL) throws -> T) throws -> T {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        return try body(root)
    }

    func testGoldenMissingFailsClosed() throws {
        try scratch { root in
            let store = ReadyGoldenStore(root: root, recording: false, overwriteIdentical: false)
            XCTAssertThrowsError(try store.compare("6:String1:x", id: "f1-patched")) {
                XCTAssertEqual($0 as? ReadyGoldenError,
                    .missing(root.appendingPathComponent("f1-patched.canonical").path))
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: root.path))
        }
    }

    func testRecordRefusesOverwrite() throws {
        try scratch { root in
            let record = ReadyGoldenStore(root: root, recording: true, overwriteIdentical: false)
            try record.capture("6:String1:x", id: "f1-patched")
            let path = root.appendingPathComponent("f1-patched.canonical").path
            XCTAssertThrowsError(try record.capture("6:String1:y", id: "f1-patched")) {
                XCTAssertEqual($0 as? ReadyGoldenError, .exists(path))
            }
            let explicit = ReadyGoldenStore(root: root, recording: true, overwriteIdentical: true)
            XCTAssertNoThrow(try explicit.capture("6:String1:x", id: "f1-patched"))
            XCTAssertThrowsError(try explicit.capture("6:String1:y", id: "f1-patched")) {
                XCTAssertEqual($0 as? ReadyGoldenError, .differs(path + " firstDifferingEscapedKey=content/String"))
            }
            try record.compare("6:String1:x", id: "f1-patched")
        }
    }

    func testCompleteContentRoundTripAndStrictHeader() throws {
        let value = "6:String4:a=\nb"
        let encoded = ReadyGoldenStore.encode(value, id: "f1-patched")
        XCTAssertEqual(try ReadyGoldenStore.decode(encoded, id: "f1-patched"), Data(value.utf8))
        XCTAssertEqual(ReadyGoldenStore.escape(Data("a=\nb%".utf8)), "a%3D%0Ab%25")
        XCTAssertThrowsError(try ReadyGoldenStore.unescape("%0a"))
        XCTAssertThrowsError(try ReadyGoldenStore.unescape("%41"))
        XCTAssertThrowsError(try ReadyGoldenStore.decode(encoded, id: "f1-ordinary"))
        let changed = Data(String(decoding: encoded, as: UTF8.self)
            .replacingOccurrences(of: "canonicalVersion=1300.1", with: "canonicalVersion=wrong").utf8)
        XCTAssertThrowsError(try ReadyGoldenStore.decode(changed, id: "f1-patched"))
        XCTAssertEqual(ReadyGoldenStore.firstDifferingEscapedKey(
            Data("4:name11:6:String1:x".utf8), Data("4:name11:6:String1:y".utf8)), "content/name/String")
        XCTAssertEqual(ReadyGoldenStore.firstDifferingEscapedKey(
            Data("2:a=11:6:String1:x".utf8), Data("2:a=11:6:String1:y".utf8)), "content/a%3D/String")
        XCTAssertEqual(ReadyGoldenStore.firstDifferingEscapedKey(Data("broken".utf8), Data("other".utf8)), "content")
    }

    func testTripwireStillFiresOnNewField() throws {
        let rows = ReadyFixture.instructions(count: 2)
        let snapshot = try AnalysisEngine(loader: ReadyFixture.Loader(binary: ReadyFixture.binary(instructions: rows)),
            decoder: ReadyFixture.Decoder(rows: rows)).analyze(url: URL(fileURLWithPath: "/tmp/ignored"))
        let actual = Set(Mirror(reflecting: snapshot).children.compactMap(\.label))
        XCTAssertNoThrow(try AnalysisSnapshotCanonicalizer.requireFieldSet("WorkspaceSnapshot", actual: actual, path: "$root"))
        XCTAssertThrowsError(try AnalysisSnapshotCanonicalizer.requireFieldSet("WorkspaceSnapshot",
            actual: actual.union(["added1300Field"]), path: "$root")) {
            XCTAssertEqual($0 as? AnalysisSnapshotCanonicalizer.Failure, .unknownField("$root.added1300Field"))
        }
    }

    func testStoredFingerprintCheckedBeforeNormalization() throws {
        let url = try TinyMachO.make(code: Data([0xc0, 0x03, 0x5f, 0xd6])).write()
        defer { try? FileManager.default.removeItem(at: url) }
        var snapshot = try AnalysisEngine().analyze(url: url)
        let binary = try XCTUnwrap(snapshot.binaries.first)
        var other = try XCTUnwrap(snapshot.analysisBySlot[binary.slot])
        other.imageBytes.append(0)
        snapshot.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(binary: binary, analysis: other)
        XCTAssertThrowsError(try AnalysisSnapshotCanonicalizer.canonicalGoldenSnapshot(snapshot, sourceURL: url)) {
            XCTAssertEqual($0 as? AnalysisSnapshotCanonicalizer.Failure,
                .fingerprintMismatch("analysisBySlot.analysisInputFingerprint"))
        }
    }

    func testRecordCannotExceedSizeCap() throws {
        try scratch { root in
            let store = ReadyGoldenStore(root: root, recording: true, overwriteIdentical: false)
            XCTAssertThrowsError(try store.capture(String(repeating: "x", count: ReadyGoldenStore.byteLimit), id: "f1-patched")) {
                guard let error = $0 as? ReadyGoldenError, case .sizeCap = error else {
                    return XCTFail("expected sizeCap")
                }
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: root.path))
        }
    }
}
