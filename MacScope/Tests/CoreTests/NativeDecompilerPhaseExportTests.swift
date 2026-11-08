import Foundation
import XCTest
@testable import MacScope

#if DEBUG
final class NativeDecompilerPhaseExportTests: XCTestCase {
    private typealias Record = NativeDecompilerPhaseRecord
    private typealias Export = NativeDecompilerPhaseExport

    private func temporaryPath() -> String {
        NSTemporaryDirectory() + "phase-export-\(UUID().uuidString).jsonl"
    }

    private func lines(at path: String) throws -> [Export.Line] {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        return try text.split(separator: "\n").map {
            try JSONDecoder().decode(Export.Line.self, from: Data($0.utf8))
        }
    }

    private final class Box: @unchecked Sendable {
        private let lock = NSLock()
        private var summaries: [Record.Summary] = []
        func add(_ summary: Record.Summary) { lock.withLock { summaries.append(summary) } }
        var all: [Record.Summary] { lock.withLock { summaries } }
    }

    private func record(
        sink: Box, export: (@Sendable (Record.Summary) -> Void)?
    ) -> Record {
        let ticks = Box2()
        return Record(
            clock: { ticks.next() }, sink: { sink.add($0) }, export: export
        )
    }

    private final class Box2: @unchecked Sendable {
        private let lock = NSLock()
        private var value: UInt64 = 1_000
        func next() -> UInt64 { lock.withLock { value += 10; return value } }
    }

    func testGateOffWritesNothing() {
        let path = temporaryPath()
        let env = [Export.pathVariable: path]
        XCTAssertNil(Export.makeSink(environment: env, traceEnabled: false))
        XCTAssertNil(Export.makeSink(environment: [:], traceEnabled: true))
        XCTAssertNil(Export.makeSink(environment: [Export.pathVariable: "relative.jsonl"],
                                     traceEnabled: true))
        let box = Box()
        let attempt = record(sink: box, export: nil)
        attempt.finish()
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        XCTAssertEqual(box.all.count, 1)
    }

    func testGateOnWritesOneLinePerFinishRoundTripped() throws {
        let path = temporaryPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let sink = try XCTUnwrap(Export.makeSink(
            environment: [Export.pathVariable: path], traceEnabled: true))
        let box = Box()
        let first = record(sink: box, export: sink)
        first.add(.functionRows, 7)
        let span = first.begin(.selector)
        first.end(span)
        _ = first.begin(.projection) // left open: partial attempt is exported too
        first.finish()
        let second = record(sink: box, export: sink)
        second.finish()
        let written = try lines(at: path)
        XCTAssertEqual(written.count, 2)
        XCTAssertEqual(written.map(\.ordinal), [1, 2])
        for (line, summary) in zip(written, box.all) {
            XCTAssertEqual(line, Export.Line(ordinal: line.ordinal, summary))
            XCTAssertEqual(line.attemptID, summary.attemptID)
        }
        XCTAssertEqual(written[0].unfinishedSpans, 1)
        XCTAssertFalse(written[0].attributionComplete)
        XCTAssertEqual(written[0].counts[Record.Counter.functionRows.rawValue], 7)
    }

    func testIdempotentFinishWritesOneLine() throws {
        let path = temporaryPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let sink = try XCTUnwrap(Export.makeSink(
            environment: [Export.pathVariable: path], traceEnabled: true))
        let box = Box()
        let attempt = record(sink: box, export: sink)
        attempt.finish()
        attempt.finish()
        XCTAssertEqual(try lines(at: path).count, 1)
        XCTAssertEqual(box.all.count, 1)
    }

    func testUnwritablePathDoesNotThrowAndFinishCompletes() throws {
        let sink = try XCTUnwrap(Export.makeSink(
            environment: [Export.pathVariable: "/nonexistent-\(UUID().uuidString)/x.jsonl"],
            traceEnabled: true))
        let box = Box()
        let attempt = record(sink: box, export: sink)
        attempt.finish()
        let again = record(sink: box, export: sink)
        again.finish()
        XCTAssertEqual(box.all.count, 2)
    }
}
#endif
