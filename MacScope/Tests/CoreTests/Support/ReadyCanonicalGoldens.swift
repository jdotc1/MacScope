import Foundation
import XCTest
@testable import MacScope

enum ReadyGoldenError: Error, Equatable {
    case invalid(String)
    case missing(String)
    case differs(String)
    case exists(String)
    case sizeCap(Int)
}

struct ReadyGoldenStore {
    static let canonicalVersion = "1300.1"
    static let byteLimit = 4 * 1024 * 1024
    let root: URL
    let recording: Bool
    let overwriteIdentical: Bool

    static func escape(_ data: Data) -> String {
        let hex = Array("0123456789ABCDEF".utf8)
        var result: [UInt8] = []
        for byte in data {
            if (0x20...0x7e).contains(byte), byte != 0x25, byte != 0x3d {
                result.append(byte)
            } else {
                result.append(0x25)
                result.append(hex[Int(byte >> 4)])
                result.append(hex[Int(byte & 15)])
            }
        }
        return String(decoding: result, as: UTF8.self)
    }

    static func unescape(_ text: String) throws -> Data {
        let bytes = Array(text.utf8)
        var output = Data()
        var index = 0
        func nibble(_ value: UInt8) -> UInt8? {
            if (48...57).contains(value) { return value - 48 }
            if (65...70).contains(value) { return value - 65 + 10 }
            return nil
        }
        while index < bytes.count {
            if bytes[index] == 0x25 {
                guard index + 2 < bytes.count,
                      let high = nibble(bytes[index + 1]), let low = nibble(bytes[index + 2]) else {
                    throw ReadyGoldenError.invalid("malformed canonical escape")
                }
                output.append(high * 16 + low)
                index += 3
            } else {
                output.append(bytes[index])
                index += 1
            }
        }
        guard String(data: output, encoding: .utf8) != nil, escape(output) == text else {
            throw ReadyGoldenError.invalid("noncanonical UTF-8/escaping")
        }
        return output
    }

    static func encode(_ canonical: String, id: String) -> Data {
        Data(("ready-canonical\ncanonicalVersion=\(canonicalVersion)\ncase=\(id)\ncontent="
            + escape(Data(canonical.utf8)) + "\n").utf8)
    }

    static func decode(_ bytes: Data, id: String) throws -> Data {
        guard let text = String(data: bytes, encoding: .utf8) else {
            throw ReadyGoldenError.invalid("invalid golden UTF-8: \(id)")
        }
        let lines = text.components(separatedBy: "\n")
        guard lines.count == 5, lines[4].isEmpty,
              lines[0] == "ready-canonical",
              lines[1] == "canonicalVersion=\(canonicalVersion)",
              lines[2] == "case=\(id)", lines[3].hasPrefix("content=") else {
            throw ReadyGoldenError.invalid("golden header/version: \(id)")
        }
        return try unescape(String(lines[3].dropFirst("content=".count)))
    }

    // Diagnostic only: walk just the first unequal framed branch, never change the oracle.
    static func firstDifferingEscapedKey(_ expected: Data, _ actual: Data) -> String {
        let left = Array(expected), right = Array(actual)
        struct Frame { let tag: Range<Int>; let body: Range<Int>; let end: Int }
        func frame(_ bytes: [UInt8], _ start: Int, _ limit: Int) -> Frame? {
            var cursor = start
            func length() -> Int? {
                let first = cursor
                var value = 0
                while cursor < limit, (48...57).contains(bytes[cursor]) {
                    let digit = Int(bytes[cursor] - 48)
                    guard value <= limit / 10 else { return nil }
                    value = value * 10 + digit
                    guard value <= limit else { return nil }
                    cursor += 1
                }
                guard cursor > first, cursor < limit, bytes[cursor] == 58 else { return nil }
                cursor += 1
                return value
            }
            guard let tagCount = length(), tagCount <= limit - cursor else { return nil }
            let tag = cursor..<(cursor + tagCount)
            cursor = tag.upperBound
            guard let bodyCount = length(), bodyCount <= limit - cursor else { return nil }
            let body = cursor..<(cursor + bodyCount)
            return Frame(tag: tag, body: body, end: body.upperBound)
        }
        let scalars: Set<String> = ["UUID", "Data", "String", "UInt64", "Int", "UInt32", "Int32",
            "UInt8", "UInt16", "Int64", "Int16", "Int8", "UInt", "FloatBits", "DoubleBits", "Bool"]
        func locate(_ a: Range<Int>, _ b: Range<Int>, _ keys: [String], _ depth: Int) -> [String] {
            var i = a.lowerBound, j = b.lowerBound
            while i < a.upperBound, j < b.upperBound {
                guard let x = frame(left, i, a.upperBound), let y = frame(right, j, b.upperBound) else {
                    return keys
                }
                if left[i..<x.end].elementsEqual(right[j..<y.end]) { i = x.end; j = y.end; continue }
                let xTag = String(decoding: left[x.tag], as: UTF8.self)
                let yTag = String(decoding: right[y.tag], as: UTF8.self)
                let next = keys + [xTag == yTag ? xTag : "{" + xTag + "|" + yTag + "}"]
                guard xTag == yTag, !scalars.contains(xTag), depth < 32,
                      !x.body.isEmpty, !y.body.isEmpty else { return next }
                return locate(x.body, y.body, next, depth + 1)
            }
            if i < a.upperBound, let x = frame(left, i, a.upperBound) {
                return keys + [String(decoding: left[x.tag], as: UTF8.self)]
            }
            if j < b.upperBound, let y = frame(right, j, b.upperBound) {
                return keys + [String(decoding: right[y.tag], as: UTF8.self)]
            }
            return keys
        }
        return escape(Data(locate(left.indices, right.indices, ["content"], 0).joined(separator: "/").utf8))
    }

    func inventory() throws -> (Set<String>, Int) {
        let manager = FileManager.default
        guard manager.fileExists(atPath: root.path) else { return ([], 0) }
        let rootInfo = try root.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard rootInfo.isDirectory == true, rootInfo.isSymbolicLink != true else {
            throw ReadyGoldenError.invalid("golden root is not a real directory: \(root.path)")
        }
        let entries = try manager.contentsOfDirectory(at: root,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
        var names = Set<String>()
        var total = 0
        for entry in entries {
            let info = try entry.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
            guard info.isRegularFile == true, info.isSymbolicLink != true,
                  ReadyCanonicalGoldens.ids.contains(entry.deletingPathExtension().lastPathComponent),
                  entry.pathExtension == "canonical", let count = info.fileSize else {
                throw ReadyGoldenError.invalid("unexpected golden entry: \(entry.lastPathComponent)")
            }
            names.insert(entry.lastPathComponent)
            total += count
        }
        guard total <= Self.byteLimit else { throw ReadyGoldenError.sizeCap(total) }
        return (names, total)
    }

    func compare(_ canonical: String, id: String) throws {
        guard ReadyCanonicalGoldens.ids.contains(id) else { throw ReadyGoldenError.invalid(id) }
        let url = root.appendingPathComponent(id + ".canonical")
        let (names, _) = try inventory()
        guard names.contains(url.lastPathComponent) else { throw ReadyGoldenError.missing(url.path) }
        let expected = try Self.decode(Data(contentsOf: url), id: id)
        let actual = Data(canonical.utf8)
        guard expected == actual else {
            throw ReadyGoldenError.differs(url.path + " firstDifferingEscapedKey="
                + Self.firstDifferingEscapedKey(expected, actual))
        }
    }

    func capture(_ canonical: String, id: String) throws {
        guard recording, ReadyCanonicalGoldens.ids.contains(id) else {
            throw ReadyGoldenError.invalid("recording not authorized: \(id)")
        }
        let url = root.appendingPathComponent(id + ".canonical")
        let bytes = Self.encode(canonical, id: id)
        let (names, size) = try inventory()
        if names.contains(url.lastPathComponent) {
            guard overwriteIdentical else { throw ReadyGoldenError.exists(url.path) }
            let existing = try Data(contentsOf: url)
            guard existing == bytes else {
                let expected = try Self.decode(existing, id: id)
                throw ReadyGoldenError.differs(url.path + " firstDifferingEscapedKey="
                    + Self.firstDifferingEscapedKey(expected, Data(canonical.utf8)))
            }
            return
        }
        guard size + bytes.count <= Self.byteLimit else { throw ReadyGoldenError.sizeCap(size + bytes.count) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try bytes.write(to: url, options: .withoutOverwriting)
        print("READY_CANONICAL_WRITE case=\(id) fileBytes=\(bytes.count) directoryFiles=\(names.count + 1) directoryBytes=\(size + bytes.count)")
    }
}

enum ReadyCanonicalGoldens {
    static let recordingRetired = true
    static let ids: Set<String> = [
        "f1-patched", "f4-journal", "f1-data", "f1-procedure", "f1-shape", "f1-hint",
        "f3-ranges-0", "f3-ranges-1", "f3-ranges-8", "f3-ranges-9", "x86-stream",
        "f1-ordinary", "f1-truncated", "f5-slice-0", "f5-slice-1",
        "authored-noreturn", "authored-returns", "repeats-three",
        "repeats-zero", "repeats-one", "repeats-two", "rehydrate-patched-gap-string"
    ]
    static let analysisIDs: Set<String> = [
        "f1-patched", "f4-journal", "f1-data", "f1-procedure", "f1-shape", "f1-hint",
        "f3-ranges-0", "f3-ranges-1", "f3-ranges-8", "f3-ranges-9", "x86-stream",
        "f1-ordinary", "f1-truncated", "f5-slice-0", "f5-slice-1"
    ]
    static let noReturnIDs: Set<String> = [
        "authored-noreturn", "authored-returns", "repeats-three",
        "repeats-zero", "repeats-one", "repeats-two"
    ]
    static let rehydrateIDs: Set<String> = ["rehydrate-patched-gap-string"]
    static let directory = TestSourceRoot.fileURL(#filePath)
        .deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("GoldenFixtures/ready-canonical-snapshots", isDirectory: true)

    private final class Session: @unchecked Sendable {
        let lock = NSLock()
        var seen = Set<String>()
        func mark(_ id: String) throws {
            lock.lock(); defer { lock.unlock() }
            guard seen.insert(id).inserted else { throw ReadyGoldenError.invalid("duplicate record: \(id)") }
        }
        func completed(_ expected: Set<String>) -> Bool {
            lock.lock(); defer { lock.unlock() }
            return seen.intersection(expected) == expected
        }
    }
    private static let session = Session()

    static func store() throws -> ReadyGoldenStore {
        let environment = ProcessInfo.processInfo.environment
        let record = environment["READY_RECORD_CANONICAL_SNAPSHOTS"] ?? "0"
        let overwrite = environment["READY_OVERWRITE_IDENTICAL_CANONICAL_SNAPSHOTS"] ?? "0"
        guard ["0", "1"].contains(record), ["0", "1"].contains(overwrite),
              record == "1" || overwrite == "0" else {
            throw ReadyGoldenError.invalid("invalid golden recording switches")
        }
        guard record != "1" || !recordingRetired else {
            throw ReadyGoldenError.invalid("recording retired; an owner ruling is required")
        }
        return ReadyGoldenStore(root: directory, recording: record == "1", overwriteIdentical: overwrite == "1")
    }

    static func finish(_ expected: Set<String>) throws {
        let store = try store()
        guard store.recording else { return }
        guard session.completed(expected) else { throw ReadyGoldenError.invalid("incomplete recording group") }
        let (names, _) = try store.inventory()
        guard expected.map({ $0 + ".canonical" }).allSatisfy(names.contains) else {
            throw ReadyGoldenError.invalid("recording group has missing files")
        }
    }

    private static func equal(_ left: String, _ right: String, _ context: String) throws {
        guard Data(left.utf8) == Data(right.utf8) else { throw ReadyGoldenError.differs(context) }
    }

    static func withSecondPath<T>(_ source: URL, _ body: (URL) throws -> T) throws -> T {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let other = root.appendingPathComponent("second-" + source.lastPathComponent)
        try Data(contentsOf: source).write(to: other, options: .withoutOverwriting)
        guard other.path != source.path, other.lastPathComponent != source.lastPathComponent else {
            throw ReadyGoldenError.invalid("two paths must differ in directory and filename")
        }
        return try body(other)
    }

    static func snapshot(_ id: String, current: WorkspaceSnapshot, sourceURL: URL? = nil,
        inputUUIDs: Set<UUID> = [], legacy: WorkspaceSnapshot? = nil,
        second: ((URL) throws -> (WorkspaceSnapshot, WorkspaceSnapshot))? = nil) throws {
        guard inputUUIDs.isEmpty else { throw ReadyGoldenError.invalid("unexpected authored input UUID: \(id)") }
        let store = try store()
        let actual = try AnalysisSnapshotCanonicalizer.canonicalGoldenSnapshot(current, sourceURL: sourceURL)
        guard store.recording else { try store.compare(actual, id: id); return }
        let old = try XCTUnwrap(legacy, "missing frozen output: \(id)")
        try equal(AnalysisSnapshotCanonicalizer.canonicalSnapshot(old),
            AnalysisSnapshotCanonicalizer.canonicalSnapshot(current), "raw frozen/current: \(id)")
        let expected = try AnalysisSnapshotCanonicalizer.canonicalGoldenSnapshot(old, sourceURL: sourceURL)
        try equal(expected, actual, "normalized frozen/current: \(id)")
        if let sourceURL {
            let second = try XCTUnwrap(second, "missing second-path producer: \(id)")
            try withSecondPath(sourceURL) { url in
                let (oldB, newB) = try second(url)
                try equal(AnalysisSnapshotCanonicalizer.canonicalSnapshot(oldB),
                    AnalysisSnapshotCanonicalizer.canonicalSnapshot(newB), "second raw frozen/current: \(id)")
                try equal(expected, AnalysisSnapshotCanonicalizer.canonicalGoldenSnapshot(oldB, sourceURL: url),
                    "second-path frozen determinism: \(id)")
                try equal(expected, AnalysisSnapshotCanonicalizer.canonicalGoldenSnapshot(newB, sourceURL: url),
                    "second-path current determinism: \(id)")
            }
        } else if second != nil {
            throw ReadyGoldenError.invalid("unexpected disk producer: \(id)")
        }
        try session.mark(id)
        try store.capture(expected, id: id)
    }
}

extension ReadyCanonicalGoldens {
    static let persistedFunctionID = UUID(uuidString: "13000000-0000-4000-8000-000000000001")!
    static let persistedBlockID = UUID(uuidString: "13000000-0000-4000-8000-000000000002")!
    static let persistedStringID = UUID(uuidString: "13000000-0000-4000-8000-000000000003")!
    static let persistedBinaryID = UUID(uuidString: "13000000-0000-4000-8000-000000000004")!
    static let persistedInputIDs: Set<UUID> = [persistedFunctionID, persistedBlockID, persistedStringID, persistedBinaryID]

    struct RehydrateInput {
        let persisted: ImageAnalysis
        let literal: StringLiteralSummary
        let expectedSections: [SectionSummary]
        let expectedRanges: [CodeDataRangeSummary]
    }

    static func rehydrateInput(_ analyzed: WorkspaceSnapshot, sourceURL: URL,
        literalAddress: UInt64) throws -> RehydrateInput {
        _ = try AnalysisSnapshotCanonicalizer.canonicalGoldenSnapshot(analyzed, sourceURL: sourceURL)
        let binary = try XCTUnwrap(analyzed.binaries.first)
        var value = try XCTUnwrap(analyzed.analysisBySlot[binary.slot])
        guard value.functions.count == 1, value.basicBlocks.count == 1,
              value.symbols.isEmpty, value.imports.isEmpty, value.indirectSymbols.isEmpty,
              value.exports.isEmpty, value.xrefs.isEmpty, value.controlFlowEdges.isEmpty,
              value.relocations.isEmpty, value.sourceLines.isEmpty else {
            throw ReadyGoldenError.invalid("rehydrate fixture shape changed")
        }
        let function = value.functions[0]
        let block = value.basicBlocks[0]
        guard Set(Mirror(reflecting: function).children.compactMap(\.label)) ==
                ["id", "name", "startAddress", "endAddress", "confidence", "noReturnProvenance"],
              Set(Mirror(reflecting: block).children.compactMap(\.label)) ==
                ["id", "functionID", "startAddress", "endAddress", "instructionCount"],
              block.functionID == function.id else {
            throw ReadyGoldenError.invalid("rehydrate identity/field contract changed")
        }
        value.functions = [FunctionSummary(id: persistedFunctionID, name: function.name,
            startAddress: function.startAddress, endAddress: function.endAddress,
            confidence: function.confidence, noReturnProvenance: function.noReturnProvenance)]
        value.basicBlocks = [BasicBlockSummary(id: persistedBlockID, functionID: persistedFunctionID,
            startAddress: block.startAddress, endAddress: block.endAddress, instructionCount: block.instructionCount)]
        let literal = StringLiteralSummary(id: persistedStringID, value: "hello",
            address: literalAddress, sourceSection: "__TEXT,__text", byteLength: 5)
        value.stringLiterals = [literal]
        value.refreshTypeCatalog()
        let pinnedBinary = AnalysisSnapshotCanonicalizer.goldenBinary(binary, id: persistedBinaryID)
        value.analysisInputFingerprint = try AnalysisFingerprintBuilder.fingerprint(binary: pinnedBinary, analysis: value)
        let sections = value.sections
        let ranges = value.codeDataRanges
        value.sections = []
        value.codeDataRanges = []
        value.diagnostics = []
        guard try AnalysisSnapshotCanonicalizer.inputUUIDs(in: value) == persistedInputIDs else {
            throw ReadyGoldenError.invalid("additional or missing rehydrate input UUID")
        }
        return RehydrateInput(persisted: value, literal: literal,
            expectedSections: sections, expectedRanges: ranges)
    }

    static func image(_ id: String, current: ImageAnalysis, input: ImageAnalysis,
        sourceURL: URL, inputUUIDs: Set<UUID>, legacy: ImageAnalysis? = nil,
        second: ((URL) throws -> (ImageAnalysis, ImageAnalysis, ImageAnalysis))? = nil) throws {
        guard inputUUIDs == persistedInputIDs else { throw ReadyGoldenError.invalid("rehydrate input UUID contract") }
        let store = try store()
        let actual = try AnalysisSnapshotCanonicalizer.canonicalImage(current, inputUUIDs: inputUUIDs)
        try equal(AnalysisSnapshotCanonicalizer.canonicalDocument(current.analysisInputFingerprint, inputUUIDs: inputUUIDs),
            AnalysisSnapshotCanonicalizer.canonicalDocument(input.analysisInputFingerprint, inputUUIDs: inputUUIDs),
            "full retained rehydrate fingerprint")
        guard store.recording else { try store.compare(actual, id: id); return }
        let old = try XCTUnwrap(legacy, "missing frozen rehydrate output")
        let expected = try AnalysisSnapshotCanonicalizer.canonicalImage(old, inputUUIDs: inputUUIDs)
        try equal(expected, actual, "frozen/current rehydrate")
        let producer = try XCTUnwrap(second, "missing second-path rehydrate producer")
        let originalInput = try AnalysisSnapshotCanonicalizer.canonicalImage(input, inputUUIDs: inputUUIDs)
        try withSecondPath(sourceURL) { url in
            let (inputB, oldB, newB) = try producer(url)
            guard try AnalysisSnapshotCanonicalizer.inputUUIDs(in: inputB) == inputUUIDs else {
                throw ReadyGoldenError.invalid("second-path rehydrate UUID contract")
            }
            try equal(originalInput, AnalysisSnapshotCanonicalizer.canonicalImage(inputB, inputUUIDs: inputUUIDs),
                "second-path rehydrate input determinism")
            try equal(expected, AnalysisSnapshotCanonicalizer.canonicalImage(oldB, inputUUIDs: inputUUIDs),
                "second-path frozen rehydrate determinism")
            try equal(expected, AnalysisSnapshotCanonicalizer.canonicalImage(newB, inputUUIDs: inputUUIDs),
                "second-path current rehydrate determinism")
        }
        try session.mark(id)
        try store.capture(expected, id: id)
    }
}
