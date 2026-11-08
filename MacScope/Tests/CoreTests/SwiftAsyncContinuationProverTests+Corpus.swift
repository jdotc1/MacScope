import Foundation
import XCTest
@testable import MacScope

extension SwiftAsyncContinuationProverTests {
    func testLinkedFixtureContinuationRelations() throws {
        let root = try ContinuationMeasurement.root()
        let oracle = try JSONDecoder().decode(ContinuationFixtureOracle.self,
            from: Data(contentsOf: root.appendingPathComponent("receipts/oracle/fixture-symbols.json")))
        let input = oracle.input + ".stripped"
        let entries = Set(oracle.functions.map(\.entry))
        let measurement = try ContinuationMeasurement.measure(input: input, entries: entries,
            output: root.appendingPathComponent("receipts/fixture/async.json"))
        // Address groups derived from the linked-symbol receipt beside the fixtures.
        let allowed: [Set<UInt64>] = [
            [0x100001080, 0x1000010cc, 0x100001114],
            [0x10000112c, 0x100001144, 0x1000011e0, 0x100001258],
            [0x1000012e0, 0x100001344, 0x1000013f8, 0x100001430],
            [0x100001464, 0x1000014dc, 0x100001524],
            [0x10000152c, 0x1000015c4, 0x1000017d4, 0x10000181c],
            [0x1000018ec, 0x10000193c, 0x10000198c],
            [0x1000019a0, 0x100001a70, 0x100001b34, 0x100001b7c],
            [0x100001da4, 0x100001dfc],
            [0x100001e38, 0x100001e98, 0x100001f00],
            [0x100001f3c, 0x100001fac, 0x100002010],
            [0x10000209c, 0x10000210c, 0x100002170],
            [0x100002194, 0x1000021f8],
            [0x100002238, 0x100002c30],
            [0x10000229c, 0x100002334, 0x10000254c, 0x100002598, 0x1000025e8, 0x100002648, 0x100002694, 0x1000026f0, 0x10000273c, 0x100002798, 0x1000027e4],
            [0x100001dfc, 0x100002a08],
            [0x100002a84, 0x100002c2c],
            [0x100002b60, 0x100002c2c],
            [0x100001dfc, 0x100002bb8],
        ]
        for edge in measurement.report.edges {
            XCTAssertTrue(allowed.contains { $0.contains(edge.source) && $0.contains(edge.resume) },
                          "Verified fixture relation is absent from linked-symbol ownership")
        }
        XCTAssertTrue(measurement.report.abstentions.allSatisfy { !$0.reason.isEmpty })
        let comparisons = oracle.functions.map { function -> ContinuationComparison in
            let chain = measurement.report.chains.first { $0.entry == function.entry }
            let actual = Set([function.entry] + (chain?.partials ?? []))
            let expected = Set([function.entry] + function.partials.map(\.address))
            return .init(entry: function.entry, exact: actual == expected, tqOnly: false,
                         missing: expected.subtracting(actual).sorted(), extra: actual.subtracting(expected).sorted(),
                         stops: measurement.report.abstentions.filter { actual.union(expected).contains($0.source) })
        }
        try ContinuationMeasurement.write(comparisons,
            to: root.appendingPathComponent("receipts/fixture/async-comparison.json"))
    }

    func testSampledContinuationBoundaries() throws {
        let root = try ContinuationMeasurement.root()
        let oracle = try JSONDecoder().decode(ContinuationCorpusOracle.self,
            from: Data(contentsOf: try ContinuationMeasurement.oracleURL()))
        XCTAssertEqual(oracle.entries.count, 50)
        let groups = Dictionary(grouping: oracle.entries, by: \.product)
        XCTAssertGreaterThanOrEqual(groups.count, 5)
        for name in groups.keys.sorted() {
            let rows = try XCTUnwrap(groups[name])
            let input = try XCTUnwrap(rows.first?.input)
            let measurement = try ContinuationMeasurement.measure(input: input, entries: Set(rows.map(\.entry)),
                output: root.appendingPathComponent("receipts/prover/\(name).json"))
            // Whole-product symbol ownership is independent of sample eligibility and chain pruning.
            let symbolRows = oracle.symbolEntries.filter { $0.product == name }
            var symbolOwners: [UInt64: Set<Int>] = [:]
            for (index, row) in symbolRows.enumerated() {
                for address in row.symbolAddresses { symbolOwners[address, default: []].insert(index) }
            }
            let falseEdges = measurement.report.edges.filter { edge in
                let sourceOwners = symbolOwners[edge.source] ?? []
                let resumeOwners = symbolOwners[edge.resume] ?? []
                return sourceOwners.isDisjoint(with: resumeOwners)
            }
            try ContinuationMeasurement.write(falseEdges,
                to: root.appendingPathComponent("receipts/prover/\(name)-false-edges.json"))
            XCTAssertTrue(falseEdges.isEmpty, "Verified product edge has no linked-symbol ownership match")
            // Also retain the stricter sampled DWARF-boundary comparison.
            for edge in measurement.report.edges where measurement.sampleWalkAddresses.contains(edge.source) {
                let owners = rows.filter { $0.oracleAddresses.contains(edge.source) }
                XCTAssertFalse(owners.isEmpty, "Verified edge has no independently established source owner")
                XCTAssertTrue(owners.allSatisfy { $0.oracleAddresses.contains(edge.resume) },
                              "Verified edge crosses an oracle boundary: \(edge.source) -> \(edge.resume)")
            }
            var comparisons: [ContinuationComparison] = []
            for row in rows {
                let chain = measurement.report.chains.first { $0.entry == row.entry }
                let actual = Set([row.entry] + (chain?.partials ?? []))
                let expected = Set(row.oracleAddresses)
                let missing = expected.subtracting(actual).sorted()
                let extra = actual.subtracting(expected).sorted()
                let stops = measurement.report.abstentions.filter { actual.union(expected).contains($0.source) }
                comparisons.append(.init(entry: row.entry, exact: actual == expected,
                    tqOnly: row.TQOnly, missing: missing, extra: extra, stops: stops))
                XCTAssertTrue(extra.isEmpty, "False chain membership at \(row.entry): \(extra)")
            }
            try ContinuationMeasurement.write(comparisons,
                to: root.appendingPathComponent("receipts/prover/\(name)-comparison.json"))
            let diagnostics = oracle.ineligible.filter { $0.product == name }.map { row in
                let chain = measurement.report.chains.first { $0.entry == row.entry }
                let actual = Set([row.entry] + (chain?.partials ?? []))
                let expected = Set(row.symbolAddresses)
                return ContinuationComparison(entry: row.entry, exact: actual == expected,
                    tqOnly: row.TQOnly, missing: expected.subtracting(actual).sorted(),
                    extra: actual.subtracting(expected).sorted(),
                    stops: measurement.report.abstentions.filter { actual.union(expected).contains($0.source) },
                    symbol: row.symbol)
            }
            try ContinuationMeasurement.write(diagnostics,
                to: root.appendingPathComponent("receipts/prover/\(name)-ineligible-comparison.json"))
        }
    }
}

private struct ContinuationFixtureOracle: Decodable {
    var input: String
    var functions: [Function]
    struct Function: Decodable {
        var entry: UInt64
        var partials: [Partial]
    }
    struct Partial: Decodable { var address: UInt64 }
}

private struct ContinuationCorpusOracle: Decodable {
    var entries: [Entry]
    var symbolEntries: [SymbolEntry]
    var ineligible: [SymbolEntry]
    struct SymbolEntry: Decodable {
        var product: String
        var entry: UInt64
        var symbol: String
        var symbolAddresses: [UInt64]
        var TQOnly: Bool
    }
    struct Entry: Decodable {
        var product: String
        var input: String
        var entry: UInt64
        var oracleAddresses: [UInt64]
        var TQOnly: Bool
    }
}

private struct ContinuationComparison: Codable {
    var entry: UInt64
    var exact: Bool
    var tqOnly: Bool
    var missing: [UInt64]
    var extra: [UInt64]
    var stops: [SwiftAsyncContinuationAbstention]
    var symbol: String? = nil
}

struct ContinuationMeasurement: Codable {
    var input: String
    var sourceCommit: String
    var entries: [UInt64]
    var sampleWalkAddresses: [UInt64]
    var wallSeconds: Double
    var report: SwiftAsyncContinuationReport
    var edgeCountsByKind: [String: Int]
    var abstentionsByReason: [String: Int]
    var barriersOnSample: [String: Int]
    var barriersAll: [String: Int]

    static func forInput(_ input: String) throws -> Self? {
        guard ProcessInfo.processInfo.environment["MACSCOPE_ASYNC_PROOF_ROOT"] != nil else { return nil }
        let root = try root()
        let fixture = try JSONDecoder().decode(ContinuationFixtureOracle.self,
            from: Data(contentsOf: root.appendingPathComponent("receipts/oracle/fixture-symbols.json")))
        if input == fixture.input + ".stripped" {
            return try measure(input: input, entries: Set(fixture.functions.map(\.entry)),
                output: root.appendingPathComponent("receipts/fixture/async.json"))
        }
        let oracle = try JSONDecoder().decode(ContinuationCorpusOracle.self,
            from: Data(contentsOf: try ContinuationMeasurement.oracleURL()))
        let selected = oracle.entries.filter { $0.input == input }
        guard let first = selected.first else { throw MeasurementError.retainedInputMismatch }
        return try measure(input: input, entries: Set(selected.map(\.entry)),
            output: root.appendingPathComponent("receipts/prover/\(first.product).json"))
    }

    static func root() throws -> URL {
        guard let path = ProcessInfo.processInfo.environment["MACSCOPE_ASYNC_PROOF_ROOT"] else {
            throw XCTSkip("Set MACSCOPE_ASYNC_PROOF_ROOT to the retained oracle and output directory")
        }
        return URL(fileURLWithPath: path, isDirectory: true)
    }

    static func oracleURL() throws -> URL {
        guard let path = ProcessInfo.processInfo.environment["MACSCOPE_ASYNC_PROOF_ORACLE"],
              path.hasPrefix("/") else { throw MeasurementError.missingOracleInput }
        return URL(fileURLWithPath: path)
    }

    static func measure(input: String, entries: Set<UInt64>, output: URL) throws -> Self {
        guard let sourceCommit = ProcessInfo.processInfo.environment["MACSCOPE_ASYNC_PROOF_COMMIT"],
              sourceCommit.count == 40 else { throw MeasurementError.missingSourceIdentity }
        if FileManager.default.fileExists(atPath: output.path) {
            let retained = try JSONDecoder().decode(Self.self, from: Data(contentsOf: output))
            guard retained.input == input, retained.entries == entries.sorted(), retained.sourceCommit == sourceCommit else {
                throw MeasurementError.retainedInputMismatch
            }
            return retained
        }
        let start = Date()
        print("Starting continuation measurement: \(input)")
        let data = try Data(contentsOf: URL(fileURLWithPath: input))
        let image = try MachOParser().parse(data, options: .init(recoverStringLiterals: false,
            recoverObjectiveCMetadata: false, recoverSwiftMetadata: false, parseCodeSignature: false))
        guard image.header.cpuType == MachOConstants.cpuTypeARM64 else {
            throw MeasurementError.unsupportedArchitecture
        }
        let offset = Int(image.selectedSliceOffset)
        let length = image.universalBinary?.selectedSlice.map { Int($0.size) } ?? data.count
        let thin = Data(data[offset..<(offset + length)])
        var rebases: [UInt64: UInt64] = [:]
        var binds: [UInt64: String] = [:]
        for fixup in image.dyldChainedFixups?.fixups ?? [] {
            if let target = fixup.rebaseTargetAddress { rebases[fixup.address] = target }
            else if let name = fixup.exactBoundSymbolName { binds[fixup.address] = name }
        }
        if image.dyldChainedFixups == nil, let command = image.loadCommands.first(where: {
            $0.command == MachOConstants.loadCommandDyldInfo || $0.command == MachOConstants.loadCommandDyldInfoOnly
        }) {
            func word(_ position: Int) throws -> Int {
                guard position >= 0, position <= thin.count, thin.count - position >= 4 else {
                    throw MeasurementError.truncatedDyldInfo
                }
                return (0..<4).reduce(0) { $0 | Int(thin[position + $1]) << ($1 * 8) }
            }
            let base = Int(command.offset)
            let ro = try word(base + 8), rs = try word(base + 12)
            let bo = try word(base + 16), bs = try word(base + 20)
            let classic = MachODyldInfoFixups.decode(data: thin,
                streams: .init(rebase: ro..<(ro + rs), bind: bo..<(bo + bs)), segments: image.segments)
            rebases = classic.rebaseTargets
            binds = classic.bindNames
        }
        let parser = SwiftMetadataParser(data: thin, sections: image.sections.map {
            .init(name: $0.sectionName, address: $0.address, fileOffset: UInt64($0.fileOffset),
                  size: $0.size, isExecutable: $0.isExecutableInstructions, isZeroFill: $0.isZeroFill,
                  segmentName: $0.segmentName)
        }, rebaseTargets: rebases, bindNames: binds)
        let metadata = parser.parseAsyncFunctions()
        // One walk per metadata entry/partial supplies both sampled and whole-product barrier counts.
        let report = SwiftAsyncContinuationProver.analyze(parser: parser, metadata: metadata,
            deadline: start.addingTimeInterval(900))
        let root = try root()
        let fixture = try JSONDecoder().decode(ContinuationFixtureOracle.self,
            from: Data(contentsOf: root.appendingPathComponent("receipts/oracle/fixture-symbols.json")))
        var sampleSources = entries
        if input == fixture.input + ".stripped" {
            sampleSources.formUnion(fixture.functions.flatMap { $0.partials.map(\.address) })
        } else {
            let oracle = try JSONDecoder().decode(ContinuationCorpusOracle.self,
                from: Data(contentsOf: try ContinuationMeasurement.oracleURL()))
            sampleSources.formUnion(oracle.entries.filter { $0.input == input }.flatMap(\.oracleAddresses))
        }
        // Include unpruned reachable sources so a conflict cannot hide a false downstream edge.
        var changed = true
        while changed {
            let count = sampleSources.count
            for edge in report.edges where sampleSources.contains(edge.source) { sampleSources.insert(edge.resume) }
            changed = sampleSources.count != count
        }
        let barriers = report.abstentions.filter { $0.reason == "unsupportedInstruction" }
        let measurement = Self(input: input, sourceCommit: sourceCommit, entries: entries.sorted(),
            sampleWalkAddresses: sampleSources.sorted(), wallSeconds: Date().timeIntervalSince(start),
            report: report, edgeCountsByKind: Dictionary(grouping: report.edges, by: { $0.kind.rawValue }).mapValues(\.count),
            abstentionsByReason: Dictionary(grouping: report.abstentions, by: \.reason).mapValues(\.count),
            barriersOnSample: Dictionary(grouping: barriers.filter { sampleSources.contains($0.source) },
                                        by: { $0.mnemonic ?? "unavailable" }).mapValues(\.count),
            barriersAll: Dictionary(grouping: barriers, by: { $0.mnemonic ?? "unavailable" }).mapValues(\.count))
        try write(measurement, to: output)
        XCTAssertLessThan(measurement.wallSeconds, 900, "Product exceeded the measurement budget")
        print("Continuation measurement complete: \(input), \(measurement.wallSeconds)s")
        return measurement
    }

    static func write<T: Encodable>(_ value: T, to output: URL) throws {
        guard !FileManager.default.fileExists(atPath: output.path) else { return }
        try FileManager.default.createDirectory(at: output.deletingLastPathComponent(), withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(value).write(to: output, options: .atomic)
    }

    enum MeasurementError: Error {
        case retainedInputMismatch, truncatedDyldInfo, missingSourceIdentity, unsupportedArchitecture, missingOracleInput
    }
}
