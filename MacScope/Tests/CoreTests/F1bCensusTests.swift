import Foundation
import XCTest
@testable import MacScope

/// Explicit, once-only diagnostics for the authorized libjpeg comparison census.
/// Normal suite discovery performs no binary analysis and creates no artifacts.
final class F1bCensusTests: XCTestCase {
    @MainActor
    func testLibjpegCompareDecisionCensus() throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["MACSCOPE_F1B_CENSUS"] == "1" else { return }
        try runCompareReceipt(witnessMode: false)
    }

    /// The ruling witness collects output metrics and site decisions in the same render pass.
    @MainActor
    func testLibjpegRulingWitness() throws {
        guard ProcessInfo.processInfo.environment["MACSCOPE_F1B_RULING_WITNESS"] == "1" else { return }
        try runCompareReceipt(witnessMode: true)
    }

    @MainActor
    private func runCompareReceipt(witnessMode: Bool) throws {
        let environment = ProcessInfo.processInfo.environment
        let destinationKey = witnessMode ? "MACSCOPE_F1B_RULING_WITNESS_DESTINATION" : "MACSCOPE_F1B_CENSUS_DESTINATION"
        let destinationPath = try XCTUnwrap(environment[destinationKey],
                                            "An explicit census destination directory is required")
        guard !destinationPath.isEmpty else { throw CensusError.invalidDestination }
        let destination = URL(fileURLWithPath: destinationPath, isDirectory: true)
        let files = ["census-started", "census.csv", "census-all-retained-ir.csv", "census-evidence.json",
                     "census-ir.txt", "pseudocode-census.txt", "witness.json", "pseudocode-all.txt",
                     "witness-site-decisions.csv"]
        for file in files where FileManager.default.fileExists(atPath: destination.appendingPathComponent(file).path) {
            throw CensusError.existingReceipt(file)
        }
        let baselineURL = TestWorkRoot.authorityURL("lanes-20261016/E-decompiler/F1b-i1-safe-causes/pseudocode-all.txt")
        let baseline = try String(contentsOf: baselineURL, encoding: .utf8)
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        let sourceHead = environment["MACSCOPE_WITNESS_SOURCE_HEAD"] ?? "unrecorded"
        try Data("sourceHead=\(sourceHead)\n".utf8).write(
            to: destination.appendingPathComponent("census-started"), options: .withoutOverwriting)

        let path = "/opt/homebrew/lib/libjpeg.8.dylib"
        let analyzed = try AnalysisEngine().analyze(url: URL(fileURLWithPath: path))
        let loaded = try loadHeaders(into: analyzed)
        let snapshot = loaded.snapshot
        let slot = snapshot.primarySlot
        let analysis = try XCTUnwrap(snapshot.analysis(in: slot))
        _ = try XCTUnwrap(snapshot.imageWideIndirectCalls(in: slot, compute: true),
                          "A complete warm image report is required")
        // These explicit options are the recorded run-3 options, independent of user defaults.
        let options = DecompilerOptions.default
        let printer = PseudocodePrinter(options: options)
        var emittedRows = [["function", "address", "reason", "detail"]]
        var retainedRows = [["function", "address", "reason", "detail", "instructionIndex", "emittedOccurrences"]]
        var pseudocode = ""
        var metricRows: [F1bWitnessOutputMetrics.Row] = []
        var decisionRows = [["function", "functionStart", "address", "instructionIndex", "decision", "reason", "detail", "emittedOccurrences"]]
        var emittedCounts: [String: Int] = [:]
        var retainedCounts: [String: Int] = [:]
        var perFunction: [[String: Any]] = []
        var candidateCount = 0
        var elidedCount = 0
        var foldedAwayCount = 0
        var duplicateOccurrenceCount = 0
        var emittedFunctionCount = 0
        let irURL = destination.appendingPathComponent("census-ir.txt")
        try Data().write(to: irURL, options: .withoutOverwriting)
        let irOutput = try FileHandle(forWritingTo: irURL)
        defer { try? irOutput.close() }

        for summary in analysis.functions {
            let input = snapshot.pseudocodeRenderInput(selectedAddress: summary.startAddress, in: slot)
            XCTAssertEqual(input.startAddress, summary.startAddress)
            // Same build and print calls, with every input field, as the canonical export renderer.
            // The warm-image inspector exposes pre-C2 IR, which is not this final rendering input.
            let built = printer.buildFunction(
                functionName: input.functionName, startAddress: input.startAddress,
                jumpTables: input.jumpTables, objcSelectors: input.objcSelectors,
                constantStrings: input.constantStrings, signatureOverrides: input.signatureOverrides,
                authoredCallSignaturesByTarget: input.authoredCallSignaturesByTarget,
                callerReturnWidth: input.callerReturnWidth, types: input.types, instructions: input.instructions)
            let projected = PseudocodePrinter.applyingStackLocalOverrides(input.stackLocalOverrides,
                to: MacIRFPEnvironmentPseudocodeProjection.project(built))
            let names = PseudocodeNameContext(function: projected, types: input.types,
                callTargetRenames: input.nameOverrides, registerNameOverrides: input.registerNameOverrides)
            let decisions = printer.compareElisionDecision(function: projected, names: names)
            let document = printer.print(function: built, types: input.types, nameOverrides: input.nameOverrides,
                registerNameOverrides: input.registerNameOverrides, stackLocalOverrides: input.stackLocalOverrides,
                resolvedIndirectCalls: input.resolvedIndirectCalls)
            let headerName = summary.name.replacingOccurrences(of: "\n", with: "\\n")
                .replacingOccurrences(of: "\r", with: "\\r")
            let header = "// FUNCTION name=\(headerName) start=0x\(String(summary.startAddress, radix: 16))\n"
            pseudocode += header + document.text + "\n\n"
            if witnessMode {
                metricRows.append(F1bWitnessOutputMetrics.extract(name: summary.name,
                    start: summary.startAddress, text: document.text))
            }
            // MacIRFunction is not Codable. Reflection retains all values, versions, source spans,
            // operation payloads and phi inputs without a second lifting or rendering invocation.
            try irOutput.write(contentsOf: Data((header + String(reflecting: projected) + "\n\n").utf8))

            var compareIndicesByAddress: [UInt64: [Int]] = [:]
            for (index, instruction) in projected.instructions.enumerated() {
                if case .intrinsic(nil, "compare", _) = instruction.operation {
                    compareIndicesByAddress[instruction.source.address, default: []].append(index)
                    candidateCount += 1
                    guard decisions[index] != nil else { throw CensusError.missingDecision(summary.name, index) }
                }
            }
            var occurrences: [Int: Int] = [:]
            for line in document.lines where isCompareStatement(line.text) {
                let source = try XCTUnwrap(line.source, "Rendered compare must retain its source span")
                let indices = compareIndicesByAddress[source.address] ?? []
                guard indices.count == 1, let index = indices.first else {
                    throw CensusError.ambiguousSource(summary.name, source.address, indices)
                }
                guard let decision = decisions[index], case let .keep(rejection) = decision else {
                    throw CensusError.emittedElidedCompare(summary.name, index)
                }
                occurrences[index, default: 0] += 1
                let detail = rejectionDetail(rejectionAddress: rejection.address, rejectionDetail: rejection.detail,
                    compare: projected.instructions[index], function: projected, lineNumber: line.lineNumber,
                    renderedText: line.text)
                emittedRows.append([summary.name, hex(source.address), rejection.reason.key, detail])
                emittedCounts[rejection.reason.key, default: 0] += 1
            }
            if !occurrences.isEmpty { emittedFunctionCount += 1 }
            var retainedInFunction = 0
            for index in decisions.keys.sorted() {
                guard let decision = decisions[index] else { continue }
                if witnessMode {
                    let instruction = projected.instructions[index]
                    let prefix = [summary.name, hex(summary.startAddress), hex(instruction.source.address), String(index)]
                    switch decision {
                    case .elide:
                        decisionRows.append(prefix + ["elide", "", "", String(occurrences[index, default: 0])])
                    case let .keep(rejection):
                        decisionRows.append(prefix + ["keep", rejection.reason.key,
                            rejectionDetail(rejectionAddress: rejection.address, rejectionDetail: rejection.detail,
                                compare: instruction, function: projected, lineNumber: nil, renderedText: nil),
                            String(occurrences[index, default: 0])])
                    }
                }
                switch decision {
                case .elide:
                    elidedCount += 1
                case let .keep(rejection):
                    let compare = projected.instructions[index]
                    let count = occurrences[index, default: 0]
                    let detail = rejectionDetail(rejectionAddress: rejection.address, rejectionDetail: rejection.detail,
                        compare: compare, function: projected, lineNumber: nil, renderedText: nil)
                    retainedRows.append([summary.name, hex(compare.source.address), rejection.reason.key,
                                         detail, String(index), String(count)])
                    retainedCounts[rejection.reason.key, default: 0] += 1
                    retainedInFunction += 1
                    if count == 0 { foldedAwayCount += 1 }
                    if count > 1 { duplicateOccurrenceCount += count - 1 }
                }
            }
            perFunction.append(["function": summary.name, "start": summary.startAddress,
                "instructions": projected.instructions.count, "candidates": decisions.count,
                "retainedIR": retainedInFunction, "emittedComparisons": occurrences.values.reduce(0, +),
                "structureFallback": String(reflecting: document.structureFallback)])
        }
        try csv(emittedRows).write(to: destination.appendingPathComponent("census.csv"), atomically: true, encoding: .utf8)
        try csv(retainedRows).write(to: destination.appendingPathComponent("census-all-retained-ir.csv"), atomically: true, encoding: .utf8)
        try pseudocode.write(to: destination.appendingPathComponent("pseudocode-census.txt"), atomically: true, encoding: .utf8)
        let identical = pseudocode == baseline
        let evidence: [String: Any] = [
            "sourceHead": sourceHead, "input": path, "functions": analysis.functions.count,
            "expectedFunctions": 914, "baselineEmittedComparisons": 465,
            "emittedComparisons": emittedRows.count - 1, "emittedFunctions": emittedFunctionCount,
            "candidateIRComparisons": candidateCount, "elidedIRComparisons": elidedCount,
            "retainedIRComparisons": retainedRows.count - 1, "retainedButFoldedAway": foldedAwayCount,
            "additionalRenderedOccurrences": duplicateOccurrenceCount,
            "emittedReasonCounts": emittedCounts, "retainedIRReasonCounts": retainedCounts,
            "completeWarmImageReport": true, "cancelled": Task.isCancelled,
            "options": String(describing: options), "canonicalTextIdenticalToBaseline": identical,
            "baseline": baselineURL.path, "perFunction": perFunction,
            "headerImport": ["version": "libjpeg-turbo 3.2.0", "jpegLibVersion": 80,
                "addedTypeCount": loaded.summary.addedNames.count,
                "importedPrototypeCount": loaded.summary.importedPrototypeCount,
                "skippedPrototypeCount": loaded.summary.skippedPrototypeCount,
                "diagnostics": loaded.summary.diagnostics],
            "method": "One render per function after a complete warm image report. Emitted compare source spans map uniquely to projected MacIR instruction indices and keep decisions. Retained IR includes sites suppressed by existing region or adjacent folds. No binary hashes or baseline regeneration."
        ]
        try JSONSerialization.data(withJSONObject: evidence, options: [.prettyPrinted, .sortedKeys])
            .write(to: destination.appendingPathComponent("census-evidence.json"), options: .atomic)
        XCTAssertEqual(analysis.functions.count, 914)
        if !witnessMode {
            XCTAssertEqual(emittedRows.count - 1, 465)
            XCTAssertEqual(emittedFunctionCount, 142)
        }
        XCTAssertEqual(candidateCount, elidedCount + retainedRows.count - 1)
        XCTAssertEqual(emittedRows.count - 1, retainedRows.count - 1 - foldedAwayCount + duplicateOccurrenceCount)
        if witnessMode {
            let baselineWitnessURL = baselineURL.deletingLastPathComponent().appendingPathComponent("witness.json")
            let baselineWitness = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: baselineWitnessURL)) as? [String: Any])
            let baselineMetrics = try XCTUnwrap(baselineWitness["outputMetrics"] as? [String: Any])
            let outputMetrics = F1bWitnessOutputMetrics.aggregate(metricRows)
            func count(_ metrics: [String: Any], _ key: String) throws -> Int {
                try XCTUnwrap((metrics[key] as? [String: Any])?["count"] as? Int)
            }
            let flagCount = try count(outputMetrics, "flagCompareStatements")
            let rawCount = try count(outputMetrics, "rawIntrinsicStatements")
            let flagDelta = flagCount - (try count(baselineMetrics, "flagCompareStatements"))
            let rawDelta = rawCount - (try count(baselineMetrics, "rawIntrinsicStatements"))
            var remainingBefore = baselineMetrics
            var remainingAfter = outputMetrics
            for key in ["flagCompareStatements", "rawIntrinsicStatements"] {
                remainingBefore.removeValue(forKey: key)
                remainingAfter.removeValue(forKey: key)
            }
            let otherMetricsIdentical = NSDictionary(dictionary: remainingBefore).isEqual(to: remainingAfter)
            let rendered = try count(outputMetrics, "functionsRendered")
            let failed = try count(outputMetrics, "functionsFailed")
            let invariants: [String: Bool] = ["rawDeltaEqualsCompareDelta": rawDelta == flagDelta,
                "otherOutputMetricsIdentical": otherMetricsIdentical,
                "rendered914": rendered == 914, "failed0": failed == 0,
                "emittedSitesMatchMetric": emittedRows.count - 1 == flagCount]
            let witness: [String: Any] = ["sourceHead": sourceHead, "input": path,
                "functions": analysis.functions.count, "outputMetrics": outputMetrics,
                "completeWarmImageReport": true, "cancelled": Task.isCancelled,
                "options": String(describing: options), "nativeSleighExport": false,
                "renderPath": "Canonical export build/print calls with identical input fields, collected once with source spans",
                "pseudocodeReceipt": "pseudocode-all.txt", "siteDecisions": "witness-site-decisions.csv",
                "emittedReasonCounts": emittedCounts, "retainedIRReasonCounts": retainedCounts,
                "candidateIRComparisons": candidateCount, "elidedIRComparisons": elidedCount,
                "retainedIRComparisons": retainedRows.count - 1, "retainedButFoldedAway": foldedAwayCount,
                "additionalRenderedOccurrences": duplicateOccurrenceCount,
                "baseline": baselineWitnessURL.path, "invariants": invariants,
                "invariantsPass": invariants.values.allSatisfy { $0 }, "targetMet": flagCount <= 400,
                "flagCompareDelta": flagDelta, "rawIntrinsicDelta": rawDelta]
            try csv(decisionRows).write(to: destination.appendingPathComponent("witness-site-decisions.csv"), atomically: true, encoding: .utf8)
            try pseudocode.write(to: destination.appendingPathComponent("pseudocode-all.txt"), atomically: true, encoding: .utf8)
            try JSONSerialization.data(withJSONObject: witness, options: [.prettyPrinted, .sortedKeys])
                .write(to: destination.appendingPathComponent("witness.json"), options: .atomic)
            for key in invariants.keys.sorted() {
                XCTAssertEqual(invariants[key], true, "Witness invariant failed: \(key)")
            }
            print("F1B_RULING_WITNESS_RECEIPT \(destination.path)")
        } else {
            XCTAssertTrue(identical, "Canonical census text differs from the retained run-3 baseline")
            print("F1B_CENSUS_RECEIPT \(destination.path)")
        }
    }

    private func hex(_ address: UInt64) -> String { "0x" + String(address, radix: 16) }

    private func isCompareStatement(_ text: String) -> Bool {
        text.range(of: #"^[ \t]*__compare\s*\("#, options: .regularExpression) != nil
    }

    private func csv(_ rows: [[String]]) -> String {
        rows.map { $0.map { "\"" + $0.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }.joined(separator: ",") }
            .joined(separator: "\n") + "\n"
    }

    private func rejectionDetail(rejectionAddress: UInt64, rejectionDetail: String, compare: MacIRInstruction,
                                 function: MacIRFunction, lineNumber: Int?, renderedText: String?) -> String {
        let blockers = function.instructions.filter { $0.source.address == rejectionAddress }
            .map { String(reflecting: $0) }.joined(separator: " | ")
        var result = "compare=\(String(reflecting: compare)); rejectionAddress=\(hex(rejectionAddress)); "
            + "rejectionDetail=\(rejectionDetail); rejectionInstructions=\(blockers)"
        if let lineNumber { result += "; renderedLine=\(lineNumber)" }
        if let renderedText { result += "; renderedText=\(renderedText)" }
        return result
    }

    @MainActor
    private func loadHeaders(into snapshot: WorkspaceSnapshot) throws
        -> (snapshot: WorkspaceSnapshot, summary: WorkspaceStore.CHeaderImportSummary) {
        let fixture = TestSourceRoot.url.appendingPathComponent("MacScope/Tests/CoreTests/Fixtures/libjpeg-turbo-3.2.0")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/clang")
        process.arguments = ["-E", "-P", "-x", "c", "-I", fixture.path, "-"]
        let input = Pipe()
        let output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.standardError
        try process.run()
        try input.fileHandleForWriting.write(contentsOf: Data("#include \"public-layout.c\"\n#include \"jpegint.h\"\n".utf8))
        try input.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw CensusError.headerPreprocessing(process.terminationStatus) }
        let store = WorkspaceStore(workspaceName: "F1b census header import", snapshot: snapshot,
            engine: AnalysisEngine(), autosaveScheduler: nil)
        let summary = store.defineTypesFromCHeader(String(decoding: data, as: UTF8.self))
        return (store.snapshot, summary)
    }

    private enum CensusError: Error {
        case invalidDestination
        case existingReceipt(String)
        case missingDecision(String, Int)
        case ambiguousSource(String, UInt64, [Int])
        case emittedElidedCompare(String, Int)
        case headerPreprocessing(Int32)
    }
}

// Exact run-3 metric extraction, retained here because the original helper is file-private.
private enum F1bWitnessOutputMetrics {
    static let returnMarker = "return unresolved_return_contract;"
    static let typeSpellings = ["undefined", "undefined1", "undefined2", "undefined4", "undefined8",
        "undefined16", "unknown", "unknown_t", "__unknown", "__unknown_type", "unresolved_type",
        "placeholder_type", "auto"]
    static let indirectPattern = #"\(\*[^()\n]+\)\s*\("#
    static let gotoPattern = #"\bgoto\s+[^;\n]+;"#
    static let labelPattern = #"(?m)^\s*([A-Za-z_][A-Za-z_0-9]*|0x[0-9a-fA-F]+):\s*$"#
    static let deadLabelPattern = #"(?m)^\s*(L_[A-Za-z0-9_]+):"#
    static let rawCastDerefPattern = #"\*\([A-Za-z_][A-Za-z0-9_ ]* \*+\)\("#
    static func deadLabels(_ text: String) -> Int {
        let ns = text as NSString
        return matches(deadLabelPattern, text).filter { match in
            let name = ns.substring(with: match.range(at: 1))
            return matches(#"\bgoto\s+"# + name + #"\b"#, text).isEmpty
        }.count
    }
    static func rawCastDerefs(_ text: String) -> Int { matches(rawCastDerefPattern, text).count }
    static func memberAccesses(_ text: String) -> Int { matches("->", text).count }
    static let statementPatterns = [
        "unmodeledInstructionLines": #"(?m)^[ \t]*\b__unknown\s*\("#,
        "rawBranches": #"(?m)^[ \t]*\b__branch\s*\("#,
        "indirectBranches": #"(?m)^[ \t]*\b__branch_register\s*\("#,
        "flagCompareStatements": #"(?m)^[ \t]*\b__compare\s*\("#,
        "rawIntrinsicStatements": #"(?m)^[ \t]*\b(__[a-z][a-z0-9_]*)\s*\("#
    ]
    static let excludedRawIntrinsics: Set<String> = ["__adrp"]
    static let warningKinds = ["warning", "diagnostic", "unsupported", "unresolved", "unknown", "failed", "error"]
    struct Row {
        let name: String
        let start: UInt64
        let counts: [String: Int]
        // Exact-text metrics are separate from the established lexed counts.
        let rawTextCounts: [String: Int]
        let warnings: [String: Int]
        let observedTypes: Set<String>
    }
    static func matches(_ pattern: String, _ text: String) -> [NSTextCheckingResult] {
        let regex = try! NSRegularExpression(pattern: pattern)
        return regex.matches(in: text, range: NSRange(text.startIndex..., in: text))
    }
    // Mask strings and comments while preserving newlines; marker-looking prose is not code.
    static func lex(_ text: String) -> (code: String, comments: [String]) {
        let chars = Array(text)
        var code = "", comments: [Int: String] = [:], index = 0, line = 0
        while index < chars.count {
            if chars[index] == "/", index + 1 < chars.count,
               chars[index + 1] == "/" || chars[index + 1] == "*" {
                let block = chars[index + 1] == "*"
                code += "  "; index += 2
                while index < chars.count {
                    if block, index + 1 < chars.count, chars[index] == "*", chars[index + 1] == "/" {
                        code += "  "; index += 2; break
                    }
                    if !block && chars[index] == "\n" { break }
                    comments[line, default: ""].append(chars[index])
                    code.append(chars[index] == "\n" ? "\n" : " ")
                    if chars[index] == "\n" { line += 1 }
                    index += 1
                }
                comments[line, default: ""] += " "
            } else if chars[index] == "\"" || chars[index] == "'" {
                let quote = chars[index]
                code.append(" "); index += 1
                while index < chars.count {
                    let char = chars[index]
                    code.append(char == "\n" ? "\n" : " "); index += 1
                    if char == "\n" { line += 1 }
                    if char == "\\", index < chars.count {
                        code.append(chars[index] == "\n" ? "\n" : " ")
                        if chars[index] == "\n" { line += 1 }
                        index += 1
                    } else if char == quote { break }
                }
            } else {
                code.append(chars[index])
                if chars[index] == "\n" { line += 1 }
                index += 1
            }
        }
        return (code, comments.keys.sorted().map { comments[$0]! })
    }
    static func extract(name: String, start: UInt64, text: String) -> Row {
        let (code, comments) = lex(text)
        let ns = code as NSString
        let typePattern = "(?:" + typeSpellings.joined(separator: "|") + ")"
        let declaration = #"\b("# + typePattern + #")\b\s*(?:\*\s*)*[A-Za-z_][A-Za-z_0-9]*(?:\s*\[[^\]\n]*\])?\s*(?=[,);=])"#
        let brace = ns.range(of: "{").location
        var localCount = 0, paramCount = 0, observed = Set<String>()
        let signatureEnd = brace == NSNotFound ? 0 : brace
        let openParen = ns.range(of: "(").location
        for match in matches(declaration, code) {
            if match.range.location < signatureEnd && openParen != NSNotFound && match.range.location > openParen {
                paramCount += 1
            } else if match.range.location > signatureEnd { localCount += 1 }
            else { continue }
            observed.insert(ns.substring(with: match.range(at: 1)))
        }
        var warnings: [String: Int] = [:]
        // One diagnostic bucket per rendered comment line, in this documented priority order.
        for comment in comments {
            if let kind = warningKinds.first(where: { !matches("(?i)\\b" + $0 + "\\b", comment).isEmpty }) {
                warnings[kind, default: 0] += 1
            }
        }
        let complete = brace != NSNotFound && code.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix("}")
        var counts = [
            "unresolvedReturnContractLines": text.components(separatedBy: .newlines).filter { $0.contains(returnMarker) }.count,
            "unresolvedIndirectCalls": matches(indirectPattern, code).count,
            "undefinedTypedLocals": localCount, "undefinedTypedParams": paramCount,
            "gotos": matches(gotoPattern, code).count, "labels": matches(labelPattern, code).count,
            "warnings": warnings.values.reduce(0, +), "functionsRendered": complete ? 1 : 0,
            "functionsFailed": complete ? 0 : 1
        ]
        for (key, pattern) in statementPatterns {
            counts[key] = matches(pattern, code).filter { match in
                key != "rawIntrinsicStatements" || !excludedRawIntrinsics.contains(ns.substring(with: match.range(at: 1)))
            }.count
        }
        return Row(name: name, start: start, counts: counts,
            rawTextCounts: ["deadLabels": deadLabels(text), "rawCastDerefs": rawCastDerefs(text),
                            "memberAccesses": memberAccesses(text)],
            warnings: warnings, observedTypes: observed)
    }
    static func aggregate(_ rows: [Row]) -> [String: Any] {
        func metric(_ value: (Row) -> Int) -> [String: Any] {
            let nonzero = rows.filter { value($0) > 0 }
            let top = nonzero.sorted { value($0) == value($1) ? $0.start < $1.start : value($0) > value($1) }
            return ["count": rows.reduce(0) { $0 + value($1) }, "functions": nonzero.count,
                "top20": top.prefix(20).map { ["name": $0.name, "start": $0.start, "count": value($0)] as [String: Any] }]
        }
        var result: [String: Any] = [:]
        for key in ["unresolvedReturnContractLines", "unresolvedIndirectCalls", "undefinedTypedLocals",
                    "undefinedTypedParams", "gotos", "labels", "warnings", "functionsRendered", "functionsFailed"] + statementPatterns.keys.sorted() {
            result[key] = metric { $0.counts[key, default: 0] }
        }
        for key in ["deadLabels", "rawCastDerefs", "memberAccesses"] {
            result[key] = metric { $0.rawTextCounts[key, default: 0] }
        }
        result["warningKinds"] = Dictionary(uniqueKeysWithValues: warningKinds.map { kind in
            (kind, metric { $0.warnings[kind, default: 0] })
        })
        result["typeSpellingsCounted"] = typeSpellings
        result["typeSpellingsObserved"] = Array(rows.reduce(into: Set<String>()) { $0.formUnion($1.observedTypes) }).sorted()
        result["method"] = ["structuredResults": "Unavailable from canonical pseudocodeText; no rerender for metrics",
            "unresolvedReturnMarker": returnMarker, "unresolvedIndirectCallRegex": indirectPattern,
            "gotoRegex": gotoPattern, "labelRegex": labelPattern,
            "deadLabelRegex": deadLabelPattern, "rawCastDerefRegex": rawCastDerefPattern,
            "exactTextMetrics": "deadLabels, rawCastDerefs and memberAccesses use exact canonical text per function, then sum; deadLabels excludes names targeted by whole-word goto in that function; rawCastDerefs and -> count occurrences, not lines; no string/comment masking",
            "codeStatementRegexes": statementPatterns,
            "rawIntrinsicStatementsExcludedCallees": excludedRawIntrinsics.sorted(),
            "codeStatements": "Standalone calls at the start of a rendered code line after indentation; strings/comments masked; assignments and nested calls excluded",
            "types": "undefinedTypedLocals and undefinedTypedParams count only typeSpellingsCounted in signature parameters or body declarations; MacIR emits concrete integer types, so these metrics are expected to be zero",
            "warnings": "Comment diagnostics only: whole-word case-insensitive warning-kind markers; first matching kind in warningKindsPriority wins; ordinary source/metadata comments excluded. MacIR emits unmodeled operations as code, so this metric is expected to be zero",
            "functionFailure": "Empty/missing-body or missing-final-brace output; nonthrowing canonical renderer has no separate error status",
            "lexing": "Strings and comments masked for code metrics; unresolvedReturnContractLines retains the original full-line contains computation",
            "baseline": "U2 head only; existing C2 width ablation cannot represent github/main without U2"]
        result["warningKindsPriority"] = warningKinds
        return result
    }
}
