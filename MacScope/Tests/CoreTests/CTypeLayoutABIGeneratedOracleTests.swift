import Foundation
import XCTest
@testable import MacScope

/// CP20 static Clang observations. Expected layout/classification never enters the
/// product: each case supplies only its complete C source and named C spellings.
/// Source identities are full canonical-declaration SHA-256 strings, not record
/// names (many independent cases intentionally name their record `R`).
final class CTypeLayoutABIGeneratedOracleTests: XCTestCase {
    private typealias Layout = CLayoutABIOracleTests.Layout
    private typealias Field = CLayoutABIOracleTests.Field
    private typealias Computed = CLayoutABIOracleTests.Computed

    private static let fixtureRoot = TestSourceRoot.fileURL(#filePath)
        .deletingLastPathComponent().appendingPathComponent("GoldenFixtures", isDirectory: true)

    private struct LayoutCase: Decodable {
        let id: String
        let canonicalSource: String?
        let expected: Layout
        private enum CodingKeys: String, CodingKey { case id; case canonicalSource = "canonical_source" }
        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            id = try container.decode(String.self, forKey: .id)
            canonicalSource = try container.decodeIfPresent(String.self, forKey: .canonicalSource)
            expected = try Layout(from: decoder)
        }
    }

    private struct LayoutFile: Decodable {
        let schema: String
        let preamble: String
        let dependencies: [String]
        let layouts: [LayoutCase]
    }

    /// Compiler-lowered transport is distinct from source sizeof/_Alignof.
    private struct TypeTransport: Decodable {
        let size: Int?
        let alignment: Int?
        let valueSize: Int?
        private enum CodingKeys: String, CodingKey {
            case size = "stack_size"
            case alignment = "stack_alignment"
            case valueSize = "abi_value_size"
        }
    }

    private struct CallCase: Decodable {
        let source: String
        let typeInfo: [String: ABICallOracleFile.TypeInfo]?
        let typeTransport: [String: TypeTransport]?
        let call: ABICallOracleFile.Call
        private enum CodingKeys: String, CodingKey { case source; case typeInfo = "type_info" }
        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            source = try container.decode(String.self, forKey: .source)
            typeInfo = try container.decodeIfPresent([String: ABICallOracleFile.TypeInfo].self, forKey: .typeInfo)
            typeTransport = try container.decodeIfPresent([String: TypeTransport].self, forKey: .typeInfo)
            call = try ABICallOracleFile.Call(from: decoder)
        }
    }

    private struct ReturnCase: Decodable {
        let source: String
        let typeInfo: [String: ABICallOracleFile.TypeInfo]?
        let typeTransport: [String: TypeTransport]?
        let typeKey: String
        let expected: ABICallOracleFile.ReturnProbe
        private enum CodingKeys: String, CodingKey {
            case source
            case typeInfo = "type_info"
            case typeKey = "type_key"
        }
        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            source = try container.decode(String.self, forKey: .source)
            typeInfo = try container.decodeIfPresent([String: ABICallOracleFile.TypeInfo].self, forKey: .typeInfo)
            typeTransport = try container.decodeIfPresent([String: TypeTransport].self, forKey: .typeInfo)
            typeKey = try container.decode(String.self, forKey: .typeKey)
            expected = try ABICallOracleFile.ReturnProbe(from: decoder)
        }
    }

    private struct ABIFile: Decodable {
        let schema: String
        let types: [String: ABICallOracleFile.TypeInfo]?
        let calls: [CallCase]
        let returnProbes: [String: ReturnCase]
        private enum CodingKeys: String, CodingKey {
            case schema, types, calls
            case returnProbes = "return_probes"
        }
    }

    private enum Observation {
        case pass
        case refused(String)
        case wrong(String)
    }

    private static func load<T: Decodable>(_ type: T.Type, from url: URL) throws -> T {
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(type, from: try A64OracleGzip.decompress(data))
    }

    /// Only a reachable anonymous parent promotes its children. The historical
    /// helper incorrectly crosses named parents; retain its other exact checks.
    private static func visibleFields(_ layout: Layout, includingUnnamedBits: Bool = false) -> [Field] {
        var reachableAnonymous = Set<Int>()
        var result: [Field] = []
        for field in layout.fields {
            reachableAnonymous = Set(reachableAnonymous.filter { $0 < field.depth })
            let visible = field.depth == 1 || reachableAnonymous.contains(field.depth - 1)
            if field.name == nil {
                if field.bitWidth == nil {
                    if visible { reachableAnonymous.insert(field.depth) }
                } else if includingUnnamedBits && visible {
                    result.append(field)
                }
            } else if visible {
                result.append(field)
            }
        }
        return result
    }

    private static func layoutDifference(_ expected: Layout, _ actual: Computed) -> String? {
        guard actual.size == expected.size else { return "size \(String(describing: actual.size)); Clang \(expected.size)" }
        guard actual.align == expected.align else { return "alignment \(String(describing: actual.align)); Clang \(expected.align)" }
        let bits = visibleFields(expected, includingUnnamedBits: true).filter { $0.bitWidth != nil }
        guard actual.bits.count == bits.count else { return "bitfield count \(actual.bits.count); Clang \(bits.count)" }
        for (got, want) in zip(actual.bits, bits) {
            guard got.name == (want.name ?? ""), got.offset == want.bitOffset, got.width == want.bitWidth else {
                return "bitfield \(got.name) at \(String(describing: got.offset)), width \(got.width); Clang \(want.bitOffset), \(want.bitWidth ?? 0)"
            }
        }
        for field in visibleFields(expected) {
            let name = field.name ?? ""
            guard let offset = actual.offsets[name] else { return "missing member \(name)" }
            if field.bitWidth == nil && offset != field.byteOffset {
                return "member \(name) at \(offset); Clang \(field.byteOffset)"
            }
        }
        let names = Set(visibleFields(expected).compactMap(\.name))
        let unexpected = Set(actual.offsets.keys).subtracting(names)
        guard unexpected.isEmpty else { return "unexpected members: " + unexpected.sorted().joined(separator: ", ") }
        return nil
    }

    /// Unknown total layout never excuses an incorrect concrete prefix.
    private static func prefixDifference(_ expected: Layout, _ actual: Computed) -> String? {
        let fields = Dictionary(visibleFields(expected).compactMap { field in
            field.name.map { ($0, field) }
        }, uniquingKeysWith: { first, _ in first })
        for (name, offset) in actual.offsets {
            guard let field = fields[name] else { return "unexpected concrete prefix member \(name)" }
            if field.bitWidth == nil && offset != field.byteOffset {
                return "concrete prefix \(name) at \(offset); Clang \(field.byteOffset)"
            }
        }
        let bits = visibleFields(expected, includingUnnamedBits: true).filter { $0.bitWidth != nil }
        guard actual.bits.count <= bits.count else { return "more concrete prefix bitfields than Clang" }
        for (got, want) in zip(actual.bits, bits) {
            guard got.name == (want.name ?? ""), got.offset == want.bitOffset, got.width == want.bitWidth else {
                return "concrete prefix bitfield \(got.name) differs from Clang"
            }
        }
        return nil
    }

    private static func observeLayout(_ item: LayoutCase, file: LayoutFile) -> Observation {
        let source = item.canonicalSource
            ?? ([file.preamble] + file.dependencies + [item.expected.declaration]).joined(separator: "\n") + "\n"
        let imported = CTypeHeaderParser.parse(source)
        let first = CLayoutABIOracleTests.computed(item.expected.name, in: CLayoutABIOracleTests.catalog(imported.types))
        guard let first else {
            return imported.diagnostics.isEmpty ? .wrong("declaration silently absent without diagnostic")
                : .refused("declaration-not-imported-with-diagnostic\n" + imported.diagnostics.joined(separator: "\n"))
        }
        let reimported = CTypeHeaderParser.parse(CTypeHeaderRenderer.render(types: imported.types))
        let second = CLayoutABIOracleTests.computed(item.expected.name, in: CLayoutABIOracleTests.catalog(reimported.types))
        guard first == second else { return .wrong("export/re-import changed the computed layout or concrete prefix") }
        if first.size == nil || first.align == nil {
            if let difference = prefixDifference(item.expected, first) { return .wrong(difference) }
            // This subtype is a layout-engine abstention, not a claimed parser
            // diagnostic-and-drop refusal. Existing model tests preserve it.
            return imported.diagnostics.isEmpty ? .refused("layout-engine-nil-without-parser-diagnostic")
                : .refused("unknown-layout-with-diagnostic\n" + imported.diagnostics.joined(separator: "\n"))
        }
        if let difference = layoutDifference(item.expected, first) { return .wrong(difference) }
        return .pass
    }

    private static func unboundReason(_ reason: MacIRABIUnboundReason) -> String {
        switch reason {
        case let .unsupportedType(type): return "unsupportedType:" + type
        case .registerExhausted: return "registerExhausted"
        case .dependentOnUnsupportedEarlierParameter: return "dependentOnUnsupportedEarlierParameter"
        case .conflictingEvidence: return "conflictingEvidence"
        case .unresolvedLegacy: return "unresolvedLegacy"
        }
    }

    private static func validateGenerated(_ location: DarwinARM64RichParameterLocation,
                                           info: ABICallOracleFile.TypeInfo,
                                           transport: TypeTransport?,
                                           expected: [ABICallOracleFile.Location]) -> Bool {
        if case let .entryStack(_, size, alignment) = location {
            // Clang 0b81c46b...: packed HFA source alignment 1, stack alignment 4.
            // Clang 097843d2...: sizeof(S5) 5, coerced i64 stack transport 8.
            guard expected.count == 1, let transport else { return false }
            return size == expected[0].size && size == transport.size && alignment == transport.alignment
        }
        if case let .composite(pieces) = location, let valueSize = transport?.valueSize {
            guard pieces.map(\.size) == expected.compactMap(\.size) else { return false }
            var cursor = 0
            for piece in pieces {
                guard piece.valueByteOffset == cursor, piece.size > 0 else { return false }
                cursor += piece.size
            }
            return cursor == valueSize
        }
        return ABICallOracleRunner.validate(location, info: info, expected: expected)
    }

    private static func knownTypeDifference(_ info: ABICallOracleFile.TypeInfo,
                                            catalog: [String: TypeDefinition]) -> String? {
        if let size = TypeDefinition.size(ofType: info.c, in: catalog), size != info.size {
            return "type \(info.c) size \(size); Clang \(info.size)"
        }
        if let alignment = TypeDefinition.alignment(ofType: info.c, in: catalog), alignment != info.align {
            return "type \(info.c) alignment \(alignment); Clang \(info.align)"
        }
        return nil
    }

    private static func observeCall(_ item: CallCase, globalTypes: [String: ABICallOracleFile.TypeInfo]) -> Observation {
        let call = item.call
        let types = item.typeInfo ?? globalTypes
        guard call.fixedCount >= 0, call.fixedCount <= call.types.count,
              call.parameters.count == call.types.count else { return .wrong("HARNESS: inconsistent formal counts") }
        let named = Array(call.parameters.prefix(call.fixedCount))
        guard named.allSatisfy({ !$0.anonymous }), call.parameters.dropFirst(call.fixedCount).allSatisfy(\.anonymous)
        else { return .wrong("HARNESS: inconsistent anonymous flags") }
        var spellings: [String] = []
        for parameter in named {
            guard let info = types[parameter.type] else { return .wrong("HARNESS: unknown type key \(parameter.type)") }
            spellings.append(info.c)
        }
        let imported = CTypeHeaderParser.parse(item.source)
        let catalog = CLayoutABIOracleTests.catalog(imported.types)
        for key in named.map(\.type) + [call.returnType] {
            guard let info = types[key] else { return .wrong("HARNESS: missing type \(key)") }
            if let difference = knownTypeDifference(info, catalog: catalog) { return .wrong(difference) }
        }
        let resolver = TypeAtlasDarwinARM64LayoutResolver(catalog: catalog)
        let bound = DarwinARM64ParameterBinder.bindRich(parameterTypes: spellings, isVariadic: call.variadic, resolver: resolver)
        guard bound.count == named.count else { return .wrong("HARNESS: named-formal count changed") }
        var refusals: [String] = []
        for (parameter, location) in zip(named, bound) {
            if case let .unbound(reason) = location {
                refusals.append("p\(parameter.index):" + unboundReason(reason))
                continue
            }
            let expected = parameter.locations.map(\.rendered).joined(separator: ",")
            let actual = ABICallOracleRunner.render(location)
            let indirect: Bool
            if case .indirect = location { indirect = true } else { indirect = false }
            guard let info = types[parameter.type], actual == expected, indirect == parameter.indirect,
                  validateGenerated(location, info: info, transport: item.typeTransport?[parameter.type],
                                    expected: parameter.locations) else {
                return .wrong("p\(parameter.index) expected \(expected), actual \(actual), indirect \(indirect); exact shape comparison failed")
            }
        }
        guard let resultInfo = types[call.returnType] else { return .wrong("HARNESS: missing result type") }
        if case let .unbound(reason) = DarwinARM64ParameterBinder.returnLocation(for: resultInfo.c, resolver: resolver) {
            refusals.append("r:" + unboundReason(reason))
        }
        return refusals.isEmpty ? .pass : .refused("prototype-unbound\n" + refusals.joined(separator: "\n"))
    }

    private static func observeReturn(_ item: ReturnCase, globalTypes: [String: ABICallOracleFile.TypeInfo]) -> Observation {
        let types = item.typeInfo ?? globalTypes
        guard item.expected.matched, let info = types[item.typeKey] else { return .wrong("HARNESS: missing or uncorroborated return fixture") }
        let imported = CTypeHeaderParser.parse(item.source)
        let catalog = CLayoutABIOracleTests.catalog(imported.types)
        if let difference = knownTypeDifference(info, catalog: catalog) { return .wrong(difference) }
        let resolver = TypeAtlasDarwinARM64LayoutResolver(catalog: catalog)
        let bound = DarwinARM64ParameterBinder.returnLocation(for: info.c, resolver: resolver)
        let expected = item.expected.locations.map(\.rendered).joined(separator: ",")
        let actual: String
        let shapeOK: Bool
        switch bound {
        case .void:
            return item.expected.locations.isEmpty ? .pass : .wrong("void return differs from nonempty compiler locations")
        case let .single(register):
            actual = ABICallOracleRunner.render(register)
            shapeOK = item.expected.locations.count == 1 && item.expected.locations[0].size == info.size
        case let .composite(pieces):
            actual = pieces.map { ABICallOracleRunner.render($0.register) }.joined(separator: ",")
            shapeOK = validateGenerated(.composite(pieces: pieces), info: info,
                                        transport: item.typeTransport?[item.typeKey], expected: item.expected.locations)
        case let .indirect(index, size, alignment):
            actual = "x\(index)(indirect result)"
            shapeOK = size == info.size && alignment == info.align
        case let .unbound(reason):
            return .refused("return-unbound\n" + unboundReason(reason))
        }
        return actual == expected && shapeOK ? .pass : .wrong("return expected \(expected), actual \(actual), shapeOK \(shapeOK)")
    }

    private static func isCanonicalID(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private static func ratchet(_ observations: [(String, Observation)], directory: URL, recordVariable: String,
                                file: StaticString = #filePath, line: UInt = #line) throws {
        let record = ProcessInfo.processInfo.environment[recordVariable] == "1"
        let passURL = directory.appendingPathComponent("baseline-pass.txt")
        let refusalURL = directory.appendingPathComponent("baseline-refused.json")
        var passing = Set<String>()
        var refused: [String: String] = [:]
        var failures: [String] = []
        var seen = Set<String>()
        for (id, observation) in observations {
            guard isCanonicalID(id), seen.insert(id).inserted else {
                failures.append("HARNESS: invalid or repeated canonical ID \(id)")
                continue
            }
            switch observation {
            case .pass: passing.insert(id)
            case let .refused(reason): refused[id] = reason
            case let .wrong(detail): failures.append(id + ": " + detail)
            }
        }
        XCTAssertFalse(passing.isEmpty, "generated passing baseline must be nonempty", file: file, line: line)
        let previousPass: Set<String>
        if let text = try? String(contentsOf: passURL, encoding: .utf8) {
            previousPass = Set(text.split(whereSeparator: \.isNewline).map(String.init))
        } else if record {
            previousPass = []
        } else {
            return XCTFail("Missing baseline-pass.txt in \(directory.path)", file: file, line: line)
        }
        let previousRefused: [String: String]
        if let data = try? Data(contentsOf: refusalURL) {
            previousRefused = try JSONDecoder().decode([String: String].self, from: data)
        } else if record {
            previousRefused = [:]
        } else {
            return XCTFail("Missing baseline-refused.json in \(directory.path)", file: file, line: line)
        }
        let lost = previousPass.subtracting(passing).sorted()
        failures += lost.map { "old PASS no longer passes: " + $0 }
        let overlap = previousPass.intersection(previousRefused.keys)
        failures += overlap.sorted().map { "HARNESS: baseline pins both PASS and refusal: " + $0 }
        for (id, reason) in previousRefused where !passing.contains(id) {
            if refused[id] != reason {
                let now = refused[id].map { "REFUSED, new reason: " + $0 } ?? "no longer refused (status: PASS or absent)"
                failures.append("old refusal ID/reason changed: " + id + "\n  baseline reason: " + reason + "\n  " + now)
            }
        }
        let unrecordedRefusals = Set(refused.keys).subtracting(previousRefused.keys)
        if !record { failures += unrecordedRefusals.sorted().map { "unrecorded refusal: " + $0 } }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"), file: file, line: line)
        print("Generated oracle \(directory.lastPathComponent): \(passing.count) PASS, \(refused.count) REFUSED, \(failures.count) gate failures")
        // Never bless an old PASS becoming a refusal/wrong answer, a changed
        // established refusal reason, or any numeric/shape/round-trip mismatch.
        if record, failures.isEmpty, !passing.isEmpty {
            try (passing.sorted().joined(separator: "\n") + "\n").write(to: passURL, atomically: true, encoding: .utf8)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
            try encoder.encode(refused).write(to: refusalURL, options: .atomic)
        }
    }

    func testGeneratedRecordLayoutRatchet() throws {
        let directory = Self.fixtureRoot.appendingPathComponent("c-layout-generated-oracle", isDirectory: true)
        let file = try Self.load(LayoutFile.self, from: directory.appendingPathComponent("layouts.json.gz"))
        XCTAssertEqual(file.schema, "macscope-c-layout-abi-oracle-slice-1-gen-1")
        XCTAssertFalse(file.layouts.isEmpty)
        XCTAssertLessThanOrEqual(file.layouts.count, 20_000)
        let observations = file.layouts.map { ($0.id, Self.observeLayout($0, file: file)) }
        // xcodebuild forwards TEST_RUNNER_MACSCOPE_GENERATED_LAYOUT_ORACLE_RECORD_BASELINE.
        try Self.ratchet(observations, directory: directory, recordVariable: "MACSCOPE_GENERATED_LAYOUT_ORACLE_RECORD_BASELINE")
    }

    func testGeneratedCallAndReturnRatchet() throws {
        let directory = Self.fixtureRoot.appendingPathComponent("abi-call-generated-oracle", isDirectory: true)
        let file = try Self.load(ABIFile.self, from: directory.appendingPathComponent("call-vectors.json.gz"))
        XCTAssertEqual(file.schema, "macscope-darwin-arm64-layout-abi-oracle-1-gen-1")
        XCTAssertFalse(file.calls.isEmpty)
        XCTAssertLessThanOrEqual(file.calls.count, 5_000)
        XCTAssertLessThanOrEqual(file.returnProbes.count, 5_000)
        var observations = file.calls.map { ($0.call.id, Self.observeCall($0, globalTypes: file.types ?? [:])) }
        observations += file.returnProbes.keys.sorted().map { id in
            (id, Self.observeReturn(file.returnProbes[id]!, globalTypes: file.types ?? [:]))
        }
        // xcodebuild forwards TEST_RUNNER_MACSCOPE_GENERATED_ABI_ORACLE_RECORD_BASELINE.
        try Self.ratchet(observations, directory: directory, recordVariable: "MACSCOPE_GENERATED_ABI_ORACLE_RECORD_BASELINE")
    }

    func testNamedAggregateBoundaryBlocksAnonymousPromotion() throws {
        // Clang c905cb82c215a7fd8b0473269fe99c575087a45961cfa0f75967780df8125bbf: size/alignment 4, named offset 0; x is nested.
        let parsed = CTypeHeaderParser.parse("struct R { struct { union { int x; }; } named; };")
        let actual = try XCTUnwrap(CLayoutABIOracleTests.computed("R", in: CLayoutABIOracleTests.catalog(parsed.types)))
        XCTAssertEqual(actual.size, 4)
        XCTAssertEqual(actual.align, 4)
        XCTAssertEqual(actual.offsets, ["named": 0])
        let fields = [Field(name: "named", depth: 1, byteOffset: 0, bitOffset: 0, bitWidth: nil),
                      Field(name: nil, depth: 2, byteOffset: 0, bitOffset: 0, bitWidth: nil),
                      Field(name: "x", depth: 3, byteOffset: 0, bitOffset: 0, bitWidth: nil)]
        let expected = Layout(name: "R", kind: "struct", family: "named-anonymous-boundary", declaration: "", size: 4, align: 4, fields: fields)
        XCTAssertEqual(Self.visibleFields(expected).compactMap(\.name), ["named"])
        XCTAssertNil(Self.layoutDifference(expected, actual))
    }

    private func assertSafeMinimalRecord(_ source: String, clangSize: Int, clangAlignment: Int,
                                         file: StaticString = #filePath, line: UInt = #line) throws {
        let parsed = CTypeHeaderParser.parse(source)
        let first = CLayoutABIOracleTests.computed("R", in: CLayoutABIOracleTests.catalog(parsed.types))
        guard let first else {
            XCTAssertFalse(parsed.diagnostics.isEmpty, "silently dropped declaration", file: file, line: line)
            return
        }
        let expected = Layout(name: "R", kind: "union", family: "minimized", declaration: source,
                              size: clangSize, align: clangAlignment,
                              fields: [Field(name: "f0", depth: 1, byteOffset: 0, bitOffset: 0, bitWidth: nil)])
        if first.size == nil || first.align == nil {
            XCTAssertFalse(parsed.diagnostics.isEmpty, "new unsupported form must be diagnosed", file: file, line: line)
            XCTAssertNil(Self.prefixDifference(expected, first), file: file, line: line)
        } else {
            XCTAssertNil(Self.layoutDifference(expected, first), file: file, line: line)
        }
        let reparsed = CTypeHeaderParser.parse(CTypeHeaderRenderer.render(types: parsed.types))
        let second = CLayoutABIOracleTests.computed("R", in: CLayoutABIOracleTests.catalog(reparsed.types))
        XCTAssertEqual(first, second, "render/re-import must preserve exactness or abstention", file: file, line: line)
    }

    /// Held-out review roots include multiple visible fields and cases whose
    /// total size is correct but whose member name is corrupted. A diagnosed
    /// unknown total still has to preserve every concrete prefix it reports.
    private func assertSafeReviewRecord(_ source: String, clangSize: Int, clangAlignment: Int,
                                        clangOffsets: [String: Int], clangKind: String = "struct", requiredFollowingFields: [String] = [],
                                        clangBits: [(name: String, offset: Int, width: Int)] = [],
                                        file: StaticString = #filePath, line: UInt = #line) throws {
        let parsed = CTypeHeaderParser.parse(source)
        let catalog = CLayoutABIOracleTests.catalog(parsed.types)
        guard let first = CLayoutABIOracleTests.computed("R", in: catalog) else {
            XCTAssertFalse(parsed.diagnostics.isEmpty, "silently dropped review declaration", file: file, line: line)
            return
        }
        let bitNames = Set(clangBits.map(\.name).filter { !$0.isEmpty })
        let fields = clangOffsets.keys.sorted().filter { !bitNames.contains($0) }.map { name in
            Field(name: name, depth: 1, byteOffset: clangOffsets[name]!, bitOffset: clangOffsets[name]! * 8, bitWidth: nil)
        } + clangBits.map { bit in
            Field(name: bit.name.isEmpty ? nil : bit.name, depth: 1, byteOffset: bit.offset / 8,
                  bitOffset: bit.offset, bitWidth: bit.width)
        }
        let expected = Layout(name: "R", kind: clangKind, family: "review-round-1", declaration: source,
                              size: clangSize, align: clangAlignment, fields: fields)
        if first.size == nil || first.align == nil {
            XCTAssertFalse(parsed.diagnostics.isEmpty, "reviewed unsupported form must be diagnosed", file: file, line: line)
            XCTAssertNil(Self.prefixDifference(expected, first), file: file, line: line)
        } else {
            XCTAssertNil(Self.layoutDifference(expected, first), file: file, line: line)
        }
        let names = Set(catalog["R"]?.fields.map(\.name) ?? [])
        for name in requiredFollowingFields {
            XCTAssertTrue(names.contains(name), "recovery consumed following declaration \(name)", file: file, line: line)
        }
        let reparsed = CTypeHeaderParser.parse(CTypeHeaderRenderer.render(types: parsed.types))
        let second = CLayoutABIOracleTests.computed("R", in: CLayoutABIOracleTests.catalog(reparsed.types))
        XCTAssertEqual(first, second, "review render/re-import must preserve exactness or abstention", file: file, line: line)
    }

    /// Each location is read from the frozen Clang caller/callee and LLVM IR
    /// witness. Compiler metrics are expectations only; the product receives
    /// the C declaration and formal/result spellings through the usual helpers.
    private func assertSafeReviewRecordAndABI(
        _ source: String, id: String, clangSize: Int, clangAlignment: Int,
        clangOffsets: [String: Int], requiredFollowingFields: [String] = [],
        clangBits: [(name: String, offset: Int, width: Int)] = [],
        clangArgument: [(String, Int)], clangNext: String, clangReturn: [(String, Int)],
        clangIndirect: Bool = false, file: StaticString = #filePath, line: UInt = #line
    ) throws {
        try assertSafeReviewRecord(source, clangSize: clangSize, clangAlignment: clangAlignment,
                                   clangOffsets: clangOffsets, requiredFollowingFields: requiredFollowingFields,
                                   clangBits: clangBits, file: file, line: line)
        let types: [String: Any] = [
            "r": ["c": "struct R", "size": clangSize, "align": clangAlignment, "kind": "aggregate"],
            "i": ["c": "int", "size": 4, "align": 4, "kind": "int"]
        ]
        func locations(_ values: [(String, Int)]) -> [[String: Any]] {
            values.map { register, size in
                let indirect = register.hasSuffix("(indirect result)")
                return ["register": register.replacingOccurrences(of: "(indirect result)", with: ""),
                        "size": size, "indirect_result": indirect]
            }
        }
        let callObject: [String: Any] = [
            "id": id, "source": source, "type_info": types, "types": ["r", "i"],
            "return_type": "r", "fixed_count": 2, "variadic": false,
            "family": "review-round-2", "signature": "struct R target(struct R, int)",
            "parameters": [
                ["index": 0, "type": "r", "effective_type": "r", "anonymous": false,
                 "indirect": clangIndirect, "locations": locations(clangArgument)],
                ["index": 1, "type": "i", "effective_type": "i", "anonymous": false,
                 "indirect": false, "locations": locations([(clangNext, 4)])]
            ]
        ]
        let call = try JSONDecoder().decode(CallCase.self, from: JSONSerialization.data(withJSONObject: callObject))
        if case let .wrong(detail) = Self.observeCall(call, globalTypes: [:]) {
            XCTFail("review call differs from Clang: \(detail)", file: file, line: line)
        }
        let resultObject: [String: Any] = [
            "source": source, "type_info": types, "type_key": "r", "matched": true,
            "locations": locations(clangReturn)
        ]
        let result = try JSONDecoder().decode(ReturnCase.self, from: JSONSerialization.data(withJSONObject: resultObject))
        if case let .wrong(detail) = Self.observeReturn(result, globalTypes: [:]) {
            XCTFail("review return differs from Clang: \(detail)", file: file, line: line)
        }
    }

    func testQualifiedFunctionPointerMemberDoesNotDisappear() throws {
        // Clang 5fd212f8df10644773e067970dfd1b5e11fd2155737bed26f52135bb5775b7b1: sizeof 8, alignment 8, f0 at 0.
        try assertSafeMinimalRecord("union R {\n  int (*const f0)(int);\n};\n", clangSize: 8, clangAlignment: 8)
    }

    func testQualifiedPointerToArrayMemberDoesNotDisappear() throws {
        // Clang 21d0d13504cac66e2765f58a420883022bfa37b0deb8b766c9d9e2ab1621f6e0: sizeof 8, alignment 8, f0 at 0.
        try assertSafeMinimalRecord("union R {\n  int (*const f0)[1];\n};\n", clangSize: 8, clangAlignment: 8)
    }

    func testArrayOfPointersToArraysDoesNotDisappear() throws {
        // Clang cee5cf3df6330de04d5846551e8828d447f60bde9655d72a823986e7016cdc9d: sizeof 8, alignment 8, f0 at 0.
        try assertSafeMinimalRecord("union R {\n  int (*f0[1])[1];\n};\n", clangSize: 8, clangAlignment: 8)
    }

    func testFlexibleArrayOfPointersToArraysDoesNotDisappear() throws {
        // Clang 2725ba8fdb611b751f07ff7df4c3002bdfe0a9b60ececb7934f8cf0ba625e2a6 (GNU11): sizeof 0, alignment 8, f0 at 0.
        try assertSafeMinimalRecord("union R {\n  int (*f0[])[1];\n};\n", clangSize: 0, clangAlignment: 8)
    }

    func testZeroArrayOfPointersToArraysDoesNotDisappear() throws {
        // Clang 309d85771b5f384c8bb24b16568cce5edea8a6b6bac122822224db9aa0060245 (GNU11): sizeof 0, alignment 8, f0 at 0.
        try assertSafeMinimalRecord("union R {\n  int (*f0[0])[1];\n};\n", clangSize: 0, clangAlignment: 8)
    }

    func testFlexibleArrayOfFunctionPointersDoesNotDisappear() throws {
        // Clang 1d53096a883502327056e62c4934cd06f075f2c7faa003e69d07a9190f388363 (GNU11): sizeof 0, alignment 8, f0 at 0.
        try assertSafeMinimalRecord("union R {\n  int (*f0[])(int);\n};\n", clangSize: 0, clangAlignment: 8)
    }

    func testExtendedVectorTypedefDoesNotBecomeItsScalarElement() throws {
        // Clang 4578b11fcbe06758d4946f6cb5c2280f2ee21bb1dcd6f7fadaa76ab32205fda0: sizeof 8, alignment 8, f0 at 0.
        try assertSafeMinimalRecord("typedef int V __attribute__((ext_vector_type(2)));\nunion R {\n  V f0;\n};\n",
                                   clangSize: 8, clangAlignment: 8)
    }

    func testExtendedVectorArgumentDoesNotUseItsScalarCarrier() throws {
        // Clang ca549e6c4d8ebf0c935b51e420c24cf3d57f1a842d24b66d5856f92e68b70330: T0 has size/alignment 8 and is passed in d0.
        let fixture = #"""
        {
          "id":"ca549e6c4d8ebf0c935b51e420c24cf3d57f1a842d24b66d5856f92e68b70330",
          "source":"typedef int T0 __attribute__((ext_vector_type(2)));\n",
          "type_info":{
            "t0":{"c":"T0","size":8,"align":8,"kind":"vector","stack_size":8,"stack_alignment":8},
            "t1":{"c":"void","size":0,"align":1,"kind":"void"}
          },
          "types":["t0"],"return_type":"t1","fixed_count":1,"variadic":false,
          "family":"minimized-extended-vector","signature":"void target(T0 p0);",
          "parameters":[{"index":0,"type":"t0","effective_type":"t0","indirect":false,"anonymous":false,
                         "locations":[{"register":"d0","size":8}]}]
        }
        """#
        let item = try JSONDecoder().decode(CallCase.self, from: Data(fixture.utf8))
        if case let .wrong(detail) = Self.observeCall(item, globalTypes: [:]) { XCTFail(detail) }
    }

    func testOneLaneExtendedVectorReturnDoesNotUseItsScalarCarrier() throws {
        // Clang d94f753fe1000d39f52c7ad1651060975b541efe2b9970ce82ad43f5761f6379: size/alignment 4, but return carrier d0 (four value bytes).
        let fixture = #"""
        {
          "source":"typedef float T0 __attribute__((ext_vector_type(1)));\n",
          "type_info":{"t0":{"c":"T0","size":4,"align":4,"kind":"vector"}},
          "type_key":"t0","matched":true,"locations":[{"register":"d0","size":4}]
        }
        """#
        let item = try JSONDecoder().decode(ReturnCase.self, from: Data(fixture.utf8))
        if case let .wrong(detail) = Self.observeReturn(item, globalTypes: [:]) { XCTFail(detail) }
    }

    func testHalfStorageRefusalIsDiagnosed() throws {
        // Clang c36e214b3352276b86ca34060f52edbdd93f8f3c68dc25c1589a3645e230a78e: _Float16 union size/alignment 2/2.
        try assertSafeMinimalRecord("union R {\n  _Float16 f0;\n};\n", clangSize: 2, clangAlignment: 2)
        // Clang 236ffb28730bf392dc4f1b6f664de618325b3c2534fc9f3796565ecbc965c359: __fp16 union size/alignment 2/2.
        try assertSafeMinimalRecord("union R {\n  __fp16 f0;\n};\n", clangSize: 2, clangAlignment: 2)
    }

    func testZeroArrayStorageRefusalIsDiagnosed() throws {
        // Clang 22b4dfb8b5e6f8951a58c67c71a54a20380dad03c0894348ec19ece9d2380a6e: zero int array, size/alignment 0/4.
        try assertSafeMinimalRecord("union R {\n  int f0[0];\n};\n", clangSize: 0, clangAlignment: 4)
        // Clang 4901c8d3a7c9cef9f8abb5cf320726d0f3312dc5f4b15451e784cfd49a077fe1: zero pointer array, 0/8.
        try assertSafeMinimalRecord("union R {\n  int *f0[0];\n};\n", clangSize: 0, clangAlignment: 8)
        // Clang bd37e8128846afcc1d6cfa13032b621e40ec21f5bbf586aef5dbad16e59e8e3e: zero function-pointer array, 0/8.
        try assertSafeMinimalRecord("union R {\n  int (*f0[0])(int);\n};\n", clangSize: 0, clangAlignment: 8)
    }

    func testZeroNamedCallWithUnboundResultIsNotAMatch() throws {
        // Clang 5d657da37530d0a72835a24d87474eac13aaca0207a11f212b3a9eb0e42abf14: T1 size/alignment 32/16, zero named arguments.
        let fixture = #"""
        {
          "id":"5d657da37530d0a72835a24d87474eac13aaca0207a11f212b3a9eb0e42abf14",
          "source":"typedef int T0 __attribute__((ext_vector_type(3)));\ntypedef struct T1 { T0 f0[2]; } T1;\n",
          "type_info":{"t0":{"c":"T1","size":32,"align":16,"kind":"aggregate"}},
          "types":[],"return_type":"t0","fixed_count":0,"variadic":false,
          "family":"zero-formals","signature":"T1 target(void);","parameters":[]
        }
        """#
        let item = try JSONDecoder().decode(CallCase.self, from: Data(fixture.utf8))
        let catalog = CLayoutABIOracleTests.catalog(CTypeHeaderParser.parse(item.source).types)
        let result = DarwinARM64ParameterBinder.returnLocation(for: "T1", resolver: TypeAtlasDarwinARM64LayoutResolver(catalog: catalog))
        let observation = Self.observeCall(item, globalTypes: [:])
        if case .unbound = result {
            guard case .refused = observation else {
                return XCTFail("An explicitly unbound result must not become a vacuous zero-argument MATCH")
            }
        } else if case let .wrong(detail) = observation {
            XCTFail(detail)
        }
    }

    func testReservedExtendedVectorTypedefIsExactOrDiagnosed() throws {
        // Clang e19401db1c58fa48a5eda838e437b6c9ba21da2c4ed5293b50b97fc0d8b6eb24: size/alignment 8/8; exact root-visible offsets.
        try assertSafeReviewRecord("typedef int V __attribute__((__ext_vector_type__(2)));\nstruct R { V x; };\n", clangSize: 8, clangAlignment: 8,
                                   clangOffsets: ["x": 0])
    }

    func testReservedVectorSizeTypedefIsExactOrDiagnosed() throws {
        // Clang 64790577f89824054f259ab73ff5e246e81d6e1cf731110e3cdec9b210608c92: size/alignment 8/8; exact root-visible offsets.
        try assertSafeReviewRecord("typedef int V __attribute__((__vector_size__(8)));\nstruct R { V x; };\n", clangSize: 8, clangAlignment: 8,
                                   clangOffsets: ["x": 0])
    }

    func testReservedPackedRecordPreservesLayout() throws {
        // Clang 81da92f80982465397e57ad0460ef6d1a8f6a1ec750964b6df2b9caa63154853: size/alignment 4/1; exact root-visible offsets.
        try assertSafeReviewRecord("struct __attribute__((__packed__)) R { int x; };\n", clangSize: 4, clangAlignment: 1,
                                   clangOffsets: ["x": 0])
    }

    func testReservedAlignedRecordPreservesLayout() throws {
        // Clang 930265265bdf81966b5fa79f80bf764b07df62b1b4a8214374d353f6b7d7d41d: size/alignment 2/2; exact root-visible offsets.
        try assertSafeReviewRecord("struct __attribute__((__aligned__(2))) R { char c; };\n", clangSize: 2, clangAlignment: 2,
                                   clangOffsets: ["c": 0])
    }

    func testReservedAlignedEmptyRecordPreservesAlignment() throws {
        // Clang 068c1c30dec046af0ae8eabf6db679cb30e40f212ea59d9b372d28cc38247d4c: size/alignment 0/2; exact root-visible offsets.
        try assertSafeReviewRecord("struct __attribute__((__aligned__(2))) R {};\n", clangSize: 0, clangAlignment: 2,
                                   clangOffsets: [:])
    }

    func testReservedPackedMemberPreservesLayout() throws {
        // Clang 75003f642d2b91acd7ad2a1b78cdfd0b219cbee01bd3ae7937ac7ff462019ce1: size/alignment 4/1; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { int x __attribute__((__packed__)); };\n", clangSize: 4, clangAlignment: 1,
                                   clangOffsets: ["x": 0])
    }

    func testReservedAlignedMemberPreservesLayout() throws {
        // Clang 0b19d9f34ee1f0b7bab658f3a57cce039ecfca458cb63650da0f66f48dea3bdc: size/alignment 2/2; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { char x __attribute__((__aligned__(2))); };\n", clangSize: 2, clangAlignment: 2,
                                   clangOffsets: ["x": 0])
    }

    func testReservedVectorSizeMemberIsExactOrDiagnosed() throws {
        // Clang b57262dbf10a20e03ff6041f4df237165596dd26775d7f16645a0690df86eb9e: size/alignment 8/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { int x __attribute__((__vector_size__(8))); };\n", clangSize: 8, clangAlignment: 8,
                                   clangOffsets: ["x": 0])
    }

    func testReservedAlignedTypedefIsExactOrDiagnosed() throws {
        // Clang 3e89bb35e4a6a8d64c3f28017b6112578fc6ac48a1efdefc6cbebcf27dabf56b: size/alignment 2/2; exact root-visible offsets.
        try assertSafeReviewRecord("typedef char T __attribute__((__aligned__(2)));\nstruct R { T x; };\n", clangSize: 2, clangAlignment: 2,
                                   clangOffsets: ["x": 0])
    }

    func testCallbackFirstCommaDeclaratorDoesNotLoseScalar() throws {
        // Clang bd3600a0f83cf5c82e6acc4ca8c88369cc9be3fef2fec6f04b0d4fe7140b53ed: size/alignment 16/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { int (*fp)(int), tail; };\n", clangSize: 16, clangAlignment: 8,
                                   clangOffsets: ["fp": 0, "tail": 8])
    }

    func testCallbackLaterCommaDeclaratorDoesNotShrinkRecord() throws {
        // Clang d71fb6a587004df0a6e8accc52da50e37625f13e721d707d7216e830a28da2aa: size/alignment 16/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { int x, (*fp)(int); };\n", clangSize: 16, clangAlignment: 8,
                                   clangOffsets: ["fp": 8, "x": 0])
        // Clang d66dda2e12ae7dd74141e94fca3987536b49fc561784c8a9b65ef1425edb3519: size/alignment 24/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { int x, (*fp)(int); char tail; };\n", clangSize: 24, clangAlignment: 8,
                                   clangOffsets: ["fp": 8, "tail": 16, "x": 0], requiredFollowingFields: ["tail"])
        // Clang 32b4862009c6ccc4e97255c8e60c366b78625d4127519573e9c771808c70a41d: size/alignment 24/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { int x, (*const fp)(int); char tail; };\n", clangSize: 24, clangAlignment: 8,
                                   clangOffsets: ["fp": 8, "tail": 16, "x": 0], requiredFollowingFields: ["tail"])
        // Clang a78a706a87e207fea175307f73cd5fc57ce7e1860841bfbc524bee8762b942bf: size/alignment 24/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { int x, (*fp[1])[1]; char tail; };\n", clangSize: 24, clangAlignment: 8,
                                   clangOffsets: ["fp": 8, "tail": 16, "x": 0], requiredFollowingFields: ["tail"])
    }

    func testInlineCallbackCommaDeclaratorDoesNotShrinkRecord() throws {
        // Clang 2305f69466991c0662187f69dd07f12d1ac2c8f8c29e8ac11403f09458c75773: size/alignment 16/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { struct { int a; } x, (*f)(int); };\n", clangSize: 16, clangAlignment: 8,
                                   clangOffsets: ["f": 8, "x": 0])
        // Clang bd54ae18ff1a0d1178eb16b2795673e8d736d8a7550ab3a0ccd07afe63025f19: size/alignment 24/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { struct { int a; } x, (*f)(int); char tail; };\n", clangSize: 24, clangAlignment: 8,
                                   clangOffsets: ["f": 8, "tail": 16, "x": 0], requiredFollowingFields: ["tail"])
    }

    func testPointerStarsDoNotLeakIntoNextScalar() throws {
        // Clang 442b3ddf2423f2aae0467e5a92498abeedf255231e078c8eba7df7d097ae0829: size/alignment 16/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { int *p, x; char tail; };\n", clangSize: 16, clangAlignment: 8,
                                   clangOffsets: ["p": 0, "tail": 12, "x": 8])
    }

    func testPointerQualifierDoesNotBecomeMemberName() throws {
        // Clang 557e918b2e3acb79c456b601bd79ac47a82cdd11bfef7027c68670167697fdb8: size/alignment 8/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { int *const p; };\n", clangSize: 8, clangAlignment: 8,
                                   clangOffsets: ["p": 0])
        // Clang 2335926453e6d39f4aba576a0763d0e4753be13be57714826b8f82bd43c5e296: size/alignment 16/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { int *const p; char tail; };\n", clangSize: 16, clangAlignment: 8,
                                   clangOffsets: ["p": 0, "tail": 8], requiredFollowingFields: ["tail"])
    }

    func testQualifiedPointerArrayRetainsNameAndBound() throws {
        // Clang aea272d21cceb0e9b33dcdb3c5762f7c7a007a64fa5ea746df0f8c0ec2db859d: size/alignment 16/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { int *const p[2]; };\n", clangSize: 16, clangAlignment: 8,
                                   clangOffsets: ["p": 0])
        // Clang a3da6e68ea102d834f055dfff24c12134e580cff4f2b028e5578c00499269169: size/alignment 24/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { int *const p[2]; char tail; };\n", clangSize: 24, clangAlignment: 8,
                                   clangOffsets: ["p": 0, "tail": 16], requiredFollowingFields: ["tail"])
    }

    func testUnsupportedVectorMemberRefusalIsDiagnosed() throws {
        // Clang 29a5f416f12b8ae103cabdb6169a16f5da6e7ce30cbe886bdc733a611926e9c8: size/alignment 8/8; exact root-visible offsets.
        try assertSafeReviewRecord("struct R { int x __attribute__((vector_size(8))); };\n", clangSize: 8, clangAlignment: 8,
                                   clangOffsets: ["x": 0])
    }

    func testUnsupportedAlignedTypedefRefusalIsDiagnosed() throws {
        // Clang f72e6c0a0149eac5facfef28e2c6a8fb6f9414f40bf5ea066f739454a2badc6d: size/alignment 2/2; exact root-visible offsets.
        try assertSafeReviewRecord("typedef char T __attribute__((aligned(2)));\nstruct R { T x; };\n", clangSize: 2, clangAlignment: 2,
                                   clangOffsets: ["x": 0])
    }

    func testInlineCallbackOnlyDoesNotBecomeAnEmptyRecord() throws {
        // Clang 6b2dbcc411cfbd0d9fd8d28ef5f2f6fa0e29be0ad5c9076694e154a86ceb90ff: size/alignment 8/8; inline callback field retained or diagnosed unknown.
        try assertSafeReviewRecord("struct R { struct { int a; } (*f)(int); };\n", clangSize: 8, clangAlignment: 8,
                                   clangOffsets: ["f": 0])
        // Clang 195815132ef1875d93050d83c5841b100172bec908dc47e0a1727ffd3ba2634c: size/alignment 16/8; inline callback field retained or diagnosed unknown.
        try assertSafeReviewRecord("struct R { struct { int a; } (*f)(int); char tail; };\n", clangSize: 16, clangAlignment: 8,
                                   clangOffsets: ["f": 0, "tail": 8], requiredFollowingFields: ["tail"])
        // Clang 38b5a054d1562b08eed1e6dd307940bf95efaedbfaa0d646e66f657f5579e7ff: deletion-minimized pointer member, size/alignment 8/8.
        try assertSafeReviewRecord("union R { union {} (*f); };\n", clangSize: 8, clangAlignment: 8,
                                   clangOffsets: ["f": 0], clangKind: "union")
        // Clang 85072a06876a13a00e9eef154ab62fa0663f873705cedc7ea5df32219c3a9ec9: deleting the star preserves the missing-name failure even at size/alignment 0/1.
        try assertSafeReviewRecord("union R { union {} (f); };\n", clangSize: 0, clangAlignment: 1,
                                   clangOffsets: ["f": 0], clangKind: "union")
    }

    func testUnnamedCommaBitFieldDoesNotInheritPointerStars() throws {
        // Clang 21 arm64-apple-macos14: record bfa29eed25b5d4632346632e039ea6590f50c757fa2897bc973c73c5686f45f5; ABI 1cbeff883d336b4164586a76960f91f521806b1f68744c9c6ef6656e1c3463e3.
        try assertSafeReviewRecordAndABI("struct R { int *p, :1; };\n",
            id: "1cbeff883d336b4164586a76960f91f521806b1f68744c9c6ef6656e1c3463e3", clangSize: 16, clangAlignment: 8,
            clangOffsets: ["p": 0],
            clangBits: [("", 64, 1)],
            clangArgument: [("x0", 8), ("x1", 8)], clangNext: "w2",
            clangReturn: [("x0", 8), ("x1", 8)])
        // Clang 21 arm64-apple-macos14: record 3e4bef9169ebf8c55fa5c93fa991b71624e072ab8767f840ad97be899a74f597; ABI 6ebb1f49d7b914ef60cc23651e1495a1b89baee9863ea69be54b8119fa9e558d.
        try assertSafeReviewRecordAndABI("struct R { unsigned int *p, :0; char tail; };\n",
            id: "6ebb1f49d7b914ef60cc23651e1495a1b89baee9863ea69be54b8119fa9e558d", clangSize: 16, clangAlignment: 8,
            clangOffsets: ["p": 0, "tail": 8], requiredFollowingFields: ["tail"],
            clangBits: [("", 64, 0)],
            clangArgument: [("x0", 8), ("x1", 8)], clangNext: "w2",
            clangReturn: [("x0", 8), ("x1", 8)])
        // Clang 21 arm64-apple-macos14: record aa7b6fd129e82ec369cab95765b6e5b006d6454b38d97774fb7310fc00edebbf; ABI facd4029d74abe26fdd1d7a113e81d5c651fc6cd7de8148e58c8ac98bd8a9802.
        try assertSafeReviewRecordAndABI("struct R { unsigned int *p, :1; char tail; };\n",
            id: "facd4029d74abe26fdd1d7a113e81d5c651fc6cd7de8148e58c8ac98bd8a9802", clangSize: 16, clangAlignment: 8,
            clangOffsets: ["p": 0, "tail": 9], requiredFollowingFields: ["tail"],
            clangBits: [("", 64, 1)],
            clangArgument: [("x0", 8), ("x1", 8)], clangNext: "w2",
            clangReturn: [("x0", 8), ("x1", 8)])
    }

    func testReservedPointerQualifiersPreserveMemberNamesAndExtents() throws {
        // Clang 21 arm64-apple-macos14: record 23c4ae8a10d4d90e9d54c5ad02b14ed4080352eb7a72ef2ffff68081f79c7eb7; ABI f13cd4b463413ba66e71d57e51bfafe8445e99fdca01250b9d14046b942f4cc2.
        try assertSafeReviewRecordAndABI("struct R { int *__const p; };\n",
            id: "f13cd4b463413ba66e71d57e51bfafe8445e99fdca01250b9d14046b942f4cc2", clangSize: 8, clangAlignment: 8,
            clangOffsets: ["p": 0],
            clangArgument: [("x0", 8)], clangNext: "w1",
            clangReturn: [("x0", 8)])
        // Clang 21 arm64-apple-macos14: record 1f1b347f3dd49277f367ed152bc2e9dbae149f97985ad5fc6d3533cff701628e; ABI 6448ade02144e148231a19005e58fce1c955992d2097b11caeb29c5bb262727d.
        try assertSafeReviewRecordAndABI("struct R { int *__const p[2]; };\n",
            id: "6448ade02144e148231a19005e58fce1c955992d2097b11caeb29c5bb262727d", clangSize: 16, clangAlignment: 8,
            clangOffsets: ["p": 0],
            clangArgument: [("x0", 8), ("x1", 8)], clangNext: "w2",
            clangReturn: [("x0", 8), ("x1", 8)])
        // Clang 21 arm64-apple-macos14: record 62e92a1bdf06131aa2ed6a25c6e52b1f859b2fd6313266766418a5269919a0cf; ABI 3aa8e820608010c80ddd1a6831148a7593e14a3a3dd496802dee3352d910c832.
        try assertSafeReviewRecordAndABI("struct R { int *__const__ p[2]; char tail; };\n",
            id: "3aa8e820608010c80ddd1a6831148a7593e14a3a3dd496802dee3352d910c832", clangSize: 24, clangAlignment: 8,
            clangOffsets: ["p": 0, "tail": 16], requiredFollowingFields: ["tail"],
            clangArgument: [("x0", 8)], clangNext: "w1",
            clangReturn: [("x8(indirect result)", 8)], clangIndirect: true)
        // Clang 21 arm64-apple-macos14: record bb496e5921727df985ea7dd81c910616b7bd07ab37424bf3a352030e6ae46f45; ABI 0af7d2b2947a49a36a5ec7cca682faf33cec93d71f945e1c45614e4dd00cb890.
        try assertSafeReviewRecordAndABI("struct R { int *__const p[2]; char tail; };\n",
            id: "0af7d2b2947a49a36a5ec7cca682faf33cec93d71f945e1c45614e4dd00cb890", clangSize: 24, clangAlignment: 8,
            clangOffsets: ["p": 0, "tail": 16], requiredFollowingFields: ["tail"],
            clangArgument: [("x0", 8)], clangNext: "w1",
            clangReturn: [("x8(indirect result)", 8)], clangIndirect: true)
        // Clang 21 arm64-apple-macos14: record a9689873e43f8ed734586df7d16ff01231e3f33b87d271a67f0a61db2624e7ab; ABI b8ecbff515e0ef9ae9d354d10b58e50a9e6e27bea4ecb2f4efb4418c09acb6fa.
        try assertSafeReviewRecordAndABI("struct R { int *__volatile__ p[2]; char tail; };\n",
            id: "b8ecbff515e0ef9ae9d354d10b58e50a9e6e27bea4ecb2f4efb4418c09acb6fa", clangSize: 24, clangAlignment: 8,
            clangOffsets: ["p": 0, "tail": 16], requiredFollowingFields: ["tail"],
            clangArgument: [("x0", 8)], clangNext: "w1",
            clangReturn: [("x8(indirect result)", 8)], clangIndirect: true)
        // Clang 21 arm64-apple-macos14: record 1aaf2744d41b05f644adf42f85cf6bbbc5e54622efddab9da3ea4b520ab311ac; ABI d4b3b94f813d808cd2a4c809c57fa0fba9ba691b32ec60f9a466b14c0e123979.
        try assertSafeReviewRecordAndABI("struct R { int *__volatile p[2]; char tail; };\n",
            id: "d4b3b94f813d808cd2a4c809c57fa0fba9ba691b32ec60f9a466b14c0e123979", clangSize: 24, clangAlignment: 8,
            clangOffsets: ["p": 0, "tail": 16], requiredFollowingFields: ["tail"],
            clangArgument: [("x0", 8)], clangNext: "w1",
            clangReturn: [("x8(indirect result)", 8)], clangIndirect: true)
    }

    func testInlinePointerArrayExpressionRetainsUnknownStorageAndFollowingField() throws {
        // Clang 21 arm64-apple-macos14: record 66714429a96edc2c8b0204b8cfc6957909d437f56b27e9db85435446d2f83701; ABI 5cf027496d8bfd36ef879cb3ea773cdbe3c3c23d6d80ffc233e70d51e6285efd.
        try assertSafeReviewRecordAndABI("struct R { struct {} *p[+1]; };\n",
            id: "5cf027496d8bfd36ef879cb3ea773cdbe3c3c23d6d80ffc233e70d51e6285efd", clangSize: 8, clangAlignment: 8,
            clangOffsets: ["p": 0],
            clangArgument: [("x0", 8)], clangNext: "w1",
            clangReturn: [("x0", 8)])
        // Clang 21 arm64-apple-macos14: record a0cce4cf0b420a7bb250b1d015396bcd2c2dd97680732df242f9b6410041b751; ABI 1e08da0e6c1a6b627277704e62a2b9806ba0b31fe2805a3560097b4daa674a10.
        try assertSafeReviewRecordAndABI("struct R { struct {} x, *p[+1]; };\n",
            id: "1e08da0e6c1a6b627277704e62a2b9806ba0b31fe2805a3560097b4daa674a10", clangSize: 8, clangAlignment: 8,
            clangOffsets: ["p": 0, "x": 0],
            clangArgument: [("x0", 8)], clangNext: "w1",
            clangReturn: [("x0", 8)])
        // Clang 21 arm64-apple-macos14: record 635ea280022d8e552cd73ed5869d2f6798052ef2ce8b10d248ced68064023767; ABI 0ba04610c07a13c64793ea5940cf7c843585f787e6880bf0a21a51a21319495e.
        try assertSafeReviewRecordAndABI("struct R { struct {} *p[+1]; char t; };\n",
            id: "0ba04610c07a13c64793ea5940cf7c843585f787e6880bf0a21a51a21319495e", clangSize: 16, clangAlignment: 8,
            clangOffsets: ["p": 0, "t": 8], requiredFollowingFields: ["t"],
            clangArgument: [("x0", 8), ("x1", 8)], clangNext: "w2",
            clangReturn: [("x0", 8), ("x1", 8)])
        // Clang 21 arm64-apple-macos14: record 97ffaab2dfa3f2107a7aad199474741f670d913ccc369316189415d291d3ebae; ABI 814c97331a1e3dd5cd3d07a454fc47c5408dd4eefd5e7bf94a5c285e6070f4ba.
        try assertSafeReviewRecordAndABI("struct R { struct { char a; } x, *p[+1]; };\n",
            id: "814c97331a1e3dd5cd3d07a454fc47c5408dd4eefd5e7bf94a5c285e6070f4ba", clangSize: 16, clangAlignment: 8,
            clangOffsets: ["p": 8, "x": 0],
            clangArgument: [("x0", 8), ("x1", 8)], clangNext: "w2",
            clangReturn: [("x0", 8), ("x1", 8)])
        // Clang 21 arm64-apple-macos14: record f25997b2c568080c86a0014e0c60ae0cec55629d317578bf46cdb8f68a762111; ABI 104741dda5ce29861e10eaca1f313a59b0902eb708ee04568947d830ce2f819a.
        try assertSafeReviewRecordAndABI("struct R { struct {} x, *p[+1]; int tail; };\n",
            id: "104741dda5ce29861e10eaca1f313a59b0902eb708ee04568947d830ce2f819a", clangSize: 16, clangAlignment: 8,
            clangOffsets: ["p": 0, "tail": 8, "x": 0], requiredFollowingFields: ["tail"],
            clangArgument: [("x0", 8), ("x1", 8)], clangNext: "w2",
            clangReturn: [("x0", 8), ("x1", 8)])
    }

    func testDeclaratorPositionAttributesDoNotFabricateOrDropMembers() throws {
        // Clang 21 arm64-apple-macos14: record 80dd60ef4af3bb802646dc2f6f256f53933bb2f81f4a9f725d41221e56574fdf; ABI b2e9ac2e33eec4a644adf3fd2dd24c66d21d2035c69f6f24239ab4796ad91ec9.
        try assertSafeReviewRecordAndABI("struct R { int __attribute__(()) p; };\n",
            id: "b2e9ac2e33eec4a644adf3fd2dd24c66d21d2035c69f6f24239ab4796ad91ec9", clangSize: 4, clangAlignment: 4,
            clangOffsets: ["p": 0],
            clangArgument: [("x0", 4)], clangNext: "w1",
            clangReturn: [("w0", 4)])
        // Clang 21 arm64-apple-macos14: record c70cca5e7a09580270a5fbadd6cca2ac5b168bf55c81829d8e3e1258f6f2048b; ABI c489715b124eca9fd304390edef991b0c1a3e02b185d78d805e93271833011a5.
        try assertSafeReviewRecordAndABI("struct R { int *__attribute__(()) p; };\n",
            id: "c489715b124eca9fd304390edef991b0c1a3e02b185d78d805e93271833011a5", clangSize: 8, clangAlignment: 8,
            clangOffsets: ["p": 0],
            clangArgument: [("x0", 8)], clangNext: "w1",
            clangReturn: [("x0", 8)])
        // Clang 21 arm64-apple-macos14: record d46c3c88b33ec58c83370cfa9ad9223dd4c4426fe346bb5a636ddf0055fffaac; ABI 6969867a363e7d1552633dff6c343b746d5fcda00b5d55555d7be2f690049f9a.
        try assertSafeReviewRecordAndABI("struct R { int *__attribute__((aligned(16))) p; };\n",
            id: "6969867a363e7d1552633dff6c343b746d5fcda00b5d55555d7be2f690049f9a", clangSize: 16, clangAlignment: 16,
            clangOffsets: ["p": 0],
            clangArgument: [("x0", 8), ("x1", 8)], clangNext: "w2",
            clangReturn: [("x0", 8), ("x1", 8)])
        // Clang 21 arm64-apple-macos14: record df889b9cb4d7dd494d51fa3bce844484ae03c14845069ffde9df8826f080b4ea; ABI 2c44cea78d4da6db7d868a25c79ccb94ac6321608105fb34d2b89fb2dac3cbb9.
        try assertSafeReviewRecordAndABI("struct R { char __attribute__(()) p; char t; };\n",
            id: "2c44cea78d4da6db7d868a25c79ccb94ac6321608105fb34d2b89fb2dac3cbb9", clangSize: 2, clangAlignment: 1,
            clangOffsets: ["p": 0, "t": 1], requiredFollowingFields: ["t"],
            clangArgument: [("x0", 2)], clangNext: "w1",
            clangReturn: [("w0", 2)])
        // Clang 21 arm64-apple-macos14: record 4bac879829ad49c958947edddc3cbe4cfc1cea785fff03a68d5d109346b4a269; ABI af7918a0e6c71a60bcb0d21d785c6c6228d17d57b406cb7d1ade4a8c049389d9.
        try assertSafeReviewRecordAndABI("struct R { int *__attribute__((aligned(16))) p; char tail; };\n",
            id: "af7918a0e6c71a60bcb0d21d785c6c6228d17d57b406cb7d1ade4a8c049389d9", clangSize: 16, clangAlignment: 16,
            clangOffsets: ["p": 0, "tail": 8], requiredFollowingFields: ["tail"],
            clangArgument: [("x0", 8), ("x1", 8)], clangNext: "w2",
            clangReturn: [("x0", 8), ("x1", 8)])
        // Clang 21 arm64-apple-macos14: record 030e2d015cf3418db11fcfa1f23b4181114b5090087835fd99de2ed145e132fa; ABI 04f64e9951441e256e40291cc3dddf119e15cf60c2041837918b045aeda73ed7.
        try assertSafeReviewRecordAndABI("struct R { int __attribute__((aligned(16))) p; char tail; };\n",
            id: "04f64e9951441e256e40291cc3dddf119e15cf60c2041837918b045aeda73ed7", clangSize: 16, clangAlignment: 16,
            clangOffsets: ["p": 0, "tail": 4], requiredFollowingFields: ["tail"],
            clangArgument: [("x0", 8), ("x1", 8)], clangNext: "w2",
            clangReturn: [("x0", 8), ("x1", 8)])
    }
}
