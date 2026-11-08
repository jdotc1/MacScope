import Foundation
import XCTest
@testable import MacScope

// Source-derived test definitions.
@MainActor
final class CTypeHeaderArrayParameterDecayTests: XCTestCase {
    private static var loadedFull: CalleeWitnessHeaders.Loaded?

    func testLongArrayParameterDecays() throws {
        let result = CTypeHeaderParser.parse("void f(long freq[]);")
        XCTAssertEqual(result.prototypes.map(\.name), ["f"])
        XCTAssertEqual(result.skippedPrototypeCount, 0)
        let signature = try XCTUnwrap(result.prototypes.first).signature
        XCTAssertEqual(signature.returnType, "void")
        XCTAssertEqual(signature.args.map(\.name), ["freq"])
        XCTAssertEqual(signature.args.map(\.type), ["int64_t *"])
    }

    func testPointerElementArrayDecays() throws {
        let result = CTypeHeaderParser.parse("void g(char *argv[], int n);")
        XCTAssertEqual(result.skippedPrototypeCount, 0)
        let signature = try XCTUnwrap(result.prototypes.first { $0.name == "g" }).signature
        XCTAssertEqual(signature.args.map(\.name), ["argv", "n"])
        XCTAssertEqual(signature.args.map(\.type), ["char **", "int32_t"])
    }

    func testSizedAndUnnamedArraysDecay() throws {
        let result = CTypeHeaderParser.parse("void h(long a[4], unsigned []);")
        XCTAssertEqual(result.skippedPrototypeCount, 0)
        let signature = try XCTUnwrap(result.prototypes.first { $0.name == "h" }).signature
        XCTAssertEqual(signature.args.map(\.name), ["a", ""])
        XCTAssertEqual(signature.args.map(\.type), ["int64_t *", "uint32_t *"])
    }

    func testConstElementArrayDecays() throws {
        let result = CTypeHeaderParser.parse("void q(const long a[]);")
        XCTAssertEqual(result.skippedPrototypeCount, 0)
        let signature = try XCTUnwrap(result.prototypes.first { $0.name == "q" }).signature
        XCTAssertEqual(signature.args.map(\.name), ["a"])
        XCTAssertEqual(signature.args.map(\.type), ["const int64_t *"])
    }

    func testUnsupportedArrayDeclaratorsRemainRefused() throws {
        let result = CTypeHeaderParser.parse("""
        void m(long a[2][3]); void s(long a[N]); void p(int (*a)[3]);
        void ok(long a[]);
        """)
        XCTAssertEqual(result.prototypes.map(\.name), ["ok"])
        XCTAssertEqual(result.skippedPrototypeCount, 3)
        XCTAssertEqual(result.diagnostics.filter { $0.hasPrefix("Skipped function prototype `") },
            ["m", "s", "p"].map { "Skipped function prototype `\($0)`: unresolved or unsupported declaration." })
    }

    func testCallbackArrayParameterDecays() throws {
        let result = CTypeHeaderParser.parse("struct S { void (*cb)(long freq[]); };")
        let field = try XCTUnwrap(result.types.first { $0.name == "S" }?.fields.first)
        XCTAssertEqual(field.name, "cb")
        let signature = try XCTUnwrap(field.functionPointerSignatureV1)
        XCTAssertEqual(signature.returnType, "void")
        XCTAssertEqual(signature.parameters.map(\.name), ["freq"])
        XCTAssertEqual(signature.parameters.map(\.type), ["int64_t *"])
    }

    func testDeclaratorOverArrayTypedefDecays() throws {
        let result = CTypeHeaderParser.parse("typedef short JBLOCK[64]; void b(JBLOCK rows[]);")
        XCTAssertEqual(result.skippedPrototypeCount, 0)
        let signature = try XCTUnwrap(result.prototypes.first { $0.name == "b" }).signature
        XCTAssertEqual(signature.args.map(\.name), ["rows"])
        XCTAssertEqual(signature.args.map(\.type), ["JBLOCK *"])
    }

    func testUnnamedAndQualifiedArrayCoresKeepTheirTypes() throws {
        let result = CTypeHeaderParser.parse("""
        void unnamed(long long [], unsigned [], const long []);
        void qualified(long const a[], long * const b[], long * restrict c[]);
        void tagged(struct foo a[], struct foo []);
        """)
        XCTAssertEqual(result.prototypes.map(\.name), ["unnamed", "qualified", "tagged"])
        XCTAssertEqual(result.skippedPrototypeCount, 0)
        XCTAssertEqual(result.prototypes[0].signature.args.map(\.name), ["", "", ""])
        XCTAssertEqual(result.prototypes[0].signature.args.map(\.type), ["int64_t *", "uint32_t *", "const int64_t *"])
        XCTAssertEqual(result.prototypes[1].signature.args.map(\.name), ["a", "b", "c"])
        XCTAssertEqual(result.prototypes[1].signature.args.map(\.type), ["const int64_t *", "int64_t * const *", "int64_t * restrict *"])
        XCTAssertEqual(result.prototypes[2].signature.args.map(\.name), ["a", ""])
        XCTAssertEqual(result.prototypes[2].signature.args.map(\.type), ["struct foo *", "struct foo *"])
    }

    func testOtherUnsupportedBoundsAndDuplicateNamesRemainRefused() throws {
        let result = CTypeHeaderParser.parse("""
        void expression(long a[2 + 2]); void minimum(long a[static 4]);
        void star(long a[*]); void qualified(long a[const 4]);
        void functionArray(int (*f[2])(int)); void duplicate(long a[], long a[]);
        void empty([]); void accepted(long a[0], long b[0x10]);
        """)
        XCTAssertEqual(result.prototypes.map(\.name), ["accepted"])
        XCTAssertEqual(result.skippedPrototypeCount, 7)
        let signature = try XCTUnwrap(result.prototypes.first).signature
        XCTAssertEqual(signature.args.map(\.name), ["a", "b"])
        XCTAssertEqual(signature.args.map(\.type), ["int64_t *", "int64_t *"])
    }

    private func fullFixture() throws -> CalleeWitnessHeaders.Loaded {
        if let loaded = Self.loadedFull { return loaded }
        let source = try CalleeWitnessHeaders.preprocessed(headerSet: .full)
        let parsed = CTypeHeaderParser.parse(source)
        var analysis = ImageAnalysis()
        for (index, name) in Set(parsed.prototypes.map(\.name)).sorted().enumerated() {
            let address = UInt64(0x1000 + index * 4)
            analysis.exports.append(ExportSummary(id: UUID(), name: "_" + name,
                address: address, source: "export trie", terminalFlags: 0))
            analysis.functions.append(FunctionSummary(id: UUID(), name: name,
                startAddress: address, endAddress: address + 4, confidence: 1))
        }
        let snapshot = WorkspaceSnapshot(binaries: [BinaryImage(id: UUID(),
            name: "synthetic", path: "/synthetic", kind: "Mach-O", architecture: "arm64")],
            analysisBySlot: [.primary: analysis])
        let loaded = try CalleeWitnessHeaders.load(into: snapshot, headerSet: .full,
                                                  preprocessedSource: source)
        Self.loadedFull = loaded
        return loaded
    }

    func testFullFixtureImportsJpegGenOptimalTable() throws {
        let loaded = try fullFixture()
        let snapshot = loaded.snapshot
        let functions = try XCTUnwrap(snapshot.analysis(in: .primary)).functions
        let signatures = Dictionary(uniqueKeysWithValues: functions.compactMap { function in
            snapshot.importedPrototypes[.primary(function.startAddress)].map { (function.name, $0) }
        })
        let signature = try XCTUnwrap(signatures["jpeg_gen_optimal_table"])
        XCTAssertEqual(signature.returnType, "void")
        XCTAssertEqual(signature.args.count, 3)
        XCTAssertEqual(signature.args.map(\.name), ["cinfo", "htbl", "freq"])
        XCTAssertEqual(signature.args.last?.type, "int64_t *")
    }
}
