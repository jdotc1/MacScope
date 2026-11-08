import XCTest
@testable import MacScope

/// Synthetic grammar-derived vectors, not compiler output.
final class RustV0DemanglerTests: XCTestCase {
    func testSupportedPathsAndExactMachOWrapper() {
        let cases = [
            ("_RC3foo", "foo"), ("__RC3foo", "foo"),
            ("_RNvC3foo3bar", "foo::bar"),
            ("_RNvNtC3foo3mod3run", "foo::mod::run"),
            ("_RC3_foo", "foo"), ("_RC3_123", "123"),
            ("_RC3__ab", "_ab"), ("_RC3a_1", "a_1")
        ]
        for (symbol, expected) in cases {
            XCTAssertEqual(RustV0Demangler.demangle(symbol), expected, symbol)
            XCTAssertEqual(Demangler.displayName(for: symbol), expected, symbol)
        }
    }

    func testDisambiguatorsAreCheckedAndOmittedFromDisplay() {
        // s_ encodes 1; s0_ encodes 2; sa_ encodes 12; sZ_ encodes 63.
        for disambiguator in ["s_", "s0_", "sa_", "sZ_", "s00_"] {
            XCTAssertEqual(RustV0Demangler.demangle("_RC" + disambiguator + "3foo"), "foo")
            XCTAssertEqual(RustV0Demangler.demangle("_RNvC3foo" + disambiguator + "3bar"), "foo::bar")
        }
        XCTAssertEqual(RustV0Demangler.demangle("_RCs" + String(repeating: "Z", count: 10) + "_1a"), "a")
        for symbol in ["_RCsZZZZZZZZZZZ_1a", "_RCs000000000000_1a", "_RCs!_1a", "_RCs", "_RCs_0"] {
            XCTAssertNil(RustV0Demangler.demangle(symbol), symbol)
        }
    }

    func testDisambiguatorUnsignedIncrementOverflowEndpoints() {
        // The grammar adds one for base62 and one for the disambiguator.
        XCTAssertEqual(RustV0Demangler.demangle("_RCslYGhA16ahyd_1a"), "a")
        XCTAssertNil(RustV0Demangler.demangle("_RCslYGhA16ahye_1a"))
        XCTAssertNil(RustV0Demangler.demangle("_RCslYGhA16ahyf_1a"))
    }

    func testMalformedAndUnsupportedNamesStayExactlyRaw() {
        let cases = [
            "", "RC3foo", "___RC3foo", "_R0C3foo", "_R1C3foo",
            "_RC0", "_RC03foo", "_RC18446744073709551616a",
            "_RC999999999999999999999a", "_RC3fo", "_RC3_ab", "_RC3123",
            "_RC3f.o", "_RC1\0", "_RC1\n", "_RC2é", "_RC٣foo",
            "_RNxC3foo3bar", "_RNCC3foo0", "_RNSC3foo0", "_RNvC3foo0",
            "_RMC3foo", "_RXC3foo", "_RYC3foo", "_RIC3fooE", "_RB_",
            "_RCu3foo", "_RC3fooC3bar", "_RC3foo.llvm.1", "_RC3foo$tail",
            "_RNvC3foo", "_RNv", "_RC3foo3bar"
        ]
        for symbol in cases {
            XCTAssertNil(RustV0Demangler.demangle(symbol), symbol)
            XCTAssertEqual(Demangler.displayName(for: symbol), symbol, symbol)
        }
    }

    func testComponentAndNumericWorkBoundaries() {
        let prefix = "_R" + String(repeating: "Nv", count: 63) + "C"
        XCTAssertEqual(RustV0Demangler.demangle(prefix + String(repeating: "s000_1a", count: 64)),
                       Array(repeating: "a", count: 64).joined(separator: "::"))
        // Four numeric bytes/component consumes exactly 256. Five exceeds it.
        XCTAssertNil(RustV0Demangler.demangle(prefix + String(repeating: "s0000_1a", count: 64)))
        XCTAssertNil(RustV0Demangler.demangle("_RNv" + String(prefix.dropFirst(2))
                                           + String(repeating: "1a", count: 65)))
    }

    func testOutputAndInputBounds() {
        let allowed = String(repeating: "a", count: 2048)
        XCTAssertEqual(RustV0Demangler.demangle("_RC2048" + allowed), allowed)
        XCTAssertNil(RustV0Demangler.demangle("_RC2049" + allowed + "a"))
        let nested = String(repeating: "a", count: 2045)
        XCTAssertEqual(RustV0Demangler.demangle("_RNvC1a2045" + nested), "a::" + nested)
        XCTAssertNil(RustV0Demangler.demangle("_RNvC1a2046" + nested + "a"))
        // An over-budget name is refused without exposing a partial display.
        let oversized = "_RC" + String(repeating: "a", count: 4094)
        XCTAssertNil(RustV0Demangler.demangle(oversized))
        XCTAssertEqual(Demangler.displayName(for: oversized), oversized)
    }

    func testItaniumAndAmbiguousLegacyRoutingIsUnchanged() {
        for symbol in ["_Z3foov", "__Z3foov", "_ZN3foo3barE", "__ZN3foo3barE"] {
            XCTAssertEqual(Demangler.mangledToReadable(symbol), ItaniumDemangler.demangle(symbol))
            XCTAssertNil(RustV0Demangler.demangle(symbol))
        }
    }
}
