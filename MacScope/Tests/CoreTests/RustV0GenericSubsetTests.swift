import XCTest
@testable import MacScope

/// Synthetic grammar-derived vectors for the bounded generic display subset.
/// Literals follow rustc/symbol-mangling/v0.html, not a compiler-derived oracle.
final class RustV0GenericSubsetTests: XCTestCase {
    private func accepted(_ symbol: String, _ expected: String,
                          file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(RustV0Demangler.demangle(symbol), expected, file: file, line: line)
        XCTAssertEqual(Demangler.displayName(for: symbol), expected, file: file, line: line)
    }

    private func refused(_ symbol: String,
                         file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNil(RustV0Demangler.demangle(symbol), file: file, line: line)
        XCTAssertEqual(Demangler.displayName(for: symbol), symbol, file: file, line: line)
    }

    func testLiteralGenericPathsAndPayloadETerminatorDistinction() {
        // C3foo consumes exactly foo; l is i32; final E closes I.
        accepted("_RIC3foolE", "foo::<i32>")
        accepted("_RINvC3foo3barlmE", "foo::bar::<i32, u32>")
        accepted("_RIC3fooNtC3bar3BazE", "foo::<bar::Baz>")
        // C1E consumes E as the identifier payload, not as the generic terminator.
        accepted("_RIC1ElE", "E::<i32>")
        accepted("_RIC3fooC1EE", "foo::<E>")
        accepted("_RIC3fooC2EEE", "foo::<EE>")
        refused("_RIC3fooC1E")
    }

    func testEveryAdmittedBasicTagFromOfficialTable() {
        let table = [("a", "i8"), ("b", "bool"), ("c", "char"), ("d", "f64"),
                     ("e", "str"), ("f", "f32"), ("h", "u8"), ("i", "isize"),
                     ("j", "usize"), ("l", "i32"), ("m", "u32"), ("n", "i128"),
                     ("o", "u128"), ("s", "i16"), ("t", "u16"), ("u", "()"),
                     ("x", "i64"), ("y", "u64")]
        for (tag, spelling) in table { accepted("_RIC1f" + tag + "E", "f::<" + spelling + ">") }
    }

    func testMixedNamedTypesNamespacesSeparatorsAndDisambiguators() {
        accepted("__RINvNtCs0_3foos_3modsZ_3runbNtC3bar3BazjE",
                 "foo::mod::run::<bool, bar::Baz, usize>")
        accepted("_RIC3_123C3__abE", "123::<_ab>")
        accepted("_RICs00_1fCsZ_1gE", "f::<g>")
        refused("_RIC1fC3123E")
        refused("_RIC1fC3_abE") // Declared three bytes would consume E; no terminator remains.
    }

    func testEmptyTruncatedTrailingAndNestedGenericFormsRefuse() {
        for symbol in ["_RIC3fooE", "_RI", "_RIC3foo", "_RIC3fool", "_RIC3foolEE",
                       "_RIC3foolE.llvm.1", "_RIC3foolEC3bar", "_RIC3foolE$tail",
                       "_RIIC3foolElE", "_RIC3fooIC3barlEE", "_RNvIC3foolE3bar",
                       "_RINvIC3foolE3barlE", "___RIC3foolE", "_R1IC3foolE"] {
            refused(symbol)
        }
    }

    func testUnsupportedGrammarIsNotPromotedToAType() {
        // Several are valid Rustv0 forms outside this display subset, not malformed claims.
        for argument in ["p", "v", "z", "L_", "Kj1_", "Rl", "Pl", "Sl", "TlE",
                         "Alj1_", "B_", "IC3barlE", "Cu3foo", "NSC3foo0", "M", "X", "Y"] {
            refused("_RIC3foo" + argument + "E")
        }
        for argument in ["C0", "C03foo", "C2é", "C1\n", "C٣foo", "C1!", "NxC1a1b"] {
            refused("_RIC3foo" + argument + "E")
        }
    }

    func testSixteenArgumentsAndSeventeenthRefusal() {
        let sixteen = String(repeating: "l", count: 16)
        let expected = Array(repeating: "i32", count: 16).joined(separator: ", ")
        accepted("_RIC1f" + sixteen + "E", "f::<" + expected + ">")
        refused("_RIC1f" + sixteen + "lE")
    }

    func testSharedComponentsAndNumericWorkAcrossBaseAndArgument() {
        // Each path has32 components; each s000_1a charges3 base62+1 decimal digits.
        let path = String(repeating: "Nv", count: 31) + "C" + String(repeating: "s000_1a", count: 32)
        let expected = Array(repeating: "a", count: 32).joined(separator: "::")
        accepted("_RI" + path + path + "E", expected + "::<" + expected + ">")
        // Same64 components,257 numeric digits: a per-argument reset would wrongly admit.
        let expensive = String(repeating: "Nv", count: 31) + "Cs0000_1a"
            + String(repeating: "s000_1a", count: 31)
        refused("_RI" + path + expensive + "E")
        //65 total components and65 numeric digits, isolating the component limit.
        let simplePath = String(repeating: "Nv", count: 31) + "C" + String(repeating: "1a", count: 32)
        refused("_RI" + simplePath + "Nv" + simplePath + "1aE")
    }

    func testNumericOverflowAndPerNumberCapsInNamedArguments() {
        for argument in ["C18446744073709551616a", "C999999999999999999999a",
                         "CsZZZZZZZZZZZ_1a", "Cs000000000000_1a", "Cs!_1a"] {
            refused("_RIC1f" + argument + "E")
        }
        //11 zero digits stay within UInt64 and the per-number bound.
        accepted("_RIC1fCs00000000000_1aE", "f::<a>")
        // The exact535 checked base62+disambiguator increment stages are retained.
        refused("_RIC1fCslYGhA16ahyf_1aE") // UInt64.max base62 payload: first +1 overflows.
        refused("_RIC1fCslYGhA16ahye_1aE") // UInt64.max-1 payload: second +1 overflows.
        accepted("_RIC1fCslYGhA16ahyd_1aE", "f::<a>") // UInt64.max-2 plus both increments fits.
    }

    func testExpandedPrimitiveAndPunctuationOutputBoundary() {
        //2041 identifier bytes +3 '::<' +3 'i32' +1 '>' =2048.
        let base = String(repeating: "a", count: 2041)
        accepted("_RIC2041" + base + "lE", base + "::<i32>")
        refused("_RIC2042" + base + "alE")
        // isize is five rendered bytes, not the one-byte input tag.
        refused("_RIC2041" + base + "iE")
        //2037+3+3+2+2+1=2048; the comma/space is charged too.
        let pairBase = String(repeating: "a", count: 2037)
        accepted("_RIC2037" + pairBase + "lhE", pairBase + "::<i32, u8>")
        refused("_RIC2038" + pairBase + "alhE")
    }

    func testNamedArgumentOutputAndInputMaterializationBounds() {
        let name = String(repeating: "a", count: 2043)
        accepted("_RIC1fC2043" + name + "E", "f::<" + name + ">")
        refused("_RIC1fC2044" + name + "aE")
        // These bounded malformed inputs exercise public refusal at4096/4097 bytes;
        // earlier syntax refusal can mask the input cap. Not claimed as a valid4096 symbol.
        let boundary = "_RIC1f" + String(repeating: "!", count: 4090)
        refused(boundary)
        refused(boundary + "!")
    }

    func testNongenericAndOtherDispatcherRoutesRemainUnchanged() {
        accepted("_RC3foo", "foo")
        accepted("__RNvC3foo3bar", "foo::bar")
        refused("_RIC3fooE") // Existing535 empty-generic definition remains true.
        for symbol in ["_Z3foov", "__Z3foov", "_ZN3foo3barE", "__ZN3foo3barE"] {
            XCTAssertEqual(Demangler.mangledToReadable(symbol), ItaniumDemangler.demangle(symbol))
            XCTAssertNil(RustV0Demangler.demangle(symbol))
        }
    }
}
