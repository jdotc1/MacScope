import XCTest
@testable import MacScope

// These fixtures exercise the actual public printer, not a test encoder.
final class PseudocodeUnknownLiteralControlEscapingTests: XCTestCase {
    private func assertStatement(
        _ expected: String,
        destination: MacIRValue? = nil,
        inputs: MacIRUnknownInputs = .none,
        mnemonic: String = "opaque",
        operands: String = "",
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let address: UInt64 = 0x4510
        let source = MacIRSourceSpan(address: address, byteText: "00 00 00 00",
            mnemonic: mnemonic, operands: operands, comment: nil)
        let instruction = MacIRInstruction(source: source,
            operation: .unknown(destination: destination, inputs: inputs,
                mnemonic: mnemonic, operands: operands))
        let function = MacIRFunction(name: "unknown_literal_controls", startAddress: address,
            instructions: [instruction])
        let printer = PseudocodePrinter(options: DecompilerOptions(
            structureControlFlow: false, deadCodeElimination: false,
            nopElision: false, functionSizeGate: 1024))
        let document = printer.print(function: function)
        let statements = document.lines(sourcedAt: address)
        let expectedText = "    " + expected

        XCTAssertEqual(statements.map(\.text), [expectedText], file: file, line: line)
        XCTAssertTrue(document.lines(sourcedAt: address + 4).isEmpty, file: file, line: line)
        guard let statement = statements.first else { return }
        // String equality alone would not detect canonical Unicode normalization.
        XCTAssertEqual(Array(statement.text.utf8), Array(expectedText.utf8), file: file, line: line)
        XCTAssertFalse(statement.text.unicodeScalars.contains {
            $0.value < 0x20 || $0.value == 0x7f
        }, file: file, line: line)
        XCTAssertEqual(statement.source, source, file: file, line: line)
    }

    func testLFCRTabAndNULInBothStringsStayLiteralData() {
        assertStatement(
            #"__unknown("opaque\n\r\t\000", "a\nb\rc\td\0007");"#,
            mnemonic: "opaque\n\r\t\u{0}", operands: "a\nb\rc\td\u{0}7")
    }

    func testEveryASCIIControlHasAnUnambiguousSpellingBeforeDigits() {
        // Each expected spelling is independent of the production encoder.
        let cases: [(UInt32, String)] = [
            (0x00, #"\000"#), (0x01, #"\001"#), (0x02, #"\002"#), (0x03, #"\003"#),
            (0x04, #"\004"#), (0x05, #"\005"#), (0x06, #"\006"#), (0x07, #"\007"#),
            (0x08, #"\010"#), (0x09, #"\t"#),   (0x0a, #"\n"#),   (0x0b, #"\013"#),
            (0x0c, #"\014"#), (0x0d, #"\r"#),   (0x0e, #"\016"#), (0x0f, #"\017"#),
            (0x10, #"\020"#), (0x11, #"\021"#), (0x12, #"\022"#), (0x13, #"\023"#),
            (0x14, #"\024"#), (0x15, #"\025"#), (0x16, #"\026"#), (0x17, #"\027"#),
            (0x18, #"\030"#), (0x19, #"\031"#), (0x1a, #"\032"#), (0x1b, #"\033"#),
            (0x1c, #"\034"#), (0x1d, #"\035"#), (0x1e, #"\036"#), (0x1f, #"\037"#),
            (0x7f, #"\177"#)
        ]
        for (value, escaped) in cases {
            let control = String(Unicode.Scalar(value)!)
            assertStatement("__unknown(\"opaque\(escaped)aF07\", \"\(escaped)7654f\");",
                mnemonic: "opaque" + control + "aF07", operands: control + "7654f")
        }
    }

    func testCRLFIsTwoPreservedScalarsRatherThanOneCharacter() {
        assertStatement(#"__unknown("opaque\r\nnext", "left\r\nright");"#,
            mnemonic: "opaque\r\nnext", operands: "left\r\nright")
    }

    func testQuotesBackslashesAndEscapeLookingTextAreNotReinterpreted() {
        assertStatement(#"__unknown("opaque\"\\n\\000", "x1, \"quoted\\path\"");"#,
            mnemonic: #"opaque"\n\000"#, operands: #"x1, "quoted\path""#)
        assertStatement(#"__unknown("opaque\\\n\\000", "tail\\");"#,
            mnemonic: "opaque\\\n\\000", operands: "tail\\")
    }

    func testPrintableUnicodeAndDecomposedScalarsRemainByteForByte() {
        assertStatement("__unknown(\"opaqueé漢🙂e\u{301}\", \"λ🧑🏽‍💻e\u{301}\");",
            mnemonic: "opaqueé漢🙂e\u{301}", operands: "λ🧑🏽‍💻e\u{301}")
    }

    func testControlsKeepDestinationAndOrderedRepeatedMayReadDependencies() {
        let first = MacIRUnknownRead(register: "x7", value: .immediate(9))
        let middle = MacIRUnknownRead(register: "x1", value: .immediate(2))
        assertStatement(
            #"x8_2 = __unknown("opaque\n\001A", "x8,\r\t\0007\177f", 0x9, 0x2, 0x9);"#,
            destination: .register(name: "x8", version: 2),
            inputs: MacIRUnknownInputs(mayRead: [first, middle, first], definiteRead: [middle]),
            mnemonic: "opaque\n\u{1}A", operands: "x8,\r\t\u{0}7\u{7f}f")
    }

    func testEmptyStringsAndEmptyDependenciesKeepCallShape() {
        assertStatement(#"__unknown("", "");"#, mnemonic: "", operands: "")
        assertStatement(#"x8_2 = __unknown("opaque", "x8, #1");"#,
            destination: .register(name: "x8", version: 2), operands: "x8, #1")
        assertStatement(#"x8_2 = __unknown("opaque", "\0007");"#,
            destination: .register(name: "x8", version: 2), operands: "\u{0}7")
    }

    func testStatementLookingTextCannotBreakTheOneVisibleStatement() {
        assertStatement(
            #"__unknown("opaque\n\"); forged(); //", "x0\r\n\"; return 1;\t\033[2J");"#,
            mnemonic: "opaque\n\"); forged(); //", operands: "x0\r\n\"; return 1;\t\u{1b}[2J")
    }
}
