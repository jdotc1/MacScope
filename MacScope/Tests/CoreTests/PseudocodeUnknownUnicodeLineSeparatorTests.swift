import XCTest
@testable import MacScope

// Public-printer assertions, not a test-local encoder or decoder.
final class PseudocodeUnknownUnicodeLineSeparatorTests: XCTestCase {
    private func assertStatement(
        _ expected: String,
        destination: MacIRValue? = nil,
        inputs: MacIRUnknownInputs = .none,
        mnemonic: String = "opaque",
        operands: String = "",
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let address: UInt64 = 0x4710
        let source = MacIRSourceSpan(address: address, byteText: "00 00 00 00",
            mnemonic: mnemonic, operands: operands, comment: nil)
        let instruction = MacIRInstruction(source: source,
            operation: .unknown(destination: destination, inputs: inputs,
                mnemonic: mnemonic, operands: operands))
        let function = MacIRFunction(name: "unknown_unicode_line_separators", startAddress: address,
            instructions: [instruction])
        let printer = PseudocodePrinter(options: DecompilerOptions(
            structureControlFlow: false, deadCodeElimination: false,
            nopElision: false, functionSizeGate: 1024))
        let document = printer.print(function: function)
        let statements = document.lines(sourcedAt: address)
        let expectedText = "    " + expected

        // Compare complete lines; splitting or trimming could hide a separator leak.
        XCTAssertEqual(statements.map(\.text), [expectedText], file: file, line: line)
        XCTAssertTrue(document.lines(sourcedAt: address + 4).isEmpty, file: file, line: line)
        guard let statement = statements.first else { return }
        // String equality alone does not detect canonical normalization.
        XCTAssertEqual(Array(statement.text.utf8), Array(expectedText.utf8), file: file, line: line)
        XCTAssertFalse(statement.text.unicodeScalars.contains {
            $0.value < 0x20 || $0.value == 0x7f || $0.value == 0x85
                || $0.value == 0x2028 || $0.value == 0x2029
        }, file: file, line: line)
        XCTAssertEqual(statement.source, source, file: file, line: line)
        guard let actualSource = statement.source else { return }
        XCTAssertEqual(Array(actualSource.mnemonic.utf8), Array(mnemonic.utf8), file: file, line: line)
        XCTAssertEqual(Array(actualSource.operands.utf8), Array(operands.utf8), file: file, line: line)
    }

    func testNextLineUsesTwoUTF8ByteEscapesBeforeFollowingDigits() {
        assertStatement(#"__unknown("opaque\302\2057654f", "\302\2050123456789aF");"#,
            mnemonic: "opaque\u{85}7654f", operands: "\u{85}0123456789aF")
    }

    func testLineSeparatorUsesThreeUTF8ByteEscapesBeforeFollowingDigits() {
        assertStatement(#"__unknown("opaque\342\200\2507654f", "\342\200\2500123456789aF");"#,
            mnemonic: "opaque\u{2028}7654f", operands: "\u{2028}0123456789aF")
    }

    func testParagraphSeparatorUsesThreeUTF8ByteEscapesBeforeFollowingDigits() {
        assertStatement(#"__unknown("opaque\342\200\2517654f", "\342\200\2510123456789aF");"#,
            mnemonic: "opaque\u{2029}7654f", operands: "\u{2029}0123456789aF")
    }

    func testAdjacentRepeatedSeparatorsKeepByteOrderAndBoundaries() {
        assertStatement(
            #"__unknown("opaque\302\205\342\200\250\342\200\251\302\2057", "\342\200\251\342\200\250\302\2050");"#,
            mnemonic: "opaque\u{85}\u{2028}\u{2029}\u{85}7",
            operands: "\u{2029}\u{2028}\u{85}0")
    }

    func testSeparatorsKeepASCIIQuotesBackslashesAndEscapeLookingTextDistinct() {
        assertStatement(
            #"__unknown("opaque\302\205\"\\\n\r\t\0007\001A\177f", "\\302\\205|\342\200\250|\\342\\200\\250|\342\200\251");"#,
            mnemonic: "opaque\u{85}\"\\\n\r\t\u{0}7\u{1}A\u{7f}f",
            operands: #"\302\205|"# + "\u{2028}|" + #"\342\200\250|"# + "\u{2029}")
    }

    func testPrintableUnicodeAndBothAccentFormsStayByteExactBesideSeparators() {
        assertStatement(
            "__unknown(\"opaque\u{e9}\\302\\205e\u{301}\\342\\200\\250漢🙂\", \"λ🧑🏽‍💻\u{e9}\\342\\200\\251e\u{301}\");",
            mnemonic: "opaque\u{e9}\u{85}e\u{301}\u{2028}漢🙂",
            operands: "λ🧑🏽‍💻\u{e9}\u{2029}e\u{301}")
    }

    func testOtherNonASCIIScalarsAreNotBroadlyReclassified() {
        // U+0084/U+0086 and U+2027/U+202A are deliberately outside the new policy.
        assertStatement(
            "__unknown(\"opaque\u{84}\\302\\205\u{86}\u{2027}\u{202a}\", \"\u{84}\u{86}\\342\\200\\250\u{2027}\\342\\200\\251\u{202a}\");",
            mnemonic: "opaque\u{84}\u{85}\u{86}\u{2027}\u{202a}",
            operands: "\u{84}\u{86}\u{2028}\u{2027}\u{2029}\u{202a}")
    }

    func testSeparatorsKeepDestinationAndOrderedRepeatedMayReadInputs() {
        let first = MacIRUnknownRead(register: "x7", value: .immediate(9))
        let middle = MacIRUnknownRead(register: "x1", value: .immediate(2))
        assertStatement(
            #"x8_2 = __unknown("opaque\302\2057", "x8,\342\200\2502\342\200\2519", 0x9, 0x2, 0x9);"#,
            destination: .register(name: "x8", version: 2),
            inputs: MacIRUnknownInputs(mayRead: [first, middle, first], definiteRead: [middle]),
            mnemonic: "opaque\u{85}7", operands: "x8,\u{2028}2\u{2029}9")
    }

    func testEmptyAndDestinationOnlyCallShapesRemainUnchanged() {
        assertStatement(#"__unknown("", "");"#, mnemonic: "", operands: "")
        assertStatement(#"x8_2 = __unknown("opaque", "x8, #1");"#,
            destination: .register(name: "x8", version: 2), operands: "x8, #1")
        assertStatement(#"x8_2 = __unknown("opaque", "\302\2057");"#,
            destination: .register(name: "x8", version: 2), operands: "\u{85}7")
        assertStatement(#"__unknown("", "\342\200\250\342\200\251");"#,
            mnemonic: "", operands: "\u{2028}\u{2029}")
    }

    func testStatementLookingSeparatorPayloadRemainsOneSourceOwnedStatement() {
        assertStatement(
            #"__unknown("opaque\302\205\"); forged(); //", "x0\342\200\250\"; return 1;\342\200\251//");"#,
            mnemonic: "opaque\u{85}\"); forged(); //",
            operands: "x0\u{2028}\"; return 1;\u{2029}//")
    }
}
