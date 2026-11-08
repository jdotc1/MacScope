// Load-command declaration strings: bounded, exact and never truncated or normalized.

import Foundation
import XCTest
@testable import MacScope

final class CEComponentLoadCommandTests: XCTestCase {
    private func read(_ bytes: [UInt8], capture: Bool = true, limit: Int = 1_048_576)
        -> (result: CE.MetadataReadResult, used: Int) {
        var ledger = CE.ReadLedger(limit: limit)
        let range = CE.PathRange.wholeRoot
        let result = CE.ComponentMetadataReader(captureLoadCommands: capture).read(
            size: UInt64(bytes.count), range: range, ledger: &ledger) { offset, count in
            guard offset + UInt64(count) <= UInt64(bytes.count) else {
                throw CE.EvidenceError.shortRead(range, expected: count, actual: 0)
            }
            return Array(bytes[Int(offset)..<(Int(offset) + count)])
        }
        return (result, ledger.used)
    }

    // SPEC-CASE: LC-BOUNDED-LOAD-STRINGS-MALFORMED-OFFSETS
    func testBoundedLoadStringsAndMalformedOffsets() {
        // Reads: 8 (magic probe) + 4 (prefix) + 32 (header) + 48 (commands).
        let consumed = 8 + 4 + 32 + 48
        let good = read(CEBytes.loadDylib())
        XCTAssertNil(good.result.failure)
        XCTAssertEqual(good.result.consumedBytes, consumed)
        XCTAssertEqual(good.used, consumed)
        XCTAssertEqual(good.result.architectures, [CEHarness.key("arm64")])
        let expected = CE.ComponentLoadDeclaration(
            architecture: CEHarness.key("arm64"), command: .load, path: CEHarness.key("@rpath/Owned.dylib"),
            currentVersion: "1.0.0", compatibilityVersion: "1.0.0", useFlags: nil)
        XCTAssertEqual(good.result.slices.first?.loadDeclarations, [expected])

        // Without capture the same image yields no load declarations.
        let plain = read(CEBytes.loadDylib(), capture: false)
        XCTAssertNil(plain.result.failure)
        XCTAssertEqual(plain.result.slices.first?.loadDeclarations, [])

        // A name offset inside the fixed command fields, or at/after the command end, is refused.
        for offset: UInt32 in [4, 23, 48, 4096] {
            let bad = read(CEBytes.loadDylib(nameOffset: offset))
            XCTAssertEqual(bad.result.failure, .malformedMetadata(nil, .wholeRoot, .badCommandString), "offset \(offset)")
            XCTAssertEqual(bad.result.slices, [], "offset \(offset)")
            XCTAssertEqual(bad.result.consumedBytes, consumed, "offset \(offset)")
        }

        // The string region is bytes 56..<80 of the image (command offset 24 within the 48-byte command).
        var unterminated = CEBytes.loadDylib()
        unterminated.replaceSubrange(56..<80, with: [UInt8](repeating: 0x41, count: 24))
        let missing = read(unterminated)
        XCTAssertEqual(missing.result.failure, .malformedMetadata(nil, .wholeRoot, .badCommandString))
        XCTAssertEqual(missing.result.slices, [])
        XCTAssertEqual(missing.result.consumedBytes, consumed)

        var invalid = CEBytes.loadDylib()
        invalid[56] = 0xff
        let notUTF8 = read(invalid)
        XCTAssertEqual(notUTF8.result.failure, .malformedMetadata(nil, .wholeRoot, .badCommandString))
        XCTAssertEqual(notUTF8.result.slices, [])
        XCTAssertEqual(notUTF8.result.consumedBytes, consumed)
    }
}
