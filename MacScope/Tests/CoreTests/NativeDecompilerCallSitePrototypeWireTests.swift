import Foundation
import XCTest
@testable import MacScope

final class NativeDecompilerCallSitePrototypeWireTests: XCTestCase {
    func testSchemaFourRoundTripsExactCallSitePrototype() throws {
        let source = inputs(records: [record()])
        let decoded = try decode(source)
        let encoded = try encode(decoded)
        XCTAssertEqual(encoded as NSDictionary, source as NSDictionary)
    }

    func testSchemaFourRequiresCollectionEvenWhenEmpty() throws {
        var source = inputs(records: [])
        XCTAssertNoThrow(try decode(source))
        source.removeValue(forKey: "callSitePrototypes")
        XCTAssertThrowsError(try decode(source))
    }

    func testOlderSchemasRejectCallSiteKeyAndPreserveLegacyShape() throws {
        for version in 1...3 {
            var source = inputs(records: [record()], version: version)
            XCTAssertThrowsError(try decode(source), "schema \(version)")
            source["callSitePrototypes"] = []
            XCTAssertThrowsError(try decode(source), "closed legacy schema \(version)")
            source.removeValue(forKey: "callSitePrototypes")
            XCTAssertEqual(try encode(decode(source)) as NSDictionary, source as NSDictionary)
        }
    }

    func testUnknownSourceAndUnknownKeysReject() throws {
        var unknownSource = record()
        unknownSource["source"] = 255
        XCTAssertThrowsError(try decode(inputs(records: [unknownSource])))
        var unknownRecordKey = record()
        unknownRecordKey["implementationTarget"] = "0000000000006000"
        XCTAssertThrowsError(try decode(inputs(records: [unknownRecordKey])))
        for version in 1...4 {
            var source = inputs(records: [], version: version)
            if version < 4 { source.removeValue(forKey: "callSitePrototypes") }
            source["futureField"] = 1
            XCTAssertThrowsError(try decode(source), "schema \(version)")
        }
    }

    func testInstructionBytesRequireExactlyFourDataBytes() throws {
        for count in [0, 1, 3, 5, 8] {
            var malformed = record()
            malformed["expectedInstructionBytes"] = Data(repeating: 0, count: count)
            XCTAssertThrowsError(try decode(inputs(records: [malformed])), "length \(count)")
        }
        var text = record()
        text["expectedInstructionBytes"] = "000c0094"
        XCTAssertThrowsError(try decode(inputs(records: [text])))
    }

    func testUnalignedCallAndTargetReject() throws {
        for key in ["callAddress", "expectedDirectTargetAddress"] {
            var malformed = record()
            malformed[key] = "0000000000001001"
            XCTAssertThrowsError(try decode(inputs(records: [malformed])), key)
        }
    }

    func testParameterCountIsBoundedAtSixtyFour() throws {
        var boundary = record()
        boundary["parameters"] = (0..<64).map { parameter(name: "p\($0)") }
        XCTAssertNoThrow(try decode(inputs(records: [boundary])))
        boundary["parameters"] = (0..<65).map { parameter(name: "p\($0)") }
        XCTAssertThrowsError(try decode(inputs(records: [boundary])))
    }

    func testRecordCountIsBoundedAtTwoHundredFiftySix() throws {
        let boundary = (0..<256).map { record(call: UInt64(0x1000 + 4 * $0)) }
        XCTAssertNoThrow(try decode(inputs(records: boundary)))
        XCTAssertThrowsError(try decode(inputs(records: boundary + [record(call: 0x1400)])))
    }

    func testCallSiteParametersRejectExplicitRegisterStorage() throws {
        var located = parameter(name: "value")
        located["storageRegister"] = "x2"
        var source = record()
        source["parameters"] = [located]
        XCTAssertThrowsError(try decode(inputs(records: [source])))
    }

    func testMalformedModelValueNeitherTrapsOnInitNorEncodes() throws {
        let scalar = try decodeType()
        let malformed = NativeDecompilerWireCallSitePrototype(
            callAddress: NativeDecompilerWireUInt64(1),
            expectedInstructionBytes: Data([0, 1, 2]),
            expectedDirectTargetAddress: NativeDecompilerWireUInt64(2),
            returnType: scalar,
            parameters: [],
            source: .objectiveCMessage
        )
        XCTAssertFalse(malformed.isWellFormed)
        XCTAssertThrowsError(try PropertyListEncoder().encode(malformed))
    }

    private func decodeType() throws -> NativeDecompilerWireAuthoredType {
        let data = try PropertyListSerialization.data(fromPropertyList: scalar, format: .binary, options: 0)
        return try PropertyListDecoder().decode(NativeDecompilerWireAuthoredType.self, from: data)
    }

    private func record(call: UInt64 = 0x1000) -> [String: Any] {
        [
            "callAddress": String(format: "%016llx", call),
            "expectedInstructionBytes": Data([0x00, 0x0c, 0x00, 0x94]),
            "expectedDirectTargetAddress": "0000000000004000",
            "returnType": scalar,
            "parameters": [parameter(name: "value")],
            "source": 0,
        ]
    }

    private var scalar: [String: Any] {
        ["tag": 0, "atom": ["tag": 1, "scalarKind": 8], "qualifiers": 0]
    }

    private func parameter(name: String) -> [String: Any] {
        ["name": name, "type": scalar]
    }

    private func inputs(records: [[String: Any]], version: Int = 4) -> [String: Any] {
        var source: [String: Any] = [
            "schemaVersion": version, "names": [], "signatures": [],
            "appliedTypes": [], "typeDefinitions": [], "callSitePrototypes": records,
        ]
        if version >= 2 { source["calleeSignatureHints"] = [] }
        if version >= 3 { source["localNames"] = [] }
        return source
    }

    private func decode(_ source: [String: Any]) throws -> NativeDecompilerWireAuthoredInputs {
        let data = try PropertyListSerialization.data(fromPropertyList: source, format: .binary, options: 0)
        try NativeDecompilerWireBinaryPropertyListValidator.validate(data)
        return try PropertyListDecoder().decode(NativeDecompilerWireAuthoredInputs.self, from: data)
    }

    private func encode(_ inputs: NativeDecompilerWireAuthoredInputs) throws -> [String: Any] {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let data = try encoder.encode(inputs)
        return try XCTUnwrap(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    }
}
