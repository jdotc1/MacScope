import Foundation
import XCTest
@testable import MacScope

final class NativeDecompilerAuthoredInputCarryTests: XCTestCase {
    func testCV01LocalNamesCarrySchemaFourPrototype() throws {
        let input = try baseV4()
        let prototype = try XCTUnwrap(input.callSitePrototypes.first)
        let result = NativeDecompilerSnapshotBuilder.withAuthoredLocalNames(
            input, stackLocals: [:], registerNames: ["x19": "total"], liveStackStorage: [])

        XCTAssertEqual(result.schemaVersion, UInt32(4))
        XCTAssertEqual(result.callSitePrototypes, [prototype] as [NativeDecompilerWireCallSitePrototype])
        XCTAssertEqual(result.localNames, [localName] as [NativeDecompilerWireAuthoredLocalName])
        XCTAssertNoThrow(try NativeDecompilerWireCanonicalRequest.canonicalAuthoredInputBytes(result))
    }

    func testCV02LocalNamesKeepSchemaThreeWithoutPrototypes() {
        let input = NativeDecompilerWireAuthoredInputs(
            schemaVersion: 3, names: [], signatures: [], appliedTypes: [], typeDefinitions: [],
            calleeSignatureHints: [], localNames: [], callSitePrototypes: [])
        let result = NativeDecompilerSnapshotBuilder.withAuthoredLocalNames(
            input, stackLocals: [:], registerNames: ["x19": "total"], liveStackStorage: [])

        XCTAssertEqual(result.schemaVersion, UInt32(3))
        XCTAssertEqual(result.callSitePrototypes.isEmpty, true as Bool)
        XCTAssertEqual(result.localNames, [localName] as [NativeDecompilerWireAuthoredLocalName])
        assertOtherArraysEmpty(result)
    }

    func testCV03LocalNamesUseSchemaThreeForEmptySchemaFourPrototypes() {
        let input = NativeDecompilerWireAuthoredInputs(
            schemaVersion: 4, names: [], signatures: [], appliedTypes: [], typeDefinitions: [],
            calleeSignatureHints: [], localNames: [], callSitePrototypes: [])
        let result = NativeDecompilerSnapshotBuilder.withAuthoredLocalNames(
            input, stackLocals: [:], registerNames: ["x19": "total"], liveStackStorage: [])

        XCTAssertEqual(result.schemaVersion, UInt32(3))
        XCTAssertEqual(result.callSitePrototypes.isEmpty, true as Bool)
        XCTAssertEqual(result.localNames, [localName] as [NativeDecompilerWireAuthoredLocalName])
        assertOtherArraysEmpty(result)
    }

    func testCV04NoLocalEditsReturnSchemaFourInputUnchanged() throws {
        let input = try baseV4()
        let result = NativeDecompilerSnapshotBuilder.withAuthoredLocalNames(
            input, stackLocals: [:], registerNames: [:], liveStackStorage: [])

        XCTAssertEqual(result, input)
        XCTAssertEqual(result.schemaVersion, UInt32(4))
    }

    func testCV05SchemaThreeCanonicalBytesMatchIndependentLiteral() throws {
        let input = NativeDecompilerWireAuthoredInputs(
            schemaVersion: 3, names: [], signatures: [], appliedTypes: [], typeDefinitions: [],
            calleeSignatureHints: [], localNames: [], callSitePrototypes: [])
        let result = NativeDecompilerSnapshotBuilder.withAuthoredLocalNames(
            input, stackLocals: [:], registerNames: ["x19": "total"], liveStackStorage: [])
        let expected: NativeDecompilerWireAuthoredInputs = NativeDecompilerWireAuthoredInputs(
            schemaVersion: 3,
            names: [],
            signatures: [],
            appliedTypes: [],
            typeDefinitions: [],
            calleeSignatureHints: [],
            localNames: [NativeDecompilerWireAuthoredLocalName(
                storageKind: .register, stackOffset: 0, byteSize: 0,
                register: "x19", name: "total", type: nil)]
        )
        let expectedBytes: Data = try NativeDecompilerWireCanonicalRequest.canonicalAuthoredInputBytes(expected)
        let actualBytes: Data = try NativeDecompilerWireCanonicalRequest.canonicalAuthoredInputBytes(result)

        XCTAssertEqual(actualBytes, expectedBytes)
        XCTAssertEqual(result.schemaVersion, UInt32(3))
        XCTAssertEqual(result.localNames, [localName] as [NativeDecompilerWireAuthoredLocalName])
        XCTAssertEqual(result.callSitePrototypes, [] as [NativeDecompilerWireCallSitePrototype])
        assertOtherArraysEmpty(result)
    }

    func testCV06CalleeHintsCarrySchemaFourLocalsAndPrototype() throws {
        let input = try baseV4(localNames: [localName])
        let prototype = try XCTUnwrap(input.callSitePrototypes.first)
        let fixture = calleeFixture()
        let result = NativeDecompilerSnapshotBuilder.withCalleeSignatureHints(
            input, functionRegions: [fixture.region], functionRange: fixture.range,
            analysis: fixture.analysis, overrides: [:], catalog: fixture.catalog)

        XCTAssertEqual(result.schemaVersion, UInt32(4))
        XCTAssertEqual(result.calleeSignatureHints.map(\.name), ["_malloc", "_free"] as [String])
        XCTAssertEqual(result.localNames, [localName] as [NativeDecompilerWireAuthoredLocalName])
        XCTAssertEqual(result.callSitePrototypes, [prototype] as [NativeDecompilerWireCallSitePrototype])
    }

    func testCV07CalleeHintsCarrySchemaThreeLocalNames() {
        let input = NativeDecompilerWireAuthoredInputs(
            schemaVersion: 3, names: [], signatures: [], appliedTypes: [], typeDefinitions: [],
            calleeSignatureHints: [], localNames: [localName], callSitePrototypes: [])
        let fixture = calleeFixture()
        let result = NativeDecompilerSnapshotBuilder.withCalleeSignatureHints(
            input, functionRegions: [fixture.region], functionRange: fixture.range,
            analysis: fixture.analysis, overrides: [:], catalog: fixture.catalog)

        XCTAssertEqual(result.schemaVersion, UInt32(3))
        XCTAssertEqual(result.calleeSignatureHints.map(\.name), ["_malloc", "_free"] as [String])
        XCTAssertEqual(result.localNames, [localName] as [NativeDecompilerWireAuthoredLocalName])
        XCTAssertEqual(result.callSitePrototypes.isEmpty, true as Bool)
    }

    func testCV08CalleeHintsKeepLegacyEmptyInputAtSchemaTwo() {
        let fixture = calleeFixture()
        let result = NativeDecompilerSnapshotBuilder.withCalleeSignatureHints(
            .empty, functionRegions: [fixture.region], functionRange: fixture.range,
            analysis: fixture.analysis, overrides: [:], catalog: fixture.catalog)

        XCTAssertEqual(result.schemaVersion, UInt32(2))
        XCTAssertEqual(result.calleeSignatureHints.map(\.name), ["_malloc", "_free"] as [String])
        XCTAssertEqual(result.localNames.isEmpty, true as Bool)
        XCTAssertEqual(result.callSitePrototypes.isEmpty, true as Bool)
    }

    func testCV09CalleeHintsUseSchemaTwoForEmptySchemaFourCollections() {
        let input = NativeDecompilerWireAuthoredInputs(
            schemaVersion: 4, names: [], signatures: [], appliedTypes: [], typeDefinitions: [],
            calleeSignatureHints: [], localNames: [], callSitePrototypes: [])
        let fixture = calleeFixture()
        let result = NativeDecompilerSnapshotBuilder.withCalleeSignatureHints(
            input, functionRegions: [fixture.region], functionRange: fixture.range,
            analysis: fixture.analysis, overrides: [:], catalog: fixture.catalog)

        XCTAssertEqual(result.schemaVersion, UInt32(2))
        XCTAssertEqual(result.calleeSignatureHints.map(\.name), ["_malloc", "_free"] as [String])
        XCTAssertEqual(result.localNames, [] as [NativeDecompilerWireAuthoredLocalName])
        XCTAssertEqual(result.callSitePrototypes, [] as [NativeDecompilerWireCallSitePrototype])
    }

    func testCV10NoHintedCalleeReturnsSchemaFourInputUnchanged() throws {
        let input = try baseV4()
        let fixture = calleeFixture()
        let result = NativeDecompilerSnapshotBuilder.withCalleeSignatureHints(
            input, functionRegions: [fixture.region], functionRange: fixture.range,
            analysis: ImageAnalysis(), overrides: [:], catalog: fixture.catalog)

        XCTAssertEqual(result, input)
        XCTAssertEqual(result.schemaVersion, UInt32(4))
    }

    func testCV11BuilderOrderCarriesPrototypeAndRoundTripsBinaryPropertyList() throws {
        let input = try baseV4()
        let prototype = try XCTUnwrap(input.callSitePrototypes.first)
        let fixture = calleeFixture()
        let result = NativeDecompilerSnapshotBuilder.withAuthoredLocalNames(
            NativeDecompilerSnapshotBuilder.withCalleeSignatureHints(
                input, functionRegions: [fixture.region], functionRange: fixture.range,
                analysis: fixture.analysis, overrides: [:], catalog: fixture.catalog),
            stackLocals: [:], registerNames: ["x19": "total"], liveStackStorage: [])

        XCTAssertEqual(result.schemaVersion, UInt32(4))
        XCTAssertEqual(result.calleeSignatureHints.map(\.name), ["_malloc", "_free"] as [String])
        XCTAssertEqual(result.localNames, [localName] as [NativeDecompilerWireAuthoredLocalName])
        XCTAssertEqual(result.callSitePrototypes, [prototype] as [NativeDecompilerWireCallSitePrototype])

        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let data: Data = try encoder.encode(result)
        try NativeDecompilerWireBinaryPropertyListValidator.validate(data)
        let decoded: NativeDecompilerWireAuthoredInputs = try PropertyListDecoder().decode(
            NativeDecompilerWireAuthoredInputs.self, from: data)
        XCTAssertEqual(decoded, result)
    }

    private var localName: NativeDecompilerWireAuthoredLocalName {
        NativeDecompilerWireAuthoredLocalName(
            storageKind: .register, stackOffset: 0, byteSize: 0,
            register: "x19", name: "total", type: nil)
    }

    private func baseV4(
        localNames: [NativeDecompilerWireAuthoredLocalName] = []
    ) throws -> NativeDecompilerWireAuthoredInputs {
        let decoded = try decode([
            "schemaVersion": 4, "names": [], "signatures": [], "appliedTypes": [],
            "typeDefinitions": [], "calleeSignatureHints": [], "localNames": [],
            "callSitePrototypes": [record()],
        ])
        return NativeDecompilerWireAuthoredInputs(
            schemaVersion: 4, names: [], signatures: [], appliedTypes: [], typeDefinitions: [],
            calleeSignatureHints: [], localNames: localNames,
            callSitePrototypes: decoded.callSitePrototypes)
    }

    private func assertOtherArraysEmpty(
        _ inputs: NativeDecompilerWireAuthoredInputs,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(inputs.names, [] as [NativeDecompilerWireAuthoredName], file: file, line: line)
        XCTAssertEqual(inputs.signatures, [] as [NativeDecompilerWireAuthoredSignature], file: file, line: line)
        XCTAssertEqual(inputs.appliedTypes, [] as [NativeDecompilerWireAppliedType], file: file, line: line)
        XCTAssertEqual(inputs.typeDefinitions, [] as [NativeDecompilerWireAuthoredTypeDefinition], file: file, line: line)
        XCTAssertEqual(inputs.calleeSignatureHints, [] as [NativeDecompilerWireCalleeSignatureHint], file: file, line: line)
    }

    private func calleeFixture() -> (
        region: NativeDecompilerWireMemoryRegion,
        range: Range<UInt64>,
        analysis: ImageAnalysis,
        catalog: CallSignatureCatalog
    ) {
        let entry: UInt64 = 0x1_0000_1000
        // mov x0, #0x40; bl +0x20 (_malloc); b +0x40 (tail call to _free); bl +0x10 (unknown)
        let words: [UInt32] = [0xd280_0800, 0x9400_0008, 0x1400_0010, 0x9400_0004]
        let bytes = Data(words.flatMap { word in (0..<4).map { UInt8(truncatingIfNeeded: word >> (8 * $0)) } })
        let region = NativeDecompilerWireMemoryRegion(
            name: "__text", startAddress: .init(entry), permissions: .readExecute,
            rawBytes: bytes, effectiveBytes: bytes, appliedPatchIDs: [])
        let range = entry ..< entry + UInt64(bytes.count)
        var analysis = ImageAnalysis()
        analysis.symbols = [
            SymbolSummary(id: UUID(), name: "_malloc", address: entry + 0x24, kind: "function",
                          libraryName: nil, rawLinkageName: "_malloc"),
            SymbolSummary(id: UUID(), name: "_free", address: entry + 0x48, kind: "function",
                          libraryName: nil, rawLinkageName: "_free"),
        ]
        let catalog = CallSignatureCatalog([
            CallSignatureSpec(canonicalName: "malloc", returnType: "void *",
                              parameters: [.init(type: "size_t", name: "size")]),
            CallSignatureSpec(canonicalName: "free", returnType: "void",
                              parameters: [.init(type: "void *", name: "ptr")]),
        ])
        return (region: region, range: range, analysis: analysis, catalog: catalog)
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

    private func decode(_ source: [String: Any]) throws -> NativeDecompilerWireAuthoredInputs {
        let data = try PropertyListSerialization.data(fromPropertyList: source, format: .binary, options: 0)
        try NativeDecompilerWireBinaryPropertyListValidator.validate(data)
        return try PropertyListDecoder().decode(NativeDecompilerWireAuthoredInputs.self, from: data)
    }
}
