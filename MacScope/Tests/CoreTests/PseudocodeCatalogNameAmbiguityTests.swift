import XCTest
@testable import MacScope

// Source-only fixture definitions. These fixtures have not been executed.
final class PseudocodeCatalogNameAmbiguityTests: XCTestCase {
    private let address: UInt64 = 0x1000
    private let objectID = MacIRParameterRowID(rawValue: "catalog-object")

    private func record(_ name: String = "Packet") -> TypeDefinition {
        TypeDefinition(kind: .struct, name: name, fields: [
            FieldDef(name: "head", type: "uint32_t"),
            FieldDef(name: "payload", type: "uint32_t")
        ])
    }

    private func conflictingRecord() -> TypeDefinition {
        TypeDefinition(kind: .struct, name: "Packet", fields: [
            FieldDef(name: "shortHead", type: "uint16_t"),
            FieldDef(name: "tag", type: "uint16_t"),
            FieldDef(name: "replacement", type: "uint32_t")
        ])
    }

    private func alias(_ name: String, to target: String) -> TypeDefinition {
        TypeDefinition(kind: .typedef, name: name,
                       fields: [FieldDef(name: "", type: target)])
    }

    private func object(_ type: String = "Packet", byteSize: Int = 8) throws -> MacIRFunctionParameter {
        var pieces = [DarwinARM64RichParameterPiece(register: .gpr(index: 0, carrierWidth: 64),
                                                    valueByteOffset: 0, size: min(byteSize, 8))]
        if byteSize > 8 {
            pieces.append(DarwinARM64RichParameterPiece(register: .gpr(index: 1, carrierWidth: 64),
                                                       valueByteOffset: 8, size: byteSize - 8))
        }
        return try XCTUnwrap(MacIRFunctionParameter(
            id: objectID, bindingID: nil, sourcePosition: 0,
            abiLocation: .unbound(reason: .unsupportedType(type)),
            richLocation: .composite(pieces: pieces),
            type: type, name: "object", evidence: .authoritativeUser))
    }

    private func pointer(_ type: String) throws -> MacIRFunctionParameter {
        try XCTUnwrap(MacIRFunctionParameter(
            id: MacIRParameterRowID(rawValue: "catalog-pointer"), bindingID: .gpr(0),
            sourcePosition: 0, abiLocation: .gpr(index: 0, carrierWidth: 64),
            type: type, name: "p", evidence: .authoritativeUser))
    }

    private func fragment(offset: Int = 4, size: Int = 4) -> MacIROperation {
        .assign(destination: .register(name: "x9", version: 0),
                source: .argumentFragment(rowID: objectID, byteOffset: offset, size: size))
    }

    private func addition(bytes: Int64 = 3) -> MacIROperation {
        .binary(destination: .register(name: "x10", version: 0), op: "+",
                left: .argument(bindingID: .gpr(0)), right: .immediate(bytes))
    }

    @discardableResult
    private func assertRendering(
        _ operation: MacIROperation, parameters: [MacIRFunctionParameter],
        types: [TypeDefinition], equals expected: String,
        file: StaticString = #filePath, line: UInt = #line
    ) -> String {
        let instruction = MacIRInstruction(
            source: MacIRSourceSpan(address: address, byteText: "00 00 00 00",
                                   mnemonic: "mov", operands: ""),
            operation: operation)
        let function = MacIRFunction(name: "catalog_fixture", startAddress: address,
                                     parameters: parameters, instructions: [instruction])
        let printer = PseudocodePrinter(options: DecompilerOptions(
            structureControlFlow: false, deadCodeElimination: false,
            nopElision: false, functionSizeGate: 1024))
        let names = PseudocodeNameContext(function: function, types: types)
        let rendered = printer.render(instruction: instruction, names: names)
        XCTAssertEqual(rendered, expected, file: file, line: line)
        let document = printer.print(function: function, types: types)
        XCTAssertEqual(document.lines(sourcedAt: address).map {
            $0.text.trimmingCharacters(in: .whitespaces)
        }, [expected + ";"], file: file, line: line)
        return rendered
    }

    func testUniqueCatalogRecordRetainsExactABIField() throws {
        assertRendering(fragment(), parameters: [try object()], types: [record()],
                        equals: "x9_0 = object.payload")
    }

    func testConflictingDuplicateRecordsRefuseFieldSugarInBothOrders() throws {
        let first = record()
        let second = conflictingRecord()
        let expected = "x9_0 = __abi_fragment(object, 4, 4)"
        let forward = assertRendering(fragment(), parameters: [try object()],
                                      types: [first, second], equals: expected)
        let reverse = assertRendering(fragment(), parameters: [try object()],
                                      types: [second, first], equals: expected)
        XCTAssertEqual(forward, reverse)
    }

    func testIdenticalDuplicateRecordsAreStillAmbiguous() throws {
        let definition = record()
        assertRendering(fragment(), parameters: [try object()], types: [definition, definition],
                        equals: "x9_0 = __abi_fragment(object, 4, 4)")
    }

    func testUniqueWholePointerTypedefRetainsExactByteOffset() throws {
        assertRendering(addition(), parameters: [try pointer("CountPointer")],
                        types: [alias("CountPointer", to: "uint32_t *")],
                        equals: "x10_0 = (CountPointer)((uint8_t *)(p) + 0x3)")
    }

    func testConflictingDuplicateAliasesCannotProvePointerInEitherOrder() throws {
        let pointerAlias = alias("CountPointer", to: "uint32_t *")
        let scalarAlias = alias("CountPointer", to: "uint32_t")
        let expected = "x10_0 = p + 0x3"
        let forward = assertRendering(addition(), parameters: [try pointer("CountPointer")],
                                      types: [pointerAlias, scalarAlias], equals: expected)
        let reverse = assertRendering(addition(), parameters: [try pointer("CountPointer")],
                                      types: [scalarAlias, pointerAlias], equals: expected)
        XCTAssertEqual(forward, reverse)
    }

    func testIdenticalDuplicatePointerAliasesDoNotProvePointer() throws {
        let definition = alias("CountPointer", to: "uint32_t *")
        assertRendering(addition(), parameters: [try pointer("CountPointer")],
                        types: [definition, definition], equals: "x10_0 = p + 0x3")
    }

    func testUniqueAliasCannotResolveThroughDuplicateAlias() throws {
        let types = [alias("OuterPointer", to: "InnerPointer"),
                     alias("InnerPointer", to: "uint32_t *"),
                     alias("InnerPointer", to: "uint64_t *")]
        assertRendering(addition(), parameters: [try pointer("OuterPointer")],
                        types: types, equals: "x10_0 = p + 0x3")
        assertRendering(addition(), parameters: [try pointer("OuterPointer")],
                        types: Array(types.reversed()), equals: "x10_0 = p + 0x3")
    }

    func testUnrelatedDuplicatesPreserveExplicitPointerAndUniqueRecord() throws {
        let types = [record("Unaffected"), record(), conflictingRecord()]
        assertRendering(fragment(), parameters: [try object("Unaffected")], types: types,
                        equals: "x9_0 = object.payload")
        assertRendering(addition(bytes: 8), parameters: [try pointer("uint32_t *")], types: types,
                        equals: "x10_0 = p + 0x2")
    }

    func testExplicitPointerToAmbiguousPointeeRetainsByteFallback() throws {
        let types = [alias("Element", to: "uint32_t"), alias("Element", to: "uint64_t")]
        let expected = "x10_0 = (Element *)((uint8_t *)(p) + 0x8)"
        assertRendering(addition(bytes: 8), parameters: [try pointer("Element *")],
                        types: types, equals: expected)
        assertRendering(addition(bytes: 8), parameters: [try pointer("Element *")],
                        types: Array(types.reversed()), equals: expected)
    }

    func testAmbiguousDependencyDoesNotInventLaterFieldOffset() throws {
        let outer = TypeDefinition(kind: .struct, name: "Container", fields: [
            FieldDef(name: "prefix", type: "uint32_t"),
            FieldDef(name: "ambiguous", type: "Choice"),
            FieldDef(name: "suffix", type: "uint32_t")
        ])
        let types = [outer, alias("Choice", to: "uint16_t"), alias("Choice", to: "uint32_t")]
        assertRendering(fragment(), parameters: [try object("Container", byteSize: 12)], types: types,
                        equals: "x9_0 = __abi_fragment(object, 4, 4)")
        assertRendering(fragment(offset: 8), parameters: [try object("Container", byteSize: 12)], types: types,
                        equals: "x9_0 = __abi_fragment(object, 8, 4)")
        assertRendering(fragment(offset: 0), parameters: [try object("Container", byteSize: 12)], types: types,
                        equals: "x9_0 = object.prefix")
    }

    func testCyclicAndIncompleteRecordsContinueToRefuseFieldSugar() throws {
        let definitions = [
            TypeDefinition(kind: .struct, name: "CycleRecord", fields: [
                FieldDef(name: "cycle", type: "CycleRecord")
            ]),
            TypeDefinition(kind: .struct, name: "IncompleteRecord", fields: [
                FieldDef(name: "missing", type: "Absent")
            ]),
            TypeDefinition(kind: .struct, name: "UnknownRecord", fields: [
                FieldDef(name: "unknown", type: "uint32_t", layoutIsUnknown: true)
            ])
        ]
        for definition in definitions {
            assertRendering(fragment(offset: 0), parameters: [try object(definition.name)],
                            types: [definition], equals: "x9_0 = __abi_fragment(object, 0, 4)")
        }
    }

    func testCyclicAndIncompleteAliasesContinueToRefusePointerProof() throws {
        let cases: [(String, [TypeDefinition])] = [
            ("CycleA", [alias("CycleA", to: "CycleB"), alias("CycleB", to: "CycleA")]),
            ("Empty", [TypeDefinition(kind: .typedef, name: "Empty")]),
            ("Missing", [alias("Missing", to: "Absent")]),
            ("Unknown", [TypeDefinition(kind: .typedef, name: "Unknown", fields: [
                FieldDef(name: "", type: "uint32_t *", layoutIsUnknown: true)
            ])]),
            ("Multiple", [TypeDefinition(kind: .typedef, name: "Multiple", fields: [
                FieldDef(name: "first", type: "uint32_t *"),
                FieldDef(name: "second", type: "uint64_t *")
            ])]),
            ("Vector", [TypeDefinition(kind: .typedef, name: "Vector", fields: [
                FieldDef(name: "", type: "uint32_t *")
            ], vectorByteSize: 16)])
        ]
        for (name, types) in cases {
            assertRendering(addition(bytes: 8), parameters: [try pointer(name)], types: types,
                            equals: "x10_0 = p + 0x8")
        }
    }
}
