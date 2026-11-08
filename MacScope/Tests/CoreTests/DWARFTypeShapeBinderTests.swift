import Foundation
import XCTest
@testable import MacScope

/// OS2 DWARF type-shape binder: `DWARFFunctionDeclaration.returnShape` and
/// `Parameter.shape` come from the type DIE chain only, never from the spelling.
/// Fixtures are synthetic DIE trees handed to the reader's declaration walker.
final class DWARFTypeShapeBinderTests: XCTestCase {
    typealias Shape = DWARFTypeShape

    private static let tagReference: UInt64 = 0x10
    private static let tagUnspecified: UInt64 = 0x3b
    private static let encBoolean: UInt64 = 0x02
    private static let encFloat: UInt64 = 0x04
    private static let encSigned: UInt64 = 0x05
    private static let encSignedChar: UInt64 = 0x06
    private static let encUnsigned: UInt64 = 0x07
    private static let encUnsignedChar: UInt64 = 0x08

    // MARK: - Rule 1: transparent qualifiers

    func testQualifiersAndTypedefsAreFollowedWithoutNameSpecialCasing() {
        // 0 int(s32) <- 1 typedef "id" <- 2 const <- 3 volatile <- 4 restrict <- 5 atomic
        let types = [
            base(enc: Self.encSigned, size: 4),
            link(DWARFConstants.tagTypedef, name: "id", to: 0),
            link(DWARFConstants.tagConstType, to: 1),
            link(DWARFConstants.tagVolatileType, to: 2),
            link(DWARFConstants.tagRestrictType, to: 3),
            link(DWARFConstants.tagAtomicType, to: 4),
        ]
        let declaration = bind(types, ret: 5, params: [1, 2, 3, 4, 5])
        XCTAssertEqual(declaration.returnShape, .s32)
        XCTAssertEqual(declaration.parameters.map(\.shape), [.s32, .s32, .s32, .s32, .s32],
                       "a typedef spelled id over int is s32: names are not special-cased")
    }

    func testNSIntegerAndBOOLTypedefsResolveThroughBaseTypes() {
        let types = [
            base(enc: Self.encSigned, size: 8),                      // 0 long
            link(DWARFConstants.tagTypedef, name: "NSInteger", to: 0), // 1
            base(enc: Self.encBoolean, size: 1),                     // 2 _Bool
            link(DWARFConstants.tagTypedef, name: "BOOL", to: 2),    // 3
            base(enc: Self.encSignedChar, size: 1),                  // 4 signed char
            link(DWARFConstants.tagTypedef, name: "BOOL", to: 4),    // 5 old-style BOOL
        ]
        let declaration = bind(types, ret: 1, params: [3, 5])
        XCTAssertEqual(declaration.returnShape, .s64)
        XCTAssertEqual(declaration.parameters.map(\.shape), [.bool, .s8])
    }

    // MARK: - Rule 2: base types

    func testBaseTypeEncodingAndSizeTable() {
        let cases: [(UInt64, UInt64, Shape)] = [
            (Self.encSigned, 1, .s8), (Self.encSigned, 2, .s16), (Self.encSigned, 4, .s32), (Self.encSigned, 8, .s64),
            (Self.encSignedChar, 1, .s8), (Self.encSignedChar, 4, .s32),
            (Self.encUnsigned, 1, .u8), (Self.encUnsigned, 2, .u16), (Self.encUnsigned, 4, .u32), (Self.encUnsigned, 8, .u64),
            (Self.encUnsignedChar, 1, .u8), (Self.encUnsignedChar, 2, .u16),
            (Self.encBoolean, 1, .bool), (Self.encFloat, 4, .f32), (Self.encFloat, 8, .f64),
            // Everything else is unknown.
            (Self.encBoolean, 4, .unknown), (Self.encFloat, 16, .unknown), (Self.encFloat, 2, .unknown),
            (Self.encSigned, 16, .unknown), (Self.encUnsigned, 3, .unknown), (0x01, 8, .unknown),
        ]
        let types = cases.map { base(enc: $0.0, size: $0.1) }
        let declaration = bind(types, ret: nil, params: Array(types.indices))
        XCTAssertEqual(declaration.parameters.map(\.shape), cases.map(\.2))
    }

    func testBaseTypeMissingEncodingOrSizeIsUnknown() {
        let types = [
            spec(DWARFConstants.tagBaseType, attributes: [DWARFConstants.atByteSize: .uint(4)]),
            spec(DWARFConstants.tagBaseType, attributes: [DWARFConstants.atEncoding: .uint(Self.encSigned)]),
        ]
        XCTAssertEqual(bind(types, ret: nil, params: [0, 1]).parameters.map(\.shape), [.unknown, .unknown])
    }

    // MARK: - Rule 3: void

    func testSubprogramWithoutTypeReturnsVoidAndUntypedParameterIsUnknown() {
        let declaration = bind([], ret: nil, params: [nil])
        XCTAssertEqual(declaration.returnShape, .void)
        XCTAssertNil(declaration.returnType)
        XCTAssertEqual(declaration.parameters.map(\.shape), [.unknown], "only a return can be void")
    }

    func testReturnWithUnresolvableReferenceIsUnknownNotVoid() {
        let subprogram = DWARFDIENode(tag: DWARFConstants.tagSubprogram,
                                      attributes: [DWARFConstants.atType: .uint(0xdead)],
                                      cuOffset: 0x20, children: [])
        XCTAssertEqual(walk(subprogram, in: [subprogram]).returnShape, .unknown)
    }

    // MARK: - Rule 4: pointers

    func testObjectiveCPointerClassification() {
        let all = [
            spec(DWARFConstants.tagStructureType, name: "objc_object"),            // 0
            ptr(to: 0),                                                            // 1
            link(DWARFConstants.tagTypedef, name: "id", to: 1),                    // 2 id
            spec(DWARFConstants.tagStructureType, name: "objc_class"),             // 3
            ptr(to: 3),                                                            // 4
            link(DWARFConstants.tagTypedef, name: "Class", to: 4),                 // 5 Class
            spec(DWARFConstants.tagStructureType, name: "objc_selector"),          // 6
            ptr(to: 6),                                                            // 7
            link(DWARFConstants.tagTypedef, name: "SEL", to: 7),                   // 8 SEL
            spec(DWARFConstants.tagClassType, name: "NSString",
                 attributes: [DWARFConstants.atAppleRuntimeClass: .uint(0x10)]),   // 9
            ptr(to: 9),                                                            // 10 NSString *
            spec(DWARFConstants.tagStructureType, name: "__block_literal_generic"), // 11
            ptr(to: 11),                                                           // 12
            spec(DWARFConstants.tagSubroutineType),                                // 13
            ptr(to: 13, attributes: [DWARFConstants.atAppleBlock: .uint(1)]),      // 14 void (^)(void)
            spec(DWARFConstants.tagStructureType, name: "NSArray",
                 attributes: [DWARFConstants.atAppleRuntimeClass: .uint(0x10)]),   // 15
            link(DWARFConstants.tagConstType, to: 15),                             // 16
            ptr(to: 16),                                                           // 17 const NSArray *
            spec(DWARFConstants.tagClassType, name: "objc_object"),                // 18 class_type spelling
            ptr(to: 18),                                                           // 19
        ]
        let declaration = bind(all, ret: 2, params: [2, 5, 8, 10, 12, 14, 17, 19])
        XCTAssertEqual(declaration.returnShape, .object)
        XCTAssertEqual(declaration.parameters.map(\.shape),
                       [.object, .classPointer, .selector, .object, .block, .block, .object, .object])
    }

    func testDataPointersAndUnknownPointees() {
        let types = [
            ptr(),                                                                  // 0 void *
            base(enc: Self.encSigned, size: 4),                                     // 1 int
            ptr(to: 1),                                                             // 2 int *
            ptr(to: 2),                                                             // 3 int **
            spec(DWARFConstants.tagStructureType, name: "Point"),                   // 4
            ptr(to: 4),                                                             // 5 Point *
            spec(DWARFConstants.tagUnionType, name: "U"),                           // 6
            ptr(to: 6),                                                             // 7 U *
            link(DWARFConstants.tagConstType),                                      // 8 const void
            ptr(to: 8),                                                             // 9 const void *
            spec(DWARFConstants.tagSubroutineType),                                 // 10
            ptr(to: 10),                                                            // 11 function pointer
            spec(DWARFConstants.tagEnumerationType, attributes: [DWARFConstants.atByteSize: .uint(4)]), // 12
            ptr(to: 12),                                                            // 13 enum * (data pointer)
            spec(DWARFConstants.tagArrayType, type: 1),                             // 14
            ptr(to: 14),                                                            // 15 pointer to array
            ptr(to: 0xdead_beef_0, raw: true),                                      // 16 missing pointee
        ]
        let declaration = bind(types, ret: nil, params: [0, 2, 3, 5, 7, 9, 11, 13, 15, 16])
        XCTAssertEqual(declaration.parameters.map(\.shape), [
            .dataPointer, .dataPointer, .dataPointer, .dataPointer, .dataPointer, .dataPointer,
            .unknown, .dataPointer, .unknown, .unknown,
        ])
    }

    // MARK: - Rule 5: enumerations

    func testEnumerations() {
        let types = [
            base(enc: Self.encSigned, size: 8),                                     // 0 long
            link(DWARFConstants.tagTypedef, name: "NSInteger", to: 0),              // 1
            spec(DWARFConstants.tagEnumerationType, type: 1,
                 attributes: [DWARFConstants.atByteSize: .uint(8)]),                // 2 enum : NSInteger
            spec(DWARFConstants.tagEnumerationType, attributes: [DWARFConstants.atByteSize: .uint(4)]), // 3
            spec(DWARFConstants.tagEnumerationType, attributes: [DWARFConstants.atByteSize: .uint(8)]), // 4
            spec(DWARFConstants.tagEnumerationType),                                // 5 no size
            base(enc: Self.encUnsigned, size: 4),                                   // 6 unsigned
            spec(DWARFConstants.tagEnumerationType, type: 6,
                 attributes: [DWARFConstants.atByteSize: .uint(4)]),                // 7 enum : unsigned
            ptr(),                                                                  // 8 void *
            spec(DWARFConstants.tagEnumerationType, type: 8),                       // 9 nonsense underlying
        ]
        let declaration = bind(types, ret: 3, params: [2, 3, 4, 5, 7, 9])
        XCTAssertEqual(declaration.returnShape, .lossyEnum(.s32))
        XCTAssertEqual(declaration.parameters.map(\.shape), [
            .s64, .lossyEnum(.s32), .lossyEnum(.other), .lossyEnum(.other), .u32, .unknown,
        ])
    }

    // MARK: - Rule 6: unknown

    func testAggregatesReferencesAndUnspecifiedAreUnknown() {
        let types = [
            spec(DWARFConstants.tagStructureType, name: "Point", attributes: [DWARFConstants.atByteSize: .uint(16)]), // 0
            spec(DWARFConstants.tagUnionType, name: "U"),                           // 1
            base(enc: Self.encSigned, size: 4),                                     // 2
            spec(DWARFConstants.tagArrayType, type: 2),                             // 3
            spec(DWARFConstants.tagSubroutineType),                                 // 4
            spec(Self.tagReference, type: 2),                                       // 5
            spec(Self.tagUnspecified, name: "decltype(nullptr)"),                   // 6
            spec(DWARFConstants.tagClassType, name: "NSObject"),                    // 7 by value
            spec(0x7777),                                                           // 8 unrecognised tag
        ]
        let declaration = bind(types, ret: 0, params: Array(types.indices))
        XCTAssertEqual(declaration.returnShape, .unknown)
        // Index 2 is the plain int that the array element refers to; it is a real s32 base type.
        var expected = Array(repeating: Shape.unknown, count: types.count)
        expected[2] = .s32
        XCTAssertEqual(declaration.parameters.map(\.shape), expected)
    }

    // MARK: - Cycles, depth, missing references

    func testTypedefCycleAndSelfReferenceAreUnknown() {
        let types = [
            link(DWARFConstants.tagTypedef, name: "A", to: 1),
            link(DWARFConstants.tagTypedef, name: "B", to: 0),
            link(DWARFConstants.tagTypedef, name: "Self", to: 2),
            ptr(to: 0),   // pointer whose pointee chain is a cycle
        ]
        let declaration = bind(types, ret: 0, params: [0, 1, 2, 3])
        XCTAssertEqual(declaration.returnShape, .unknown)
        XCTAssertEqual(declaration.parameters.map(\.shape), [.unknown, .unknown, .unknown, .unknown])
    }

    func testMissingReferenceIsUnknown() {
        let types = [link(DWARFConstants.tagTypedef, name: "Dangling", raw: 0xbad0)]
        XCTAssertEqual(bind(types, ret: 0, params: [0]).parameters.map(\.shape), [.unknown])
    }

    func testDepthCapOfSixteen() {
        // 0 int, then typedef chain 1...N each pointing at the previous one.
        func chain(_ links: Int) -> DWARFFunctionDeclaration {
            var types = [base(enc: Self.encSigned, size: 4)]
            for index in 1...links { types.append(link(DWARFConstants.tagTypedef, name: "T\(index)", to: index - 1)) }
            return bind(types, ret: nil, params: [links])
        }
        XCTAssertEqual(chain(5).parameters.map(\.shape), [.s32])
        XCTAssertEqual(chain(16).parameters.map(\.shape), [.s32], "the 16th hop is still inside the cap")
        XCTAssertEqual(chain(17).parameters.map(\.shape), [.unknown], "the 17th hop exceeds the cap")
        XCTAssertEqual(chain(40).parameters.map(\.shape), [.unknown])
    }

    // MARK: - Spellings and existing output are unchanged

    func testSpellingsStillComeFromNamesAndShapesNeverReadThem() {
        let types = [
            base(enc: Self.encSigned, size: 4, name: "int"),                        // 0
            link(DWARFConstants.tagTypedef, name: "Weird", to: 0),                  // 1
        ]
        let declaration = bind(types, ret: 1, params: [1])
        XCTAssertEqual(declaration.returnType, "Weird")
        XCTAssertEqual(declaration.parameters.map(\.type), ["Weird"])
        XCTAssertEqual(declaration.returnShape, .s32)
        XCTAssertEqual(declaration.parameters.map(\.shape), [.s32])
    }

    // MARK: - Fixture builders

    private struct TypeSpec {
        var tag: UInt64
        var attributes: [UInt64: DWARFAttributeValue]
    }

    private static let firstTypeOffset = 0x100
    private static let stride = 0x10

    private func offset(of index: Int) -> UInt64 { UInt64(Self.firstTypeOffset + index * Self.stride) }

    private func spec(
        _ tag: UInt64, name: String? = nil, type: Int? = nil,
        attributes: [UInt64: DWARFAttributeValue] = [:]
    ) -> TypeSpec {
        var attributes = attributes
        if let name { attributes[DWARFConstants.atName] = .string(name) }
        if let type { attributes[DWARFConstants.atType] = .uint(offset(of: type)) }
        return TypeSpec(tag: tag, attributes: attributes)
    }

    private func base(enc: UInt64, size: UInt64, name: String? = nil) -> TypeSpec {
        spec(DWARFConstants.tagBaseType, name: name ?? "base",
             attributes: [DWARFConstants.atEncoding: .uint(enc), DWARFConstants.atByteSize: .uint(size)])
    }

    /// A qualifier or typedef; `to` nil means no DW_AT_type (void), `raw` is an absolute bad offset.
    private func link(_ tag: UInt64, name: String? = nil, to: Int? = nil, raw: UInt64? = nil) -> TypeSpec {
        var attributes: [UInt64: DWARFAttributeValue] = [:]
        if let to { attributes[DWARFConstants.atType] = .uint(offset(of: to)) }
        if let raw { attributes[DWARFConstants.atType] = .uint(raw) }
        if let name { attributes[DWARFConstants.atName] = .string(name) }
        return TypeSpec(tag: tag, attributes: attributes)
    }

    private func ptr(
        to: Int? = nil, raw: Bool = false,
        attributes: [UInt64: DWARFAttributeValue] = [:]
    ) -> TypeSpec {
        var attributes = attributes
        if raw { attributes[DWARFConstants.atType] = .uint(0xbad0) }
        else if let to { attributes[DWARFConstants.atType] = .uint(offset(of: to)) }
        return TypeSpec(tag: DWARFConstants.tagPointerType, attributes: attributes)
    }

    /// Builds a CU with one subprogram (return `ret`, parameters `params`, indices into `types`)
    /// followed by the type DIEs, then runs the reader's declaration walker over it.
    private func bind(_ types: [TypeSpec], ret: Int?, params: [Int?]) -> DWARFFunctionDeclaration {
        var attributes: [UInt64: DWARFAttributeValue] = [DWARFConstants.atLowPC: .address(0x1000)]
        if let ret { attributes[DWARFConstants.atType] = .uint(offset(of: ret)) }
        let parameters = params.enumerated().map { ordinal, index -> DWARFDIENode in
            var parameterAttributes: [UInt64: DWARFAttributeValue] = [:]
            if let index { parameterAttributes[DWARFConstants.atType] = .uint(offset(of: index)) }
            return DWARFDIENode(tag: DWARFConstants.tagFormalParameter, attributes: parameterAttributes,
                                cuOffset: 0x40 + ordinal, children: [])
        }
        let subprogram = DWARFDIENode(tag: DWARFConstants.tagSubprogram, attributes: attributes,
                                      cuOffset: 0x20, children: parameters)
        let typeNodes = types.enumerated().map { index, spec in
            DWARFDIENode(tag: spec.tag, attributes: spec.attributes,
                         cuOffset: Self.firstTypeOffset + index * Self.stride, children: [])
        }
        return walk(subprogram, in: [subprogram] + typeNodes)
    }

    private func walk(_ subprogram: DWARFDIENode, in nodes: [DWARFDIENode]) -> DWARFFunctionDeclaration {
        let root = DWARFDIENode(tag: DWARFConstants.tagCompileUnit, attributes: [:], cuOffset: 0x0b, children: nodes)
        return DWARFFunctionSignatureReader(sections: .init())
            .declaration(for: subprogram, offsetMap: DWARFFunctionSignatureReader.offsetMap(for: root))
    }
}
