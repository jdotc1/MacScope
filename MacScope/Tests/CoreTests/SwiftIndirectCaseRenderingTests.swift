import Foundation
import XCTest
@testable import MacScope

// In-memory definitions; no parser or compiler fixture.
final class SwiftIndirectCaseRenderingTests: XCTestCase {
    func testRecordedIndirectCaseKeepsAssociatedType() {
        let type = SwiftTypeDescriptor(kind: .enum, name: "Tree", fields: [
            SwiftField(name: "branch", typeName: "Tree", isIndirectCase: true)
        ])
        XCTAssertEqual(SwiftInterfaceRenderer.render(types: [type]), """
        enum Tree {
            indirect case branch(Tree)
        }
        """)
    }

    func testSameAssociatedTypeWithoutFlagStaysOrdinary() {
        let type = SwiftTypeDescriptor(kind: .enum, name: "Tree", fields: [
            SwiftField(name: "branch", typeName: "Tree", isIndirectCase: false)
        ])
        XCTAssertEqual(SwiftInterfaceRenderer.render(types: [type]), """
        enum Tree {
            case branch(Tree)
        }
        """)
    }

    func testMixedFlagsPreserveOrderWithoutVarOrNameHeuristics() {
        let type = SwiftTypeDescriptor(kind: .enum, name: "Tree", fields: [
            SwiftField(name: "leaf", typeName: "Int", isIndirectCase: true),
            SwiftField(name: "indirectBranch", typeName: "Tree", isVar: true),
            SwiftField(name: "last", isIndirectCase: true)
        ])
        XCTAssertEqual(SwiftInterfaceRenderer.render(types: [type]), """
        enum Tree {
            indirect case leaf(Int)
            case indirectBranch(Tree)
            indirect case last
        }
        """)
    }

    func testUnknownAssociatedTypeKeepsMarkerWithoutMangledFallback() {
        let type = SwiftTypeDescriptor(kind: .enum, name: "UnknownPayload", fields: [
            SwiftField(name: "payload", typeName: nil, mangledTypeName: "unresolvedShape",
                       isIndirectCase: true, unresolvedReason: "unnameableShape")
        ])
        XCTAssertEqual(SwiftInterfaceRenderer.render(types: [type]), """
        enum UnknownPayload {
            indirect case payload
        }
        """)
    }

    func testStructFieldsKeepLetAndVarRegardlessOfIndirectFlag() {
        let type = SwiftTypeDescriptor(kind: .struct, name: "Record", fields: [
            SwiftField(name: "fixed", typeName: "Int", isIndirectCase: true),
            SwiftField(name: "mutable", isVar: true, isIndirectCase: true)
        ])
        XCTAssertEqual(SwiftInterfaceRenderer.render(types: [type]), """
        struct Record {
            let fixed: Int
            var mutable
        }
        """)
    }

    func testClassFieldsKeepLetAndVarRegardlessOfIndirectFlag() {
        let type = SwiftTypeDescriptor(kind: .class, name: "Object", fields: [
            SwiftField(name: "fixed", isIndirectCase: true),
            SwiftField(name: "mutable", typeName: "String", isVar: true, isIndirectCase: true)
        ])
        XCTAssertEqual(SwiftInterfaceRenderer.render(types: [type]), """
        class Object {
            let fixed
            var mutable: String
        }
        """)
    }

    func testLegacyFieldWithoutIndirectKeyDecodesToOrdinaryCase() throws {
        // Newly authored tiny JSON, not a retained input or parser fixture.
        let bytes = Data(#"{"name":"legacy","typeName":"Tree","isVar":true}"#.utf8)
        let field = try JSONDecoder().decode(SwiftField.self, from: bytes)
        XCTAssertFalse(field.isIndirectCase)
        XCTAssertTrue(field.isVar)
        let type = SwiftTypeDescriptor(kind: .enum, name: "Tree", fields: [field])
        XCTAssertEqual(SwiftInterfaceRenderer.render(types: [type]), """
        enum Tree {
            case legacy(Tree)
        }
        """)
    }
}
