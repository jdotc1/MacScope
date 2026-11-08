import XCTest
@testable import MacScope

final class ObjCMethodOwnerIndexTests: XCTestCase {
    private func method(_ selector: String, _ imp: UInt64?, classSide: Bool = false,
                        encoding: String? = "v16@0:8") -> ObjCMethod {
        .init(selector: selector, typeEncoding: encoding, isClassMethod: classSide, implementation: imp)
    }

    private func objcClass(_ name: String, superclass: String? = nil,
                           classMethods: [ObjCMethod] = [], instanceMethods: [ObjCMethod] = []) -> ObjCClass {
        .init(name: name, superclassName: superclass, adoptedProtocols: [], classMethods: classMethods,
              instanceMethods: instanceMethods, ivars: [], properties: [])
    }

    private func category(_ name: String, on className: String,
                          classMethods: [ObjCMethod] = [], instanceMethods: [ObjCMethod] = []) -> ObjCCategory {
        .init(name: name, className: className, classMethods: classMethods,
              instanceMethods: instanceMethods, adoptedProtocols: [], properties: [])
    }

    func testUniqueInstanceOwner() {
        let classes = [objcClass("A", instanceMethods: [method("foo", 0x10)])]
        guard case .unique(let match) = ObjCMethodOwnerIndex.owner(
            implementation: 0x10, classes: classes, categories: []) else {
            return XCTFail("expected a unique owner")
        }
        XCTAssertEqual(match.owner.container, .objcClass(name: "A"))
        XCTAssertFalse(match.owner.isClassMethod)
        XCTAssertEqual(match.method.selector, "foo")
    }

    func testClassSideOwnerNormalizesMethodSideFlag() {
        // The stored method claims instance side; its container list is the authority.
        let classes = [objcClass("A", classMethods: [method("make", 0x20, classSide: false)])]
        guard case .unique(let match) = ObjCMethodOwnerIndex.owner(
            implementation: 0x20, classes: classes, categories: []) else {
            return XCTFail("expected a unique owner")
        }
        XCTAssertTrue(match.owner.isClassMethod)
        XCTAssertTrue(match.method.isClassMethod)
    }

    func testUnknownImplementationHasNoOwner() {
        let classes = [objcClass("A", instanceMethods: [method("foo", 0x10)])]
        XCTAssertEqual(ObjCMethodOwnerIndex.owner(implementation: 0x99, classes: classes, categories: []), .none)
    }

    func testSharedImplementationAcrossOwnersIsAmbiguousAndSorted() {
        let classes = [objcClass("A", instanceMethods: [method("foo", 0x10)])]
        let categories = [category("C", on: "A", classMethods: [method("bar", 0x10, classSide: true)])]
        guard case .ambiguous(let matches) = ObjCMethodOwnerIndex.owner(
            implementation: 0x10, classes: classes, categories: categories) else {
            return XCTFail("expected an ambiguous owner")
        }
        XCTAssertEqual(matches.map(\.displayName), ["+[A(C) bar]", "-[A foo]"])
    }

    func testDuplicateRecordOfSameOwnerAndSelectorIsNotAmbiguous() {
        let record = objcClass("A", instanceMethods: [method("foo", 0x10)])
        guard case .unique = ObjCMethodOwnerIndex.owner(
            implementation: 0x10, classes: [record, record], categories: []) else {
            return XCTFail("a repeated identical record must collapse to one owner")
        }
    }

    func testStaticScopeStopsAtFirstDeclaringLevel() {
        let classes = [
            objcClass("Sub", superclass: "Base", instanceMethods: [method("foo", 1)]),
            objcClass("Base", instanceMethods: [method("foo", 2)]),
        ]
        let found = ObjCMethodOwnerIndex.methodsInStaticScope(
            selector: "foo", receiverClassName: "Sub", isClassMethod: false, classes: classes, categories: [])
        XCTAssertEqual(found.compactMap { $0.method.implementation }, [1])
        XCTAssertEqual(found.first?.owner.container, .objcClass(name: "Sub"))
    }

    func testStaticScopeInheritsFromSuperclass() {
        let classes = [
            objcClass("Sub", superclass: "Base"),
            objcClass("Base", instanceMethods: [method("foo", 2)]),
        ]
        let found = ObjCMethodOwnerIndex.methodsInStaticScope(
            selector: "foo", receiverClassName: "Sub", isClassMethod: false, classes: classes, categories: [])
        XCTAssertEqual(found.first?.owner.container, .objcClass(name: "Base"))
        XCTAssertEqual(found.count, 1)
    }

    func testStaticScopeAbstainsWhenSuperclassIsAmbiguous() {
        let classes = [
            objcClass("Sub", superclass: "Base1"),
            objcClass("Sub", superclass: "Base2"),
            objcClass("Base1", instanceMethods: [method("foo", 1)]),
            objcClass("Base2", instanceMethods: [method("foo", 2)]),
        ]
        XCTAssertTrue(ObjCMethodOwnerIndex.methodsInStaticScope(
            selector: "foo", receiverClassName: "Sub", isClassMethod: false, classes: classes, categories: []).isEmpty)
    }

    func testStaticScopeTerminatesOnSuperclassCycle() {
        let classes = [objcClass("A", superclass: "B"), objcClass("B", superclass: "A")]
        XCTAssertTrue(ObjCMethodOwnerIndex.methodsInStaticScope(
            selector: "foo", receiverClassName: "A", isClassMethod: false, classes: classes, categories: []).isEmpty)
    }

    func testStaticScopeIncludesCategoriesAtTheSameLevelInStableOrder() {
        let classes = [objcClass("Sub", instanceMethods: [method("foo", 1)])]
        let categories = [category("Cat", on: "Sub", instanceMethods: [method("foo", 2)])]
        let found = ObjCMethodOwnerIndex.methodsInStaticScope(
            selector: "foo", receiverClassName: "Sub", isClassMethod: false, classes: classes, categories: categories)
        XCTAssertEqual(found.compactMap { $0.method.implementation }, [1, 2])
    }

    func testStaticScopeSeparatesClassAndInstanceSides() {
        let classes = [objcClass("A", classMethods: [method("make", 5, classSide: true)],
                                 instanceMethods: [method("make", 6)])]
        let classSide = ObjCMethodOwnerIndex.methodsInStaticScope(
            selector: "make", receiverClassName: "A", isClassMethod: true, classes: classes, categories: [])
        let instanceSide = ObjCMethodOwnerIndex.methodsInStaticScope(
            selector: "make", receiverClassName: "A", isClassMethod: false, classes: classes, categories: [])
        XCTAssertEqual(classSide.compactMap { $0.method.implementation }, [5])
        XCTAssertEqual(instanceSide.compactMap { $0.method.implementation }, [6])
    }

    func testStaticScopeDeduplicatesIdenticalRecords() {
        let record = objcClass("A", instanceMethods: [method("foo", 1)])
        let found = ObjCMethodOwnerIndex.methodsInStaticScope(
            selector: "foo", receiverClassName: "A", isClassMethod: false, classes: [record, record], categories: [])
        XCTAssertEqual(found.count, 1)
    }

    func testReceiverClassNameForCategoryIsTheExtendedClass() {
        let owner = ObjCMethodOwner(container: .category(name: "Cat", className: "Sub"), isClassMethod: false)
        XCTAssertEqual(ObjCMethodOwnerIndex.receiverClassName(for: owner), "Sub")
        XCTAssertEqual(ObjCMethodOwnerIndex.receiverClassName(
            for: .init(container: .objcClass(name: "A"), isClassMethod: true)), "A")
    }
}
