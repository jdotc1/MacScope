import Foundation
import XCTest
@testable import MacScope

@MainActor
final class AnnotationBatchChangedKeysTests: XCTestCase {
    func testLocalLabelBatchUsesActualPrimarySlotAndPreservesSibling() throws {
        let primary = ImageSlot(rawValue: 7), sibling = ImageSlot(rawValue: 9)
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "fixture", path: "/fixture", kind: "Mach-O executable",
                        architecture: "arm64", slot: slot)
        }
        let primaryKey = ImageAddress(slot: primary, address: 0x1000)
        let siblingKey = ImageAddress(slot: sibling, address: 0x1000)
        let original = [primaryKey: AddressOverride(customName: "keep", localLabel: "old"),
                        siblingKey: AddressOverride(localLabel: "sibling")]
        let store = WorkspaceStore(workspaceName: "Batch", snapshot: WorkspaceSnapshot(
            binaries: [image(primary), image(sibling)], analysisBySlot: [primary: ImageAnalysis(), sibling: ImageAnalysis()],
            addressOverrides: original), engine: AnalysisEngine(), autosaveScheduler: nil)
        store.focusImage(sibling)
        XCTAssertEqual(store.focusedImageSlot, sibling)
        let result = try WorkspaceScriptingAPI(store: store).execute("set-local-labels", arguments: .object([
            "entries": .array([.object(["address": .hex(0x1000), "label": .string("new")])])
        ]))
        XCTAssertEqual(result["changed"], .int(1))
        XCTAssertEqual(store.snapshot.addressOverrides[primaryKey]?.localLabel, "new")
        XCTAssertEqual(store.snapshot.addressOverrides[primaryKey]?.customName, "keep")
        XCTAssertEqual(store.snapshot.addressOverrides[siblingKey]?.localLabel, "sibling")
        store.undoManager.undo()
        XCTAssertEqual(store.snapshot.addressOverrides, original)
    }

    func testOperandBatchUsesActualPrimarySlotAndPreservesSibling() throws {
        let primary = ImageSlot(rawValue: 7), sibling = ImageSlot(rawValue: 9)
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "fixture", path: "/fixture", kind: "Mach-O executable",
                        architecture: "arm64", slot: slot)
        }
        let primaryKey = ImageAddress(slot: primary, address: 0x1000)
        let siblingKey = ImageAddress(slot: sibling, address: 0x1000)
        let original = [primaryKey: AddressOverride(customName: "keep", operandFormat: .decimal),
                        siblingKey: AddressOverride(operandFormat: .character)]
        let store = WorkspaceStore(workspaceName: "Batch", snapshot: WorkspaceSnapshot(
            binaries: [image(primary), image(sibling)], analysisBySlot: [primary: ImageAnalysis(), sibling: ImageAnalysis()],
            addressOverrides: original), engine: AnalysisEngine(), autosaveScheduler: nil)
        store.focusImage(sibling)
        XCTAssertEqual(store.focusedImageSlot, sibling)
        let result = try WorkspaceScriptingAPI(store: store).execute("set-operand-formats", arguments: .object([
            "entries": .array([.object(["address": .hex(0x1000), "format": .string("hex")])])
        ]))
        XCTAssertEqual(result["changed"], .int(1))
        XCTAssertEqual(store.snapshot.addressOverrides[primaryKey]?.operandFormat, .hex)
        XCTAssertEqual(store.snapshot.addressOverrides[primaryKey]?.customName, "keep")
        XCTAssertEqual(store.snapshot.addressOverrides[siblingKey]?.operandFormat, .character)
        store.undoManager.undo()
        XCTAssertEqual(store.snapshot.addressOverrides, original)
    }

    func testTypeBatchUsesActualPrimarySlotAndPreservesSibling() throws {
        let primary = ImageSlot(rawValue: 7), sibling = ImageSlot(rawValue: 9)
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "fixture", path: "/fixture", kind: "Mach-O executable",
                        architecture: "arm64", slot: slot)
        }
        let primaryKey = ImageAddress(slot: primary, address: 0x1000)
        let siblingKey = ImageAddress(slot: sibling, address: 0x1000)
        let original = [primaryKey: AddressOverride(customName: "keep", appliedTypeName: "OldType"),
                        siblingKey: AddressOverride(appliedTypeName: "SiblingType")]
        let store = WorkspaceStore(workspaceName: "Batch", snapshot: WorkspaceSnapshot(
            binaries: [image(primary), image(sibling)], analysisBySlot: [primary: ImageAnalysis(), sibling: ImageAnalysis()],
            addressOverrides: original), engine: AnalysisEngine(), autosaveScheduler: nil)
        store.focusImage(sibling)
        XCTAssertEqual(store.focusedImageSlot, sibling)
        let result = try WorkspaceScriptingAPI(store: store).execute("set-types", arguments: .object([
            "entries": .array([.object(["address": .hex(0x1000), "type": .string("NewType")])])
        ]))
        XCTAssertEqual(result["changed"], .int(1))
        XCTAssertEqual(store.snapshot.addressOverrides[primaryKey]?.appliedTypeName, "NewType")
        XCTAssertEqual(store.snapshot.addressOverrides[primaryKey]?.customName, "keep")
        XCTAssertEqual(store.snapshot.addressOverrides[siblingKey]?.appliedTypeName, "SiblingType")
        store.undoManager.undo()
        XCTAssertEqual(store.snapshot.addressOverrides, original)
    }

    func testNoOpAndPrunedEmptyEntriesPreserveBatchSemantics() {
        let slot = ImageSlot.primary
        let named = ImageAddress(slot: slot, address: 0x1000)
        let empty = ImageAddress(slot: slot, address: 0x2000)
        let image = BinaryImage(id: UUID(), name: "fixture", path: "/fixture", kind: "Mach-O executable",
                                architecture: "arm64", slot: slot)
        let original = [named: AddressOverride(customName: "old"), empty: AddressOverride()]
        let store = WorkspaceStore(workspaceName: "Batch", snapshot: WorkspaceSnapshot(
            binaries: [image], analysisBySlot: [slot: ImageAnalysis()], addressOverrides: original),
            engine: AnalysisEngine(), autosaveScheduler: nil)
        store.undoManager.removeAllActions()
        let generation = store.mutationGeneration
        XCTAssertEqual(store.setCustomNames([
            (address: 0x1000, name: "temporary"), (address: 0x1000, name: "old"),
            (address: 0x3000, name: "temporary"), (address: 0x3000, name: nil),
        ], in: slot), 0)
        XCTAssertEqual(store.snapshot.addressOverrides, original)
        XCTAssertEqual(store.mutationGeneration, generation)
        XCTAssertFalse(store.undoManager.canUndo)
        XCTAssertEqual(store.setCustomNames([(address: 0x2000, name: nil)], in: slot), 1)
        XCTAssertNil(store.snapshot.addressOverrides[empty])
        store.undoManager.undo()
        XCTAssertEqual(store.snapshot.addressOverrides, original)
    }

    func testRepeatedEditsCompareOriginalAndFinalWithoutTouchingSibling() {
        let primary = ImageSlot(rawValue: 7)
        let sibling = ImageSlot(rawValue: 9)
        func image(_ slot: ImageSlot) -> BinaryImage {
            BinaryImage(id: UUID(), name: "fixture", path: "/fixture", kind: "Mach-O executable",
                        architecture: "arm64", slot: slot)
        }
        var overrides: [ImageAddress: AddressOverride] = [:]
        for index in 0..<4096 {
            overrides[ImageAddress(slot: primary, address: 0x10000 + UInt64(index) * 4)] =
                AddressOverride(customName: "keep-\(index)")
        }
        overrides[ImageAddress(slot: primary, address: 0x1000)] = AddressOverride(customName: "old")
        overrides[ImageAddress(slot: sibling, address: 0x1000)] = AddressOverride(customName: "sibling")
        let store = WorkspaceStore(workspaceName: "Batch", snapshot: WorkspaceSnapshot(
            binaries: [image(primary), image(sibling)], analysisBySlot: [primary: ImageAnalysis(), sibling: ImageAnalysis()],
            addressOverrides: overrides), engine: AnalysisEngine(), autosaveScheduler: nil)
        store.undoManager.removeAllActions()
        let changed = store.setCustomNames([
            (address: 0x1000, name: "temporary"), (address: 0x1000, name: "old"),
            (address: 0x1004, name: "new"), (address: 0x1008, name: "temporary"),
            (address: 0x1008, name: nil),
        ], in: primary)
        XCTAssertEqual(changed, 1)
        var expected = overrides
        expected[ImageAddress(slot: primary, address: 0x1004)] = AddressOverride(customName: "new")
        XCTAssertEqual(store.snapshot.addressOverrides, expected)
        XCTAssertEqual(store.snapshot.addressOverrides[ImageAddress(slot: primary, address: 0x1004)]?.customName, "new")
        XCTAssertEqual(store.snapshot.addressOverrides[ImageAddress(slot: sibling, address: 0x1000)]?.customName, "sibling")
        XCTAssertEqual(store.snapshot.addressOverrides[ImageAddress(slot: primary, address: 0x10000)]?.customName, "keep-0")
        store.undoManager.undo()
        XCTAssertEqual(store.snapshot.addressOverrides, overrides)
        store.undoManager.redo()
        XCTAssertEqual(store.snapshot.addressOverrides, expected)
    }

    func testCommentBatchKeepsOtherFieldsAndUndoRestoresOriginal() {
        let slot = ImageSlot.primary
        let key = ImageAddress(slot: slot, address: 0x2000)
        let image = BinaryImage(id: UUID(), name: "fixture", path: "/fixture", kind: "Mach-O executable",
                                architecture: "arm64", slot: slot)
        let original = [key: AddressOverride(customName: "keep-name", customComment: "old")]
        let store = WorkspaceStore(workspaceName: "Batch", snapshot: WorkspaceSnapshot(
            binaries: [image], analysisBySlot: [slot: ImageAnalysis()], addressOverrides: original),
            engine: AnalysisEngine(), autosaveScheduler: nil)
        store.undoManager.removeAllActions()
        XCTAssertEqual(store.setCustomComments([(address: 0x2000, comment: " updated "),
                                                (address: 0x2000, comment: "final")], in: slot), 1)
        XCTAssertEqual(store.snapshot.addressOverrides[key]?.customName, "keep-name")
        XCTAssertEqual(store.snapshot.addressOverrides[key]?.customComment, "final")
        store.undoManager.undo()
        XCTAssertEqual(store.snapshot.addressOverrides, original)
    }
}
