// Component inventory capture and metadata declarations: hierarchy, traversal budgets, strict header validation,
// declared labels and cancellation. Header-level cases drive the metadata reader on in-memory bytes.

import Foundation
import XCTest
@testable import MacScope

final class CEComponentInventoryTests: XCTestCase {
    private typealias H = CEHarness

    // MARK: Helpers

    private final class Counter { var value = 0 }

    private func component(_ inventory: CE.ComponentInventory, _ path: String, file: StaticString = #filePath, line: UInt = #line) -> CE.ComponentRecord? {
        let found = inventory.components.first { $0.path.display == path }
        XCTAssertNotNil(found, "missing component \(path)", file: file, line: line)
        return found
    }

    private func hasBudgetIssue(_ scope: CE.InventoryScope, _ kind: CE.LimitKind) -> Bool {
        scope.issues.contains { issue in
            if case .budgetExceeded(let limit, _) = issue.error { return limit == kind }
            return false
        }
    }

    private func read(_ bytes: [UInt8], limit: Int = 1_048_576, capture: Bool = false, file: StaticString = #filePath, line: UInt = #line)
        -> (result: CE.MetadataReadResult, used: Int) {
        var ledger = CE.ReadLedger(limit: limit)
        let range = CE.PathRange.wholeRoot
        let result = CE.ComponentMetadataReader(captureLoadCommands: capture).read(
            size: UInt64(bytes.count), range: range, ledger: &ledger) { offset, count in
            guard offset + UInt64(count) <= UInt64(bytes.count) else {
                XCTFail("read outside the image: \(offset)+\(count) of \(bytes.count)", file: file, line: line)
                throw CE.EvidenceError.shortRead(range, expected: count, actual: 0)
            }
            return Array(bytes[Int(offset)..<(Int(offset) + count)])
        }
        return (result, ledger.used)
    }

    private func put(_ bytes: inout [UInt8], at offset: Int, le value: UInt32) {
        bytes.replaceSubrange(offset..<(offset + 4), with: CEBytes.le32([value]))
    }
    private func put(_ bytes: inout [UInt8], at offset: Int, be value: UInt32) {
        bytes.replaceSubrange(offset..<(offset + 4), with: CEBytes.be32([value]))
    }

    private func refusal(_ bytes: [UInt8], _ reason: CE.MetadataReason, _ name: String, file: StaticString = #filePath, line: UInt = #line) {
        let outcome = read(bytes, file: file, line: line)
        XCTAssertEqual(outcome.result.failure, .malformedMetadata(nil, .wholeRoot, reason), name, file: file, line: line)
        XCTAssertEqual(outcome.result.slices, [], name, file: file, line: line)
        XCTAssertEqual(outcome.result.architectures, [], name, file: file, line: line)
        XCTAssertEqual(outcome.result.minimums, [], name, file: file, line: line)
    }

    // MARK: Rows 12-21

    // SPEC-CASE: CI-MIXED-ARCH-TREE-DECLARATIONS
    func testMixedArchitectureTreeAndDeclarations() throws {
        let bundle = try CEBundle(self)
        try bundle.info(["CFBundleIdentifier": "com.example.main", "CFBundleShortVersionString": "2.0"], executable: "Main")
        try bundle.write("Contents/MacOS/Main", CEBytes.universal)
        try bundle.write("Contents/Helpers/intel", CEBytes.x86Build)
        try bundle.write("Contents/Helpers/arm", CEBytes.arm64)
        let worker = "Contents/XPCServices/Worker.xpc"
        try bundle.info(["CFBundleIdentifier": "com.example.worker", "CFBundleShortVersionString": "1.5"], executable: "worker",
                        at: worker + "/Contents/Info.plist")
        try bundle.write(worker + "/Contents/MacOS/worker", CEBytes.arm64)
        let nested = worker + "/Contents/Frameworks/Nested.framework"
        try bundle.info(["CFBundleIdentifier": "com.example.nested", "CFBundleVersion": "7"], executable: "Nested",
                        at: nested + "/Versions/A/Resources/Info.plist")
        try bundle.write(nested + "/Versions/A/Nested", CEBytes.arm64)
        let owned = "Contents/Frameworks/Owned.framework"
        try bundle.info(["CFBundleIdentifier": "com.example.owned.framework", "CFBundleShortVersionString": "3.1"], executable: "Owned",
                        at: owned + "/Versions/A/Resources/Info.plist")
        try bundle.write(owned + "/Versions/A/Owned", CEBytes.arm64)
        try bundle.symlink(owned + "/Versions/Current", to: "A")

        let inventory = try H.capture(bundle).inventory
        XCTAssertEqual(H.paths(inventory), [
            owned + "/Versions/A/Owned",
            "Contents/Helpers/arm",
            "Contents/Helpers/intel",
            "Contents/MacOS/Main",
            nested + "/Versions/A/Nested",
            worker + "/Contents/MacOS/worker",
        ])
        XCTAssertTrue(inventory.components.allSatisfy(\.metadataAvailable))
        XCTAssertTrue(inventory.components.allSatisfy { !$0.isDeclarationOnly })

        let arm64 = H.key("arm64"), x86 = H.key("x86_64")
        let main = component(inventory, "Contents/MacOS/Main")
        XCTAssertEqual(main?.kind, H.key("app"))
        XCTAssertEqual(main?.architectures, [arm64, x86])
        XCTAssertEqual(main?.minimumOS, [CE.ArchitectureMinimum(architecture: arm64, minimum: "14.1.0"),
                                         CE.ArchitectureMinimum(architecture: x86, minimum: "12.3.0")])
        XCTAssertEqual(main?.declaredBundleID, H.key("com.example.main"))
        XCTAssertEqual(main?.declaredVersion, H.key("2.0"))

        let intel = component(inventory, "Contents/Helpers/intel")
        XCTAssertEqual(intel?.kind, H.key("helper"))
        XCTAssertEqual(intel?.architectures, [x86])
        XCTAssertEqual(intel?.minimumOS, [CE.ArchitectureMinimum(architecture: x86, minimum: "13.0.0")])
        let arm = component(inventory, "Contents/Helpers/arm")
        XCTAssertEqual(arm?.kind, H.key("helper"))
        XCTAssertEqual(arm?.architectures, [arm64])
        XCTAssertEqual(arm?.minimumOS, [CE.ArchitectureMinimum(architecture: arm64, minimum: "14.1.0")])

        let workerRecord = component(inventory, worker + "/Contents/MacOS/worker")
        XCTAssertEqual(workerRecord?.kind, H.key("xpc"))
        XCTAssertEqual(workerRecord?.declaredBundleID, H.key("com.example.worker"))
        XCTAssertEqual(workerRecord?.declaredVersion, H.key("1.5"))
        let nestedRecord = component(inventory, nested + "/Versions/A/Nested")
        XCTAssertEqual(nestedRecord?.kind, H.key("framework"))
        XCTAssertEqual(nestedRecord?.declaredBundleID, H.key("com.example.nested"))
        XCTAssertEqual(nestedRecord?.declaredVersion, H.key("7"))
        let ownedRecord = component(inventory, owned + "/Versions/A/Owned")
        XCTAssertEqual(ownedRecord?.kind, H.key("framework"))
        XCTAssertEqual(ownedRecord?.declaredBundleID, H.key("com.example.owned.framework"))
        XCTAssertEqual(ownedRecord?.declaredVersion, H.key("3.1"))

        // Only the Intel helper is Intel-only; the fat main and the arm images are not.
        let intelOnly = inventory.components.filter { !$0.architectures.isEmpty && $0.architectures.allSatisfy { $0 == x86 } }
        XCTAssertEqual(intelOnly.map { $0.path.display }, ["Contents/Helpers/intel"])

        // The versioned-framework link is a typed exclusion, never a component.
        XCTAssertEqual(H.exclusions(inventory, .skippedLink), [owned + "/Versions/Current"])
        XCTAssertNoThrow(try inventory.validate())
    }

    // SPEC-CASE: CI-TRAVERSAL-BUDGET-PARTIAL
    func testEachTraversalBudgetRemainsPartial() throws {
        let unseen = H.path("Contents/Helpers/helper")

        // Entry budget.
        let entries = try CEBundle(self)
        try entries.standardLayout()
        let entryScope = try H.capture(entries, limits: .init(entries: 3)).inventory.scope
        XCTAssertEqual(entryScope.completion, .partial)
        XCTAssertFalse(H.inventory([], entryScope).covers(unseen))
        XCTAssertTrue(entryScope.remainderUnknown)
        XCTAssertTrue(hasBudgetIssue(entryScope, .entries))
        XCTAssertFalse(entryScope.exclusions.filter { $0.state == .entryLimit }.isEmpty)
        XCTAssertLessThanOrEqual(entryScope.visited, 3)

        // Depth budget.
        let depth = try CEBundle(self)
        try depth.standardLayout()
        let depthInventory = try H.capture(depth, limits: .init(depth: 1)).inventory
        XCTAssertEqual(depthInventory.scope.completion, .partial)
        XCTAssertFalse(depthInventory.covers(unseen))
        XCTAssertTrue(hasBudgetIssue(depthInventory.scope, .depth))
        XCTAssertTrue(H.exclusions(depthInventory, .depthLimit).contains("Contents/MacOS"))
        XCTAssertTrue(depthInventory.components.isEmpty)

        // Candidate budget: the first candidate in byte order is kept, the next one stops the walk.
        let candidates = try CEBundle(self)
        try candidates.standardLayout()
        let candidateInventory = try H.capture(candidates, limits: .init(candidates: 1)).inventory
        XCTAssertEqual(candidateInventory.scope.completion, .partial)
        XCTAssertFalse(candidateInventory.covers(unseen))
        XCTAssertTrue(hasBudgetIssue(candidateInventory.scope, .candidates))
        XCTAssertEqual(H.exclusions(candidateInventory, .candidateLimit), ["Contents/Helpers/helper"])
        XCTAssertEqual(H.paths(candidateInventory), ["Contents/Frameworks/Owned.framework/Versions/A/Owned"])
        XCTAssertTrue(candidateInventory.scope.remainderUnknown)

        // Header-byte budget: a 4096-byte candidate uses the whole budget, the next candidate hits the cap.
        let header = try CEBundle(self)
        try header.info(["CFBundleIdentifier": "com.example.owned"], executable: "OwnedMain")
        try header.write("Contents/Helpers/a", CEBytes.padded)
        try header.write("Contents/Helpers/b", CEBytes.arm64)
        let headerResult = try H.capture(header, limits: .init(headerBytes: 4096))
        let headerInventory = headerResult.inventory
        XCTAssertEqual(headerInventory.scope.completion, .partial)
        XCTAssertFalse(headerInventory.covers(unseen))
        XCTAssertLessThanOrEqual(headerResult.headerBytesUsed, 4096)
        XCTAssertTrue(hasBudgetIssue(headerInventory.scope, .headerBytes))
        XCTAssertEqual(H.exclusions(headerInventory, .headerLimit), ["Contents/Helpers/b"])
        // The first candidate keeps no trusted metadata because the shared budget was already spent.
        let first = component(headerInventory, "Contents/Helpers/a")
        XCTAssertEqual(first?.metadataAvailable, false)
        XCTAssertEqual(first?.architectures, [])
    }

    // SPEC-CASE: CI-CHANGED-CANDIDATE-NOT-SUCCESS
    func testChangedCandidateCannotBecomeMetadataSuccess() throws {
        let bundle = try CEBundle(self)
        try bundle.info(["CFBundleIdentifier": "com.example.owned"], executable: "OwnedMain")
        let target = "Contents/MacOS/OwnedMain"
        try bundle.write(target, CEBytes.arm64)
        let leaf = CE.PathRange.leaf(H.path(target))
        XCTAssertEqual(CEBytes.arm64.count, CEBytes.x86Build.count)
        let opens = Counter()
        // The second file open of the candidate is the descriptor-relative revalidation: replace the content just before it.
        let inventory = try H.capture(bundle, fault: { operation, range in
            if operation == .openFile, range == leaf {
                opens.value += 1
                if opens.value == 2 { try? bundle.write(target, CEBytes.x86Build) }
            }
            return nil
        }).inventory
        XCTAssertGreaterThanOrEqual(opens.value, 2)
        let record = component(inventory, target)
        XCTAssertEqual(record?.metadataAvailable, false)
        XCTAssertEqual(record?.architectures, [])
        XCTAssertEqual(record?.minimumOS, [])
        XCTAssertEqual(record?.slices, [])
        XCTAssertTrue(record?.issues.contains { $0.error == .changedInput(leaf) } ?? false)
        XCTAssertEqual(inventory.scope.completion, .partial)
        XCTAssertFalse(inventory.isComplete)
    }

    // SPEC-CASE: CI-MALFORMED-HEADERS-BUDGET-UNAVAILABLE
    func testMalformedHeadersAndMetadataBudgetStayUnavailable() throws {
        var oversized = CEBytes.arm64
        put(&oversized, at: 20, le: 1_048_577)

        let bundle = try CEBundle(self)
        try bundle.info(["CFBundleIdentifier": "com.example.owned"], executable: "OwnedMain")
        let target = "Contents/MacOS/OwnedMain"
        try bundle.write(target, oversized)
        let inventory = try H.capture(bundle).inventory
        let record = component(inventory, target)
        XCTAssertEqual(record?.metadataAvailable, false)
        XCTAssertEqual(record?.architectures, [])
        XCTAssertEqual(record?.minimumOS, [])
        XCTAssertEqual(record?.slices, [])
        XCTAssertTrue(record?.issues.contains { $0.error == .malformedMetadata(nil, .leaf(H.path(target)), .loadCommandBounds) } ?? false)
        XCTAssertEqual(inventory.scope.completion, .partial)

        // The reader refuses the same bytes directly.
        refusal(oversized, .loadCommandBounds, "oversized sizeofcmds")

        // An independent eight-byte budget allows the magic probe only; the next read is refused before the source is called.
        var ledger = CE.ReadLedger(limit: 8)
        var sourceCalls: [Int] = []
        let result = CE.ComponentMetadataReader().read(size: UInt64(CEBytes.arm64.count), range: .wholeRoot, ledger: &ledger) { offset, count in
            sourceCalls.append(count)
            return Array(CEBytes.arm64[Int(offset)..<(Int(offset) + count)])
        }
        XCTAssertEqual(result.failure, .budgetExceeded(.headerBytes, .wholeRoot))
        XCTAssertEqual(result.consumedBytes, 8)
        XCTAssertEqual(ledger.used, 8)
        XCTAssertEqual(sourceCalls, [8])
        XCTAssertEqual(result.slices, [])
        XCTAssertEqual(result.architectures, [])

        // A zero budget refuses the very first read.
        var empty = CE.ReadLedger(limit: 0)
        let none = CE.ComponentMetadataReader().read(size: 56, range: .wholeRoot, ledger: &empty) { _, _ in
            XCTFail("source must not be called")
            return []
        }
        XCTAssertEqual(none.failure, .budgetExceeded(.headerBytes, .wholeRoot))
        XCTAssertEqual(none.consumedBytes, 0)
    }

    // SPEC-CASE: CI-UNKNOWN-CPU-ARM64E-NOT-UNWIND-COVERAGE
    func testUnknownCPUAndArm64eAreNotUnwindCoverage() {
        var unknown = CEBytes.arm64
        put(&unknown, at: 4, le: 0x12345678)
        put(&unknown, at: 8, le: 9)
        var arm64e = CEBytes.arm64
        put(&arm64e, at: 8, le: 2)

        let unknownResult = read(unknown).result
        XCTAssertNil(unknownResult.failure)
        XCTAssertEqual(unknownResult.architectures, [H.key("cpu0x12345678/subtype0x9")])
        XCTAssertEqual(unknownResult.slices.first?.cpuType, 0x12345678)
        XCTAssertEqual(unknownResult.slices.first?.cpuSubtype, 9)
        let label = unknownResult.architectures[0].display
        XCTAssertFalse(label.hasPrefix("x86_64") || label.hasPrefix("i386"), "unknown CPU is not classified Intel")
        XCTAssertFalse(unknownResult.architectures.contains(H.key("arm64")))

        let arm64eResult = read(arm64e).result
        XCTAssertNil(arm64eResult.failure)
        XCTAssertEqual(arm64eResult.architectures, [H.key("arm64e")])
        let plain = read(CEBytes.arm64).result
        XCTAssertEqual(plain.architectures, [H.key("arm64")])
        XCTAssertNotEqual(arm64eResult.architectures, plain.architectures)
        XCTAssertNotEqual(arm64eResult.slices.first?.cpuSubtype, plain.slices.first?.cpuSubtype)
    }

    // SPEC-CASE: CI-STRICT-UNIVERSAL-THIN-WIDTH
    func testStrictUniversalLayoutAndThinHeaderWidth() {
        // Control: the supplied universal image and thin image are accepted unchanged.
        XCTAssertNil(read(CEBytes.universal).result.failure)
        XCTAssertNil(read(CEBytes.arm64).result.failure)

        var overlap = CEBytes.universal
        put(&overlap, at: 36, be: 4096)
        refusal(overlap, .overlappingSlices, "second slice overlaps the first")

        var disagreement = CEBytes.universal
        put(&disagreement, at: 8, be: 0x01000007)
        refusal(disagreement, .architectureDisagreement, "table CPU differs from the slice header")

        var narrow = CEBytes.arm64
        put(&narrow, at: 4, le: 7)
        refusal(narrow, .abiWidthMismatch, "32-bit CPU under 64-bit magic")

        var tools = CEBytes.arm64
        put(&tools, at: 52, le: 1)
        refusal(tools, .badBuildVersion, "tools count without payload")
    }

    // SPEC-CASE: CI-NESTED-NO-BORROWED-LABELS
    func testNestedImagesCannotBorrowLabelsFromMissingOrMismatchedExecutable() throws {
        let worker = "Contents/XPCServices/Worker.xpc"
        let workerInfo = worker + "/Contents/Info.plist"
        let bundle = try CEBundle(self)
        try bundle.info(["CFBundleIdentifier": "com.example.main"], executable: "Main")
        try bundle.write("Contents/MacOS/Main", CEBytes.arm64)
        try bundle.info(["CFBundleIdentifier": "com.example.worker"], executable: "worker", at: workerInfo)
        try bundle.write(worker + "/Contents/MacOS/worker", CEBytes.arm64)
        // A Worker-named helper outside the nested declared principal.
        try bundle.write("Contents/Helpers/Worker", CEBytes.arm64)

        for phase in ["declared executable", "executable declaration removed"] {
            if phase != "declared executable" {
                try bundle.info(["CFBundleIdentifier": "com.example.worker"], executable: nil, at: workerInfo)
            }
            let inventory = try H.capture(bundle).inventory
            let helper = component(inventory, "Contents/Helpers/Worker")
            XCTAssertEqual(helper?.kind, H.key("helper"), phase)
            XCTAssertNotEqual(helper?.declaredBundleID, H.key("com.example.worker"), phase)
            let nested = component(inventory, worker + "/Contents/MacOS/worker")
            XCTAssertEqual(nested?.kind, H.key("xpc"), phase)
            XCTAssertEqual(nested?.path.display, worker + "/Contents/MacOS/worker", phase)
        }

        // Root principal declared but absent: the image set stays partial with a typed principal issue.
        let missing = try CEBundle(self)
        try missing.info(["CFBundleIdentifier": "com.example.main"], executable: "Missing")
        try missing.write("Contents/MacOS/Other", CEBytes.arm64)
        let absent = try H.capture(missing).inventory
        XCTAssertEqual(absent.scope.completion, .partial)
        XCTAssertTrue(absent.scope.issues.contains { $0.kind == .principalUnavailable })

        // No executable declaration at all: a declaration-only record carries the label, never an image.
        let undeclared = try CEBundle(self)
        try undeclared.info(["CFBundleIdentifier": "com.example.main"], executable: nil)
        try undeclared.write("Contents/MacOS/Other", CEBytes.arm64)
        let none = try H.capture(undeclared).inventory
        XCTAssertEqual(none.scope.completion, .partial)
        XCTAssertTrue(none.scope.issues.contains { $0.kind == .principalUnresolved })
        let only = component(none, "Contents/Info.plist")
        XCTAssertEqual(only?.isDeclarationOnly, true)
        XCTAssertEqual(only?.kind, H.key("app"))
        XCTAssertEqual(only?.architectures, [])
        XCTAssertEqual(only?.metadataAvailable, false)
        XCTAssertFalse(H.exclusions(none, .outsideCodeLocations).contains("Contents/Info.plist"))
    }

    // SPEC-CASE: CI-CONTRADICTORY-PLATFORM-NO-MAC-MINIMUM
    func testContradictoryPlatformCommandsCannotPublishMacMinimum() {
        let legacy = CEBytes.le32([0x24, 16, 0x000e0000, 0])
        func image(platform: UInt32) -> [UInt8] {
            var bytes = CEBytes.arm64
            put(&bytes, at: 16, le: 2)
            put(&bytes, at: 20, le: 40)
            put(&bytes, at: 40, le: platform)
            return bytes + legacy
        }
        // Build-version platform iOS followed by a legacy macOS minimum.
        refusal(image(platform: 2), .ambiguousPlatform, "iOS then macOS minimum")
        // Even two macOS declarations are contradictory.
        refusal(image(platform: 1), .ambiguousPlatform, "build version then legacy minimum")
        XCTAssertEqual(read(image(platform: 2)).result.minimums, [])
        // Control: a single declaration publishes its minimum.
        XCTAssertEqual(read(CEBytes.arm64).result.minimums,
                       [CE.ArchitectureMinimum(architecture: H.key("arm64"), minimum: "14.1.0")])
    }

    // SPEC-CASE: CI-THIN32-FAT64-DECLARATIONS
    func testThin32BigEndianAndLittleEndianFat64Declarations() {
        let thin32 = [0xce, 0xfa, 0xed, 0xfe] + CEBytes.le32([7, 3, 2, 1, 16, 0, 0x24, 16, 0x000c0300, 0])
        XCTAssertEqual(thin32.count, 44)
        let thin32Result = read(thin32).result
        XCTAssertNil(thin32Result.failure)
        XCTAssertEqual(thin32Result.architectures, [H.key("i386")])
        XCTAssertEqual(thin32Result.minimums, [CE.ArchitectureMinimum(architecture: H.key("i386"), minimum: "12.3.0")])
        XCTAssertEqual(thin32Result.slices.first?.size, 44)
        XCTAssertEqual(thin32Result.slices.first?.isUniversal, false)

        let thin64 = [0xfe, 0xed, 0xfa, 0xcf] + CEBytes.be32([0x01000007, 3, 2, 1, 16, 0, 0, 0x24, 16, 0x000c0300, 0])
        XCTAssertEqual(thin64.count, 48)
        let thin64Result = read(thin64).result
        XCTAssertNil(thin64Result.failure)
        XCTAssertEqual(thin64Result.architectures, [H.key("x86_64")])
        XCTAssertEqual(thin64Result.minimums, [CE.ArchitectureMinimum(architecture: H.key("x86_64"), minimum: "12.3.0")])
        XCTAssertEqual(thin64Result.slices.first?.size, 48)

        var fat64 = [0xbf, 0xba, 0xfe, 0xca] + CEBytes.le32([1]) + CEBytes.le32([0x0100000c, 0, 4096, 0, 56, 0, 12, 0])
        XCTAssertEqual(fat64.count, 40)
        fat64 += [UInt8](repeating: 0, count: 4096 - fat64.count) + CEBytes.arm64
        XCTAssertEqual(fat64.count, 4152)
        let fat64Result = read(fat64).result
        XCTAssertNil(fat64Result.failure)
        XCTAssertEqual(fat64Result.architectures, [H.key("arm64")])
        XCTAssertEqual(fat64Result.minimums, [CE.ArchitectureMinimum(architecture: H.key("arm64"), minimum: "14.1.0")])
        XCTAssertEqual(fat64Result.slices.first?.offset, 4096)
        XCTAssertEqual(fat64Result.slices.first?.size, 56)
        XCTAssertEqual(fat64Result.slices.first?.isUniversal, true)
    }

    // SPEC-CASE: CI-CANCELLED-SCOPE-NOT-COMPLETE
    func testCancelledScopeIsNotComplete() async throws {
        let bundle = try CEBundle(self)
        try bundle.standardLayout()
        let root = bundle.root
        let (result, faults) = try await Task { () throws -> (CE.CaptureResult, Int) in
            _ = withUnsafeCurrentTask { task in task?.cancel() }
            let counter = Counter()
            let result = try CE.capture(selection: root, fault: { _, _ in counter.value += 1; return nil }) { _, _ in [] }
            return (result, counter.value)
        }.value
        let inventory = result.inventory
        XCTAssertEqual(inventory.scope.completion, .cancelled)
        XCTAssertFalse(inventory.isComplete)
        XCTAssertEqual(inventory.components.count, 0)
        XCTAssertEqual(inventory.scope.exclusions, [])
        XCTAssertEqual(inventory.scope.searchedLocations, [])
        XCTAssertTrue(inventory.scope.remainderUnknown)
        XCTAssertTrue(inventory.scope.issues.contains { $0.kind == .cancelled })
        XCTAssertEqual(inventory.scope.visited, 0)
        XCTAssertEqual(result.headerBytesUsed, 0)
        XCTAssertEqual(result.observations.count, 0)
        XCTAssertEqual(faults, 0, "no descriptor operation may run")
        XCTAssertFalse(inventory.covers(H.path("Contents/Helpers/helper")))
    }
}
