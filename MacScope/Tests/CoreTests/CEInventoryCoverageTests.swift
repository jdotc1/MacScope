// Inventory coverage of the component evidence core: every regular file of an owned bundle is accounted for exactly
// once as a component or a typed exclusion, scope facts stay exact, and the published values are plain structs.

import Darwin
import Foundation
import XCTest
@testable import MacScope

// MARK: Shared fileprivate helpers

private func bytes(_ text: String) -> [UInt8] { Array(text.utf8) }

private func withSession<T>(_ root: String, _ body: (CE.ActiveSession) throws -> T) throws -> T {
    let ops = CE.DescriptorOps(fault: { _, _ in nil })
    let descriptor = try ops.openRoot(root)
    defer { ops.close(descriptor) }
    let rootStat = try ops.stat(descriptor, .wholeRoot)
    return try body(CE.ActiveSession(id: CE.SessionID(rawValue: UUID()), root: descriptor, rootStat: rootStat, ops: ops))
}

private func discover(_ root: String, limits: CE.BundleDiscovery.Limits = .init()) throws -> CE.BundleDiscoveryResult {
    try withSession(root) { session in
        var ledger = CE.ReadLedger(limit: limits.headerBytes)
        return try CE.BundleDiscovery(limits: limits).discover(session, inventoryID: UUID(), ledger: &ledger)
    }
}

private func chmod(_ bundle: CEBundle, _ path: String, _ mode: mode_t) {
    XCTAssertEqual(Darwin.chmod(bundle.url(path).path, mode), 0, "chmod \(path)")
}

/// Independent filesystem survey: relative paths of regular files (with their executable bit) and of directories.
private func survey(_ root: URL) -> (regular: [String: Bool], directories: Set<String>) {
    let manager = FileManager.default
    var regular: [String: Bool] = [:]
    var directories = Set<String>()
    for case let relative as String in manager.enumerator(atPath: root.path)?.allObjects ?? [] {
        guard let attributes = try? manager.attributesOfItem(atPath: root.path + "/" + relative) else { continue }
        switch attributes[.type] as? FileAttributeType {
        case .typeRegular: regular[relative] = ((attributes[.posixPermissions] as? Int) ?? 0) & 0o111 != 0
        case .typeDirectory: directories.insert(relative)
        default: break
        }
    }
    return (regular, directories)
}

/// How many times each raw path appears across components and exclusions together.
private func unionCounts(_ inventory: CE.ComponentInventory) -> [[UInt8]: Int] {
    var counts: [[UInt8]: Int] = [:]
    for component in inventory.components { counts[component.path.bytes, default: 0] += 1 }
    for exclusion in inventory.scope.exclusions { counts[exclusion.rawPath.bytes, default: 0] += 1 }
    return counts
}

private func exclusion(_ inventory: CE.ComponentInventory, _ path: String) -> CE.ExclusionRecord? {
    inventory.scope.exclusions.first { $0.rawPath.bytes == bytes(path) }
}

private func component(_ inventory: CE.ComponentInventory, _ path: String) -> CE.ComponentRecord? {
    inventory.components.first { $0.path.bytes == bytes(path) }
}

private let script = bytes("#!/bin/sh\necho owned test script\n")

final class CEInventoryCoverageTests: XCTestCase {

    // MARK: Parity

    func test_INV_FIND_PERM_PARITY() throws {
        let bundle = try CEBundle(self)
        try bundle.info()
        try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        try bundle.write("Contents/Helpers/tool", CEBytes.arm64)
        try bundle.write("Contents/Helpers/script.sh", script)
        try bundle.write("Contents/Resources/outside-tool", CEBytes.arm64)
        try bundle.write("Contents/rootexec", CEBytes.arm64)
        try bundle.write("Contents/Resources/data.bin", bytes("not executable"), executable: false)
        try bundle.directory("Contents/Helpers/emptydir")

        let inventory = try CEHarness.capture(bundle).inventory
        let counts = unionCounts(inventory)
        let facts = survey(bundle.root)

        // Every regular executable path appears exactly once in the components plus exclusions union.
        let executables = facts.regular.filter(\.value).keys.sorted()
        XCTAssertEqual(executables.count, 5)
        for path in executables { XCTAssertEqual(counts[bytes(path)], 1, "\(path) must appear exactly once") }
        // A script is non-image, an outside-code executable is outside code, an in-code image is a component.
        XCTAssertEqual(exclusion(inventory, "Contents/Helpers/script.sh")?.state, .nonImage)
        XCTAssertEqual(exclusion(inventory, "Contents/Resources/outside-tool")?.state, .outsideCodeLocations)
        XCTAssertEqual(exclusion(inventory, "Contents/rootexec")?.state, .outsideCodeLocations)
        XCTAssertNotNil(component(inventory, "Contents/Helpers/tool"))
        XCTAssertNil(exclusion(inventory, "Contents/Helpers/tool"))
        // Directories are never listed, in either set.
        XCTAssertTrue(facts.directories.contains("Contents/Helpers/emptydir"))
        for directory in facts.directories { XCTAssertNil(counts[bytes(directory)], "directory \(directory) must not be listed") }
        // The union holds nothing the survey did not see.
        for path in counts.keys { XCTAssertNotNil(facts.regular[String(decoding: path, as: UTF8.self)], "unexpected \(path)") }
        XCTAssertEqual(inventory.scope.completion, .complete)
    }

    func test_INV_CONTENTS_LAYOUT_PARITY() throws {
        let bundle = try CEBundle(self)
        try bundle.info()
        let layout: [(path: String, mode: mode_t)] = [
            ("Contents/MacOS/OwnedMain", 0o755),
            ("Contents/Frameworks/Owned.framework/Versions/A/Owned", 0o644),
            ("Contents/Frameworks/Owned.framework/Versions/A/Libraries/inner", 0o600),
            ("Contents/PlugIns/plug", 0o644),
            ("Contents/XPCServices/Owned.xpc/Contents/MacOS/service", 0o755),
            ("Contents/Helpers/helper", 0o640),
            ("Contents/Library/LoginItems/Login.app/Contents/MacOS/Login", 0o644),
        ]
        for item in layout {
            try bundle.write(item.path, CEBytes.arm64)
            chmod(bundle, item.path, item.mode)
        }

        let inventory = try CEHarness.capture(bundle).inventory
        let counts = unionCounts(inventory)
        let facts = survey(bundle.root)
        // All regular files, whatever their mode bits, are represented once.
        XCTAssertEqual(facts.regular.count, layout.count + 1)
        for path in facts.regular.keys { XCTAssertEqual(counts[bytes(path)], 1, "\(path)") }
        XCTAssertEqual(counts.values.reduce(0, +), facts.regular.count)
        // The mode does not decide image status: all seven in-code files are components, including nested framework files.
        XCTAssertEqual(Set(inventory.components.map { $0.path.bytes }), Set(layout.map { bytes($0.path) }))
        XCTAssertEqual(CEHarness.exclusions(inventory, .outsideCodeLocations), ["Contents/Info.plist"])
        XCTAssertEqual(inventory.scope.exclusions.count, 1)
        XCTAssertEqual(inventory.scope.completion, .complete)
        XCTAssertNil(inventory.scope.exclusionOverflow)
        // Every code location reports as searched.
        let regions = inventory.scope.searchedLocations.filter { $0.role == .codeRegion }
        XCTAssertEqual(regions.count, 6)
        XCTAssertTrue(regions.allSatisfy { $0.status == .searched })
    }

    // MARK: Exclusion states

    func test_INV_EXCLUSION_NON_IMAGE() throws {
        let bundle = try CEBundle(self)
        try bundle.info()
        try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        try bundle.write("Contents/Helpers/readme.txt", bytes("plain readme text"), executable: false)
        try bundle.write("Contents/Helpers/run.sh", script)

        let inventory = try CEHarness.capture(bundle).inventory
        XCTAssertEqual(Set(CEHarness.exclusions(inventory, .nonImage)), ["Contents/Helpers/readme.txt", "Contents/Helpers/run.sh"])
        XCTAssertEqual(CEHarness.paths(inventory), ["Contents/MacOS/OwnedMain"], "non-image files never become components")
        for path in ["Contents/Helpers/readme.txt", "Contents/Helpers/run.sh"] {
            let record = exclusion(inventory, path)
            XCTAssertEqual(record?.range, .leaf(CEHarness.path(path)))
            XCTAssertNil(record?.canonicalPath)
            XCTAssertFalse(record?.state.hides ?? true, "a non-image file conceals no component")
            XCTAssertFalse(inventory.scope.issues.contains { $0.range == .leaf(CEHarness.path(path)) })
        }
        // A non-image exclusion keeps the scope complete and the neighbouring path covered.
        XCTAssertEqual(inventory.scope.completion, .complete)
        XCTAssertTrue(inventory.covers(CEHarness.path("Contents/Helpers/other")))
        XCTAssertEqual(try discover(bundle.root.path).headerBytes, CEBytes.arm64.count + bytes("plain readme text").count + script.count)
    }

    func test_INV_EXCLUSION_SKIPPED_LINK() throws {
        let bundle = try CEBundle(self)
        try bundle.info()
        try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        try bundle.write("Contents/Frameworks/Owned.framework/Versions/A/Owned", CEBytes.arm64)
        try bundle.symlink("Contents/Frameworks/Owned.framework/Versions/Current", to: "A")
        try bundle.symlink("Contents/Helpers/broken", to: "does-not-exist")
        let outside = bundle.base.appendingPathComponent("outside-dir")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try Data(CEBytes.arm64).write(to: outside.appendingPathComponent("leak"))
        try bundle.symlink("Contents/Frameworks/Escape", to: outside.path)
        try bundle.symlink("Contents/Resources/mainlink", to: "../MacOS/OwnedMain")

        let inventory = try CEHarness.capture(bundle).inventory
        XCTAssertEqual(Set(CEHarness.exclusions(inventory, .skippedLink)), [
            "Contents/Frameworks/Owned.framework/Versions/Current", "Contents/Helpers/broken",
            "Contents/Frameworks/Escape", "Contents/Resources/mainlink",
        ])
        // Links are recorded as links and never followed: only the two real files are components.
        XCTAssertEqual(Set(CEHarness.paths(inventory)),
                       ["Contents/MacOS/OwnedMain", "Contents/Frameworks/Owned.framework/Versions/A/Owned"])
        for record in inventory.scope.exclusions where record.state == .skippedLink {
            XCTAssertEqual(record.range, .subtree(try CE.RelativePath(record.rawPath.display)))
            XCTAssertTrue(record.state.hides)
        }
        // Links are fully accounted for, so the scope is complete, but nothing beneath a link is covered.
        XCTAssertEqual(inventory.scope.completion, .complete)
        XCTAssertFalse(inventory.covers(CEHarness.path("Contents/Frameworks/Escape/leak")))
        XCTAssertFalse(inventory.covers(CEHarness.path("Contents/Frameworks/Owned.framework/Versions/Current/Owned")))
        XCTAssertFalse(inventory.covers(CEHarness.path("Contents/Helpers/broken")))
        XCTAssertNil(component(inventory, "Contents/Frameworks/Escape/leak"))
        XCTAssertNil(component(inventory, "Contents/Frameworks/Owned.framework/Versions/Current/Owned"))
    }

    func test_INV_EXCLUSION_DUPLICATE_FILE() throws {
        let bundle = try CEBundle(self)
        try bundle.info()
        try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        try bundle.write("Contents/Helpers/a", CEBytes.arm64)
        try bundle.hardLink("Contents/Helpers/b", to: "Contents/Helpers/a")
        try bundle.hardLink("Contents/Resources/alias", to: "Contents/Helpers/a")

        let inventory = try CEHarness.capture(bundle).inventory
        // One inode, one component: the first in-code name by raw bytes.
        XCTAssertEqual(Set(CEHarness.paths(inventory)), ["Contents/MacOS/OwnedMain", "Contents/Helpers/a"])
        XCTAssertEqual(Set(CEHarness.exclusions(inventory, .duplicateFile)), ["Contents/Helpers/b", "Contents/Resources/alias"])
        for path in ["Contents/Helpers/b", "Contents/Resources/alias"] {
            let record = exclusion(inventory, path)
            XCTAssertEqual(record?.canonicalPath?.bytes, bytes("Contents/Helpers/a"), "\(path) names its canonical entry")
            XCTAssertEqual(record?.range, .leaf(CEHarness.path(path)))
            XCTAssertFalse(record?.state.hides ?? true)
        }
        // The alias is not also reported as outside code, and no path is both a component and an exclusion.
        XCTAssertFalse(CEHarness.exclusions(inventory, .outsideCodeLocations).contains("Contents/Resources/alias"))
        let counts = unionCounts(inventory)
        XCTAssertTrue(counts.values.allSatisfy { $0 == 1 })
        XCTAssertEqual(inventory.scope.completion, .complete)
        // Every in-code name is probed before inodes are grouped (three reads); the name outside code is never read.
        XCTAssertEqual(try discover(bundle.root.path).headerBytes, 3 * CEBytes.arm64.count)
    }

    func test_INV_EXCLUSION_OUTSIDE_CODE_LOCATIONS() throws {
        let bundle = try CEBundle(self)
        try bundle.info()
        try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        try bundle.write("Contents/Resources/exec-resource", CEBytes.arm64)
        try bundle.write("Contents/rootexec", CEBytes.arm64)
        try bundle.write("Contents/Resources/data", bytes("a plain resource"), executable: false)

        let inventory = try CEHarness.capture(bundle).inventory
        XCTAssertEqual(Set(CEHarness.exclusions(inventory, .outsideCodeLocations)), [
            "Contents/Resources/exec-resource", "Contents/rootexec", "Contents/Resources/data", "Contents/Info.plist",
        ])
        XCTAssertEqual(CEHarness.paths(inventory), ["Contents/MacOS/OwnedMain"])
        for path in ["Contents/Resources/exec-resource", "Contents/rootexec", "Contents/Resources/data"] {
            XCTAssertEqual(exclusion(inventory, path)?.range, .leaf(CEHarness.path(path)))
        }
        XCTAssertFalse(CEHarness.exclusions(inventory, .outsideCodeLocations).isEmpty)
        XCTAssertTrue(inventory.scope.exclusions.allSatisfy { !$0.state.hides }, "outside files conceal no component")
        XCTAssertEqual(inventory.scope.completion, .complete)
        // Outside-code files carry no image authority and are never probed: only the principal is read.
        let result = try discover(bundle.root.path)
        XCTAssertEqual(result.headerBytes, CEBytes.arm64.count)
        XCTAssertEqual(result.entries.filter(\.selectable).map { $0.rawPath.bytes }, [bytes("Contents/MacOS/OwnedMain")])
        XCTAssertTrue(result.entries.filter { $0.state == .outsideCodeLocations }.allSatisfy { $0.provenance == nil })
    }

    func test_INV_EXCLUSION_TYPED_FIELDS() throws {
        let bundle = try CEBundle(self)
        try bundle.info()
        try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        try bundle.write("Contents/Helpers/ok", CEBytes.arm64)
        try bundle.write("Contents/Helpers/object", CEBytes.object)
        try bundle.write("Contents/Helpers/badfat", CEBytes.badFat)
        try bundle.write("Contents/Helpers/note.txt", bytes("note"), executable: false)
        try bundle.symlink("Contents/Helpers/link", to: "ok")
        try bundle.hardLink("Contents/Helpers/zdup", to: "Contents/Helpers/ok")
        try bundle.write("Contents/Resources/res", bytes("resource"), executable: false)
        let fifo = bundle.url("Contents/Helpers/fifo").path
        XCTAssertEqual(mkfifo(fifo, 0o644), 0)
        try bundle.writeRaw("Contents/Helpers", name: [0xfe], bytes("bad name"))

        let inventory = try CEHarness.capture(bundle).inventory
        try inventory.validate()
        let invalidPath = bytes("Contents/Helpers/") + [0xfe]

        // The disposition of each state: component, exclusion or issue, with no overlap between the first two.
        struct Row { let path: [UInt8]; let component: Bool; let exclusion: CE.ExclusionState?; let componentIssue: Bool }
        let table: [Row] = [
            Row(path: bytes("Contents/Helpers/ok"), component: true, exclusion: nil, componentIssue: false),
            Row(path: bytes("Contents/Helpers/object"), component: true, exclusion: nil, componentIssue: true),
            Row(path: bytes("Contents/Helpers/badfat"), component: true, exclusion: nil, componentIssue: true),
            Row(path: bytes("Contents/Helpers/note.txt"), component: false, exclusion: .nonImage, componentIssue: false),
            Row(path: bytes("Contents/Helpers/link"), component: false, exclusion: .skippedLink, componentIssue: false),
            Row(path: bytes("Contents/Helpers/zdup"), component: false, exclusion: .duplicateFile, componentIssue: false),
            Row(path: bytes("Contents/Helpers/fifo"), component: false, exclusion: .skippedSpecial, componentIssue: false),
            Row(path: bytes("Contents/Resources/res"), component: false, exclusion: .outsideCodeLocations, componentIssue: false),
            Row(path: invalidPath, component: false, exclusion: .invalidName, componentIssue: false),
        ]
        for row in table {
            let name = String(decoding: row.path, as: UTF8.self)
            let record = inventory.components.first { $0.path.bytes == row.path }
            let excluded = inventory.scope.exclusions.first { $0.rawPath.bytes == row.path }
            XCTAssertEqual(record != nil, row.component, "component presence for \(name)")
            XCTAssertEqual(excluded?.state, row.exclusion, "exclusion state for \(name)")
            XCTAssertFalse(record != nil && excluded != nil, "\(name) must not be both")
            if row.component { XCTAssertEqual(record?.issues.isEmpty, !row.componentIssue, "component issue for \(name)") }
        }
        // Malformed and unsupported images stay components with typed issues and no exclusion.
        XCTAssertEqual(component(inventory, "Contents/Helpers/object")?.issues.first?.error,
                       .malformedHeader(.leaf(CEHarness.path("Contents/Helpers/object")), .unsupportedFileType))
        XCTAssertEqual(component(inventory, "Contents/Helpers/badfat")?.issues.first?.error,
                       .malformedHeader(.leaf(CEHarness.path("Contents/Helpers/badfat")), .badUniversalLayout))
        // The invalid name keeps its raw bytes and raises a typed scope issue.
        XCTAssertTrue(inventory.scope.issues.contains { $0.kind == .unsafePath })
        XCTAssertNil(exclusion(inventory, String(decoding: invalidPath, as: UTF8.self))?.rawPath.text)
        // Which states hide components is a fixed table.
        let hiding: [CE.ExclusionState: Bool] = [
            .nonImage: false, .outsideCodeLocations: false, .duplicateFile: false,
            .skippedLink: true, .skippedSpecial: true, .invalidName: true, .unreadable: true, .changed: true,
            .entryLimit: true, .depthLimit: true, .candidateLimit: true, .headerLimit: true, .pathLimit: true,
        ]
        for (state, hides) in hiding { XCTAssertEqual(state.hides, hides, "\(state)") }
        XCTAssertEqual(inventory.scope.completion, .partial)
        XCTAssertTrue(inventory.components.allSatisfy { $0.parentID == nil })
    }

    func test_INV_EXCLUSION_OVERFLOW_COUNTED() throws {
        // One exclusion is always Contents/Info.plist; the rest are non-image files, so the totals are exact.
        let cases: [(textFiles: Int, observed: Int, omitted: Int)] = [(254, 255, 0), (255, 256, 1), (299, 300, 45)]
        for item in cases {
            let bundle = try CEBundle(self)
            try bundle.info()
            try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
            for index in 0..<item.textFiles {
                try bundle.write(String(format: "Contents/Helpers/t%03d.txt", index), bytes("text"), executable: false)
            }
            let inventory = try CEHarness.capture(bundle).inventory
            try inventory.validate()
            let scope = inventory.scope
            XCTAssertEqual(scope.exclusions.count, min(item.observed, 255), "retained for \(item.observed)")
            if item.omitted == 0 {
                XCTAssertNil(scope.exclusionOverflow, "255 exclusions alone are not an overflow")
                XCTAssertEqual(scope.completion, .complete)
                XCTAssertTrue(inventory.covers(CEHarness.path("Contents/MacOS/OwnedMain")))
            } else {
                XCTAssertEqual(scope.exclusionOverflow, CE.OverflowFact(observed: item.observed, retained: 255))
                XCTAssertEqual(scope.exclusionOverflow?.omitted, item.omitted)
                XCTAssertFalse(inventory.covers(CEHarness.path("Contents/MacOS/OwnedMain")), "an overflowed scope covers nothing")
                XCTAssertFalse(inventory.isComplete && scope.exclusionOverflow != nil && inventory.covers(CEHarness.path("Contents/Helpers/zz")))
            }
            // Retained exclusions are the leading records in raw path order, and issues do not overflow here.
            XCTAssertEqual(scope.exclusions.map(\.rawPath), scope.exclusions.map(\.rawPath).sorted())
            XCTAssertNil(scope.issueOverflow)
            XCTAssertEqual(inventory.components.count, 1)
        }
    }

    // MARK: Pure values

    func test_INV_PATH_NFC_NFD_DISTINCT() throws {
        let nfc = "Contents/Helpers/\u{e9}"
        let nfd = "Contents/Helpers/e\u{301}"
        let nfcPath = CEHarness.path(nfc)
        let nfdPath = CEHarness.path(nfd)
        // Swift string equality folds canonical equivalents; the byte paths must not.
        XCTAssertEqual(nfc, nfd)
        XCTAssertEqual(nfcPath.last.bytes, [0xc3, 0xa9])
        XCTAssertEqual(nfdPath.last.bytes, [0x65, 0xcc, 0x81])
        XCTAssertNotEqual(nfcPath, nfdPath)
        XCTAssertNotEqual(nfcPath.key, nfdPath.key)
        XCTAssertEqual(Set([nfcPath, nfdPath]).count, 2)
        XCTAssertTrue(nfdPath < nfcPath, "ordering is by raw bytes")

        // Validation accepts the distinct pair and keeps both, but rejects a true duplicate.
        let pair = CEHarness.inventory([CEHarness.record(nfc), CEHarness.record(nfd)])
        XCTAssertNoThrow(try pair.validate())
        XCTAssertEqual(pair.components.count, 2)
        let duplicate = CEHarness.inventory([CEHarness.record(nfc), CEHarness.record(nfc)])
        XCTAssertThrowsError(try duplicate.validate()) { XCTAssertEqual($0 as? CE.EvidenceError, .invalidInventory(.duplicatePath)) }

        // The matcher keeps them separate: a rename between normalization forms is never a same-location match.
        let matcher = CE.ComponentMatcher()
        let renamed = matcher.match(previous: CEHarness.inventory([CEHarness.record(nfc)]),
                                    current: CEHarness.inventory([CEHarness.record(nfd)]))
        XCTAssertEqual(Set(renamed.map(\.status)), [.unmatchedPrevious, .unmatchedCurrent])
        XCTAssertFalse(renamed.contains { $0.status == .sameLocation })
        let both = matcher.match(previous: pair, current: CEHarness.inventory([CEHarness.record(nfd), CEHarness.record(nfc)]))
        XCTAssertEqual(both.count, 2)
        XCTAssertTrue(both.allSatisfy { $0.status == .sameLocation })
        for match in both {
            let old = pair.component(try XCTUnwrap(match.previousID))
            XCTAssertNotNil(old)
            XCTAssertNotNil(match.currentID)
        }
        XCTAssertEqual(Set(both.compactMap(\.previousID)).count, 2)
        XCTAssertEqual(Set(both.compactMap(\.currentID)).count, 2)
    }

    func test_INV_VALUE_SHAPE_NO_CLASS() throws {
        let bundle = try CEBundle(self)
        try bundle.info()
        try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        try bundle.write("Contents/Helpers/h", CEBytes.arm64)
        var live: CE.LiveComponentInventory?
        let captured = try CE.capture(selection: bundle.root) { inventory, _ in live = inventory; return [] }
        let first = try XCTUnwrap(live)

        // Every published value is a struct, and none of its stored members is a class instance.
        func assertValue(_ value: Any, _ label: String, file: StaticString = #filePath, line: UInt = #line) {
            let mirror = Mirror(reflecting: value)
            XCTAssertEqual(mirror.displayStyle, .struct, "\(label) must be a struct", file: file, line: line)
            XCTAssertFalse(type(of: value) is AnyObject.Type, "\(label) must not be a class", file: file, line: line)
            for child in mirror.children where Mirror(reflecting: child.value).displayStyle == .class {
                XCTFail("\(label).\(child.label ?? "?") holds a class instance", file: file, line: line)
            }
        }
        let provenance = try XCTUnwrap(first.provenance.values.first)
        assertValue(first, "LiveComponentInventory")
        assertValue(first.inventory, "ComponentInventory")
        assertValue(first.inventory.scope, "InventoryScope")
        assertValue(try XCTUnwrap(first.inventory.components.first), "ComponentRecord")
        assertValue(try XCTUnwrap(first.inventory.scope.exclusions.first), "ExclusionRecord")
        assertValue(try XCTUnwrap(first.inventory.scope.searchedLocations.first), "SearchLocation")
        assertValue(provenance, "BundleImageProvenance")
        assertValue(captured, "CaptureResult")
        assertValue(CE.OverflowFact(observed: 300, retained: 255), "OverflowFact")
        assertValue(CEHarness.path("Contents/Helpers/h"), "RelativePath")

        // Copies are independent values: a changed copy leaves the original untouched.
        var copy = first.inventory
        XCTAssertEqual(copy.components, first.inventory.components)
        XCTAssertEqual(copy.scope, first.inventory.scope)
        copy = CE.ComponentInventory(id: UUID(), components: [], scope: CEHarness.scope(.partial))
        XCTAssertEqual(first.inventory.components.count, 2)
        XCTAssertEqual(first.inventory.scope.completion, .complete)
        XCTAssertTrue(copy.components.isEmpty)
        var provenanceCopy = first.provenance
        provenanceCopy.removeAll()
        XCTAssertEqual(first.provenance.count, 2)

        // A token from a finished session is powerless in any other session, even against the same bundle.
        try withSession(bundle.root.path) { later in
            XCTAssertNotEqual(later.id, first.session)
            XCTAssertEqual(provenance.session, first.session)
            XCTAssertThrowsError(try CE.CodeUnitPreflight.revalidate(provenance, session: later)) {
                XCTAssertEqual($0 as? CE.EvidenceError, .staleCapability)
            }
        }
        // The stale token cannot authorize a capture either: a request carrying another session is refused.
        let foreign = CE.SessionID(rawValue: UUID())
        let error = XCTAssertThrowsErrorResult {
            _ = try CE.capture(selection: bundle.root) { inventory, _ in
                guard let component = inventory.inventory.components.first else { return [] }
                return [CE.CaptureRequest(session: foreign, inventoryID: inventory.inventory.id, componentID: component.id,
                                          category: .info, architecture: nil)]
            }
        }
        XCTAssertEqual(error as? CE.EvidenceError, .staleCapability)
    }
}

/// Runs `body` and returns the error it throws, failing when it does not throw.
private func XCTAssertThrowsErrorResult(file: StaticString = #filePath, line: UInt = #line, _ body: () throws -> Void) -> Error? {
    do { try body() } catch { return error }
    XCTFail("expected an error", file: file, line: line)
    return nil
}
