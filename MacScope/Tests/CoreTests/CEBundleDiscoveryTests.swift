// Bundle discovery behavior of the component evidence core: descriptor-relative whole-root walk, typed dispositions,
// principal handling and declaration capture. Every bundle is an owned temporary tree; nothing is executed or loaded.

import Darwin
import Foundation
import XCTest
@testable import MacScope

// MARK: Shared fileprivate helpers

private final class CECounter: @unchecked Sendable {
    var calls = 0
    func bump() { calls += 1 }
}

private func bytes(_ text: String) -> [UInt8] { Array(text.utf8) }

/// Runs `body` with a live session over `root`, mirroring what one capture call builds. The descriptor stays local.
private func withSession<T>(_ root: String, fault: @escaping CE.FaultInjector = { _, _ in nil },
                            _ body: (CE.ActiveSession) throws -> T) throws -> T {
    let ops = CE.DescriptorOps(fault: fault)
    let descriptor = try ops.openRoot(root)
    defer { ops.close(descriptor) }
    let rootStat = try ops.stat(descriptor, .wholeRoot)
    return try body(CE.ActiveSession(id: CE.SessionID(rawValue: UUID()), root: descriptor, rootStat: rootStat, ops: ops))
}

private func discover(_ root: String, limits: CE.BundleDiscovery.Limits = .init(),
                      fault: @escaping CE.FaultInjector = { _, _ in nil }) throws -> CE.BundleDiscoveryResult {
    try withSession(root, fault: fault) { session in
        var ledger = CE.ReadLedger(limit: limits.headerBytes)
        return try CE.BundleDiscovery(limits: limits).discover(session, inventoryID: UUID(), ledger: &ledger)
    }
}

private func entry(_ result: CE.BundleDiscoveryResult, _ path: String) -> CE.BundleDiscoveryEntry? {
    result.entries.first { $0.rawPath.bytes == bytes(path) }
}

private func thrown(_ body: () throws -> Void) -> CE.EvidenceError? {
    do { try body(); return nil } catch { return error as? CE.EvidenceError }
}

private func readFile(_ url: URL) throws -> [UInt8] { [UInt8](try Data(contentsOf: url)) }

private let infoPath = CE.BundleDiscovery.infoPath

final class CEBundleDiscoveryTests: XCTestCase {

    // MARK: 1

    func testOwnedBundleCandidatesScopesAndLinksNeverAnalyzeOrExecute() throws {
        // SPEC-CASE: BD-OWNED-BUNDLE-CANDIDATES-SCOPES-LINKS
        let bundle = try CEBundle(self)
        try bundle.standardLayout()
        let result = try discover(bundle.root.path)

        let main = "Contents/MacOS/OwnedMain"
        let expectedCandidates: Set<[UInt8]> = [
            bytes(main), bytes("Contents/Frameworks/Owned.framework/Versions/A/Owned"), bytes("Contents/Helpers/helper"),
            bytes("Contents/XPCServices/Owned.xpc/Contents/MacOS/service"),
        ]
        let candidates = result.entries.filter { $0.state == .candidate && $0.selectable }.map { $0.rawPath.bytes }
        XCTAssertEqual(candidates.count, 4)
        XCTAssertEqual(Set(candidates), expectedCandidates)

        // The principal binds to the exact declared path.
        XCTAssertEqual(result.principal, .declared(CEHarness.path(main)))
        XCTAssertEqual(result.entries.filter(\.isPrincipal).map { $0.rawPath.bytes }, [bytes(main)])

        // Link, non-image helper and outside-code resources keep their own typed dispositions.
        let link = entry(result, "Contents/Frameworks/Owned.framework/Versions/Current")
        XCTAssertEqual(link?.state, .skippedLink)
        XCTAssertEqual(link?.range, .subtree(CEHarness.path("Contents/Frameworks/Owned.framework/Versions/Current")))
        XCTAssertNil(link?.provenance)
        XCTAssertEqual(entry(result, "Contents/Helpers/readme.txt")?.state, .nonImage)
        let resource = entry(result, "Contents/Resources/outside-code-scope")
        XCTAssertEqual(resource?.state, .outsideCodeLocations)
        XCTAssertEqual(resource?.range, .leaf(CEHarness.path("Contents/Resources/outside-code-scope")))
        XCTAssertNil(resource?.provenance, "an outside-code header-valid file is never a selectable image")
        XCTAssertEqual(entry(result, "Contents/Info.plist")?.state, .outsideCodeLocations)

        // The link target is never walked through the link.
        XCTAssertFalse(result.entries.contains { $0.rawPath.bytes.starts(with: bytes("Contents/Frameworks/Owned.framework/Versions/Current/")) })
        XCTAssertFalse(result.partial, "a skipped link is a typed exclusion; the rest of the root was fully observed")
        XCTAssertFalse(result.cancelled)
        XCTAssertFalse(result.remainderUnknown)
        XCTAssertTrue(result.issues.isEmpty)

        // Only in-code regular files are probed, each charged by its actual size: four headers plus the text helper.
        XCTAssertEqual(result.headerBytes, 4 * CEBytes.arm64.count + bytes("Resource, not image").count)
        XCTAssertLessThanOrEqual(result.headerBytes, CE.BundleDiscovery.Limits().headerBytes)

        // Results are in raw byte order.
        XCTAssertEqual(result.entries.map(\.rawPath), result.entries.map(\.rawPath).sorted())

        // Searched-location truth: absent regions are absent, the link makes the full root incomplete.
        func status(_ range: CE.PathRange) -> CE.SearchLocation.Status? { result.searchedLocations.first { $0.range == range }?.status }
        let regions = CE.BundleDiscovery.codeLocations
        XCTAssertEqual(regions.map { status(.subtree($0)) }, [.searched, .searched, .absent, .searched, .searched, .absent])
        XCTAssertEqual(result.searchedLocations.first { $0.role == .fullRoot }?.status, .searched)

        // The same tree through the real capture path: four components, typed kinds, no component hides in an exclusion.
        let inventory = try CEHarness.capture(bundle).inventory
        XCTAssertEqual(inventory.components.count, 4)
        let kinds = Dictionary(uniqueKeysWithValues: inventory.components.map { ($0.path.bytes, $0.kind.text ?? "") })
        XCTAssertEqual(kinds[bytes(main)], "app")
        XCTAssertEqual(kinds[bytes("Contents/Frameworks/Owned.framework/Versions/A/Owned")], "framework")
        XCTAssertEqual(kinds[bytes("Contents/Helpers/helper")], "helper")
        XCTAssertEqual(kinds[bytes("Contents/XPCServices/Owned.xpc/Contents/MacOS/service")], "xpc")
        let componentPaths = Set(inventory.components.map { $0.path.bytes })
        XCTAssertTrue(componentPaths.isDisjoint(with: Set(inventory.scope.exclusions.map { $0.rawPath.bytes })))
        XCTAssertEqual(CEHarness.exclusions(inventory, .skippedLink), ["Contents/Frameworks/Owned.framework/Versions/Current"])
        XCTAssertEqual(CEHarness.exclusions(inventory, .nonImage), ["Contents/Helpers/readme.txt"])
        XCTAssertEqual(Set(CEHarness.exclusions(inventory, .outsideCodeLocations)),
                       ["Contents/Info.plist", "Contents/Resources/outside-code-scope"])
        XCTAssertEqual(inventory.scope.completion, .complete)
    }

    // MARK: 2

    func testHardlinksDeduplicateAndDirectoryLinksCannotEscape() throws {
        // SPEC-CASE: BD-HARDLINKS-DEDUP-DIRLINKS-NO-ESCAPE
        let bundle = try CEBundle(self)
        try bundle.info()
        try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        try bundle.write("Contents/Helpers/a", CEBytes.arm64)
        try bundle.hardLink("Contents/Helpers/b", to: "Contents/Helpers/a")
        // An outside-code alias whose name sorts before every code name must still not steal canonical authority.
        try bundle.hardLink("Contents/AAA-alias", to: "Contents/Helpers/a")

        // A directory link to an owned sibling directory outside the root that holds a header-valid image.
        let outside = bundle.base.appendingPathComponent("outside-image")
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try Data(CEBytes.arm64).write(to: outside.appendingPathComponent("leak"))
        try bundle.symlink("Contents/Frameworks/Escape", to: outside.path)

        let result = try discover(bundle.root.path)
        let a = entry(result, "Contents/Helpers/a")
        let b = entry(result, "Contents/Helpers/b")
        let alias = entry(result, "Contents/AAA-alias")
        XCTAssertEqual(a?.state, .candidate)
        XCTAssertNotNil(a?.provenance)
        for duplicate in [b, alias] {
            XCTAssertEqual(duplicate?.state, .duplicateFile)
            XCTAssertNil(duplicate?.provenance, "an alias carries no image capability")
            XCTAssertEqual(duplicate?.canonicalPath?.bytes, bytes("Contents/Helpers/a"))
            XCTAssertEqual(duplicate?.canonicalEntryID, a?.id)
            XCTAssertEqual(duplicate?.physical, a?.physical)
        }
        XCTAssertEqual(result.entries.filter { $0.physical == a?.physical && $0.selectable }.count, 1)

        // The directory link is recorded as a link and nothing beneath it is ever named.
        let escape = entry(result, "Contents/Frameworks/Escape")
        XCTAssertEqual(escape?.state, .skippedLink)
        XCTAssertEqual(escape?.range, .subtree(CEHarness.path("Contents/Frameworks/Escape")))
        XCTAssertFalse(result.entries.contains { $0.rawPath.bytes.starts(with: bytes("Contents/Frameworks/Escape/")) })
        XCTAssertFalse(result.entries.contains { $0.physical == entry(result, "Contents/Frameworks/Escape")?.physical && $0.state != .skippedLink && $0.physical != nil })

        // Through capture: one component for the inode, aliases only as exclusions, never both.
        let inventory = try CEHarness.capture(bundle).inventory
        let componentPaths = inventory.components.map { $0.path.bytes }
        XCTAssertEqual(Set(componentPaths), [bytes("Contents/MacOS/OwnedMain"), bytes("Contents/Helpers/a")])
        let duplicates = inventory.scope.exclusions.filter { $0.state == .duplicateFile }
        XCTAssertEqual(Set(duplicates.map { $0.rawPath.bytes }), [bytes("Contents/Helpers/b"), bytes("Contents/AAA-alias")])
        XCTAssertTrue(duplicates.allSatisfy { $0.canonicalPath?.bytes == bytes("Contents/Helpers/a") })
        XCTAssertTrue(Set(componentPaths).isDisjoint(with: Set(inventory.scope.exclusions.map { $0.rawPath.bytes })))
        XCTAssertEqual(CEHarness.exclusions(inventory, .skippedLink), ["Contents/Frameworks/Escape"])
    }

    // MARK: 3

    func testEntryDepthCandidateAndHeaderLimitsAreVisible() throws {
        // SPEC-CASE: BD-LIMITS-VISIBLE
        // Entry cap: the one entry already spent leaves no room for Contents' children.
        do {
            let bundle = try CEBundle(self)
            try bundle.info()
            try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
            let limits = CE.BundleDiscovery.Limits(entries: 1)
            let result = try discover(bundle.root.path, limits: limits)
            let stop = entry(result, "Contents")
            XCTAssertEqual(stop?.state, .entryLimit)
            XCTAssertEqual(stop?.range, .subtree(CEHarness.path("Contents")))
            XCTAssertEqual(stop?.issue?.error, .budgetExceeded(.entries, .subtree(CEHarness.path("Contents"))))
            XCTAssertTrue(result.partial)
            XCTAssertTrue(result.remainderUnknown)
            XCTAssertLessThanOrEqual(result.visited, 1)
            XCTAssertFalse(result.entries.contains { $0.selectable })
            XCTAssertTrue(result.issues.contains { $0.error == .budgetExceeded(.entries, .subtree(CEHarness.path("Contents"))) })
            let inventory = try CEHarness.capture(bundle, limits: limits).inventory
            XCTAssertEqual(inventory.scope.completion, .partial)
            XCTAssertEqual(inventory.scope.limitEntries, 1)
            XCTAssertEqual(CEHarness.exclusions(inventory, .entryLimit), ["Contents"])
            XCTAssertTrue(inventory.scope.remainderUnknown)
            XCTAssertFalse(inventory.covers(CEHarness.path("Contents/MacOS/OwnedMain")))
        }
        // Depth cap: Contents is at depth 1, so Contents/MacOS is refused as a depth limit.
        do {
            let bundle = try CEBundle(self)
            try bundle.info()
            try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
            let limits = CE.BundleDiscovery.Limits(depth: 1)
            let result = try discover(bundle.root.path, limits: limits)
            let stop = entry(result, "Contents/MacOS")
            XCTAssertEqual(stop?.state, .depthLimit)
            XCTAssertEqual(stop?.issue?.error, .budgetExceeded(.depth, .subtree(CEHarness.path("Contents/MacOS"))))
            XCTAssertTrue(result.partial)
            XCTAssertFalse(result.entries.contains { $0.selectable })
            let inventory = try CEHarness.capture(bundle, limits: limits).inventory
            XCTAssertEqual(inventory.scope.completion, .partial)
            XCTAssertEqual(CEHarness.exclusions(inventory, .depthLimit), ["Contents/MacOS"])
            XCTAssertEqual(inventory.scope.limitDepth, 1)
        }
        // Candidate cap: Helpers is walked before MacOS, so the second helper hits the one-candidate ceiling.
        do {
            let bundle = try CEBundle(self)
            try bundle.info()
            try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
            try bundle.write("Contents/Helpers/h1", CEBytes.arm64)
            try bundle.write("Contents/Helpers/h2", CEBytes.arm64)
            let limits = CE.BundleDiscovery.Limits(candidates: 1)
            let result = try discover(bundle.root.path, limits: limits)
            XCTAssertEqual(result.entries.filter(\.selectable).map { $0.rawPath.bytes }, [bytes("Contents/Helpers/h1")])
            XCTAssertEqual(entry(result, "Contents/Helpers/h2")?.state, .candidateLimit)
            XCTAssertEqual(entry(result, "Contents/Helpers/h2")?.issue?.error,
                           .budgetExceeded(.candidates, .leaf(CEHarness.path("Contents/Helpers/h2"))))
            XCTAssertTrue(result.partial)
            XCTAssertTrue(result.remainderUnknown)
            let inventory = try CEHarness.capture(bundle, limits: limits).inventory
            XCTAssertEqual(inventory.scope.completion, .partial)
            XCTAssertEqual(CEHarness.exclusions(inventory, .candidateLimit), ["Contents/Helpers/h2"])
            XCTAssertEqual(CEHarness.paths(inventory), ["Contents/Helpers/h1"])
            XCTAssertEqual(inventory.scope.limitCandidates, 1)
        }
        // Header budget: a 4096-byte candidate is read first (Helpers/a before Helpers/b) and exhausts the 4096-byte budget.
        do {
            let bundle = try CEBundle(self)
            try bundle.info()
            try bundle.write("Contents/Helpers/a", CEBytes.padded)
            try bundle.write("Contents/Helpers/b", CEBytes.arm64)
            let limits = CE.BundleDiscovery.Limits(headerBytes: 4096)
            let result = try discover(bundle.root.path, limits: limits)
            XCTAssertEqual(entry(result, "Contents/Helpers/a")?.state, .candidate)
            XCTAssertEqual(entry(result, "Contents/Helpers/b")?.state, .headerLimit)
            XCTAssertEqual(entry(result, "Contents/Helpers/b")?.issue?.error,
                           .budgetExceeded(.headerBytes, .leaf(CEHarness.path("Contents/Helpers/b"))))
            XCTAssertEqual(result.headerBytes, 4096)
            XCTAssertLessThanOrEqual(result.headerBytes, limits.headerBytes)
            XCTAssertTrue(result.partial)
            XCTAssertTrue(result.remainderUnknown)
        }
    }

    // MARK: 4

    func testChangedInputRootAndIntermediateLinksRejectBeforeOwnedAudit() throws {
        // SPEC-CASE: BD-CHANGED-INPUT-ROOT-LINKS-REJECT
        let helper = "Contents/Helpers/h"
        func makeBundle() throws -> CEBundle {
            let bundle = try CEBundle(self)
            try bundle.info()
            try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
            try bundle.write(helper, CEBytes.arm64)
            return bundle
        }
        func provenance(_ session: CE.ActiveSession) throws -> CE.BundleImageProvenance {
            var ledger = CE.ReadLedger(limit: CE.BundleDiscovery.Limits().headerBytes)
            let result = try CE.BundleDiscovery().discover(session, inventoryID: UUID(), ledger: &ledger)
            return try XCTUnwrap(entry(result, helper)?.provenance)
        }

        // Control: an untouched candidate revalidates against its own session.
        do {
            let bundle = try makeBundle()
            try withSession(bundle.root.path) { session in
                XCTAssertNil(thrown { try CE.CodeUnitPreflight.revalidate(try provenance(session), session: session) })
            }
        }
        // A selected helper changed after discovery is refused.
        do {
            let bundle = try makeBundle()
            try withSession(bundle.root.path) { session in
                let token = try provenance(session)
                try Data(CEBytes.arm64 + [0]).write(to: bundle.url(helper))
                XCTAssertEqual(thrown { try CE.CodeUnitPreflight.revalidate(token, session: session) },
                               .changedInput(.leaf(CEHarness.path(helper))))
            }
        }
        // An ancestor directory replaced by a link is refused by the no-follow descriptor walk.
        do {
            let bundle = try makeBundle()
            try withSession(bundle.root.path) { session in
                let token = try provenance(session)
                try FileManager.default.moveItem(at: bundle.url("Contents/Helpers"), to: bundle.url("Contents/Helpers.real"))
                try bundle.symlink("Contents/Helpers", to: "Helpers.real")
                let error = thrown { try CE.CodeUnitPreflight.revalidate(token, session: session) }
                guard case .io(let operation, let code, _)? = error else { return XCTFail("expected a typed io refusal, got \(String(describing: error))") }
                XCTAssertEqual(operation, .openDirectory)
                XCTAssertTrue([ELOOP, ENOTDIR].contains(code))
            }
        }
        // An observed root identity change is refused.
        do {
            let bundle = try makeBundle()
            try withSession(bundle.root.path) { session in
                let token = try provenance(session)
                var forged = session.rootStat
                forged.st_ino += 1
                let moved = CE.ActiveSession(id: session.id, root: session.root, rootStat: forged, ops: session.ops)
                XCTAssertEqual(thrown { try CE.CodeUnitPreflight.revalidate(token, session: moved) },
                               .changedInput(.leaf(CEHarness.path(helper))))
            }
        }
        // A mere root rename is not observable: the pinned descriptor still validates and no absolute path is reopened.
        do {
            let bundle = try makeBundle()
            try withSession(bundle.root.path) { session in
                let token = try provenance(session)
                try FileManager.default.moveItem(at: bundle.root, to: bundle.base.appendingPathComponent("Renamed.app"))
                XCTAssertNil(thrown { try CE.CodeUnitPreflight.revalidate(token, session: session) })
            }
        }
        // An expired or foreign session token is refused before any read.
        do {
            let bundle = try makeBundle()
            let token = try withSession(bundle.root.path) { try provenance($0) }
            try withSession(bundle.root.path) { later in
                XCTAssertEqual(thrown { try CE.CodeUnitPreflight.revalidate(token, session: later) }, .staleCapability)
            }
        }
        // A root that is itself a link is refused at admission, before any inventory exists.
        do {
            let bundle = try makeBundle()
            let link = bundle.base.appendingPathComponent("Link.app")
            try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: bundle.root.path)
            let error = thrown { _ = try CE.capture(selection: link) { _, _ in [] } }
            guard case .io(let operation, let code, let range)? = error else { return XCTFail("expected a typed io refusal, got \(String(describing: error))") }
            XCTAssertEqual(operation, .openRoot)
            XCTAssertEqual(range, .wholeRoot)
            XCTAssertTrue([ELOOP, ENOTDIR].contains(code))
        }
    }

    // MARK: 5

    func testCancelledDiscoveryAndMalformedOrUnsupportedHeadersRemainExplicit() async throws {
        // SPEC-CASE: BD-CANCELLED-MALFORMED-UNSUPPORTED-EXPLICIT
        let cancelBundle = try CEBundle(self)
        try cancelBundle.info()
        try cancelBundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        let cancelRoot = cancelBundle.root
        let probe = CECounter()
        let aggregate = try await Task { () throws -> CE.CaptureResult in
            withUnsafeCurrentTask { $0?.cancel() }
            return try CE.capture(selection: cancelRoot, fault: { _, _ in probe.bump(); return nil }) { _, _ in [] }
        }.value
        XCTAssertEqual(aggregate.inventory.scope.completion, .cancelled)
        XCTAssertTrue(aggregate.inventory.components.isEmpty)
        XCTAssertTrue(aggregate.inventory.scope.exclusions.isEmpty)
        XCTAssertTrue(aggregate.inventory.scope.issues.contains { $0.kind == .cancelled })
        XCTAssertTrue(aggregate.inventory.scope.remainderUnknown)
        XCTAssertTrue(aggregate.observations.isEmpty)
        XCTAssertEqual(aggregate.headerBytesUsed, 0)
        XCTAssertEqual(probe.calls, 0, "a pre-cancelled capture opens no descriptor")
        XCTAssertFalse(aggregate.inventory.isComplete)

        // Discovery itself, cancelled before the walk, reports cancelled and partial with nothing recorded.
        let cancelledPath = cancelRoot.path
        let walked = try await Task { () throws -> CE.BundleDiscoveryResult in
            withUnsafeCurrentTask { $0?.cancel() }
            return try discover(cancelledPath)
        }.value
        XCTAssertTrue(walked.cancelled)
        XCTAssertTrue(walked.partial)
        XCTAssertTrue(walked.entries.isEmpty)
        XCTAssertTrue(walked.issues.contains { $0.kind == .cancelled })

        // Separate uncancelled fixture: unsupported, malformed and valid universal headers stay distinct.
        let bundle = try CEBundle(self)
        try bundle.info()
        try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        try bundle.write("Contents/Helpers/object", CEBytes.object)
        try bundle.write("Contents/Helpers/badfat", CEBytes.badFat)
        try bundle.write("Contents/Helpers/universal", CEBytes.universal)
        let result = try discover(bundle.root.path)
        let object = entry(result, "Contents/Helpers/object")
        XCTAssertEqual(object?.state, .unsupportedType)
        XCTAssertEqual(object?.issue?.error, .malformedHeader(.leaf(CEHarness.path("Contents/Helpers/object")), .unsupportedFileType))
        XCTAssertNil(object?.provenance)
        let badFat = entry(result, "Contents/Helpers/badfat")
        XCTAssertEqual(badFat?.state, .malformedHeader)
        XCTAssertEqual(badFat?.issue?.error, .malformedHeader(.leaf(CEHarness.path("Contents/Helpers/badfat")), .badUniversalLayout))
        XCTAssertNil(badFat?.provenance)
        let universal = entry(result, "Contents/Helpers/universal")
        XCTAssertEqual(universal?.state, .candidate, "discovery only admits the universal container; slices are validated later")
        XCTAssertNotNil(universal?.provenance)
        XCTAssertTrue(result.partial)
        XCTAssertFalse(result.cancelled)

        let inventory = try CEHarness.capture(bundle).inventory
        XCTAssertEqual(inventory.scope.completion, .partial)
        for path in ["Contents/Helpers/object", "Contents/Helpers/badfat"] {
            let record = inventory.components.first { $0.path.bytes == bytes(path) }
            XCTAssertNotNil(record, "\(path) stays visible as a component")
            XCTAssertEqual(record?.metadataAvailable, false)
            XCTAssertEqual(record?.architectures, [])
            XCTAssertEqual(record?.issues.first?.kind, .malformedHeader)
        }
        let validUniversal = inventory.components.first { $0.path.bytes == bytes("Contents/Helpers/universal") }
        XCTAssertEqual(validUniversal?.metadataAvailable, true)
        XCTAssertEqual(validUniversal?.architectures.map { $0.bytes }, [bytes("arm64"), bytes("x86_64")])
        XCTAssertTrue(CEHarness.exclusions(inventory, .nonImage).isEmpty)
    }

    // MARK: 6

    func testInvalidNamesConsumeEntryBudgetAndRemainVisible() throws {
        // SPEC-CASE: BD-INVALID-NAMES-CONSUME-BUDGET
        let bundle = try CEBundle(self)
        try bundle.info()
        try bundle.writeRaw("Contents/Helpers", name: [0xfe], Array("x".utf8))
        try bundle.writeRaw("Contents/Helpers", name: [0xff], Array("y".utf8))
        let fe = bytes("Contents/Helpers/") + [0xfe]
        let ff = bytes("Contents/Helpers/") + [0xff]

        // Budget exactly large enough: root (1), Contents (2), Helpers (2) = 5 charged entries, both names visible.
        let roomy = try discover(bundle.root.path, limits: .init(entries: 5))
        XCTAssertEqual(roomy.visited, 5)
        for raw in [fe, ff] {
            let found = roomy.entries.first { $0.rawPath.bytes == raw }
            XCTAssertEqual(found?.state, .invalidName)
            XCTAssertEqual(found?.issue?.kind, .unsafePath)
            XCTAssertNil(found?.provenance)
            XCTAssertNil(found?.rawPath.text, "raw bytes are kept, never decoded lossily")
        }
        XCTAssertNotEqual(fe, ff)
        XCTAssertEqual(Set(roomy.entries.filter { $0.state == .invalidName }.map { $0.rawPath.bytes }), [fe, ff])
        XCTAssertTrue(roomy.partial)

        // One entry fewer: the invalid names already consumed the budget, so the walk stops with a typed limit.
        let tight = try discover(bundle.root.path, limits: .init(entries: 4))
        let stop = entry(tight, "Contents/Helpers")
        XCTAssertEqual(stop?.state, .entryLimit)
        XCTAssertEqual(stop?.issue?.error, .budgetExceeded(.entries, .subtree(CEHarness.path("Contents/Helpers"))))
        XCTAssertTrue(tight.partial)
        XCTAssertTrue(tight.remainderUnknown)
        XCTAssertLessThanOrEqual(tight.visited, 4)

        // Through capture the raw bytes survive into the exclusion records and stay byte-distinct.
        let inventory = try CEHarness.capture(bundle).inventory
        let invalid = inventory.scope.exclusions.filter { $0.state == .invalidName }
        XCTAssertEqual(Set(invalid.map { $0.rawPath.bytes }), [fe, ff])
        XCTAssertTrue(invalid.allSatisfy { $0.range.kind == .subtree })
        XCTAssertEqual(inventory.scope.completion, .partial)
    }

    // MARK: 7

    func testMissingPrincipalRetainsDeclarationsWithoutInventingCodeUnit() throws {
        // SPEC-CASE: BD-MISSING-PRINCIPAL-KEEPS-DECLARATIONS
        let bundle = try CEBundle(self)
        try bundle.info(["CFBundleIdentifier": "com.example.owned", "CFBundleShortVersionString": "1.0"], executable: nil)
        try bundle.write("Contents/Resources/PrivacyInfo.xcprivacy", CEBytes.plist(["NSPrivacyTracking": false]), executable: false)
        try bundle.write("Contents/Helpers/h", CEBytes.arm64)
        let servicePath = "Contents/XPCServices/Worker.xpc/Contents/MacOS/service"
        let workerInfo = "Contents/XPCServices/Worker.xpc/Contents/Info.plist"
        try bundle.info(["CFBundleIdentifier": "com.example.worker"], executable: "service", at: workerInfo)
        try bundle.write(servicePath, CEBytes.arm64)

        let result = try discover(bundle.root.path)
        XCTAssertEqual(result.principal, .unresolved)
        XCTAssertTrue(result.partial)
        XCTAssertTrue(result.issues.contains { $0.kind == .principalUnresolved && $0.range == .wholeRoot })
        XCTAssertFalse(result.entries.contains(where: \.isPrincipal), "no principal capability is invented")
        XCTAssertEqual(Set(result.entries.filter(\.selectable).map { $0.rawPath.bytes }), [bytes("Contents/Helpers/h"), bytes(servicePath)])
        let declarations = try XCTUnwrap(result.resourceDeclarations)
        XCTAssertEqual(declarations.info, try readFile(bundle.url("Contents/Info.plist")))
        XCTAssertEqual(declarations.privacyState, .present)
        XCTAssertEqual(declarations.privacy, try readFile(bundle.url("Contents/Resources/PrivacyInfo.xcprivacy")))
        XCTAssertNil(declarations.privacyIssue)

        var live: CE.LiveComponentInventory?
        let captured = try CE.capture(selection: bundle.root) { inventory, session in
            live = inventory
            guard let service = inventory.inventory.components.first(where: { $0.path.bytes == bytes(servicePath) }) else { return [] }
            return [CE.CaptureRequest(session: session, inventoryID: inventory.inventory.id, componentID: service.id, category: .info, architecture: nil)]
        }
        let inventory = captured.inventory
        let only = inventory.components.filter(\.isDeclarationOnly)
        XCTAssertEqual(only.count, 1)
        let record = try XCTUnwrap(only.first)
        XCTAssertEqual(record.path.bytes, bytes("Contents/Info.plist"))
        XCTAssertEqual(record.kind.bytes, bytes("app"))
        XCTAssertEqual(record.declaredBundleID?.bytes, bytes("com.example.owned"))
        XCTAssertEqual(record.declaredVersion?.bytes, bytes("1.0"))
        XCTAssertEqual(record.architectures, [])
        XCTAssertTrue(record.slices.isEmpty)
        XCTAssertFalse(record.metadataAvailable)
        let liveInventory = try XCTUnwrap(live)
        XCTAssertNil(liveInventory.provenance[record.id], "the declaration-only record has no image token")
        XCTAssertEqual(liveInventory.provenance.count, 2)
        XCTAssertNotNil(liveInventory.resourceDeclarations)
        XCTAssertEqual(Set(inventory.components.filter { !$0.isDeclarationOnly }.map { $0.path.bytes }),
                       [bytes("Contents/Helpers/h"), bytes(servicePath)])
        XCTAssertEqual(inventory.scope.completion, .partial)
        XCTAssertFalse(CEHarness.exclusions(inventory, .outsideCodeLocations).contains("Contents/Info.plist"))
        XCTAssertTrue(CEHarness.exclusions(inventory, .outsideCodeLocations).contains("Contents/Resources/PrivacyInfo.xcprivacy"))
        XCTAssertTrue(inventory.scope.issues.contains { $0.kind == .principalUnresolved })

        // The nested exact principal still preflights and captures its own Info.plist.
        let observation = try XCTUnwrap(captured.observations.first)
        XCTAssertEqual(captured.observations.count, 1)
        XCTAssertEqual(observation.state, .present)
        XCTAssertEqual(observation.category, .info)
        XCTAssertEqual(observation.source?.path.bytes, bytes(workerInfo))
    }

    // MARK: 8

    func testDeclaredPrincipalControlDoesNotAddDeclarationOnlyRecord() throws {
        // SPEC-CASE: BD-DECLARED-PRINCIPAL-NO-DECLARATION-ONLY-RECORD
        let bundle = try CEBundle(self)
        try bundle.info(["CFBundleIdentifier": "com.example.owned"])
        try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        let main = "Contents/MacOS/OwnedMain"

        let result = try discover(bundle.root.path)
        XCTAssertEqual(result.principal, .declared(CEHarness.path(main)))
        XCTAssertEqual(result.entries.filter(\.isPrincipal).map { $0.rawPath.bytes }, [bytes(main)])
        XCTAssertNil(result.resourceDeclarations, "declaration bytes are captured only for an unresolved principal")
        XCTAssertTrue(result.issues.isEmpty)
        XCTAssertFalse(result.partial)

        var live: CE.LiveComponentInventory?
        let captured = try CE.capture(selection: bundle.root) { inventory, session in
            live = inventory
            guard let component = inventory.inventory.components.first else { return [] }
            return [CE.CaptureRequest(session: session, inventoryID: inventory.inventory.id, componentID: component.id, category: .info, architecture: nil)]
        }
        let inventory = captured.inventory
        XCTAssertEqual(inventory.components.count, 1)
        XCTAssertFalse(inventory.components.contains(where: \.isDeclarationOnly))
        XCTAssertEqual(inventory.components.first?.path.bytes, bytes(main))
        XCTAssertEqual(inventory.components.first?.kind.bytes, bytes("app"))
        XCTAssertEqual(inventory.components.first?.declaredBundleID?.bytes, bytes("com.example.owned"))
        XCTAssertNil(inventory.components.first { $0.path.bytes == bytes("Contents/Info.plist") }, "no duplicate declaration-only record")
        XCTAssertEqual(CEHarness.exclusions(inventory, .outsideCodeLocations), ["Contents/Info.plist"])
        XCTAssertEqual(live?.provenance.count, 1)
        XCTAssertNil(live?.resourceDeclarations)
        XCTAssertEqual(inventory.scope.completion, .complete)
        // The single principal authorizes its own Info capture.
        XCTAssertEqual(captured.observations.first?.state, .present)
    }

    // MARK: 9

    func testInvalidPrincipalAndMalformedOrLinkedInfoRemainRejected() throws {
        // SPEC-CASE: BD-INVALID-PRINCIPAL-AND-INFO-REJECTED
        func refusal(_ prepare: (CEBundle) throws -> Void) throws -> CE.EvidenceError? {
            let bundle = try CEBundle(self)
            try prepare(bundle)
            try bundle.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
            return thrown { _ = try CEHarness.capture(bundle) }
        }
        let leaf = CE.PathRange.leaf(infoPath)

        let unsafe: [Any] = ["../escape", "/absolute", "a/b", "a\\b", "", 3]
        for value in unsafe {
            let error = try refusal { try $0.write("Contents/Info.plist", CEBytes.plist(["CFBundleExecutable": value]), executable: false) }
            XCTAssertEqual(error, .malformedMetadata(.info, leaf, .invalidExecutable), "executable value \(value)")
        }

        let truncated = bytes("<?xml version=\"1.0\"?><plist><dict><key>")
        XCTAssertEqual(try refusal { try $0.write("Contents/Info.plist", truncated, executable: false) },
                       .malformedMetadata(.info, leaf, .badPlist))
        XCTAssertEqual(try refusal { try $0.write("Contents/Info.plist", [], executable: false) },
                       .malformedMetadata(.info, leaf, .badPlist))
        let array = [UInt8](try PropertyListSerialization.data(fromPropertyList: ["a", "b"], format: .xml, options: 0))
        XCTAssertEqual(try refusal { try $0.write("Contents/Info.plist", array, executable: false) },
                       .malformedMetadata(.info, leaf, .notDictionary))

        // A linked Info.plist is refused by the no-follow open, never read through the link.
        let linked = try refusal {
            try $0.write("Contents/Real.plist", CEBytes.plist(["CFBundleExecutable": "OwnedMain"]), executable: false)
            try $0.symlink("Contents/Info.plist", to: "Real.plist")
        }
        XCTAssertEqual(linked, .io(.openFile, errno: ELOOP, leaf))

        // The control with a valid declaration succeeds, so the refusals above come from the declarations themselves.
        let control = try CEBundle(self)
        try control.info()
        try control.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        XCTAssertEqual(try CEHarness.capture(control).inventory.components.count, 1)
    }

    // MARK: 10

    func testMissingPrincipalPrivacyLinkUnavailableAndEmptyBundleHasNoImageAuthority() throws {
        // SPEC-CASE: BD-MISSING-PRINCIPAL-PRIVACY-LINK-EMPTY-BUNDLE
        let bundle = try CEBundle(self)
        try bundle.info(["CFBundleIdentifier": "com.example.empty"], executable: nil)
        try bundle.write("Contents/Resources/real.xcprivacy", CEBytes.plist(["NSPrivacyTracking": false]), executable: false)
        try bundle.symlink("Contents/Resources/PrivacyInfo.xcprivacy", to: "real.xcprivacy")
        let privacy = CE.BundleDiscovery.privacyPath

        let result = try discover(bundle.root.path)
        XCTAssertEqual(result.principal, .unresolved)
        XCTAssertTrue(result.partial)
        XCTAssertFalse(result.entries.contains(where: \.selectable), "no image authority in an empty bundle")
        let declarations = try XCTUnwrap(result.resourceDeclarations)
        XCTAssertEqual(declarations.privacyState, .unavailable)
        XCTAssertNil(declarations.privacy)
        XCTAssertEqual(declarations.privacyIssue?.error, .io(.openFile, errno: ELOOP, .leaf(privacy)))
        XCTAssertEqual(declarations.privacyIssue?.operation, .openFile)
        XCTAssertEqual(declarations.privacyIssue?.errno, ELOOP)
        XCTAssertEqual(entry(result, "Contents/Resources/PrivacyInfo.xcprivacy")?.state, .skippedLink)
        // None of the six code locations exists.
        let codeRegions = result.searchedLocations.filter { $0.role == .codeRegion }
        XCTAssertEqual(codeRegions.count, 6)
        XCTAssertTrue(codeRegions.allSatisfy { $0.status == .absent })

        var live: CE.LiveComponentInventory?
        let captured = try CE.capture(selection: bundle.root) { inventory, session in
            live = inventory
            guard let only = inventory.inventory.components.first(where: \.isDeclarationOnly) else { return [] }
            return [CE.CaptureRequest(session: session, inventoryID: inventory.inventory.id, componentID: only.id, category: .privacy, architecture: nil)]
        }
        let inventory = captured.inventory
        XCTAssertEqual(inventory.components.count, 1)
        XCTAssertEqual(inventory.components.first?.isDeclarationOnly, true)
        XCTAssertEqual(inventory.components.first?.path.bytes, bytes("Contents/Info.plist"))
        XCTAssertEqual(live?.provenance.count, 0)
        XCTAssertEqual(live?.resourceDeclarations?.privacyState, .unavailable)
        XCTAssertNotEqual(inventory.scope.completion, .complete)
        // Exclusions are retained even though they grant no image authority.
        XCTAssertEqual(CEHarness.exclusions(inventory, .outsideCodeLocations), ["Contents/Resources/real.xcprivacy"])
        XCTAssertEqual(CEHarness.exclusions(inventory, .skippedLink), ["Contents/Resources/PrivacyInfo.xcprivacy"])
        // The privacy observation for the declaration-only record is unavailable with the link issue, never absent.
        let observation = try XCTUnwrap(captured.observations.first)
        XCTAssertEqual(captured.observations.count, 1)
        XCTAssertEqual(observation.state, .unavailable)
        XCTAssertNil(observation.values)
        XCTAssertEqual(observation.issue?.error, .io(.openFile, errno: ELOOP, .leaf(privacy)))
    }
}
