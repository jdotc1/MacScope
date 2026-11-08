// Error tests: typed refusals that throw, partial or cancelled results that never claim completeness, and error shapes.

import Darwin
import Foundation
import XCTest
@testable import MacScope

final class CEErrorTests: XCTestCase {
    private let infoLeaf = CE.PathRange.leaf(CEHarness.path("Contents/Info.plist"))
    private let mainPath = "Contents/MacOS/OwnedMain"
    private let helperPath = "Contents/Helpers/aaa"
    private let arm = CEHarness.key("arm64")
    private let x86 = CEHarness.key("x86_64")

    private final class Box: @unchecked Sendable {
        var on = false
        var count = 0
    }

    // MARK: Helpers

    /// Two admitted candidates: Contents/Helpers/aaa (walked first) and the principal Contents/MacOS/OwnedMain.
    private func twoComponentBundle() throws -> CEBundle {
        let bundle = try CEBundle(self)
        try bundle.info()
        try bundle.write(mainPath, CEBytes.arm64)
        try bundle.write(helperPath, CEBytes.arm64)
        return bundle
    }

    private func thrown(_ root: URL, limits: CE.BundleDiscovery.Limits = .init(), fault: @escaping CE.FaultInjector = { _, _ in nil },
                        choose: (CE.LiveComponentInventory, CE.SessionID) -> [CE.CaptureRequest] = { _, _ in [] }) -> CE.EvidenceError? {
        do {
            _ = try CE.capture(selection: root, limits: limits, fault: fault, choose: choose)
            return nil
        } catch {
            return error as? CE.EvidenceError
        }
    }

    private func expect<T>(_ expected: CE.EvidenceError, file: StaticString = #filePath, line: UInt = #line, _ body: () throws -> T) {
        do {
            _ = try body()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? CE.EvidenceError, expected, file: file, line: line)
        }
    }

    private func openDescriptorCount() -> Int {
        (0..<2048).reduce(0) { $0 + (fcntl(Int32($1), F_GETFD) == -1 ? 0 : 1) }
    }

    private func unavailableObservation(_ inventory: UUID, _ component: UUID, category: CE.DeclarationCategory = .info,
                                        architecture: CE.ExactUTF8Key? = nil) throws -> CE.DeclarationObservation {
        let range = CE.PathRange.leaf(CEHarness.path("Contents/Info.plist"))
        return try CE.DeclarationObservation(inventoryID: inventory, componentID: component, category: category, architecture: architecture,
                                             state: .unavailable, issue: CE.EvidenceIssue(.io(.read, errno: EIO, range), range: range))
    }

    private func record(_ path: String, id: UUID = UUID(), parent: UUID? = nil, architectures: [CE.ExactUTF8Key] = [],
                        minimum: [CE.ArchitectureMinimum] = [], issues: [CE.EvidenceIssue] = []) -> CE.ComponentRecord {
        CE.ComponentRecord(id: id, parentID: parent, path: CEHarness.path(path), kind: CEHarness.key("helper"), declaredBundleID: nil,
                           declaredVersion: nil, architectures: architectures, minimumOS: minimum, slices: [], issues: issues,
                           issueOverflow: nil, metadataAvailable: true, isDeclarationOnly: false)
    }

    private func scope(locations: [CE.SearchLocation] = [], exclusions: [CE.ExclusionRecord] = [],
                       issues: [CE.EvidenceIssue] = []) -> CE.InventoryScope {
        CE.InventoryScope(searchedLocations: locations, completion: .complete, exclusions: exclusions, exclusionOverflow: nil, issues: issues,
                          issueOverflow: nil, visited: 0, headerBytes: 0, remainderUnknown: false, limitEntries: 4096, limitDepth: 12,
                          limitCandidates: 128, limitHeaderBytes: 1_048_576)
    }

    private func nested(_ levels: Int) -> [String: Any] {
        var value: [String: Any] = [:]
        for _ in 1..<max(levels, 1) { value = ["k": value] }
        return value
    }

    // MARK: ERR-TYPED-REFUSAL-SHAPES

    func test_ERR_TYPED_REFUSAL_SHAPES() throws {
        // SPEC-CASE: ERR-TYPED-REFUSAL-SHAPES

        // 1. Limits are validated first and throw; nothing is captured and `choose` never runs.
        let bundle = try twoComponentBundle()
        let invalidLimits: [(CE.BundleDiscovery.Limits, CE.LimitKind)] = [
            (.init(entries: 0), .entries), (.init(entries: -1), .entries), (.init(entries: 4097), .entries),
            (.init(depth: 0), .depth), (.init(depth: 13), .depth),
            (.init(candidates: 0), .candidates), (.init(candidates: 129), .candidates),
            (.init(headerBytes: 4095), .headerBytes), (.init(headerBytes: 1_048_577), .headerBytes),
            (.init(entries: 0, depth: 0, candidates: 0, headerBytes: 0), .entries),
            (.init(depth: 0, candidates: 0), .depth),
        ]
        for (limits, kind) in invalidLimits {
            let ran = Box()
            let error = thrown(bundle.root, limits: limits, choose: { _, _ in ran.on = true; return [] })
            XCTAssertEqual(error, .invalidLimits(kind), "\(limits)")
            XCTAssertFalse(ran.on, "limits are refused before any capture")
        }
        XCTAssertNoThrow(try CE.BundleDiscovery.Limits(entries: 4096, depth: 12, candidates: 128, headerBytes: 1_048_576).validate())
        XCTAssertNoThrow(try CE.BundleDiscovery.Limits(entries: 1, depth: 1, candidates: 1, headerBytes: 4096).validate())
        // Limits come before selection: a bad extension with bad limits reports the limits.
        XCTAssertEqual(thrown(URL(fileURLWithPath: "/nonexistent/x.txt"), limits: .init(entries: 0)), .invalidLimits(.entries))

        // 2. Selection shape.
        XCTAssertEqual(thrown(URL(string: "https://example.com/Owned.app")!), .invalidSelection, "not a file URL")
        for name in ["Owned", "Owned.ap", "Owned.apps", "Owned.app.txt", "Owned.txt"] {
            let odd = try CEBundle(self, name: name)
            try odd.info()
            XCTAssertEqual(thrown(odd.root), .invalidSelection, name)
        }
        for name in ["Owned.APP", "Owned.App"] {
            let cased = try CEBundle(self, name: name)
            try cased.info()
            try cased.write(mainPath, CEBytes.arm64)
            XCTAssertNil(thrown(cased.root), "extension compare is ASCII case-insensitive: \(name)")
        }
        let missing = bundle.base.appendingPathComponent("Missing.app")
        XCTAssertEqual(thrown(missing), .io(.openRoot, errno: ENOENT, .wholeRoot))
        let fileRoot = bundle.base.appendingPathComponent("File.app")
        try Data([1, 2, 3]).write(to: fileRoot)
        XCTAssertEqual(thrown(fileRoot), .io(.openRoot, errno: ENOTDIR, .wholeRoot))
        let linkRoot = bundle.base.appendingPathComponent("Link.app")
        try FileManager.default.createSymbolicLink(at: linkRoot, withDestinationURL: bundle.root)
        if case .io(let operation, let code, let range)? = thrown(linkRoot) {
            XCTAssertEqual(operation, .openRoot)
            XCTAssertEqual(range, .wholeRoot)
            XCTAssertTrue([ELOOP, ENOTDIR].contains(code), "a linked root is refused by the no-follow open, got errno \(code)")
        } else {
            XCTFail("a symlinked .app root must throw an openRoot failure")
        }

        // 3. Root-level injected failures throw typed io errors with the operation and errno kept apart.
        XCTAssertEqual(thrown(bundle.root, fault: { op, _ in op == .openRoot ? EACCES : nil }), .io(.openRoot, errno: EACCES, .wholeRoot))
        XCTAssertEqual(thrown(bundle.root, fault: { op, range in op == .statDescriptor && range == .wholeRoot ? EIO : nil }),
                       .io(.statDescriptor, errno: EIO, .wholeRoot))
        let contents = CE.PathRange.leaf(CEHarness.path("Contents"))
        XCTAssertEqual(thrown(bundle.root, fault: { op, range in op == .openDirectory && range == contents ? EACCES : nil }),
                       .io(.openDirectory, errno: EACCES, contents))
        XCTAssertEqual(thrown(bundle.root, fault: { op, range in op == .openFile && range == self.infoLeaf ? ENOENT : nil }),
                       .io(.openFile, errno: ENOENT, infoLeaf))
        XCTAssertEqual(thrown(bundle.root, fault: { op, range in op == .read && range == self.infoLeaf ? EIO : nil }),
                       .io(.read, errno: EIO, infoLeaf))
        XCTAssertEqual(thrown(bundle.root, fault: { op, range in op == .statDescriptor && range == self.infoLeaf ? EIO : nil }),
                       .io(.statDescriptor, errno: EIO, infoLeaf))

        // 4. The required root Info.plist: structural failures throw before any inventory exists.
        func bundleWith(info bytes: [UInt8]?, extra: [String: Any]? = nil) throws -> CEBundle {
            let b = try CEBundle(self)
            if let bytes { try b.write("Contents/Info.plist", bytes, executable: false) }
            if let extra { try b.info(extra, executable: nil) }
            return b
        }
        let truncated = Array("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>a</key>".utf8)
        let arrayPlist = Array(("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
            + "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><array/></plist>").utf8)
        let noContents = try CEBundle(self)
        try FileManager.default.removeItem(at: noContents.url("Contents"))
        XCTAssertEqual(thrown(noContents.root), .io(.openDirectory, errno: ENOENT, contents))
        XCTAssertEqual(thrown(try CEBundle(self).root), .io(.openFile, errno: ENOENT, infoLeaf), "Contents without Info.plist")
        XCTAssertEqual(thrown(try bundleWith(info: truncated).root), .malformedMetadata(.info, infoLeaf, .badPlist))
        XCTAssertEqual(thrown(try bundleWith(info: arrayPlist).root), .malformedMetadata(.info, infoLeaf, .notDictionary))
        XCTAssertEqual(thrown(try bundleWith(info: []).root), .malformedMetadata(.info, infoLeaf, .badPlist), "empty file")
        XCTAssertEqual(thrown(try bundleWith(info: CEBytes.plist(["Padding": String(repeating: "a", count: 70_000)])).root),
                       .malformedMetadata(.info, infoLeaf, .oversize))
        XCTAssertEqual(thrown(try bundleWith(info: nil, extra: ["CFBundleExecutable": "a/b"]).root),
                       .malformedMetadata(.info, infoLeaf, .invalidExecutable))
        XCTAssertEqual(thrown(try bundleWith(info: nil, extra: ["CFBundleExecutable": ".."]).root),
                       .malformedMetadata(.info, infoLeaf, .invalidExecutable))
        XCTAssertEqual(thrown(try bundleWith(info: nil, extra: ["CFBundleExecutable": 7]).root),
                       .malformedMetadata(.info, infoLeaf, .invalidExecutable))
        XCTAssertEqual(thrown(try bundleWith(info: nil, extra: ["CFBundleExecutable": ""]).root),
                       .malformedMetadata(.info, infoLeaf, .invalidExecutable))
        let dirInfo = try CEBundle(self)
        try dirInfo.directory("Contents/Info.plist")
        XCTAssertEqual(thrown(dirInfo.root), .malformedMetadata(.info, infoLeaf, .notRegularFile))
        let linkInfo = try CEBundle(self)
        try linkInfo.write("Contents/Real.plist", CEBytes.plist(["CFBundleExecutable": "OwnedMain"]), executable: false)
        try linkInfo.symlink("Contents/Info.plist", to: "Real.plist")
        XCTAssertEqual(thrown(linkInfo.root), .io(.openFile, errno: ELOOP, infoLeaf))

        // 5. An undeclared executable is a partial result, not a throw: a declaration-only record carries the Info facts.
        do {
            let unresolved = try CEBundle(self)
            try unresolved.info(["CFBundleIdentifier": "com.example.undeclared"], executable: nil)
            let result = try CEHarness.capture(unresolved)
            XCTAssertEqual(result.inventory.scope.completion, .partial)
            XCTAssertTrue(result.inventory.scope.issues.contains { $0.error == .principalUnresolved })
            let only = try XCTUnwrap(result.inventory.components.first { $0.isDeclarationOnly })
            XCTAssertEqual(only.path, CEHarness.path("Contents/Info.plist"))
            XCTAssertFalse(only.metadataAvailable)
            XCTAssertFalse(result.inventory.covers(only.path))
        }

        // 6. Image header failures are recorded on the component, never thrown, and keep the inventory partial.
        do {
            let headers = try CEBundle(self)
            try headers.info()
            try headers.write(mainPath, CEBytes.arm64)
            try headers.write("Contents/Helpers/badfat", CEBytes.badFat)
            try headers.write("Contents/Helpers/short", [0xcf, 0xfa, 0xed, 0xfe])
            try headers.write("Contents/Helpers/object", CEBytes.object)
            let result = try CEHarness.capture(headers)
            XCTAssertEqual(result.inventory.scope.completion, .partial)
            func component(_ path: String) -> CE.ComponentRecord? { result.inventory.components.first { $0.path == CEHarness.path(path) } }
            let reasons: [(String, CE.MetadataReason)] = [
                ("Contents/Helpers/badfat", .badUniversalLayout), ("Contents/Helpers/short", .truncated),
                ("Contents/Helpers/object", .unsupportedFileType),
            ]
            for (path, reason) in reasons {
                let record = component(path)
                XCTAssertNotNil(record, path)
                XCTAssertEqual(record?.metadataAvailable, false, path)
                XCTAssertEqual(record?.architectures.count, 0, path)
                XCTAssertTrue(record?.issues.contains { $0.error == .malformedHeader(.leaf(CEHarness.path(path)), reason) } ?? false, path)
            }
            XCTAssertEqual(component(mainPath)?.metadataAvailable, true, "the valid principal is unaffected")
            XCTAssertFalse(result.inventory.covers(CEHarness.path(mainPath)), "a partial inventory covers nothing")
        }

        // 7. Inventory validation: each structural reason, exactly once, and a valid baseline.
        let base = record("Contents/Helpers/a")
        XCTAssertNoThrow(try CEHarness.inventory([base, record("Contents/Helpers/b", parent: base.id)]).validate())
        func invalid(_ reason: CE.InventoryReason, _ inventory: CE.ComponentInventory, file: StaticString = #filePath, line: UInt = #line) {
            expect(.invalidInventory(reason), file: file, line: line) { try inventory.validate() }
        }
        invalid(.tooManyComponents, CEHarness.inventory((0..<129).map { record("Contents/Helpers/h\($0)") }))
        XCTAssertNoThrow(try CEHarness.inventory((0..<128).map { record("Contents/Helpers/h\($0)") }).validate())
        let issueRange = CE.PathRange.wholeRoot
        invalid(.scopeTooLarge, CEHarness.inventory([base], scope(issues: (0..<256).map { _ in CE.EvidenceIssue(.cancelled, range: issueRange) })))
        invalid(.scopeTooLarge, CEHarness.inventory([base], scope(exclusions: (0..<256).map { index in
            CE.ExclusionRecord(range: .leaf(CEHarness.path("Contents/Helpers/x\(index)")), rawPath: CEHarness.key("x\(index)"),
                               state: .nonImage, canonicalPath: nil, omittedCount: 0)
        })))
        invalid(.scopeTooLarge, CEHarness.inventory([base], scope(locations: (0..<17).map { _ in
            CE.SearchLocation(range: .wholeRoot, role: .fullRoot, status: .searched)
        })))
        invalid(.scopeTooLarge, CEHarness.inventory([record("Contents/Helpers/a", issues: (0..<65).map { _ in CE.EvidenceIssue(.cancelled) })]))
        XCTAssertNoThrow(try CEHarness.inventory([base], scope(issues: (0..<255).map { _ in CE.EvidenceIssue(.cancelled) })).validate())
        let sharedID = UUID()
        invalid(.duplicateID, CEHarness.inventory([record("Contents/Helpers/a", id: sharedID), record("Contents/Helpers/b", id: sharedID)]))
        invalid(.duplicatePath, CEHarness.inventory([record("Contents/Helpers/a"), record("Contents/Helpers/a")]))
        for bad in [[".."], ["a/b"], [""], ["a\u{0}b"]] {
            let unsafe = CE.ComponentRecord(id: UUID(), parentID: nil, path: CE.RelativePath(unchecked: bad.map { CEHarness.key($0) }),
                                            kind: CEHarness.key("helper"), declaredBundleID: nil, declaredVersion: nil, architectures: [],
                                            minimumOS: [], slices: [], issues: [], issueOverflow: nil, metadataAvailable: true,
                                            isDeclarationOnly: false)
            invalid(.badPath, CEHarness.inventory([unsafe]))
        }
        invalid(.badParent, CEHarness.inventory([record("Contents/Helpers/a", parent: UUID())]))
        let selfParent = UUID()
        invalid(.badParent, CEHarness.inventory([record("Contents/Helpers/a", id: selfParent, parent: selfParent)]))
        let first = UUID(), second = UUID()
        invalid(.cyclicParents, CEHarness.inventory([record("Contents/Helpers/a", id: first, parent: second),
                                                     record("Contents/Helpers/b", id: second, parent: first)]))
        invalid(.tooManyArchitectures, CEHarness.inventory([record("Contents/Helpers/a",
                                                                    architectures: (0..<65).map { CEHarness.key("a\($0)") })]))
        invalid(.duplicateArchitecture, CEHarness.inventory([record("Contents/Helpers/a", architectures: [arm, arm])]))
        invalid(.minimumWithoutArchitecture, CEHarness.inventory([record("Contents/Helpers/a", architectures: [arm],
            minimum: [CE.ArchitectureMinimum(architecture: x86, minimum: "12.0")])]))
        XCTAssertNoThrow(try CEHarness.inventory([record("Contents/Helpers/a", architectures: [arm, x86],
            minimum: [CE.ArchitectureMinimum(architecture: x86, minimum: "12.0")])]).validate())

        // 8. Observation reasons at review construction. These throw; nothing is partially accepted.
        let target = record("Contents/Helpers/aaa", architectures: [arm])
        let inventory = CEHarness.inventory([target])
        let good = try unavailableObservation(inventory.id, target.id)
        XCTAssertNoThrow(try CE.ComponentReview(inventory: inventory, observations: [good]))
        expect(.invalidObservation(.tooManyObservations)) {
            try CE.ComponentReview(inventory: inventory, observations: Array(repeating: good, count: 385))
        }
        expect(.invalidObservation(.inventoryMismatch)) {
            try CE.ComponentReview(inventory: inventory, observations: [unavailableObservation(UUID(), target.id)])
        }
        expect(.invalidObservation(.unknownComponentRecord)) {
            try CE.ComponentReview(inventory: inventory, observations: [unavailableObservation(inventory.id, UUID())])
        }
        expect(.invalidObservation(.duplicateObservation)) { try CE.ComponentReview(inventory: inventory, observations: [good, good]) }
        expect(.invalidObservation(.architectureNotEnumerated)) {
            try CE.ComponentReview(inventory: inventory, observations: [unavailableObservation(inventory.id, target.id,
                                                                                               category: .loadCommands, architecture: x86)])
        }
        expect(.sourceMismatch) {
            let wrong = CE.DeclarationSource(path: CEHarness.path("Contents/Wrong.plist"), architecture: nil)
            return try CE.ComponentReview(inventory: inventory, observations: [CE.DeclarationObservation(
                inventoryID: inventory.id, componentID: target.id, category: .info, state: .present,
                values: EntitlementDictionary(), source: wrong)])
        }

        // 9. Request refusals inside the capture throw typed errors; nothing is returned.
        func mainID(_ live: CE.LiveComponentInventory) -> UUID { live.inventory.components.first { $0.path == CEHarness.path(mainPath) }!.id }
        func request(_ live: CE.LiveComponentInventory, _ session: CE.SessionID, category: CE.DeclarationCategory = .info,
                     architecture: CE.ExactUTF8Key? = nil, inventory: UUID? = nil, component: UUID? = nil) -> CE.CaptureRequest {
            CE.CaptureRequest(session: session, inventoryID: inventory ?? live.inventory.id, componentID: component ?? mainID(live),
                              category: category, architecture: architecture)
        }
        let previous = try CE.capture(selection: bundle.root) { live, session in [request(live, session)] }
        XCTAssertEqual(previous.observations.count, 1)
        let root = bundle.root
        XCTAssertEqual(thrown(root, choose: { live, _ in [request(live, CE.SessionID(rawValue: UUID()))] }), .staleCapability)
        XCTAssertEqual(thrown(root, choose: { live, _ in [request(live, previous.sessionID)] }), .staleCapability, "a session from an earlier call")
        XCTAssertEqual(thrown(root, choose: { live, session in [request(live, session, inventory: previous.inventory.id)] }),
                       .invalidObservation(.inventoryMismatch))
        XCTAssertEqual(thrown(root, choose: { live, session in [request(live, session, inventory: UUID())] }),
                       .invalidObservation(.inventoryMismatch))
        XCTAssertEqual(thrown(root, choose: { live, session in [request(live, session, component: UUID())] }), .unknownComponent)
        XCTAssertEqual(thrown(root, choose: { live, session in
            [request(live, session, component: previous.inventory.components[0].id)]
        }), .unknownComponent, "component ids are fresh for every capture")
        XCTAssertEqual(thrown(root, choose: { live, session in [request(live, session, category: .info, architecture: self.arm)] }),
                       .invalidObservation(.wrongArchitectureField))
        XCTAssertEqual(thrown(root, choose: { live, session in [request(live, session, category: .privacy, architecture: self.arm)] }),
                       .invalidObservation(.wrongArchitectureField))
        XCTAssertEqual(thrown(root, choose: { live, session in [request(live, session, category: .loadCommands, architecture: nil)] }),
                       .invalidObservation(.wrongArchitectureField))
        XCTAssertEqual(thrown(root, choose: { live, session in [request(live, session), request(live, session)] }),
                       .invalidObservation(.duplicateObservation))
        XCTAssertEqual(thrown(root, choose: { live, session in
            [request(live, session, category: .loadCommands, architecture: self.arm), request(live, session, category: .privacy),
             request(live, session, category: .loadCommands, architecture: self.arm)]
        }), .invalidObservation(.duplicateObservation))
        XCTAssertEqual(thrown(root, choose: { live, session in Array(repeating: request(live, session), count: 385) }),
                       .budgetExceeded(.observations, .wholeRoot))
        // The first bad request decides: a stale session outranks an unknown component and a duplicate.
        XCTAssertEqual(thrown(root, choose: { live, session in
            [request(live, session), request(live, CE.SessionID(rawValue: UUID()), component: UUID())]
        }), .staleCapability)
        // Distinct categories on one component are not duplicates.
        let ok = try CE.capture(selection: root) { live, session in
            [request(live, session, category: .info), request(live, session, category: .privacy),
             request(live, session, category: .loadCommands, architecture: self.arm)]
        }
        XCTAssertEqual(ok.observations.count, 3)

        // 10. Payload decoding refusals.
        let source = CEHarness.path("Contents/Resources/PrivacyInfo.xcprivacy")
        let leaf = CE.PathRange.leaf(source)
        func decode(_ bytes: [UInt8]) throws -> EntitlementDictionary {
            try CE.DeclarationObservation.decode(bytes, source: source, category: .privacy)
        }
        expect(.malformedMetadata(.privacy, leaf, .oversize)) { try decode([UInt8](repeating: 0x20, count: 65_537)) }
        expect(.malformedMetadata(.privacy, leaf, .badPlist)) { try decode([UInt8](repeating: 0x20, count: 65_536)) }
        expect(.malformedMetadata(.privacy, leaf, .badPlist)) { try decode([]) }
        expect(.malformedMetadata(.privacy, leaf, .badPlist)) { try decode(truncated) }
        expect(.malformedMetadata(.privacy, leaf, .notDictionary)) { try decode(arrayPlist) }
        XCTAssertNoThrow(try decode(CEBytes.plist(nested(33))), "depth 32 is the last accepted level")
        expect(.malformedMetadata(.privacy, leaf, .badPlist)) { try decode(CEBytes.plist(nested(34))) }
        expect(.malformedMetadata(.info, CE.PathRange.leaf(source), .oversize)) {
            try CE.DeclarationObservation.decode([UInt8](repeating: 0x20, count: 65_537), source: source, category: .info)
        }

        // 11. Error shape: every case maps to its own kind; descriptions are bounded; operation and errno only exist for io.
        let range = CE.PathRange.leaf(CEHarness.path("Contents/Helpers/aaa"))
        let table: [(CE.EvidenceError, CE.IssueKind)] = [
            (.invalidSelection, .invalidSelection), (.invalidLimits(.entries), .invalidLimits), (.unsafePath(nil), .unsafePath),
            (.unsafePath(range), .unsafePath), (.io(.read, errno: EIO, range), .io),
            (.shortRead(range, expected: 8, actual: 4), .shortRead), (.changedInput(range), .changedInput),
            (.malformedHeader(range, .truncated), .malformedHeader), (.malformedMetadata(.info, range, .badPlist), .malformedMetadata),
            (.malformedMetadata(nil, range, .oversize), .malformedMetadata), (.budgetExceeded(.headerBytes, range), .budgetExceeded),
            (.invalidInventory(.duplicateID), .invalidInventory), (.invalidObservation(.badSource), .invalidObservation),
            (.architectureMismatch, .architectureMismatch), (.unknownComponent, .unknownComponent), (.unknownMatch, .unknownMatch),
            (.sourceMismatch, .sourceMismatch), (.staleCapability, .staleCapability), (.cancelled, .cancelled),
            (.principalUnavailable(range), .principalUnavailable), (.principalUnresolved, .principalUnresolved),
        ]
        XCTAssertEqual(Set(table.map { $0.1 }).count, 19, "nineteen distinct kinds")
        for (error, kind) in table {
            XCTAssertEqual(error.kind, kind, "\(error)")
            let issue = CE.EvidenceIssue(error, range: range)
            XCTAssertEqual(issue.kind, kind)
            XCTAssertEqual(issue.error, error)
            XCTAssertEqual(issue.range, range)
            let text = try XCTUnwrap(error.errorDescription)
            XCTAssertTrue(text.hasPrefix("Component evidence: "))
            XCTAssertLessThanOrEqual(text.utf8.count, 512)
            XCTAssertEqual((error as Error).localizedDescription, text)
            XCTAssertEqual(issue.display, text)
            if case .io(let operation, let code, _) = error {
                XCTAssertEqual(issue.operation, operation)
                XCTAssertEqual(issue.errno, code)
            } else {
                XCTAssertNil(issue.operation, "\(error)")
                XCTAssertNil(issue.errno, "\(error)")
            }
        }
        XCTAssertEqual(CE.EvidenceIssue(.cancelled).range, .wholeRoot, "the default range is the whole root")
        // A pathologically long path cannot push a description past its 512-byte bound.
        let huge = CE.RelativePath(unchecked: (0..<2000).map { _ in CEHarness.key("component") })
        let hugeError = CE.EvidenceError.unsafePath(.leaf(huge))
        XCTAssertLessThanOrEqual(try XCTUnwrap(hugeError.errorDescription).utf8.count, 512)
        XCTAssertLessThanOrEqual(CE.EvidenceIssue(hugeError, range: .leaf(huge)).display.utf8.count, 512)
        XCTAssertEqual(CE.EvidenceError.io(.read, errno: EIO, range), CE.EvidenceError.io(.read, errno: EIO, range))
        XCTAssertNotEqual(CE.EvidenceError.io(.read, errno: EIO, range), CE.EvidenceError.io(.read, errno: EACCES, range))
        XCTAssertNotEqual(CE.EvidenceError.io(.read, errno: EIO, range), CE.EvidenceError.io(.openFile, errno: EIO, range))
    }

    // MARK: ERR-ERROR-MID-WALK-NEVER-COMPLETE

    func test_ERR_ERROR_MID_WALK_NEVER_COMPLETE() async throws {
        // SPEC-CASE: ERR-ERROR-MID-WALK-NEVER-COMPLETE
        let bundle = try twoComponentBundle()
        let main = CEHarness.path(mainPath)
        let helper = CEHarness.path(helperPath)
        let macos = CEHarness.path("Contents/MacOS")
        let helpersDir = CEHarness.path("Contents/Helpers")

        func location(_ result: CE.CaptureResult, _ range: CE.PathRange) -> CE.SearchLocation.Status? {
            result.inventory.scope.searchedLocations.first { $0.range == range }?.status
        }

        // Baseline: a clean walk with a clean EOF (errno 0 from readdir) is complete and covers both components.
        let clean = try CEHarness.capture(bundle)
        XCTAssertEqual(clean.inventory.scope.completion, .complete)
        XCTAssertEqual(CEHarness.paths(clean.inventory), [helperPath, mainPath])
        XCTAssertTrue(clean.inventory.components.allSatisfy { $0.metadataAvailable })
        XCTAssertEqual(CEHarness.exclusions(clean.inventory, .unreadable), [])
        XCTAssertTrue(clean.inventory.scope.issues.isEmpty)
        XCTAssertTrue(clean.inventory.covers(helper))
        XCTAssertTrue(clean.inventory.covers(main))
        XCTAssertEqual(location(clean, .subtree(macos)), .searched)
        XCTAssertEqual(location(clean, .subtree(helpersDir)), .searched)
        XCTAssertEqual(location(clean, .wholeRoot), .searched)

        // Faults after the first admitted component. Each yields a partial result, never a complete one and never a throw.
        let target: [(CE.Operation, CE.PathRange, String, Bool)] = [
            (.statEntry, .leaf(main), mainPath, false),
            (.openFile, .leaf(main), mainPath, false),
            (.statDescriptor, .leaf(main), mainPath, false),
            (.read, .leaf(main), mainPath, false),
            (.duplicateDirectory, .subtree(macos), "Contents/MacOS", true),
            (.enumerate, .subtree(macos), "Contents/MacOS", true),
            (.openDirectory, .subtree(macos), "Contents/MacOS", true),
            (.statDescriptor, .subtree(macos), "Contents/MacOS", true),
        ]
        let descriptorsBefore = openDescriptorCount()
        for code in [EIO, EACCES] {
            for (operation, range, raw, directoryLevel) in target {
                let label = "\(operation.rawValue)@\(range.display) errno \(code)"
                let result = try CE.capture(selection: bundle.root, fault: { op, r in op == operation && r == range ? code : nil }) { _, _ in [] }
                let inventory = result.inventory
                XCTAssertEqual(inventory.scope.completion, .partial, label)
                XCTAssertFalse(inventory.isComplete, label)
                XCTAssertEqual(CEHarness.paths(inventory), [helperPath], "\(label): the admitted component is retained, the faulted one is not")
                XCTAssertEqual(inventory.components.first?.metadataAvailable, true, label)
                XCTAssertEqual(CEHarness.exclusions(inventory, .unreadable), [raw], label)
                XCTAssertEqual(inventory.scope.exclusions.first { $0.state == .unreadable }?.range, range, label)
                XCTAssertTrue(inventory.scope.issues.contains { $0.error == .principalUnavailable(.leaf(main)) }, "\(label): principal loss is reported")
                XCTAssertFalse(inventory.covers(helper), "\(label): a partial inventory covers nothing")
                XCTAssertFalse(inventory.covers(main), label)
                XCTAssertEqual(location(result, .wholeRoot), .incomplete, label)
                XCTAssertEqual(location(result, .subtree(helpersDir)), .searched, "\(label): untouched locations stay searched")
                if directoryLevel {
                    XCTAssertEqual(location(result, .subtree(macos)), .incomplete, "\(label): an unlisted directory is not searched")
                }
                XCTAssertTrue(result.observations.isEmpty, label)
            }
        }
        XCTAssertEqual(openDescriptorCount(), descriptorsBefore, "no descriptor survives a faulted capture")

        // A readdir error is not the same as EOF: the faulted listing is unreadable and incomplete, the clean one is searched.
        let enumerateFault = try CE.capture(selection: bundle.root, fault: { op, r in op == .enumerate && r == .subtree(macos) ? EIO : nil }) { _, _ in [] }
        XCTAssertEqual(location(enumerateFault, .subtree(macos)), .incomplete)
        XCTAssertEqual(location(clean, .subtree(macos)), .searched)
        XCTAssertNotEqual(enumerateFault.inventory.scope.completion, clean.inventory.scope.completion)

        // A fault in the later metadata read of an admitted component keeps it listed but unavailable, and the result partial.
        do {
            let counter = Box()
            let result = try CE.capture(selection: bundle.root, fault: { op, r in
                guard op == .read, r == .leaf(helper) else { return nil }
                counter.count += 1
                return counter.count == 2 ? EIO : nil
            }) { _, _ in [] }
            XCTAssertEqual(counter.count, 2, "one discovery probe and one metadata read")
            XCTAssertEqual(result.inventory.scope.completion, .partial)
            XCTAssertEqual(CEHarness.paths(result.inventory), [helperPath, mainPath])
            let faulted = try XCTUnwrap(result.inventory.components.first { $0.path == helper })
            XCTAssertFalse(faulted.metadataAvailable)
            XCTAssertTrue(faulted.architectures.isEmpty)
            XCTAssertTrue(faulted.issues.contains { $0.error == .io(.read, errno: EIO, .leaf(helper)) })
            XCTAssertEqual(result.inventory.components.first { $0.path == main }?.metadataAvailable, true)
            XCTAssertFalse(result.inventory.covers(helper))
        }

        // Cancellation. The work runs inside a child task so that cancelling it cannot cancel the test itself.
        let root = bundle.root

        // (a) Cancelled while the first candidate's entry is statted: the rest of the walk is abandoned.
        let afterHelper = Task { () throws -> CE.CaptureResult in
            try CE.capture(selection: root, fault: { op, r in
                if op == .statEntry && r == .leaf(helper) { _ = withUnsafeCurrentTask { $0?.cancel() } }
                return nil
            }) { _, _ in [] }
        }
        let cancelledEarly = try await afterHelper.value
        XCTAssertEqual(cancelledEarly.inventory.scope.completion, .cancelled)
        XCTAssertNotEqual(cancelledEarly.inventory.scope.completion, .complete)
        XCTAssertTrue(cancelledEarly.inventory.scope.issues.contains { $0.kind == .cancelled })
        XCTAssertTrue(cancelledEarly.inventory.scope.remainderUnknown)
        XCTAssertFalse(CEHarness.paths(cancelledEarly.inventory).contains(mainPath), "the abandoned walk never reached the principal")
        XCTAssertTrue(cancelledEarly.inventory.scope.issues.contains { $0.error == .principalUnavailable(.leaf(main)) })
        XCTAssertFalse(cancelledEarly.inventory.covers(helper))
        XCTAssertEqual(location(cancelledEarly, .wholeRoot), .incomplete)
        XCTAssertTrue(cancelledEarly.inventory.components.allSatisfy { !$0.metadataAvailable || $0.issues.isEmpty })

        // (b) Cancelled at the last candidate: both are admitted by the walk, neither gets metadata, and the result says cancelled.
        let atMain = Task { () throws -> CE.CaptureResult in
            try CE.capture(selection: root, fault: { op, r in
                if op == .statEntry && r == .leaf(main) { _ = withUnsafeCurrentTask { $0?.cancel() } }
                return nil
            }) { _, _ in [] }
        }
        let cancelledLate = try await atMain.value
        XCTAssertEqual(cancelledLate.inventory.scope.completion, .cancelled)
        XCTAssertEqual(CEHarness.paths(cancelledLate.inventory), [helperPath, mainPath])
        for component in cancelledLate.inventory.components {
            XCTAssertFalse(component.metadataAvailable, component.path.display)
            XCTAssertTrue(component.issues.contains { $0.kind == .cancelled }, component.path.display)
        }
        XCTAssertFalse(cancelledLate.inventory.covers(main))

        // (c) Cancelled before the call starts: an empty cancelled inventory, no choose, no descriptor work.
        let chosen = Box()
        let preCancelled = Task { () throws -> CE.CaptureResult in
            _ = withUnsafeCurrentTask { $0?.cancel() }
            return try CE.capture(selection: root) { _, _ in chosen.on = true; return [] }
        }
        let empty = try await preCancelled.value
        XCTAssertFalse(chosen.on)
        XCTAssertEqual(empty.inventory.scope.completion, .cancelled)
        XCTAssertTrue(empty.inventory.components.isEmpty)
        XCTAssertTrue(empty.observations.isEmpty)
        XCTAssertEqual(empty.headerBytesUsed, 0)
        XCTAssertEqual(empty.inventory.scope.issues.map { $0.kind }, [.cancelled])
        XCTAssertTrue(empty.inventory.scope.remainderUnknown)
        XCTAssertFalse(empty.inventory.isComplete)
        XCTAssertFalse(empty.inventory.covers(main))
        // Argument errors still win over cancellation: they are refused, not reported as a cancelled result.
        let refusedWhileCancelled = Task { () -> CE.EvidenceError? in
            _ = withUnsafeCurrentTask { $0?.cancel() }
            do { _ = try CE.capture(selection: root, limits: .init(entries: 0)) { _, _ in [] }; return nil }
            catch { return error as? CE.EvidenceError }
        }
        let refusal = await refusedWhileCancelled.value
        XCTAssertEqual(refusal, .invalidLimits(.entries))

        // (d) Cancelled while observations are captured: the first completes, later ones become unavailable with a cancelled issue.
        let armed = Box()
        let duringRequests = Task { () throws -> CE.CaptureResult in
            try CE.capture(selection: root, fault: { op, r in
                if armed.on && op == .openFile && r == .leaf(CEHarness.path("Contents/Info.plist")) {
                    _ = withUnsafeCurrentTask { $0?.cancel() }
                }
                return nil
            }) { live, session in
                armed.on = true
                let id = live.inventory.components.first { $0.path == main }!.id
                return [CE.CaptureRequest(session: session, inventoryID: live.inventory.id, componentID: id, category: .info, architecture: nil),
                        CE.CaptureRequest(session: session, inventoryID: live.inventory.id, componentID: id, category: .privacy, architecture: nil),
                        CE.CaptureRequest(session: session, inventoryID: live.inventory.id, componentID: id, category: .loadCommands,
                                          architecture: CEHarness.key("arm64"))]
            }
        }
        let midRequests = try await duringRequests.value
        XCTAssertEqual(midRequests.inventory.scope.completion, .cancelled)
        XCTAssertNotEqual(midRequests.inventory.scope.completion, .complete)
        XCTAssertEqual(midRequests.observations.count, 3)
        XCTAssertEqual(midRequests.observations[0].category, .info)
        XCTAssertEqual(midRequests.observations[0].state, .present, "the observation already running is completed, not discarded")
        for later in midRequests.observations.dropFirst() {
            XCTAssertEqual(later.state, .unavailable, later.category.rawValue)
            XCTAssertEqual(later.issue?.error, .cancelled, later.category.rawValue)
            XCTAssertNil(later.values)
            XCTAssertNotEqual(later.state, .notPresent, "a cancelled privacy read is not an absence")
        }
        XCTAssertTrue(midRequests.inventory.scope.issues.contains { $0.kind == .cancelled })
        XCTAssertFalse(midRequests.inventory.covers(main))
    }
}
