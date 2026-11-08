// Declaration state tests: present / notPresent / unavailable per category, live captures and the nine-pair matrix.

import Darwin
import Foundation
import XCTest
@testable import MacScope

final class CEDeclarationStateTests: XCTestCase {
    private let mainPath = "Contents/MacOS/OwnedMain"
    private let servicePath = "Contents/XPCServices/Owned.xpc/Contents/MacOS/service"
    private let serviceInfo = "Contents/XPCServices/Owned.xpc/Contents/Info.plist"
    private let privacyPath = "Contents/Resources/PrivacyInfo.xcprivacy"
    private let resourcesPath = "Contents/Resources"
    private let arm = CEHarness.key("arm64")
    private let truncatedPlist = Array("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>a</key>".utf8)
    private let arrayPlist = Array(("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        + "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><array/></plist>").utf8)

    // MARK: Helpers

    private final class Switch: @unchecked Sendable { var on = false }

    private struct Captured {
        let result: CE.CaptureResult
        let observation: CE.DeclarationObservation
        let component: CE.ComponentRecord
    }

    private func appBundle(main: [UInt8] = CEBytes.arm64) throws -> CEBundle {
        let bundle = try CEBundle(self)
        try bundle.info()
        try bundle.write(mainPath, main)
        return bundle
    }

    private func serviceBundle(info: [UInt8]?) throws -> CEBundle {
        let bundle = try appBundle()
        try bundle.write(servicePath, CEBytes.arm64)
        if let info { try bundle.write(serviceInfo, info, executable: false) }
        return bundle
    }

    /// One capture with a single request. The fault seam is armed only once the request phase begins.
    private func capture(_ bundle: CEBundle, _ path: String, _ category: CE.DeclarationCategory, architecture: String? = nil,
                         limits: CE.BundleDiscovery.Limits = .init(), beforeCapture: (() throws -> Void)? = nil,
                         fault: ((CE.Operation, CE.PathRange) -> Int32?)? = nil) throws -> Captured {
        let armed = Switch()
        let target = CEHarness.path(path)
        let result = try CE.capture(selection: bundle.root, limits: limits,
                                    fault: { operation, range in armed.on ? fault?(operation, range) : nil }) { live, session in
            _ = try? beforeCapture?()
            armed.on = true
            guard let component = live.inventory.components.first(where: { $0.path == target }) else { return [] }
            return [CE.CaptureRequest(session: session, inventoryID: live.inventory.id, componentID: component.id,
                                      category: category, architecture: architecture.map(CEHarness.key))]
        }
        let component = try XCTUnwrap(result.inventory.components.first { $0.path == target }, "component \(path) admitted")
        let observation = try XCTUnwrap(result.observations.first, "one observation for the single request")
        XCTAssertEqual(result.observations.count, 1)
        XCTAssertEqual(observation.componentID, component.id)
        XCTAssertEqual(observation.inventoryID, result.inventory.id)
        XCTAssertEqual(observation.category, category)
        return Captured(result: result, observation: observation, component: component)
    }

    private func expectUnavailable(_ captured: Captured, _ error: CE.EvidenceError, range: CE.PathRange? = nil,
                                   file: StaticString = #filePath, line: UInt = #line) {
        let observation = captured.observation
        XCTAssertEqual(observation.state, .unavailable, file: file, line: line)
        XCTAssertNil(observation.values, file: file, line: line)
        XCTAssertEqual(observation.issue?.error, error, file: file, line: line)
        if let range { XCTAssertEqual(observation.issue?.range, range, file: file, line: line) }
    }

    private func expect<T>(_ expected: CE.EvidenceError, file: StaticString = #filePath, line: UInt = #line, _ body: () throws -> T) {
        do {
            _ = try body()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? CE.EvidenceError, expected, file: file, line: line)
        }
    }

    private func dictionary(_ pairs: [(String, EntitlementValue)]) throws -> EntitlementDictionary {
        try EntitlementDictionary(entries: pairs.map { EntitlementEntry(key: $0.0, value: $0.1) })
    }

    // Pure-value observations for the pair matrix. Side 0 is previous (flag true, EIO), side 1 is current (flag 1, EACCES).
    private let matrixInventory = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
    private let matrixComponent = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!

    private func matrixSource(_ category: CE.DeclarationCategory, _ architecture: CE.ExactUTF8Key?) -> CE.DeclarationSource {
        let path: String
        switch category {
        case .info: path = "Contents/Info.plist"
        case .loadCommands: path = mainPath
        case .privacy: path = privacyPath
        }
        return CE.DeclarationSource(path: CEHarness.path(path), architecture: architecture)
    }

    private func matrixObservation(_ state: CE.DeclarationState, _ category: CE.DeclarationCategory, _ architecture: CE.ExactUTF8Key?,
                                   side: Int, emptyPresent: Bool = false) throws -> CE.DeclarationObservation {
        let source = matrixSource(category, architecture)
        switch state {
        case .present:
            let values = emptyPresent ? try dictionary([]) : try dictionary([("flag", side == 0 ? .boolean(true) : .integer(1))])
            return try CE.DeclarationObservation(inventoryID: matrixInventory, componentID: matrixComponent, category: category,
                                                 architecture: architecture, state: .present, values: values, source: source)
        case .notPresent:
            return try CE.DeclarationObservation(inventoryID: matrixInventory, componentID: matrixComponent, category: category,
                                                 architecture: architecture, state: .notPresent, source: source)
        case .unavailable:
            let range = CE.PathRange.leaf(source.path)
            let issue = CE.EvidenceIssue(.io(.read, errno: side == 0 ? EIO : EACCES, range), range: range)
            return try CE.DeclarationObservation(inventoryID: matrixInventory, componentID: matrixComponent, category: category,
                                                 architecture: architecture, state: .unavailable, issue: issue)
        }
    }

    private func expectedKind(_ previous: CE.DeclarationState, _ current: CE.DeclarationState) -> CE.DeclarationDifference.Kind {
        switch (previous, current) {
        case (.present, .present): .comparedPresent
        case (.present, .notPresent): .becameAbsent
        case (.notPresent, .present): .becamePresent
        case (.notPresent, .notPresent): .bothAbsent
        default: .unavailable
        }
    }

    /// Every ordered pair of the given states over DeclarationDifference.
    private func assertPairMatrix(_ category: CE.DeclarationCategory, _ architecture: CE.ExactUTF8Key?, states: [CE.DeclarationState],
                                  file: StaticString = #filePath, line: UInt = #line) throws {
        for p in states {
            for c in states {
                let label = "\(category.rawValue) \(p.rawValue)/\(c.rawValue)"
                let previous = try matrixObservation(p, category, architecture, side: 0)
                let current = try matrixObservation(c, category, architecture, side: 1)
                let difference = try CE.DeclarationDifference(previous: previous, current: current)
                XCTAssertEqual(difference.kind, expectedKind(p, c), label, file: file, line: line)
                XCTAssertEqual(difference.previous, previous, label, file: file, line: line)
                XCTAssertEqual(difference.current, current, label, file: file, line: line)
                XCTAssertEqual(difference.category, category, label, file: file, line: line)
                XCTAssertEqual(difference.architecture, architecture, label, file: file, line: line)
                if difference.kind == .comparedPresent {
                    let rows = difference.rows ?? []
                    XCTAssertEqual(rows.filter { $0.kind != .unchanged }.map { $0.key }, ["flag"], label, file: file, line: line)
                    XCTAssertEqual(rows.first?.previous, .boolean(true), label, file: file, line: line)
                    XCTAssertEqual(rows.first?.current, .integer(1), label, file: file, line: line)
                } else {
                    XCTAssertNil(difference.rows, "\(label): no value rows outside present/present", file: file, line: line)
                }
                if p == .unavailable {
                    XCTAssertEqual(difference.previous.issue?.errno, EIO, label, file: file, line: line)
                    XCTAssertNil(difference.previous.values, label, file: file, line: line)
                }
                if c == .unavailable {
                    XCTAssertEqual(difference.current.issue?.errno, EACCES, label, file: file, line: line)
                    XCTAssertNil(difference.current.values, label, file: file, line: line)
                }
                if p == .notPresent { XCTAssertNil(difference.previous.values, label, file: file, line: line) }
                if c == .notPresent { XCTAssertNil(difference.current.values, label, file: file, line: line) }
            }
        }
    }

    /// The constructor refuses every payload that does not match its state.
    private func assertStatePayloadRefusals(_ category: CE.DeclarationCategory, _ architecture: CE.ExactUTF8Key?,
                                            file: StaticString = #filePath, line: UInt = #line) throws {
        let source = matrixSource(category, architecture)
        let values = try dictionary([("flag", .boolean(true))])
        let issue = CE.EvidenceIssue(.io(.read, errno: EIO, .leaf(source.path)), range: .leaf(source.path))
        func make(_ state: CE.DeclarationState, values: EntitlementDictionary? = nil, source: CE.DeclarationSource? = nil,
                  issue: CE.EvidenceIssue? = nil) throws -> CE.DeclarationObservation {
            try CE.DeclarationObservation(inventoryID: matrixInventory, componentID: matrixComponent, category: category,
                                          architecture: architecture, state: state, values: values, source: source, issue: issue)
        }
        expect(.invalidObservation(.badStatePayload), file: file, line: line) { try make(.present, source: source) }
        expect(.invalidObservation(.badStatePayload), file: file, line: line) { try make(.present, values: values) }
        expect(.invalidObservation(.badStatePayload), file: file, line: line) { try make(.present, values: values, source: source, issue: issue) }
        expect(.invalidObservation(.missingTypedReason), file: file, line: line) { try make(.unavailable) }
        expect(.invalidObservation(.missingTypedReason), file: file, line: line) { try make(.unavailable, source: source) }
        expect(.invalidObservation(.badStatePayload), file: file, line: line) { try make(.unavailable, values: values, issue: issue) }
        // A well-formed unavailable observation carries a typed issue and no values.
        let good = try make(.unavailable, issue: issue)
        XCTAssertEqual(good.state, .unavailable, file: file, line: line)
        XCTAssertNil(good.values, file: file, line: line)
        if category == .privacy {
            expect(.invalidObservation(.badStatePayload), file: file, line: line) { try make(.notPresent) }
            expect(.invalidObservation(.badStatePayload), file: file, line: line) { try make(.notPresent, values: values, source: source) }
            expect(.invalidObservation(.badStatePayload), file: file, line: line) { try make(.notPresent, source: source, issue: issue) }
        } else {
            // Info and load commands have no authoritative absence: notPresent is invalid input however it is filled in.
            expect(.invalidObservation(.notPresentNotAllowed), file: file, line: line) { try make(.notPresent) }
            expect(.invalidObservation(.notPresentNotAllowed), file: file, line: line) { try make(.notPresent, source: source) }
            expect(.invalidObservation(.notPresentNotAllowed), file: file, line: line) { try make(.notPresent, values: values, source: source) }
            expect(.invalidObservation(.notPresentNotAllowed), file: file, line: line) { try make(.notPresent, source: source, issue: issue) }
        }
    }

    // MARK: STATE-INFO-PRESENT-UNAVAILABLE

    func test_STATE_INFO_PRESENT_UNAVAILABLE() throws {
        // SPEC-CASE: STATE-INFO-PRESENT-UNAVAILABLE
        let infoRange = CE.PathRange.leaf(CEHarness.path(serviceInfo))

        // A valid dictionary is present with its typed values and exact source.
        do {
            let bundle = try serviceBundle(info: CEBytes.plist(["CFBundleIdentifier": "com.example.service", "Flag": true]))
            let captured = try capture(bundle, servicePath, .info)
            let observation = captured.observation
            XCTAssertEqual(observation.state, .present)
            XCTAssertNil(observation.architecture)
            XCTAssertNil(observation.issue)
            XCTAssertEqual(observation.values?["Flag"], .boolean(true))
            XCTAssertEqual(observation.values?["CFBundleIdentifier"], .string("com.example.service"))
            XCTAssertEqual(observation.source, CE.DeclarationSource(path: CEHarness.path(serviceInfo), architecture: nil))
        }
        // A present empty dictionary stays present.
        do {
            let bundle = try serviceBundle(info: CEBytes.plist([:]))
            let observation = try capture(bundle, servicePath, .info).observation
            XCTAssertEqual(observation.state, .present)
            XCTAssertEqual(observation.values?.entries.count, 0)
            XCTAssertNotNil(observation.source)
        }

        // Missing, unreadable, malformed, linked and oversized Info are unavailable with a typed cause, never notPresent.
        do {
            let captured = try capture(try serviceBundle(info: nil), servicePath, .info)
            expectUnavailable(captured, .io(.openFile, errno: ENOENT, infoRange), range: infoRange)
            XCTAssertNil(captured.observation.source)
            XCTAssertEqual(captured.observation.issue?.operation, .openFile)
            XCTAssertEqual(captured.observation.issue?.errno, ENOENT)
        }
        do {
            let bundle = try serviceBundle(info: CEBytes.plist(["Flag": true]))
            let captured = try capture(bundle, servicePath, .info, fault: { operation, range in
                operation == .openFile && range == infoRange ? EACCES : nil
            })
            expectUnavailable(captured, .io(.openFile, errno: EACCES, infoRange), range: infoRange)
        }
        do {
            let bundle = try serviceBundle(info: CEBytes.plist(["Flag": true]))
            let captured = try capture(bundle, servicePath, .info, fault: { operation, range in
                operation == .read && range == infoRange ? EIO : nil
            })
            expectUnavailable(captured, .io(.read, errno: EIO, infoRange), range: infoRange)
        }
        do {
            let captured = try capture(try serviceBundle(info: truncatedPlist), servicePath, .info)
            expectUnavailable(captured, .malformedMetadata(.info, infoRange, .badPlist), range: infoRange)
        }
        do {
            let captured = try capture(try serviceBundle(info: arrayPlist), servicePath, .info)
            expectUnavailable(captured, .malformedMetadata(.info, infoRange, .notDictionary), range: infoRange)
        }
        do {
            let captured = try capture(try serviceBundle(info: []), servicePath, .info)
            expectUnavailable(captured, .malformedMetadata(nil, infoRange, .badPlist), range: infoRange)
        }
        do {
            let big = CEBytes.plist(["Padding": String(repeating: "a", count: 70_000)])
            XCTAssertGreaterThan(big.count, CE.BundleDiscovery.maximumPlistBytes)
            let captured = try capture(try serviceBundle(info: big), servicePath, .info)
            expectUnavailable(captured, .malformedMetadata(nil, infoRange, .oversize), range: infoRange)
        }
        do {
            let bundle = try serviceBundle(info: nil)
            try bundle.symlink(serviceInfo, to: "../../../Info.plist")
            let captured = try capture(bundle, servicePath, .info)
            expectUnavailable(captured, .io(.openFile, errno: ELOOP, infoRange), range: infoRange)
        }

        // Constructor and pair-matrix assertions. Info has no notPresent column or row.
        try assertStatePayloadRefusals(.info, nil)
        expect(.invalidObservation(.wrongArchitectureField)) {
            try CE.DeclarationObservation(inventoryID: matrixInventory, componentID: matrixComponent, category: .info,
                                          architecture: arm, state: .present, values: dictionary([]), source: matrixSource(.info, arm))
        }
        try assertPairMatrix(.info, nil, states: [.present, .unavailable])
    }

    // MARK: STATE-LOADCMD-PRESENT-UNAVAILABLE

    func test_STATE_LOADCMD_PRESENT_UNAVAILABLE() throws {
        // SPEC-CASE: STATE-LOADCMD-PRESENT-UNAVAILABLE
        let mainRange = CE.PathRange.leaf(CEHarness.path(mainPath))

        // A present image with zero load commands is present with an empty command list.
        do {
            let captured = try capture(try appBundle(), mainPath, .loadCommands, architecture: "arm64")
            let observation = captured.observation
            XCTAssertEqual(observation.state, .present)
            XCTAssertEqual(observation.architecture, arm)
            XCTAssertEqual(observation.values?["commands"], .array([]))
            XCTAssertEqual(observation.source, CE.DeclarationSource(path: CEHarness.path(mainPath), architecture: arm))
            XCTAssertNil(observation.issue)
        }
        // One command is reported with the donor-fixed field names, from the exact requested slice.
        do {
            let captured = try capture(try appBundle(main: CEBytes.loadDylib()), mainPath, .loadCommands, architecture: "arm64")
            let observation = captured.observation
            XCTAssertEqual(observation.state, .present)
            guard case .array(let rows)? = observation.values?["commands"], rows.count == 1,
                  case .dictionary(let row) = rows[0] else { return XCTFail("one command row expected") }
            XCTAssertEqual(row["architecture"], .string("arm64"))
            XCTAssertEqual(row["command"], .string("load"))
            XCTAssertEqual(row["path"], .string("@rpath/Owned.dylib"))
            XCTAssertEqual(row["currentVersion"], .string("1.0.0"))
            XCTAssertEqual(row["compatibilityVersion"], .string("1.0.0"))
            XCTAssertNil(row["useFlags"])
        }
        // A slice the component does not have is unavailable, and the requested label is kept exactly.
        for label in ["x86_64", "arm64e", "ARM64"] {
            let captured = try capture(try appBundle(), mainPath, .loadCommands, architecture: label)
            expectUnavailable(captured, .architectureMismatch, range: mainRange)
            XCTAssertEqual(captured.observation.architecture, CEHarness.key(label))
            XCTAssertNil(captured.observation.source)
        }
        // A malformed command string is unavailable with the typed metadata cause.
        do {
            let captured = try capture(try appBundle(main: CEBytes.loadDylib(nameOffset: 200)), mainPath, .loadCommands, architecture: "arm64")
            XCTAssertEqual(captured.component.architectures, [arm], "inventory capture does not parse load commands")
            expectUnavailable(captured, .malformedMetadata(nil, mainRange, .badCommandString), range: mainRange)
            XCTAssertEqual(captured.observation.architecture, arm)
        }
        // A read failure during the load capture is unavailable with its operation and errno.
        do {
            let captured = try capture(try appBundle(), mainPath, .loadCommands, architecture: "arm64", fault: { operation, range in
                operation == .read && range == mainRange ? EIO : nil
            })
            expectUnavailable(captured, .io(.read, errno: EIO, mainRange), range: mainRange)
        }
        // An exhausted shared header budget is unavailable, and the bytes consumed before the failure stay charged.
        do {
            var image = [0xcf, 0xfa, 0xed, 0xfe] + CEBytes.le32([0x0100000c, 0, 2, 1, 3000, 0, 0]) + CEBytes.le32([0x2b, 3000])
            image += [UInt8](repeating: 0, count: 2992)
            XCTAssertEqual(image.count, 3032)
            let limits = CE.BundleDiscovery.Limits(headerBytes: 8192)
            let captured = try capture(try appBundle(main: image), mainPath, .loadCommands, architecture: "arm64", limits: limits)
            XCTAssertEqual(captured.component.architectures, [arm])
            expectUnavailable(captured, .budgetExceeded(.headerBytes, mainRange), range: mainRange)
            let beforeRequest = 3032 + (8 + 4 + 32 + 3000)
            XCTAssertGreaterThan(captured.result.headerBytesUsed, beforeRequest, "partial reads before the refusal stay charged")
            XCTAssertLessThanOrEqual(captured.result.headerBytesUsed, 8192)
            XCTAssertEqual(captured.result.inventory.scope.headerBytes, captured.result.headerBytesUsed)
        }

        try assertStatePayloadRefusals(.loadCommands, arm)
        expect(.invalidObservation(.emptyArchitecture)) {
            try CE.DeclarationObservation(inventoryID: matrixInventory, componentID: matrixComponent, category: .loadCommands,
                                          state: .present, values: dictionary([]), source: matrixSource(.loadCommands, nil))
        }
        expect(.invalidObservation(.emptyArchitecture)) {
            try CE.DeclarationObservation(inventoryID: matrixInventory, componentID: matrixComponent, category: .loadCommands,
                                          architecture: CE.ExactUTF8Key(""), state: .present, values: dictionary([]),
                                          source: matrixSource(.loadCommands, CE.ExactUTF8Key("")))
        }
        try assertPairMatrix(.loadCommands, arm, states: [.present, .unavailable])
    }

    // MARK: STATE-PRIVACY-PRESENT

    func test_STATE_PRIVACY_PRESENT() throws {
        // SPEC-CASE: STATE-PRIVACY-PRESENT
        let manifest = CE.PathRange.leaf(CEHarness.path(privacyPath))
        func bundle(manifest bytes: [UInt8]) throws -> CEBundle {
            let bundle = try appBundle()
            try bundle.write(privacyPath, bytes, executable: false)
            return bundle
        }

        let withTrue = try capture(try bundle(manifest: CEBytes.plist(["NSPrivacyTracking": true])), mainPath, .privacy)
        XCTAssertEqual(withTrue.observation.state, .present)
        XCTAssertEqual(withTrue.observation.values?["NSPrivacyTracking"], .boolean(true))
        XCTAssertEqual(withTrue.observation.source, CE.DeclarationSource(path: CEHarness.path(privacyPath), architecture: nil))
        XCTAssertNil(withTrue.observation.issue)

        // An empty manifest dictionary is present, not absent.
        let empty = try capture(try bundle(manifest: CEBytes.plist([:])), mainPath, .privacy)
        XCTAssertEqual(empty.observation.state, .present)
        XCTAssertEqual(empty.observation.values?.entries.count, 0)

        // Semantic differences use the exact typed comparator.
        let withOne = try capture(try bundle(manifest: CEBytes.plist(["NSPrivacyTracking": 1])), mainPath, .privacy)
        let difference = try CE.DeclarationDifference(previous: withTrue.observation, current: withOne.observation)
        XCTAssertEqual(difference.kind, .comparedPresent)
        XCTAssertEqual((difference.rows ?? []).filter { $0.kind != .unchanged }.map { $0.key }, ["NSPrivacyTracking"])
        let sameAgain = try CE.DeclarationDifference(previous: withTrue.observation, current: withTrue.observation)
        XCTAssertEqual(sameAgain.kind, .comparedPresent)
        XCTAssertEqual((sameAgain.rows ?? []).filter { $0.kind != .unchanged }.count, 0, "zero changes is still a present/present comparison")
        let emptyVersusTrue = try CE.DeclarationDifference(previous: empty.observation, current: withTrue.observation)
        XCTAssertEqual((emptyVersusTrue.rows ?? []).map { $0.kind }, [.added])

        // Malformed and oversized manifests are unavailable.
        let malformed = try capture(try bundle(manifest: truncatedPlist), mainPath, .privacy)
        expectUnavailable(malformed, .malformedMetadata(.privacy, manifest, .badPlist), range: manifest)
        let notDictionary = try capture(try bundle(manifest: arrayPlist), mainPath, .privacy)
        expectUnavailable(notDictionary, .malformedMetadata(.privacy, manifest, .notDictionary), range: manifest)
        let zero = try capture(try bundle(manifest: []), mainPath, .privacy)
        expectUnavailable(zero, .malformedMetadata(nil, manifest, .badPlist), range: manifest)
        let big = try capture(try bundle(manifest: CEBytes.plist(["Padding": String(repeating: "a", count: 70_000)])), mainPath, .privacy)
        expectUnavailable(big, .malformedMetadata(nil, manifest, .oversize), range: manifest)

        try assertStatePayloadRefusals(.privacy, nil)
        try assertPairMatrix(.privacy, nil, states: [.present, .notPresent, .unavailable])
        // Present-empty against absent stays a state transition in both directions.
        let emptyPresent = try matrixObservation(.present, .privacy, nil, side: 0, emptyPresent: true)
        let absent = try matrixObservation(.notPresent, .privacy, nil, side: 1)
        XCTAssertEqual(try CE.DeclarationDifference(previous: emptyPresent, current: absent).kind, .becameAbsent)
        XCTAssertEqual(try CE.DeclarationDifference(previous: absent, current: emptyPresent).kind, .becamePresent)
    }

    // MARK: STATE-PRIVACY-NOT-PRESENT-ONLY-ON-ENOENT

    func test_STATE_PRIVACY_NOT_PRESENT_ONLY_ON_ENOENT() throws {
        // SPEC-CASE: STATE-PRIVACY-NOT-PRESENT-ONLY-ON-ENOENT
        let manifest = CE.PathRange.leaf(CEHarness.path(privacyPath))
        let resources = CE.PathRange.leaf(CEHarness.path(resourcesPath))

        // Resources directory opens, the explicit manifest is missing: the only authoritative absence.
        do {
            let bundle = try appBundle()
            try bundle.directory(resourcesPath)
            let observation = try capture(bundle, mainPath, .privacy).observation
            XCTAssertEqual(observation.state, .notPresent)
            XCTAssertNil(observation.values)
            XCTAssertNil(observation.issue)
            XCTAssertEqual(observation.source, CE.DeclarationSource(path: CEHarness.path(privacyPath), architecture: nil))
        }
        // The same ENOENT delivered on the manifest open by the fault seam is the same absence.
        do {
            let bundle = try appBundle()
            try bundle.write(privacyPath, CEBytes.plist([:]), executable: false)
            let observation = try capture(bundle, mainPath, .privacy, fault: { operation, range in
                operation == .openFile && range == manifest ? ENOENT : nil
            }).observation
            XCTAssertEqual(observation.state, .notPresent)
            XCTAssertNil(observation.values)
        }
        // ENOENT during the preflight (the resources directory itself) is unavailable, not manifest absence.
        do {
            let captured = try capture(try appBundle(), mainPath, .privacy)
            expectUnavailable(captured, .io(.openDirectory, errno: ENOENT, resources), range: manifest)
        }
        do {
            let bundle = try appBundle()
            try bundle.write(privacyPath, CEBytes.plist([:]), executable: false)
            let captured = try capture(bundle, mainPath, .privacy, fault: { operation, range in
                operation == .openDirectory && range == resources ? ENOENT : nil
            })
            expectUnavailable(captured, .io(.openDirectory, errno: ENOENT, resources), range: manifest)
        }
        // A parent that disappears between inventory and capture is a changed input, never an absent manifest.
        do {
            let bundle = try appBundle()
            try bundle.write(privacyPath, CEBytes.plist([:]), executable: false)
            let removal = bundle.url(resourcesPath)
            let captured = try capture(bundle, mainPath, .privacy, beforeCapture: {
                try FileManager.default.removeItem(at: removal)
            })
            expectUnavailable(captured, .io(.openDirectory, errno: ENOENT, resources), range: manifest)
        }
        // The resources path is a regular file: ENOTDIR on the preflight, unavailable.
        do {
            let bundle = try appBundle()
            try bundle.write(resourcesPath, [1, 2, 3], executable: false)
            let captured = try capture(bundle, mainPath, .privacy)
            expectUnavailable(captured, .io(.openDirectory, errno: ENOTDIR, resources), range: manifest)
        }
        // ENOENT on any operation other than the manifest open is not absence.
        for operation in [CE.Operation.read, .statDescriptor] {
            let bundle = try appBundle()
            try bundle.write(privacyPath, CEBytes.plist([:]), executable: false)
            let captured = try capture(bundle, mainPath, .privacy, fault: { op, range in
                op == operation && range == manifest ? ENOENT : nil
            })
            expectUnavailable(captured, .io(operation, errno: ENOENT, manifest), range: manifest)
        }
        // ENOENT on a different path's manifest open is not this manifest's absence either.
        do {
            let bundle = try appBundle()
            try bundle.write(privacyPath, CEBytes.plist([:]), executable: false)
            let other = CE.PathRange.leaf(CEHarness.path("Contents/Resources/Other.xcprivacy"))
            let observation = try capture(bundle, mainPath, .privacy, fault: { op, range in
                op == .openFile && range == other ? ENOENT : nil
            }).observation
            XCTAssertEqual(observation.state, .present)
        }
    }

    // MARK: STATE-PRIVACY-UNAVAILABLE-OTHER-ERRNO

    func test_STATE_PRIVACY_UNAVAILABLE_OTHER_ERRNO() throws {
        // SPEC-CASE: STATE-PRIVACY-UNAVAILABLE-OTHER-ERRNO
        let manifest = CE.PathRange.leaf(CEHarness.path(privacyPath))
        let resources = CE.PathRange.leaf(CEHarness.path(resourcesPath))
        let errnos: [Int32] = [EACCES, EIO, ENOTDIR, ELOOP]
        let sites: [(CE.Operation, CE.PathRange)] = [
            (.openFile, manifest), (.read, manifest), (.statDescriptor, manifest), (.openDirectory, resources),
        ]
        for (operation, range) in sites {
            for code in errnos {
                let bundle = try appBundle()
                try bundle.write(privacyPath, CEBytes.plist(["NSPrivacyTracking": true]), executable: false)
                let captured = try capture(bundle, mainPath, .privacy, fault: { op, r in op == operation && r == range ? code : nil })
                expectUnavailable(captured, .io(operation, errno: code, range), range: manifest)
                let observation = captured.observation
                XCTAssertEqual(observation.issue?.operation, operation)
                XCTAssertEqual(observation.issue?.errno, code)
                XCTAssertNil(observation.values, "no empty-dictionary substitution")
                XCTAssertNil(observation.source)
                XCTAssertNotEqual(observation.state, .notPresent)
            }
        }
        // A linked manifest is refused by the no-follow open and is unavailable.
        do {
            let bundle = try appBundle()
            try bundle.directory(resourcesPath)
            try bundle.symlink(privacyPath, to: "../Info.plist")
            let captured = try capture(bundle, mainPath, .privacy)
            expectUnavailable(captured, .io(.openFile, errno: ELOOP, manifest), range: manifest)
        }
        // Unavailable stays unavailable in every ordered pair that contains it.
        try assertPairMatrix(.privacy, nil, states: [.present, .notPresent, .unavailable])
        let unavailable = try matrixObservation(.unavailable, .privacy, nil, side: 0)
        for other in [CE.DeclarationState.present, .notPresent, .unavailable] {
            let partner = try matrixObservation(other, .privacy, nil, side: 1)
            XCTAssertEqual(try CE.DeclarationDifference(previous: unavailable, current: partner).kind, .unavailable)
            XCTAssertEqual(try CE.DeclarationDifference(previous: partner, current: unavailable).kind, .unavailable)
        }
    }

    // MARK: STATE-ENTITLEMENT-NOT-PRESENT-VS-UNAVAILABLE

    func test_STATE_ENTITLEMENT_NOT_PRESENT_VS_UNAVAILABLE() throws {
        // SPEC-CASE: STATE-ENTITLEMENT-NOT-PRESENT-VS-UNAVAILABLE
        let present0 = try matrixObservation(.present, .privacy, nil, side: 0)
        let absent0 = try matrixObservation(.notPresent, .privacy, nil, side: 0)
        let unavailable0 = try matrixObservation(.unavailable, .privacy, nil, side: 0)

        // Snapshots keep all three states distinct and copy their payloads exactly.
        let presentSnapshot = try CE.ComponentEntitlementSnapshot(present0)
        XCTAssertEqual(presentSnapshot.declarations.state, .dictionaryPresent)
        XCTAssertEqual(presentSnapshot.declarations.values, present0.values)
        XCTAssertNil(presentSnapshot.declarations.reason)
        XCTAssertEqual(presentSnapshot.declarations.format, "plist")
        XCTAssertEqual(presentSnapshot.source, present0.source)
        let absentSnapshot = try CE.ComponentEntitlementSnapshot(absent0)
        XCTAssertEqual(absentSnapshot.declarations.state, .notPresent)
        XCTAssertNil(absentSnapshot.declarations.values)
        XCTAssertNil(absentSnapshot.declarations.reason)
        let unavailableSnapshot = try CE.ComponentEntitlementSnapshot(unavailable0)
        XCTAssertEqual(unavailableSnapshot.declarations.state, .unavailable)
        XCTAssertNil(unavailableSnapshot.declarations.values)
        XCTAssertEqual(unavailableSnapshot.declarations.reason, CE.IssueKind.io.rawValue)
        XCTAssertNotEqual(absentSnapshot.declarations, unavailableSnapshot.declarations)
        XCTAssertNotEqual(absentSnapshot, unavailableSnapshot)
        XCTAssertEqual(try CE.ComponentEntitlementSnapshot(present0), presentSnapshot, "value copy is stable")

        // All nine ordered pairs.
        for p in [CE.DeclarationState.present, .notPresent, .unavailable] {
            for c in [CE.DeclarationState.present, .notPresent, .unavailable] {
                let label = "\(p.rawValue)/\(c.rawValue)"
                let result = try CE.ComponentEntitlementComparisonResult(
                    previous: CE.ComponentEntitlementSnapshot(matrixObservation(p, .privacy, nil, side: 0)),
                    current: CE.ComponentEntitlementSnapshot(matrixObservation(c, .privacy, nil, side: 1)))
                if p == .unavailable || c == .unavailable {
                    XCTAssertNil(result.comparison, "\(label): unavailable never becomes an empty-dictionary comparison")
                    continue
                }
                let rows = try XCTUnwrap(result.comparison, label).rows
                switch (p, c) {
                case (.present, .present):
                    XCTAssertEqual(rows.filter { $0.kind != .unchanged }.map { $0.key }, ["flag"], label)
                case (.present, .notPresent):
                    XCTAssertEqual(rows.map { $0.kind }, [.removed], label)
                case (.notPresent, .present):
                    XCTAssertEqual(rows.map { $0.kind }, [.added], label)
                default:
                    XCTAssertTrue(rows.isEmpty, label)
                }
                XCTAssertEqual(result.previous.declarations.state, p == .present ? .dictionaryPresent : .notPresent, label)
                XCTAssertEqual(result.current.declarations.state, c == .present ? .dictionaryPresent : .notPresent, label)
            }
        }
        // Present-empty against absent: no value rows, but the states stay different.
        let emptyPresent = try CE.ComponentEntitlementSnapshot(matrixObservation(.present, .privacy, nil, side: 0, emptyPresent: true))
        let absent = try CE.ComponentEntitlementSnapshot(matrixObservation(.notPresent, .privacy, nil, side: 1))
        let transition = try CE.ComponentEntitlementComparisonResult(previous: emptyPresent, current: absent)
        XCTAssertEqual(transition.comparison?.rows.count, 0)
        XCTAssertNotEqual(transition.previous.declarations.state, transition.current.declarations.state)

        // Info and load commands snapshot present and unavailable; they have no absent state to snapshot.
        for (category, architecture) in [(CE.DeclarationCategory.info, CE.ExactUTF8Key?.none), (.loadCommands, arm)] {
            let present = try CE.ComponentEntitlementSnapshot(matrixObservation(.present, category, architecture, side: 0))
            let unavailable = try CE.ComponentEntitlementSnapshot(matrixObservation(.unavailable, category, architecture, side: 1))
            XCTAssertEqual(present.architecture, architecture)
            XCTAssertEqual(unavailable.declarations.state, .unavailable)
            XCTAssertNil(try CE.ComponentEntitlementComparisonResult(previous: present, current: unavailable).comparison)
            XCTAssertNotNil(try CE.ComponentEntitlementComparisonResult(previous: present, current: present).comparison)
            expect(.invalidObservation(.notPresentNotAllowed)) {
                try CE.DeclarationObservation(inventoryID: matrixInventory, componentID: matrixComponent, category: category,
                                              architecture: architecture, state: .notPresent,
                                              source: matrixSource(category, architecture))
            }
        }

        // Inconsistent payload and state can never reach a snapshot: the observation itself refuses.
        try assertStatePayloadRefusals(.privacy, nil)
    }
}
