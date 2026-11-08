// Focused pair-admission cases. Fixtures and recorders belong to each invocation.

import Darwin
import Foundation
import XCTest
@testable import MacScope

final class ComponentEvidencePairAdmissionTests: XCTestCase {
    private typealias CE = ComponentEvidence
    private typealias Delta = ComponentEvidenceSecurityDelta

    private final class OwnerA {}
    private final class OwnerB {}

    /// Records real calls, never substitutes a capture result or wraps the supplied sink.
    private final class Trace {
        var opens: [Delta.Side] = []
        var invocations: [Delta.Side] = []
        var selections: [URL] = []
        var limits: [CE.BundleDiscovery.Limits] = []
        var returns: [(side: Delta.Side, value: CE.CaptureResult)] = []
        var receivedSink: [Bool] = []
        var events: [CE.PairAdmissionEvent] = []
        var admitted: Int = 0
        var injection: CE.PairFaultInjector?
        var beforeCapture: ((Delta.Side) -> Void)?
        var afterCapture: ((Delta.Side, CE.CaptureResult) -> Void)?
        var eventHook: ((CE.PairAdmissionEvent) -> Void)?

        func fault(_ side: Delta.Side, _ operation: CE.Operation, _ range: CE.PathRange) -> Int32? {
            if operation == .openRoot { opens.append(side) }
            return injection?(side, operation, range)
        }

        func execute(_ side: Delta.Side, _ selection: URL, _ limits: CE.BundleDiscovery.Limits,
                     _ fault: CE.FaultInjector, _ sink: CE.SignatureSink?,
                     _ choose: CE.PairChooser) throws -> CE.CaptureResult {
            invocations.append(side)
            selections.append(selection)
            self.limits.append(limits)
            receivedSink.append(sink != nil)
            beforeCapture?(side)
            let result = try CE.capture(selection: selection, limits: limits, fault: fault,
                                        signatureSink: sink, choose: choose)
            returns.append((side, result))
            afterCapture?(side, result)
            return result
        }

        func observe(_ event: CE.PairAdmissionEvent) {
            events.append(event)
            eventHook?(event)
        }
    }

    private static var mainPath: CE.RelativePath { try! CE.RelativePath("Contents/MacOS/OwnedMain") }

    private static func infoRequest(_ live: CE.LiveComponentInventory, _ session: CE.SessionID) -> [CE.CaptureRequest] {
        guard let principal = live.inventory.components.first(where: { $0.path == mainPath }) else {
            XCTFail("fixture must expose its principal component")
            return []
        }
        XCTAssertEqual(live.session, session)
        return [CE.CaptureRequest(session: session, inventoryID: live.inventory.id,
                                  componentID: principal.id, category: .info, architecture: nil)]
    }

    @discardableResult
    private static func admit(_ trace: Trace, previous: CE.PairSelection, current: CE.PairSelection,
                              owner: AnyObject?, installation: UUID?,
                              limits: CE.BundleDiscovery.Limits = .init(),
                              choose: CE.PairChooser = { _, _ in [] }) throws -> CE.AdmittedPair {
        let pair = try CE._admitPair(previous: previous, current: current, owner: owner, installation: installation,
                                     limits: limits, fault: trace.fault, execute: trace.execute,
                                     observe: trace.observe, choose: choose)
        trace.admitted += 1
        return pair
    }

    private static func refused(_ operation: () throws -> CE.AdmittedPair,
                                file: StaticString = #filePath, line: UInt = #line) throws -> Delta.Refusal {
        var refusal: Delta.Refusal?
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            refusal = error as? Delta.Refusal
            XCTAssertNotNil(refusal, "expected the existing typed refusal", file: file, line: line)
        }
        return try XCTUnwrap(refusal, file: file, line: line)
    }

    private static func counts(_ trace: Trace, opens: Int, invocations: Int, returns: Int, admitted: Int,
                               file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(trace.opens.count, opens, file: file, line: line)
        XCTAssertEqual(trace.invocations.count, invocations, file: file, line: line)
        XCTAssertEqual(trace.returns.count, returns, file: file, line: line)
        XCTAssertEqual(trace.admitted, admitted, file: file, line: line)
    }

    private static func singleFailure(_ refusal: Delta.Refusal, side: Delta.Side, kind: Delta.UnderlyingKind,
                                      file: StaticString = #filePath, line: UInt = #line) {
        let rawCode: String = side == .previous ? "previousUnavailable" : "currentUnavailable"
        let code: Delta.RefusalCode = side == .previous ? .previousUnavailable : .currentUnavailable
        let expected: [Delta.ReadSideFailure] = [.init(side: side, code: code, underlyingKind: kind)]
        XCTAssertEqual(refusal.code.rawValue, rawCode, file: file, line: line)
        XCTAssertEqual(refusal.side, side, file: file, line: line)
        XCTAssertEqual(refusal.underlyingKind, kind, file: file, line: line)
        XCTAssertEqual(refusal.sideFailures, expected, file: file, line: line)
    }

    private static func stale(_ operation: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { error in
            guard let refusal = error as? Delta.Refusal else {
                return XCTFail("expected sourceStale refusal", file: file, line: line)
            }
            let expectedCode: String = "sourceStale"
            let expectedFailures: [Delta.ReadSideFailure] = []
            XCTAssertEqual(refusal.code.rawValue, expectedCode, file: file, line: line)
            XCTAssertEqual(refusal.underlyingKind, Delta.UnderlyingKind.stale, file: file, line: line)
            XCTAssertNil(refusal.side, file: file, line: line)
            XCTAssertEqual(refusal.sideFailures, expectedFailures, file: file, line: line)
        }
    }

    /// Compares every AR1 component field except generated UUIDs; UUID references are joined by byte path.
    private static func normalizedCapture(_ left: CE.CaptureResult, _ right: CE.CaptureResult,
                                          file: StaticString = #filePath, line: UInt = #line) {
        let lhs = left.inventory.components.sorted { $0.path < $1.path }
        let rhs = right.inventory.components.sorted { $0.path < $1.path }
        XCTAssertEqual(lhs.map(\.path), rhs.map(\.path), file: file, line: line)
        for (a, b) in zip(lhs, rhs) {
            XCTAssertEqual(a.kind, b.kind, file: file, line: line)
            XCTAssertEqual(a.parentID.flatMap { left.inventory.component($0)?.path },
                           b.parentID.flatMap { right.inventory.component($0)?.path }, file: file, line: line)
            XCTAssertEqual(a.declaredBundleID, b.declaredBundleID, file: file, line: line)
            XCTAssertEqual(a.declaredVersion, b.declaredVersion, file: file, line: line)
            XCTAssertEqual(a.architectures, b.architectures, file: file, line: line)
            XCTAssertEqual(a.minimumOS, b.minimumOS, file: file, line: line)
            XCTAssertEqual(a.slices, b.slices, file: file, line: line)
            XCTAssertEqual(a.issues, b.issues, file: file, line: line)
            XCTAssertEqual(a.issueOverflow, b.issueOverflow, file: file, line: line)
            XCTAssertEqual(a.metadataAvailable, b.metadataAvailable, file: file, line: line)
            XCTAssertEqual(a.isDeclarationOnly, b.isDeclarationOnly, file: file, line: line)
        }
        XCTAssertEqual(left.inventory.scope, right.inventory.scope, file: file, line: line)
        XCTAssertEqual(left.observations.count, right.observations.count, file: file, line: line)
        for (a, b) in zip(left.observations, right.observations) {
            XCTAssertEqual(a.inventoryID, left.inventory.id, file: file, line: line)
            XCTAssertEqual(b.inventoryID, right.inventory.id, file: file, line: line)
            XCTAssertNotNil(left.inventory.component(a.componentID), file: file, line: line)
            XCTAssertNotNil(right.inventory.component(b.componentID), file: file, line: line)
            XCTAssertEqual(left.inventory.component(a.componentID)?.path,
                           right.inventory.component(b.componentID)?.path, file: file, line: line)
            XCTAssertEqual(a.category, b.category, file: file, line: line)
            XCTAssertEqual(a.architecture, b.architecture, file: file, line: line)
            XCTAssertEqual(a.state, b.state, file: file, line: line)
            XCTAssertEqual(a.values, b.values, file: file, line: line)
            XCTAssertEqual(a.source, b.source, file: file, line: line)
            XCTAssertEqual(a.issue, b.issue, file: file, line: line)
        }
        XCTAssertEqual(left.headerBytesUsed, right.headerBytesUsed, file: file, line: line)
        XCTAssertEqual(left.rootIdentity, right.rootIdentity, file: file, line: line)
    }

    private static func normalizedAttachment(_ left: CE.SignatureEvidenceAttachment,
                                             _ right: CE.SignatureEvidenceAttachment,
                                             file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(left.componentIDs, right.componentIDs, file: file, line: line)
        for path in left.componentIDs {
            XCTAssertEqual(left.evidence(for: path), right.evidence(for: path), file: file, line: line)
        }
        XCTAssertEqual(left.failures, right.failures, file: file, line: line)
    }

    // TC01: the byte oracle enables the same real signature sink and chooser policy.
    func testTC01ProviderEqualParityWithSignatureEnabledCapture() throws {
        let fixture = try CEBundle(self)
        try fixture.info(["CFBundleIdentifier": "com.example.owned", "CFBundleShortVersionString": "1.0"])
        try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        var directEntries: [(componentID: CE.RelativePath, evidence: CE.SignatureEvidence)] = []
        var directFailures: [CE.SignatureCaptureFailure] = []
        var directSinkCalls: Int = 0
        let sink: CE.SignatureSink = { path, result in
            directSinkCalls += 1
            switch result {
            case .success(let value): directEntries.append((path, value))
            case .failure(let error): directFailures.append(.init(componentID: path, error: error))
            }
        }
        let direct = try CE.capture(selection: fixture.root, signatureSink: sink, choose: Self.infoRequest)
        let attachment = try CE.SignatureEvidenceAttachment(inventoryID: direct.inventory.id,
                                                            entries: directEntries, failures: directFailures)
        try attachment.bind(to: direct.inventory)
        let identity = CE.ProviderCaptureIdentity(providerDomain: UUID(), token: UUID())
        let trace = Trace()
        let owner = OwnerA()
        let pair = try Self.admit(trace, previous: .init(url: fixture.root, providerIdentity: identity),
                                  current: .init(url: fixture.root, providerIdentity: identity),
                                  owner: owner, installation: UUID(), choose: Self.infoRequest)
        Self.counts(trace, opens: 1, invocations: 1, returns: 1, admitted: 1)
        XCTAssertEqual(directSinkCalls, Int(1))
        XCTAssertEqual(direct.inventory.scope.completion, CE.InventoryCompletion.complete)
        XCTAssertEqual(direct.observations.count, Int(1))
        XCTAssertEqual(direct.observations.first?.category, CE.DeclarationCategory.info)
        XCTAssertEqual(direct.observations.first?.state, CE.DeclarationState.present)
        XCTAssertEqual(pair.aliasDecision, CE.AliasDecision.providerSame)
        XCTAssertEqual(pair.backingCount, Int(1))
        XCTAssertEqual(trace.receivedSink, [Bool(true)])
        XCTAssertNotEqual(direct.sessionID, pair.previous.capture.sessionID)
        XCTAssertNotEqual(direct.inventory.id, pair.previous.capture.inventory.id)
        XCTAssertNotNil(pair.previous.capture.rootIdentity)
        Self.normalizedCapture(direct, pair.previous.capture)
        Self.normalizedAttachment(attachment, pair.previous.attachment)
        XCTAssertEqual(pair.previous.attachment.inventoryID, pair.previous.capture.inventory.id)
        XCTAssertEqual(pair.current.capture.inventory.id, pair.previous.capture.inventory.id)
        XCTAssertEqual(pair.current.capture.sessionID, pair.previous.capture.sessionID)
        XCTAssertEqual(pair.work.previousHeaderBytesUsed, direct.headerBytesUsed)
        XCTAssertNil(pair.work.currentHeaderBytesUsed)
        XCTAssertEqual(pair.work.headerBytesUsed, direct.headerBytesUsed)
    }

    // TC02: equal contents under independently allocated roots are not identity.
    func testTC02DistinctProviderRootsRetainOrderedCapturesAndRemainder() throws {
        let previous = try CEBundle(self)
        let current = try CEBundle(self)
        for fixture in [previous, current] {
            try fixture.info()
            try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        }
        let trace = Trace()
        let owner = OwnerA()
        let domain = UUID()
        let pIdentity = CE.ProviderCaptureIdentity(providerDomain: domain, token: UUID())
        let cIdentity = CE.ProviderCaptureIdentity(providerDomain: domain, token: UUID())
        let limits = CE.BundleDiscovery.Limits(entries: 32, depth: 8, candidates: 16, headerBytes: 8192)
        let pair = try Self.admit(trace, previous: .init(url: previous.root, providerIdentity: pIdentity),
                                  current: .init(url: current.root, providerIdentity: cIdentity),
                                  owner: owner, installation: UUID(), limits: limits)
        Self.counts(trace, opens: 2, invocations: 2, returns: 2, admitted: 1)
        XCTAssertEqual(trace.invocations, [Delta.Side.previous, Delta.Side.current])
        XCTAssertEqual(trace.opens, [Delta.Side.previous, Delta.Side.current])
        XCTAssertEqual(trace.receivedSink, [Bool(true), Bool(true)])
        XCTAssertEqual((try XCTUnwrap(trace.limits.first)), limits)
        let p = pair.work.previousHeaderBytesUsed
        let c = try XCTUnwrap(pair.work.currentHeaderBytesUsed)
        XCTAssertEqual((try XCTUnwrap(trace.limits.dropFirst().first)), CE.BundleDiscovery.Limits(entries: 32, depth: 8, candidates: 16,
                                                                headerBytes: limits.headerBytes - p))
        XCTAssertEqual(pair.work.jointHeaderLimit, Int(8192))
        XCTAssertEqual(pair.work.headerBytesUsed, p + c)
        XCTAssertLessThanOrEqual(p + c, limits.headerBytes)
        XCTAssertEqual(pair.backingCount, Int(2))
        XCTAssertEqual(pair.aliasDecision, CE.AliasDecision.distinct)
        XCTAssertEqual(pair.previousProviderIdentity, pIdentity)
        XCTAssertEqual(pair.currentProviderIdentity, cIdentity)
        XCTAssertNotEqual(pair.previous.capture.inventory.id, pair.current.capture.inventory.id)
        XCTAssertNotEqual(pair.previous.capture.rootIdentity, pair.current.capture.rootIdentity)
        XCTAssertEqual(pair.previous.capture.inventory.id, (try XCTUnwrap(trace.returns.first)).value.inventory.id)
        XCTAssertEqual(pair.current.capture.inventory.id, (try XCTUnwrap(trace.returns.dropFirst().first)).value.inventory.id)
    }

    // TC03: the previous spelling is the sole authority after provider equality.
    func testTC03EqualProviderNeverUsesMissingCurrentSelection() throws {
        let fixture = try CEBundle(self)
        try fixture.info()
        try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        let identity = CE.ProviderCaptureIdentity(providerDomain: UUID(), token: UUID())
        let missing = fixture.base.appendingPathComponent("Missing.app")
        let trace = Trace()
        let owner = OwnerA()
        var chooserCalls: Int = 0
        let pair = try Self.admit(trace, previous: .init(url: fixture.root, providerIdentity: identity),
                                  current: .init(url: missing, providerIdentity: identity),
                                  owner: owner, installation: UUID()) { live, session in
            chooserCalls += 1
            return Self.infoRequest(live, session)
        }
        Self.counts(trace, opens: 1, invocations: 1, returns: 1, admitted: 1)
        XCTAssertEqual(chooserCalls, Int(1))
        XCTAssertEqual(trace.selections, [fixture.root])
        XCTAssertEqual(trace.invocations, [Delta.Side.previous])
        XCTAssertEqual(trace.receivedSink, [Bool(true)])
        XCTAssertEqual(pair.backingCount, Int(1))
        XCTAssertEqual(pair.aliasDecision, CE.AliasDecision.providerSame)
        XCTAssertEqual(pair.previous.capture.inventory.id, pair.current.capture.inventory.id)
        XCTAssertEqual(pair.previous.capture.sessionID, pair.current.capture.sessionID)
        XCTAssertEqual(pair.previous.attachment.inventoryID, pair.current.attachment.inventoryID)
        Self.normalizedCapture(pair.previous.capture, pair.current.capture)
        Self.normalizedAttachment(pair.previous.attachment, pair.current.attachment)
        XCTAssertNil(pair.work.currentHeaderBytesUsed)
        XCTAssertEqual(pair.work.headerBytesUsed, pair.work.previousHeaderBytesUsed)
        XCTAssertEqual(trace.events, [CE.PairAdmissionEvent.attachmentBuilt(.previous), .attachmentBound(.previous),
                                     .sideReady(.previous), .willCommit])
    }

    // TC04: ancestor spelling coalesces by captured root identity, while separate roots stay distinct.
    func testTC04UnknownIdentityRootAliasPreservesBothCharges() throws {
        for aliases: Bool in [true, false] {
            let first = try CEBundle(self)
            let second = try CEBundle(self)
            for fixture in [first, second] {
                try fixture.info()
                try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
            }
            try first.symlink("Contents/up", to: "../..")
            let secondURL = aliases ? first.url("Contents/up/Owned.app") : second.root
            let trace = Trace()
            let owner = OwnerA()
            let pair = try Self.admit(trace, previous: .init(url: first.root), current: .init(url: secondURL),
                                      owner: owner, installation: UUID())
            Self.counts(trace, opens: 2, invocations: 2, returns: 2, admitted: 1)
            XCTAssertEqual(trace.invocations, [Delta.Side.previous, Delta.Side.current])
            XCTAssertEqual(trace.events, [CE.PairAdmissionEvent.attachmentBuilt(.previous), .attachmentBound(.previous),
                                         .sideReady(.previous), .attachmentBuilt(.current), .attachmentBound(.current),
                                         .sideReady(.current), .willCommit])
            let p = pair.work.previousHeaderBytesUsed
            let c = try XCTUnwrap(pair.work.currentHeaderBytesUsed)
            XCTAssertEqual(pair.work.headerBytesUsed, p + c)
            XCTAssertNotEqual((try XCTUnwrap(trace.returns.first)).value.inventory.id, (try XCTUnwrap(trace.returns.dropFirst().first)).value.inventory.id)
            XCTAssertEqual(pair.previous.capture.inventory.id, (try XCTUnwrap(trace.returns.first)).value.inventory.id)
            if aliases {
                XCTAssertEqual((try XCTUnwrap(trace.returns.first)).value.rootIdentity, (try XCTUnwrap(trace.returns.dropFirst().first)).value.rootIdentity)
                XCTAssertEqual(pair.aliasDecision, CE.AliasDecision.rootsCoalesced)
                XCTAssertEqual(pair.backingCount, Int(1))
                XCTAssertEqual(pair.current.capture.inventory.id, (try XCTUnwrap(trace.returns.first)).value.inventory.id)
                XCTAssertEqual(pair.current.attachment.inventoryID, (try XCTUnwrap(trace.returns.first)).value.inventory.id)
                XCTAssertEqual(p, c)
                XCTAssertEqual(pair.work.headerBytesUsed, Int(2) * p)
            } else {
                XCTAssertNotEqual((try XCTUnwrap(trace.returns.first)).value.rootIdentity, (try XCTUnwrap(trace.returns.dropFirst().first)).value.rootIdentity)
                XCTAssertEqual(pair.aliasDecision, CE.AliasDecision.distinct)
                XCTAssertEqual(pair.backingCount, Int(2))
                XCTAssertEqual(pair.current.capture.inventory.id, (try XCTUnwrap(trace.returns.dropFirst().first)).value.inventory.id)
            }
        }
    }

    // TC05: full provider identity includes the domain, not merely the token.
    func testTC05ContradictoryProviderIdentitiesRefuseEqualRoots() throws {
        for differentDomains: Bool in [false, true] {
            let fixture = try CEBundle(self)
            try fixture.info()
            try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
            let domain = UUID()
            let token = UUID()
            let previous = CE.ProviderCaptureIdentity(providerDomain: domain, token: token)
            let current = CE.ProviderCaptureIdentity(providerDomain: differentDomains ? UUID() : domain,
                                                      token: differentDomains ? token : UUID())
            XCTAssertNotEqual(previous, current)
            let owner = OwnerA()
            let trace = Trace()
            let refusal = try Self.refused {
                try Self.admit(trace, previous: .init(url: fixture.root, providerIdentity: previous),
                               current: .init(url: fixture.root, providerIdentity: current),
                               owner: owner, installation: UUID())
            }
            Self.counts(trace, opens: 2, invocations: 2, returns: 2, admitted: 0)
            XCTAssertEqual(refusal.code.rawValue, String("ambiguousSelection"))
            XCTAssertNil(refusal.side)
            XCTAssertNil(refusal.underlyingKind)
            XCTAssertEqual(refusal.sideFailures, [Delta.ReadSideFailure]())
            XCTAssertFalse(trace.events.contains(.willCommit))
            XCTAssertEqual(trace.events.filter { $0 == .attachmentBuilt(.previous) }.count, Int(1))
            XCTAssertEqual(trace.events.filter { $0 == .attachmentBuilt(.current) }.count, Int(1))
        }
    }

    private enum EarlyFailure: CaseIterable {
        case missing, extensionMismatch, nonFileURL, openRoot, initialStat
        var opens: Int { self == .extensionMismatch || self == .nonFileURL ? 0 : 1 }
    }

    // TC06: all proven-prefix failures in each side order and with both sides failing.
    func testTC06EarlyFailureMatrixHasExactCountsAndOrderedRefusals() throws {
        for failure in EarlyFailure.allCases {
            for failedSides: [Delta.Side] in [[.previous], [.current], [.previous, .current]] {
                let previous = try CEBundle(self)
                let current = try CEBundle(self)
                for fixture in [previous, current] {
                    try fixture.info()
                    try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
                }
                func selection(_ fixture: CEBundle, _ side: Delta.Side) -> URL {
                    guard failedSides.contains(side) else { return fixture.root }
                    switch failure {
                    case .missing: return fixture.base.appendingPathComponent("Missing.app")
                    case .extensionMismatch: return fixture.base.appendingPathComponent("Owned.txt")
                    case .nonFileURL: return URL(string: "https://example.invalid/Owned.app")!
                    case .openRoot, .initialStat: return fixture.root
                    }
                }
                let trace = Trace()
                trace.injection = { side, operation, range in
                    guard failedSides.contains(side) else { return nil }
                    if failure == .openRoot && operation == .openRoot { return EACCES }
                    if failure == .initialStat && operation == .statDescriptor && range == .wholeRoot { return EIO }
                    return nil
                }
                let limits = CE.BundleDiscovery.Limits(headerBytes: 8192)
                let owner = OwnerA()
                let refusal = try Self.refused {
                    try Self.admit(trace, previous: .init(url: selection(previous, .previous)),
                                   current: .init(url: selection(current, .current)),
                                   owner: owner, installation: UUID(), limits: limits)
                }
                let both: Bool = failedSides.count == 2
                let expectedOpens: Int = both ? Int(2) * failure.opens : Int(1) + failure.opens
                Self.counts(trace, opens: expectedOpens, invocations: 2, returns: both ? 0 : 1, admitted: 0)
                XCTAssertEqual(trace.invocations, [Delta.Side.previous, Delta.Side.current])
                if failedSides.contains(.previous) {
                    XCTAssertEqual(trace.limits, [limits, limits])
                } else {
                    let p = try XCTUnwrap(trace.returns.first?.value.headerBytesUsed)
                    XCTAssertEqual((try XCTUnwrap(trace.limits.dropFirst().first)).headerBytes, limits.headerBytes - p)
                }
                if both {
                    let expected: [Delta.ReadSideFailure] = [
                        .init(side: .previous, code: .previousUnavailable, underlyingKind: .unavailable),
                        .init(side: .current, code: .currentUnavailable, underlyingKind: .unavailable)]
                    XCTAssertEqual(refusal.code.rawValue, String("previousUnavailable"))
                    XCTAssertNil(refusal.side)
                    XCTAssertNil(refusal.underlyingKind)
                    XCTAssertEqual(refusal.sideFailures, expected)
                } else {
                    Self.singleFailure(refusal, side: failedSides[0], kind: .unavailable)
                }
                XCTAssertFalse(trace.events.contains(.willCommit))
            }
        }
    }

    // TC06: zero-open invalid limits and one-open mixed invalid-selection/missing-path pairs.
    func testTC06BothInvalidLimitsAndMixedEarlyFailures() throws {
        for variant: Int in 0..<3 {
            let invalidLimits: Bool = variant == 0
            let invalidPrevious: Bool = variant == 1
            do {
                let fixture = try CEBundle(self)
                try fixture.info()
                try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
                let invalid = fixture.base.appendingPathComponent("Owned.txt")
                let missing = fixture.base.appendingPathComponent("Missing.app")
                let previous = invalidLimits ? fixture.root : (invalidPrevious ? invalid : missing)
                let current = invalidLimits ? fixture.root : (invalidPrevious ? missing : invalid)
                let limits = CE.BundleDiscovery.Limits(headerBytes: invalidLimits ? 4095 : 8192)
                let owner = OwnerA()
                let trace = Trace()
                let refusal = try Self.refused {
                    try Self.admit(trace, previous: .init(url: previous), current: .init(url: current),
                                   owner: owner, installation: UUID(), limits: limits)
                }
                Self.counts(trace, opens: invalidLimits ? 0 : 1, invocations: 2, returns: 0, admitted: 0)
                let kind: Delta.UnderlyingKind = invalidLimits ? .budget : .unavailable
                let expected: [Delta.ReadSideFailure] = [
                    .init(side: .previous, code: .previousUnavailable, underlyingKind: kind),
                    .init(side: .current, code: .currentUnavailable, underlyingKind: kind)]
                XCTAssertEqual(refusal.code.rawValue, String("previousUnavailable"))
                XCTAssertNil(refusal.side)
                XCTAssertNil(refusal.underlyingKind)
                XCTAssertEqual(refusal.sideFailures, expected)
                XCTAssertEqual(trace.limits, [limits, limits])
            }
        }
    }

    // TC06: equality makes even a proven early previous failure terminal.
    func testTC06EqualProviderFailureNeverFallsBackToCurrent() throws {
        for failure in EarlyFailure.allCases {
            let fixture = try CEBundle(self)
            try fixture.info()
            try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
            let previousURL: URL
            switch failure {
            case .missing: previousURL = fixture.base.appendingPathComponent("Missing.app")
            case .extensionMismatch: previousURL = fixture.base.appendingPathComponent("Owned.txt")
            case .nonFileURL: previousURL = URL(string: "https://example.invalid/Owned.app")!
            case .openRoot, .initialStat: previousURL = fixture.root
            }
            let trace = Trace()
            trace.injection = { _, operation, range in
                if failure == .openRoot && operation == .openRoot { return EACCES }
                if failure == .initialStat && operation == .statDescriptor && range == .wholeRoot { return EIO }
                return nil
            }
            let identity = CE.ProviderCaptureIdentity(providerDomain: UUID(), token: UUID())
            let owner = OwnerA()
            let refusal = try Self.refused {
                try Self.admit(trace, previous: .init(url: previousURL, providerIdentity: identity),
                               current: .init(url: fixture.root, providerIdentity: identity),
                               owner: owner, installation: UUID())
            }
            Self.counts(trace, opens: failure.opens, invocations: 1, returns: 0, admitted: 0)
            Self.singleFailure(refusal, side: .previous, kind: .unavailable)
            XCTAssertEqual(trace.invocations, [Delta.Side.previous])
        }
    }

    // TC06: a chooser error after real capture work has unknown charge and cannot fund another capture.
    func testTC06UnknownPhaseChooserFailureStopsWithoutFallback() throws {
        for failedSide: Delta.Side in [.previous, .current] {
            let previous = try CEBundle(self)
            let current = try CEBundle(self)
            for fixture in [previous, current] {
                try fixture.info()
                try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
            }
            let trace = Trace()
            let owner = OwnerA()
            let refusal = try Self.refused {
                try Self.admit(trace, previous: .init(url: previous.root), current: .init(url: current.root),
                               owner: owner, installation: UUID()) { live, session in
                    guard trace.invocations.last == failedSide else { return [] }
                    guard let principal = live.inventory.components.first(where: { $0.path == Self.mainPath }) else {
                        XCTFail("fixture must expose its principal component")
                        return []
                    }
                    return [.init(session: session, inventoryID: UUID(), componentID: principal.id,
                                  category: .info, architecture: nil)]
                }
            }
            let previousFailed: Bool = failedSide == .previous
            Self.counts(trace, opens: previousFailed ? 1 : 2, invocations: previousFailed ? 1 : 2,
                        returns: previousFailed ? 0 : 1, admitted: 0)
            Self.singleFailure(refusal, side: failedSide, kind: .bindingMismatch)
            XCTAssertFalse(trace.events.contains(.willCommit))
        }
    }

    // TC06: later descriptor failures are not confused with the initial open/stat prefix.
    func testTC06LaterDescriptorThrowsConservativelyStop() throws {
        for failedSide: Delta.Side in [.previous, .current] {
            for operation: CE.Operation in [.openDirectory, .read] {
                let previous = try CEBundle(self)
                let current = try CEBundle(self)
                for fixture in [previous, current] {
                    try fixture.info()
                    try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
                }
                let target = try CE.RelativePath(operation == .read ? "Contents/Info.plist" : "Contents")
                let trace = Trace()
                trace.injection = { side, actual, range in
                    side == failedSide && actual == operation && range == .leaf(target) ? EIO : nil
                }
                let owner = OwnerA()
                let refusal = try Self.refused {
                    try Self.admit(trace, previous: .init(url: previous.root), current: .init(url: current.root),
                                   owner: owner, installation: UUID())
                }
                let previousFailed: Bool = failedSide == .previous
                Self.counts(trace, opens: previousFailed ? 1 : 2, invocations: previousFailed ? 1 : 2,
                            returns: previousFailed ? 0 : 1, admitted: 0)
                Self.singleFailure(refusal, side: failedSide, kind: .readFailed)
            }
        }
    }

    // TC07: returned receipts, not invented probe totals, determine the joint header allowance.
    func testTC07ThinFixturesUseExactJointHeaderRemainder() throws {
        let previous = try CEBundle(self)
        let current = try CEBundle(self)
        for fixture in [previous, current] {
            try fixture.info()
            try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        }
        let trace = Trace()
        let owner = OwnerA()
        let limits = CE.BundleDiscovery.Limits(entries: 16, depth: 6, candidates: 8, headerBytes: 8192)
        let pair = try Self.admit(trace, previous: .init(url: previous.root), current: .init(url: current.root),
                                  owner: owner, installation: UUID(), limits: limits)
        Self.counts(trace, opens: 2, invocations: 2, returns: 2, admitted: 1)
        let p = pair.work.previousHeaderBytesUsed
        let c = try XCTUnwrap(pair.work.currentHeaderBytesUsed)
        XCTAssertEqual(trace.returns.map { $0.value.inventory.scope.completion },
                       [CE.InventoryCompletion.complete, CE.InventoryCompletion.complete])
        XCTAssertEqual((try XCTUnwrap(trace.limits.dropFirst().first)), .init(entries: 16, depth: 6, candidates: 8, headerBytes: Int(8192) - p))
        XCTAssertEqual(pair.work.jointHeaderLimit, Int(8192))
        XCTAssertEqual(pair.work.headerBytesUsed, p + c)
        XCTAssertLessThanOrEqual(pair.work.headerBytesUsed, Int(8192))
    }

    // TC07: the gate records the fixed fixture preconditions without retry or calibration.
    func testTC07BelowMinimumRemainderStillInvokesCurrentExactlyOnce() throws {
        let previous = try CEBundle(self)
        let current = try CEBundle(self)
        try previous.info()
        try previous.write("Contents/MacOS/OwnedMain", CEBytes.padded)
        try current.info()
        try current.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        let trace = Trace()
        let owner = OwnerA()
        let limits = CE.BundleDiscovery.Limits(headerBytes: 8192)
        let refusal = try Self.refused {
            try Self.admit(trace, previous: .init(url: previous.root), current: .init(url: current.root),
                           owner: owner, installation: UUID(), limits: limits)
        }
        Self.counts(trace, opens: 1, invocations: 2, returns: 1, admitted: 0)
        let first = try XCTUnwrap(trace.returns.first?.value)
        XCTAssertEqual(first.inventory.scope.completion, CE.InventoryCompletion.complete,
                       "fixed padded fixture must complete on previous")
        XCTAssertGreaterThan(first.headerBytesUsed, Int(4096), "fixed padded fixture must leave less than the minimum")
        XCTAssertLessThanOrEqual(first.headerBytesUsed, Int(8192))
        guard first.inventory.scope.completion == .complete, first.headerBytesUsed > 4096,
              first.headerBytesUsed <= 8192 else { return }
        XCTAssertEqual((try XCTUnwrap(trace.limits.dropFirst().first)), .init(headerBytes: Int(8192) - first.headerBytesUsed))
        XCTAssertEqual(trace.opens, [Delta.Side.previous])
        Self.singleFailure(refusal, side: .current, kind: .budget)
    }

    // TC07: explicit-budget and unreadable partials remain different causes, on either side.
    func testTC07PartialResultsStopAndClassifyTheirRetainedCause() throws {
        for budget: Bool in [true, false] {
            for failedSide: Delta.Side in [.previous, .current] {
                let previous = try CEBundle(self)
                let current = try CEBundle(self)
                for fixture in [previous, current] {
                    try fixture.info()
                    try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
                }
                let failedFixture = failedSide == .previous ? previous : current
                let resources = try CE.RelativePath("Contents/Resources")
                try failedFixture.directory("Contents/Resources")
                if budget && failedSide == .current {
                    for index: Int in 0..<8 {
                        try failedFixture.write("Contents/Resources/item\(index)", [UInt8(0)], executable: false)
                    }
                }
                let entries: Int = budget ? (failedSide == .previous ? 1 : 8) : 4096
                let limits = CE.BundleDiscovery.Limits(entries: entries, headerBytes: 8192)
                let trace = Trace()
                if !budget {
                    trace.injection = { side, operation, range in
                        side == failedSide && operation == .enumerate && range == .subtree(resources) ? EACCES : nil
                    }
                }
                let owner = OwnerA()
                let refusal = try Self.refused {
                    try Self.admit(trace, previous: .init(url: previous.root), current: .init(url: current.root),
                                   owner: owner, installation: UUID(), limits: limits)
                }
                let previousFailed: Bool = failedSide == .previous
                Self.counts(trace, opens: previousFailed ? 1 : 2, invocations: previousFailed ? 1 : 2,
                            returns: previousFailed ? 1 : 2, admitted: 0)
                let returned = try XCTUnwrap(trace.returns.last?.value)
                XCTAssertEqual(returned.inventory.scope.completion, CE.InventoryCompletion.partial)
                if budget {
                    XCTAssertTrue(returned.inventory.scope.issues.contains { $0.kind == .budgetExceeded })
                } else {
                    XCTAssertTrue(returned.inventory.scope.exclusions.contains { $0.state == .unreadable })
                    XCTAssertFalse(returned.inventory.scope.issues.contains { $0.kind == .budgetExceeded })
                }
                Self.singleFailure(refusal, side: failedSide, kind: budget ? .budget : .readFailed)
                XCTAssertFalse(trace.events.contains(.attachmentBuilt(failedSide)))
                XCTAssertFalse(trace.events.contains(.willCommit))
            }
        }
    }

    private enum CancellationPoint: CaseIterable, Sendable {
        case beforeAdmission, previousInitialReturn, previousAfterOpen, betweenSides
        case currentInitialReturn, currentAfterOpen, finalCommit
        var expectedOpens: Int {
            switch self {
            case .beforeAdmission, .previousInitialReturn: 0
            case .previousAfterOpen, .betweenSides, .currentInitialReturn: 1
            case .currentAfterOpen, .finalCommit: 2
            }
        }
        var expectedCalls: Int {
            switch self {
            case .beforeAdmission: 0
            case .previousInitialReturn, .previousAfterOpen, .betweenSides: 1
            case .currentInitialReturn, .currentAfterOpen, .finalCommit: 2
            }
        }
        var expectedSide: Delta.Side? {
            switch self {
            case .previousInitialReturn, .previousAfterOpen: .previous
            case .currentInitialReturn, .currentAfterOpen: .current
            case .beforeAdmission, .betweenSides, .finalCommit: nil
            }
        }
    }

    private struct CancellationReport: Sendable {
        let refusal: Delta.Refusal?
        let unexpectedError: Bool
        let opens: [Delta.Side]
        let invocations: [Delta.Side]
        let returns: Int
        let admitted: Int
        let lastEventWasCommit: Bool
        let completions: [CE.InventoryCompletion]
    }

    // TC08: each task cancels itself synchronously at one selected boundary; no task shares mutable state.
    func testTC08CancellationBoundariesPublishNoPair() async throws {
        for point in CancellationPoint.allCases {
            let previous = try CEBundle(self)
            let current = try CEBundle(self)
            for fixture in [previous, current] {
                try fixture.info()
                try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
            }
            let previousURL = previous.root
            let currentURL = current.root
            let report = await Task.detached { () -> CancellationReport in
                let trace = Trace()
                let owner = OwnerA()
                func cancel() { withUnsafeCurrentTask { $0?.cancel() } }
                if point == .beforeAdmission { cancel() }
                trace.beforeCapture = { side in
                    if (point == .previousInitialReturn && side == .previous)
                        || (point == .currentInitialReturn && side == .current) { cancel() }
                }
                trace.injection = { side, operation, _ in
                    if operation == .openRoot && ((point == .previousAfterOpen && side == .previous)
                        || (point == .currentAfterOpen && side == .current)) { cancel() }
                    return nil
                }
                trace.afterCapture = { side, _ in
                    if point == .betweenSides && side == .previous { cancel() }
                }
                trace.eventHook = { event in
                    if point == .finalCommit && event == .willCommit { cancel() }
                }
                var refusal: Delta.Refusal?
                var unexpectedError: Bool = false
                do {
                    try Self.admit(trace, previous: .init(url: previousURL), current: .init(url: currentURL),
                                   owner: owner, installation: UUID())
                } catch let error as Delta.Refusal {
                    refusal = error
                } catch {
                    unexpectedError = true
                }
                return CancellationReport(refusal: refusal, unexpectedError: unexpectedError, opens: trace.opens,
                                          invocations: trace.invocations, returns: trace.returns.count,
                                          admitted: trace.admitted, lastEventWasCommit: trace.events.last == .willCommit,
                                          completions: trace.returns.map { $0.value.inventory.scope.completion })
            }.value
            XCTAssertFalse(report.unexpectedError)
            let refusal = try XCTUnwrap(report.refusal)
            XCTAssertEqual(refusal.code.rawValue, String("cancelled"))
            XCTAssertEqual(refusal.underlyingKind, Delta.UnderlyingKind.cancelled)
            XCTAssertEqual(refusal.side, point.expectedSide)
            let expectedFailures: [Delta.ReadSideFailure] = point.expectedSide.map {
                [.init(side: $0, code: .cancelled, underlyingKind: .cancelled)]
            } ?? []
            XCTAssertEqual(refusal.sideFailures, expectedFailures)
            XCTAssertEqual(report.opens.count, point.expectedOpens)
            XCTAssertEqual(report.invocations.count, point.expectedCalls)
            XCTAssertEqual(report.returns, point.expectedCalls)
            XCTAssertEqual(report.admitted, Int(0))
            if point.expectedCalls < 2 { XCTAssertFalse(report.invocations.contains(.current)) }
            switch point {
            case .previousInitialReturn, .previousAfterOpen:
                XCTAssertEqual(report.completions, [CE.InventoryCompletion.cancelled])
            case .currentInitialReturn, .currentAfterOpen:
                XCTAssertEqual(report.completions, [CE.InventoryCompletion.complete, CE.InventoryCompletion.cancelled])
            case .betweenSides:
                XCTAssertEqual(report.completions, [CE.InventoryCompletion.complete])
            case .finalCommit:
                XCTAssertEqual(report.completions, [CE.InventoryCompletion.complete, CE.InventoryCompletion.complete])
                XCTAssertTrue(report.lastEventWasCommit)
            case .beforeAdmission:
                XCTAssertEqual(report.completions, [CE.InventoryCompletion]())
            }
        }
    }

    // TC09: binding holds only an ObjectIdentifier; releasing the caller's owner clears its weak reference.
    func testTC09OwnerBindingRejectsMismatchAndRetainsNoOwner() throws {
        let fixture = try CEBundle(self)
        try fixture.info()
        try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        var owner: OwnerA? = OwnerA()
        weak var weakOwner = owner
        let other = OwnerB()
        let installation = UUID()
        let identity = CE.ProviderCaptureIdentity(providerDomain: UUID(), token: UUID())
        let trace = Trace()
        let pair = try Self.admit(trace, previous: .init(url: fixture.root, providerIdentity: identity),
                                  current: .init(url: fixture.root, providerIdentity: identity),
                                  owner: owner, installation: installation)
        XCTAssertEqual(pair.binding.ownerID, ObjectIdentifier(try XCTUnwrap(owner)))
        XCTAssertNoThrow(try pair.binding.validate(currentOwner: weakOwner, currentInstallation: installation))
        Self.stale { try pair.binding.validate(currentOwner: other, currentInstallation: installation) }
        Self.stale { try pair.binding.validate(currentOwner: nil, currentInstallation: installation) }
        owner = nil
        XCTAssertNil(weakOwner)
        Self.stale { try pair.binding.validate(currentOwner: weakOwner, currentInstallation: installation) }
        Self.counts(trace, opens: 1, invocations: 1, returns: 1, admitted: 1)
        let missingOwnerTrace = Trace()
        Self.stale {
            try Self.admit(missingOwnerTrace, previous: .init(url: fixture.root), current: .init(url: fixture.root),
                           owner: nil, installation: installation)
        }
        Self.counts(missingOwnerTrace, opens: 0, invocations: 0, returns: 0, admitted: 0)
    }

    // TC10: validation is value-only and does not start any additional file work.
    func testTC10InstallationBindingRejectsChangedOrMissingInstallation() throws {
        let fixture = try CEBundle(self)
        try fixture.info()
        try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        let owner = OwnerA()
        let installation = UUID()
        let nextInstallation = UUID()
        let identity = CE.ProviderCaptureIdentity(providerDomain: UUID(), token: UUID())
        let trace = Trace()
        let pair = try Self.admit(trace, previous: .init(url: fixture.root, providerIdentity: identity),
                                  current: .init(url: fixture.root, providerIdentity: identity),
                                  owner: owner, installation: installation)
        XCTAssertEqual(pair.binding.installationID, installation)
        XCTAssertNoThrow(try pair.binding.validate(currentOwner: owner, currentInstallation: installation))
        Self.stale { try pair.binding.validate(currentOwner: owner, currentInstallation: nextInstallation) }
        Self.stale { try pair.binding.validate(currentOwner: owner, currentInstallation: nil) }
        Self.counts(trace, opens: 1, invocations: 1, returns: 1, admitted: 1)
        let missingInstallationTrace = Trace()
        Self.stale {
            try Self.admit(missingInstallationTrace, previous: .init(url: fixture.root), current: .init(url: fixture.root),
                           owner: owner, installation: nil)
        }
        Self.counts(missingInstallationTrace, opens: 0, invocations: 0, returns: 0, admitted: 0)
    }

    // TC13: one genuine sink result is built and bound once, and cannot bind a copied inventory with another UUID.
    func testTC13AttachmentConstructionAndInventoryBindingAreExact() throws {
        let fixture = try CEBundle(self)
        try fixture.info()
        try fixture.write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        let owner = OwnerA()
        let trace = Trace()
        let identity = CE.ProviderCaptureIdentity(providerDomain: UUID(), token: UUID())
        let pair = try Self.admit(trace, previous: .init(url: fixture.root, providerIdentity: identity),
                                  current: .init(url: fixture.root, providerIdentity: identity),
                                  owner: owner, installation: UUID())
        Self.counts(trace, opens: 1, invocations: 1, returns: 1, admitted: 1)
        XCTAssertEqual(trace.events.filter { $0 == .attachmentBuilt(.previous) }.count, Int(1))
        XCTAssertEqual(trace.events.filter { $0 == .attachmentBound(.previous) }.count, Int(1))
        XCTAssertEqual(trace.events.filter { $0 == .attachmentBuilt(.current) }.count, Int(0))
        XCTAssertEqual(trace.events.filter { $0 == .attachmentBound(.current) }.count, Int(0))
        let inventory = pair.previous.capture.inventory
        let attachment = pair.previous.attachment
        XCTAssertEqual(attachment.inventoryID, inventory.id)
        XCTAssertEqual(pair.current.attachment.inventoryID, inventory.id)
        XCTAssertEqual(attachment.componentIDs, [Self.mainPath])
        XCTAssertEqual(attachment.failures, [CE.SignatureCaptureFailure]())
        let evidence = try XCTUnwrap(attachment.evidence(for: Self.mainPath))
        XCTAssertEqual(evidence.slices.count, Int(1))
        XCTAssertEqual(evidence.slices.first?.state, CE.SignatureEvidenceState.signatureAbsent)
        let changed = CE.ComponentInventory(id: UUID(), components: inventory.components, scope: inventory.scope)
        XCTAssertThrowsError(try attachment.bind(to: changed)) {
            XCTAssertEqual($0 as? CE.SignatureCaptureError, CE.SignatureCaptureError.invalidEvidence(.keyMismatch))
        }
    }
}
