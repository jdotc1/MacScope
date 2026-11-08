import Combine
import Foundation
import XCTest
@testable import MacScope

/// Authored fixtures for the AR0 coordinator reads. Every value is written by hand; no digest is computed,
/// no binary is loaded, no AIRS output is consulted.
enum AIRSReadFixtures {
    static let identityHex = String(repeating: "a", count: 64)

    static func identity() throws -> MachOSliceArtifactIdentity {
        try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: 0x0100000c, rawCPUSubtype: 0,
                                       selectedSliceSHA256: identityHex, selectedSliceByteCount: 64)
    }

    static func finding(_ identity: MachOSliceArtifactIdentity, id: String, start: UInt64, end: UInt64,
                        verdict: String = "agreement", reasons: [String] = []) -> UnwindAuditFinding {
        UnwindAuditFinding(
            identity: identity,
            function: FunctionVersionFingerprint(id: id, address: start, symbolName: nil, size: end - start),
            endAddress: end, verdict: verdict, coverage: "full", mode: "bounded", scope: "function",
            reasonCodes: reasons, checkedPCs: [start])
    }

    static func report(_ identity: MachOSliceArtifactIdentity, _ findings: [UnwindAuditFinding],
                       model: UnwindAuditModel = .boundedLoops) -> UnwindAuditReport {
        UnwindAuditReport(identity: identity, analysisModelVersion: model.rawValue, findings: findings)
    }

    /// The three authored rows of SPEC 10: agreement, inconsistency, unresolved.
    static func threeFindings(_ identity: MachOSliceArtifactIdentity) -> [UnwindAuditFinding] {
        [finding(identity, id: "f1", start: 0x1000, end: 0x1010, verdict: "agreement"),
         finding(identity, id: "f2", start: 0x2000, end: 0x2010, verdict: "inconsistency", reasons: ["cfa_mismatch"]),
         finding(identity, id: "f3", start: 0x3000, end: 0x3010, verdict: "unresolved", reasons: ["unsupported"])]
    }

    static func context(command: String = AIRSMCPReads.unwindCommand, model: AIRSReadModel = .v1,
                        function: UInt64? = nil, entryID: UUID = UUID(), epochs: AIRSEpochs? = nil) -> AIRSReadContext {
        AIRSReadContext(
            command: command, model: model, modelID: model.modelID(for: command), imageSlot: 0, imageOwnerID: UUID(),
            installationID: UUID(), generation: UUID(), entryID: entryID,
            epochs: epochs ?? AIRSEpochs(focus: UUID(), source: UUID(), reportState: UUID()), function: function)
    }

    static func builtReport(_ result: AIRSBuildResult, file: StaticString = #filePath, line: UInt = #line) -> AIRSReadReport? {
        guard case .report(let report) = result else { XCTFail("expected a report", file: file, line: line); return nil }
        return report
    }

    /// A report whose rows are opaque authored objects, for byte-budget tests.
    static func syntheticReport(rows: [ScriptValue], context c: AIRSReadContext) -> AIRSReadReport {
        AIRSReadReport(
            id: UUID(), command: c.command, model: c.model, modelID: c.modelID, imageSlot: c.imageSlot,
            imageOwnerID: c.imageOwnerID, installationID: c.installationID, generation: c.generation,
            entryID: c.entryID, focusEpoch: c.epochs.focus, reportStateEpoch: c.epochs.reportState,
            filterToken: c.filterToken, rows: rows, header: ["source": .string("authored")],
            denominators: .init(fields: ["authored": .bool(true)]), sourceComplete: true)
    }

    static func cursorFactory(_ report: AIRSReadReport) -> (Int) -> String? {
        { next in
            AIRSReadCursor(command: report.command, entryID: report.entryID, reportID: report.id,
                           imageSlot: report.imageSlot, imageOwnerID: report.imageOwnerID,
                           installationID: report.installationID, generation: report.generation,
                           focusEpoch: report.focusEpoch, reportStateEpoch: report.reportStateEpoch,
                           modelID: report.modelID, filterToken: report.filterToken, offset: next).encoded()
        }
    }

    static func capturedInput(byteCount: Int = 64) throws -> AIRSCapturedInput {
        let layout = try MachOPreferredSegmentLayout(records: [
            .init(name: "__TEXT", preferredVMStart: 0x1000, preferredVMSize: 0x40,
                  sliceRelativeFileOffset: 0, fileSize: 0x40, initialProtections: 5)
        ], selectedSliceByteCount: 64)
        return AIRSCapturedInput(imageID: UUID(), bytes: Data(count: byteCount), sourceURL: URL(fileURLWithPath: "/authored"),
                                 identity: try identity(), layout: layout, integrity: .verified)
    }

    // MARK: Swift request windows (authored words, copied in shape from the existing Swift tests)

    static func swiftRequest(window: [UInt32]) -> SwiftErrorFlowRequest {
        var words: [UInt32] = [0x94000020] + window
        words += Array(repeating: 0xd65f03c0, count: 33 - words.count)
        return .init(
            slice: .init(artifactSHA256: identityHex, sliceOffset: 0, sliceByteCount: 4096, cpuType: 0x0100000c,
                         cpuSubtype: 0, littleEndian: true),
            code: .init(baseAddress: 0x1000, sliceRelativeFileOffset: 256, sectionOrdinal: 1, hasEmbeddedData: false,
                        hasRelocations: false, words: words),
            functions: [.init(start: 0x1000, endExclusive: 0x1080, boundarySource: "lc_function_starts"),
                        .init(start: 0x1080, endExclusive: 0x1084, boundarySource: "lc_function_starts")],
            symbols: [.init(address: 0x1080, name: "_$s4Demo5parseyS2iKF", nType: 0x0f, nDesc: 0, sectionOrdinal: 1)])
    }

    static func regionRequest(callerWords: Int = 32) -> SwiftErrorFlowRequest {
        let window: [UInt32] = [0xb4000095, 0xaa1503e0, 0xd503201f, 0x92800000]
        var words = [UInt32(0x94000000) | UInt32(callerWords)] + window
        words += Array(repeating: UInt32(0xd65f03c0), count: callerWords + 1 - words.count)
        let base: UInt64 = 0x1000
        let callee = base + UInt64(callerWords) * 4
        return .init(
            slice: .init(artifactSHA256: identityHex, sliceOffset: 0, sliceByteCount: 1_048_576, cpuType: 0x0100000c,
                         cpuSubtype: 0, littleEndian: true),
            code: .init(baseAddress: base, sliceRelativeFileOffset: 256, sectionOrdinal: 1, hasEmbeddedData: false,
                        hasRelocations: false, words: words),
            functions: [.init(start: base, endExclusive: callee, boundarySource: "lc_function_starts"),
                        .init(start: callee, endExclusive: callee + 4, boundarySource: "lc_function_starts")],
            symbols: [.init(address: callee, name: "_$s4Demo5parseyS2iKF", nType: 0x0f, nDesc: 0, sectionOrdinal: 1)])
    }

    /// 257 separate one-edge callers (mirrors the existing region cap test shape).
    static func region257Request() -> SwiftErrorFlowRequest {
        var input = regionRequest()
        let callerCount = 257, calleeIndex = callerCount * 4
        input.code.words = []
        input.functions = []
        for index in 0..<callerCount {
            let start = UInt64(0x1000 + index * 16)
            input.functions.append(.init(start: start, endExclusive: start + 16, boundarySource: "lc_function_starts"))
            input.code.words += [0x94000000 | UInt32(calleeIndex - index * 4), 0xb5000055, 0xd503201f, 0xd65f03c0]
        }
        let callee = UInt64(0x1000 + calleeIndex * 4)
        input.code.words.append(0xd65f03c0)
        input.functions.append(.init(start: callee, endExclusive: callee + 4, boundarySource: "lc_function_starts"))
        input.symbols[0].address = callee
        return input
    }

    /// One caller 0x1000..<0x2010 holding 257 four-word groups that all call the same throwing callee.
    static func singleCaller257Request() -> SwiftErrorFlowRequest {
        var input = regionRequest()
        let groups = 257
        input.code.words = []
        let callerEnd = UInt64(0x1000 + groups * 16)
        let calleeIndex = groups * 4
        for index in 0..<groups {
            input.code.words += [0x94000000 | UInt32(calleeIndex - index * 4), 0xb5000055, 0xd503201f, 0xd65f03c0]
        }
        input.code.words.append(0xd65f03c0)
        input.functions = [.init(start: 0x1000, endExclusive: callerEnd, boundarySource: "lc_function_starts"),
                           .init(start: callerEnd, endExclusive: callerEnd + 4, boundarySource: "lc_function_starts")]
        input.symbols[0].address = callerEnd
        return input
    }

    static func rawEdges(_ request: SwiftErrorFlowRequest, model: AIRSReadModel = .v1, census: AIRSCensus? = nil) -> AIRSSwiftRawResult {
        let report: SwiftErrorFlowReport
        let modelID: String
        switch model {
        case .registerCopiesV2:
            report = SwiftErrorFlowAnalyzer.analyze(request, model: .registerCopiesV2)
            modelID = SwiftErrorFlowModel.registerCopiesV2.rawValue
        default:
            report = SwiftErrorFlowAnalyzer.analyze(request, model: .nativeV1)
            modelID = SwiftErrorFlowModel.nativeV1.rawValue
        }
        return AIRSSwiftRawResult(census: census, outcome: .edges(report), admittedIntervals: request.functions,
                                  model: model, modelID: modelID)
    }

    static func rawRegions(_ request: SwiftErrorFlowRequest, census: AIRSCensus? = nil) -> AIRSSwiftRawResult {
        AIRSSwiftRawResult(census: census, outcome: .regions(SwiftErrorRegionAnalyzer.analyze(request)),
                           admittedIntervals: request.functions, model: .regionsV1,
                           modelID: "macscope-swift-error-region-native-v1")
    }

    static func census(starts: [UInt64], raw: Int? = nil, complete: Bool? = true) -> AIRSCensus {
        AIRSCensus(rawFunctionStartCount: raw ?? starts.count, uniqueStarts: starts,
                   parseOutcome: complete == true ? "terminated" : "unknown", isComplete: complete)
    }
}

/// A controllable stand-in for one live workspace. It is only ever read by the AR0 gates.
@MainActor
final class AIRSFakeWorld {
    var focused = ImageSlot.primary
    var installationID = UUID()
    var generation = UUID()
    var ownerID = UUID()
    var state = UnwindAuditResultState()
    var captureCalls = 0
    var input: AIRSCapturedInput?
    let focusSubject = PassthroughSubject<Void, Never>()
    let identity: MachOSliceArtifactIdentity

    init() throws { identity = try AIRSReadFixtures.identity() }

    func key(model: UnwindAuditModel = .boundedLoops) -> UnwindAuditResultKey {
        UnwindAuditResultKey(imageID: ownerID, slot: .primary, generation: generation, identity: identity,
                             modelID: model.rawValue, configuration: .init())
    }

    func complete(_ report: UnwindAuditReport, model: UnwindAuditModel = .boundedLoops) {
        let request = state.begin(key(model: model))
        state.publish(report, for: request)
    }

    func begin(model: UnwindAuditModel = .boundedLoops) { _ = state.begin(key(model: model)) }

    func source() -> AIRSReadSource {
        AIRSReadSource(
            owner: self,
            focusedSlot: { [unowned self] in focused },
            installationID: { [unowned self] in installationID },
            analysisGeneration: { [unowned self] in generation },
            imageOwnerID: { [unowned self] _ in ownerID },
            unwindKey: { [unowned self] _, model in key(model: model) },
            unwindState: { [unowned self] in state },
            swiftKey: { [unowned self] slot in
                SwiftErrorFlowSourceKey(imageID: ownerID, slot: slot, generation: generation,
                                        documentInstallationID: installationID, identity: identity)
            },
            capture: { [unowned self] _ in captureCalls += 1; return input },
            subscribe: { [unowned self] entry in
                [focusSubject.sink { [weak entry] in entry?.noteFocusChange() }]
            })
    }

    func moveFocus(_ slot: ImageSlot) {
        focused = slot
        focusSubject.send()
    }

    static func resolve(_ value: ScriptValue) -> ImageSlot? {
        switch value { case .int(0): return .primary; case .int(1): return ImageSlot(rawValue: 1); default: return nil }
    }
}
