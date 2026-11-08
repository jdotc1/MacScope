import Foundation
import XCTest
@testable import MacScope

// Pure, test-file-only evaluator of the Ghostty benchmark-proper wrapper acceptance table (AD01-AD12).
// It reads hand-built, Summary-shaped fixtures. Nothing here parses telemetry, exports a seam, or ships.

private typealias WTPhase = NativeDecompilerPhaseRecord.Phase
private typealias WTCounter = NativeDecompilerPhaseRecord.Counter

/// A decision-table outcome. Raw values are the table's literal names.
private enum WTOutcome: String, Equatable {
    case eligible = "ELIGIBLE", notEligible = "NOT_ELIGIBLE"
    case open = "OPEN", openInvalidRecord = "OPEN_INVALID_RECORD", openBranch = "OPEN_BRANCH"
    case pair = "PAIR", notAPair = "NOT_A_PAIR"
    case traceUsable = "TRACE_USABLE", tracePartial = "TRACE_PARTIAL"
    case nativeSuccess = "NATIVE_SUCCESS", branchRefusal = "BRANCH_REFUSAL", branchDeadline = "BRANCH_DEADLINE"
    case branchTransport = "BRANCH_TRANSPORT", branchError = "BRANCH_ERROR", branchFallback = "BRANCH_FALLBACK"
    case coldCaptureMiss = "COLD_CAPTURE_MISS", captureAlreadyWarm = "CAPTURE_ALREADY_WARM"
    case overCapNoRetention = "OVER_CAP_NO_RETENTION"
    case captureReuseObserved = "CAPTURE_REUSE_OBSERVED", noReuseBranch = "NO_REUSE_BRANCH"
    case resultHitObserved = "RESULT_HIT_OBSERVED", resultAlreadyWarm = "RESULT_ALREADY_WARM"
    case resultMissBranch = "RESULT_MISS_BRANCH"
    case canonicalAsExpected = "CANONICAL_AS_EXPECTED", canonicalDeviation = "CANONICAL_DEVIATION"
    case branchNotComplete = "BRANCH_NOT_COMPLETE"
    case residualDominant = "NO_PHASE_SELECTABLE_RESIDUAL_DOMINANT", residualTie = "NO_PHASE_SELECTABLE_RESIDUAL_TIE"
    case residualBelowLargestPhase = "RESIDUAL_BELOW_LARGEST_PHASE"
    case noPositivePhaseSelectable = "NO_POSITIVE_PHASE_SELECTABLE"
    case heldValidationDominant = "HELD_VALIDATION_DOMINANT", noMappedPhaseSelectable = "NO_MAPPED_PHASE_SELECTABLE"
    case noSelection = "NO_SELECTION"
    case proofD1 = "PROOF_CANDIDATE_d1", proofD2 = "PROOF_CANDIDATE_d2", proofD3 = "PROOF_CANDIDATE_d3"
    case proofD4 = "PROOF_CANDIDATE_d4", proofD6 = "PROOF_CANDIDATE_d6", proofD7 = "PROOF_CANDIDATE_d7"
    case replyEqualityHeld = "REPLY_EQUALITY_HELD", replyDiffers = "REPLY_DIFFERS"
    case recordedOnly = "RECORDED_ONLY"
}

/// Explicit read states: observed false is Unobserved even when the stored count is 0.
private enum WTRead: Equatable {
    case present(UInt64), unobserved, missing, invalid
}

private struct WTSummary: Equatable {
    static let schema = "phase-summary-v1"
    var schema = WTSummary.schema
    var counts = [Int64](repeating: 0, count: WTCounter.allCases.count)
    var counterObserved = [Bool](repeating: false, count: WTCounter.allCases.count)
    var completedSpans = [Int64](repeating: 0, count: WTPhase.allCases.count)
    var exclusiveDurations = [Int64](repeating: 0, count: WTPhase.allCases.count)
    var residualNanoseconds: Int64 = 0
    var droppedIntervals: Int64 = 0
    var suppressedSpans: Int64 = 0
    var unfinishedSpans: Int64 = 0
    var overlappingSpans = false
    var attributionComplete = true

    mutating func observe(_ counter: WTCounter, _ value: Int64) {
        counts[counter.rawValue] = value
        counterObserved[counter.rawValue] = true
    }

    var isValid: Bool {
        schema == WTSummary.schema
            && counts.count == WTCounter.allCases.count && counterObserved.count == WTCounter.allCases.count
            && completedSpans.count == WTPhase.allCases.count && exclusiveDurations.count == WTPhase.allCases.count
            && !(counts + completedSpans + exclusiveDurations
                + [residualNanoseconds, droppedIntervals, suppressedSpans, unfinishedSpans]).contains { $0 < 0 }
    }

    func counter(_ counter: WTCounter) -> WTRead {
        guard isValid else { return .invalid }
        return counterObserved[counter.rawValue] ? .present(UInt64(counts[counter.rawValue])) : .unobserved
    }

    func completed(_ phase: WTPhase) -> WTRead {
        guard isValid else { return .invalid }
        return .present(UInt64(completedSpans[phase.rawValue]))
    }
}

private struct WTRequest: Equatable {
    var id = "req-cold"
    var method = "tools/call", tool = "decompile", address = "0x1000", arguments = "{}"
    var image = "image-A", generation = "gen-1", settings = "settings-1"
}

private struct WTReply: Equatable {
    var text: String? = "void f(void) {}"
    var generation: String? = "gen-1"
    var omissions: String? = "none"
    var refusal: String? = nil
    var cursor: String? = nil
    var imageIdentity: String? = "image-A"
    var content: String? = "content-1"
    var cache: String? = "miss"
    /// Decoded result compared under E; the cache disclosure is asserted separately.
    var comparable: WTReply { var copy = self; copy.cache = nil; return copy }
}

private struct WTDisposition {
    var isError: Bool? = false
    var jsonrpcError: String? = nil
    var typedRefusal: [String: String]? = nil
    var backend: String? = "native"
}

private struct WTCall {
    var request: WTRequest? = WTRequest()
    var reply: WTReply? = WTReply()
    var summary: WTSummary? = WTSummary()
    var disposition = WTDisposition()
    var wallMs: Double? = 1.0
}

private struct WTInput {
    var releaseIdentity: String? = "release-1"
    var readyOrdered: Bool? = true
    var traceName: String? = "phase-trace"
    var launchValue: String? = "1"
    var prewarmOff: Bool? = true
    var warmAfterColdReply: Bool? = true
    var interveningOperation: Bool? = false
    var cold: WTCall? = WTCall()
    var warm: WTCall? = WTCall()
    var buildIdentity: String? = "build-1"
    var scope: String? = "ghostty-benchmark-proper"

    /// Synthetic ordinal fixture (not a measurement): cold capture miss and result miss, warm reuse and hit.
    static var base: WTInput {
        var cold = WTCall()
        var coldSummary = WTSummary()
        coldSummary.observe(.captureMisses, 1)
        coldSummary.observe(.resultCacheMisses, 1)
        coldSummary.observe(.canonicalPasses, 2)
        coldSummary.observe(.sliceDigestPasses, 1)
        coldSummary.observe(.xrefRows, 0) // observed zero
        coldSummary.exclusiveDurations[WTPhase.referenceCounts.rawValue] = 50
        coldSummary.exclusiveDurations[WTPhase.validation.rawValue] = 20
        coldSummary.exclusiveDurations[WTPhase.dispatch.rawValue] = 10
        coldSummary.exclusiveDurations[WTPhase.selector.rawValue] = 5
        coldSummary.residualNanoseconds = 10
        for phase in [WTPhase.validation, .dispatch, .replyDecode, .replyValidation, .cacheRetention] {
            coldSummary.completedSpans[phase.rawValue] = 1
        }
        cold.summary = coldSummary
        var warm = WTCall()
        warm.request = WTRequest(id: "req-warm")
        var warmSummary = WTSummary()
        warmSummary.observe(.captureHits, 1)
        warmSummary.observe(.resultCacheHits, 1)
        warmSummary.observe(.canonicalPasses, 2)
        warmSummary.exclusiveDurations[WTPhase.referenceCounts.rawValue] = 7
        warmSummary.residualNanoseconds = 3
        warm.summary = warmSummary
        var warmReply = WTReply()
        warmReply.cache = "hit"
        warm.reply = warmReply
        return WTInput(cold: cold, warm: warm)
    }
}

private struct WTResult: Equatable {
    var ad01 = WTOutcome.open, ad02 = WTOutcome.open, ad03 = WTOutcome.open
    var ad04 = WTOutcome.open, ad05 = WTOutcome.open, ad06 = WTOutcome.open, ad07 = WTOutcome.open
    var ad08 = WTOutcome.noSelection, ad09 = WTOutcome.open, ad10 = WTOutcome.open
    var ad11Cold = WTOutcome.openBranch, ad11Warm = WTOutcome.openBranch
    var ad12 = WTOutcome.open
    /// Full tie set of maximal exclusive phases, lowest rawValue first.
    var tieSet: [String] = []
}

private enum WTEvaluator {
    static let mapping: [WTPhase: WTOutcome] = [
        .referenceCounts: .proofD1,
        .selector: .proofD2, .sizeCheck: .proofD2, .comments: .proofD2,
        .projection: .proofD3, .authoredPreview: .proofD3, .contextAdmission: .proofD3,
        .patchAndCave: .proofD3, .authoredFinal: .proofD3,
        .imageFacets: .proofD4, .segmentAttestation: .proofD4, .sliceAndFingerprint: .proofD4,
        .sliceDigest: .proofD4, .fingerprint: .proofD4,
        .canonicalRequest: .proofD6, .codecAggregate: .proofD6,
        .ownedAdmission: .proofD7, .projectionQueue: .proofD7,
    ]

    static func evaluate(_ input: WTInput) -> WTResult {
        var result = WTResult()
        result.ad01 = eligibility(input)
        result.ad02 = pairing(input)
        let coldTrace = traceStatus(input.cold)
        let warmTrace = traceStatus(input.warm)
        result.ad03 = worst(coldTrace, warmTrace, order: [.openInvalidRecord, .tracePartial, .open, .traceUsable])
        result.ad11Cold = disposition(input.cold)
        result.ad11Warm = disposition(input.warm)
        result.ad04 = coldCapture(input.cold, trace: coldTrace)
        result.ad05 = warmReuse(input.warm, pair: result.ad02, trace: warmTrace)
        result.ad06 = resultBranch(input.cold, input.warm, pair: result.ad02, coldTrace: coldTrace, warmTrace: warmTrace)
        result.ad07 = worst(canonical(input.cold, result.ad11Cold), canonical(input.warm, result.ad11Warm),
            order: [.openInvalidRecord, .canonicalDeviation, .branchNotComplete, .open, .canonicalAsExpected])
        result.ad10 = replyEquality(input)
        let (ad09, tie, winner) = residual(input.cold, trace: coldTrace)
        result.ad09 = ad09
        result.tieSet = tie
        result.ad08 = proof(input, result, winner: winner)
        result.ad12 = recorded(input)
        return result
    }

    static func worst(_ a: WTOutcome, _ b: WTOutcome, order: [WTOutcome]) -> WTOutcome {
        for candidate in order where a == candidate || b == candidate { return candidate }
        return a
    }

    static func eligibility(_ input: WTInput) -> WTOutcome {
        let enabling = input.launchValue.map { ["1", "true", "yes"].contains($0.lowercased()) }
        let facts: [Bool?] = [
            input.releaseIdentity.map { !$0.isEmpty }, input.readyOrdered,
            input.traceName.map { !$0.isEmpty }, enabling, input.prewarmOff,
        ]
        if facts.contains(false) { return .notEligible }
        return facts.contains { $0 == nil } ? .open : .eligible
    }

    static func pairing(_ input: WTInput) -> WTOutcome {
        guard let cold = input.cold?.request, let warm = input.warm?.request else { return .open }
        var known = cold.id == warm.id
        known = known || cold.method != warm.method || cold.tool != warm.tool || cold.address != warm.address
        known = known || cold.arguments != warm.arguments || cold.image != warm.image
        known = known || cold.generation != warm.generation || cold.settings != warm.settings
        known = known || input.warmAfterColdReply == false || input.interveningOperation == true
        if known { return .notAPair }
        return input.warmAfterColdReply == nil || input.interveningOperation == nil ? .open : .pair
    }

    static func traceStatus(_ call: WTCall?) -> WTOutcome {
        guard let summary = call?.summary else { return .open }
        guard summary.isValid else { return .openInvalidRecord }
        let partial = !summary.attributionComplete || summary.droppedIntervals > 0 || summary.suppressedSpans > 0
            || summary.unfinishedSpans > 0 || summary.overlappingSpans
        return partial ? .tracePartial : .traceUsable
    }

    static func disposition(_ call: WTCall?) -> WTOutcome {
        guard let d = call?.disposition, let isError = d.isError else { return .openBranch }
        if let rpc = d.jsonrpcError { return rpc == "timeout" ? .branchTransport : .branchError }
        if isError {
            guard let refusal = d.typedRefusal, !refusal.isEmpty else { return .branchError }
            switch refusal["code"] {
            case "tooLarge": return .branchRefusal
            case "deadline": return .branchDeadline
            default: return .branchError
            }
        }
        switch d.backend {
        case "native": return .nativeSuccess
        case "macir": return .branchFallback
        default: return .openBranch
        }
    }

    static func coldCapture(_ call: WTCall?, trace: WTOutcome) -> WTOutcome {
        guard let call, let summary = call.summary else { return .open }
        guard summary.isValid else { return .openInvalidRecord }
        guard disposition(call) == .nativeSuccess else { return .branchNotComplete }
        let hits = summary.counter(.captureHits), misses = summary.counter(.captureMisses)
        let over = summary.counter(.captureOverCap)
        func one(_ r: WTRead) -> Bool { r == .present(1) }
        if hits != .unobserved, misses != .unobserved { return .openInvalidRecord }
        if hits != .unobserved, over != .unobserved { return .openInvalidRecord }
        if one(hits), misses == .unobserved, over == .unobserved { return .captureAlreadyWarm }
        if one(misses), hits == .unobserved {
            if one(over) { return .overCapNoRetention }
            if over == .unobserved { return .coldCaptureMiss }
        }
        if hits == .unobserved, misses == .unobserved { return .open }
        return .openInvalidRecord
    }

    static func warmReuse(_ call: WTCall?, pair: WTOutcome, trace: WTOutcome) -> WTOutcome {
        guard pair == .pair, trace == .traceUsable, let call, let summary = call.summary else { return .open }
        guard disposition(call) == .nativeSuccess else { return .branchNotComplete }
        let hits = summary.counter(.captureHits), misses = summary.counter(.captureMisses)
        let over = summary.counter(.captureOverCap)
        if misses == .present(1) { return hits == .unobserved ? .noReuseBranch : .openInvalidRecord }
        guard hits == .present(1), misses == .unobserved, over == .unobserved,
              summary.completed(.validation) == .present(0),
              summary.counter(.sliceDigestPasses) == .unobserved else { return .open }
        return .captureReuseObserved
    }

    static func resultBranch(_ cold: WTCall?, _ warm: WTCall?, pair: WTOutcome,
                             coldTrace: WTOutcome, warmTrace: WTOutcome) -> WTOutcome {
        guard pair == .pair, coldTrace == .traceUsable, warmTrace == .traceUsable,
              let c = cold?.summary, let w = warm?.summary else { return .open }
        let coldHit = c.counter(.resultCacheHits), coldMiss = c.counter(.resultCacheMisses)
        let warmHit = w.counter(.resultCacheHits), warmMiss = w.counter(.resultCacheMisses)
        if coldHit != .unobserved, coldMiss != .unobserved { return .openInvalidRecord }
        if warmHit != .unobserved, warmMiss != .unobserved { return .openInvalidRecord }
        if coldHit == .present(1) { return .resultAlreadyWarm }
        if warmMiss == .present(1), warmHit == .unobserved { return coldMiss == .present(1) ? .resultMissBranch : .open }
        guard coldMiss == .present(1), warmHit == .present(1) else { return .open }
        for phase in [WTPhase.dispatch, .replyDecode, .replyValidation, .cacheRetention]
        where w.completed(phase) != .present(0) { return .openInvalidRecord }
        return .resultHitObserved
    }

    static func canonical(_ call: WTCall?, _ disposition: WTOutcome) -> WTOutcome {
        guard let summary = call?.summary else { return .open }
        guard summary.isValid else { return .openInvalidRecord }
        guard disposition == .nativeSuccess else { return .branchNotComplete }
        switch summary.counter(.canonicalPasses) {
        case .present(2): return .canonicalAsExpected
        case .present: return .canonicalDeviation
        default: return .open
        }
    }

    static func replyEquality(_ input: WTInput) -> WTOutcome {
        guard let cold = input.cold?.reply, let warm = input.warm?.reply else { return .open }
        return cold.comparable == warm.comparable ? .replyEqualityHeld : .replyDiffers
    }

    /// AD09: single exclusive entries only, never sums or inclusive parents.
    static func residual(_ call: WTCall?, trace: WTOutcome) -> (WTOutcome, [String], WTPhase?) {
        guard let summary = call?.summary else { return (.open, [], nil) }
        guard summary.isValid else { return (.openInvalidRecord, [], nil) }
        let largest = summary.exclusiveDurations.max() ?? 0
        let residual = summary.residualNanoseconds
        let tied = WTPhase.allCases.filter { largest > 0 && summary.exclusiveDurations[$0.rawValue] == largest }
        let names = tied.map { "\($0)" }
        if largest == 0, residual == 0 { return (.noPositivePhaseSelectable, [], nil) }
        if residual > largest { return (.residualDominant, names, nil) }
        if residual == largest { return (.residualTie, names, nil) }
        // Tie rule: validation held, else any unmapped phase, else the lowest rawValue.
        if tied.contains(.validation) { return (.residualBelowLargestPhase, names, .validation) }
        if let unmapped = tied.first(where: { mapping[$0] == nil }) { return (.residualBelowLargestPhase, names, unmapped) }
        return (.residualBelowLargestPhase, names, tied.min { $0.rawValue < $1.rawValue })
    }

    static func proof(_ input: WTInput, _ r: WTResult, winner: WTPhase?) -> WTOutcome {
        guard r.ad01 == .eligible, r.ad02 == .pair, r.ad10 == .replyEqualityHeld,
              r.ad11Cold == .nativeSuccess, r.ad11Warm == .nativeSuccess,
              r.ad04 == .coldCaptureMiss, r.ad09 == .residualBelowLargestPhase,
              traceStatus(input.cold) == .traceUsable,
              input.cold?.summary?.counter(.resultCacheMisses) == .present(1),
              let winner else { return .noSelection }
        if winner == .validation { return .heldValidationDominant }
        return mapping[winner] ?? .noMappedPhaseSelectable
    }

    /// AD12: values are recorded only; no wall value changes any outcome.
    static func recorded(_ input: WTInput) -> WTOutcome {
        guard input.buildIdentity != nil, input.scope != nil, let cold = input.cold, let warm = input.warm,
              cold.wallMs != nil, warm.wallMs != nil, cold.summary != nil, warm.summary != nil else { return .open }
        return .recordedOnly
    }
}

final class NativeDecompilerWrapperAcceptanceTableTests: XCTestCase {
    private func evaluate(_ edit: (inout WTInput) -> Void = { _ in }) -> WTResult {
        var input = WTInput.base
        edit(&input)
        return WTEvaluator.evaluate(input)
    }

    func testWR03TC15BaseFixtureOutcomes() {
        let r = evaluate()
        XCTAssertEqual(r.ad01, .eligible)
        XCTAssertEqual(r.ad02, .pair)
        XCTAssertEqual(r.ad03, .traceUsable)
        XCTAssertEqual(r.ad04, .coldCaptureMiss)
        XCTAssertEqual(r.ad05, .captureReuseObserved)
        XCTAssertEqual(r.ad06, .resultHitObserved)
        XCTAssertEqual(r.ad07, .canonicalAsExpected)
        XCTAssertEqual(r.ad10, .replyEqualityHeld)
        XCTAssertEqual(r.ad11Cold, .nativeSuccess)
        XCTAssertEqual(r.ad11Warm, .nativeSuccess)
        XCTAssertEqual(r.ad09, .residualBelowLargestPhase)
        XCTAssertEqual(r.ad08, .proofD1)
        XCTAssertEqual(r.ad12, .recordedOnly)
        XCTAssertEqual(r.tieSet, ["referenceCounts"])
    }

    func testWR03TC15EligibilityAndPairing() {
        XCTAssertEqual(evaluate { $0.releaseIdentity = nil }.ad01, .open)
        XCTAssertEqual(evaluate { $0.launchValue = "0" }.ad01, .notEligible)
        XCTAssertEqual(evaluate { $0.readyOrdered = false }.ad01, .notEligible)
        XCTAssertEqual(evaluate { $0.prewarmOff = false }.ad01, .notEligible)
        XCTAssertEqual(evaluate { $0.prewarmOff = nil; $0.launchValue = "0" }.ad01, .notEligible, "known unmet outranks missing")
        XCTAssertEqual(evaluate { $0.cold?.reply = nil }.ad10, .open)
        XCTAssertEqual(evaluate { $0.warm?.request = nil }.ad02, .open)
        XCTAssertEqual(evaluate { $0.warm?.request?.image = "image-B" }.ad02, .notAPair)
        XCTAssertEqual(evaluate { $0.warm?.request?.address = "0x1008" }.ad02, .notAPair)
        XCTAssertEqual(evaluate { $0.warm?.request?.arguments = "{\"x\":1}" }.ad02, .notAPair)
        XCTAssertEqual(evaluate { $0.warm?.request?.generation = "gen-2" }.ad02, .notAPair)
        XCTAssertEqual(evaluate { $0.interveningOperation = true }.ad02, .notAPair)
        XCTAssertEqual(evaluate { $0.warmAfterColdReply = false }.ad02, .notAPair)
    }

    func testWR03TC15TraceUsability() {
        XCTAssertEqual(evaluate { $0.cold?.summary?.droppedIntervals = 1 }.ad03, .tracePartial)
        XCTAssertEqual(evaluate { $0.cold?.summary?.suppressedSpans = 1 }.ad03, .tracePartial)
        XCTAssertEqual(evaluate { $0.cold?.summary?.unfinishedSpans = 1 }.ad03, .tracePartial)
        XCTAssertEqual(evaluate { $0.warm?.summary?.overlappingSpans = true }.ad03, .tracePartial)
        XCTAssertEqual(evaluate { $0.warm?.summary?.attributionComplete = false }.ad03, .tracePartial)
        XCTAssertEqual(evaluate { $0.cold?.summary = nil }.ad03, .open)
        XCTAssertEqual(evaluate { $0.cold?.summary?.counts.removeLast() }.ad03, .openInvalidRecord)
        XCTAssertEqual(evaluate { $0.cold?.summary?.schema = "other" }.ad03, .openInvalidRecord)
        XCTAssertEqual(evaluate { $0.warm?.summary?.counts[0] = -1 }.ad03, .openInvalidRecord)
        // Observed false with a stored 0 is Unobserved; observed true with 0 is Present(0).
        var summary = WTSummary()
        summary.counts[WTCounter.captureHits.rawValue] = 0
        XCTAssertEqual(summary.counter(.captureHits), .unobserved)
        summary.counterObserved[WTCounter.captureHits.rawValue] = true
        XCTAssertEqual(summary.counter(.captureHits), .present(0))
    }

    func testWR03TC15CaptureResultAndCanonicalRows() {
        XCTAssertEqual(evaluate { $0.cold?.summary?.observe(.captureHits, 1)
            $0.cold?.summary?.counterObserved[WTCounter.captureMisses.rawValue] = false }.ad04, .captureAlreadyWarm)
        XCTAssertEqual(evaluate { $0.cold?.summary?.observe(.captureOverCap, 1) }.ad04, .overCapNoRetention)
        XCTAssertEqual(evaluate { $0.cold?.summary?.observe(.captureHits, 1) }.ad04, .openInvalidRecord)
        XCTAssertEqual(evaluate { $0.warm?.summary?.observe(.captureHits, 0) }.ad05, .open, "an observed hit count of 0 is not a reuse")
        XCTAssertEqual(evaluate { $0.warm?.summary?.observe(.sliceDigestPasses, 0) }.ad05, .open,
                       "an observed digest of 0 does not satisfy AD05")
        XCTAssertEqual(evaluate { $0.warm?.summary?.observe(.captureMisses, 1)
            $0.warm?.summary?.counterObserved[WTCounter.captureHits.rawValue] = false }.ad05, .noReuseBranch)
        XCTAssertEqual(evaluate { $0.cold?.summary?.observe(.resultCacheHits, 1)
            $0.cold?.summary?.counterObserved[WTCounter.resultCacheMisses.rawValue] = false }.ad06, .resultAlreadyWarm)
        XCTAssertEqual(evaluate { $0.warm?.summary?.observe(.resultCacheMisses, 1)
            $0.warm?.summary?.counterObserved[WTCounter.resultCacheHits.rawValue] = false }.ad06, .resultMissBranch)
        XCTAssertEqual(evaluate { $0.warm?.summary?.observe(.resultCacheMisses, 1) }.ad06, .openInvalidRecord)
        XCTAssertEqual(evaluate {
            $0.cold?.summary?.counterObserved[WTCounter.resultCacheMisses.rawValue] = false
            $0.warm?.summary?.counterObserved[WTCounter.resultCacheHits.rawValue] = false }.ad06, .open)
        XCTAssertEqual(evaluate { $0.cold?.summary?.observe(.canonicalPasses, 1) }.ad07, .canonicalDeviation)
        XCTAssertEqual(evaluate {
            $0.cold?.summary?.observe(.canonicalPasses, 1)
            $0.cold?.disposition = WTDisposition(isError: true, typedRefusal: ["code": "tooLarge"], backend: nil)
        }.ad07, .branchNotComplete)
        XCTAssertEqual(evaluate { $0.warm?.summary?.counterObserved[WTCounter.canonicalPasses.rawValue] = false }.ad07, .open)
    }

    func testWR03TC15ResidualAndMappingRules() {
        func table(_ exclusive: [WTPhase: Int64], residual: Int64) -> WTResult {
            evaluate {
                $0.cold?.summary?.exclusiveDurations = [Int64](repeating: 0, count: WTPhase.allCases.count)
                for (phase, value) in exclusive { $0.cold?.summary?.exclusiveDurations[phase.rawValue] = value }
                $0.cold?.summary?.residualNanoseconds = residual
            }
        }
        XCTAssertEqual(table([.referenceCounts: 3], residual: 4).ad09, .residualDominant)
        XCTAssertEqual(table([.referenceCounts: 3], residual: 3).ad09, .residualTie)
        XCTAssertEqual(table([.referenceCounts: 3], residual: 2).ad09, .residualBelowLargestPhase)
        XCTAssertEqual(table([:], residual: 0).ad09, .noPositivePhaseSelectable)
        XCTAssertEqual(table([:], residual: 0).ad08, .noSelection)
        // Tie of referenceCounts and selector at 3 with residual 1: lowest rawValue (selector) wins, tie set reported.
        let tied = table([.referenceCounts: 3, .selector: 3], residual: 1)
        XCTAssertEqual(tied.ad08, .proofD2)
        XCTAssertEqual(tied.tieSet, ["selector", "referenceCounts"])
        XCTAssertEqual(table([.validation: 3], residual: 1).ad08, .heldValidationDominant)
        XCTAssertEqual(table([.validation: 3, .referenceCounts: 3], residual: 1).ad08, .heldValidationDominant)
        XCTAssertEqual(table([.dispatch: 3], residual: 1).ad08, .noMappedPhaseSelectable)
        XCTAssertEqual(table([.dispatch: 3, .referenceCounts: 3], residual: 1).ad08, .noMappedPhaseSelectable)
        let candidates: [(WTPhase, WTOutcome)] = [
            (.referenceCounts, .proofD1), (.selector, .proofD2), (.sizeCheck, .proofD2), (.comments, .proofD2),
            (.projection, .proofD3), (.authoredPreview, .proofD3), (.contextAdmission, .proofD3),
            (.patchAndCave, .proofD3), (.authoredFinal, .proofD3),
            (.imageFacets, .proofD4), (.segmentAttestation, .proofD4), (.sliceAndFingerprint, .proofD4),
            (.sliceDigest, .proofD4), (.fingerprint, .proofD4),
            (.canonicalRequest, .proofD6), (.codecAggregate, .proofD6),
            (.ownedAdmission, .proofD7), (.projectionQueue, .proofD7),
        ]
        for (phase, outcome) in candidates {
            XCTAssertEqual(table([phase: 9, .snapshotRead: 2], residual: 1).ad08, outcome, "\(phase)")
        }
        // Any veto means no selection and no runner-up substitution.
        XCTAssertEqual(evaluate { $0.cold?.summary?.observe(.captureOverCap, 1) }.ad08, .noSelection)
        XCTAssertEqual(evaluate { $0.launchValue = "0" }.ad08, .noSelection)
        XCTAssertEqual(evaluate { $0.warm?.request?.image = "image-B" }.ad08, .noSelection)
        XCTAssertEqual(evaluate { $0.warm?.reply?.text = "different" }.ad08, .noSelection)
    }

    func testWR03TC15ReplyEqualityDispositionAndRecordedOnly() {
        XCTAssertEqual(evaluate { $0.warm?.reply?.generation = nil }.ad10, .replyDiffers, "deleted generation with cache present")
        XCTAssertEqual(evaluate { $0.warm?.reply?.omissions = "dropped" }.ad10, .replyDiffers)
        XCTAssertEqual(evaluate { $0.warm?.reply?.refusal = "tooLarge" }.ad10, .replyDiffers)
        XCTAssertEqual(evaluate { $0.warm?.reply?.cursor = "next" }.ad10, .replyDiffers)
        XCTAssertEqual(evaluate { $0.warm?.reply?.imageIdentity = "image-B" }.ad10, .replyDiffers)
        XCTAssertEqual(evaluate { $0.warm?.reply?.content = "other" }.ad10, .replyDiffers)
        XCTAssertEqual(evaluate { $0.warm?.reply?.cache = "miss" }.ad10, .replyEqualityHeld, "cache disclosure is asserted separately")
        func disposition(_ edit: (inout WTDisposition) -> Void) -> WTOutcome {
            evaluate { edit(&$0.cold!.disposition) }.ad11Cold
        }
        XCTAssertEqual(disposition { $0 = WTDisposition(isError: true, typedRefusal: ["code": "tooLarge"], backend: nil) }, .branchRefusal)
        XCTAssertEqual(disposition { $0 = WTDisposition(isError: true, typedRefusal: ["code": "deadline"], backend: nil) }, .branchDeadline)
        XCTAssertEqual(disposition { $0 = WTDisposition(isError: true, jsonrpcError: "timeout", backend: nil) }, .branchTransport)
        XCTAssertEqual(disposition { $0 = WTDisposition(isError: true, jsonrpcError: "internal", backend: nil) }, .branchError)
        XCTAssertEqual(disposition { $0 = WTDisposition(isError: true, typedRefusal: [:], backend: nil) }, .branchError,
                       "an empty typedRefusal object is not a refusal")
        XCTAssertEqual(disposition { $0.backend = "macir" }, .branchFallback)
        XCTAssertEqual(disposition { $0.backend = nil }, .openBranch)
        XCTAssertEqual(disposition { $0.isError = nil }, .openBranch)
        XCTAssertEqual(evaluate { $0.cold?.disposition.backend = "macir" }.ad08, .noSelection, "a failure on either call vetoes proof")
        // AD12 is recorded only: wall values below, equal to and above the roadmap number change nothing.
        let outcomes = [0.5, 2_000.0, 5_000.0].map { wall in evaluate { $0.cold?.wallMs = wall; $0.warm?.wallMs = wall } }
        XCTAssertEqual(outcomes[0], outcomes[1])
        XCTAssertEqual(outcomes[1], outcomes[2])
        XCTAssertEqual(outcomes[0].ad12, .recordedOnly)
        XCTAssertEqual(evaluate { $0.buildIdentity = nil }.ad12, .open)
        XCTAssertEqual(evaluate { $0.cold?.wallMs = nil }.ad12, .open)
    }

    /// TC16 bridge: the literal pair observations of the capture rehearsal fed to the evaluator.
    /// P-cold and P-reuse come from the capture test class; the result branch is asserted literally (OQ5).
    func testWR03TC16PairObservationsFeedTheEvaluator() {
        let hit = evaluate()
        XCTAssertEqual(hit.ad04, .coldCaptureMiss)
        XCTAssertEqual(hit.ad05, .captureReuseObserved)
        XCTAssertEqual(hit.ad06, .resultHitObserved)
        XCTAssertEqual(hit.ad07, .canonicalAsExpected)
        // The miss branch is its own branch, never a double-hit pass.
        let miss = evaluate {
            $0.warm?.summary?.counterObserved[WTCounter.resultCacheHits.rawValue] = false
            $0.warm?.summary?.observe(.resultCacheMisses, 1)
            $0.warm?.reply?.cache = "miss"
        }
        XCTAssertEqual(miss.ad04, .coldCaptureMiss)
        XCTAssertEqual(miss.ad05, .captureReuseObserved)
        XCTAssertEqual(miss.ad06, .resultMissBranch)
        XCTAssertNotEqual(miss.ad06, .resultHitObserved)
        XCTAssertEqual(miss.ad07, .canonicalAsExpected)
    }
}
