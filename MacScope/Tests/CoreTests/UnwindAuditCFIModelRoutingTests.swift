import Foundation
import XCTest
@testable import MacScope

private actor SuspendedCFIModelAudit {
    enum HarnessError: Error, Equatable, Sendable {
        case startTimedOut, closed, duplicateEntry
    }

    private var result: CheckedContinuation<UnwindAuditReport, any Error>?
    private var didStart = false
    private(set) var isClosed = false

    func run() async throws -> UnwindAuditReport {
        guard !isClosed else { throw HarnessError.closed }
        guard !didStart else { throw HarnessError.duplicateEntry }
        didStart = true
        // Deliberately ignore task cancellation so the tests exercise the
        // publication fence. Every exit path must finish or close this gate.
        return try await withCheckedThrowingContinuation { continuation in
            result = continuation
        }
    }

    func waitUntilStarted(timeout: Duration = .seconds(5)) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        do {
            while !didStart {
                try Task.checkCancellation()
                guard !isClosed else { throw HarnessError.closed }
                guard clock.now < deadline else { throw HarnessError.startTimedOut }
                try await clock.sleep(until: min(deadline, clock.now.advanced(by: .milliseconds(10))))
            }
        } catch {
            close()
            throw error
        }
    }

    func finish(_ report: UnwindAuditReport) {
        guard !isClosed else { return }
        isClosed = true
        let pending = result
        result = nil
        pending?.resume(returning: report)
    }

    func close() {
        isClosed = true
        let pending = result
        result = nil
        pending?.resume(throwing: HarnessError.closed)
    }
}

@MainActor
final class UnwindAuditCFIModelRoutingTests: XCTestCase {
    private func input(modelID: String = UnwindAuditModel.boundedCFIControls.rawValue)
        throws -> (LoadedBinary, UnwindAuditResultKey) {
        let identity = try MachOSliceArtifactIdentity(uuid: nil, rawCPUType: 0x0100000c,
            rawCPUSubtype: 0, selectedSliceSHA256: String(repeating: "a", count: 64),
            selectedSliceByteCount: 64)
        let key = UnwindAuditResultKey(imageID: UUID(), slot: .primary, generation: UUID(),
            identity: identity, modelID: modelID, configuration: .init())
        let binary = LoadedBinary(name: "authored", path: "", isBundle: false,
            cpuType: 0x0100000c, cpuSubtype: 0, fileTypeName: "Mach-O",
            architectureDisplayName: "arm64", metadata: .empty,
            artifactIdentity: identity, artifactIntegrityState: .verified,
            bytes: Data(repeating: 0, count: 64), sliceOffset: 0, sections: [],
            executableTextSection: nil, entryPointAddress: nil, symbols: [], imports: [],
            indirectSymbols: [], exports: [], stringLiterals: [], functionStarts: [], objcSelectors: [:])
        return (binary, key)
    }

    private func report(_ key: UnwindAuditResultKey) -> UnwindAuditReport {
        .init(identity: key.identity, analysisModelVersion: key.modelID,
              configuration: key.configuration, findings: [])
    }

    func testSuspendedRunnerStartWaitTimesOutAndClosesGate() async {
        let suspended = SuspendedCFIModelAudit()
        do {
            try await suspended.waitUntilStarted(timeout: .milliseconds(20))
            XCTFail("A runner that never enters must fail its readiness deadline")
        } catch {
            XCTAssertEqual(error as? SuspendedCFIModelAudit.HarnessError, .startTimedOut)
        }
        let isClosed = await suspended.isClosed
        XCTAssertTrue(isClosed)
        await suspended.close()
    }

    func testSuspendedRunnerClosedBeforeEntryRefusesWithoutSuspending() async {
        let suspended = SuspendedCFIModelAudit()
        await suspended.close()
        do {
            _ = try await suspended.run()
            XCTFail("A closed gate must refuse a runner that enters later")
        } catch {
            XCTAssertEqual(error as? SuspendedCFIModelAudit.HarnessError, .closed)
        }
        await suspended.close()
    }

    func testInteractiveModelsDoNotExposeOtherServiceModels() throws {
        XCTAssertEqual(UnwindAuditResultKey.currentModelID, UnwindAuditModel.boundedLoops.rawValue)
        for model in [UnwindAuditModel.boundedLoops, .boundedCFIControls] {
            let (_, key) = try input(modelID: model.rawValue)
            XCTAssertEqual(key.model, model)
        }
        for modelID in [UnwindAuditModel.boundedLoopCalls.rawValue,
                        UnwindAuditModel.boundedLoopCallsMOVK.rawValue, "unknown-model"] {
            let (_, key) = try input(modelID: modelID)
            XCTAssertNil(key.model)
        }
        XCTAssertFalse(UnwindAuditModel.boundedCFIControls.permitsLoopCalls)
        XCTAssertFalse(UnwindAuditModel.boundedCFIControls.permitsMOVK)
        XCTAssertTrue(UnwindAuditModel.boundedCFIControls.permitsCFIControls)
    }

    func testCapturedModelReachesRunnerAndAcceptedPublication() async throws {
        let (binary, key) = try input()
        let expected = report(key)
        let coordinator = UnwindAuditCoordinator(modelRunner: { received, limits, model in
            XCTAssertEqual(received.artifactIdentity, key.identity)
            XCTAssertEqual(limits, key.configuration)
            XCTAssertEqual(model, .boundedCFIControls)
            return expected
        })
        var publication: UnwindAuditRequest?
        coordinator.onAcceptedPublication = { _, request in publication = request }
        let task = try XCTUnwrap(coordinator.start(binary: binary, key: key))
        await task.value
        XCTAssertEqual(coordinator.state.phase, .completed)
        XCTAssertEqual(coordinator.state.report, expected)
        XCTAssertEqual(publication?.key, key)
    }

    func testLegacyRunnerCannotSilentlyRunExtendedModel() async throws {
        let (binary, key) = try input()
        let coordinator = UnwindAuditCoordinator(runner: { _, _ in
            XCTFail("A legacy runner must not execute a model it cannot receive")
            throw UnwindAuditReportError.invalidModel
        })
        let task = try XCTUnwrap(coordinator.start(binary: binary, key: key))
        await task.value
        guard case .failed = coordinator.state.phase else { return XCTFail("Expected explicit refusal") }
        XCTAssertNil(coordinator.state.report)
    }

    func testUnknownModelRefusesBeforeLoadingRetainedInput() async throws {
        let (_, key) = try input(modelID: "unknown-model")
        let coordinator = UnwindAuditCoordinator(modelRunner: { _, _, _ in
            XCTFail("Unsupported model entered the runner")
            throw UnwindAuditReportError.invalidModel
        })
        let task = coordinator.start(key: key) {
            XCTFail("Unsupported model entered the loader")
            throw UnwindAuditReportError.invalidModel
        }
        await task.value
        guard case .failed = coordinator.state.phase else { return XCTFail("Expected unsupported-model refusal") }
        XCTAssertNil(coordinator.state.report)
    }

    func testStandardResultCannotSatisfyExtendedRequest() async throws {
        let (binary, key) = try input()
        let coordinator = UnwindAuditCoordinator(modelRunner: { _, _, _ in
            .init(identity: key.identity, findings: [])
        })
        coordinator.onAcceptedPublication = { _, _ in XCTFail("Wrong model retained as accepted evidence") }
        let task = try XCTUnwrap(coordinator.start(binary: binary, key: key))
        await task.value
        guard case .failed = coordinator.state.phase else { return XCTFail("Expected model mismatch") }
        XCTAssertNil(coordinator.state.report)
        XCTAssertEqual(coordinator.state.discardedPublicationCount, 1)
    }

    func testChangingOnlyModelRejectsUncooperativeLateCompletion() async throws {
        let (binary, extended) = try input()
        let standard = UnwindAuditResultKey(imageID: extended.imageID, slot: extended.slot,
            generation: extended.generation, identity: extended.identity,
            modelID: UnwindAuditResultKey.currentModelID, configuration: extended.configuration)
        let suspended = SuspendedCFIModelAudit()
        let coordinator = UnwindAuditCoordinator(modelRunner: { _, _, _ in try await suspended.run() })
        coordinator.onAcceptedPublication = { _, _ in XCTFail("Retired model published") }
        do {
            let task = try XCTUnwrap(coordinator.start(binary: binary, key: extended))
            try await suspended.waitUntilStarted()
            coordinator.activate(standard)
            await suspended.finish(report(extended))
            await task.value
            XCTAssertEqual(coordinator.state.key, standard)
            XCTAssertEqual(coordinator.state.phase, .idle)
            XCTAssertNil(coordinator.state.report)
            XCTAssertEqual(coordinator.state.discardedPublicationCount, 1)
        } catch {
            coordinator.cancel()
            await suspended.close()
            throw error
        }
        await suspended.close()
    }

    func testCancellingExtendedAuditRejectsLateCompletion() async throws {
        let (binary, key) = try input()
        let suspended = SuspendedCFIModelAudit()
        let coordinator = UnwindAuditCoordinator(modelRunner: { _, _, _ in try await suspended.run() })
        do {
            let task = try XCTUnwrap(coordinator.start(binary: binary, key: key))
            try await suspended.waitUntilStarted()
            coordinator.cancel()
            await suspended.finish(report(key))
            await task.value
            XCTAssertEqual(coordinator.state.phase, .cancelled)
            XCTAssertNil(coordinator.state.report)
            XCTAssertEqual(coordinator.state.discardedPublicationCount, 1)
        } catch {
            coordinator.cancel()
            await suspended.close()
            throw error
        }
        await suspended.close()
    }

    func testExtendedReportRoundTripRetainsModelAndLimits() throws {
        let (_, key) = try input()
        let original = report(key)
        let decoded = try JSONDecoder().decode(UnwindAuditReport.self,
            from: JSONEncoder().encode(original))
        XCTAssertEqual(decoded, original)
        XCTAssertEqual(decoded.analysisModelVersion, "arm64-bounded-cfi-controls-v4")
        XCTAssertEqual(decoded.schemaVersion, 1)
    }

    func testComparisonDoesNotTreatChangedModelAsRecoveryChange() throws {
        let (_, key) = try input()
        let finding = UnwindAuditFinding(identity: key.identity,
            function: .init(id: "owned", address: 0x1000, symbolName: "_owned", size: 4),
            endAddress: 0x1004, verdict: "unresolved", coverage: "dwarf_reference",
            mode: "dwarf", scope: "metadata_only")
        let before = UnwindAuditReport(identity: key.identity, findings: [finding])
        var after = before
        after.analysisModelVersion = UnwindAuditModel.boundedCFIControls.rawValue
        let comparison = try UnwindAuditComparator.compare(baseline: before, current: after)
        XCTAssertFalse(comparison.modelCompatible)
        XCTAssertEqual(comparison.changes.map(\.change), [.incompatible])
    }
}
