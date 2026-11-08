import Foundation

/// Bounds the coordinator even if an injected provider never completes.
/// Crucial: the *production* XPC session must separately cancel/invalidate
/// that worker. Detached losing work is not treated as successfully cancelled.
enum NEWFEATURESDeadlineResult: Sendable {
    case completed(NEWFEATURESDecompileResponse)
    case timedOut
    case cancelled
}

private actor FirstResult {
    private var value: NEWFEATURESDeadlineResult?
    private var continuation: CheckedContinuation<NEWFEATURESDeadlineResult, Never>?

    func publish(_ newValue: NEWFEATURESDeadlineResult) {
        guard value == nil else { return }
        value = newValue
        if let continuation {
            self.continuation = nil
            continuation.resume(returning: newValue)
        }
    }

    func wait() async -> NEWFEATURESDeadlineResult {
        if let value { return value }
        return await withCheckedContinuation { continuation in
            self.continuation = continuation
        }
    }
}

enum NEWFEATURESDeadlineRace {
    static func run(
        request: NEWFEATURESDecompileRequest,
        provider: any NEWFEATURESNativeDecompiling
    ) async -> NEWFEATURESDeadlineResult {
        let gate = FirstResult()
        let work = Task.detached {
            let result = await provider.decompile(request)
            await gate.publish(.completed(result))
        }
        let timer = Task.detached {
            do {
                try await ContinuousClock().sleep(until: request.deadline)
                await gate.publish(.timedOut)
            } catch {
                // Timer cancellation occurs after a winner is selected.
            }
        }
        let chosen = await withTaskCancellationHandler {
            await gate.wait()
        } onCancel: {
            Task { await gate.publish(.cancelled) }
        }
        work.cancel()
        timer.cancel()
        return chosen
    }
}
