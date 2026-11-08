import Foundation
import NEWFEATURESCore

/// Production seam for the EXISTING source-attested native batch export.
/// Do not use ScriptingNativeDecompiling here: its pseudocode-only document
/// cannot independently attest native artifact/function/request identity.
///
/// Callers must back this closure with NativePseudocodeBatchSession and
/// NativeProviderExportValidation after inspecting current API contracts.
/// That batch implementation MUST bound bytes before allocation/publication,
/// invalidate timed-out XPC workers and return the real worker receipt.
struct NEWFEATURESValidatedBatchAdapter: NEWFEATURESNativeDecompiling {
    let performValidatedExport:
        @Sendable (NEWFEATURESDecompileRequest) async -> NEWFEATURESDecompileResponse

    func decompile(_ request: NEWFEATURESDecompileRequest) async -> NEWFEATURESDecompileResponse {
        guard ContinuousClock().now < request.deadline else {
            return NEWFEATURESDecompileResponse(
                function: request.function, backend: .unavailable, text: nil,
                complete: false, refusalCode: "deadline-before-native-export"
            )
        }
        return await performValidatedExport(request)
    }
}

/// App authority facade: MTPLX and script clients never own the Phase2 ledger
/// or NativeProviderExportValidation acceptance state.
struct NEWFEATURESAppSourceChecker: NEWFEATURESSourceChecking {
    let currentLedgerAdmission: @Sendable (NEWFEATURESLedgerAdmission) async -> Bool
    let validateNativeExport:
        @Sendable (NEWFEATURESDecompileResponse, NEWFEATURESDecompileRequest, NEWFEATURESLedgerAdmission) async -> Bool
    let validateMacIRArtifact:
        @Sendable (NEWFEATURESDecompileResponse, NEWFEATURESDecompileRequest, NEWFEATURESLedgerAdmission) async -> Bool

    func isCurrent(_ admission: NEWFEATURESLedgerAdmission) async -> Bool {
        await currentLedgerAdmission(admission)
    }

    func admits(
        _ response: NEWFEATURESDecompileResponse,
        for request: NEWFEATURESDecompileRequest,
        admission: NEWFEATURESLedgerAdmission
    ) async -> Bool {
        guard admission.image == request.function.image else { return false }
        switch response.backend {
        case .nativeSleigh:
            guard response.workerReceipt?.observedFunction == request.function else { return false }
            return await validateNativeExport(response, request, admission)
        case .macIRFallback:
            guard response.fallbackReceipt?.observedFunction == request.function else { return false }
            return await validateMacIRArtifact(response, request, admission)
        case .unavailable:
            return false
        }
    }
}

/// Safe explicit refusal until the source-validated batch session is wired.
struct NEWFEATURESUnwiredNativeProvider: NEWFEATURESNativeDecompiling {
    func decompile(_ request: NEWFEATURESDecompileRequest) async -> NEWFEATURESDecompileResponse {
        NEWFEATURESDecompileResponse(
            function: request.function, backend: .unavailable, text: nil,
            complete: false, refusalCode: "native-batch-admission-not-wired"
        )
    }
}
