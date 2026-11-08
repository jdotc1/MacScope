// Source-adapted portable contract; see PROVENANCE.md.
import Foundation

/// One derivation of current receipt effects for validation, checkpoints and workflow admission.
/// Call only after the state's receipt shapes, identities and evidence have been validated.
/// Historical receipts remain available for audit and exact retry; they are not current authority.
struct VAAcceptedReceiptHistory: Sendable {
    private struct Effect: Sendable {
        let operationID: UUID
        let edit: VAEditIntent
    }
    private var effects: [String: Effect] = [:]
    private var currentSegment: Set<UUID> = []

    var materializedFieldCount: Int { effects.count }
    var materializedOperationIDs: [UUID] {
        Array(Set(effects.values.map(\.operationID))).sorted { $0.uuidString < $1.uuidString }
    }

    init(state: VAVerificationState) throws {
        let current = try state.projection.stamp()
        var latestAccepted: VAProjectionStamp?
        for receipt in state.receipts where receipt.decision == .accepted {
            guard let after = receipt.after else {
                throw VAVerificationError.invalidState("accepted receipt has no after projection")
            }
            if let previous = latestAccepted {
                guard after.revision > previous.revision, receipt.before.revision >= previous.revision else {
                    throw VAVerificationError.invalidState("duplicate or regressing accepted transition")
                }
                if receipt.before.revision == previous.revision &&
                   receipt.before.installationID == previous.installationID {
                    guard receipt.before == previous else {
                        throw VAVerificationError.invalidState("accepted transition does not start at the prior accepted projection")
                    }
                } else {
                    effects.removeAll(keepingCapacity: true)
                    currentSegment.removeAll(keepingCapacity: true)
                }
            }
            for edit in receipt.request.edits {
                effects[Self.key(edit)] = Effect(operationID: receipt.request.id, edit: edit)
            }
            currentSegment.insert(receipt.request.id)
            latestAccepted = after
        }
        guard let latestAccepted, latestAccepted.revision == current.revision,
              latestAccepted.installationID == current.installationID else {
            // A manual change or new installation after the last accepted operation ends the
            // current verified segment even if a field happens to regain its historical value.
            effects.removeAll()
            currentSegment.removeAll()
            return
        }
        guard latestAccepted == current else {
            throw VAVerificationError.invalidState("current projection conflicts with its latest accepted receipt")
        }
        for effect in effects.values {
            let edit = effect.edit
            guard let function = state.projection.function(edit.target) else {
                throw VAVerificationError.unknownTarget
            }
            switch edit.kind {
            case .functionName:
                guard function.customName == edit.value else {
                    throw VAVerificationError.invalidState("accepted name is not materialized")
                }
            case .functionComment:
                guard function.customComment == edit.value else {
                    throw VAVerificationError.invalidState("accepted comment is not materialized")
                }
            case .functionPrototype, .addressType:
                // The portable projection has no type or prototype fields.
                throw VAVerificationError.unsupportedMutation
            }
        }
    }

    func requireCurrentEffects(of receipt: VAVerificationReceipt, for target: VATargetReference) throws {
        guard currentSegment.contains(receipt.request.id) else { throw VAVerificationError.staleProjection }
        let scoped = receipt.request.edits.filter { $0.target == target }
        guard !scoped.isEmpty else { throw VAVerificationError.mismatchedEvidence }
        for edit in scoped {
            // Equal values do not restore a superseded receipt's current authority (ABA).
            guard let effect = effects[Self.key(edit)], effect.operationID == receipt.request.id,
                  effect.edit == edit else { throw VAVerificationError.staleProjection }
        }
    }

    private static func key(_ edit: VAEditIntent) -> String {
        "\(edit.target.componentID)/\(edit.target.function)/\(edit.kind.rawValue)"
    }
}
