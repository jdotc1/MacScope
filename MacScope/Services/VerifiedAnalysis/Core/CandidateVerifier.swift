// Source-adapted portable contract; see PROVENANCE.md.
import Foundation

public enum VACandidateVerifier {
    /// Native schemas need not invent portable artifact hashes or code observations. The
    /// owner supplies its complete supported value projection and an exact delta eraser.
    /// Measurement/protected-field coverage remains an independent native check.
    static func verify<State: Equatable>(before: State, candidate: State,
                                         requested: String?, observed: String?,
                                         eraseRequestedDelta: (inout State) -> Void) throws {
        guard observed == requested else {
            throw VAVerificationError.candidateMismatch("requested annotation was not recorded")
        }
        var normalized = candidate
        eraseRequestedDelta(&normalized)
        guard normalized == before else {
            throw VAVerificationError.candidateMismatch("candidate changed supported state outside the requested field")
        }
    }

    public static func verify(before: VAWorkspaceProjection, candidate: VAWorkspaceProjection, edits: [VAEditIntent]) throws {
        try before.validate()
        try candidate.validate()
        guard !edits.isEmpty, edits.count <= 64 else { throw VAVerificationError.invalidRequest("invalid candidate scope") }
        var normalized = candidate
        var seen = Set<String>()
        for edit in edits {
            let key = "\(edit.target.componentID)/\(edit.target.function)/\(edit.kind.rawValue)"
            guard seen.insert(key).inserted else { throw VAVerificationError.invalidRequest("duplicate candidate scope") }
            // The portable projection has no type or prototype fields. Refuse before target lookup so a
            // data-address target reports the real reason instead of unknownTarget.
            if edit.kind == .addressType || edit.kind == .functionPrototype { throw VAVerificationError.unsupportedMutation }
            guard let original = before.function(edit.target),
                  let c = normalized.components.firstIndex(where: { $0.id == edit.target.componentID }),
                  let f = normalized.components[c].functions.firstIndex(where: { $0.address == edit.target.function }) else {
                throw VAVerificationError.unknownTarget
            }
            switch edit.kind {
            case .functionName:
                guard normalized.components[c].functions[f].customName == edit.value else {
                    throw VAVerificationError.candidateMismatch("requested function name was not recorded")
                }
                normalized.components[c].functions[f].customName = original.customName
            case .functionComment:
                guard normalized.components[c].functions[f].customComment == edit.value else {
                    throw VAVerificationError.candidateMismatch("requested function comment was not recorded")
                }
                normalized.components[c].functions[f].customComment = original.customComment
            case .functionPrototype, .addressType:
                // The portable projection has no type or prototype fields.
                throw VAVerificationError.unsupportedMutation
            }
        }
        // Erasing exactly the authorized field deltas must reproduce the complete supported projection.
        // This also protects all component identities, code, call inventory, ordering, and revision.
        guard normalized == before else {
            throw VAVerificationError.candidateMismatch("candidate changed state outside the authorized name/comment fields")
        }
    }
}
