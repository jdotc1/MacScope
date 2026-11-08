// Original to this item (AR3, NF03). One side of a security delta: a validated AR1 review and, optionally, the AR2
// signature attachment captured under the same inventory. Construction checks structure and numeric binding only;
// nothing here reads a file, and no live authority is carried. This type wraps the landed AR1/AR2 values directly
// instead of the design's adapter snapshot types (recorded deviation).

import Foundation

extension ComponentEvidenceSecurityDelta {
    /// Cooperative cancellation and deadline seams. Closures are pure reads of caller state.
    struct Control: Sendable {
        let isCancelled: @Sendable () -> Bool
        let deadlineReached: @Sendable () -> Bool
        static let none = Control(isCancelled: { false }, deadlineReached: { false })

        func check() throws {
            if isCancelled() { throw Refusal.make(.cancelled) }
            if deadlineReached() { throw Refusal.make(.deadlineExceeded) }
        }
    }

    struct Input: Sendable {
        let side: Side
        let review: ComponentEvidence.ComponentReview
        let signatures: ComponentEvidence.SignatureEvidenceAttachment?
        /// Caller-known losses on this side (for example a capped capture). Each forces PARTIAL.
        let partialDetails: [PartialDetail]

        init(side: Side, review: ComponentEvidence.ComponentReview,
             signatures: ComponentEvidence.SignatureEvidenceAttachment? = nil, partialDetails: [PartialDetail] = []) throws {
            do { try review.inventory.validate() } catch { throw Refusal.make(.invalidReview, side: side) }
            if let signatures {
                do { try signatures.bind(to: review.inventory) } catch {
                    throw Refusal.make(.evidenceBindingMismatch, side: side, kind: .bindingMismatch)
                }
            }
            self.side = side; self.review = review; self.signatures = signatures; self.partialDetails = partialDetails
        }

        var inventory: ComponentEvidence.ComponentInventory { review.inventory }
    }
}

extension ComponentEvidenceSecurityDelta.Refusal {
    /// A refusal without side failures cannot fail its checked initializer.
    static func make(_ code: ComponentEvidenceSecurityDelta.RefusalCode, side: ComponentEvidenceSecurityDelta.Side? = nil,
                     kind: ComponentEvidenceSecurityDelta.UnderlyingKind? = nil) -> Self {
        guard let refusal = try? Self(code: code, side: side, underlyingKind: kind) else {
            preconditionFailure("a refusal without side failures is always valid")
        }
        return refusal
    }
}
