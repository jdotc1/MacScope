// Adapted from the exact DER mapping in MacScope/Services/EntitlementComparison/
// EntitlementValueReader+Exact.swift (the private exactDERDictionary and exactDERValue functions are copied here
// with attribution; that file is not edited), and from the EntitlementLens bounded form adapter through the AIRS
// component evidence core at donor commit fa5a2f3128da9134969055cebea145e2ca144214.
// MacScope adds independent decoding of each retained form, typed refusals, form agreement and the read guard.
// The XML-first exact reader is never called on both forms at once, and nothing here validates trust.

import Foundation

extension ComponentEvidence {
    enum EntitlementForm: String, Sendable, Hashable { case xml, der }

    enum EntitlementAdapterLimit: String, Sendable, Hashable { case payloadBytes, depth, nodes, rootKeys, decodedBytes }

    enum EntitlementAdapterRefusal: Sendable, Hashable {
        case limit(EntitlementAdapterLimit)
        case invalidPropertyList(String)
        case invalidRoot
        case malformedDER(String)
        case duplicateKey
        case unsupportedValue(String)
        case unknownDecoderFailure
        /// The raw form itself was unavailable (for example its slot inventory was refused).
        case rawUnavailable(SignatureEvidenceProblem)
    }

    /// What is known about how the dictionary keys relate to the source bytes.
    enum SourceKeyFidelity: String, Sendable, Hashable {
        case exactUTF8Bytes
        /// Foundation may merge or canonicalize original XML keys; a lossless raw-key mapping is not claimed (ruling O6).
        case notProvedForFoundationXML
    }

    enum EntitlementFormState: Sendable, Equatable {
        case decoded(EntitlementDictionary)
        case unavailable(EntitlementAdapterRefusal)
    }

    struct EntitlementFormObservation: Sendable, Equatable {
        let form: EntitlementForm
        let state: EntitlementFormState
        let sourceKeyFidelity: SourceKeyFidelity
        var dictionary: EntitlementDictionary? { if case .decoded(let value) = state { value } else { nil } }
    }

    enum EntitlementFormAgreement: Sendable {
        case nonePresent
        case xmlOnly
        case derOnly
        case bothEquivalent
        /// Both dictionaries stay on the result; there is no selected winner.
        case bothDifferent(EntitlementComparison)
        case oneUnavailable(availableForm: EntitlementForm, failedForm: EntitlementForm)
        case bothUnavailable
        /// A single present form failed to decode.
        case onlyFormUnavailable(EntitlementForm)
        /// The slice itself could not provide either form.
        case sliceUnavailable(SignatureEvidenceProblem)
    }

    struct AttributedEntitlementResult: Sendable {
        let key: SignatureEvidenceKey
        let source: RelativePath
        let xml: EntitlementFormObservation?
        let der: EntitlementFormObservation?
        let agreement: EntitlementFormAgreement
        /// An unsigned or entitlement-free slice is an attributed notPresent, never an empty dictionary.
        var isNotPresent: Bool { if case .nonePresent = agreement { true } else { false } }
    }

    enum RawEntitlementAdapter {
        static let payloadBound = 262_144

        static func decodeXML(_ payload: [UInt8]) -> EntitlementFormObservation {
            func result(_ state: EntitlementFormState) -> EntitlementFormObservation {
                EntitlementFormObservation(form: .xml, state: state, sourceKeyFidelity: .notProvedForFoundationXML)
            }
            guard payload.count <= payloadBound else { return result(.unavailable(.limit(.payloadBytes))) }
            do {
                let object = try PropertyListSerialization.propertyList(from: Data(payload), format: nil)
                guard let root = object as? NSDictionary else { return result(.unavailable(.invalidRoot)) }
                guard root.count <= 256 else { return result(.unavailable(.limit(.rootKeys))) }
                let dictionary = try FoundationEntitlementDecoder(limits: .init(maxDepth: 16, maxNodes: 4_096, maxBytes: payloadBound)).decode(root)
                return result(.decoded(dictionary))
            } catch let error as EntitlementDataError {
                switch error {
                case .limitExceeded("nesting depth"): return result(.unavailable(.limit(.depth)))
                case .limitExceeded("node count"): return result(.unavailable(.limit(.nodes)))
                case .limitExceeded("decoded byte count"): return result(.unavailable(.limit(.decodedBytes)))
                case .limitExceeded: return result(.unavailable(.unknownDecoderFailure))
                case .duplicateKey: return result(.unavailable(.duplicateKey))
                case .invalidRoot: return result(.unavailable(.invalidRoot))
                case .unsupportedType(let name), .invalidNumber(let name): return result(.unavailable(.unsupportedValue(String(name.prefix(80)))))
                case .nonFiniteNumber, .nonFiniteDate, .invalidLimits: return result(.unavailable(.unknownDecoderFailure))
                }
            } catch {
                return result(.unavailable(.invalidPropertyList(String(error.localizedDescription.prefix(120)))))
            }
        }

        static func decodeDER(_ payload: [UInt8]) -> EntitlementFormObservation {
            func result(_ state: EntitlementFormState) -> EntitlementFormObservation {
                EntitlementFormObservation(form: .der, state: state, sourceKeyFidelity: .exactUTF8Bytes)
            }
            do {
                let entries = try AppleEntitlementDER.decode(Data(payload))
                return result(.decoded(try exactDERDictionary(entries)))
            } catch let failure as AppleEntitlementDER.Failure {
                switch failure.detail {
                case "payload exceeds 262144 byte bound": return result(.unavailable(.limit(.payloadBytes)))
                case "nesting depth": return result(.unavailable(.limit(.depth)))
                case "node count": return result(.unavailable(.limit(.nodes)))
                case "top-level key count": return result(.unavailable(.limit(.rootKeys)))
                case "DER duplicate key": return result(.unavailable(.duplicateKey))
                default: return result(.unavailable(.malformedDER(String(failure.detail.prefix(80)))))
                }
            } catch is EntitlementDataError {
                return result(.unavailable(.duplicateKey))
            } catch {
                return result(.unavailable(.unknownDecoderFailure))
            }
        }

        // Copied from EntitlementValueReader+Exact.swift (private there).
        private static func exactDERDictionary(_ entries: [AppleEntitlementDER.Entry]) throws -> EntitlementDictionary {
            try EntitlementDictionary(entries: entries.map { .init(key: $0.key, value: try exactDERValue($0.value)) })
        }

        private static func exactDERValue(_ value: AppleEntitlementDER.Value) throws -> EntitlementValue {
            switch value {
            case .boolean(let value): return .boolean(value)
            case .string(let value): return .string(value)
            case .integer(let value): return .integer(value)
            case .unsignedInteger(let value): return .unsignedInteger(value)
            case .array(let values): return .array(try values.map(exactDERValue))
            case .dictionary(let entries): return .dictionary(try exactDERDictionary(entries))
            }
        }

        private static func observation(_ form: EntitlementForm, _ presence: EvidencePresence<SignatureBlobEvidence>)
            -> EntitlementFormObservation? {
            switch presence {
            case .notPresent: return nil
            case .unavailable(let problem):
                return EntitlementFormObservation(form: form, state: .unavailable(.rawUnavailable(problem)),
                    sourceKeyFidelity: form == .xml ? .notProvedForFoundationXML : .exactUTF8Bytes)
            case .present(let blob): return form == .xml ? decodeXML(blob.payload) : decodeDER(blob.payload)
            }
        }

        /// Decodes each retained form independently and attributes the result to `key`'s slice.
        static func convert(slice: SignatureSliceEvidence, key: SignatureEvidenceKey) -> AttributedEntitlementResult {
            func result(_ xml: EntitlementFormObservation?, _ der: EntitlementFormObservation?, _ agreement: EntitlementFormAgreement)
                -> AttributedEntitlementResult {
                AttributedEntitlementResult(key: key, source: key.componentID, xml: xml, der: der, agreement: agreement)
            }
            switch slice.state {
            case .signatureAbsent, .entitlementsAbsent:
                return result(nil, nil, .nonePresent)
            case .unexamined(let problem):
                return result(nil, nil, .sliceUnavailable(problem))
            case .malformed(let refusal):
                return result(nil, nil, .sliceUnavailable(.structureRefused(refusal)))
            case .budgetExceeded(let limit):
                return result(nil, nil, .sliceUnavailable(.capReached(limit)))
            case .collected:
                break
            }
            let xml = observation(.xml, slice.entitlementsXML), der = observation(.der, slice.entitlementsDER)
            switch (xml, der) {
            case (nil, nil): return result(nil, nil, .nonePresent)
            case (let xml?, nil):
                return result(xml, nil, xml.dictionary != nil ? .xmlOnly : .onlyFormUnavailable(.xml))
            case (nil, let der?):
                return result(nil, der, der.dictionary != nil ? .derOnly : .onlyFormUnavailable(.der))
            case (let xml?, let der?):
                switch (xml.dictionary, der.dictionary) {
                case (let left?, let right?):
                    if left == right { return result(xml, der, .bothEquivalent) }
                    return result(xml, der, .bothDifferent(EntitlementComparison(previous: left, current: right)))
                case (.some, nil): return result(xml, der, .oneUnavailable(availableForm: .xml, failedForm: .der))
                case (nil, .some): return result(xml, der, .oneUnavailable(availableForm: .der, failedForm: .xml))
                case (nil, nil): return result(xml, der, .bothUnavailable)
                }
            }
        }
    }

    /// Ordered guard around an injected, nonescaping adapter: cancellation, exact numeric slice membership,
    /// the adapter, cancellation, descriptor-only revalidation by the caller, identity equality, cancellation, publish.
    enum EntitlementReadGuard {
        static func read(attachment: SignatureEvidenceAttachment, key: SignatureEvidenceKey,
                         isCancelled: () -> Bool = { Task.isCancelled }, revalidate: () throws -> Void,
                         adapter: (SignatureSliceEvidence) throws -> AttributedEntitlementResult) throws -> AttributedEntitlementResult {
            if isCancelled() { throw SignatureCaptureError.cancelled }
            guard let slice = attachment.slice(for: key) else { throw SignatureCaptureError.wrongSlice }
            let result = try adapter(slice)
            if isCancelled() { throw SignatureCaptureError.cancelled }
            try revalidate()
            guard result.key == key, result.source == key.componentID else { throw SignatureCaptureError.wrongSlice }
            if isCancelled() { throw SignatureCaptureError.cancelled }
            return result
        }
    }
}
