import Foundation

extension CalleeClaimEnvelope.Event {
    init(_ event: VACalleeClaimEvent) throws {
        try event.validateShape()
        try self.init(canonicalBytes: VerifiedAnnotationAuditCodec.encode(event))
    }
    func makeEvent() throws -> VACalleeClaimEvent {
        do {
            let event = try JSONDecoder().decode(VACalleeClaimEvent.self, from: canonicalBytes)
            // Reject duplicate/unknown members, explicit nulls and noncanonical spellings
            // even in nested types whose own decoder might ignore them.
            guard try VerifiedAnnotationAuditCodec.encode(event) == canonicalBytes else {
                throw CalleeClaimEnvelopeError.malformedEvent
            }
            return event
        } catch let error as CalleeClaimEnvelopeError { throw error }
        catch { throw CalleeClaimEnvelopeError.malformedEvent }
    }
}

extension CalleeClaimEnvelope {
    init(ledger: CalleeClaimLedger) throws {
        guard ledger.events.count <= Self.maximumEvents else { throw CalleeClaimEnvelopeError.tooManyEvents }
        var events: [Event] = []
        var encodedByteLowerBound = 0
        for source in ledger.events {
            let event = try Event(source)
            encodedByteLowerBound += ((event.canonicalBytes.count + 2) / 3) * 4
            guard encodedByteLowerBound <= Self.maximumEncodedBytes else {
                throw CalleeClaimEnvelopeError.envelopeTooLarge
            }
            events.append(event)
        }
        try self.init(events: events)
    }
    /// Decode and replay into a candidate. Never install a prefix on any rejection.
    func makeLedger() throws -> CalleeClaimLedger {
        try validate()
        do {
            return try CalleeClaimLedger(events: events.map { try $0.makeEvent() })
        } catch let error as CalleeClaimEnvelopeError { throw error }
        catch { throw CalleeClaimEnvelopeError.invalidLedger }
    }
}
