import Foundation
import NEWFEATURESCore

enum NEWFEATURESCallPathFailure: Error, Equatable, Sendable {
    case unsupportedArchitecture
    case invalidFunctionOwnership
    case endpointUnresolved
    case inputLimit
    case outputLimit
}

struct NEWFEATURESCallProjectionLimits: Sendable {
    let maximumFunctions: Int
    let maximumInstructions: Int
    let maximumXrefs: Int
    let maximumWork: Int
    let maximumUnresolvedSamples: Int

    static let standard = Self(maximumFunctions: 100_000, maximumInstructions: 1_000_000,
                               maximumXrefs: 200_000, maximumWork: 4_000_000,
                               maximumUnresolvedSamples: 96)

    func validate() throws {
        guard (1...100_000).contains(maximumFunctions),
              (1...1_000_000).contains(maximumInstructions),
              (0...1_000_000).contains(maximumXrefs),
              (1...8_000_000).contains(maximumWork),
              (0...500).contains(maximumUnresolvedSamples) else {
            throw NEWFEATURESError.invalidPolicy
        }
    }
}

struct NEWFEATURESUnresolvedCallObservation: Encodable, Hashable, Sendable {
    enum Reason: String, Encodable, Hashable, Sendable {
        case callerOwnershipUnavailable
        case targetOwnershipUnavailable
        case decodedCallEvidenceUnavailable
        case indirectTargetUnavailable
        case callXrefUnavailable
    }

    let callSite: UInt64
    let observedTarget: UInt64?
    let reason: Reason

    private enum CodingKeys: String, CodingKey { case callSite, observedTarget, reason }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode("0x" + String(callSite, radix: 16), forKey: .callSite)
        try values.encodeIfPresent(observedTarget.map { "0x" + String($0, radix: 16) }, forKey: .observedTarget)
        try values.encode(reason, forKey: .reason)
    }
}

struct NEWFEATURESVerifiedCallProjection: Sendable {
    let graph: NEWFEATURESGraphSnapshot
    let source: NEWFEATURESFunctionKey
    let destination: NEWFEATURESFunctionKey
    let functionIDsByStart: [UInt64: UUID]
    let unresolvedObservationCount: Int
    let unresolvedSamples: [NEWFEATURESUnresolvedCallObservation]
    let constructionWork: Int

    /// Consumes a captured, source-owned projection. Instruction text is not a call
    /// witness: only a unique retained four-byte BL word matching the xref target is
    /// traversable. This first increment deliberately does not prove indirect calls.
    static func make(
        projection: FocusedGraphProjection,
        image: NEWFEATURESImageKey,
        sourceAddress: UInt64,
        destinationAddress: UInt64,
        operation: NEWFEATURESGraphOperation,
        limits: NEWFEATURESCallProjectionLimits = .standard
    ) throws -> Self {
        try limits.validate()
        try operation.checkpoint()
        guard image.architecture == "arm64" || image.architecture == "arm64e" else {
            throw NEWFEATURESCallPathFailure.unsupportedArchitecture
        }
        guard projection.imageSlot.rawValue == image.slot, projection.ownerBinaryID == image.binaryID else {
            throw NEWFEATURESAdmissionFailure.staleSource
        }
        guard projection.functions.count <= limits.maximumFunctions,
              projection.instructions.count <= limits.maximumInstructions,
              projection.xrefs.count <= limits.maximumXrefs else {
            throw NEWFEATURESCallPathFailure.inputLimit
        }

        var work = 0
        func checkpoint() throws {
            try operation.checkpoint()
            guard work < limits.maximumWork else { throw NEWFEATURESCallPathFailure.inputLimit }
            work += 1
        }

        var ids: Set<UUID> = []
        var functionIDsByStart: [UInt64: UUID] = [:]
        var functions: [NEWFEATURESFunctionKey] = []
        functions.reserveCapacity(projection.functions.count)
        for function in projection.functions {
            try checkpoint()
            guard function.endAddress > function.startAddress, function.startAddress & 3 == 0,
                  ids.insert(function.id).inserted,
                  functionIDsByStart[function.startAddress] == nil else {
                throw NEWFEATURESCallPathFailure.invalidFunctionOwnership
            }
            functionIDsByStart[function.startAddress] = function.id
            functions.append(NEWFEATURESFunctionKey(image: image, address: function.startAddress))
        }
        let ranges = try FunctionRangeIndex(projection.functions, checking: checkpoint)
        guard let sourceFunction = try ranges.owner(of: sourceAddress, checking: checkpoint),
              let destinationFunction = try ranges.owner(of: destinationAddress, checking: checkpoint) else {
            throw NEWFEATURESCallPathFailure.endpointUnresolved
        }

        var wordsByAddress: [UInt64: UInt32] = [:]
        var seenAddresses: Set<UInt64> = []
        var decodedCalls: [(address: UInt64, target: UInt64?)] = []
        let decoder = ARM64Decoder()
        for row in projection.instructions {
            try checkpoint()
            guard seenAddresses.insert(row.address).inserted else {
                wordsByAddress[row.address] = nil
                continue
            }
            guard row.address & 3 == 0, let word = instructionWord(row.bytes) else { continue }
            wordsByAddress[row.address] = word
            if let target = FunctionStartCallTargetDerivation.directCallTarget(word: word, at: row.address) {
                decodedCalls.append((row.address, target))
            } else if word & 0xfe00_0000 == 0xd600_0000 {
                // Reuse the actual decoder's call classification for BLR and allocated
                // authenticated register calls. Display mnemonics confer no authority.
                let bytes = Data((0..<4).map { UInt8(truncatingIfNeeded: word >> ($0 * 8)) })
                if let instruction = decoder.decode(bytes, baseAddress: row.address, maxInstructionCount: 1).first,
                   instruction.flow == .indirectCall, instruction.branchTarget == nil {
                    decodedCalls.append((row.address, nil))
                }
            }
        }

        var unresolvedCount = 0
        var unresolved: [NEWFEATURESUnresolvedCallObservation] = []
        var seenUnresolved: Set<NEWFEATURESUnresolvedCallObservation> = []
        func recordUnresolved(_ address: UInt64, _ target: UInt64?,
                              _ reason: NEWFEATURESUnresolvedCallObservation.Reason) throws {
            let observation = NEWFEATURESUnresolvedCallObservation(
                callSite: address, observedTarget: target, reason: reason
            )
            guard seenUnresolved.insert(observation).inserted else { return }
            unresolvedCount += 1
            guard limits.maximumUnresolvedSamples > 0 else { return }
            func precedes(_ lhs: NEWFEATURESUnresolvedCallObservation,
                          _ rhs: NEWFEATURESUnresolvedCallObservation) -> Bool {
                if lhs.callSite != rhs.callSite { return lhs.callSite < rhs.callSite }
                if lhs.observedTarget != rhs.observedTarget {
                    if lhs.observedTarget == nil { return false }
                    if rhs.observedTarget == nil { return true }
                    return (lhs.observedTarget ?? 0) < (rhs.observedTarget ?? 0)
                }
                return lhs.reason.rawValue < rhs.reason.rawValue
            }
            var low = 0, high = unresolved.count
            while low < high {
                try checkpoint()
                let mid = (low + high) / 2
                if precedes(unresolved[mid], observation) { low = mid + 1 } else { high = mid }
            }
            if low < limits.maximumUnresolvedSamples {
                unresolved.insert(observation, at: low)
                if unresolved.count > limits.maximumUnresolvedSamples { unresolved.removeLast() }
            }
        }
        var edges: [NEWFEATURESCallEdge] = []
        var unresolvedEdges: [NEWFEATURESUnresolvedCallEdge] = []
        edges.reserveCapacity(min(projection.xrefs.count, limits.maximumXrefs))
        func requireEdgeCapacity() throws {
            guard edges.count < limits.maximumXrefs - unresolvedEdges.count else {
                throw NEWFEATURESCallPathFailure.inputLimit
            }
        }
        var observedCallSites: Set<UInt64> = []
        for xref in projection.xrefs {
            try checkpoint()
            guard xref.kind == XRefKind.call else { continue }
            observedCallSites.insert(xref.from)
            guard let caller = try ranges.owner(of: xref.from, checking: checkpoint) else {
                try recordUnresolved(xref.from, xref.to, .callerOwnershipUnavailable)
                continue
            }
            guard let callee = try ranges.owner(of: xref.to, checking: checkpoint) else {
                try recordUnresolved(xref.from, xref.to, .targetOwnershipUnavailable)
                try requireEdgeCapacity()
                unresolvedEdges.append(.init(caller: .init(image: image, address: caller.startAddress),
                                             callSite: xref.from, observedTarget: xref.to))
                continue
            }
            let target = wordsByAddress[xref.from].flatMap {
                FunctionStartCallTargetDerivation.directCallTarget(word: $0, at: xref.from)
            }
            var uniquelyOwnedInstruction = true
            for offset in UInt64(0)..<4 {
                try checkpoint()
                let address = xref.from.addingReportingOverflow(offset)
                guard !address.overflow,
                      try ranges.owner(of: address.partialValue, checking: checkpoint)?.id == caller.id else {
                    uniquelyOwnedInstruction = false
                    break
                }
            }
            let confidence: NEWFEATURESCallConfidence = target == xref.to && uniquelyOwnedInstruction
                ? .confirmedDirect : .unverified
            if confidence == .unverified {
                try recordUnresolved(xref.from, xref.to, .decodedCallEvidenceUnavailable)
            }
            try requireEdgeCapacity()
            edges.append(.init(caller: .init(image: image, address: caller.startAddress),
                               callee: .init(image: image, address: callee.startAddress),
                               callSite: xref.from, confidence: confidence))
        }
        for call in decodedCalls {
            try checkpoint()
            guard !observedCallSites.contains(call.address), wordsByAddress[call.address] != nil else { continue }
            try recordUnresolved(call.address, call.target,
                                 call.target == nil ? .indirectTargetUnavailable : .callXrefUnavailable)
            if let caller = try ranges.owner(of: call.address, checking: checkpoint) {
                try requireEdgeCapacity()
                unresolvedEdges.append(.init(caller: .init(image: image, address: caller.startAddress),
                                             callSite: call.address, observedTarget: call.target))
            }
        }
        let graph = try NEWFEATURESGraphSnapshot(
            functions: functions, edges: edges, unresolvedEdges: unresolvedEdges, operation: operation,
            limits: NEWFEATURESGraphInputLimits(maxFunctions: limits.maximumFunctions,
                                               maxEdges: limits.maximumXrefs)
        )
        try operation.checkpoint()
        return Self(graph: graph,
                    source: .init(image: image, address: sourceFunction.startAddress),
                    destination: .init(image: image, address: destinationFunction.startAddress),
                    functionIDsByStart: functionIDsByStart,
                    unresolvedObservationCount: unresolvedCount, unresolvedSamples: unresolved,
                    constructionWork: work)
    }

    private static func instructionWord(_ text: String) -> UInt32? {
        guard text.utf8.prefix(33).count <= 32 else { return nil }
        let tokens = text.split(whereSeparator: \.isWhitespace)
        guard tokens.count == 4 else { return nil }
        var word: UInt32 = 0
        for (index, token) in tokens.enumerated() {
            guard token.utf8.count == 2, let byte = UInt8(token, radix: 16) else { return nil }
            word |= UInt32(byte) << (index * 8)
        }
        return word
    }
}
