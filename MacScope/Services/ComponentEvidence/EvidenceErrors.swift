// Adapted from the AIRS component evidence core at donor commit fa5a2f3128da9134969055cebea145e2ca144214.
// Original relative paths: native/Sources/AIRSCore/BundleDiscovery.swift,
// native/Sources/AIRSCore/ComponentInventory.swift, native/Sources/AIRSEntitlements/ComponentReview.swift
// (the free-text ReportError.invalidContents and archive error uses).
// License: MIT, Copyright (c) 2026 Jeffrey D. Cooney; the notice is in ThirdParty/AIRS/LICENSE.
// Adaptations: value-only typed failures replace every free-text and archive error; no NSError payload.

import Foundation

extension ComponentEvidence {
    /// Bounded numeric ceilings and counted domains named by a refusal or a recorded cap.
    enum LimitKind: String, Sendable, Hashable, CaseIterable {
        case entries, depth, candidates, headerBytes, pathBytes, components, searchedLocations
        case exclusions, scopeIssues, componentIssues, architectures, slices, loadCommands
        case loadRecords, commandString, observations, plistBytes, payloadBytes, decodeLimits, requests
    }

    /// The failing or observed operation. Descriptor-relative names only.
    enum Operation: String, Sendable, Hashable {
        case openRoot, openDirectory, openFile, statEntry, statDescriptor, duplicateDirectory
        case enumerate, read, close, parse, decode
    }

    /// Closed set of failure case names; readable separately from payloads.
    enum IssueKind: String, Sendable, Hashable {
        case invalidSelection, invalidLimits, unsafePath, io, shortRead, changedInput, malformedHeader
        case malformedMetadata, budgetExceeded, invalidInventory, invalidObservation, architectureMismatch
        case unknownComponent, unknownMatch, sourceMismatch, staleCapability, cancelled
        case principalUnavailable, principalUnresolved
    }

    enum MetadataReason: String, Sendable, Hashable {
        case emptyImage, truncated, unsupportedMagic, badUniversalLayout, overlappingSlices, nonzeroReserved
        case architectureDisagreement, abiWidthMismatch, unsupportedFileType, loadCommandBounds
        case badCommandSize, ambiguousPlatform, badBuildVersion, badDylibCommand, badCommandString
        case loadRecordBudget, duplicateArchitecture, notDictionary, invalidExecutable
        case executablePathMismatch, invalidLabel, badPlist, oversize, notRegularFile
    }

    enum InventoryReason: String, Sendable, Hashable {
        case tooManyComponents, duplicateID, duplicatePath, badPath, badParent, cyclicParents
        case tooManyArchitectures, duplicateArchitecture, minimumWithoutArchitecture, textTooLong
        case scopeTooLarge, invalidTimestamp, nonTextPath, completeWithGap
    }

    enum ObservationReason: String, Sendable, Hashable {
        case tooManyObservations, duplicateObservation, unknownComponentRecord, badSource
        case wrongArchitectureField, badStatePayload, notPresentNotAllowed, missingTypedReason
        case unparseablePayload, emptyArchitecture, reasonTooLong, componentMismatch
        case inventoryMismatch, architectureNotEnumerated
    }

    enum EvidenceError: Error, Sendable, Equatable, LocalizedError {
        case invalidSelection
        case invalidLimits(LimitKind)
        case unsafePath(PathRange?)
        case io(Operation, errno: Int32, PathRange)
        case shortRead(PathRange, expected: Int, actual: Int)
        case changedInput(PathRange)
        case malformedHeader(PathRange, MetadataReason)
        case malformedMetadata(DeclarationCategory?, PathRange, MetadataReason)
        case budgetExceeded(LimitKind, PathRange)
        case invalidInventory(InventoryReason)
        case invalidObservation(ObservationReason)
        case architectureMismatch
        case unknownComponent
        case unknownMatch
        case sourceMismatch
        case staleCapability
        case cancelled
        case principalUnavailable(PathRange)
        case principalUnresolved

        var kind: IssueKind {
            switch self {
            case .invalidSelection: .invalidSelection
            case .invalidLimits: .invalidLimits
            case .unsafePath: .unsafePath
            case .io: .io
            case .shortRead: .shortRead
            case .changedInput: .changedInput
            case .malformedHeader: .malformedHeader
            case .malformedMetadata: .malformedMetadata
            case .budgetExceeded: .budgetExceeded
            case .invalidInventory: .invalidInventory
            case .invalidObservation: .invalidObservation
            case .architectureMismatch: .architectureMismatch
            case .unknownComponent: .unknownComponent
            case .unknownMatch: .unknownMatch
            case .sourceMismatch: .sourceMismatch
            case .staleCapability: .staleCapability
            case .cancelled: .cancelled
            case .principalUnavailable: .principalUnavailable
            case .principalUnresolved: .principalUnresolved
            }
        }
        /// Computed, bounded, never parsed.
        var errorDescription: String? {
            let text = "Component evidence: " + String(describing: self)
            return text.utf8.count <= 512 ? text : String(text.prefix(512))
        }
    }

    /// One recorded failure with its affected range. `errno` and `operation` are separately readable.
    struct EvidenceIssue: Sendable, Equatable {
        let error: EvidenceError
        let range: PathRange
        let operation: Operation?
        let errno: Int32?
        init(_ error: EvidenceError, range: PathRange = .wholeRoot) {
            self.error = error
            self.range = range
            switch error {
            case .io(let operation, let code, _): self.operation = operation; self.errno = code
            default: self.operation = nil; self.errno = nil
            }
        }
        var kind: IssueKind { error.kind }
        var display: String { error.errorDescription ?? "" }
    }
}
