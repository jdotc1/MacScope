import Foundation

/// Presentation and publication of a captured listing, not an alternative source authority.
@MainActor
enum BoundedListingExportController {
    enum Failure: LocalizedError {
        case sourceUnavailable, staleSource

        var errorDescription: String? {
            switch self {
            case .sourceUnavailable:
                return String(localized: "The selected image has no available listing. Analyze it before exporting.")
            case .staleSource:
                return String(localized: "The export source or its workspace changed. Start export again.")
            }
        }
    }

    struct SourceStamp: Equatable {
        let state: Phase2ReadCurrentState
        let mutationGeneration: UInt64

        func matches(state: Phase2ReadCurrentState, mutationGeneration: UInt64) -> Bool {
            self.state == state && self.mutationGeneration == mutationGeneration
        }
    }

    /// Inert rendered content. Constructing this does not grant publication permission.
    struct Content: Sendable {
        let listing: DocumentExportService.BoundedListing
        let suggestedName: String
        var fileExtension: String { listing.format == .html ? "html" : "txt" }
        var message: String {
            if let reason = listing.stopReason {
                let explanation: String
                switch reason {
                case .rowLimit:
                    explanation = String(localized: "The row limit was reached.")
                case .inputFieldLimit:
                    explanation = String(localized: "The next row contains a field that is too long to export.")
                case .outputByteLimit:
                    explanation = String(localized: "The file size limit was reached.")
                case .unsupportedHTMLControl:
                    explanation = String(localized: "The next row contains a character that HTML cannot represent.")
                }
                return String(localized: "Partial listing: \(listing.consumedRows) of \(listing.inputRowCount) rows. \(explanation) This is not a complete listing.")
            }
            return String(localized: "Complete captured listing: \(listing.consumedRows) rows.")
        }
    }

    @MainActor
    struct Prepared {
        let content: Content
        private let validateSource: @MainActor () throws -> Void
        private let publishText: @MainActor ((String) throws -> Void) throws -> Void

        fileprivate init(content: Content,
                         validateSource: @escaping @MainActor () throws -> Void,
                         publishText: @escaping @MainActor ((String) throws -> Void) throws -> Void) {
            self.content = content
            self.validateSource = validateSource
            self.publishText = publishText
        }

        func isCurrent() -> Bool {
            do { try validateSource(); return true } catch { return false }
        }

        func publish(to url: URL) throws {
            try validateSource()
            // publishText invokes the real admission bridge at this synchronous sink.
            try publishText { text in try text.write(to: url, atomically: true, encoding: .utf8) }
        }
    }

    static func captureErrorMessage(_ error: Error) -> String {
        switch error {
        case let failure as Failure:
            return failure.localizedDescription
        case NEWFEATURESAdmissionFailure.analysisRequired:
            return String(localized: "Analyze the selected image before exporting its listing.")
        case NEWFEATURESAdmissionFailure.sourceIdentityUnavailable:
            return String(localized: "The selected image's retained analysis could not be matched to its source. Analyze it again before exporting.")
        case NEWFEATURESAdmissionFailure.staleSource, NEWFEATURESAdmissionFailure.documentClosed:
            return String(localized: "The export source or its workspace changed. Start export again.")
        case is DocumentExportService.ListingRenderError:
            return String(localized: "The listing could not be rendered within the export limits.")
        case is CancellationError:
            return String(localized: "The listing export was cancelled.")
        default:
            return error.localizedDescription
        }
    }

    static func render(snapshot: WorkspaceSnapshot, slot: ImageSlot, name: String,
                       format: DocumentExportService.ListingFormat,
                       limits: DocumentExportService.ListingLimits) throws -> Content {
        guard snapshot.binary(in: slot) != nil, snapshot.analysis(in: slot) != nil else {
            throw Failure.sourceUnavailable
        }
        let captured = DisassemblyListingBuilder.buildResolved(snapshot: snapshot, slot: slot)
        let listing = try DocumentExportService().renderBoundedListing(
            rows: captured.rows, resolved: captured.resolved, format: format, limits: limits)
        return Content(listing: listing,
                       suggestedName: name + (listing.isComplete ? "" : "-partial"))
    }

    static func capture(store: WorkspaceStore, session: WorkspaceDocumentSession,
                        format: DocumentExportService.ListingFormat,
                        limits: DocumentExportService.ListingLimits,
                        isCurrentOwner: @escaping @MainActor () -> Bool) throws -> Prepared {
        guard isCurrentOwner() else { throw Failure.staleSource }
        let slot = store.focusedImageSlot
        let snapshot = store.snapshot
        guard let binary = snapshot.binary(in: slot) else { throw Failure.sourceUnavailable }
        let bridge = NEWFEATURESAdmissionBridge(store: store, session: session)
        let admission = try bridge.admit(slot: slot)
        let stamp = SourceStamp(state: store.phase2ReadCurrentState(for: slot),
                                mutationGeneration: store.mutationGeneration.rawValue)
        let validate: @MainActor () throws -> Void = { [weak store] in
            guard isCurrentOwner(), let store,
                  stamp.matches(state: store.phase2ReadCurrentState(for: slot),
                                mutationGeneration: store.mutationGeneration.rawValue) else {
                throw Failure.staleSource
            }
            try bridge.revalidate(admission)
        }
        let content = try render(snapshot: snapshot, slot: slot,
                                 name: "\(store.workspaceName)-\(binary.name)-listing",
                                 format: format, limits: limits)
        try validate()
        let envelope = admission.retaining(content.listing.text)
        return Prepared(content: content, validateSource: validate, publishText: { sink in
            try validate()
            try bridge.publish(envelope, to: sink)
        })
    }

    /// The save-panel result is consumed only once; nil is cancellation, never a write.
    /// Used by the listing-specific sink after the existing panel's final validation.
    @discardableResult
    static func publishSelection(_ url: URL?, validate: () throws -> Void,
                                 write: (URL) throws -> Void) throws -> Bool {
        guard let url else { return false }
        try validate()
        try write(url)
        return true
    }
}
