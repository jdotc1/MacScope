import Foundation

enum NEWFEATURESSessionLookupError: Error, Equatable, CustomStringConvertible {
    case documentSessionUnavailable

    var description: String { "document session unavailable" }
}

/// Maps a store to the document session that owns it. The resolver is installed once by the
/// composition root that owns the session registry; nil by default, so a surface built without
/// that root (tests, headless tools) refuses instead of guessing a session.
@MainActor
enum NEWFEATURESSessionLookup {
    typealias Resolver = @MainActor (WorkspaceStore) -> WorkspaceDocumentSession?

    private(set) static var resolver: Resolver?

    static func install(_ resolver: Resolver?) { self.resolver = resolver }

    static func session(for store: WorkspaceStore) throws -> WorkspaceDocumentSession {
        guard let session = resolver?(store) else {
            throw NEWFEATURESSessionLookupError.documentSessionUnavailable
        }
        return session
    }
}
