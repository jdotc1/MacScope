import XCTest
@testable import MacScope

@MainActor
final class NEWFEATURESSessionLookupTests: XCTestCase {
    private var previous: NEWFEATURESSessionLookup.Resolver?

    override func setUp() {
        super.setUp()
        previous = NEWFEATURESSessionLookup.resolver
    }

    override func tearDown() {
        NEWFEATURESSessionLookup.install(previous)
        super.tearDown()
    }

    private func installRegistryResolver(_ registry: WorkspaceSessionRegistry) {
        // Same shape as the composition root in WorkspaceDocumentRuntime.
        NEWFEATURESSessionLookup.install { [weak registry] store in
            registry.flatMap { r in r.windowID(for: store).flatMap(r.documentSessionIfPresent) }
        }
    }

    private func makeStore() -> WorkspaceStore {
        WorkspaceStore(workspaceName: "Lookup", snapshot: AnalysisEngine.previewSnapshot(), engine: AnalysisEngine())
    }

    func testAdoptedStoreResolvesToItsSession() throws {
        let registry = WorkspaceSessionRegistry()
        let store = makeStore()
        let id = WorkspaceWindowID.fresh()
        registry.adopt(store, for: id)
        installRegistryResolver(registry)
        let session = try NEWFEATURESSessionLookup.session(for: store)
        XCTAssertTrue(session === registry.documentSessionIfPresent(for: id))
    }

    func testEvictedStoreResolvesToNamedError() throws {
        let registry = WorkspaceSessionRegistry()
        let store = makeStore()
        let id = WorkspaceWindowID.fresh()
        registry.adopt(store, for: id)
        installRegistryResolver(registry)
        registry.evict(id)
        XCTAssertThrowsError(try NEWFEATURESSessionLookup.session(for: store)) { error in
            XCTAssertEqual(error as? NEWFEATURESSessionLookupError, .documentSessionUnavailable)
            XCTAssertEqual("\(error)", "document session unavailable")
        }
    }

    func testNilResolverGivesNamedError() {
        NEWFEATURESSessionLookup.install(nil)
        XCTAssertThrowsError(try NEWFEATURESSessionLookup.session(for: makeStore())) { error in
            XCTAssertEqual(error as? NEWFEATURESSessionLookupError, .documentSessionUnavailable)
        }
    }
}
