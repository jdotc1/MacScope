import Foundation
import XCTest
@testable import MacScope

// Authored, unrun. Local helpers, not private helpers from existing test classes.
@MainActor
struct TypeAtlasReplyTestHarness {
    enum Route: CaseIterable { case inline, asynchronous, attached }
    let entries: [TypeAtlasEntry]
    let snapshot: WorkspaceSnapshot
    let api: WorkspaceScriptingAPI
    let executor: MCPAttachExecutor
    static let owner = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!

    init(_ entries: [TypeAtlasEntry]) {
        self.entries = entries
        var analysis = ImageAnalysis()
        analysis.typeCatalog = .init(slot: .primary, entries: entries)
        snapshot = WorkspaceSnapshot(binaries: [BinaryImage(id: Self.owner, name: "synthetic-atlas",
            path: "/unused/synthetic-atlas", kind: "Mach-O", architecture: "arm64")],
            analysisBySlot: [.primary: analysis])
        let store = WorkspaceStore(workspaceName: "Synthetic reply", snapshot: snapshot,
            engine: AnalysisEngine(), autosaveScheduler: nil)
        api = WorkspaceScriptingAPI(store: store)
        var clock: UInt64 = 0
        executor = MCPAttachExecutor(store: store, api: { WorkspaceScriptingAPI(store: $0) }, now: {
            clock += 1_000_000_000
            return clock
        })
        executor.setConsent(.allowed)
    }

    func read(_ route: Route, _ args: ScriptValue = .object([:])) async throws -> ScriptValue {
        switch route {
        case .inline: return try api.execute("list-image-types", arguments: args)
        case .asynchronous: return try await api.executeAsync("list-image-types", arguments: args)
        case .attached: return try await executor.execute("list-image-types", args)
        }
    }

    func original() throws -> ScriptValue {
        let links = try WorkspaceScriptingAPI.makeTypeAtlasSwiftObjCLinks(entries, checkpoint: {})
        let rows = try entries.enumerated().map { index, entry in
            try WorkspaceScriptingAPI.applyingTypeAtlasLink(
                WorkspaceScriptingAPI.typeAtlasEntryValue(entry), link: links.byIndex[index], checkpoint: {})
        }
        var fields = WorkspaceScriptingAPI.imageProvenanceFields(slot: .primary, snapshot: snapshot)
        fields["total"] = .int(Int64(entries.count)); fields["types"] = .array(rows)
        if let counts = links.counts { fields["swiftObjCLinks"] = WorkspaceScriptingAPI.typeAtlasLinkCountsValue(counts) }
        return .object(fields)
    }

    static func small(_ index: Int) -> TypeAtlasEntry {
        let name = "C\(index)"
        return TypeAtlasEntry(id: .init(slot: .primary, kind: .objcClass,
            key: .address(UInt64(4096 + index * 16))), kind: .objcClass, name: name,
            superclass: nil, members: [], conformances: [], methods: [], users: [], evidence: .descriptor)
    }
}
