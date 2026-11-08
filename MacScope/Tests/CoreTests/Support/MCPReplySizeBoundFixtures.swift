// Authored, unrun.
import Foundation
@testable import MacScope

@MainActor
enum MCPReplySizeBoundFixtures {
    static let start: UInt64 = 0x1000065d0
    static var factsArgs: ScriptValue { .object(["address": .hex(start)]) }

    static func asciiName(_ length: Int, ordinal: Int) -> String {
        let suffix = String(ordinal)
        return String(repeating: "Q", count: length - suffix.utf8.count) + suffix
    }

    static func functions(count: Int, name: (Int) -> String) -> WorkspaceStore {
        var analysis = ImageAnalysis()
        analysis.functions = (0..<count).map { index in
            let address = 0x700000000 + UInt64(index * 4)
            return FunctionSummary(id: UUID(), name: name(index), startAddress: address,
                                   endAddress: address + 4, confidence: 0.5)
        }
        return WorkspaceStore(workspaceName: "Synthetic 1291 functions",
            snapshot: WorkspaceSnapshot(binaries: [], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    static func types() -> [TypeAtlasEntry] {
        (0..<450).map { index in
            let kind: TypeAtlasKind = index < 400 ? .objcClass : .objcProtocol
            return TypeAtlasEntry(id: .init(slot: .primary, kind: kind,
                key: .address(0x700000000 + UInt64(index * 16))), kind: kind,
                name: asciiName(128, ordinal: index), superclass: nil, members: [],
                conformances: [], methods: [], users: [], evidence: .descriptor)
        }
    }

    static func facts(nearCap: Bool) -> WorkspaceStore {
        var analysis = ImageAnalysis()
        // 180 escapable bytes + 76 ASCII = 256 bytes, 436 JSON-text bytes.
        let heavy = String(repeating: "\"\\", count: 90) + String(repeating: "Q", count: 76)
        let end = start + (nearCap ? 0x80 : 0x40)
        analysis.functions = [FunctionSummary(id: UUID(), name: nearCap ? heavy : "fixture",
            startAddress: start, endAddress: end, confidence: 1)]
        let names = nearCap ? Array(repeating: heavy, count: 8) :
            ["_objc_opt_class", "_objc_msgSend$writableTypes", "_objc_msgSend$mutableCopy",
             "_objc_msgSend$isRichText", "_objc_msgSend$removeObject:"]
        analysis.symbols = names.enumerated().map { index, name in
            SymbolSummary(id: UUID(), name: name, address: 0x2000 + UInt64(index * 4),
                          kind: "import", libraryName: nil)
        }
        analysis.xrefs = names.indices.reversed().map { index in
            XRef(id: UUID(), from: start + UInt64(index * 4), to: 0x2000 + UInt64(index * 4), kind: "call")
        }
        analysis.stringLiteralCoverage = .complete
        if nearCap {
            for index in 0..<8 {
                let address = 0x3000 + UInt64(index * 4)
                analysis.symbols.append(SymbolSummary(id: UUID(), name: heavy, address: address,
                    kind: "local", libraryName: nil))
                analysis.xrefs.append(XRef(id: UUID(), from: start + 0x20 + UInt64(index * 4),
                    to: address, kind: "data"))
            }
            analysis.basicBlocks = (0..<8).map { index in
                BasicBlockSummary(id: UUID(), functionID: UUID(), startAddress: start + UInt64(index * 16),
                    endAddress: start + UInt64((index + 1) * 16), instructionCount: 4)
            }
            analysis.controlFlowEdges = [ControlFlowEdge(id: UUID(), from: start,
                to: start + 0x40, kind: "branch")]
        } else {
            analysis.xrefs.append(XRef(id: UUID(), from: start, to: 0x2000, kind: "call"))
            analysis.xrefs.append(XRef(id: UUID(), from: start + 0x20, to: 0x3000, kind: "string"))
            analysis.stringLiterals = [StringLiteralSummary(id: UUID(), value: "hello", address: 0x3000,
                sourceSection: "__TEXT,__cstring", byteLength: 6)]
            analysis.constantStrings = ImageConstantStringProvider.build(stringLiterals: analysis.stringLiterals, cfStrings: [:])
            analysis.basicBlocks = [BasicBlockSummary(id: UUID(), functionID: UUID(), startAddress: start,
                endAddress: end, instructionCount: 16)]
            analysis.controlFlowEdges = [ControlFlowEdge(id: UUID(), from: start + 4, to: start + 0x30, kind: "branch"),
                ControlFlowEdge(id: UUID(), from: start + 8, to: start + 0x30, kind: "switch"),
                ControlFlowEdge(id: UUID(), from: start + 12, to: 0x2000, kind: "call"),
                ControlFlowEdge(id: UUID(), from: start + 16, to: start + 20, kind: "fallthrough")]
        }
        let image = BinaryImage(id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            name: "synthetic-1291-facts", path: "/unused/synthetic-1291-facts",
            kind: "Mach-O executable", architecture: "arm64")
        return WorkspaceStore(workspaceName: "Synthetic 1291 facts",
            snapshot: WorkspaceSnapshot(binaries: [image], analysisBySlot: [.primary: analysis]),
            engine: AnalysisEngine(), autosaveScheduler: nil)
    }
}
