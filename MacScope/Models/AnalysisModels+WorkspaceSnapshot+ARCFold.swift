import Foundation

/// E4 slice A: the catalog-backed (Tier 1) ARC callee set and the import-stub resolver.
///
/// Identity comes only from the unsymbolized `bl` target address, the loader's indirect-symbol
/// table and a fixed allowlist. Rendered pseudocode text is symbolized and renamable, so it is
/// never an identity source. This is a sibling of `executableImportStubTargets`: same stub
/// authority, without the tail-callee void filter, which excludes id-returning retains.
enum ARCCalleeCatalog {
    struct Entry: Hashable, Sendable {
        let family: ARCFamily
        let role: ARCRole
        let isCountVariant: Bool
        let objectRegisterIndex: Int
    }

    /// Key: import symbol with one leading underscore stripped.
    static let entries: [String: Entry] = {
        var table: [String: Entry] = [:]
        func add(_ name: String, _ entry: Entry) {
            // Tier 1 only: the symbol must be declared by the standard signature catalog.
            guard CallSignatureCatalog.standard.signature(for: name) != nil else { return }
            table[name] = entry
        }
        add("objc_retain", Entry(family: .objc, role: .retain, isCountVariant: false, objectRegisterIndex: 0))
        add("objc_release", Entry(family: .objc, role: .release, isCountVariant: false, objectRegisterIndex: 0))
        add("objc_autorelease", Entry(family: .objc, role: .autorelease, isCountVariant: false, objectRegisterIndex: 0))
        add("objc_retainAutoreleasedReturnValue", Entry(family: .objc, role: .retainAutoreleasedReturn,
                                                        isCountVariant: false, objectRegisterIndex: 0))
        for helper in RuntimeSignatureSeeds.objcRegisterHelpers {
            guard let index = Int(helper.objectRegister.dropFirst()) else { continue }
            add(helper.canonicalName, Entry(family: .objc,
                role: helper.operation == .retain ? .retain : .release,
                isCountVariant: false, objectRegisterIndex: index))
        }
        add("swift_errorRetain", Entry(family: .swift, role: .retain, isCountVariant: false, objectRegisterIndex: 0))
        add("swift_errorRelease", Entry(family: .swift, role: .release, isCountVariant: false, objectRegisterIndex: 0))
        for prefix in ["swift_", "swift_nonatomic_"] {
            for (stem, role) in [("retain", ARCRole.retain), ("release", .release),
                                 ("bridgeObjectRetain", .retain), ("bridgeObjectRelease", .release),
                                 ("unknownObjectRetain", .retain), ("unknownObjectRelease", .release)] {
                add(prefix + stem, Entry(family: .swift, role: role, isCountVariant: false, objectRegisterIndex: 0))
                add(prefix + stem + "_n", Entry(family: .swift, role: role, isCountVariant: true, objectRegisterIndex: 0))
            }
        }
        return table
    }()

    static func strippedSymbol(_ name: String) -> String {
        name.hasPrefix("_") ? String(name.dropFirst()) : name
    }

    /// Q6: libraryName is the full LC_LOAD_DYLIB install name (MachOParser `libraryName(for:dylibs:)`
    /// returns `dylibs[ordinal - 1].name`, e.g. `/usr/lib/libobjc.A.dylib`,
    /// `/usr/lib/swift/libswiftCore.dylib`); `dynamic lookup` and `main executable` are the loader's
    /// special strings. Accept nil, or a last path component beginning with the family's library.
    static func libraryMatches(_ libraryName: String?, family: ARCFamily) -> Bool {
        guard let libraryName else { return true }
        let component = libraryName.split(separator: "/").last.map(String.init) ?? libraryName
        switch family {
        case .objc: return component.hasPrefix("libobjc")
        case .swift: return component.hasPrefix("libswiftCore")
        }
    }
}

/// Per-request resolver. Building it indexes the indirect-symbol rows once.
struct ARCStubResolver {
    private let rows: [IndirectSymbolSummary]
    private let byAddress: [UInt64: [IndirectSymbolSummary]]
    private let byName: [String?: [IndirectSymbolSummary]]
    private let functionRanges: [(start: UInt64, end: UInt64)]
    private let functionStarts: Set<UInt64>

    init(analysis: ImageAnalysis) {
        rows = analysis.indirectSymbols
        byAddress = Dictionary(grouping: rows, by: \.address)
        byName = Dictionary(grouping: rows.filter {
            StubCallSymbolicator.linkageSlotClass(for: $0) == .executableImportStub
        }, by: \.symbolName)
        functionRanges = analysis.functions.map { ($0.startAddress, $0.endAddress) }
        functionStarts = Set(analysis.functions.map(\.startAddress))
    }

    func identity(at address: UInt64) -> ARCCalleeIdentity? {
        guard let matches = byAddress[address], matches.count == 1, let entry = matches.first,
              !functionStarts.contains(entry.address),
              StubCallSymbolicator.linkageSlotClass(for: entry) == .executableImportStub,
              !entry.isLocal, !entry.isAbsolute,
              let name = entry.symbolName, !name.isEmpty,
              byName[name]?.count == 1,
              entry.entrySize > 0,
              !entry.address.addingReportingOverflow(UInt64(entry.entrySize)).overflow,
              !functionRanges.contains(where: { $0.start <= entry.address && entry.address < $0.end }),
              !rows.contains(where: { other in
                  guard other.address != entry.address else { return false }
                  return other.address < entry.address
                      ? entry.address - other.address < UInt64(other.entrySize)
                      : other.address - entry.address < UInt64(entry.entrySize)
              }) else { return nil }
        let symbol = ARCCalleeCatalog.strippedSymbol(name)
        guard let known = ARCCalleeCatalog.entries[symbol],
              ARCCalleeCatalog.libraryMatches(entry.libraryName, family: known.family) else { return nil }
        return ARCCalleeIdentity(family: known.family, role: known.role, importSymbol: symbol,
            libraryName: entry.libraryName, isCountVariant: known.isCountVariant,
            objectRegisterIndex: known.objectRegisterIndex)
    }
}

extension WorkspaceSnapshot {
    /// Unsymbolized `bl` row address -> ARC identity, for the function selected by `target`.
    /// The rows come from the export index (numeric targets), not from the symbolized target rows.
    func arcFoldCallSites(
        for target: (function: FunctionSummary, instructions: [InstructionRow])?, in slot: ImageSlot
    ) -> [UInt64: ARCCalleeIdentity] {
        guard let target, let analysis = analysis(in: slot) else { return [:] }
        let excluded = codeExcludedAddresses(in: slot)
        let body = analysis.exportInstructionIndex().instructions(
            start: target.function.startAddress, end: target.function.endAddress
        ).filter { !excluded.contains($0.address) }
        let resolver = ARCStubResolver(analysis: analysis)
        var memo: [UInt64: ARCCalleeIdentity?] = [:]
        var sites: [UInt64: ARCCalleeIdentity] = [:]
        for row in body where row.mnemonic.lowercased() == "bl" {
            guard let token = row.operands.split(separator: ",").last
                .map({ String($0).trimmingCharacters(in: .whitespaces) }),
                  let targetAddress = BranchTargetSymbolizer.parseHexAddress(token) else { continue }
            let identity: ARCCalleeIdentity?
            if let cached = memo[targetAddress] { identity = cached }
            else {
                identity = resolver.identity(at: targetAddress)
                memo[targetAddress] = .some(identity)
            }
            if let identity { sites[row.address] = identity }
        }
        return sites
    }
}
