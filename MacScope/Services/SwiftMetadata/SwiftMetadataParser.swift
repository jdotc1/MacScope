import Foundation

/// Walks the Swift reflection metadata in a 64-bit Mach-O image to recover nominal types
/// (class/struct/enum) with their stored properties / enum cases:
/// `__swift5_types` → type context descriptor → `__swift5_fieldmd` field descriptor → records.
///
/// **Relative pointers.** Every cross-reference in Swift metadata is a 32-bit *self-relative*
/// pointer: the target VA is `fieldVA + Int32(value)` (value `0` means null). The parser works in
/// virtual-address space and maps VA→file-offset through the section table, exactly like
/// [[macscope-objc-class-parser]]. No chained-fixup resolution is needed for the direct pointers
/// Tier 1 follows; the `rebaseTargets` map is consulted only for *indirect* symbolic references.
///
/// **Correctness over coverage.** Field *names* are always clean C-strings. Field *types* are
/// decoded only when certain — common standard-library substitutions (`Si`→Int…) and single-hop
/// symbolic references resolve to a name; anything exotic yields `typeName == nil` rather than a
/// fabricated type. Every read is range-checked and every walk is bounded, since this parses
/// untrusted input (see [[macscope-parser-security-hardening]]).
struct SwiftMetadataParser {
    struct Section: Hashable, Sendable {
        var name: String
        var address: UInt64
        var fileOffset: UInt64
        var size: UInt64
        var isExecutable: Bool = false
        var isZeroFill: Bool = false
        var segmentName: String? = nil
    }

    let bytes: [UInt8]
    let sections: [Section]
    /// Indirect symbolic-reference GOT slots: location VA → resolved descriptor VA (chained-fixup REBASE).
    let rebaseTargets: [UInt64: UInt64]
    /// GOT slots bound to an EXTERNAL symbol (chained-fixup BIND): location VA → mangled symbol name,
    /// e.g. `_$sSQMp` (Swift.Equatable protocol descriptor). Used to name an external protocol/type a
    /// conformance references. Empty for Tier-1 callers.
    let bindNames: [UInt64: String]
    let metadataAddresses: [UInt64]
    /// Names of defined in-image symbols at candidate async function-pointer records.
    /// Consumers must validate symbol semantics and record bytes before using an extent.
    /// Preserve aliases so conflicting names cannot be hidden by dictionary overwrite.
    let asyncFunctionPointerSymbols: [UInt64: [String]]

    var metadataByDescriptor: [UInt64: UInt64] = [:]
    /// Class metadata address points keyed by descriptor, from the descriptor word at metadata+64.
    /// R1 is the `...N` metadata symbols, R2 the Objective-C class list (a Swift class IS its ObjC class
    /// object). Candidates that disagree, or are not unique, leave the descriptor out (class offsets unknown).
    var classMetadataByDescriptor: [UInt64: UInt64] = [:]
    /// Objective-C-rooted (NSObject) class vectors are link-time values the ObjC runtime may slide. They are
    /// committed only by a caller that will run the ivar cross-check afterwards; everyone else sees nil.
    let allowProvisionalObjCRootedClassOffsets: Bool
    private var methodLinks = SwiftMetadataFunctionExtractor.MethodLinks()

    init(data: Data, sections: [Section], rebaseTargets: [UInt64: UInt64] = [:], bindNames: [UInt64: String] = [:],
         metadataAddresses: [UInt64] = [], asyncFunctionPointerSymbols: [UInt64: [String]] = [:],
         objcClassAddresses: [UInt64] = [], allowProvisionalObjCRootedClassOffsets: Bool = false,
         slotInventory: SwiftSlotInventory = .unknown) {
        self.allowProvisionalObjCRootedClassOffsets = allowProvisionalObjCRootedClassOffsets
        self.bytes = [UInt8](data)
        self.sections = sections
        self.rebaseTargets = rebaseTargets
        self.bindNames = bindNames
        self.metadataAddresses = metadataAddresses
        self.asyncFunctionPointerSymbols = asyncFunctionPointerSymbols
        methodLinks = SwiftMetadataFunctionExtractor.annotatingMethodSymbols(
            SwiftMetadataFunctionExtractor.methodLinks(
                data: data, sections: sections, inventory: slotInventory
            ),
            symbols: asyncFunctionPointerSymbols
        )
        // Exact metadata symbols outrank the shape heuristic around descriptor-pointer fixups.
        // Keep conflicts at either priority unknown: address ordering is not layout evidence.
        let symbols = metadataCandidates(at: metadataAddresses.prefix(Limits.maxTypes))
        let heuristics = metadataCandidates(at: rebaseTargets.keys.lazy.filter { $0 >= 8 }.map { $0 - 8 })
        for (descriptor, addresses) in symbols where addresses.count == 1 {
            metadataByDescriptor[descriptor] = addresses.first
        }
        for (descriptor, addresses) in heuristics where symbols[descriptor] == nil && addresses.count == 1 {
            metadataByDescriptor[descriptor] = addresses.first
        }
        let r1 = classMetadataCandidates(at: metadataAddresses.prefix(Limits.maxTypes))
        let r2 = classMetadataCandidates(at: objcClassAddresses.prefix(Limits.maxTypes))
        for descriptor in Set(r1.keys).union(r2.keys) {
            let first = r1[descriptor] ?? [], second = r2[descriptor] ?? []
            if !first.isEmpty, !second.isEmpty, first != second { continue }   // R1 and R2 disagree
            let all = first.union(second)
            if all.count == 1 { classMetadataByDescriptor[descriptor] = all.first }
        }
    }

    /// Candidate class metadata address points: the word at `address + 64` names the class descriptor
    /// (Metadata.h TargetClassMetadata layout, 64-bit ObjC platforms), as a rebase target or literal.
    private func classMetadataCandidates<S: Sequence>(at addresses: S) -> [UInt64: Set<UInt64>] where S.Element == UInt64 {
        var candidates: [UInt64: Set<UInt64>] = [:]
        for address in addresses where address <= UInt64.max - 72 {
            guard bindNames[address + 64] == nil,
                  let descriptor = rebaseTargets[address + 64] ?? readU64(atVA: address + 64),
                  descriptor != 0 else { continue }
            candidates[descriptor, default: []].insert(address)
        }
        return candidates
    }

    /// Distinct candidate addresses for the same descriptor are ambiguous even if their vectors
    /// happen to agree. A symbol conflict also blocks fallback to weaker heuristic evidence.
    private func metadataCandidates<S: Sequence>(at addresses: S) -> [UInt64: Set<UInt64>] where S.Element == UInt64 {
        var candidates: [UInt64: Set<UInt64>] = [:]
        for address in addresses where address <= UInt64.max - 16 {
            guard readU64(atVA: address) == 0x200,
                  bindNames[address + 8] == nil,
                  let descriptor = rebaseTargets[address + 8] ?? readU64(atVA: address + 8) else { continue }
            candidates[descriptor, default: []].insert(address)
        }
        return candidates
    }

    // Defensive bounds for untrusted input.
    enum Limits {
        static let maxTypes = 200_000
        static let maxFieldsPerType = 65_536
        static let maxStringLength = 4_096
        /// Cap on a context-parent walk (leaf → … → module). Real nesting is a handful deep; the
        /// cap plus a visited set stops a crafted parent cycle or chain from walking forever.
        static let maxParentWalk = 64
    }

    /// `ContextDescriptorKind` is the low 5 bits of `Flags`; the common type-descriptor prefix is
    /// `Flags(u32) Parent(i32) Name(i32) AccessFunction(i32) Fields(i32)`.
    private enum Offset {
        static let parent = 4      // RelativeIndirectablePointer<ContextDescriptor>
        static let name = 8        // RelativeDirectPointer<CChar> to the type name
        static let fields = 16     // RelativeDirectPointer<FieldDescriptor> (0 if none)
        static let superclass = 20   // class descriptors only: RelativeDirectPointer<char> mangled name
        static let fieldRecordSize = 12
        static let fieldDescNumFields = 12
        static let fieldDescHeader = 16
        static let recordMangledType = 4
        static let recordFieldName = 8
    }

    enum ContextKind: UInt32 {
        case module = 0
        case opaque = 4
        case `protocol` = 3
        case `class` = 16
        case `struct` = 17
        case `enum` = 18

        init?(flags: UInt32) {
            self.init(rawValue: flags & 0x1f)
        }

        var mangledKind: UInt8? {
            switch self {
            case .class: return UInt8(ascii: "C")
            case .struct: return UInt8(ascii: "V")
            case .enum: return UInt8(ascii: "O")
            case .protocol: return UInt8(ascii: "P")
            case .module, .opaque: return nil
            }
        }
    }

    private struct DescriptorPath {
        struct Component {
            var name: String
            var kind: UInt8
        }

        var module: String
        var components: [Component]

        var mangledType: String {
            var bytes: [UInt8] = []
            Self.appendMangledIdentifier(module, to: &bytes)
            for component in components {
                Self.appendMangledIdentifier(component.name, to: &bytes)
                bytes.append(component.kind)
            }
            return String(decoding: bytes, as: UTF8.self)
        }

        var unqualifiedName: String {
            components.map(\.name).joined(separator: ".")
        }

        private static func appendMangledIdentifier(_ identifier: String, to bytes: inout [UInt8]) {
            bytes.append(contentsOf: Array(String(identifier.utf8.count).utf8))
            bytes.append(contentsOf: Array(identifier.utf8))
        }
    }

    private struct SplicedFieldMangling {
        var mangled: String
        var modules: Set<String>
        var allowedLocalQualifiedNames: Set<String>
    }

    /// What a symbolic reference points at: a mangled nominal type (module + path, with kind letters)
    /// plus the module and dotted path the demangler will print for it.
    private struct SymbolicTarget {
        var mangled: String
        var module: String
        var unqualifiedName: String
    }

    func parseTypes() -> [SwiftTypeDescriptor] {
        parseTypesReport().types
    }

    /// `parseTypes()` plus the graded failures met on the way (see `MetadataParseDiagnostic`):
    /// an unreadable type descriptor abandons the rest of `__swift5_types`; an unreadable name
    /// or field record skips that one item; an unmodelled descriptor kind is kept with a label;
    /// a context-parent walk that hits the cap or a cycle stops and says so.
    func parseTypesReport() -> (types: [SwiftTypeDescriptor], diagnostics: [MetadataParseDiagnostic],
                                genericAbstentions: [MetadataParseDiagnostic], genericDiagnosticsDropped: Int) {
        guard let typesSection = sections.first(where: { $0.name == "__swift5_types" }) else { return ([], [], [], 0) }
        let count = min(Int(typesSection.size / 4), Limits.maxTypes)
        var result: [SwiftTypeDescriptor] = []
        var diagnostics: [MetadataParseDiagnostic] = []
        for index in 0..<count {
            guard let entryVA = Self.checkedMetadataAddress(from: typesSection.address,
                                                            offset: UInt64(index * 4)) else {
                diagnostics.append(.init(grade: .abandonedList, address: typesSection.address,
                                         message: "Entry address overflows in __swift5_types at index \(index); "
                                             + "abandoned the remaining \(count - index) __swift5_types entries"))
                break
            }
            guard let descriptorVA = resolveRelativePointer(at: entryVA) else {
                diagnostics.append(.init(grade: .skippedItem, address: entryVA,
                                         message: "Null or unreadable __swift5_types entry at \(Self.hex(entryVA))"))
                continue
            }
            guard let flags = readU32(atVA: descriptorVA) else {
                diagnostics.append(.init(grade: .abandonedList, address: descriptorVA,
                                         message: "Cannot read Swift type descriptor at \(Self.hex(descriptorVA)); "
                                             + "abandoned the remaining \(count - index) __swift5_types entries"))
                break
            }
            guard let type = parseTypeDescriptor(at: descriptorVA, flags: flags, diagnostics: &diagnostics) else { continue }
            result.append(type)
        }
        let finished = Self.finishGenericDiagnostics(diagnostics)
        return (result, finished.diagnostics, finished.abstentions, finished.dropped)
    }

    private static func hex(_ value: UInt64) -> String { "0x" + String(value, radix: 16) }

    /// Walks `__swift5_protos` (relative-indirectable pointers) to the in-image protocol descriptors.
    /// An external (bound) or unnameable entry is skipped, never guessed.
    func parseProtocols() -> [SwiftProtocolDescriptor] {
        parseProtocolsReport().protocols
    }

    func parseProtocolsReport() -> (protocols: [SwiftProtocolDescriptor], diagnostics: [MetadataParseDiagnostic],
                                    genericAbstentions: [MetadataParseDiagnostic], genericDiagnosticsDropped: Int) {
        guard let section = sections.first(where: { $0.name == "__swift5_protos" }) else { return ([], [], [], 0) }
        let count = min(Int(section.size / 4), Limits.maxTypes)
        var result: [SwiftProtocolDescriptor] = []
        var diagnostics: [MetadataParseDiagnostic] = []
        for index in 0..<count {
            guard let entryVA = Self.checkedMetadataAddress(from: section.address,
                                                            offset: UInt64(index * 4)) else { break }
            guard let descriptorVA = resolveRelativeIndirectablePointer(at: entryVA),
                  let flags = readU32(atVA: descriptorVA), ContextKind(flags: flags) == .protocol,
                  let name = descriptorName(at: descriptorVA) else { continue }
            var descriptor = SwiftProtocolDescriptor(name: name, descriptorAddress: descriptorVA)
            populateProtocolSignature(&descriptor, diagnostics: &diagnostics)
            result.append(descriptor)
        }
        let finished = Self.finishGenericDiagnostics(diagnostics)
        return (result, finished.diagnostics, finished.abstentions, finished.dropped)
    }

    /// 64-bit `ProtocolConformanceDescriptor` field offsets (protocol@0, typeRef@4, witness@8,
    /// flags@12). The trailing context/conditional data is not needed for the (type, protocol) pair.
    private enum ConformanceOffset {
        static let protocolField: UInt64 = 0
        static let typeRef: UInt64 = 4
        static let flags: UInt64 = 12
    }

    /// Walks `__swift5_proto` → `ProtocolConformanceDescriptor`, recovering `(conforming type,
    /// protocol)` pairs. Tier-1: a conformance is surfaced only when BOTH names resolve in-image —
    /// an external (bound) protocol or an unhandled type-reference kind is skipped, never guessed.
    func parseConformances() -> [SwiftConformance] {
        parseConformancesReport().conformances
    }

    /// `parseConformances()` plus graded failures: an unreadable conformance descriptor abandons
    /// the rest of `__swift5_proto`; an unnameable (external or unhandled) one is skipped as before.
    func parseConformancesReport() -> (conformances: [SwiftConformance], diagnostics: [MetadataParseDiagnostic],
                                       genericAbstentions: [MetadataParseDiagnostic], genericDiagnosticsDropped: Int) {
        guard let section = sections.first(where: { $0.name == "__swift5_proto" }) else { return ([], [], [], 0) }
        let count = min(Int(section.size / 4), Limits.maxTypes)
        var result: [SwiftConformance] = []
        var diagnostics: [MetadataParseDiagnostic] = []
        for index in 0..<count {
            guard let entryVA = Self.checkedMetadataAddress(from: section.address,
                                                            offset: UInt64(index * 4)) else {
                diagnostics.append(.init(grade: .abandonedList, address: section.address,
                                         message: "Entry address overflows in __swift5_proto at index \(index); "
                                             + "abandoned the remaining \(count - index) __swift5_proto entries"))
                break
            }
            guard let descriptorVA = resolveRelativePointer(at: entryVA) else { continue }
            guard let flagsVA = Self.checkedMetadataAddress(from: descriptorVA, offset: ConformanceOffset.flags),
                  readU32(atVA: flagsVA) != nil else {
                diagnostics.append(.init(grade: .abandonedList, address: descriptorVA,
                                         message: "Cannot read protocol conformance descriptor at \(Self.hex(descriptorVA)); "
                                             + "abandoned the remaining \(count - index) __swift5_proto entries"))
                break
            }
            guard let conformance = parseConformance(at: descriptorVA, diagnostics: &diagnostics) else { continue }
            result.append(conformance)
        }
        let finished = Self.finishGenericDiagnostics(diagnostics)
        return (result, finished.diagnostics, finished.abstentions, finished.dropped)
    }

    private func parseConformance(at descriptorVA: UInt64,
                                  diagnostics: inout [MetadataParseDiagnostic]) -> SwiftConformance? {
        guard let flagsVA = Self.checkedMetadataAddress(from: descriptorVA, offset: ConformanceOffset.flags),
              let flags = readU32(atVA: flagsVA),
              let typeRefFieldVA = Self.checkedMetadataAddress(from: descriptorVA, offset: ConformanceOffset.typeRef),
              let typeName = conformingTypeName(descriptorVA: descriptorVA, flags: flags),
              let protocolName = conformanceProtocolName(descriptorVA: descriptorVA) else { return nil }
        let typeRef = resolveRelativePointer(at: typeRefFieldVA)
        let typeDescriptor: UInt64?
        switch (flags >> 3) & 0x7 {
        case 0: typeDescriptor = typeRef
        case 1: typeDescriptor = typeRef.flatMap { bindNames[$0] == nil ? rebaseTargets[$0] : nil }
        default: typeDescriptor = nil
        }
        var conformance = SwiftConformance(typeName: typeName, protocolName: protocolName,
                                descriptorAddress: descriptorVA, typeDescriptorAddress: typeDescriptor,
                                methods: methodLinks.conformances[descriptorVA],
                                typeQualifiedName: conformingTypeQualifiedName(descriptorVA: descriptorVA, flags: flags),
                                protocolQualifiedName: conformanceProtocolQualifiedName(descriptorVA: descriptorVA))
        populateConditionalRequirements(&conformance, flags: flags, diagnostics: &diagnostics)
        populateConformanceWitnesses(&conformance, flags: flags, diagnostics: &diagnostics)
        return conformance
    }

    /// The conforming type, from `typeRef`@4 interpreted by the `TypeReferenceKind` in `flags`
    /// (bits 3–5). Kind 0 = a direct relative pointer to the type's nominal context descriptor;
    /// kind 1 = the same via a GOT slot (rebase-resolved); kind 2 = a direct ObjC class-name string.
    /// Indirect-ObjC (3) and any other kind are not resolved this tier.
    private func conformingTypeName(descriptorVA: UInt64, flags: UInt32) -> String? {
        guard let typeRefFieldVA = Self.checkedMetadataAddress(from: descriptorVA, offset: ConformanceOffset.typeRef) else { return nil }
        switch (flags >> 3) & 0x7 {
        case 0:
            return resolveRelativePointer(at: typeRefFieldVA).flatMap { nominalName(atDescriptor: $0) }
        case 1:
            guard let gotVA = resolveRelativePointer(at: typeRefFieldVA) else { return nil }
            if let inImage = rebaseTargets[gotVA] { return nominalName(atDescriptor: inImage) }
            if let bound = bindNames[gotVA] { return nominalName(fromBoundSymbol: bound, suffix: "Mn") }
            return nil
        case 2:
            return resolveRelativePointer(at: typeRefFieldVA).flatMap { readCString(atVA: $0) }
                .flatMap { $0.isEmpty ? nil : $0 }
        default:
            return nil
        }
    }

    /// The conformed-to protocol name. `protocol`@0 is a `RelativeIndirectablePointer`: the low bit
    /// marks indirection (the target is a GOT slot holding the real pointer). A direct target is the
    /// in-image `ProtocolDescriptor`; an indirect target resolves through a rebase to an in-image
    /// descriptor. A bound (external) protocol has no in-image descriptor here → nil (Tier-2).
    private func conformanceProtocolName(descriptorVA: UInt64) -> String? {
        let fieldVA = descriptorVA &+ ConformanceOffset.protocolField
        guard let raw = readI32(atVA: fieldVA), raw != 0,
              let targetVA = Self.checkedRelativeTarget(from: fieldVA, offset: raw & ~1) else { return nil }
        guard raw & 1 == 1 else { return nominalName(atDescriptor: targetVA) }
        // Indirect: targetVA is a GOT slot — in-image → rebase to the ProtocolDescriptor; EXTERNAL →
        // a bind to the protocol's `…Mp` symbol (Tier-2, e.g. `_$sSQMp` = Swift.Equatable).
        if let inImage = rebaseTargets[targetVA] { return nominalName(atDescriptor: inImage) }
        if let bound = bindNames[targetVA] { return nominalName(fromBoundSymbol: bound, suffix: "Mp") }
        return nil
    }

    private func conformingTypeQualifiedName(descriptorVA: UInt64, flags: UInt32) -> String? {
        guard let typeRefFieldVA = Self.checkedMetadataAddress(from: descriptorVA, offset: ConformanceOffset.typeRef) else { return nil }
        switch (flags >> 3) & 0x7 {
        case 0:
            return resolveRelativePointer(at: typeRefFieldVA).flatMap { qualifiedName(atDescriptor: $0) }
        case 1:
            guard let gotVA = resolveRelativePointer(at: typeRefFieldVA) else { return nil }
            if let inImage = rebaseTargets[gotVA] { return qualifiedName(atDescriptor: inImage) }
            return bindNames[gotVA].flatMap { Self._qualifiedBoundSymbolName($0, suffix: "Mn") }
        default:
            return nil
        }
    }

    private func conformanceProtocolQualifiedName(descriptorVA: UInt64) -> String? {
        let fieldVA = descriptorVA &+ ConformanceOffset.protocolField
        guard let raw = readI32(atVA: fieldVA), raw != 0,
              let targetVA = Self.checkedRelativeTarget(from: fieldVA, offset: raw & ~1) else { return nil }
        guard raw & 1 == 1 else { return qualifiedName(atDescriptor: targetVA) }
        if let inImage = rebaseTargets[targetVA] { return qualifiedName(atDescriptor: inImage) }
        return bindNames[targetVA].flatMap { Self._qualifiedBoundSymbolName($0, suffix: "Mp") }
    }

    /// `Module.Outer.Inner` for a context descriptor, walking leaf → parent → … → module. Anonymous
    /// contexts add nothing; an extension contributes the type it extends (a local descriptor, or an
    /// unmangled stdlib substitution), else a `<ext:mangled>` marker. A parent bound to an external
    /// symbol is named from that symbol. nil if no module is reached, never a guessed one.
    func qualifiedName(atDescriptor descriptorVA: UInt64, depth: Int = 0) -> String? {
        guard depth <= 4 else { return nil }
        var parts: [String] = []   // leaf first
        var currentVA = descriptorVA
        var visited: Set<UInt64> = []
        func joined(_ prefix: String) -> String { ([prefix] + parts.reversed()).joined(separator: ".") }
        for _ in 0..<Limits.maxParentWalk {
            guard visited.insert(currentVA).inserted, let flags = readU32(atVA: currentVA) else { return nil }
            switch flags & 0x1f {
            case 0:
                return descriptorName(at: currentVA).map(joined)
            case 1:
                guard let extended = extendedTypeQualifiedName(ofExtension: currentVA, depth: depth) else {
                    guard let marker = extensionMarker(ofExtension: currentVA) else { return nil }
                    parts.append(marker)
                    break
                }
                return joined(extended)
            case 2:
                break
            case 3, 16, 17, 18:
                guard let name = descriptorName(at: currentVA) else { return nil }
                parts.append(name)
            default:
                return nil
            }
            guard let parentField = Self.checkedMetadataAddress(from: currentVA, offset: UInt64(Offset.parent)),
                  let raw = readI32(atVA: parentField), raw != 0,
                  let target = Self.checkedRelativeTarget(from: parentField, offset: raw & ~1) else { return nil }
            if raw & 1 == 0 { currentVA = target; continue }
            if let inImage = rebaseTargets[target] { currentVA = inImage; continue }
            guard let bound = bindNames[target] else { return nil }
            let external = Self._qualifiedBoundSymbolName(bound, suffix: "Mn")
                ?? Self._qualifiedBoundSymbolName(bound, suffix: "Mm")
            return external.map(joined)
        }
        return nil
    }

    /// An extension descriptor's name field (+8) is the mangled extended type. Only an exact
    /// symbolic reference to a local nominal, or a whole-string stdlib substitution, is named.
    private func extendedTypeQualifiedName(ofExtension descriptorVA: UInt64, depth: Int) -> String? {
        guard let nameField = Self.checkedMetadataAddress(from: descriptorVA, offset: UInt64(Offset.name)),
              let mangledVA = resolveRelativePointer(at: nameField),
              let raw = readMangledBytes(atVA: mangledVA, requiresTerminator: true), let control = raw.first else { return nil }
        if control == 0x01, raw.count >= 5 {
            guard let refField = Self.checkedMetadataAddress(from: mangledVA, offset: 1),
                  let rel = readI32(atVA: refField),
                  let target = Self.checkedRelativeTarget(from: refField, offset: rel) else { return nil }
            return qualifiedName(atDescriptor: target, depth: depth + 1)
        }
        if control == 0x02, raw.count >= 5 {
            guard let refField = Self.checkedMetadataAddress(from: mangledVA, offset: 1),
                  let rel = readI32(atVA: refField),
                  let slot = Self.checkedRelativeTarget(from: refField, offset: rel) else { return nil }
            if let inImage = rebaseTargets[slot] { return qualifiedName(atDescriptor: inImage, depth: depth + 1) }
            return bindNames[slot].flatMap { Self._qualifiedBoundSymbolName($0, suffix: "Mn") }
        }
        guard raw.allSatisfy({ $0 >= 0x20 && $0 < 0x7f }) else { return nil }
        let text = String(decoding: raw, as: UTF8.self)
        return Self.standardMetadataSubstitution(text, suffix: "Mn").map { "Swift." + $0 }
    }

    private func extensionMarker(ofExtension descriptorVA: UInt64) -> String? {
        guard let nameField = Self.checkedMetadataAddress(from: descriptorVA, offset: UInt64(Offset.name)),
              let mangledVA = resolveRelativePointer(at: nameField),
              let raw = readMangledBytes(atVA: mangledVA, requiresTerminator: true) else { return nil }
        return "<ext:\(sanitizedMangled(raw))>"
    }

    /// `Module.Name` for an EXTERNAL descriptor symbol, only when the whole symbol body parses as
    /// `<len><module><len><name>…` (optionally `s` for Swift, kind letters between) or is a known
    /// stdlib substitution (→ `Swift.<name>`). Anything else is nil: the module is never guessed.
    static func _qualifiedBoundSymbolName(_ symbol: String, suffix: String) -> String? {
        var s = symbol
        if s.hasPrefix("_") { s.removeFirst() }
        guard !suffix.isEmpty, s.hasPrefix("$s"), s.hasSuffix(suffix), s.count > 2 + suffix.count else { return nil }
        let body = Array(s.dropFirst(2).dropLast(suffix.count))
        if let simple = standardMetadataSubstitution(String(body), suffix: suffix) { return "Swift." + simple }
        var identifiers: [String] = []
        var words: [String] = []
        var i = 0
        if body.first == "s", body.count > 1, body[1].isNumber { identifiers.append("Swift"); i = 1 }
        while i < body.count {
            guard let identifier = decodeManglingIdentifier(body, index: &i, words: &words) else { return nil }
            identifiers.append(identifier)
            if i < body.count, "CVOP".contains(body[i]) { i += 1 }
        }
        return identifiers.count >= 2 || (suffix == "Mm" && identifiers.count == 1) ? identifiers.joined(separator: ".") : nil
    }

    /// A context descriptor's name is a relative direct pointer at `Offset.name` (+8) — shared by
    /// nominal type descriptors and protocol descriptors (both are `ContextDescriptor`s).
    private func nominalName(atDescriptor descriptorVA: UInt64) -> String? {
        guard let nameField = Self.checkedMetadataAddress(from: descriptorVA, offset: UInt64(Offset.name)),
              let nameVA = resolveRelativePointer(at: nameField),
              let name = readCString(atVA: nameVA), !name.isEmpty else { return nil }
        return name
    }

    /// Extracts the simple nominal name from an EXTERNAL Swift metadata-descriptor symbol
    /// `_$s<X><suffix>` (suffix `Mp` = protocol descriptor, `Mn` = nominal type descriptor): a known
    /// standard-library substitution (e.g. `SQ` → Equatable), else the last length-prefixed identifier
    /// in `<X>` (e.g. `s23CustomStringConvertible` → CustomStringConvertible, `8MyMod8MyProto` →
    /// MyProto). nil when it can't be parsed confidently — never a fabricated name.
    private func nominalName(fromBoundSymbol symbol: String, suffix: String) -> String? {
        Self._extractBoundSymbolName(symbol, suffix: suffix)
    }

    static func _extractBoundSymbolName(_ symbol: String, suffix: String) -> String? {
        var s = symbol
        if s.hasPrefix("_") { s.removeFirst() }
        guard !suffix.isEmpty,
              s.hasPrefix("$s"), s.hasSuffix(suffix), s.count > 2 + suffix.count else { return nil }
        let body = String(s.dropFirst(2).dropLast(suffix.count))
        return Self.standardMetadataSubstitution(body, suffix: suffix) ?? Self.lastManglingIdentifier(in: body)
    }

    /// Two-character standard-library metadata substitutions, derived from `xcrun swift-demangle`.
    /// The tables are suffix-keyed: protocol descriptors (`Mp`) and nominal type descriptors (`Mn`)
    /// accept different `S?` code sets, and an unverified form stays nil rather than fabricating.
    private static func standardMetadataSubstitution(_ body: String, suffix: String) -> String? {
        switch suffix {
        case "Mp":
            switch body {
            case "Se": return "Decodable"
            case "Sj": return "Numeric"
            case "Sk": return "RandomAccessCollection"
            case "Sl": return "Collection"
            case "Sm": return "RangeReplaceableCollection"
            case "St": return "IteratorProtocol"
            case "Sx": return "Strideable"
            case "Sy": return "StringProtocol"
            case "Sz": return "BinaryInteger"
            case "SB": return "BinaryFloatingPoint"
            case "SE": return "Encodable"
            case "SF": return "FloatingPoint"
            case "SG": return "RandomNumberGenerator"
            case "SH": return "Hashable"
            case "SK": return "BidirectionalCollection"
            case "SL": return "Comparable"
            case "SM": return "MutableCollection"
            case "SQ": return "Equatable"
            case "ST": return "Sequence"
            case "SU": return "UnsignedInteger"
            case "SX": return "RangeExpression"
            case "SY": return "RawRepresentable"
            case "SZ": return "SignedInteger"
            default: return nil
            }
        case "Mn":
            switch body {
            case "Sa": return "Array"
            case "Sb": return "Bool"
            case "Sd": return "Double"
            case "Sf": return "Float"
            case "Sh": return "Set"
            case "Si": return "Int"
            case "Sn": return "Range"
            case "Sp": return "UnsafeMutablePointer"
            case "Sq": return "Optional"
            case "Sr": return "UnsafeMutableBufferPointer"
            case "Ss": return "Substring"
            case "Su": return "UInt"
            case "Sv": return "UnsafeMutableRawPointer"
            case "Sw": return "UnsafeMutableRawBufferPointer"
            case "SA": return "AutoreleasingUnsafeMutablePointer"
            case "SD": return "Dictionary"
            case "SI": return "DefaultIndices"
            case "SJ": return "Character"
            case "SN": return "ClosedRange"
            case "SO": return "ObjectIdentifier"
            case "SP": return "UnsafePointer"
            case "SR": return "UnsafeBufferPointer"
            case "SS": return "String"
            case "SV": return "UnsafeRawPointer"
            case "SW": return "UnsafeRawBufferPointer"
            default: return nil
            }
        default:
            return nil
        }
    }

    /// Parses a mangled nominal `<module><name>` (length-prefixed `<len><identifier>` runs, with an
    /// optional single-char module substitution like `s` for the Swift stdlib) and returns the LAST
    /// identifier. A bare protocol/type descriptor mangling carries no generic suffix, so the final
    /// length-prefixed run is the name.
    private static func lastManglingIdentifier(in mangled: String) -> String? {
        let chars = Array(mangled)
        var i = 0
        var words: [String] = []
        var last: String?
        var firstIdentifier: String?
        var identifierEnd = 0
        while i < chars.count {
            // Local declaration contexts have a rendered signature, not a simple dotted path.
            if chars[i] == "L", i + 1 < chars.count, chars[i + 1] == "_" { return nil }
            guard chars[i].isASCII && chars[i].isNumber else { i += 1; continue }
            guard let identifier = decodeManglingIdentifier(chars, index: &i, words: &words) else { return nil }
            if firstIdentifier == nil { firstIdentifier = identifier }
            last = identifier
            identifierEnd = i
        }
        // A discriminator or an unparsed function/generic trailer is not a nominal name.
        let trailer = String(chars[identifierEnd...])
        // AA refers to the first identifier; retain this existing simple-name case.
        if chars.first?.isASCII == true, chars.first?.isNumber == true,
           ["AAC", "AAV", "AAO"].contains(String(trailer.suffix(3))),
           ["", "LLC", "LLV", "LLO"].contains(String(trailer.dropLast(3))) {
            return firstIdentifier
        }
        guard ["", "C", "V", "O", "P", "a"].contains(trailer) else { return nil }
        return last
    }

    /// Decode one ASCII identifier; its word table belongs to the entire symbol.
    /// Swift ABI Mangling.rst, Identifiers; Demangler.cpp, demangleIdentifier().
    /// Punycode and general substitutions remain unsupported here.
    private static func decodeManglingIdentifier(_ chars: [Character], index: inout Int,
                                                 words: inout [String]) -> String? {
        func ascii(_ c: Character) -> UInt8? { c.asciiValue }
        func digit(_ c: Character) -> Bool { ascii(c).map { (48...57).contains($0) } ?? false }
        func lower(_ c: Character) -> Bool { ascii(c).map { (97...122).contains($0) } ?? false }
        func upper(_ c: Character) -> Bool { ascii(c).map { (65...90).contains($0) } ?? false }
        guard index < chars.count, digit(chars[index]) else { return nil }
        var compressed = chars[index] == "0"
        if compressed {
            index += 1
            guard index < chars.count, chars[index] != "0" else { return nil }
        }
        var result = ""
        repeat {
            while compressed && index < chars.count && (lower(chars[index]) || upper(chars[index])) {
                let marker = chars[index]
                let wordIndex = Int(ascii(marker)!) - (lower(marker) ? 97 : 65)
                guard wordIndex < words.count else { return nil }
                result += words[wordIndex]
                index += 1
                if upper(marker) { compressed = false }
            }
            if index < chars.count, chars[index] == "0" {
                index += 1
                break
            }
            var length = 0
            var hasDigits = false
            while index < chars.count, digit(chars[index]) {
                let value = Int(ascii(chars[index])! - 48)
                guard length <= (Int.max - value) / 10 else { return nil }
                length = length * 10 + value
                hasDigits = true
                index += 1
            }
            guard hasDigits, length > 0, length <= chars.count - index else { return nil }
            let literal = Array(chars[index..<(index + length)])
            // Non-ASCII identifiers require the separate Punycode production.
            guard literal.allSatisfy({ $0.isASCII }) else { return nil }
            result += String(literal)
            var start: Int?
            for offset in 0...literal.count {
                let current: Character = offset < literal.count ? literal[offset] : "\0"
                if let begin = start,
                   current == "\0" || current == "_" || (upper(current) && !upper(literal[offset - 1])) {
                    if offset - begin >= 2, words.count < 26 {
                        words.append(String(literal[begin..<offset]))
                    }
                    start = nil
                }
                if start == nil, !digit(current), current != "_", current != "\0" { start = offset }
            }
            index += length
        } while compressed
        return result.isEmpty ? nil : result
    }

    private func parseTypeDescriptor(at descriptorVA: UInt64,
                                     flags: UInt32,
                                     diagnostics: inout [MetadataParseDiagnostic]) -> SwiftTypeDescriptor? {
        guard let nameField = Self.checkedMetadataAddress(from: descriptorVA, offset: UInt64(Offset.name)),
              let nameVA = resolveRelativePointer(at: nameField),
              let name = readCString(atVA: nameVA), !name.isEmpty else {
            diagnostics.append(.init(grade: .skippedItem, address: descriptorVA,
                                     message: "Cannot read the name of the Swift type descriptor at \(Self.hex(descriptorVA))"))
            return nil
        }
        guard let kind = SwiftTypeKind(contextDescriptorKind: flags) else {
            // Unmodelled kind: keep the type, labelled, with no fields — the field-descriptor
            // offset is only known for the modelled class/struct/enum layouts.
            let rawKind = flags & 0x1f
            diagnostics.append(.init(grade: .labelledUnknownKind, address: descriptorVA,
                                     message: "Unknown type kind \(rawKind) at \(Self.hex(descriptorVA))"))
            return SwiftTypeDescriptor(kind: .unknown, name: name, rawKind: rawKind, descriptorAddress: descriptorVA)
        }

        // Only complete non-generic structs and classes can have static offsets; enums are never scanned.
        // Class gate G1: non-generic, no singleton/foreign initialization, no resilient superclass (bit 13).
        let staticStruct = kind == .struct && flags & 0x80 == 0 && (flags >> 16) & 3 == 0
        let staticClass = kind == .class && flags & 0x80 == 0 && (flags >> 16) & 3 == 0
            && (flags >> 16) & (1 << 13) == 0
        var fields: [SwiftField] = []
        var declaredFieldCount: UInt32? = nil
        if let fieldsField = Self.checkedMetadataAddress(from: descriptorVA, offset: UInt64(Offset.fields)),
           let fieldDescVA = resolveRelativePointer(at: fieldsField) {
            fields = parseFieldDescriptor(at: fieldDescVA, diagnostics: &diagnostics)
            if staticStruct || staticClass,
               let countVA = Self.checkedMetadataAddress(from: fieldDescVA, offset: UInt64(Offset.fieldDescNumFields)),
               fieldOffsetScalarSpan(atVA: countVA, width: 4) {
                declaredFieldCount = readU32(atVA: countVA)
            }
        }
        // Struct vectors contain uint32 offsets, indexed by a pointer-sized word offset.
        // Generic and singleton/foreign-initialized metadata are incomplete until runtime.
        if staticStruct,
           let offsets = staticStructFieldOffsets(at: descriptorVA, fieldCount: fields.count,
                                                  declaredFieldCount: declaredFieldCount) {
            for index in fields.indices {
                fields[index].byteOffset = offsets[index]
            }
        }
        if staticClass,
           let minimumStart = classOffsetMinimumStart(at: descriptorVA, diagnostics: &diagnostics),
           let offsets = staticClassFieldOffsets(at: descriptorVA, fieldCount: fields.count,
                                                 declaredFieldCount: declaredFieldCount,
                                                 minimumStart: minimumStart) {
            for index in fields.indices {
                fields[index].byteOffset = offsets[index]
            }
        }
        let context = parentChainFacts(of: descriptorVA)
        // ClassDescriptor.SuperclassType@20 follows the 20-byte TypeContextDescriptor prefix (Metadata.h);
        // null for a root class. Keep unresolved manglings as diagnostics with their reason.
        var superclass: String?
        var superclassUnresolvedReason: String?
        if kind == .class,
           let superclassField = Self.checkedMetadataAddress(from: descriptorVA, offset: UInt64(Offset.superclass)),
           let superclassVA = resolveRelativePointer(at: superclassField) {
            let decoded = decodeFieldType(at: superclassVA, diagnostics: &diagnostics)
            superclass = decoded.typeName ?? decoded.mangled
            superclassUnresolvedReason = decoded.typeName == nil ? (decoded.reason ?? "unreadableType") : nil
        }
        var type = SwiftTypeDescriptor(kind: kind, name: name, fields: fields, descriptorAddress: descriptorVA,
                                   methods: methodLinks.types[descriptorVA],
                                   qualifiedName: qualifiedName(atDescriptor: descriptorVA), superclass: superclass,
                                   superclassUnresolvedReason: superclassUnresolvedReason,
                                   isGeneric: flags & 0x80 != 0, isPrivateOrLocal: context.hasAnonymous,
                                   isImportedCType: context.module == "__C")
        populateGenericSignature(&type, flags: flags, diagnostics: &diagnostics)
        return type
    }

    /// Commit only a complete, uniquely mapped scalar vector, with no skipped field records.
    /// Comparing the nominal count to the surviving fields alone loses the raw record ordinals.
    private func staticStructFieldOffsets(at descriptorVA: UInt64, fieldCount: Int,
                                          declaredFieldCount: UInt32?) -> [UInt64]? {
        guard fieldCount > 0,
              let countsVA = Self.checkedMetadataAddress(from: descriptorVA, offset: 20),
              fieldOffsetScalarSpan(atVA: countsVA, width: 8),
              let count = readU32(atVA: countsVA), Int(count) == fieldCount,
              declaredFieldCount == count,
              let words = readU32(atVA: countsVA + 4), words >= 2,
              let metadata = metadataByDescriptor[descriptorVA],
              let vector = Self.checkedMetadataAddress(from: metadata, offset: UInt64(words) * 8),
              fieldOffsetScalarSpan(atVA: vector, width: UInt64(count) * 4) else { return nil }
        var offsets: [UInt64] = []
        offsets.reserveCapacity(fieldCount)
        for index in 0..<fieldCount {
            // The complete span proves these additions and each four-byte footprint.
            guard let offset = readU32(atVA: vector + UInt64(index) * 4) else { return nil }
            offsets.append(UInt64(offset))
        }
        // Zero is a scalar value, not proof of an unfilled vector: zero-sized fields can
        // share an offset. Do not infer a minimum from the field type or ordinal.
        return offsets
    }

    /// Class ancestry gate G2 (v1): a root Swift class starts after the 16-byte HeapObject header; an
    /// NSObject-rooted class after the 8-byte isa, and only when the caller will cross-check the ivar list.
    /// Any other superclass (in-image Swift, external Swift, other ObjC) returns nil: the class stays unknown.
    private func classOffsetMinimumStart(at descriptorVA: UInt64,
                                         diagnostics: inout [MetadataParseDiagnostic]) -> UInt64? {
        guard let field = Self.checkedMetadataAddress(from: descriptorVA, offset: UInt64(Offset.superclass)),
              let raw = readI32(atVA: field) else { return nil }
        if raw == 0 { return 16 }
        guard allowProvisionalObjCRootedClassOffsets,
              let superVA = resolveRelativePointer(at: field),
              decodeFieldType(at: superVA, diagnostics: &diagnostics).mangled == "So8NSObjectC" else { return nil }
        return 8
    }

    /// Commit only a complete class vector: pointer-sized entries at `metadata + FieldOffsetVectorOffset * 8`
    /// (Metadata.h TargetClassMetadata::getFieldOffsets), none a zero runtime placeholder, non-decreasing,
    /// at or after the superclass-implied start and not past InstanceSize (u32 at metadata+48). Zero is NOT a
    /// scalar here: a class always has a header, so a real field offset is never 0.
    private func staticClassFieldOffsets(at descriptorVA: UInt64, fieldCount: Int,
                                         declaredFieldCount: UInt32?, minimumStart: UInt64) -> [UInt64]? {
        guard fieldCount > 0,
              let countsVA = Self.checkedMetadataAddress(from: descriptorVA, offset: 36),
              fieldOffsetScalarSpan(atVA: countsVA, width: 8),
              let count = readU32(atVA: countsVA), Int(count) == fieldCount,
              declaredFieldCount == count,
              let words = readU32(atVA: countsVA + 4), words >= 10,   // after the ten-word ObjC-compatible header
              let metadata = classMetadataByDescriptor[descriptorVA],
              let vector = Self.checkedMetadataAddress(from: metadata, offset: UInt64(words) * 8),
              fieldOffsetScalarSpan(atVA: vector, width: UInt64(count) * 8),
              let sizeVA = Self.checkedMetadataAddress(from: metadata, offset: 48),
              fieldOffsetScalarSpan(atVA: sizeVA, width: 4),
              let instanceSize = readU32(atVA: sizeVA),
              !classRequiresMetadataUpdate(atMetadata: metadata) else { return nil }
        var offsets: [UInt64] = []
        offsets.reserveCapacity(fieldCount)
        var previous = minimumStart
        for index in 0..<fieldCount {
            guard let offset = readU64(atVA: vector + UInt64(index) * 8),
                  offset != 0, offset >= previous, offset <= UInt64(instanceSize) else { return nil }
            previous = offset
            offsets.append(offset)
        }
        return offsets
    }

    /// `class_ro_t.flags` bit 6 (objc4 RO_HAS_SWIFT_INITIALIZER, objc-runtime-new.h:55: "ro field for Swift
    /// metadata initializer callback") marks Update/FixedOrUpdate classes whose runtime may rewrite offsets.
    /// That this is the compiler's HasMetadataUpdateCallback bit is inferred from the comment, not confirmed
    /// in the Swift sources. An unreadable ro (data word not a file-backed pointer) is not treated as set.
    private func classRequiresMetadataUpdate(atMetadata metadata: UInt64) -> Bool {
        guard let dataVA = Self.checkedMetadataAddress(from: metadata, offset: 32),
              bindNames[dataVA] == nil,
              let raw = rebaseTargets[dataVA] ?? readU64(atVA: dataVA), raw & ~7 != 0,
              let flags = readU32(atVA: raw & ~7) else { return false }
        return flags & (1 << 6) != 0
    }

    /// Offset words must never be interpreted from any part of an eight-byte pointer fixup.
    /// A fixup at `p` overlaps `[address, address + width)` exactly when `address - 7 <= p < address + width`,
    /// so this is `width + 7` dictionary lookups, not a scan of every fixup.
    private func fieldOffsetScalarSpan(atVA address: UInt64, width: UInt64) -> Bool {
        guard uniqueFileBackedSpan(atVA: address, width: width) != nil else { return false }
        let first = address >= 7 ? address - 7 : 0
        let (end, overflow) = address.addingReportingOverflow(width)
        guard !overflow else { return false }
        var pointer = first
        while pointer < end {
            if bindNames[pointer] != nil || rebaseTargets[pointer] != nil { return false }
            pointer += 1
        }
        return true
    }

    /// Walks leaf → parent → … → module once: whether an anonymous context (kind 2) sits in the chain,
    /// and the root module's name. Bounded and cycle-safe like `descriptorPath`; an unresolvable parent
    /// (external or unreadable) ends the walk with whatever was seen, and `module` stays nil.
    private func parentChainFacts(of descriptorVA: UInt64) -> (hasAnonymous: Bool, module: String?) {
        var current = descriptorVA
        var visited: Set<UInt64> = [descriptorVA]
        var hasAnonymous = false
        for _ in 0..<Limits.maxParentWalk {
            guard let parentField = Self.checkedMetadataAddress(from: current, offset: UInt64(Offset.parent)),
                  let parent = resolveRelativeIndirectablePointer(at: parentField),
                  visited.insert(parent).inserted, let flags = readU32(atVA: parent) else { break }
            switch flags & 0x1f {
            case ContextKind.module.rawValue: return (hasAnonymous, descriptorName(at: parent))
            case 2: hasAnonymous = true
            default: break
            }
            current = parent
        }
        return (hasAnonymous, nil)
    }

    private func parseFieldDescriptor(at fieldDescVA: UInt64,
                                      diagnostics: inout [MetadataParseDiagnostic]) -> [SwiftField] {
        // Prove addresses before mapped reads: a wrapped address can otherwise point to
        // unrelated, perfectly readable low-address metadata.
        guard let recordSizeVA = Self.checkedMetadataAddress(from: fieldDescVA, offset: 10),
              let numFieldsVA = Self.checkedMetadataAddress(from: fieldDescVA, offset: UInt64(Offset.fieldDescNumFields)),
              let recordSize = readU16(atVA: recordSizeVA),
              Int(recordSize) == Offset.fieldRecordSize,   // bail on an unexpected record stride
              let numFields = readU32(atVA: numFieldsVA) else { return [] }
        let recordCount = min(Int(numFields), Limits.maxFieldsPerType)

        var fields: [SwiftField] = []
        fields.reserveCapacity(recordCount)
        for record in 0..<recordCount {
            // The capped count and fixed stride bound this product; checked arithmetic
            // also keeps the proof local if those constants change later.
            let (recordBytes, productOverflow) = UInt64(record).multipliedReportingOverflow(by: UInt64(Offset.fieldRecordSize))
            guard !productOverflow,
                  let recordOffset = Self.checkedMetadataAddress(from: UInt64(Offset.fieldDescHeader), offset: recordBytes),
                  let recordVA = Self.checkedMetadataAddress(from: fieldDescVA, offset: recordOffset) else {
                diagnostics.append(.init(grade: .skippedItem, address: fieldDescVA,
                                         message: "Field record address overflows at descriptor \(Self.hex(fieldDescVA)) "
                                             + "(\(recordCount - record) of \(recordCount) skipped)"))
                break
            }
            guard let recordFlags = readU32(atVA: recordVA) else {
                // Past the mapped end: every later record is unreadable too, so stop here.
                diagnostics.append(.init(grade: .skippedItem, address: recordVA,
                                         message: "Cannot read field records from \(Self.hex(recordVA)) "
                                             + "(\(recordCount - record) of \(recordCount) skipped)"))
                break
            }
            guard let nameSlotVA = Self.checkedMetadataAddress(from: recordVA, offset: UInt64(Offset.recordFieldName)),
                  let mangledSlotVA = Self.checkedMetadataAddress(from: recordVA, offset: UInt64(Offset.recordMangledType)) else {
                diagnostics.append(.init(grade: .skippedItem, address: recordVA,
                                         message: "Field record member address overflows at \(Self.hex(recordVA))"))
                continue
            }
            let nameVA = resolveRelativePointer(at: nameSlotVA)
            guard let fieldName = nameVA.flatMap({ readCString(atVA: $0) }), !fieldName.isEmpty else {
                diagnostics.append(.init(grade: .skippedItem, address: recordVA,
                                         message: "Cannot read field record at \(Self.hex(recordVA))"))
                continue
            }

            let mangledVA = resolveRelativePointer(at: mangledSlotVA)
            let decoded = decodeFieldType(at: mangledVA, diagnostics: &diagnostics)
            // FieldRecordFlags: IsIndirectCase = 0x1, IsVar = 0x2.
            let isIndirectCase = (recordFlags & 0x1) != 0
            let isVar = (recordFlags & 0x2) != 0
            fields.append(SwiftField(name: fieldName,
                                     typeName: decoded.typeName,
                                     mangledTypeName: decoded.mangled,
                                     isVar: isVar,
                                     isIndirectCase: isIndirectCase,
                                     unresolvedReason: decoded.typeName == nil && decoded.mangled != nil ? decoded.reason : nil))
        }
        return fields
    }

    // MARK: - Field-type decoding (best effort, never fabricated)

    func decodeFieldType(at mangledVA: UInt64?,
                                 diagnostics: inout [MetadataParseDiagnostic]) -> (typeName: String?, mangled: String?, reason: String?) {
        guard let mangledVA else { return (nil, nil, nil) }
        guard let raw = readMangledBytes(atVA: mangledVA, requiresTerminator: true) else {
            // A partial mangling is diagnostic text only, never input to type resolution.
            guard let partial = readMangledBytes(atVA: mangledVA), !partial.isEmpty else {
                return (nil, nil, nil)
            }
            let printable = sanitizedMangled(partial)
            return (nil, printable.isEmpty ? nil : printable, "unnameableShape")
        }
        guard !raw.isEmpty else { return (nil, nil, nil) }
        if raw.contains(where: { Self.symbolicReferencePayloadWidth($0) != nil }) {
            var reason = "unnameableShape"
            let resolved = splicedFieldMangling(from: raw, baseVA: mangledVA, reason: &reason, diagnostics: &diagnostics).flatMap { spliced -> String? in
                guard let demangled = SwiftDemangler.demangleType(spliced.mangled) else { return nil }
                return Self.fieldTypeName(fromDemangled: demangled,
                                          modules: spliced.modules,
                                          allowedLocalQualifiedNames: spliced.allowedLocalQualifiedNames)
            }
            let printable = sanitizedMangled(raw)
            return (resolved, printable.isEmpty ? nil : printable, resolved == nil ? reason : nil)
        }
        let mangled = String(decoding: raw, as: UTF8.self)
        if let std = standardLibraryType(forMangled: mangled) {
            return (std, mangled, nil)
        }
        // The control-byte guard above means this point is symbolic-reference-free. The demangler
        // route is accepted only when stripping Swift. leaves no foreign-module qualifier.
        if let demangled = SwiftDemangler.demangleType(mangled),
           let stdlib = Self.pureSwiftStdlibName(demangled) {
            return (stdlib, mangled, nil)
        }
        return (nil, mangled, "unnameableShape")
    }

    /// A printable diagnostic form of a mangled type name: each symbolic-reference unit is collapsed
    /// to a single `…` placeholder so
    /// raw little-endian pointer bytes never leak into the string, while the surrounding structural
    /// operators (`Say…G`, `…Sg`, …) are preserved as a hint.
    func sanitizedMangled(_ raw: [UInt8]) -> String {
        var out: [UInt8] = []
        var index = 0
        while index < raw.count {
            let byte = raw[index]
            if let payloadWidth = Self.symbolicReferencePayloadWidth(byte) {
                out.append(contentsOf: Array("…".utf8))
                index += 1 + payloadWidth
            } else {
                out.append(byte)
                index += 1
            }
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Rewrites every embedded symbolic reference into the referenced descriptor's textual Swift
    /// mangling. Each descriptor must be in-image and must walk through nominal parents to a module
    /// context; otherwise the field stays unresolved rather than falling back to a leaf name.
    private func splicedFieldMangling(from raw: [UInt8],
                                      baseVA: UInt64,
                                      reason: inout String,
                                      diagnostics: inout [MetadataParseDiagnostic]) -> SplicedFieldMangling? {
        var out: [UInt8] = []
        var index = 0
        var modules: Set<String> = []
        var allowedLocalQualifiedNames: Set<String> = []

        while index < raw.count {
            let byte = raw[index]
            guard let payloadWidth = Self.symbolicReferencePayloadWidth(byte) else {
                out.append(byte)
                index += 1
                continue
            }

            guard payloadWidth == 4, raw[index] == 0x01 || raw[index] == 0x02 else {
                reason = "unsupportedReference"
                return nil
            }
            guard let target = resolveSymbolicReferencePath(in: raw, at: index, baseVA: baseVA,
                                                            reason: &reason, diagnostics: &diagnostics) else {
                return nil
            }
            modules.insert(target.module)
            allowedLocalQualifiedNames.insert(target.unqualifiedName)
            out.append(contentsOf: Array(target.mangled.utf8))
            index += 1 + payloadWidth
        }

        guard !modules.isEmpty else { return nil }
        return SplicedFieldMangling(mangled: String(decoding: out, as: UTF8.self),
                                    modules: modules,
                                    allowedLocalQualifiedNames: allowedLocalQualifiedNames)
    }

    /// Resolves one symbolic reference to the referenced context descriptor path.
    /// `0x01` = direct relative pointer to the context descriptor; `0x02` = indirect (the relative
    /// pointer targets a GOT slot whose chained-fixup REBASE gives the descriptor VA, or whose BIND
    /// names an external descriptor symbol). A slot with neither fixup entry stays `needsFixup`.
    private func resolveSymbolicReferencePath(in raw: [UInt8],
                                              at index: Int,
                                              baseVA: UInt64,
                                              reason: inout String,
                                              diagnostics: inout [MetadataParseDiagnostic]) -> SymbolicTarget? {
        let control = raw[index]
        guard control == 0x01 || control == 0x02, index + 4 < raw.count else {
            reason = "unsupportedReference"
            return nil
        }
        let relOffset = Int32(bitPattern:
            UInt32(raw[index + 1]) | UInt32(raw[index + 2]) << 8
            | UInt32(raw[index + 3]) << 16 | UInt32(raw[index + 4]) << 24)
        guard let pointerVA = Self.checkedMetadataAddress(from: baseVA, offset: UInt64(index + 1)),
              let targetVA = Self.checkedRelativeTarget(from: pointerVA, offset: relOffset) else {
            reason = control == 0x01 ? "unresolvedDescriptor" : "needsFixup"
            return nil
        }
        let descriptorVA: UInt64
        if control == 0x01 {
            descriptorVA = targetVA
        } else if let rebased = rebaseTargets[targetVA] {
            descriptorVA = rebased
        } else if let symbol = bindNames[targetVA] {
            if let external = externalTarget(forSymbol: symbol) { return external }
            reason = "unresolvedDescriptor"
            return nil
        } else {
            reason = "needsFixup"
            return nil
        }
        guard let path = descriptorPath(at: descriptorVA, diagnostics: &diagnostics) else {
            reason = "unresolvedDescriptor"
            return nil
        }
        return SymbolicTarget(mangled: path.mangledType, module: path.module, unqualifiedName: path.unqualifiedName)
    }

    /// An external nominal-type or protocol descriptor symbol (`_$s10Foundation3URLVMn`, `$sSQMp`):
    /// An Mn body is a complete type mangling. An Mp body omits the protocol kind letter P,
    /// except for complete stdlib substitutions. Restore it before demangling and splicing.
    private func externalTarget(forSymbol symbol: String) -> SymbolicTarget? {
        var name = Substring(symbol)
        if name.hasPrefix("_") { name = name.dropFirst() }
        guard name.hasPrefix("$s"), name.hasSuffix("Mn") || name.hasSuffix("Mp") else { return nil }
        var inner = String(name.dropFirst(2).dropLast(2))
        guard !inner.isEmpty else { return nil }
        if name.hasSuffix("Mp") {
            // Second-level standard protocol substitutions are complete protocol types,
            // not context/name bodies needing a trailing P. Swift 6.3:
            // include/swift/Demangling/StandardTypesMangling.def, Protocol entries.
            let concurrencyProtocol: String?
            switch inner {
            case "ScA": concurrencyProtocol = "Actor"
            case "ScF": concurrencyProtocol = "Executor"
            case "Scf": concurrencyProtocol = "SerialExecutor"
            case "Sch": concurrencyProtocol = "TaskExecutor"
            case "ScI": concurrencyProtocol = "AsyncIteratorProtocol"
            case "Sci": concurrencyProtocol = "AsyncSequence"
            default: concurrencyProtocol = nil
            }
            if let concurrencyProtocol {
                // The field consumer reparses this type. Use the equivalent explicit
                // Swift protocol spelling, including for substitutions it cannot decode.
                let mangled = "s\(concurrencyProtocol.utf8.count)\(concurrencyProtocol)P"
                return SymbolicTarget(mangled: mangled, module: "Swift",
                                      unqualifiedName: concurrencyProtocol)
            }
            if Self.standardMetadataSubstitution(inner, suffix: "Mp") == nil {
                inner += "P"
            }
        }
        guard !inner.utf8.contains(where: { $0 < 0x20 }),
              let demangled = SwiftDemangler.demangleType(inner),
              let dot = demangled.firstIndex(of: "."), dot != demangled.startIndex,
              !demangled.contains(where: { "<>()[]?, ".contains($0) }) else { return nil }
        return SymbolicTarget(mangled: inner,
                              module: String(demangled[..<dot]),
                              unqualifiedName: String(demangled[demangled.index(after: dot)...]))
    }

    /// Walks leaf → parent → … → module. Bounded by `Limits.maxParentWalk` and a visited set:
    /// a cycle or an over-long chain stops the walk with a `walkCapped` diagnostic and yields nil
    /// (the field stays unresolved) instead of looping or guessing a partial path.
    private func descriptorPath(at descriptorVA: UInt64,
                                diagnostics: inout [MetadataParseDiagnostic]) -> DescriptorPath? {
        guard let flags = readU32(atVA: descriptorVA),
              let leafKind = ContextKind(flags: flags),
              let leafMangledKind = leafKind.mangledKind,
              let leafName = descriptorName(at: descriptorVA) else { return nil }

        var components = [DescriptorPath.Component(name: leafName, kind: leafMangledKind)]
        var currentVA = descriptorVA
        var visited: Set<UInt64> = [descriptorVA]

        for _ in 0..<Limits.maxParentWalk {
            guard let parentField = Self.checkedMetadataAddress(from: currentVA, offset: UInt64(Offset.parent)),
                  let parentVA = resolveRelativeIndirectablePointer(at: parentField) else { return nil }
            guard !visited.contains(parentVA) else {
                diagnostics.append(.init(grade: .walkCapped, address: parentVA,
                                         message: "Context-parent cycle at \(Self.hex(parentVA)); "
                                             + "stopped walking from \(Self.hex(descriptorVA))"))
                return nil
            }
            guard let parentFlags = readU32(atVA: parentVA),
                  let parentKind = ContextKind(flags: parentFlags) else { return nil }
            visited.insert(parentVA)

            if parentKind == .module {
                guard let moduleName = descriptorName(at: parentVA) else { return nil }
                return DescriptorPath(module: moduleName, components: Array(components.reversed()))
            }

            guard let parentMangledKind = parentKind.mangledKind,
                  let parentName = descriptorName(at: parentVA) else { return nil }
            components.append(DescriptorPath.Component(name: parentName, kind: parentMangledKind))
            currentVA = parentVA
        }

        diagnostics.append(.init(grade: .walkCapped, address: currentVA,
                                 message: "Way too many parents (> \(Limits.maxParentWalk)), stopping at \(Self.hex(currentVA))"))
        return nil
    }

    func descriptorName(at descriptorVA: UInt64) -> String? {
        guard let nameField = Self.checkedMetadataAddress(from: descriptorVA, offset: UInt64(Offset.name)),
              let nameVA = resolveRelativePointer(at: nameField),
              let name = readCString(atVA: nameVA), !name.isEmpty else { return nil }
        return name
    }

    func resolveRelativeIndirectablePointer(at fieldVA: UInt64) -> UInt64? {
        guard let raw = readI32(atVA: fieldVA), raw != 0,
              let targetVA = Self.checkedRelativeTarget(from: fieldVA, offset: raw & ~1) else { return nil }
        guard raw & 1 == 1 else { return targetVA }
        return rebaseTargets[targetVA]
    }

    /// The common standard-library substitutions that appear as bare stored-property types. Only an
    /// exact whole-string match decodes; partial/generic manglings (e.g. `SaySiG`) stay `nil`.
    private func standardLibraryType(forMangled mangled: String) -> String? {
        switch mangled {
        case "Si": return "Int"
        case "Su": return "UInt"
        case "Sb": return "Bool"
        case "Sd": return "Double"
        case "Sf": return "Float"
        case "SS": return "String"
        case "Ss": return "Substring"
        default: return nil
        }
    }

    static func pureSwiftStdlibName(_ qualified: String) -> String? {
        let stripped = stripSwiftModuleQualifiers(from: qualified)
        // A residual module qualifier (`__C.`, `Foundation.`, a custom module) → not a nameable
        // stdlib type.
        guard !stripped.contains(".") else { return nil }
        // A bare generic parameter / archetype renders as a lone uppercase letter (`A`, `A?`,
        // `Set<A>`, `[A]`) — it names no concrete type, so it must NOT be fabricated as one.
        guard !containsArchetypeToken(stripped) else { return nil }
        return stripped
    }

    private static func fieldTypeName(fromDemangled qualified: String,
                                      modules: Set<String>,
                                      allowedLocalQualifiedNames: Set<String>) -> String? {
        let stripped = stripModuleQualifiers(from: qualified, modules: modules.union(["Swift"]))
        guard !containsArchetypeToken(stripped),
              !containsDisallowedQualifiedName(in: stripped,
                                               allowedLocalQualifiedNames: allowedLocalQualifiedNames) else {
            return nil
        }
        return stripped
    }

    /// True if any identifier token in `s` is archetype-shaped — a single uppercase ASCII letter
    /// optionally followed by digits (`A`, `B`, `A1`). Concrete stdlib type names (`Int`, `Set`,
    /// `UInt`, `String`) never match, since after the leading uppercase they carry lowercase letters.
    private static func containsArchetypeToken(_ s: String) -> Bool {
        var token = ""
        func isIdentifierScalar(_ c: Character) -> Bool {
            c == "_" || (c.isASCII && (c.isLetter || c.isNumber))
        }
        func tokenIsArchetype() -> Bool {
            defer { token = "" }
            guard let first = token.first, first.isASCII, first.isUppercase else { return false }
            return token.dropFirst().allSatisfy { $0.isNumber }
        }
        for character in s {
            if isIdentifierScalar(character) {
                token.append(character)
            } else if tokenIsArchetype() {
                return true
            }
        }
        return tokenIsArchetype()
    }

    private static func stripSwiftModuleQualifiers(from qualified: String) -> String {
        stripModuleQualifiers(from: qualified, modules: ["Swift"])
    }

    private static func stripModuleQualifiers(from qualified: String, modules: Set<String>) -> String {
        var result = ""
        var index = qualified.startIndex
        let sortedModules = modules.filter { !$0.isEmpty }.sorted { $0.count > $1.count }
        while index < qualified.endIndex {
            var matchedModule = false
            for module in sortedModules {
                let prefix = module + "."
                if qualified[index...].hasPrefix(prefix),
                   (index == qualified.startIndex || !isIdentifierContinuation(qualified[qualified.index(before: index)])) {
                    index = qualified.index(index, offsetBy: prefix.count)
                    matchedModule = true
                    break
                }
            }
            guard !matchedModule else { continue }
            result.append(qualified[index])
            index = qualified.index(after: index)
        }
        return result
    }

    private static func containsDisallowedQualifiedName(in text: String,
                                                        allowedLocalQualifiedNames: Set<String>) -> Bool {
        var index = text.startIndex
        while index < text.endIndex {
            guard isIdentifierContinuation(text[index]) else {
                index = text.index(after: index)
                continue
            }

            var parts: [String] = []
            var cursor = index
            while cursor < text.endIndex {
                let partStart = cursor
                while cursor < text.endIndex, isIdentifierContinuation(text[cursor]) {
                    cursor = text.index(after: cursor)
                }
                parts.append(String(text[partStart..<cursor]))

                guard cursor < text.endIndex,
                      text[cursor] == ".",
                      text.index(after: cursor) < text.endIndex,
                      isIdentifierContinuation(text[text.index(after: cursor)]) else {
                    break
                }
                cursor = text.index(after: cursor)
            }

            if parts.count >= 2,
               !allowedLocalQualifiedNames.contains(parts.joined(separator: ".")) {
                return true
            }
            index = cursor
        }
        return false
    }

    private static func isIdentifierContinuation(_ character: Character) -> Bool {
        guard character.unicodeScalars.count == 1,
              let scalar = character.unicodeScalars.first else { return false }
        return scalar == "_" || scalar.properties.isAlphabetic || scalar.properties.numericType != nil
    }

    static func symbolicReferencePayloadWidth(_ control: UInt8) -> Int? {
        guard control >= 0x01, control <= 0x1f else { return nil }
        return control >= 0x18 ? 8 : 4
    }

    // MARK: - Generic metadata decoding

    // Metadata.h:2822–2841: retroactive context, requirements, then pack descriptors.
    private func populateConditionalRequirements(_ conformance: inout SwiftConformance,
                                                  flags: UInt32,
                                                  diagnostics: inout [MetadataParseDiagnostic]) {
        guard let descriptor = conformance.descriptorAddress else { return }
        guard descriptor & 3 == 0 else {
            genericFailure(.invalidConformanceTail, descriptor,
                           "Misaligned conformance descriptor", diagnostics: &diagnostics)
            return
        }
        guard flags & 0x00f0_0007 == 0 else {
            genericFailure(.unsupportedGenericMetadata, descriptor,
                           "Unsupported conformance flag bits while reading conditional requirements",
                           diagnostics: &diagnostics)
            return
        }
        let retroactiveBytes: UInt64 = flags & 0x40 == 0 ? 0 : 4
        let requirementCount = Int((flags >> 8) & 0xff)
        let packCount = Int(flags >> 24)
        let requirementOffset = 16 + retroactiveBytes
        let packOffset = requirementOffset + UInt64(requirementCount) * 12
        let totalBytes = packOffset + UInt64(packCount) * 8
        guard genericSpan(at: descriptor, width: totalBytes, diagnostics: &diagnostics,
                          code: .invalidConformanceTail),
              let requirementsAddress = genericAddress(descriptor, requirementOffset),
              let packsAddress = genericAddress(descriptor, packOffset) else { return }

        if retroactiveBytes != 0, let contextField = genericAddress(descriptor, 16) {
            conformance.retroactiveContextAddress = conditionalRetroactiveContext(
                at: contextField, diagnostics: &diagnostics)
        }
        guard let requirements = genericRequirements(at: requirementsAddress,
                                                       count: requirementCount,
                                                       diagnostics: &diagnostics) else { return }
        conformance.conditionalRequirements = requirements

        var packs: [SwiftGenericPackShape] = []
        for index in 0..<packCount {
            guard let address = genericAddress(packsAddress, UInt64(index) * 8),
                  let indexAddress = genericAddress(address, 2),
                  let shapeAddress = genericAddress(address, 4),
                  let unusedAddress = genericAddress(address, 6),
                  let kind = readU16(atVA: address), let argument = readU16(atVA: indexAddress),
                  let shape = readU16(atVA: shapeAddress), let unused = readU16(atVA: unusedAddress) else {
                genericFailure(.invalidConformanceTail, packsAddress,
                               "Truncated conditional pack-shape descriptor", diagnostics: &diagnostics)
                return
            }
            guard kind <= 1, unused == 0 else {
                genericFailure(.invalidPackShape, address,
                               "Unsupported conditional pack kind or nonzero reserved field",
                               diagnostics: &diagnostics)
                return
            }
            if let previous = packs.last,
               kind < previous.kind || (kind == previous.kind && argument <= previous.index) {
                genericFailure(.invalidPackShape, address,
                               "Conditional pack descriptors are not ordered by kind and argument index",
                               diagnostics: &diagnostics)
                return
            }
            // Conformance tails have no NumShapeClasses header: retain this index without
            // inventing a shape-class bound from the number of conditional requirements.
            packs.append(.init(kind: kind, index: argument, shapeClass: shape, unused: unused))
        }
        conformance.conditionalPackShapes = packs
    }

    private func conditionalRetroactiveContext(at field: UInt64,
                                               diagnostics: inout [MetadataParseDiagnostic]) -> UInt64? {
        guard let raw = readI32(atVA: field) else {
            genericFailure(.invalidConformanceTail, field,
                           "Unreadable retroactive context reference", diagnostics: &diagnostics)
            return nil
        }
        // TargetRelativeContextPointer is nullable (MetadataRef.h:99–102).
        guard raw != 0 else { return nil }
        guard let reference = Self.checkedRelativeTarget(from: field, offset: raw & ~1),
              reference & 3 == 0 else {
            genericFailure(.unresolvedGenericReference, field,
                           "Invalid retroactive context displacement or alignment", diagnostics: &diagnostics)
            return nil
        }
        let context: UInt64
        if raw & 1 != 0 {
            guard reference & 7 == 0 else {
                genericFailure(.unresolvedGenericReference, field,
                               "Misaligned retroactive context pointer slot", diagnostics: &diagnostics)
                return nil
            }
            guard genericSpan(at: reference, width: 8, diagnostics: &diagnostics,
                              code: .unresolvedGenericReference) else { return nil }
            guard bindNames[reference] == nil,
                  let target = rebaseTargets[reference] else {
                genericFailure(.unresolvedGenericReference, field,
                               "Retroactive context has no unambiguous in-image rebase", diagnostics: &diagnostics)
                return nil
            }
            context = target
        } else {
            context = reference
        }
        guard context & 3 == 0,
              genericSpan(at: context, width: 8, diagnostics: &diagnostics,
                          code: .unresolvedGenericReference) else {
            if context & 3 != 0 {
                genericFailure(.unresolvedGenericReference, field,
                               "Misaligned retroactive context target", diagnostics: &diagnostics)
            }
            return nil
        }
        return context
    }

    // Metadata.h:2822–2841 fixes every preceding tail, including conditional pack descriptors.
    private func populateConformanceWitnesses(_ conformance: inout SwiftConformance,
                                               flags: UInt32,
                                               diagnostics: inout [MetadataParseDiagnostic]) {
        guard let descriptor = conformance.descriptorAddress else { return }
        guard descriptor & 3 == 0 else {
            genericFailure(.invalidConformanceTail, descriptor,
                           "Misaligned conformance descriptor", diagnostics: &diagnostics)
            return
        }
        guard flags & 0x00f0_0007 == 0 else {
            genericFailure(.unsupportedGenericMetadata, descriptor,
                           "Unsupported conformance flag bits while reading witness tails",
                           diagnostics: &diagnostics)
            return
        }
        var offset: UInt64 = 16 + (flags & 0x40 == 0 ? 0 : 4)
        offset += UInt64((flags >> 8) & 0xff) * 12
        offset += UInt64(flags >> 24) * 8
        guard genericSpan(at: descriptor, width: offset, diagnostics: &diagnostics,
                          code: .invalidConformanceTail) else { return }

        if flags & (1 << 16) != 0 {
            guard genericSpan(at: descriptor, width: offset + 4, diagnostics: &diagnostics,
                              code: .invalidConformanceTail),
                  let header = genericAddress(descriptor, offset),
                  let count = readU32(atVA: header) else { return }
            guard count <= UInt32(Limits.maxFieldsPerType) else {
                genericFailure(.invalidConformanceTail, header,
                               "Resilient witness count exceeds the bounded record limit", diagnostics: &diagnostics)
                return
            }
            offset += 4
            let witnessesOffset = offset
            offset += UInt64(count) * 8
            guard genericSpan(at: descriptor, width: offset, diagnostics: &diagnostics,
                              code: .invalidConformanceTail) else { return }
            // The count describes complete records even if an external target cannot be named.
            conformance.resilientWitnessCount = count
            for index in 0..<count {
                guard let requirement = genericAddress(descriptor, witnessesOffset + UInt64(index) * 8),
                      let implementation = genericAddress(requirement, 4),
                      let implementationRaw = readU32(atVA: implementation) else { return }
                _ = conformanceWitnessReference(
                    at: requirement, indirectable: true,
                    targetWidth: 8, targetAlignment: 4, nullable: true,
                    diagnostics: &diagnostics)
                if implementationRaw != 0 {
                    genericAbstention(implementation,
                                   "Resilient implementation pointer encoding requires the target compact-function configuration",
                                   diagnostics: &diagnostics)
                }
            }
        } else {
            conformance.resilientWitnessCount = 0
        }

        if flags & (1 << 17) != 0 {
            guard genericSpan(at: descriptor, width: offset + 12, diagnostics: &diagnostics,
                              code: .invalidConformanceTail),
                  let table = genericAddress(descriptor, offset),
                  let privateSize = genericAddress(table, 2),
                  let instantiator = genericAddress(table, 4),
                  let privateData = genericAddress(table, 8),
                  let words = readU16(atVA: table), let privateFlags = readU16(atVA: privateSize),
                  let instantiatorRaw = readU32(atVA: instantiator) else { return }
            if instantiatorRaw != 0 {
                genericAbstention(instantiator,
                               "Compact instantiator pointer retained raw until the target encoding is established",
                               diagnostics: &diagnostics)
            }
            // The private cache contains NumGenericMetadataPrivateDataWords (=16) pointers.
            let privateTarget = conformanceWitnessReference(
                at: privateData, indirectable: false, targetWidth: 16 * 8,
                targetAlignment: 8, nullable: true, permitsZeroFill: true,
                diagnostics: &diagnostics)
            conformance.genericWitnessTable = .init(witnessTableSizeInWords: words,
                                                      privateSizeAndFlags: privateFlags,
                                                      instantiatorAddress: nil,
                                                      privateDataAddress: privateTarget)
            conformance.genericWitnessTable?.instantiatorRawValue = instantiatorRaw
            offset += 12
        }

        if flags & (1 << 19) != 0 {
            guard genericSpan(at: descriptor, width: offset + 8, diagnostics: &diagnostics,
                              code: .invalidConformanceTail),
                  let actor = genericAddress(descriptor, offset) else { return }
            genericAbstention(actor,
                           "Global-actor reference is bounded but not semantically decoded; the supplied ABI count overload disagrees",
                           diagnostics: &diagnostics)
        }
    }

    private func conformanceWitnessReference(at field: UInt64, indirectable: Bool,
                                             targetWidth: UInt64, targetAlignment: UInt64 = 1,
                                             nullable: Bool, permitsZeroFill: Bool = false,
                                             diagnostics: inout [MetadataParseDiagnostic]) -> UInt64? {
        guard let raw = readI32(atVA: field) else {
            genericFailure(.invalidConformanceTail, field,
                           "Unreadable conformance-tail reference", diagnostics: &diagnostics)
            return nil
        }
        if raw == 0 && nullable { return nil }
        guard let reference = Self.checkedRelativeTarget(from: field,
                                                         offset: indirectable ? raw & ~1 : raw) else {
            genericFailure(.unresolvedGenericReference, field,
                           "Overflowing conformance-tail relative reference", diagnostics: &diagnostics)
            return nil
        }
        let target: UInt64
        if indirectable && raw & 1 != 0 {
            guard reference & 7 == 0 else {
                genericFailure(.unresolvedGenericReference, field,
                               "Misaligned conformance-tail pointer slot", diagnostics: &diagnostics)
                return nil
            }
            guard genericSpan(at: reference, width: 8, diagnostics: &diagnostics,
                              code: .unresolvedGenericReference) else { return nil }
            guard bindNames[reference] == nil,
                  let resolved = rebaseTargets[reference] else {
                genericFailure(.unresolvedGenericReference, field,
                               "Conformance-tail target has no unambiguous in-image rebase", diagnostics: &diagnostics)
                return nil
            }
            target = resolved
        } else {
            target = reference
        }
        guard target % targetAlignment == 0 else {
            genericFailure(.unresolvedGenericReference, field,
                           "Misaligned conformance-tail target", diagnostics: &diagnostics)
            return nil
        }
        if permitsZeroFill {
            // A mutable instantiation cache may reside in BSS. Validate its mapped extent;
            // there is no attempt to read cache bytes or realize the witness table.
            guard targetWidth > 0, target <= UInt64.max - (targetWidth - 1) else {
                genericFailure(.unresolvedGenericReference, field,
                               "Overflowing conformance cache extent", diagnostics: &diagnostics)
                return nil
            }
            let owners = sections.filter { section in
                guard section.size > 0 else { return false }
                return target >= section.address
                    ? target - section.address < section.size
                    : section.address - target < targetWidth
            }
            guard owners.count == 1, let owner = owners.first,
                  owner.size >= targetWidth, owner.size - 1 <= UInt64.max - owner.address,
                  target >= owner.address, target - owner.address <= owner.size - targetWidth else {
                genericFailure(.unresolvedGenericReference, field,
                               "Conformance cache extent is unmapped or ambiguous", diagnostics: &diagnostics)
                return nil
            }
            if !owner.isZeroFill,
               !genericSpan(at: target, width: targetWidth, diagnostics: &diagnostics,
                            code: .unresolvedGenericReference) { return nil }
            return target
        }
        guard genericSpan(at: target, width: targetWidth, diagnostics: &diagnostics,
                          code: .unresolvedGenericReference) else { return nil }
        return target
    }

    private func populateGenericSignature(_ type: inout SwiftTypeDescriptor, flags: UInt32,
                                          diagnostics: inout [MetadataParseDiagnostic]) {
        guard flags & 0x80 != 0, let descriptor = type.descriptorAddress else { return }
        guard (flags >> 8) & 0xff == 0 else {
            genericFailure(.unsupportedGenericMetadata, descriptor, "Unsupported generic context descriptor flags",
                           diagnostics: &diagnostics)
            return
        }
        let fixedSize: UInt64
        switch type.kind {
        case .class: fixedSize = 44
        case .struct, .enum: fixedSize = 28
        case .unknown: return
        }
        guard descriptor & 3 == 0,
              genericSpan(at: descriptor, width: fixedSize + 16, diagnostics: &diagnostics),
              let header = genericAddress(descriptor, fixedSize),
              let cache = readI32(atVA: header), let pattern = readI32(atVA: header + 4),
              let numParams = readU16(atVA: header + 8), let numRequirements = readU16(atVA: header + 10),
              let numKeys = readU16(atVA: header + 12), let genericFlags = readU16(atVA: header + 14) else {
            genericFailure(.truncatedGenericMetadata, descriptor, "Incomplete nominal generic header",
                           diagnostics: &diagnostics)
            return
        }
        guard genericFlags & ~UInt16(7) == 0 else {
            genericFailure(.unsupportedGenericMetadata, header, "Unsupported generic context flags",
                           diagnostics: &diagnostics)
            return
        }
        // The included headers reference, but do not define, InvertibleProtocolSet. Its
        // storage width is required before subsequent cumulative counts can be located.
        guard genericFlags & 2 == 0 else {
            genericAbstention(header, "Conditional inverted-protocol set storage is not verified",
                           diagnostics: &diagnostics)
            return
        }
        var cursor = fixedSize + 16
        let afterParams = cursor + UInt64(numParams)
        let requirementsOffset = (afterParams + 3) & ~UInt64(3)
        let requirementsEnd = requirementsOffset + UInt64(numRequirements) * 12
        guard genericSpan(at: descriptor, width: requirementsEnd, diagnostics: &diagnostics),
              let paramsAddress = genericAddress(descriptor, cursor),
              let requirementsAddress = genericAddress(descriptor, requirementsOffset) else { return }
        var parameters: [SwiftGenericParameter] = []
        if numParams != 0 {
            guard let span = uniqueFileBackedSpan(atVA: paramsAddress, width: UInt64(numParams)) else { return }
            for index in 0..<Int(numParams) {
                let raw = bytes[span.fileOffset + index]
                guard raw & 0x40 == 0, raw & 0x3f <= 2 else {
                    genericFailure(.unsupportedGenericMetadata, paramsAddress + UInt64(index),
                                   "Unsupported generic parameter descriptor", diagnostics: &diagnostics)
                    return
                }
                parameters.append(.init(rawValue: raw))
            }
        }
        guard let requirements = genericRequirements(at: requirementsAddress, count: Int(numRequirements),
                                                     diagnostics: &diagnostics) else { return }
        for requirement in requirements {
            if let index = requirement.genericParameterIndex, index != 0xffff, index >= numParams {
                genericFailure(.invalidGenericRequirement, requirement.address,
                               "Inverted requirement generic-parameter index is outside its signature",
                               diagnostics: &diagnostics)
                return
            }
        }
        var signature = SwiftGenericSignature(headerAddress: header, numKeyArguments: numKeys,
            flags: genericFlags, parameters: parameters, requirements: requirements,
            instantiationCacheRelativeOffset: cache, defaultInstantiationPatternRelativeOffset: pattern)
        cursor = requirementsEnd
        let hasPacks = parameters.contains { $0.kind == 1 }
        guard hasPacks == (genericFlags & 1 != 0),
              hasPacks || !requirements.contains(where: { $0.isPackRequirement }) else {
            genericFailure(.invalidPackShape, header, "Pack flag disagrees with generic parameter and requirement descriptors",
                           diagnostics: &diagnostics)
            return
        }
        let scalarKeys = parameters.filter { $0.hasKeyArgument }.count
            + requirements.filter { $0.hasKeyArgument }.count
        if !hasPacks, Int(numKeys) != scalarKeys {
            genericFailure(.invalidGenericRequirement, header, "Scalar key-argument count disagrees with key descriptor flags",
                           diagnostics: &diagnostics)
            return
        }
        if genericFlags & 1 != 0 {
            guard genericSpan(at: descriptor, width: cursor + 4, diagnostics: &diagnostics),
                  let packHeader = genericAddress(descriptor, cursor),
                  let numPacks = readU16(atVA: packHeader), let numShapes = readU16(atVA: packHeader + 2) else { return }
            cursor += 4
            let metadataPacks = parameters.filter { $0.kind == 1 && $0.hasKeyArgument }.count
            let witnessPacks = requirements.filter { $0.isPackRequirement && $0.hasKeyArgument }.count
            guard Int(numPacks) == metadataPacks + witnessPacks,
                  Int(numKeys) >= scalarKeys + Int(numShapes) else {
                genericFailure(.invalidPackShape, packHeader, "Pack count disagrees with key parameter and requirement descriptors",
                               diagnostics: &diagnostics)
                return
            }
            guard genericSpan(at: descriptor, width: cursor + UInt64(numPacks) * 8,
                              diagnostics: &diagnostics) else { return }
            var packs: [SwiftGenericPackShape] = []
            var previous: SwiftGenericPackShape?
            for index in 0..<Int(numPacks) {
                guard let record = genericAddress(descriptor, cursor + UInt64(index) * 8),
                      let kind = readU16(atVA: record), let argument = readU16(atVA: record + 2),
                      let shape = readU16(atVA: record + 4), let unused = readU16(atVA: record + 6) else { return }
                let expectedKind: UInt16 = index < metadataPacks ? 0 : 1
                guard kind == expectedKind, argument >= numShapes, argument < numKeys,
                      shape < numShapes, unused == 0,
                      previous.map({ $0.index < argument }) ?? true else {
                    genericFailure(.invalidPackShape, record, "Invalid pack kind, order, argument index, shape class or reserved field",
                                   diagnostics: &diagnostics)
                    return
                }
                let pack = SwiftGenericPackShape(kind: kind, index: argument, shapeClass: shape, unused: unused)
                packs.append(pack); previous = pack
            }
            signature.numShapeClasses = numShapes
            signature.packShapes = packs
            cursor += UInt64(numPacks) * 8
        }
        let valueCount = parameters.filter { $0.kind == 2 }.count
        guard (valueCount > 0) == (genericFlags & 4 != 0) else {
            genericFailure(.invalidGenericValue, header, "Value flag disagrees with generic parameter descriptors",
                           diagnostics: &diagnostics)
            return
        }
        if genericFlags & 4 != 0 {
            guard genericSpan(at: descriptor, width: cursor + 4, diagnostics: &diagnostics),
                  let valueHeader = genericAddress(descriptor, cursor),
                  let numValues = readU32(atVA: valueHeader) else { return }
            cursor += 4
            guard UInt64(numValues) == UInt64(valueCount) else {
                genericFailure(.invalidGenericValue, valueHeader, "Value count disagrees with generic parameter descriptors",
                               diagnostics: &diagnostics)
                return
            }
            guard genericSpan(at: descriptor, width: cursor + UInt64(numValues) * 4,
                              diagnostics: &diagnostics) else { return }
            var values: [UInt32] = []
            for index in 0..<valueCount {
                guard let record = genericAddress(descriptor, cursor + UInt64(index) * 4),
                      let value = readU32(atVA: record) else { return }
                guard value == 0 else {
                    genericFailure(.invalidGenericValue, record, "Unsupported generic value type",
                                   diagnostics: &diagnostics)
                    return
                }
                values.append(value)
            }
            signature.valueTypes = values
        }
        type.genericSignature = signature
        if flags & 0x20 != 0 {
            genericAbstention(descriptor,
                           "Separate type-level invertible-protocol set is not decoded", diagnostics: &diagnostics)
        }
    }

    // Metadata.h:3343–3358: fixed protocol prefix, then signature requirements and requirements.
    private func populateProtocolSignature(_ descriptor: inout SwiftProtocolDescriptor,
                                            diagnostics: inout [MetadataParseDiagnostic]) {
        let address = descriptor.descriptorAddress
        guard address & 3 == 0 else {
            genericFailure(.invalidGenericRequirement, address,
                           "Misaligned protocol descriptor", diagnostics: &diagnostics)
            return
        }
        guard genericSpan(at: address, width: 24, diagnostics: &diagnostics,
                          code: .truncatedGenericMetadata),
              let flags = readU32(atVA: address),
              let signatureCountField = genericAddress(address, 12),
              let requirementCountField = genericAddress(address, 16),
              let namesField = genericAddress(address, 20),
              let signatureCount = readU32(atVA: signatureCountField),
              let requirementCount = readU32(atVA: requirementCountField) else { return }
        guard flags & 0x0000_ff00 == 0 else {
            genericFailure(.unsupportedGenericMetadata, address,
                           "Unsupported protocol context-descriptor flags", diagnostics: &diagnostics)
            return
        }
        guard signatureCount <= UInt32(Limits.maxFieldsPerType),
              requirementCount <= UInt32(Limits.maxFieldsPerType) else {
            genericFailure(.invalidGenericRequirement, address,
                           "Protocol requirement counts exceed the bounded record limit", diagnostics: &diagnostics)
            return
        }
        let signatureBytes = UInt64(signatureCount) * 12
        let descriptorBytes = 24 + signatureBytes + UInt64(requirementCount) * 8
        guard genericSpan(at: address, width: descriptorBytes, diagnostics: &diagnostics,
                          code: .truncatedGenericMetadata),
              let signatureAddress = genericAddress(address, 24) else { return }
        descriptor.requirementSignature = genericRequirements(at: signatureAddress,
                                                               count: Int(signatureCount),
                                                               diagnostics: &diagnostics)

        guard let namesOffset = readI32(atVA: namesField) else { return }
        if namesOffset == 0 {
            descriptor.associatedTypeNames = []
            return
        }
        guard let namesAddress = Self.checkedRelativeTarget(from: namesField, offset: namesOffset),
              let names = protocolAssociatedNamesString(at: namesAddress, diagnostics: &diagnostics) else {
            genericFailure(.unresolvedGenericReference, namesField,
                           "Unresolved protocol associated-type-name reference", diagnostics: &diagnostics)
            return
        }
        guard !names.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f }) else {
            genericFailure(.invalidGenericRequirement, namesAddress,
                           "Control character in protocol associated-type names", diagnostics: &diagnostics)
            return
        }
        descriptor.associatedTypeNames = names.split(separator: " ").map(String.init)
    }

    private func protocolAssociatedNamesString(at address: UInt64,
                                               diagnostics: inout [MetadataParseDiagnostic]) -> String? {
        for length in 0..<Limits.maxStringLength {
            guard let span = uniqueFileBackedSpan(atVA: address, width: UInt64(length) + 1) else {
                genericFailure(.unresolvedGenericReference, address,
                               "Associated-type names cross their file-backed section", diagnostics: &diagnostics)
                return nil
            }
            if bytes[span.fileOffset + length] == 0 {
                guard let result = String(bytes: bytes[span.fileOffset..<(span.fileOffset + length)],
                                          encoding: .utf8) else {
                    genericFailure(.invalidGenericRequirement, address,
                                   "Invalid UTF-8 in protocol associated-type names", diagnostics: &diagnostics)
                    return nil
                }
                return result
            }
        }
        genericFailure(.unresolvedGenericReference, address,
                       "Unterminated protocol associated-type names", diagnostics: &diagnostics)
        return nil
    }

    /// Marker for a diagnostic that records an intentional abstention (well-formed but unsupported
    /// metadata). Reports route these to `genericAbstentions`, never to `diagnostics`.
    private static func isGenericAbstention(_ diagnostic: MetadataParseDiagnostic) -> Bool {
        diagnostic.grade == .labelledUnknownKind && diagnostic.code == .unsupportedGenericMetadata
    }

    private static let genericDroppedMarker = "generic-diagnostics-dropped"

    /// Counts a generic diagnostic that no longer fits under `MetadataParseDiagnosticLog.maxEntries`,
    /// in a marker entry that `finishGenericDiagnostics` removes and reports as a number.
    private func countDroppedGenericDiagnostic(diagnostics: inout [MetadataParseDiagnostic]) {
        if let index = diagnostics.lastIndex(where: {
            $0.grade == .walkCapped && $0.code == nil && $0.message == Self.genericDroppedMarker
        }) {
            diagnostics[index].address += 1
        } else {
            diagnostics.append(.init(grade: .walkCapped, address: 1, message: Self.genericDroppedMarker))
        }
    }

    /// A genuine generic read failure (stays in `diagnostics`).
    private func genericFailure(_ code: MetadataParseDiagnostic.Code, _ address: UInt64,
                                _ message: String, diagnostics: inout [MetadataParseDiagnostic]) {
        guard diagnostics.count < MetadataParseDiagnosticLog.maxEntries else {
            countDroppedGenericDiagnostic(diagnostics: &diagnostics)
            return
        }
        diagnostics.append(.init(grade: .skippedItem, address: address, message: message, code: code))
    }

    /// An intentional abstention: the metadata is well formed but its meaning is not decoded.
    private func genericAbstention(_ address: UInt64, _ message: String,
                                   diagnostics: inout [MetadataParseDiagnostic]) {
        guard diagnostics.count < MetadataParseDiagnosticLog.maxEntries else {
            countDroppedGenericDiagnostic(diagnostics: &diagnostics)
            return
        }
        diagnostics.append(.init(grade: .labelledUnknownKind, address: address, message: message,
                                 code: .unsupportedGenericMetadata))
    }

    /// Splits abstentions and the dropped-entry marker out of a report's diagnostics.
    private static func finishGenericDiagnostics(_ diagnostics: [MetadataParseDiagnostic])
        -> (diagnostics: [MetadataParseDiagnostic], abstentions: [MetadataParseDiagnostic], dropped: Int) {
        var kept: [MetadataParseDiagnostic] = []
        var abstentions: [MetadataParseDiagnostic] = []
        var dropped = 0
        for diagnostic in diagnostics {
            if diagnostic.grade == .walkCapped, diagnostic.code == nil, diagnostic.message == genericDroppedMarker {
                dropped += Int(clamping: diagnostic.address)
            } else if isGenericAbstention(diagnostic) {
                abstentions.append(diagnostic)
            } else {
                kept.append(diagnostic)
            }
        }
        return (kept, abstentions, dropped)
    }

    private func genericAddress(_ base: UInt64, _ offset: UInt64) -> UInt64? {
        Self.checkedMetadataAddress(from: base, offset: offset)
    }

    private func genericSpan(at address: UInt64, width: UInt64,
                             diagnostics: inout [MetadataParseDiagnostic],
                             code: MetadataParseDiagnostic.Code = .truncatedGenericMetadata) -> Bool {
        guard width > 0 else { return true }
        guard uniqueFileBackedSpan(atVA: address, width: width) != nil else {
            genericFailure(code, address, "Generic metadata span is truncated, overlapping, or not file backed",
                           diagnostics: &diagnostics)
            return false
        }
        return true
    }

    /// The caller selects the record count from an ABI header. The entire array must have one owner.
    func genericRequirements(at address: UInt64, count: Int,
                             diagnostics: inout [MetadataParseDiagnostic]) -> [SwiftGenericRequirement]? {
        guard count >= 0, count <= Limits.maxFieldsPerType else {
            genericFailure(.invalidGenericRequirement, address, "Generic requirement count exceeds the read budget",
                           diagnostics: &diagnostics)
            return nil
        }
        guard count != 0 else { return [] }
        guard address & 3 == 0,
              genericSpan(at: address, width: UInt64(count) * 12, diagnostics: &diagnostics) else {
            if address & 3 != 0 {
                genericFailure(.invalidGenericRequirement, address, "Unaligned generic requirement array",
                               diagnostics: &diagnostics)
            }
            return nil
        }
        var result: [SwiftGenericRequirement] = []
        result.reserveCapacity(count)
        for index in 0..<count {
            guard let record = genericAddress(address, UInt64(index) * 12),
                  let subjectField = genericAddress(record, 4), let payloadField = genericAddress(record, 8),
                  let flags = readU32(atVA: record), let payload = readU32(atVA: payloadField) else { return nil }
            guard flags & ~UInt32(0x1bf) == 0, let kind = SwiftGenericRequirement.Kind(rawValue: flags & 0x1f) else {
                genericFailure(.unsupportedGenericMetadata, record, "Unsupported generic requirement flags or kind",
                               diagnostics: &diagnostics)
                return nil
            }
            guard let subject = genericMangledName(at: subjectField, diagnostics: &diagnostics) else { return nil }
            var requirement = SwiftGenericRequirement(address: record, flags: flags,
                subjectMangledName: subject.mangled, subject: subject.name, rawPayload: payload,
                subjectMangledBytes: subject.bytes)
            if subject.name == nil { requirement.unresolvedReason = "unresolvedSubjectName" }
            switch kind {
            case .sameType, .baseClass, .sameShape:
                guard let target = genericMangledName(at: payloadField, diagnostics: &diagnostics) else { return nil }
                requirement.targetMangledName = target.mangled
                requirement.targetMangledBytes = target.bytes
                requirement.target = target.name
                if target.name == nil { requirement.unresolvedReason = "unresolvedTargetName" }
            case .protocol:
                guard let protocolReference = genericProtocolReference(at: payloadField,
                                                                       diagnostics: &diagnostics) else { return nil }
                requirement.target = protocolReference.name
                requirement.protocolDescriptorAddress = protocolReference.address
                if protocolReference.name == nil { requirement.unresolvedReason = "unresolvedProtocol" }
            case .sameConformance:
                guard let target = genericIndirectTarget(at: payloadField, targetWidth: 16,
                                                         diagnostics: &diagnostics) else { return nil }
                requirement.conformanceDescriptorAddress = target
            case .layout:
                guard payload == 0 else {
                    genericFailure(.unsupportedGenericMetadata, payloadField, "Unsupported generic layout constraint",
                                   diagnostics: &diagnostics)
                    return nil
                }
                requirement.layout = payload
            case .invertedProtocols:
                requirement.genericParameterIndex = UInt16(truncatingIfNeeded: payload)
                requirement.invertedProtocols = UInt16(truncatingIfNeeded: payload >> 16)
                requirement.unresolvedReason = "unverifiedInvertibleProtocolEncoding"
                genericAbstention(payloadField,
                               "Inverted-protocol union retained raw; protocol-set storage and bit names are unspecified",
                               diagnostics: &diagnostics)
            }
            result.append(requirement)
        }
        return result
    }

    /// Bounded mangled names may contain embedded NUL bytes inside symbolic reference payloads.
    private func genericMangledName(at field: UInt64, diagnostics: inout [MetadataParseDiagnostic])
        -> (mangled: String, name: String?, bytes: [UInt8])? {
        guard let target = resolveRelativePointer(at: field),
              let raw = readMangledBytes(atVA: target, requiresTerminator: true), !raw.isEmpty else {
            genericFailure(.invalidGenericRequirement, field, "Null, unreadable or unterminated requirement mangling",
                           diagnostics: &diagnostics)
            return nil
        }
        let mangled: String
        let printable: String
        if raw.contains(where: { Self.symbolicReferencePayloadWidth($0) != nil }) {
            printable = sanitizedMangled(raw)
            var reason = "unresolvedSymbolicReference"
            guard let spliced = splicedFieldMangling(from: raw, baseVA: target, reason: &reason,
                                                    diagnostics: &diagnostics) else {
                genericFailure(.unresolvedGenericReference, field, "Requirement symbolic reference: \(reason)",
                               diagnostics: &diagnostics)
                return (printable, nil, raw)
            }
            mangled = spliced.mangled
        } else {
            guard let text = String(bytes: raw, encoding: .utf8) else {
                genericFailure(.invalidGenericRequirement, field, "Requirement mangling is not UTF-8",
                               diagnostics: &diagnostics)
                return nil
            }
            mangled = text
            printable = text
        }
        let name = SwiftDemangler.demangleType(mangled).map(Self.stripSwiftModuleQualifiers)
        if name == nil {
            genericFailure(.unresolvedGenericReference, field, "Requirement mangling is outside the existing demangler's supported grammar",
                           diagnostics: &diagnostics)
        }
        return (printable, name, raw)
    }

    /// Only Swift protocol references are named here. The absent RelativePointer.h leaves ObjC
    /// IntPair interpretation unverified; such records are conservatively diagnosed and withheld.
    private func genericProtocolReference(at field: UInt64, diagnostics: inout [MetadataParseDiagnostic])
        -> (name: String?, address: UInt64?)? {
        guard let raw = readI32(atVA: field), raw != 0 else {
            genericFailure(.invalidGenericRequirement, field, "Null generic protocol reference", diagnostics: &diagnostics)
            return nil
        }
        guard raw & 2 == 0 else {
            genericAbstention(field, "Tagged Objective-C protocol requirement is not verified",
                           diagnostics: &diagnostics)
            return nil
        }
        guard let target = Self.checkedRelativeTarget(from: field, offset: raw & ~1) else {
            genericFailure(.unresolvedGenericReference, field, "Generic protocol reference overflows the address space",
                           diagnostics: &diagnostics)
            return nil
        }
        var descriptor = target
        if raw & 1 != 0 {
            guard target & 7 == 0 else {
                genericFailure(.unresolvedGenericReference, field, "Misaligned protocol pointer slot",
                               diagnostics: &diagnostics)
                return nil
            }
            guard genericSpan(at: target, width: 8, diagnostics: &diagnostics, code: .unresolvedGenericReference) else { return nil }
            guard !(bindNames[target] != nil && rebaseTargets[target] != nil) else {
                genericFailure(.unresolvedGenericReference, field, "Conflicting bind and rebase for protocol requirement",
                               diagnostics: &diagnostics)
                return nil
            }
            if let bound = bindNames[target] {
                guard let name = nominalName(fromBoundSymbol: bound, suffix: "Mp") else {
                    genericFailure(.unresolvedGenericReference, field, "External protocol symbol cannot be named",
                                   diagnostics: &diagnostics)
                    return (nil, nil)
                }
                return (name, nil)
            }
            guard let rebased = rebaseTargets[target] else {
                genericFailure(.unresolvedGenericReference, field, "Protocol pointer slot needs a fixup",
                               diagnostics: &diagnostics)
                return (nil, nil)
            }
            descriptor = rebased
        }
        guard descriptor & 3 == 0,
              genericSpan(at: descriptor, width: 24, diagnostics: &diagnostics, code: .unresolvedGenericReference),
              let flags = readU32(atVA: descriptor), ContextKind(flags: flags) == .protocol,
              let nameField = genericAddress(descriptor, 8),
              let nameAddress = resolveRelativePointer(at: nameField),
              let name = genericStrictCString(at: nameAddress), !name.isEmpty,
              !name.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f }) else {
            genericFailure(.unresolvedGenericReference, field, "Invalid or unnameable generic protocol descriptor",
                           diagnostics: &diagnostics)
            return nil
        }
        return (name, descriptor)
    }

    private func genericIndirectTarget(at field: UInt64, targetWidth: UInt64,
                                       diagnostics: inout [MetadataParseDiagnostic]) -> UInt64? {
        // SameConformance uses a nonnullable relative pointer: zero is a self displacement.
        guard let raw = readI32(atVA: field),
              let target = Self.checkedRelativeTarget(from: field, offset: raw & ~1) else {
            genericFailure(.unresolvedGenericReference, field, "Invalid relative-indirectable requirement reference",
                           diagnostics: &diagnostics)
            return nil
        }
        let resolved: UInt64
        if raw & 1 != 0 {
            guard target & 7 == 0 else {
                genericFailure(.unresolvedGenericReference, field, "Misaligned conformance pointer slot",
                               diagnostics: &diagnostics)
                return nil
            }
            guard genericSpan(at: target, width: 8, diagnostics: &diagnostics, code: .unresolvedGenericReference),
                  bindNames[target] == nil, let rebased = rebaseTargets[target] else {
                genericFailure(.unresolvedGenericReference, field, "Conformance pointer slot needs an unambiguous rebase",
                               diagnostics: &diagnostics)
                return nil
            }
            resolved = rebased
        } else { resolved = target }
        guard resolved & 3 == 0 else {
            genericFailure(.unresolvedGenericReference, field, "Misaligned same-conformance target",
                           diagnostics: &diagnostics)
            return nil
        }
        guard genericSpan(at: resolved, width: targetWidth, diagnostics: &diagnostics,
                          code: .unresolvedGenericReference) else { return nil }
        return resolved
    }

    private func genericStrictCString(at address: UInt64) -> String? {
        for length in 0..<Limits.maxStringLength {
            guard let span = uniqueFileBackedSpan(atVA: address, width: UInt64(length) + 1) else { return nil }
            if bytes[span.fileOffset + length] == 0 {
                return String(bytes: bytes[span.fileOffset..<(span.fileOffset + length)], encoding: .utf8)
            }
        }
        return nil
    }

    // MARK: - Bounds-checked primitives

    /// A complete file-backed footprint owned by exactly one section. Every intersecting
    /// section counts, even if it cannot cover the whole read or is zero-fill.
    func uniqueFileBackedSpan(atVA va: UInt64, width: UInt64) -> (section: Section, fileOffset: Int)? {
        guard width > 0, va <= UInt64.max - (width - 1) else { return nil }
        var owner: Section?
        for section in sections where section.size > 0 {
            // Subtraction avoids trusting a potentially wrapping section end. A malformed
            // competing section still creates ambiguity wherever its declared extent overlaps.
            let intersects = va >= section.address
                ? va - section.address < section.size
                : section.address - va < width
            guard intersects else { continue }
            guard owner == nil else { return nil }
            owner = section
        }
        guard let section = owner, !section.isZeroFill,
              section.size >= width,
              section.size - 1 <= UInt64.max - section.address,
              va >= section.address else { return nil }
        let delta = va - section.address
        guard delta <= section.size - width else { return nil }
        let (fileStart, overflow) = section.fileOffset.addingReportingOverflow(delta)
        guard !overflow, fileStart <= UInt64.max - (width - 1),
              let offset = Int(exactly: fileStart), offset <= bytes.count,
              width <= UInt64(bytes.count - offset) else { return nil }
        return (section, offset)
    }

    /// First-containing-section translation only; callers prove their own byte footprint.
    /// Zero-fill and overlapping sections retain their original ordering semantics.
    func fileOffset(forVA va: UInt64) -> Int? {
        for section in sections where section.size > 0 {
            let (end, rangeOverflow) = section.address.addingReportingOverflow(section.size)
            // A wrapped exclusive end never matched the old predicate. Keep looking,
            // including when the mathematical end is UInt64.max + 1.
            guard !rangeOverflow else { continue }
            if va >= section.address, va < end {
                let delta = va - section.address
                let (offset, offsetOverflow) = section.fileOffset.addingReportingOverflow(delta)
                // A matching section shadows later mappings even when translation fails.
                guard !offsetOverflow else { return nil }
                return Int(exactly: offset)
            }
        }
        return nil
    }

    /// Reads a 32-bit self-relative pointer at `fieldVA`; returns the target VA (`fieldVA + value`)
    /// or nil if the slot is unmapped, the value is 0 (null), or the target is outside UInt64.
    func resolveRelativePointer(at fieldVA: UInt64) -> UInt64? {
        guard let raw = readI32(atVA: fieldVA), raw != 0 else { return nil }
        return Self.checkedRelativeTarget(from: fieldVA, offset: raw)
    }

    /// Prove a metadata field address before consulting any mapped bytes or fixup evidence.
    private static func checkedMetadataAddress(from base: UInt64, offset: UInt64) -> UInt64? {
        let (address, overflow) = base.addingReportingOverflow(offset)
        return overflow ? nil : address
    }

    /// Keep the address unsigned; widen before negating so Int32.min has a valid magnitude.
    /// Zero is allowed here because a non-null indirectable word of 1 has zero displacement.
    private static func checkedRelativeTarget(from fieldVA: UInt64, offset: Int32) -> UInt64? {
        let displacement = Int64(offset)
        if displacement >= 0 {
            let (target, overflow) = fieldVA.addingReportingOverflow(UInt64(displacement))
            return overflow ? nil : target
        }
        let (target, underflow) = fieldVA.subtractingReportingOverflow(UInt64(-displacement))
        return underflow ? nil : target
    }

    func readU64(atVA va: UInt64) -> UInt64? {
        guard let span = uniqueFileBackedSpan(atVA: va, width: 8) else { return nil }
        var value: UInt64 = 0
        for index in 0..<8 {
            value |= UInt64(bytes[span.fileOffset + index]) << (index * 8)
        }
        return value
    }

    func readU32(atVA va: UInt64) -> UInt32? {
        guard let span = uniqueFileBackedSpan(atVA: va, width: 4) else { return nil }
        let off = span.fileOffset
        return UInt32(bytes[off]) | UInt32(bytes[off + 1]) << 8
            | UInt32(bytes[off + 2]) << 16 | UInt32(bytes[off + 3]) << 24
    }

    func readI32(atVA va: UInt64) -> Int32? {
        readU32(atVA: va).map { Int32(bitPattern: $0) }
    }

    func readU16(atVA va: UInt64) -> UInt16? {
        guard let span = uniqueFileBackedSpan(atVA: va, width: 2) else { return nil }
        let off = span.fileOffset
        return UInt16(bytes[off]) | UInt16(bytes[off + 1]) << 8
    }

    func readCString(atVA va: UInt64) -> String? {
        for length in 0..<Limits.maxStringLength {
            // Prove the entire prefix before inspecting its newest byte, including NUL.
            // Do not require bytes after NUL: they are not part of this string's footprint.
            guard let span = uniqueFileBackedSpan(atVA: va, width: UInt64(length) + 1) else { return nil }
            let end = span.fileOffset + length // The proven width keeps this below bytes.count.
            if bytes[end] == 0 {
                return String(decoding: bytes[span.fileOffset..<end], as: UTF8.self)
            }
        }
        return nil // Unterminated within the existing cap, including the terminator.
    }

    /// Reads a (possibly symbolic-reference-bearing) mangled type name: bytes up to NUL, where bytes
    /// 0x01...0x1F are *not* terminators (they introduce symbolic-reference payloads).
    /// Extension names require a terminator; field decoding retains partial bytes for diagnostics.
    func readMangledBytes(atVA va: UInt64, requiresTerminator: Bool = false) -> [UInt8]? {
        var cursor = 0
        var out: [UInt8] = []
        while cursor < Limits.maxStringLength {
            // Prove the entire prefix, including a possible NUL, before reading its next byte.
            guard let span = uniqueFileBackedSpan(atVA: va, width: UInt64(cursor) + 1) else {
                return cursor == 0 || requiresTerminator ? nil : out
            }
            let byte = bytes[span.fileOffset + cursor]
            if byte == 0 { return out }
            out.append(byte)
            // Preserve the consumed control on a truncated payload, but copy no partial payload.
            if let payloadWidth = Self.symbolicReferencePayloadWidth(byte) {
                guard payloadWidth < Limits.maxStringLength - cursor,
                      let payloadSpan = uniqueFileBackedSpan(atVA: va,
                          width: UInt64(cursor + 1 + payloadWidth)) else {
                    return requiresTerminator ? nil : out
                }
                for offset in 1...payloadWidth {
                    out.append(bytes[payloadSpan.fileOffset + cursor + offset])
                }
                cursor += 1 + payloadWidth
            } else {
                cursor += 1
            }
        }
        return requiresTerminator ? nil : out
    }
}
