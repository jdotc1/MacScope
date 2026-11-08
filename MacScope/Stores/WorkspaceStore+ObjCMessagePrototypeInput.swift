import Foundation

// Production input adapter for `ObjCMessagePrototypeResolver` (OSR-1 PR B, slice 2a).
// Nothing in the decompile path calls it yet. Every source is qualified against the slot's
// current image or its map stays empty (fail closed); there is no fallback.
//
// `debugABIByImplementation` is filled only from the same qualified declarations admitted
// to `declarationsByImplementation`, using the ABI shapes the DWARF reader bound from the
// type DIEs (never from spellings). Only authoritative, non-variadic declarations get an
// entry, with every parameter including self and _cmd in order; any other admitted
// declaration is left out so the resolver keeps its classification.
extension WorkspaceStore {
    /// Upper bound on distinct implementations considered per function.
    static let maximumObjCMessageCandidateImplementations = 512

    func objcMessagePrototypeInput(
        for function: MacIRFunction,
        in slot: ImageSlot
    ) -> ObjCMessagePrototypeResolver.Input? {
        guard let analysis = snapshot.analysis(in: slot),
              snapshot.binary(in: slot) != nil,
              let end = function.endAddress, end > function.startAddress else { return nil }

        // Calls and the selectors named by structured MacIR evidence.
        var callAddresses: [UInt64] = []
        var evidenceSelectors: Set<String> = []
        for instruction in function.instructions {
            guard case let .call(frame, _) = instruction.operation else { continue }
            callAddresses.append(instruction.source.address)
            if let name = frame.arguments.fixedArgument(at: 1)?.selectorEvidence?.name {
                evidenceSelectors.insert(name)
            }
        }

        // Effective instruction bytes and the direct BL target decoded from those same bytes.
        let index = analysis.exportInstructionIndex()
        var bytesByAddress: [UInt64: [UInt8]] = [:]
        var directTargetByAddress: [UInt64: UInt64] = [:]
        for address in callAddresses {
            let (limit, overflow) = address.addingReportingOverflow(4)
            guard !overflow else { continue }
            let rows = index.instructions(start: address, end: limit)
            guard rows.count == 1, rows[0].address == address,
                  !index.loaderExcludedAddresses.contains(address),
                  snapshot.patch(at: ImageAddress(slot: slot, address: address)) == nil,
                  let bytes = Self.fourBytes(fromHexText: rows[0].bytes) else { continue }
            bytesByAddress[address] = bytes
            if let target = Self.directBranchLinkTarget(bytes: bytes, at: address) {
                directTargetByAddress[address] = target
            }
        }

        // Callable symbols at the decoded targets: loader raw linkage names and loader
        // executable import stubs only, and only when the address has exactly one name.
        let targets = Set(directTargetByAddress.values)
        var loaderNames: [UInt64: Set<String>] = [:]
        for symbol in analysis.symbols {
            guard let address = symbol.address, targets.contains(address),
                  let raw = symbol.rawLinkageName, !raw.isEmpty else { continue }
            loaderNames[address, default: []].insert(raw)
        }
        var indirectRowAddresses: Set<UInt64> = []
        for row in analysis.indirectSymbols where targets.contains(row.address) {
            indirectRowAddresses.insert(row.address)
            guard StubCallSymbolicator.linkageSlotClass(for: row) == .executableImportStub,
                  !row.isLocal, !row.isAbsolute,
                  let name = row.symbolName, !name.isEmpty else { continue }
            loaderNames[row.address, default: []].insert(name)
        }
        var callableSymbolByAddress: [UInt64: String] = [:]
        for (address, names) in loaderNames where names.count == 1 {
            callableSymbolByAddress[address] = names.first
        }

        // Verified selector stubs: recovered `__objc_stubs` symbols only. The recovery's
        // output is cross-checked against the image's selector table and section, and a
        // loader symbol or indirect row at the address defeats it. Names alone never count.
        let selectorNames = Set(analysis.objcSelectors.values)
        let stubSections = analysis.sections.filter {
            $0.name.split(separator: ",").last == "__objc_stubs" && !$0.isZeroFill
        }
        var stubCandidates: [UInt64: Set<String>] = [:]
        for symbol in analysis.symbols {
            guard symbol.kind == "stub", symbol.rawLinkageName == nil,
                  let address = symbol.address, targets.contains(address),
                  symbol.name.hasPrefix(ObjCStubSelectorRecovery.symbolPrefix) else { continue }
            let selector = String(symbol.name.dropFirst(ObjCStubSelectorRecovery.symbolPrefix.count))
            guard !selector.isEmpty, selectorNames.contains(selector),
                  loaderNames[address] == nil, !indirectRowAddresses.contains(address),
                  stubSections.contains(where: {
                      address >= $0.address && address - $0.address < $0.size
                  }) else { continue }
            stubCandidates[address, default: []].insert(selector)
        }
        var verifiedSelectorStubByAddress: [UInt64: String] = [:]
        for (address, selectors) in stubCandidates where selectors.count == 1 {
            let selector = selectors.first!
            verifiedSelectorStubByAddress[address] = selector
            callableSymbolByAddress[address] = ObjCStubSelectorRecovery.symbolPrefix + selector
            evidenceSelectors.insert(selector)
        }

        // Declarations: candidate implementations are those carrying a selector this function
        // can send. The batch must pass the same provenance checks as the signature candidates
        // (generation, owner binary, image UUID, slice, architecture, SDK, installation, seal).
        // Variadic and non-authoritative declarations are passed through on purpose so the
        // resolver classifies them (fixedness-unproven); the signature-candidate helper
        // would drop them.
        var implementations: Set<UInt64> = []
        func collect(_ methods: [ObjCMethod]) {
            for method in methods where evidenceSelectors.contains(method.selector) {
                if let implementation = method.implementation { implementations.insert(implementation) }
            }
        }
        for objcClass in analysis.objcClasses {
            collect(objcClass.classMethods); collect(objcClass.instanceMethods)
        }
        for category in analysis.objcCategories {
            collect(category.classMethods); collect(category.instanceMethods)
        }
        var declarations: [UInt64: DWARFFunctionDeclaration] = [:]
        var debugABI: [UInt64: ObjCMessageABIComparison.DebugPrototype] = [:]
        if implementations.count <= Self.maximumObjCMessageCandidateImplementations,
           let batch = objcSignatureDeclarations[slot],
           let binary = snapshot.binary(in: slot),
           batch.generation == objcDeclarationSourceGenerations[slot],
           batch.binaryID == binary.id,
           batch.imageUUID == binary.metadata.uuid.flatMap(UUID.init(uuidString:)),
           batch.seal.uuid == batch.imageUUID,
           batch.selectedSliceIndex == binary.selectedSliceIndex,
           batch.machOSelectedSliceFact == binary.machOSelectedSliceFact,
           batch.architecture == binary.architecture,
           batch.sdkVersion == binary.metadata.sdkVersion,
           batch.documentInstallationID == documentInstallationID {
            for implementation in implementations.sorted() {
                if let declaration = batch.declarations[implementation] {
                    declarations[implementation] = declaration
                    if declaration.hasAuthoritativeParameterList, !declaration.isVariadic {
                        debugABI[implementation] = .init(
                            returnType: .init(spelling: declaration.returnType ?? "",
                                              shape: Self.abiShape(declaration.returnShape)),
                            parameters: declaration.parameters.map {
                                .init(spelling: $0.type ?? "", shape: Self.abiShape($0.shape))
                            }
                        )
                    }
                }
            }
        }

        let allOverrides = snapshot.functionSignatureOverrides(in: slot)
        let overrides = allOverrides.filter { implementations.contains($0.key) }

        return .init(
            function: function,
            classes: analysis.objcClasses,
            categories: analysis.objcCategories,
            declarationsByImplementation: declarations,
            signatureOverrides: overrides,
            debugABIByImplementation: debugABI,
            instructionAuthority: .init(
                bytesByAddress: bytesByAddress,
                directTargetByAddress: directTargetByAddress,
                callableSymbolByAddress: callableSymbolByAddress,
                verifiedSelectorStubByAddress: verifiedSelectorStubByAddress,
                functionRange: function.startAddress ..< end
            )
        )
    }

    /// Exhaustive 1:1 mapping from the DWARF binder's shape to the comparison shape.
    static func abiShape(_ shape: DWARFTypeShape) -> ObjCMessageABIComparison.Shape {
        switch shape {
        case .s8: return .s8
        case .u8: return .u8
        case .s16: return .s16
        case .u16: return .u16
        case .s32: return .s32
        case .u32: return .u32
        case .s64: return .s64
        case .u64: return .u64
        case .bool: return .bool
        case .f32: return .f32
        case .f64: return .f64
        case .object: return .object
        case .classPointer: return .classPointer
        case .selector: return .selector
        case .block: return .block
        case .dataPointer: return .dataPointer
        case .void: return .void
        case .lossyEnum(.s32): return .lossyEnum(.s32)
        case .lossyEnum(.other): return .lossyEnum(.other)
        case .unknown: return .unknown
        }
    }

    private static func fourBytes(fromHexText text: String) -> [UInt8]? {
        let tokens = text.split(separator: " ")
        guard tokens.count == 4 else { return nil }
        var bytes: [UInt8] = []
        for token in tokens {
            guard token.count == 2, let byte = UInt8(token, radix: 16) else { return nil }
            bytes.append(byte)
        }
        return bytes
    }

    /// ARM64 `BL imm26` target, decoded from little-endian instruction bytes.
    private static func directBranchLinkTarget(bytes: [UInt8], at address: UInt64) -> UInt64? {
        guard bytes.count == 4 else { return nil }
        let word = UInt32(bytes[0]) | UInt32(bytes[1]) << 8 | UInt32(bytes[2]) << 16 | UInt32(bytes[3]) << 24
        guard word & 0xFC00_0000 == 0x9400_0000 else { return nil }
        let delta = Int64(Int32(bitPattern: (word & 0x03FF_FFFF) << 6) >> 4)
        let (target, overflow) = Int64(exactly: address).map { $0.addingReportingOverflow(delta) } ?? (0, true)
        guard !overflow, target >= 0 else { return nil }
        return UInt64(target)
    }
}
