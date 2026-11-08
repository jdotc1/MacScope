import Foundation

struct NativePreparedFunction: Sendable {
    let image: NativeExecutionImage
    let function: FunctionSummary
    let evidence: NativeFunctionPrototypeEvidence
    let globals: [NativeExecutionObservedGlobal]
}

enum NativeFunctionPreparation {
    /// Consumes already-admitted analysis bytes. It does not repeat their digest verification.
    static func prepare(binary: BinaryImage, function: FunctionSummary, analysis: ImageAnalysis) throws -> NativePreparedFunction {
        guard binary.artifactIntegrityState == .verified,
              let artifact = binary.artifactIdentity, artifact.architectureVariant == .arm64,
              let uuid = artifact.uuid,
              let witness = binary.containerAdmissionWitness, witness.selectedSliceIdentity == artifact,
              let stamp = witness.sourceFileStamp,
              stamp.byteCount == witness.containerByteCount,
              UInt64(analysis.imageBytes.count) == artifact.selectedSliceByteCount else {
            throw NativeExecutionError.unavailable("Open the original macOS ARM64 executable again to establish its current source-file binding.")
        }
        guard NativeExecutionFileStamp.capture(path: stamp.canonicalPath) == stamp else {
            throw NativeExecutionError.unavailable("The executable changed since it was analyzed. Open the current file before running a function.")
        }
        let options = MachOParseOptions(recoverStringLiterals: false, recoverObjectiveCMetadata: false,
            recoverSwiftMetadata: false, parseCodeSignature: false, requestedSliceIndex: nil)
        let file = try MachOParser().parse(analysis.imageBytes, options: options)
        guard file.header.fileType == 2, file.header.cpuType == artifact.rawCPUType,
              file.header.cpuSubtype == artifact.rawCPUSubtype,
              file.buildVersion?.platform == MachOConstants.platformMacOS
                || (file.buildVersion == nil && file.legacyMinimumOSVersion?.platformName == "macOS") else {
            throw NativeExecutionError.unavailable("Native calls currently require a macOS ARM64 executable or app main executable.")
        }
        guard file.loadCommands.filter({ $0.command == 0x8000_0028 }).count == 1,
              file.entryPointOffset != nil, file.entryPointVirtualAddress == nil,
              let entry = file.entryPointAddress,
              file.uuid.flatMap({ UUID(uuidString: $0.stringValue) }) == uuid else {
            throw NativeExecutionError.unavailable("The executable does not establish one exact LC_MAIN entry and image UUID.")
        }
        guard !file.encryptionInfos.contains(where: \.isActive) else {
            throw NativeExecutionError.unavailable("Encrypted executable images are not supported for native function calls.")
        }
        let regions = file.segments.compactMap { segment -> NativeExecutionImageRegion? in
            guard segment.vmSize > 0, segment.initialProtection & 1 != 0 else { return nil }
            return NativeExecutionImageRegion(name: segment.name, staticAddress: segment.vmAddress,
                byteCount: segment.vmSize, permissions: UInt8(truncatingIfNeeded: segment.initialProtection))
        }
        guard !regions.isEmpty, regions.count <= 128,
              regions.allSatisfy({ $0.byteCount <= UInt64.max - $0.staticAddress }) else {
            throw NativeExecutionError.unavailable("The executable image layout exceeds the native-call limit.")
        }
        let ordered = regions.sorted { $0.staticAddress < $1.staticAddress }
        for pair in zip(ordered, ordered.dropFirst()) {
            guard pair.0.byteCount <= UInt64.max - pair.0.staticAddress,
                  pair.0.staticAddress + pair.0.byteCount <= pair.1.staticAddress else {
                throw NativeExecutionError.unavailable("The executable has overlapping or overflowing runtime image regions.")
            }
        }
        let names = analysis.symbols.filter { $0.address == function.startAddress }.map { $0.rawLinkageName ?? $0.name } + [function.name]
        let knownUnsupported = names.contains { name in
            name.hasPrefix("_$s") || name.hasPrefix("$s") || name.hasPrefix("_$S") || name.hasPrefix("_T")
                || name.hasPrefix("-[") || name.hasPrefix("+[") || name.hasPrefix("__ZN") || name.hasPrefix("_ZN")
        }
        var evidence = analysis.nativeFunctionPrototypes[function.startAddress]
        if evidence == nil {
            evidence = NativeFunctionPrototypeResolver(sections: dwarfSections(file: file, bytes: analysis.imageBytes))
                .resolve()[function.startAddress]
        }
        if knownUnsupported {
            evidence = .ineligible("Swift, Objective-C methods and C++ member calling conventions are not supported in this release.")
        }
        let image = NativeExecutionImage(binaryID: binary.id, canonicalPath: stamp.canonicalPath, uuid: uuid,
            selectedSliceSHA256: artifact.selectedSliceSHA256, selectedSliceOffset: witness.sliceOffset,
            selectedSliceByteCount: artifact.selectedSliceByteCount, entryAddress: entry, regions: regions, fileStamp: stamp)
        // Range and alignment admission is shared with the real call request.
        let prototype = try NativeFunctionPrototype(returnType: .void, parameterTypes: [], provenance: .userOverride)
        _ = try NativeFunctionCallRequest(image: image, staticFunctionAddress: function.startAddress, prototype: prototype, arguments: [])
        var seen = Set<UInt64>()
        let globals = analysis.symbols.sorted { ($0.address ?? 0) < ($1.address ?? 0) }.compactMap { symbol -> NativeExecutionObservedGlobal? in
            guard let address = symbol.address, !symbol.name.isEmpty, symbol.name.utf8.count <= 256,
                  seen.insert(address).inserted,
                  let region = regions.first(where: { $0.permissions & 1 != 0 && $0.permissions & 4 == 0
                      && $0.name != "__LINKEDIT" && $0.contains(address) }) else { return nil }
            let available = region.byteCount - (address - region.staticAddress)
            return NativeExecutionObservedGlobal(name: symbol.name, staticAddress: address, byteCount: Int(min(8, available)))
        }
        return NativePreparedFunction(image: image, function: function,
            evidence: evidence ?? .needsExplicitSignature("No complete supported DWARF declaration is available. Confirm a C-compatible signature."),
            globals: Array(globals.prefix(4096)))
    }

    private static func dwarfSections(file: MachOFile, bytes: Data) -> DWARFReader.Sections {
        var result = DWARFReader.Sections()
        for section in file.sections where section.segmentName == "__DWARF" {
            let start = UInt64(section.fileOffset)
            guard section.size <= UInt64(bytes.count), start <= UInt64(bytes.count) - section.size,
                  let first = Int(exactly: start), let count = Int(exactly: section.size) else { continue }
            let data = bytes.subdata(in: first..<(first + count))
            switch section.sectionName {
            case "__debug_info": result.debugInfo = data
            case "__debug_abbrev": result.debugAbbrev = data
            case "__debug_str": result.debugStr = data
            case "__debug_str_offs", "__debug_str_offsets": result.debugStrOffsets = data
            case "__debug_addr": result.debugAddr = data
            default: break
            }
        }
        return result
    }
}
