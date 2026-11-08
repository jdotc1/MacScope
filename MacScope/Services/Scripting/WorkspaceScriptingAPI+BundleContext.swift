import CoreFoundation
import Darwin
import Foundation

extension WorkspaceScriptingAPI {
    nonisolated static func selectedSliceValue(_ image: BinaryImage?) -> ScriptValue {
        guard let fact = image?.machOSelectedSliceFact else { return .null }
        let row = MachOUniversalSlice(index: fact.selectedSliceIndex, cpuType: fact.cpuType,
            cpuSubtype: fact.cpuSubtype, offset: 0, size: 0, alignment: 0)
        return .object([
            "containerKind": .string(fact.containerKind.rawValue),
            "index": .int(Int64(fact.selectedSliceIndex)), "count": .int(Int64(fact.sliceCount)),
            "architecture": .string(row.architectureName), "cpuType": .int(Int64(fact.cpuType)),
            "cpuSubtype": .int(Int64(fact.cpuSubtype)),
        ])
    }

    nonisolated static func sliceListing(data: Data, fact: MachOSelectedSliceFact?) throws -> ScriptValue {
        let table: [MachOUniversalSlice]?
        do { table = try MachOParser().strictUniversalSlices(in: data) }
        catch {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .malformedInput,
                detail: "the fat header is malformed: \(error)"))
        }
        let changed = ScriptingError.structuredRefusal(MCPToolRefusal(code: .preconditionFailed,
            detail: "the file changed since analysis: the fat table no longer matches the analysed slice"))
        if let table {
            if let fact {
                guard fact.containerKind == .universal, fact.sliceCount == table.count,
                      let row = table.first(where: { $0.index == fact.selectedSliceIndex }),
                      row.cpuType == fact.cpuType else { throw changed }
            }
            return .object([
                "containerKind": .string("universal"), "sliceCount": .int(Int64(table.count)),
                "selectedSliceIndex": fact.map { .int(Int64($0.selectedSliceIndex)) } ?? .null,
                "slices": .array(table.map { sliceRow($0, selected: $0.index == fact?.selectedSliceIndex,
                                                     alignment: .int(Int64($0.alignment))) }),
            ])
        }
        guard let fact else {
            return .object(["containerKind": .null, "sliceCount": .int(0), "slices": .array([]),
                "reason": .string("the image is not a Mach-O file or has no slice record")])
        }
        guard fact.containerKind == .thin, thinHeaderMatches(data, fact: fact) else { throw changed }
        let row = MachOUniversalSlice(index: 0, cpuType: fact.cpuType, cpuSubtype: fact.cpuSubtype,
                                     offset: 0, size: UInt64(data.count), alignment: 0)
        return .object(["containerKind": .string("thin"), "sliceCount": .int(1),
            "selectedSliceIndex": .int(0), "slices": .array([sliceRow(row, selected: true, alignment: .null)])])
    }

    /// Read only the thin header prefix, using its own magic rather than host byte order.
    /// MachOBinaryLoader projects the raw header CPU words into the analysed fact.
    /// This is a consistency check, not a fresh file-identity or full-header validation.
    nonisolated private static func thinHeaderMatches(_ data: Data, fact: MachOSelectedSliceFact) -> Bool {
        let bytes = Array(data.prefix(12))
        guard bytes.count == 12 else { return false }
        func word(at offset: Int, littleEndian: Bool) -> UInt32 {
            let indices = littleEndian ? [3, 2, 1, 0] : [0, 1, 2, 3]
            return indices.reduce(UInt32(0)) { ($0 << 8) | UInt32(bytes[offset + $1]) }
        }
        let littleEndian: Bool
        switch word(at: 0, littleEndian: false) {
        case 0xfeedface, 0xfeedfacf: littleEndian = false
        case 0xcefaedfe, 0xcffaedfe: littleEndian = true
        default: return false
        }
        return Int32(bitPattern: word(at: 4, littleEndian: littleEndian)) == fact.cpuType
            && Int32(bitPattern: word(at: 8, littleEndian: littleEndian)) == fact.cpuSubtype
    }

    nonisolated private static func sliceRow(_ row: MachOUniversalSlice, selected: Bool,
                                             alignment: ScriptValue) -> ScriptValue {
        .object(["index": .int(Int64(row.index)), "architecture": .string(row.architectureName),
            "cpuType": .int(Int64(row.cpuType)), "cpuSubtype": .int(Int64(row.cpuSubtype)),
            "offset": .hex(row.offset), "size": .hex(row.size), "alignment": alignment,
            "selected": .bool(selected)])
    }

    nonisolated private static func bundleContextImage(_ arguments: ScriptValue, snapshot: WorkspaceSnapshot)
        throws -> (slot: ImageSlot, image: BinaryImage, file: URL) {
        let slot = try resolveImageSlot(arguments, snapshot: snapshot)
        guard let image = snapshot.binary(in: slot) else {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .unknownSubject,
                detail: "no image is loaded in slot \(slot.rawValue)"))
        }
        let file: URL
        if let path = image.resolvedExecutablePath {
            file = URL(fileURLWithPath: path)
        } else if image.kind == "app bundle" {
            do {
                file = try MachOImportService().resolveExecutable(at: URL(fileURLWithPath: image.path)).executableURL
            } catch {
                throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .preconditionFailed,
                    detail: "the image file cannot be read: \(error.localizedDescription)", retryable: false))
            }
        } else { file = URL(fileURLWithPath: image.path) }
        return (slot, image, file)
    }

    nonisolated static func imageSlices(_ arguments: ScriptValue, snapshot: WorkspaceSnapshot) throws -> ScriptValue {
        let context = try bundleContextImage(arguments, snapshot: snapshot)
        let data: Data
        do { data = try Data(contentsOf: context.file, options: .mappedIfSafe) }
        catch {
            throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .preconditionFailed,
                detail: "the image file cannot be read: \(error.localizedDescription)", retryable: false))
        }
        guard case .object(var fields) = try sliceListing(data: data, fact: context.image.machOSelectedSliceFact)
        else { preconditionFailure("sliceListing returns an object") }
        fields.merge(imageProvenanceFields(slot: context.slot, snapshot: snapshot)) { _, new in new }
        fields["path"] = .string(context.file.path)
        return .object(fields)
    }

    private enum BundlePlistError: LocalizedError {
        case detail(String)
        var errorDescription: String? { switch self { case .detail(let text): return text } }
    }

    /// This reader bounds bundle metadata independently of executable resolution.
    nonisolated static func boundedPlist(at url: URL, maximum: Int = 4_194_304) throws -> [String: Any] {
        guard maximum >= 0, maximum < Int.max else { throw BundlePlistError.detail("invalid Info.plist byte bound") }
        let descriptor = open(url.path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw BundlePlistError.detail("Info.plist cannot be opened: \(url.path)") }
        defer { close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), metadata.st_size >= 0 else {
            throw BundlePlistError.detail("Info.plist is not a regular file")
        }
        guard metadata.st_size <= maximum else { throw BundlePlistError.detail("Info.plist exceeds \(maximum) bytes") }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: min(65_536, maximum + 1))
        while data.count <= maximum {
            let count = Darwin.read(descriptor, &buffer, min(buffer.count, maximum + 1 - data.count))
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw BundlePlistError.detail("Info.plist could not be read") }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
        }
        guard data.count <= maximum else { throw BundlePlistError.detail("Info.plist exceeds \(maximum) bytes") }
        let value = try PropertyListSerialization.propertyList(from: data, format: nil)
        guard let dictionary = value as? [String: Any] else {
            throw BundlePlistError.detail("Info.plist is not a dictionary")
        }
        return dictionary
    }

    nonisolated private static func plistScriptValue(_ value: Any) -> ScriptValue {
        switch value {
        case let number as NSNumber:
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return .bool(number.boolValue) }
            let value = number.doubleValue
            if value.rounded(.towardZero) == value, let integer = Int64(exactly: value) { return .int(integer) }
            return .double(value)
        case let string as String: return .string(string)
        case let values as [Any]: return .array(values.map(plistScriptValue))
        case let values as [String: Any]: return .object(values.mapValues(plistScriptValue))
        default: return .null
        }
    }

    nonisolated private static func enclosingBundle(image: BinaryImage, file: URL) -> URL? {
        if image.kind == "app bundle" { return URL(fileURLWithPath: image.path) }
        let canonicalFile = file.standardizedFileURL.resolvingSymlinksInPath()
        var ancestor = file.deletingLastPathComponent()
        while ancestor.path != "/" {
            if ancestor.pathExtension.caseInsensitiveCompare("app") == .orderedSame {
                guard let resolved = try? MachOImportService().resolveExecutable(at: ancestor).executableURL,
                      resolved.standardizedFileURL.resolvingSymlinksInPath() == canonicalFile else { return nil }
                return ancestor
            }
            let parent = ancestor.deletingLastPathComponent()
            guard parent != ancestor else { break }
            ancestor = parent
        }
        return nil
    }

    nonisolated static func bundleInfo(_ arguments: ScriptValue, snapshot: WorkspaceSnapshot) throws -> ScriptValue {
        let context = try bundleContextImage(arguments, snapshot: snapshot)
        let image = context.image
        var fields = imageProvenanceFields(slot: context.slot, snapshot: snapshot)
        fields["path"] = .string(context.file.path)
        fields["uuid"] = image.metadata.uuid.map(ScriptValue.string) ?? .null
        fields["platform"] = image.metadata.platformName.map(ScriptValue.string) ?? .null
        fields["minimumOSVersion"] = image.metadata.minimumOSVersion.map(ScriptValue.string) ?? .null
        fields["sdkVersion"] = image.metadata.sdkVersion.map(ScriptValue.string) ?? .null
        fields["buildTools"] = .array(image.metadata.buildTools.map(ScriptValue.string))
        if let bundle = enclosingBundle(image: image, file: context.file) {
            let flat = bundle.appendingPathComponent("Info.plist")
            let plistURL = FileManager.default.fileExists(atPath: flat.path)
                ? flat : bundle.appendingPathComponent("Contents/Info.plist")
            do {
                let plist = try boundedPlist(at: plistURL)
                var object: [String: ScriptValue] = ["path": .string(bundle.path), "infoPlistPath": .string(plistURL.path)]
                for (key, source) in [("bundleIdentifier", "CFBundleIdentifier"), ("executable", "CFBundleExecutable"),
                    ("name", "CFBundleName"), ("shortVersion", "CFBundleShortVersionString"),
                    ("version", "CFBundleVersion"), ("packageType", "CFBundlePackageType"),
                    ("minimumSystemVersion", "LSMinimumSystemVersion")] {
                    object[key] = (plist[source] as? String).map(ScriptValue.string) ?? .null
                }
                let types = plist["CFBundleDocumentTypes"] as? [Any] ?? []
                object["documentTypes"] = .array(types.map(plistScriptValue))
                object["documentTypeCount"] = .int(Int64(types.count))
                fields["bundle"] = .object(object)
                // Keep the existing bundle object intact and disclose the separate live read.
                fields["bundleSource"] = .string("live Info.plist read at call time; not tied to the analysed snapshot")
            } catch {
                fields["bundle"] = .null
                fields["bundleReason"] = .string(error.localizedDescription)
            }
        } else {
            fields["bundle"] = .null
            fields["bundleReason"] = .string("the image is not inside an app bundle")
        }
        if let metadata = snapshot.analysis(in: context.slot)?.machOMetadata {
            fields["linkedDylibs"] = .array(metadata.dependentDylibs.map { library in
                .object(["path": .string(library.path), "kind": .string(library.kind),
                    "currentVersion": .string(library.currentVersion),
                    "compatibilityVersion": .string(library.compatibilityVersion), "ordinal": .int(Int64(library.ordinal))])
            })
            let signature = metadata.codeSignature
            let presentation = MachOSignatureCoveragePresentation(imageName: image.name,
                architecture: image.architecture, selectedSliceIndex: image.selectedSliceIndex,
                hasOtherContainerBytes: nil, hasCodeSignature: signature != nil,
                machOSelectedSliceFact: image.machOSelectedSliceFact)
            fields["signing"] = .object([
                "present": .bool(signature != nil), "identifier": signature?.identifier.map(ScriptValue.string) ?? .null,
                "teamIdentifier": signature?.teamIdentifier.map(ScriptValue.string) ?? .null,
                "hashType": signature?.hashTypeName.map(ScriptValue.string) ?? .null,
                "flags": signature?.codeSignatureFlags.map { .string(String(format: "0x%x", $0)) } ?? .null,
                "source": .string(presentation.source), "coverage": .string(presentation.coverage),
                "signature": .string(presentation.signature),
            ])
        } else {
            fields["linkedDylibs"] = .null
            fields["signing"] = .null
            fields["metadataReason"] = .string("load metadata is derived at analysis and is not kept in a reloaded workspace; re-analyse to see dylibs and signing")
        }
        return .object(fields)
    }
}
