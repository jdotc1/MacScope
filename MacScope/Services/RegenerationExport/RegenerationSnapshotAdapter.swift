import Foundation
import CryptoKit

/// Reads existing captured identity and metadata only. StableFunctionID derives an export ID
/// from the same qualified coordinate used by Reconstruction; it grants no acceptance authority.
enum RegenerationSnapshotAdapter {
    static func prepare(snapshot: WorkspaceSnapshot, slot: ImageSlot,
                        application: RegenerationCapturedApplication) throws -> RegenerationProjectInput {
        guard let binary = snapshot.binary(in: slot), let analysis = snapshot.analysis(in: slot),
              let identity = binary.artifactIdentity, binary.artifactIntegrityState == .verified,
              identity.architectureVariant == .arm64,
              let fingerprint = analysis.analysisInputFingerprint,
              fingerprint.binaryID == binary.id, fingerprint.imageSlot == slot,
              fingerprint.binaryPath == binary.path, fingerprint.binaryName == binary.name,
              fingerprint.selectedSliceIndex == binary.selectedSliceIndex,
              fingerprint.artifactIdentity == identity,
              fingerprint.imageBytesSHA256 == identity.selectedSliceSHA256,
              fingerprint.imageByteCount == identity.selectedSliceByteCount,
              analysis.imageBytes.count == identity.selectedSliceByteCount,
              binary.metadata.platformName == nil || binary.metadata.platformName == "macOS" else {
            throw RegenerationError.invalidInput("selected image lacks matching captured macOS arm64 identity")
        }
        let binding = ReconstructionImageBinding(binaryID: binary.id, imageSlot: slot,
            selectedSliceIndex: binary.selectedSliceIndex, architecture: .arm64, machOIdentity: identity)
        var objc: [UInt64: String] = [:]
        for cls in analysis.objcClasses.sorted(by: { $0.name < $1.name }) {
            for method in cls.classMethods + cls.instanceMethods {
                if let address = method.implementation, objc[address] == nil {
                    objc[address] = cls.name + ": " + ObjCTypeEncoding.methodSignature(method)
                }
            }
        }
        for category in analysis.objcCategories.sorted(by: { $0.name < $1.name }) {
            for method in category.classMethods + category.instanceMethods {
                if let address = method.implementation, objc[address] == nil {
                    objc[address] = category.className + " (" + category.name + "): " + ObjCTypeEncoding.methodSignature(method)
                }
            }
        }
        let swiftMethods = Set(analysis.swiftTypes.flatMap { ($0.methods ?? []).compactMap(\.implementation) })
        let swiftSymbols = Set(analysis.symbols.compactMap { symbol -> UInt64? in
            guard let raw = symbol.rawLinkageName,
                  ["_$s", "$s", "_$S", "$S"].contains(where: { raw.hasPrefix($0) }) else { return nil }
            return symbol.address
        })
        var used = Set<UUID>(), aliasCounts: [UUID: Int] = [:], functions: [RegenerationFunctionInput] = []
        for function in analysis.functions.sorted(by: {
            if $0.startAddress != $1.startAddress { return $0.startAddress < $1.startAddress }
            if $0.endAddress != $1.endAddress { return $0.endAddress < $1.endAddress }
            return $0.name < $1.name
        }) {
            var id = ReconstructionStableImageAuthority.stableFunctionID(image: binding,
                analysisFingerprintSHA256: fingerprint.overallSHA256, startAddress: function.startAddress,
                endAddressExclusive: function.endAddress, boundarySchemaVersion: ReconstructionFunctionCoordinate.schemaVersion)
            // Preserve duplicate discovery rows without making export identity depend on
            // their incidental import UUIDs. Equal-name duplicates are interchangeable rows.
            let ordinal = aliasCounts[id, default: 0]
            aliasCounts[id] = ordinal + 1
            if ordinal > 0 { id = aliasID(base: id, name: function.name, ordinal: ordinal) }
            guard used.insert(id).inserted else { throw RegenerationError.invalidInput("function aliases have colliding captured identity") }
            let override = snapshot.signatureOverride(at: ImageAddress(slot: slot, address: function.startAddress))
            var cSignature: RegenerationCSignature?
            if let override, let result = override.returnType, override.variadicState == .fixed,
               case .authoritative(let parameters) = override.parameterList {
                cSignature = .init(returnType: result, parameterTypes: parameters.map(\.type), provenance: "authored signature override")
            }
            let language: RegenerationLanguage
            if objc[function.startAddress] != nil { language = .objc }
            else if swiftMethods.contains(function.startAddress) || swiftSymbols.contains(function.startAddress) { language = .swift }
            else if cSignature != nil { language = .c }
            else { language = .unknown }
            let name = snapshot.addressOverride(at: ImageAddress(slot: slot, address: function.startAddress))?.customName ?? function.name
            functions.append(.init(functionUUID: id, address: function.startAddress, endAddress: function.endAddress,
                name: name, language: language, recoveredDeclaration: objc[function.startAddress], cSignature: cSignature))
        }
        var references = ["Support/ObservedBundleInfo.plist": application.originalInfoPlist,
            "Support/RecoveredObjectiveCInterface.txt": Data(ObjectiveCHeaderRenderer.render(classes: analysis.objcClasses, categories: analysis.objcCategories).utf8),
            "Support/RecoveredSwiftInterface.txt": Data(SwiftInterfaceRenderer.render(types: analysis.swiftTypes, conformances: analysis.swiftConformances).utf8)]
        var diagnostics = application.diagnostics
        if let entitlements = analysis.machOMetadata?.codeSignature?.entitlementsXML {
            references["Support/" + RegenerationEncoding.identifier(application.applicationName) + ".entitlements"] = Data(entitlements.utf8)
        } else if analysis.machOMetadata?.codeSignature?.entitlementsDER == true {
            diagnostics.append("Captured metadata reports DER entitlements without XML source; entitlements were not fabricated.")
        }
        for other in snapshot.binaries where other.slot != slot {
            diagnostics.append("Image slot \(other.slot.rawValue) (\(other.name)) is outside this export's function coverage.")
        }
        diagnostics.append("Only recovered metadata or an authored signature establishes function language; other functions remain unknown.")
        var input = RegenerationProjectInput(applicationName: application.applicationName,
            image: .init(imageSlot: slot.rawValue, selectedSliceIndex: binary.selectedSliceIndex, architecture: "arm64",
                         selectedSliceSHA256: identity.selectedSliceSHA256, analysisFingerprintSHA256: fingerprint.overallSHA256),
            functions: functions, originalDeploymentTarget: binary.metadata.minimumOSVersion,
            dependentLibraries: analysis.machOMetadata?.dependentDylibs.map(\.path) ?? [],
            referenceFiles: references, diagnostics: diagnostics)
        input.nominalTypes = analysis.objcClasses.map { cls in
            .init(name: cls.name, module: nil, language: .objc, kind: .class,
                  fields: cls.ivars.map { .init(name: $0.name, recoveredType: $0.typeEncoding, mutable: true) })
        } + analysis.swiftTypes.map { type in
            .init(name: type.qualifiedName ?? type.name, module: nil, language: .swift,
                  kind: RegenerationNominalKind(rawValue: type.kind.rawValue) ?? .unknown,
                  fields: type.fields.map { .init(name: $0.name, recoveredType: $0.typeName, mutable: $0.isVar) })
        }
        return input
    }

    private static func aliasID(base: UUID, name: String, ordinal: Int) -> UUID {
        let preimage = "MacScope.RegenerationAlias.v1\0" + base.uuidString.lowercased()
            + "\0" + name + "\0" + String(ordinal)
        var bytes = Array(SHA256.hash(data: Data(preimage.utf8)).prefix(16))
        bytes[6] = (bytes[6] & 0x0f) | 0x80
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}
