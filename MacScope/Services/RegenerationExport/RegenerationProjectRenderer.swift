import Foundation

enum RegenerationProjectRenderer {
    static func render(_ input: RegenerationProjectInput,
                       resources: [ResourceRoundTripRecord] = [],
                       dependencyFiles: [String: Data] = [:],
                       dependencyCapability: RegenerationDependencyInventoryCapability? = nil) throws -> RegenerationRenderedProject {
        guard input.image.architecture == "arm64", input.image.imageSlot >= 0,
              validDigest(input.image.selectedSliceSHA256), validDigest(input.image.analysisFingerprintSHA256),
              input.functions.count <= 100_000, input.applicationName.utf8.count <= 1_024 else {
            throw RegenerationError.invalidInput("expected bounded macOS arm64 input and captured identity")
        }
        guard Set(input.functions.map(\.functionUUID)).count == input.functions.count,
              input.functions.allSatisfy({ $0.address < $0.endAddress }) else {
            throw RegenerationError.invalidInput("duplicate function identity or invalid boundary")
        }
        var files = input.referenceFiles
        guard files["Support/Info.plist"] == nil,
              files.keys.allSatisfy({ $0.hasPrefix("Support/") && RegenerationEncoding.relativePath($0) }) else {
            throw RegenerationError.invalidInput("reference files must remain in Support")
        }
        if let capability = dependencyCapability {
            guard capability.path == "DEPENDENCIES.json", capability.coverage == "capturedSnapshotOnly",
                  capability.liveBundleObservations == "unassessed",
                  Set(dependencyFiles.keys) == [capability.path],
                  let report = dependencyFiles[capability.path], report.count <= 67_108_864 else {
                throw RegenerationError.invalidInput("dependency capability lacks its bounded captured-only report")
            }
            for (path, bytes) in dependencyFiles {
                guard files[path] == nil else { throw RegenerationError.invalidInput("dependency output collision") }
                files[path] = bytes
            }
        } else if !dependencyFiles.isEmpty {
            throw RegenerationError.invalidInput("dependency report requires an explicit capability")
        }
        var diagnostics = input.diagnostics
        diagnostics.append(RegenerationResourceProvenance.diagnostic)
        let deployment = deploymentTarget(input.originalDeploymentTarget)
        if deployment != input.originalDeploymentTarget {
            diagnostics.append("Skeleton deployment target is \(deployment); original requirement is retained separately.")
        }
        files["Sources/Support/main.c"] = Data("// Synthetic skeleton entry point; no recovered function is invoked.\nint main(void) { return 0; }\n".utf8)
        files["Sources/Support/MacScopeUnresolved.h"] = Data("#pragma once\n// Opaque placeholder. No recovered ABI or storage layout is asserted.\ntypedef struct MacScopeUnresolved MacScopeUnresolved;\n".utf8)
        files["Sources/Support/MacScopeUnresolved.swift"] = Data("// Explicit nonfunctional placeholder; no recovered layout is asserted.\nstruct MacScopeUnresolved { private init() {} }\n".utf8)
        for (path, data) in try RegenerationNominalRenderer.render(input.nominalTypes) {
            guard files[path] == nil else { throw RegenerationError.invalidInput("nominal type output collision") }
            files[path] = data
        }
        var records: [RegenerationFunctionRecord] = []
        for function in input.functions.sorted(by: { a, b in
            a.address == b.address ? a.functionUUID.uuidString < b.functionUUID.uuidString : a.address < b.address
        }) {
            let key = function.functionUUID.uuidString.lowercased().replacingOccurrences(of: "-", with: "")
            let suffix = function.language == .swift ? "swift" : function.language == .objc ? "m" : "c"
            let folder = function.language == .swift ? "Swift/Recovered" : function.language == .objc ? "ObjC" : "C"
            let path = "Sources/\(folder)/function_\(key).\(suffix)"
            var lines = ["// Recovered name: " + RegenerationEncoding.annotation(function.name),
                         "// Address: " + RegenerationEncoding.address(function.address),
                         "// Nonfunctional stub; not a callable replacement for the original ABI."]
            if let declaration = function.recoveredDeclaration {
                lines.append("// Recovered declaration: " + RegenerationEncoding.annotation(declaration))
            }
            lines.append("// MACSCOPE-STUB " + function.functionUUID.uuidString.lowercased())
            let markerLine = lines.count
            var notes: [String] = []
            if function.language == .swift {
                lines.append("func msrg_stub_\(key)() -> Never { fatalError(\"Recovered function is unimplemented\") }")
                notes.append("Signature unresolved; explicit Swift placeholder.")
            } else if let signature = function.cSignature, signature.canRender, function.language == .c {
                let parameters = signature.parameterTypes.enumerated().map { "\($0.element) arg\($0.offset)" }
                lines.append("\(signature.returnType) msrg_stub_\(key)(\(parameters.isEmpty ? "void" : parameters.joined(separator: ", "))) { __builtin_trap(); }")
            } else {
                lines.append("void msrg_stub_\(key)(void) { __builtin_trap(); }")
                notes.append("Signature unresolved or unsupported; explicit nonfunctional C-family placeholder.")
            }
            files[path] = Data((lines.joined(separator: "\n") + "\n").utf8)
            records.append(.init(imageQualifiedAddress: .init(imageSlot: input.image.imageSlot,
                selectedSliceIndex: input.image.selectedSliceIndex, imageSHA256: input.image.selectedSliceSHA256,
                address: RegenerationEncoding.address(function.address),
                endAddressExclusive: RegenerationEncoding.address(function.endAddress)),
                functionUUID: function.functionUUID, name: function.name, language: function.language,
                stubFile: path, stubLine: markerLine, state: .stub, diagnostics: notes))
        }
        let selected = try ResourceRoundTripComposition.buildPaths(resources)
        let manifest = RegenerationManifest(schemaVersion: 1, applicationName: input.applicationName,
            image: input.image, originalDeploymentTarget: input.originalDeploymentTarget,
            deploymentTarget: deployment, dependentLibraries: input.dependentLibraries.sorted(),
            functions: records, resources: resources.sorted { $0.compiledPaths.joined() < $1.compiledPaths.joined() },
            resourceProvenance: .currentBundle,
            capabilities: dependencyCapability.map { RegenerationCapabilities(dependencyInventory: $0) },
            diagnostics: diagnostics)
        files["REGEN-MANIFEST.json"] = try RegenerationEncoding.json(manifest)
        files["C-BODY-REQUEST.json"] = try RegenerationEncoding.json(RegenerationCStubFill.request(for: input))
        let name = RegenerationEncoding.identifier(input.applicationName)
        let info: [String: Any] = ["CFBundleIdentifier": "org.macscope.regenerated." + name.lowercased(),
            "CFBundleName": name, "CFBundleExecutable": "$(EXECUTABLE_NAME)",
            "CFBundlePackageType": "APPL", "CFBundleVersion": "1", "CFBundleShortVersionString": "1.0"]
        files["Support/Info.plist"] = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        let originals = selected.filter { $0.hasPrefix("Resources/Compiled/") }
        // Compiled inputs must be copied verbatim, preserving their relative paths. Putting each
        // file in Xcode's ordinary resources phase flattens subdirectories and can recompile nibs.
        let buildResources: [[String: Any]] = selected.map {
            ["path": $0, "buildPhase": $0.hasPrefix("Resources/Compiled/") ? "none" : "resources"]
        }
        var target: [String: Any] = ["type": "application", "platform": "macOS", "deploymentTarget": deployment,
            "sources": [["path": "Sources"]] + buildResources,
            "settings": ["base": ["ARCHS": "arm64", "SUPPORTED_PLATFORMS": "macosx", "SWIFT_VERSION": "6.0",
                "PRODUCT_NAME": name, "PRODUCT_MODULE_NAME": "MSRG_" + name,
                "CLANG_ENABLE_MODULES": "YES", "CLANG_ENABLE_OBJC_ARC": "YES", "ALWAYS_SEARCH_USER_PATHS": "NO",
                "SWIFT_OPTIMIZATION_LEVEL": "-Onone", "ENABLE_USER_SCRIPT_SANDBOXING": "YES",
                "CODE_SIGNING_ALLOWED": "NO", "CODE_SIGNING_REQUIRED": "NO", "GENERATE_INFOPLIST_FILE": "NO",
                "INFOPLIST_FILE": "Support/Info.plist", "PRODUCT_BUNDLE_IDENTIFIER": "org.macscope.regenerated." + name.lowercased()]]]
        if !originals.isEmpty {
            var script = ["set -eu", "resources=\"${TARGET_BUILD_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}\"", "/bin/mkdir -p \"$resources\""]
            for original in originals.sorted() {
                let relative = String(original.dropFirst("Resources/Compiled/".count))
                let parent = (relative as NSString).deletingLastPathComponent
                if !parent.isEmpty { script.append("/bin/mkdir -p \"$resources/\"" + shellLiteral(parent)) }
                script.append("/usr/bin/ditto \"$SRCROOT/\"" + shellLiteral(original) + " \"$resources/\"" + shellLiteral(relative))
            }
            target["postBuildScripts"] = [["name": "Copy observed compiled resources", "script": script.joined(separator: "\n"),
                "basedOnDependencyAnalysis": false, "inputFiles": ["$(SRCROOT)/Resources/Compiled"],
                "outputFiles": ["$(TARGET_BUILD_DIR)/$(UNLOCALIZED_RESOURCES_FOLDER_PATH)"]]]
        }
        let spec: [String: Any] = ["name": name, "options": ["minimumXcodeGenVersion": "2.46.0"],
            "targets": [name: target]]
        files["project.yml"] = try JSONSerialization.data(withJSONObject: spec, options: [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]) + Data([10])
        return .init(files: files, manifest: manifest, buildResources: selected)
    }

    private static func shellLiteral(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func validDigest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private static func deploymentTarget(_ original: String?) -> String {
        guard let original, !original.isEmpty, original.utf8.count <= 16,
              original.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({
                  !$0.isEmpty && $0.utf8.allSatisfy { (48...57).contains($0) }
              }),
              let major = Int(original.split(separator: ".")[0]), major >= 11 else { return "11.0" }
        return original
    }
}
