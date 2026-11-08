import Foundation

/// Producer data is not compilation or Reconstruction acceptance authority.
struct RegenerationCBodyPacket: Codable, Sendable {
    let schema: String
    let bodies: [Body]

    struct Body: Codable, Sendable {
        let image: RegenerationImageIdentity?
        let functionUUID: UUID?
        let address: String
        let endAddressExclusive: String
        let emittedSymbol: String
        let source: String
        let prototypeAuthority: String
        let rules: [String]
        let producerReceipt: String?
    }
}

struct RegenerationCBodyProvenance: Codable, Equatable, Sendable {
    let classification: String
    let sourceFile: String
    let originalStubFile: String
    let emittedSymbol: String
    let prototypeAuthority: String
    let rules: [String]
    let producerReceipt: String?
    let compilation: String
    let runtimeEquivalence: String
}

/// Consumes completed producer output; never repairs C, invokes a compiler, or hashes an image.
/// The producer remains responsible for source emission. This boundary requires an exact
/// captured image/function binding and never promotes a caller's claimed compile status.
enum RegenerationCStubFill {
    struct Request: Codable, Sendable {
        struct Function: Codable, Sendable {
            let functionUUID: UUID
            let address: String
            let endAddressExclusive: String
            let name: String
            let language: RegenerationLanguage
            let emittedSymbol: String
        }
        let schema: String
        let image: RegenerationImageIdentity
        let functions: [Function]
    }

    static func request(for input: RegenerationProjectInput) -> Request {
        .init(schema: "macscope-rg3-c-body-request-v1", image: input.image,
            functions: input.functions.filter { $0.language == .c || $0.language == .unknown }
                .sorted { $0.functionUUID.uuidString < $1.functionUUID.uuidString }.map {
                    .init(functionUUID: $0.functionUUID, address: RegenerationEncoding.address($0.address),
                        endAddressExclusive: RegenerationEncoding.address($0.endAddress), name: $0.name,
                        language: $0.language, emittedSymbol: "msrg_recovered_" +
                            $0.functionUUID.uuidString.lowercased().replacingOccurrences(of: "-", with: ""))
                })
    }

    static func apply(_ packet: RegenerationCBodyPacket, to project: inout RegenerationRenderedProject) throws {
        guard packet.schema == "macscope-rg3-c-bodies-v1", packet.bodies.count <= 1_000 else {
            throw RegenerationError.invalidInput("unsupported or unbounded C-body packet")
        }
        var records = project.manifest.functions
        var files = project.files
        var diagnostics = project.manifest.diagnostics
        var seen = Set<UUID>()
        var remainingSourceBytes = 8_388_608
        for body in packet.bodies {
            guard body.source.utf8.count <= remainingSourceBytes else {
                throw RegenerationError.invalidInput("RG3 source packet exceeds shared byte limit")
            }
            remainingSourceBytes -= body.source.utf8.count
            guard let id = body.functionUUID, let image = body.image else {
                diagnostics.append("RG3 refused a body without captured image and function identity; original stubs retained.")
                continue
            }
            guard seen.insert(id).inserted else {
                throw RegenerationError.invalidInput("duplicate RG3 function identity")
            }
            guard image == project.manifest.image,
                  let index = records.firstIndex(where: { $0.functionUUID == id }),
                  records[index].imageQualifiedAddress.address == body.address,
                  records[index].imageQualifiedAddress.endAddressExclusive == body.endAddressExclusive else {
                diagnostics.append("RG3 refused mismatched captured identity for \(id.uuidString.lowercased()); original stub retained.")
                continue
            }
            let old = records[index]
            guard old.state == .stub, old.language == .c || old.language == .unknown else {
                diagnostics.append("RG3 refused non-C or already-filled function \(id.uuidString.lowercased()).")
                continue
            }
            let key = id.uuidString.lowercased().replacingOccurrences(of: "-", with: "")
            let symbol = "msrg_recovered_" + key
            guard body.emittedSymbol == symbol, !body.source.isEmpty, body.source.utf8.count <= 1_048_576,
                  !body.source.contains("\0"), !body.prototypeAuthority.isEmpty,
                  body.prototypeAuthority.utf8.count <= 4_096, !body.rules.isEmpty,
                  body.rules.count <= 128, body.rules.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 256 }),
                  (body.producerReceipt?.utf8.count ?? 0) <= 4_096 else {
                throw RegenerationError.invalidInput("invalid RG3 body, symbol, or provenance")
            }
            guard admitsSingleLeafSource(body.source, symbol: symbol) else {
                throw RegenerationError.invalidInput("RG3 source is outside the producer's bounded single-function format")
            }
            let bodyPath = "Decompiled/C/function_\(key).c"
            let originalPath = "Support/OriginalStubs/function_\(key).c.txt"
            guard files[bodyPath] == nil, files[originalPath] == nil,
                  let original = files[old.stubFile], old.stubFile == "Sources/C/function_\(key).c" else {
                throw RegenerationError.invalidInput("RG3 source collision or unexpected original stub path")
            }
            files[bodyPath] = Data(body.source.utf8)
            files[originalPath] = original
            // Retain the source byte-for-byte. The generated target compiles this one include,
            // not a second copy of the producer's translation unit or numeric helpers.
            let marker = "// MACSCOPE-FILLED " + id.uuidString.lowercased()
            files[old.stubFile] = Data((marker + "\n#include \"../../" + bodyPath + "\"\n").utf8)
            let provenance = RegenerationCBodyProvenance(classification: "SIGNATURE_ASSISTED_C_EXPORT",
                sourceFile: bodyPath, originalStubFile: originalPath, emittedSymbol: symbol,
                prototypeAuthority: body.prototypeAuthority, rules: body.rules,
                producerReceipt: body.producerReceipt, compilation: "not-established-by-consumer",
                runtimeEquivalence: "NOT_ESTABLISHED")
            records[index] = .init(imageQualifiedAddress: old.imageQualifiedAddress, functionUUID: id,
                name: old.name, language: .c, stubFile: old.stubFile, stubLine: 1, state: .filled,
                diagnostics: old.diagnostics + ["Signature-assisted C body imported. Producer receipt is a reference only; compilation and runtime equivalence are not established by this import."],
                cBody: provenance, dependencyId: old.dependencyId)
        }
        let old = project.manifest
        let manifest = RegenerationManifest(schemaVersion: old.schemaVersion, applicationName: old.applicationName,
            image: old.image, originalDeploymentTarget: old.originalDeploymentTarget,
            deploymentTarget: old.deploymentTarget, dependentLibraries: old.dependentLibraries,
            functions: records, resources: old.resources, resourceProvenance: old.resourceProvenance,
            capabilities: old.capabilities, diagnostics: diagnostics)
        files["REGEN-MANIFEST.json"] = try RegenerationEncoding.json(manifest)
        project = .init(files: files, manifest: manifest, buildResources: project.buildResources)
    }
    /// A deliberately narrow envelope for DEA's scalar-leaf adapter, not general C parsing.
    /// Unknown directives, global definitions, string literals and support helpers are refused.
    private static func admitsSingleLeafSource(_ source: String, symbol: String) -> Bool {
        var text = source
        let headers = "#include <stdint.h>\n#include <math.h>\n"
        guard text.hasPrefix(headers) else { return false }
        text.removeFirst(headers.count)
        for helper in [
            "static inline double __a64_absolute_f64(double a) { return fabs(a); }\n",
            "static inline float __a64_subtract_f32(float a, float b) { return a - b; }\n"
        ] {
            if text.hasPrefix(helper) { text.removeFirst(helper.count) }
        }
        text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.hasPrefix("int " + symbol + "("), !text.contains("#"),
              !text.contains("\""), !text.contains("'"), !text.contains("\\"),
              !text.contains("__attribute__"), !text.contains("__asm"),
              let opening = text.firstIndex(of: "{") else { return false }
        let header = String(text[..<opening])
        let parameter = #"(?:int|float|double)(?: \*)? [A-Za-z_][A-Za-z_0-9]*"#
        let pattern = "^int " + symbol + #"\("# + parameter + "(?:, " + parameter + #")*\) \s*$"#
        guard header.range(of: pattern, options: .regularExpression) != nil else { return false }
        var body = String(text[opening...])
        body = body.replacingOccurrences(of: "/\\*[^*]*(?:\\*(?!/)[^*]*)*\\*/|//[^\n]*", with: "", options: .regularExpression)
        var depth = 0
        for (index, character) in body.enumerated() {
            if character == "{" { depth += 1 }
            if character == "}" { depth -= 1 }
            if depth < 0 || (depth == 0 && !body.dropFirst(index + 1).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) { return false }
        }
        return depth == 0
    }

}
