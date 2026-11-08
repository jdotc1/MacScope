import Foundation

/// Selects the repository-pinned tool using its retained metadata. This reads the accepted pin;
/// it deliberately does not replay dependency hashes, signing checks, or materializer verification.
enum RegenerationXcodeGenTool {
    static let revision = "2.46.0"
    static let gitRevision = "8445e778451c7e44237b90281bde622d764b0084"

    static func locate(environment: [String: String] = ProcessInfo.processInfo.environment,
                       bundle: Bundle = .main) throws -> URL {
        let tool: URL, metadata: URL
        if let explicit = environment["MACSCOPE_XCODEGEN"] {
            guard explicit.hasPrefix("/"), !explicit.contains("\0") else {
                throw RegenerationError.invalidPath("MACSCOPE_XCODEGEN must name the retained pinned tool by absolute path")
            }
            tool = URL(fileURLWithPath: explicit)
            metadata = tool.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("MATERIALIZATION.json")
        } else if let bundled = bundle.url(forResource: "xcodegen", withExtension: nil),
                  let identity = bundle.url(forResource: "RegenerationXcodeGenIdentity", withExtension: "json") {
            tool = bundled; metadata = identity
        } else {
            throw RegenerationError.toolFailed("Pinned XcodeGen is unavailable; configure MACSCOPE_XCODEGEN or include the governed tool in app resources")
        }
        guard tool.lastPathComponent == "xcodegen", FileManager.default.isExecutableFile(atPath: tool.path),
              let values = try JSONSerialization.jsonObject(with: Data(contentsOf: metadata)) as? [String: Any],
              values["revision"] as? String == revision, values["gitRevision"] as? String == gitRevision,
              values["integrationMode"] as? String == "repository-owned-prebuilt-tool" else {
            throw RegenerationError.toolFailed("Configured XcodeGen does not have the expected retained pin metadata")
        }
        return tool
    }
}
