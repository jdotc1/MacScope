import Foundation

/// Listing policy only. This type never supplies a command allow-list.
enum MCPToolListingProfile: Sendable, Equatable {
    case core
    case full

    static let coreNames: Set<String> = [
        "info", "list-image-types", "search", "decompile", "functions", "symbols",
        "strings", "sections", "instructions", "read-bytes", "callers", "callees",
        "xrefs", "name-at", "containing-function", "demangle", "function-facts",
        "function-references", "call-path", "imports", "exports", "basic-blocks",
        "resolve-symbol", "commands", "rename", "set-names", "set-comment", "set-comments",
    ]
    private static let harnessNames: Set<String> = ["neon-hitrate", "reconstruction-jobs"]
    static let environmentKey = "MACSCOPE_MCP_LIST_PROFILE"
    static let unknownValueWarning = "Unknown MACSCOPE_MCP_LIST_PROFILE; using full."

    /// Exact spelling is intentional: do not trim, fold case, or echo an unknown value.
    static func resolve(_ value: String?) -> (profile: Self, warning: String?) {
        switch value {
        case nil, "core": return (.core, nil)
        case "full": return (.full, nil)
        default: return (.full, unknownValueWarning)
        }
    }

    /// Called only after the server's existing authority and harness predicates.
    func lists(_ name: String, harnessVisible: Bool) -> Bool {
        self == .full || Self.coreNames.contains(name)
            || (harnessVisible && Self.harnessNames.contains(name))
    }

    static func launchConfiguration(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        warn: (String) -> Void = MCPStartupLog.line
    ) -> MCPServer.Configuration {
        let selection = resolve(environment[environmentKey])
        if let warning = selection.warning { warn(warning) }
        return MCPServer.Configuration.production.listing(profile: selection.profile)
    }
}

extension MCPServer.Configuration {
    /// Copy every limit, including the non-default in-flight request limit.
    func listing(profile: MCPToolListingProfile?) -> Self {
        Self(
            maximumInputBytes: maximumInputBytes,
            maximumOutputBytes: maximumOutputBytes,
            maximumToolDurationNanoseconds: maximumToolDurationNanoseconds,
            maximumRememberedCancellations: maximumRememberedCancellations,
            maximumInFlightRequests: maximumInFlightRequests,
            listingProfile: profile
        )
    }
}
