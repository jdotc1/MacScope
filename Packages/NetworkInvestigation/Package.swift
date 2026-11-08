// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MacScopeNetworkInvestigation",
    platforms: [.macOS("27.0")],
    products: [
        .library(name: "NetworkEvidenceCore", targets: ["NetworkEvidenceCore"]),
        .library(name: "ExternalMCP", targets: ["ExternalMCP"]),
        .library(name: "ProxymanInstallation", targets: ["ProxymanInstallation"]),
        .library(name: "ProxymanIntegration", targets: ["ProxymanIntegration"]),
        .library(name: "ProxymanAdapter", targets: ["ProxymanAdapter"]),
    ],
    dependencies: [
        // Vendored local-path packages (NW0b); resolve offline.
        .package(path: "../../ThirdParty/MCPSwiftSDK"),
        .package(path: "../../ThirdParty/SwiftLog"),
    ],
    targets: [
        .target(name: "NetworkEvidenceCore"),
        .target(name: "ExternalMCP", dependencies: [
            .product(name: "MCP", package: "MCPSwiftSDK"),
            .product(name: "Logging", package: "SwiftLog"),
        ]),
        .executableTarget(name: "MCPFixtureServer", dependencies: [
            .product(name: "MCP", package: "MCPSwiftSDK"),
        ]),
        .target(name: "ProxymanInstallation", dependencies: ["ExternalMCP"]),
        .target(name: "ProxymanIntegration", dependencies: ["ExternalMCP", "ProxymanInstallation"]),
        .target(name: "ProxymanAdapter", dependencies: ["ExternalMCP", "NetworkEvidenceCore"]),
        .testTarget(name: "NetworkEvidenceCoreTests", dependencies: ["NetworkEvidenceCore"]),
        .testTarget(name: "ExternalMCPTests", dependencies: ["ExternalMCP", "MCPFixtureServer"]),
        .testTarget(name: "ProxymanInstallationTests", dependencies: ["ProxymanInstallation", "ExternalMCP"]),
        .testTarget(name: "ProxymanIntegrationTests", dependencies: ["ProxymanIntegration", "ProxymanInstallation", "ExternalMCP", "MCPFixtureServer"]),
        .testTarget(name: "ProxymanAdapterTests", dependencies: ["ProxymanAdapter", "ExternalMCP", "NetworkEvidenceCore"]),
    ],
    swiftLanguageModes: [.v6]
)
