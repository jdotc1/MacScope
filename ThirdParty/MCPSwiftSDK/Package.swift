// swift-tools-version:6.1
// MacScope vendored manifest for modelcontextprotocol/swift-sdk 0.12.1 (see PATCHES.md).
// Dropped from upstream: the conformance executables and their sources, the swift-nio and
// swift-docc-plugin dependencies, and the test target. Dependencies point at vendored local paths.

import PackageDescription

let package = Package(
    name: "mcp-swift-sdk",
    platforms: [
        .macOS("13.0")
    ],
    products: [
        .library(
            name: "MCP",
            targets: ["MCP"])
    ],
    dependencies: [
        .package(path: "../SwiftSystem"),
        .package(path: "../SwiftLog"),
        .package(path: "../EventSource"),
    ],
    targets: [
        .target(
            name: "MCP",
            dependencies: [
                .product(name: "SystemPackage", package: "SwiftSystem"),
                .product(name: "Logging", package: "SwiftLog"),
                .product(name: "EventSource", package: "EventSource"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency")
            ]
        )
    ]
)
