// swift-tools-version: 6.1
// MacScope vendored manifest for mattt/eventsource 1.6.0 (see PATCHES.md).
// The upstream AsyncHTTPClient trait, its async-http-client and swift-nio
// dependencies, the AsyncHTTPClient source file and the test target are removed.

import PackageDescription

let package = Package(
    name: "EventSource",
    platforms: [
        .macOS("12.0")
    ],
    products: [
        .library(
            name: "EventSource",
            targets: ["EventSource"]
        )
    ],
    targets: [
        .target(name: "EventSource")
    ]
)
