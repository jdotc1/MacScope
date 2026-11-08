// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NEWFEATURESCore",
    // A reusable pure core. MacScope itself still requires macOS 27 and Xcode 27.
    platforms: [.macOS(.v15)],
    products: [.library(name: "NEWFEATURESCore", targets: ["NEWFEATURESCore"])],
    targets: [
        .target(name: "NEWFEATURESCore"),
        .testTarget(
            name: "NEWFEATURESCoreTests", dependencies: ["NEWFEATURESCore"],
            resources: [.process("Fixtures")]
        ),
    ]
)
