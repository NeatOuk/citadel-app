// swift-tools-version:5.9
// CitadelCore: Citadel's decision logic for the macOS Network Extension.
import PackageDescription

let package = Package(
    name: "CitadelCore",
    platforms: [.macOS(.v13)],
    products: [.library(name: "CitadelCore", targets: ["CitadelCore"])],
    targets: [
        .target(name: "CitadelCore"),
        .testTarget(name: "CitadelCoreTests", dependencies: ["CitadelCore"], resources: [.copy("Fixtures")]),
    ]
)
