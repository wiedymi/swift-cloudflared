// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "swift-cloudflared",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "SwiftCloudflared",
            targets: ["SwiftCloudflared"]
        ),
        .executable(
            name: "swift-cloudflared-e2e",
            targets: ["SwiftCloudflaredE2E"]
        )
    ],
    targets: [
        .target(
            name: "SwiftCloudflared"
        ),
        .executableTarget(
            name: "SwiftCloudflaredE2E",
            dependencies: ["SwiftCloudflared"],
            path: "Examples/E2E"
        ),
        .testTarget(
            name: "SwiftCloudflaredTests",
            dependencies: ["SwiftCloudflared"]
        )
    ]
)
