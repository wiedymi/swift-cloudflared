// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Cloudflared",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "Cloudflared",
            targets: ["Cloudflared"]
        ),
        .executable(
            name: "cloudflared-e2e",
            targets: ["CloudflaredE2E"]
        )
    ],
    targets: [
        .target(
            name: "Cloudflared",
            path: "Sources/Cloudflared"
        ),
        .executableTarget(
            name: "CloudflaredE2E",
            dependencies: ["Cloudflared"],
            path: "Examples/E2E"
        ),
        .testTarget(
            name: "CloudflaredTests",
            dependencies: ["Cloudflared"],
            path: "Tests/CloudflaredTests"
        )
    ]
)
