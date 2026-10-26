// swift-tools-version: 6.2

import PackageDescription

// Account sign-in for SwiftCLIKit apps, on SwiftIdentity.
//
// Depends on swift-cli-kit and swift-identity only (and Apple's DocC plugin). A sign-in method's own package (swift-oauth
// for device sign-in, say) is the app's dependency, never this package's: SwiftPM resolves every
// package-level dependency, so naming one here would make every app download it.
let package = Package(
    name: "swift-cli-kit-auth",
    platforms: [.macOS(.v14), .iOS(.v17), .visionOS(.v1)],
    products: [
        .library(name: "SwiftCLIKitAuth", targets: ["SwiftCLIKitAuth"]),
        .library(name: "SwiftCLIKitAuthSSH", targets: ["SwiftCLIKitAuthSSH"]),
    ],
    dependencies: [
        .package(url: "https://github.com/jpurnell/swift-cli-kit.git", from: "2.3.0"),
        .package(url: "https://github.com/jpurnell/swift-identity.git", from: "0.7.1"),
        // Apple's, and already resolved through swift-cli-kit, so it adds nothing to download.
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.4.3"),
        // Already resolved through swift-cli-kit (swift-nio-ssh is its dependency, swift-nio is
        // swift-nio-ssh's), so they add nothing to download. Named only so the SSH tests can
        // drive a real NIOSSH client; no library target links them.
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.81.0"),
        .package(url: "https://github.com/apple/swift-nio-ssh.git", from: "0.15.0"),
    ],
    targets: [
        .target(
            name: "SwiftCLIKitAuth",
            dependencies: [
                .product(name: "SwiftCLIKit", package: "swift-cli-kit"),
                .product(name: "SwiftIdentity", package: "swift-identity"),
            ]
        ),
        .target(
            name: "SwiftCLIKitAuthSSH",
            dependencies: [
                "SwiftCLIKitAuth",
                .product(name: "SwiftCLIKitSSH", package: "swift-cli-kit"),
                .product(name: "SwiftIdentity", package: "swift-identity"),
            ]
        ),
        .testTarget(
            name: "SwiftCLIKitAuthTests",
            dependencies: [
                "SwiftCLIKitAuth",
                .product(name: "SwiftCLIKit", package: "swift-cli-kit"),
                .product(name: "SwiftIdentity", package: "swift-identity"),
            ]
        ),
        .testTarget(
            name: "SwiftCLIKitAuthSSHTests",
            dependencies: [
                "SwiftCLIKitAuthSSH",
                .product(name: "SwiftCLIKitSSH", package: "swift-cli-kit"),
                .product(name: "SwiftIdentity", package: "swift-identity"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
            ]
        ),
    ]
)
