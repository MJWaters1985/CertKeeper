// swift-tools-version: 6.0
import PackageDescription

/// SwiftNIO carries TLS connections where Network.framework doesn't exist (the Linux server).
let linuxOnly = TargetDependencyCondition.when(platforms: [.linux])

var products: [Product] = [
    .executable(name: "certkeeper-server", targets: ["CertKeeperServer"]),
]
var targets: [Target] = [
    .target(
        name: "CertKeeperCore",
        dependencies: [
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "_CryptoExtras", package: "swift-crypto"),
            .product(name: "SwiftASN1", package: "swift-asn1"),
            .product(name: "NIOCore", package: "swift-nio", condition: linuxOnly),
            .product(name: "NIOPosix", package: "swift-nio", condition: linuxOnly),
            .product(name: "NIOTLS", package: "swift-nio", condition: linuxOnly),
            .product(name: "NIOSSL", package: "swift-nio-ssl", condition: linuxOnly),
        ],
        swiftSettings: [.swiftLanguageMode(.v5)]
    ),
    // The web server edition (Linux container; also builds on macOS for development).
    .executableTarget(
        name: "CertKeeperServer",
        dependencies: [
            "CertKeeperCore",
            .product(name: "Hummingbird", package: "hummingbird"),
            .product(name: "HummingbirdTLS", package: "hummingbird"),
            .product(name: "ServiceLifecycle", package: "swift-service-lifecycle"),
            .product(name: "Logging", package: "swift-log"),
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOSSL", package: "swift-nio-ssl"),
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "_CryptoExtras", package: "swift-crypto"),
        ],
        resources: [.copy("Web")],
        swiftSettings: [.swiftLanguageMode(.v5)]
    ),
    .testTarget(
        name: "CertKeeperServerTests",
        dependencies: ["CertKeeperServer", "CertKeeperCore", .product(name: "X509", package: "swift-certificates"),
                       .product(name: "Crypto", package: "swift-crypto")],
        swiftSettings: [.swiftLanguageMode(.v5)]
    ),
    .testTarget(
        name: "CertKeeperCoreTests",
        dependencies: ["CertKeeperCore"],
        swiftSettings: [.swiftLanguageMode(.v5)]
    ),
]

#if os(macOS)
// The SwiftUI app only builds on macOS.
products.append(.executable(name: "CertKeeper", targets: ["CertKeeper"]))
targets.append(
    .executableTarget(
        name: "CertKeeper",
        dependencies: ["CertKeeperCore"],
        swiftSettings: [.swiftLanguageMode(.v5)]
    )
)
#endif

let package = Package(
    name: "CertKeeper",
    platforms: [.macOS(.v15)],
    products: products,
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.9.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.3.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.27.0"),
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.5.0"),
        .package(url: "https://github.com/swift-server/swift-service-lifecycle.git", from: "2.6.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.6.0"),
        .package(url: "https://github.com/apple/swift-http-types.git", from: "1.3.0"),
    ],
    targets: targets
)
