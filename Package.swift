// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CertKeeper",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "CertKeeper", targets: ["CertKeeper"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.9.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.3.0"),
    ],
    targets: [
        .target(
            name: "CertKeeperCore",
            dependencies: [
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .executableTarget(
            name: "CertKeeper",
            dependencies: ["CertKeeperCore"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "CertKeeperCoreTests",
            dependencies: ["CertKeeperCore"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
