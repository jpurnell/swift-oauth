// swift-tools-version: 6.2
import PackageDescription

// SwiftOAuth — both halves of OAuth 2.0, with storage as a protocol.
//
// The two roles share a name and almost no behaviour: a provider issues tokens
// and validates its own; a client obtains another system's and refreshes them.
// They share the *wire* — grant types, token responses, error codes, and PKCE,
// where the client generates the verifier the server validates. That shared
// vocabulary lives in SwiftOAuthCore and is why this is one package.
//
// Neither half depends on the other: a service that only issues tokens never
// links client code.
let package = Package(
    name: "SwiftOAuth",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "SwiftOAuthCore", targets: ["SwiftOAuthCore"]),
        .library(name: "SwiftOAuthProvider", targets: ["SwiftOAuthProvider"]),
        .library(name: "SwiftOAuthClient", targets: ["SwiftOAuthClient"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.3.0")
    ],
    targets: [
        // Models, errors, grant types, PKCE. No behaviour beyond value types and
        // cryptographic primitives: both halves depend on this, so a change here
        // moves two working systems at once.
        .target(
            name: "SwiftOAuthCore",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .target(
            name: "SwiftOAuthProvider",
            dependencies: [
                "SwiftOAuthCore",
                .product(name: "Crypto", package: "swift-crypto")
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .target(
            name: "SwiftOAuthClient",
            dependencies: [
                "SwiftOAuthCore",
                .product(name: "Crypto", package: "swift-crypto")
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "SwiftOAuthCoreTests",
            dependencies: ["SwiftOAuthCore"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "SwiftOAuthProviderTests",
            dependencies: ["SwiftOAuthProvider"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "SwiftOAuthClientTests",
            dependencies: ["SwiftOAuthClient"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        )
    ]
)
