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
    // The client half is Foundation and Crypto only, so it runs anywhere Swift
    // does — including in an iOS app consuming a third-party API. The provider
    // half needs a server and SQLite, and is not expected to be built for iOS,
    // but nothing in the manifest needs to say so: a target is only compiled
    // when something depends on it.
    platforms: [
        .macOS(.v14),
        .iOS(.v17)
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
            // Declared, not excluded. swift-docc-plugin finds a catalogue through the
            // target's `sourceFiles`, which `exclude:` removes it from — so excluding would
            // silence SwiftPM's unhandled-file warning by handing DocC nothing, and doc-lint
            // would pass over an article it never opened.
            resources: [.copy("SwiftOAuthCore.docc")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .systemLibrary(
            name: "CSQLite",
            pkgConfig: "sqlite3",
            providers: [
                .brew(["sqlite3"]),
                .apt(["libsqlite3-dev"])
            ]
        ),
        .target(
            name: "SwiftOAuthProvider",
            dependencies: [
                "SwiftOAuthCore",
                "CSQLite",
                .product(name: "Crypto", package: "swift-crypto")
            ],
            // Declared, not excluded. swift-docc-plugin finds a catalogue through the
            // target's `sourceFiles`, which `exclude:` removes it from — so excluding would
            // silence SwiftPM's unhandled-file warning by handing DocC nothing, and doc-lint
            // would pass over an article it never opened.
            resources: [.copy("SwiftOAuthProvider.docc")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .target(
            name: "SwiftOAuthClient",
            dependencies: [
                "SwiftOAuthCore",
                .product(name: "Crypto", package: "swift-crypto")
            ],
            // Declared, not excluded. swift-docc-plugin finds a catalogue through the
            // target's `sourceFiles`, which `exclude:` removes it from — so excluding would
            // silence SwiftPM's unhandled-file warning by handing DocC nothing, and doc-lint
            // would pass over an article it never opened.
            resources: [.copy("SwiftOAuthClient.docc")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "SwiftOAuthCoreTests",
            dependencies: ["SwiftOAuthCore"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "SwiftOAuthProviderTests",
            // CSQLite so a migration test can plant a row in the old schema directly. The
            // package's own API cannot write one — every write names the current columns — so
            // without raw SQL the survival of pre-migration data is untestable.
            dependencies: ["SwiftOAuthProvider", "CSQLite"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // The two halves against each other. Neither depends on the other in production —
        // that is the architecture — so nothing else checks they agree on the wire.
        .testTarget(
            name: "SwiftOAuthConformanceTests",
            dependencies: ["SwiftOAuthCore", "SwiftOAuthClient", "SwiftOAuthProvider"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "SwiftOAuthClientTests",
            dependencies: ["SwiftOAuthClient"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        )
    ]
)
