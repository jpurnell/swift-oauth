// swift-tools-version: 6.2
import PackageDescription

// SQLite, for the provider's token store.
//
// On Apple platforms the SDK ships a universal libsqlite3, and the module map's `link "sqlite3"`
// finds it. Naming pkg-config or a Homebrew provider there is worse than naming nothing:
// SwiftPM then puts Homebrew's library directory first on the link line, and on Apple Silicon
// that copy is arm64 only — so the x86_64 half of a universal build (what
// `xcodebuild -destination generic/platform=macOS` produces) links against nothing and every
// `sqlite3_*` symbol is undefined. `#if os` here is the host building the package, which is
// the question being asked.
#if os(Linux)
let sqlite: Target = .systemLibrary(
    name: "CSQLite",
    pkgConfig: "sqlite3",
    providers: [.apt(["libsqlite3-dev"])]
)
#else
let sqlite: Target = .systemLibrary(name: "CSQLite")
#endif

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
        .library(name: "SwiftOAuthClient", targets: ["SwiftOAuthClient"]),
        // mTLS lives in its own product, so linking NIO is something a consumer opts into.
        //
        // Being precise about what that buys: SwiftPM resolves every package-level dependency
        // regardless, so the download is taken either way. What a separate product avoids is
        // *linking* NIO into a binary that never uses it, and compiling it as part of every
        // build of the other targets.
        .library(name: "SwiftOAuthMTLS", targets: ["SwiftOAuthMTLS"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        // For mTLS only — RFC 8705. `URLSession` cannot answer a client-certificate challenge
        // on Linux: corelibs-foundation's `URLCredential` has no identity-based initialiser,
        // and its source says outright that there is no SecIdentity support. NIOSSL's
        // `TLSConfiguration` does expose `certificateChain` and `privateKey`, and
        // AsyncHTTPClient accepts one — so mutual TLS means a NIO-backed transport or nothing.
        .package(url: "https://github.com/swift-server/async-http-client.git", from: "1.19.0"),
        // For the tests only: the loopback servers the redirect tests are run against. Already
        // in the graph through AsyncHTTPClient, so naming it adds nothing to what is resolved;
        // it is named because a target may only import what its package declares.
        //
        // 2.70.0, because that is the lowest version the stub compiles against, found by
        // resolving the lowest version of everything this manifest admits and building. The
        // floor used to read 2.62.0 and had never been built: `ChannelOption.backlog` and
        // `.socketOption(_:)` as leading-dot members arrived in 2.70.0, and against 2.62.0
        // the stub fails with "type 'ChannelOption' has no member 'backlog'".
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.70.0"),
        // For the tests only, and for the same reason as `swift-nio` above: already resolved
        // through AsyncHTTPClient, and named because the test-support target imports them. The
        // redirect rule has to be shown to hold from `https` to `http`, which needs a loopback
        // server that speaks TLS (`swift-nio-ssl`) and a certificate for it to present —
        // minted at run time (`swift-certificates`, `swift-asn1`) so no private key is ever
        // committed. None of the three reaches a library target through this declaration;
        // `SwiftOAuthMTLS` already gets NIOSSL through AsyncHTTPClient.
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.25.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.0.0"),
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
        .target(
            name: "SwiftOAuthMTLS",
            dependencies: [
                "SwiftOAuthCore",
                "SwiftOAuthClient",
                .product(name: "AsyncHTTPClient", package: "async-http-client")
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        sqlite,
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
        // Test support, in no product: two loopback servers, one redirecting to the other, the
        // second recording whatever reaches it. A target rather than a file because the client
        // and mTLS test targets both need it.
        .target(
            name: "RedirectWireStub",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto")
            ],
            path: "Tests/RedirectWireStub",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "SwiftOAuthCoreTests",
            dependencies: ["SwiftOAuthCore"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "SwiftOAuthMTLSTests",
            dependencies: [
                "SwiftOAuthMTLS",
                "RedirectWireStub",
                .product(name: "AsyncHTTPClient", package: "async-http-client")
            ],
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
            dependencies: ["SwiftOAuthClient", "RedirectWireStub"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        )
    ]
)
