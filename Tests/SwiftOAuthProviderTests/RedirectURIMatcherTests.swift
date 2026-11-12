import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider


/// Builds a URI from components, so a test states which part differs rather than hiding it in a
/// string.
private func uri(
    _ scheme: String, _ host: String, port: Int? = nil, path: String = "/cb",
    query: String? = nil, fragment: String? = nil, user: String? = nil
) -> String {
    var components = URLComponents()
    components.scheme = scheme
    components.user = user
    components.host = host.contains(":") ? "[\(host)]" : host
    components.port = port
    components.path = path
    components.query = query
    components.fragment = fragment
    return components.string ?? ""
}

/// RFC 8252 §7.3 and §8.4: loopback redirects match on everything but the port.
///
/// Expected values come from the RFC text: "The authorization server MUST allow any port to be
/// specified at the time of the request for loopback IP redirect URIs" (§7.3); otherwise the full
/// URI must match exactly, "the exception is loopback redirects, where an exact match is
/// required except for the port URI component" (§8.4); and §8.3 recommends the IP literals over
/// `localhost`.
@Suite("RFC 8252 — redirect URI matching")
struct RedirectURIMatcherTests {

    @Test("A loopback request may use any port", arguments: [
        (uri("http", "127.0.0.1"), uri("http", "127.0.0.1", port: 51004)),       // RFC 8252 §7.3's own example port range
        (uri("http", "::1"), uri("http", "::1", port: 61023)),
        (uri("http", "127.0.0.1"), uri("http", "127.0.0.1")),
        (uri("http", "127.0.0.1", port: 8080), uri("http", "127.0.0.1", port: 51004)),
        (uri("http", "127.0.0.1", query: "x=1"), uri("http", "127.0.0.1", port: 51004, query: "x=1")),
    ])
    func loopbackIgnoresThePort(registered: String, presented: String) {
        #expect(RedirectURIMatcher.matches(registered: registered, presented: presented))
    }

    @Test("Every other component of a loopback URI must still be equal", arguments: [
        (uri("http", "127.0.0.1"), uri("http", "127.0.0.1", port: 51004, path: "/other")),     // path
        (uri("http", "127.0.0.1"), uri("http", "127.0.0.1", port: 51004, path: "/cb/")),       // path
        (uri("http", "127.0.0.1"), uri("https", "127.0.0.1", port: 51004)),       // scheme
        (uri("http", "127.0.0.1"), uri("http", "127.0.0.2", port: 51004)),        // host
        (uri("http", "127.0.0.1"), uri("http", "127.0.0.1", port: 51004, query: "x=1")),    // query
        (uri("http", "127.0.0.1", query: "x=1"), uri("http", "127.0.0.1", port: 51004)),    // query
        (uri("http", "127.0.0.1"), uri("http", "127.0.0.1", port: 51004, fragment: "frag")),   // fragment
        (uri("http", "127.0.0.1"), uri("http", "127.0.0.1", port: 51004, user: "user")),   // userinfo
        (uri("http", "127.0.0.1"), uri("http", "::1", port: 51004)),            // other IP family
        (uri("http", "::1"), uri("http", "127.0.0.1", port: 51004)),            // other IP family
        (uri("http", "127.0.0.1"), uri("http", "localhost", port: 51004)),        // localhost is not the literal
        (uri("http", "127.0.0.1"), uri("http", "127.0.0.1.evil.example", port: 51004)),
    ])
    func loopbackOtherwiseExact(registered: String, presented: String) {
        #expect(!RedirectURIMatcher.matches(registered: registered, presented: presented))
    }

    @Test("localhost is not treated as loopback: it stays an exact match")
    func localhostIsExact() {
        #expect(RedirectURIMatcher.matches(
            registered: uri("http", "localhost", port: 5000), presented: uri("http", "localhost", port: 5000)))
        #expect(!RedirectURIMatcher.matches(
            registered: uri("http", "localhost"), presented: uri("http", "localhost", port: 5000)))
        #expect(!RedirectURIMatcher.matches(
            registered: uri("http", "localhost", port: 5000), presented: uri("http", "127.0.0.1", port: 5000)))
    }

    @Test("A non-loopback URI needs an exact match, port included", arguments: [
        (uri("https", "app.example.com"), uri("https", "app.example.com", port: 8443)),
        (uri("https", "app.example.com"), uri("https", "app.example.com", path: "/cb/")),
        (uri("https", "app.example.com"), uri("http", "app.example.com")),
        (uri("http", "192.0.2.1"), uri("http", "192.0.2.1", port: 8080)),
        (uri("https", "127.0.0.1"), uri("https", "127.0.0.1", port: 8443)),   // loopback rule is for http only
        ("com.example.app:/cb", "com.example.app:/other"),
    ])
    func everythingElseIsExact(registered: String, presented: String) {
        #expect(!RedirectURIMatcher.matches(registered: registered, presented: presented))
    }

    @Test("An identical URI matches", arguments: [
        uri("https", "app.example.com"), "com.example.app:/cb", "biz.keepitfun.fleetwatch://oauth",
    ])
    func identicalMatches(uri: String) {
        #expect(RedirectURIMatcher.matches(registered: uri, presented: uri))
    }

    @Test("A native registration must be https, loopback http, or a reverse-DNS scheme", arguments: [
        uri("https", "app.example.com"), uri("http", "127.0.0.1"), uri("http", "127.0.0.1", port: 8080),
        uri("http", "::1"), "com.example.app:/cb", "biz.keepitfun.fleetwatch://oauth",
    ])
    func nativeAcceptable(uri: String) {
        #expect(RedirectURIMatcher.nativeRegistrationProblem(uri) == nil)
    }

    @Test("A native registration with another shape is refused", arguments: [
        "myapp:/cb", "myapp://callback", uri("http", "localhost"), uri("http", "app.example.com"),
        uri("http", "192.0.2.1"), "not a uri", "", "/relative/path",
    ])
    func nativeRefused(uri: String) {
        #expect(RedirectURIMatcher.nativeRegistrationProblem(uri) != nil)
    }
}

/// The matcher where it is used: registration and the authorization endpoint, on both stores.
@Suite("RFC 8252 — native clients on the server")
struct NativeClientServerTests {

    private static func makeServer(_ kind: StoreKind) throws -> OAuthServer {
        OAuthServer(
            storage: try kind.makeStore(), issuer: uri("https", "auth.example.com", path: ""),
            scopesSupported: ["read"], served: .core, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
    }

    private static func register(
        _ server: OAuthServer, uris: [String], type: ApplicationType
    ) async throws -> String {
        try await server.registerClient(ClientRegistrationRequest(
            clientName: "App", redirectUris: uris, grantTypes: ["authorization_code"],
            tokenEndpointAuthMethod: "none", applicationType: type)).clientId
    }

    private static func authorize(
        _ server: OAuthServer, clientId: String, redirect: String
    ) async throws -> AuthorizationResponse {
        let challenge = try PKCE.generateCodeChallenge(
            verifier: PKCE.generateCodeVerifier(), method: .s256)
        return try await server.handleAuthorizationRequest(AuthorizationRequest(
            responseType: "code", clientId: clientId, redirectUri: redirect, scope: "read",
            state: nil, codeChallenge: challenge, codeChallengeMethod: "S256"), subject: "alice")
    }

    @Test("A native client registers a reverse-DNS scheme", arguments: StoreKind.allCases)
    func reverseDNSRegisters(store kind: StoreKind) async throws {
        let server = try Self.makeServer(kind)
        let id = try await Self.register(server, uris: ["com.example.app:/cb"], type: .native)
        #expect(!id.isEmpty)
    }

    @Test("FleetWatch's registration passes", arguments: StoreKind.allCases)
    func fleetWatchRegisters(store kind: StoreKind) async throws {
        let server = try Self.makeServer(kind)
        let id = try await Self.register(
            server, uris: ["biz.keepitfun.fleetwatch://oauth"], type: .native)
        #expect(!id.isEmpty)
    }

    @Test("A native client with a bare scheme is refused", arguments: StoreKind.allCases)
    func bareSchemeRefused(store kind: StoreKind) async throws {
        let server = try Self.makeServer(kind)
        do {
            _ = try await Self.register(server, uris: ["myapp:/cb"], type: .native)
            Issue.record("a native client registered a scheme with no period")
        } catch let error as OAuthError {
            #expect(error.code == "invalid_client_metadata")
        }
    }

    @Test("A web client keeps today's rules", arguments: StoreKind.allCases)
    func webClientUnchanged(store kind: StoreKind) async throws {
        let server = try Self.makeServer(kind)
        let id = try await Self.register(server, uris: ["myapp:/cb"], type: .web)
        #expect(!id.isEmpty)
    }

    @Test("A loopback client is honoured on an ephemeral port", arguments: StoreKind.allCases)
    func loopbackEphemeralPort(store kind: StoreKind) async throws {
        let server = try Self.makeServer(kind)
        let id = try await Self.register(
            server, uris: [uri("http", "127.0.0.1"), uri("http", "::1")], type: .native)

        let v4 = try await Self.authorize(server, clientId: id, redirect: uri("http", "127.0.0.1", port: 51004))
        let v6 = try await Self.authorize(server, clientId: id, redirect: uri("http", "::1", port: 61023))
        #expect(!v4.code.isEmpty)
        #expect(!v6.code.isEmpty)
    }

    @Test("A loopback client is not honoured at another path, host or family",
          arguments: StoreKind.allCases)
    func loopbackOtherwiseRefused(store kind: StoreKind) async throws {
        let server = try Self.makeServer(kind)
        let id = try await Self.register(server, uris: [uri("http", "127.0.0.1")], type: .native)

        for presented in [
            uri("http", "127.0.0.1", port: 51004, path: "/other"), uri("http", "localhost", port: 5000), uri("http", "::1", port: 51004),
            uri("https", "127.0.0.1", port: 51004),
        ] {
            do {
                _ = try await Self.authorize(server, clientId: id, redirect: presented)
                Issue.record("\(presented) was honoured against the registered loopback URI")
            } catch is OAuthError {}
        }
    }

    @Test("The validation entry point also honours a loopback port", arguments: StoreKind.allCases)
    func validateEntryPoint(store kind: StoreKind) async throws {
        let server = try Self.makeServer(kind)
        let id = try await Self.register(server, uris: [uri("http", "127.0.0.1")], type: .native)
        let challenge = try PKCE.generateCodeChallenge(
            verifier: PKCE.generateCodeVerifier(), method: .s256)

        let client = try await server.validateAuthorizationRequest(AuthorizationRequest(
            responseType: "code", clientId: id, redirectUri: uri("http", "127.0.0.1", port: 51004),
            scope: "read", state: nil, codeChallenge: challenge, codeChallengeMethod: "S256"))
        #expect(client.clientId == id)
    }

    @Test("A web client's non-loopback URI still needs an exact match", arguments: StoreKind.allCases)
    func webExact(store kind: StoreKind) async throws {
        let server = try Self.makeServer(kind)
        let id = try await Self.register(server, uris: [uri("https", "app.example.com")], type: .web)
        do {
            _ = try await Self.authorize(server, clientId: id, redirect: uri("https", "app.example.com", port: 8443))
            Issue.record("a different port was honoured for a web client")
        } catch is OAuthError {}
    }
}
