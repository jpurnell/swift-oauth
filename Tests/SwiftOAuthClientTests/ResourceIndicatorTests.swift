import Foundation
import Testing
import SwiftOAuthCore
@testable import SwiftOAuthClient

/// RFC 8707 resource indicators — telling the authorization server which API a token is for.
///
/// Without them a token is bearer-shaped and audience-less: an authorization server that
/// protects several resources issues something that any of them will accept, so a token
/// obtained for one service can be replayed against another. The `resource` parameter is what
/// lets the server bind an audience.
///
/// MCP's 2025-06-18 revision **requires** this of clients, naming the canonical URI of the MCP
/// server. Until now this package did not send it, which made every MCP client built on it
/// non-conformant with the revision it was otherwise implementing.
@Suite("Resource indicators — RFC 8707")
struct ResourceIndicatorTests {

    /// The authorization request carries it, so consent is granted for a named audience rather
    /// than for everything the server protects.
    @Test("The authorization URL carries the resource")
    func authorizationURLCarriesResource() async throws {
        let connection = makeResourceConnection(resource: "https://mcp.example.com/mcp")

        let url = await connection.authorizationURL(
            state: "state", challenge: "challenge", redirectURI: "http://127.0.0.1:9000/callback")

        #expect(queryItems(of: url)["resource"] == "https://mcp.example.com/mcp")
    }

    /// A provider with no resource configured sends no parameter — not an empty one. An empty
    /// `resource=` is a request for a token audienced to the empty string, which a strict
    /// server rejects and a lax one honours.
    @Test("No configured resource means no parameter")
    func noResourceMeansNoParameter() async throws {
        let connection = makeResourceConnection(resource: nil)

        let url = await connection.authorizationURL(
            state: "state", challenge: "challenge", redirectURI: "http://127.0.0.1:9000/callback")

        #expect(queryItems(of: url)["resource"] == nil)
    }

    /// The token request carries it too. RFC 8707 §2 requires it on *both* — an authorization
    /// request alone tells the server what to consent to, and the token request is what
    /// actually asks for the audience.
    @Test("The token exchange carries the resource")
    func tokenExchangeCarriesResource() async throws {
        let transport = StubTransport([
            .tokens(access: "access", refresh: "refresh", expiresIn: 3_600)
        ])
        let connection = makeResourceConnection(
            resource: "https://mcp.example.com/mcp", transport: transport)

        _ = try await connection.exchange(
            authorizationCode: "code", verifier: "verifier",
            redirectURI: "http://127.0.0.1:9000/callback")

        let sent = try #require(await transport.requests.first)
        #expect(sent["resource"] == "https://mcp.example.com/mcp")
    }

    /// And the refresh. A token refreshed without it can come back audienced to something
    /// else — or to nothing — which turns a working session into `invalid_audience` at the
    /// resource, long after the sign-in that would explain it.
    @Test("A refresh carries the resource")
    func refreshCarriesResource() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([
            .tokens(access: "refreshed", refresh: "rotated", expiresIn: 3_600)
        ])
        try await storage.store(
            StoredCredential(
                accessToken: "old",
                refreshToken: "old-refresh",
                accessExpiry: clock.now.addingTimeInterval(-1),
                rotatedAt: clock.now.addingTimeInterval(-3_600)),
            for: .testConnection)
        let connection = makeResourceConnection(
            resource: "https://mcp.example.com/mcp",
            transport: transport,
            storage: storage,
            clock: clock)

        _ = try await connection.validAccessToken()

        let sent = try #require(await transport.requests.first)
        #expect(sent["resource"] == "https://mcp.example.com/mcp")
    }

    /// RFC 8707 §2 requires an absolute URI **without a fragment**. A fragment is a
    /// client-side concept the server never sees, so leaving one on makes two clients asking
    /// for the same audience look like they asked for different ones.
    @Test("A fragment is removed from the resource")
    func fragmentIsRemoved() async throws {
        let connection = makeResourceConnection(resource: "https://mcp.example.com/mcp#section")

        let url = await connection.authorizationURL(
            state: "state", challenge: "challenge", redirectURI: "http://127.0.0.1:9000/callback")

        #expect(queryItems(of: url)["resource"] == "https://mcp.example.com/mcp")
    }

    /// A query string is kept. It is part of what identifies the resource, and unlike a
    /// fragment the server does see it.
    @Test("A query string is kept on the resource")
    func queryIsKept() async throws {
        let connection = makeResourceConnection(resource: "https://mcp.example.com/mcp?tenant=acme")

        let url = await connection.authorizationURL(
            state: "state", challenge: "challenge", redirectURI: "http://127.0.0.1:9000/callback")

        #expect(queryItems(of: url)["resource"] == "https://mcp.example.com/mcp?tenant=acme")
    }
}

// MARK: - Helpers

private func makeResourceConnection(
    resource: String?,
    transport: any TokenTransport = StubTransport([]),
    storage: any OAuthClientStorage = InMemoryClientStorage(),
    clock: TestClock = TestClock()
) -> OAuthConnection {
    let configuration = ProviderConfiguration(
        identifier: "test",
        authorizationEndpoint: URL(string: "https://provider.example/authorize") ?? URL(fileURLWithPath: "/"),
        tokenEndpoint: URL(string: "https://provider.example/token") ?? URL(fileURLWithPath: "/"),
        scope: "mcp:tools",
        // SECURITY: parses a literal written in this test; nothing reaches it from a server.
        resource: resource.flatMap { URL(string: $0) })
    return OAuthConnection(
        configuration: configuration,
        credentials: .testCredentials,
        storage: storage,
        connection: .testConnection,
        transport: transport,
        now: { clock.now })
}

/// The query of a URL, as a dictionary.
private func queryItems(of url: URL) -> [String: String] {
    guard let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems else {
        return [:]
    }
    return Dictionary(items.compactMap { item in
        item.value.map { (item.name, $0) }
    }, uniquingKeysWith: { first, _ in first })
}
