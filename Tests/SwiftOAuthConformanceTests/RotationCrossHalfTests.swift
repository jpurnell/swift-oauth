import Foundation
import Testing
import SwiftOAuthCore
import SwiftOAuthClient
import SwiftOAuthProvider

/// Refresh-token rotation, the package's own client against a rotating provider.
///
/// The client has handled rotation since 0.12 (`OAuthConnection` stores whatever refresh token
/// a response carries before it returns the access token) and the provider never rotated, so the
/// two halves had never been run against each other doing it. Each hop goes through the
/// provider's HTTP handler as a form body and a status.
@Suite("Conformance — rotation across the halves, over HTTP")
struct RotationCrossHalfTests {

    static let issuer = "https://mcp.example.com"

    private static func provider(
        _ policy: RefreshTokenRotationPolicy
    ) throws -> (OAuthServer, ProviderOverHTTP, SharedClock) {
        let clock = SharedClock()
        let server = OAuthServer(
            storage: try OAuthStorage(path: ":memory:"), issuer: issuer,
            scopesSupported: ["mcp:tools"],
            served: try ServedCapabilities(
                grantTypes: [.authorizationCode, .refreshToken, .deviceCode],
                clientAuthenticationMethods: [.none, .clientSecretBasic],
                deviceAuthorization: "\(issuer)/device_authorization"),
            resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true),
            rotationPolicy: policy,
            now: { clock.now })
        return (server, ProviderOverHTTP(handler: OAuthHTTPHandler(server: server)), clock)
    }

    /// A client signed in by the device grant, holding a credential that is already expired
    /// so that its next use refreshes.
    private static func signedIn(
        _ server: OAuthServer, wire: ProviderOverHTTP, clock: SharedClock, storage: InMemoryClientStorage
    ) async throws -> (OAuthConnection, ConnectionID, TokenResponse) {
        let handler = OAuthHTTPHandler(server: server)
        let registration = await handler.handleRegistrationRequest(body: """
            {"client_name":"Terminal","redirect_uris":[],
             "grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],
             "token_endpoint_auth_method":"none"}
            """)
        let registered: SwiftOAuthProvider.ClientRegistrationResponse = try ProviderOverHTTP.read(registration)
        let credentials = ClientCredentials(
            environment: "test", clientID: registered.clientId, clientSecret: "")
        let issued = try await server.authorizeDevice(clientId: credentials.clientID, scope: "mcp:tools")
        try await server.approveDeviceCode(userCode: issued.userCode, subject: "ada")
        clock.advance(6)
        let tokens = try await server.redeemDeviceCode(issued.deviceCode, clientId: credentials.clientID)

        let connectionID = ConnectionID(tenant: "t", provider: "mcp", account: "ada")
        try await storage.store(
            StoredCredential(
                accessToken: tokens.accessToken, refreshToken: try #require(tokens.refreshToken),
                accessExpiry: clock.now.addingTimeInterval(-1), rotatedAt: clock.now),
            for: connectionID)
        let configuration = ProviderConfiguration(
            identifier: "mcp",
            authorizationEndpoint: try #require(URL(string: "\(issuer)/authorize")),
            tokenEndpoint: try #require(URL(string: "\(issuer)/token")),
            scope: "mcp:tools", authenticationMethod: .none)
        let connection = OAuthConnection(
            configuration: configuration, credentials: credentials, storage: storage,
            connection: connectionID, transport: wire, now: { clock.now })
        return (connection, connectionID, tokens)
    }

    @Test("A client refreshes through several rotations, each time with the token it was last given")
    func clientFollowsRotation() async throws {
        let (server, wire, clock) = try Self.provider(.rotating)
        let storage = InMemoryClientStorage()
        let (connection, connectionID, tokens) = try await Self.signedIn(
            server, wire: wire, clock: clock, storage: storage)
        let original = try #require(tokens.refreshToken)

        var seen: [String] = [original]
        for round in 1...3 {
            let access = try await connection.validAccessToken()
            #expect(try await server.introspect(token: access).active, "round \(round)")
            let stored = try #require(try await storage.credential(for: connectionID))
            #expect(!seen.contains(stored.refreshToken), "round \(round) kept an old refresh token")
            seen.append(stored.refreshToken)
            // Expire it again so the next call refreshes.
            try await storage.store(
                StoredCredential(
                    accessToken: stored.accessToken, refreshToken: stored.refreshToken,
                    accessExpiry: clock.now.addingTimeInterval(-1),
                    previousRefreshToken: stored.previousRefreshToken, rotatedAt: stored.rotatedAt),
                for: connectionID)
        }
        #expect(Set(seen).count == 4)
    }

    @Test("A client that presents the token it was rotated away from is refused, and loses its grant")
    func staleTokenEndsTheGrant() async throws {
        let (server, wire, clock) = try Self.provider(.rotating)
        let storage = InMemoryClientStorage()
        let (connection, connectionID, tokens) = try await Self.signedIn(
            server, wire: wire, clock: clock, storage: storage)
        let original = try #require(tokens.refreshToken)

        let fresh = try await connection.validAccessToken()
        #expect(try await server.introspect(token: fresh).active)

        // A client that restored a backup: it holds the first refresh token again.
        try await storage.store(
            StoredCredential(
                accessToken: "stale", refreshToken: original,
                accessExpiry: clock.now.addingTimeInterval(-1), rotatedAt: clock.now),
            for: connectionID)
        await #expect(throws: (any Error).self) {
            _ = try await connection.validAccessToken()
        }

        #expect(try await server.introspect(token: fresh).active == false,
                "the grant should be gone, not just the stale token")
    }

    @Test("Under .reusable the client keeps its one refresh token, as before")
    func reusableKeepsTheToken() async throws {
        let (server, wire, clock) = try Self.provider(.reusable)
        let storage = InMemoryClientStorage()
        let (connection, connectionID, tokens) = try await Self.signedIn(
            server, wire: wire, clock: clock, storage: storage)

        _ = try await connection.validAccessToken()

        let stored = try #require(try await storage.credential(for: connectionID))
        #expect(stored.refreshToken == tokens.refreshToken)
    }
}
