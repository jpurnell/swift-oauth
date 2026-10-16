import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// The provider issues `client_credentials` tokens — opt-in, to operator-created clients only.
///
/// The provider used to refuse this grant outright, because it issues access with no user
/// present. The concern was who could obtain such access, and these suites hold the answers
/// that replace the refusal: no one can self-register for it, the deployment must opt in, a
/// service client's scopes are fixed when an operator creates it, and its tokens are short and
/// never refreshed. See `project/plans/proposals/ProviderClientCredentials.md`.
enum ClientCredentialsFixtures {

    static func makeServer(
        served: ServedCapabilities = .core, scopesSupported: [String]? = ["push:send:fleet", "push:read"]
    ) throws -> (OAuthServer, OAuthStorage) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(
            storage: storage, issuer: "https://hub.example.com",
            scopesSupported: scopesSupported, served: served, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        return (server, storage)
    }
}

/// Dynamic registration is open to anyone who can reach `/register`. A machine identity
/// minted there would be exactly the unattended access the original refusal was about.
@Suite("Client credentials — registration is closed to it")
struct ClientCredentialsRegistrationTests {

    @Test("Registering for client_credentials is refused", arguments: [
        ["client_credentials"],
        ["authorization_code", "client_credentials"]
    ])
    func registrationRefused(grantTypes: [String]) async throws {
        let (server, _) = try ClientCredentialsFixtures.makeServer()
        await #expect(throws: OAuthError.invalidClientMetadata(
            "client_credentials clients are created by an operator, not through registration.")
        ) {
            _ = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Would-be service",
                redirectUris: ["https://client.example.com/cb"],
                grantTypes: grantTypes))
        }
    }

    @Test("Over HTTP, the refusal is a 400 invalid_client_metadata")
    func registrationRefusedOverHTTP() async throws {
        let (server, _) = try ClientCredentialsFixtures.makeServer()
        let handler = OAuthHTTPHandler(server: server)
        let response = await handler.handleRegistrationRequest(body: """
            {"client_name":"Would-be service","redirect_uris":["https://client.example.com/cb"],
             "grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_basic"}
            """)

        #expect(response.statusCode == 400)
        #expect(response.body.contains("\"invalid_client_metadata\""))
    }
}

/// An operator creates a service client; nothing reachable over HTTP does.
@Suite("Client credentials — operator-created service clients")
struct ServiceClientCreationTests {

    @Test("A service client is created with its scopes, a secret, and only this grant")
    func createsServiceClient() async throws {
        let (server, storage) = try ClientCredentialsFixtures.makeServer()

        let created = try await server.createServiceClient(
            name: "Fleet monitor", scopes: ["push:send:fleet"])

        #expect(!created.clientId.isEmpty)
        #expect(created.clientSecret.count >= 32)
        #expect(created.scopes == ["push:send:fleet"])

        let stored = try #require(await storage.getClient(clientId: created.clientId))
        #expect(stored.grantTypes == [GrantType.clientCredentials.rawValue])
        #expect(stored.scopeCeiling == ["push:send:fleet"])
        #expect(stored.redirectUris.isEmpty)
        #expect(stored.tokenEndpointAuthMethod == "client_secret_basic")
        #expect(try await storage.clientSecretMatches(
            clientId: created.clientId, presented: created.clientSecret))
    }

    /// Without a secret, a service client would be a bearer of nothing: anyone who learned its
    /// id could obtain its tokens.
    @Test("A public service client is refused")
    func publicServiceClientRefused() async throws {
        let (server, _) = try ClientCredentialsFixtures.makeServer()
        await #expect(throws: OAuthError.self) {
            _ = try await server.createServiceClient(
                name: "Anyone", scopes: ["push:send:fleet"], authentication: .none)
        }
    }

    /// A service client with no scopes would hold a token good for whatever a resource server
    /// assumes an empty scope means — the unscoped credential this replaces.
    @Test("A service client with no scopes is refused")
    func emptyScopesRefused() async throws {
        let (server, _) = try ClientCredentialsFixtures.makeServer()
        await #expect(throws: OAuthError.self) {
            _ = try await server.createServiceClient(name: "Unscoped", scopes: [])
        }
    }

    @Test("A scope the deployment does not offer is refused")
    func unofferedScopeRefused() async throws {
        let (server, _) = try ClientCredentialsFixtures.makeServer()
        await #expect(throws: OAuthError.self) {
            _ = try await server.createServiceClient(
                name: "Overreaching", scopes: ["push:send:fleet", "admin"])
        }
    }
}

/// A client's scope ceiling binds every flow, not only `client_credentials`.
///
/// Without that, a channel-scoped design fails at the first dynamically registered client: it
/// asks for `push:send:fleet` at `/authorize`, a person clicks Approve, and the ceiling a
/// service client was held to means nothing.
@Suite("Scope ceiling — every flow")
struct ScopeCeilingTests {

    private static let redirect = "https://app.example.com/cb"

    private static func saveCeilinged(_ storage: OAuthStorage, ceiling: Set<String>?) async throws {
        try await storage.saveClient(RegisteredClient(
            clientId: "app", clientSecret: nil, clientName: "App",
            redirectUris: [redirect], grantTypes: ["authorization_code"],
            tokenEndpointAuthMethod: "none", registrationDate: Date(),
            scopeCeiling: ceiling))
    }

    private static func authorize(scope: String?) -> AuthorizationRequest {
        AuthorizationRequest(
            responseType: "code", clientId: "app", redirectUri: redirect,
            scope: scope, state: "s",
            codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            codeChallengeMethod: "S256")
    }

    @Test("The ceiling survives storage")
    func ceilingRoundTrips() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        try await Self.saveCeilinged(storage, ceiling: ["push:read", "push:register"])

        let stored = try #require(await storage.getClient(clientId: "app"))
        #expect(stored.scopeCeiling == ["push:read", "push:register"])
    }

    @Test("A client with no ceiling has none after storage")
    func absentCeilingRoundTrips() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        try await Self.saveCeilinged(storage, ceiling: nil)

        let stored = try #require(await storage.getClient(clientId: "app"))
        #expect(stored.scopeCeiling == nil)
    }

    @Test("Asking /authorize for more than the ceiling is refused before consent")
    func authorizeBeyondCeilingRefused() async throws {
        let (server, storage) = try ClientCredentialsFixtures.makeServer()
        try await Self.saveCeilinged(storage, ceiling: ["push:read"])

        await #expect(throws: OAuthError.self) {
            _ = try await server.validateAuthorizationRequest(Self.authorize(scope: "push:read push:send:fleet"))
        }
        await #expect(throws: OAuthError.self) {
            _ = try await server.handleAuthorizationRequest(Self.authorize(scope: "push:send:fleet"))
        }
    }

    @Test("Within the ceiling, the code carries what was asked for")
    func authorizeWithinCeiling() async throws {
        let (server, storage) = try ClientCredentialsFixtures.makeServer()
        try await Self.saveCeilinged(storage, ceiling: ["push:read", "push:register"])

        let response = try await server.handleAuthorizationRequest(Self.authorize(scope: "push:read"))
        let code = try #require(await storage.getAuthorizationCode(code: response.code))
        #expect(code.scope == "push:read")
    }

    /// Absent a requested scope, a ceilinged client gets its ceiling — not a default invented
    /// for some other deployment.
    @Test("With no scope requested, the code carries the ceiling")
    func authorizeWithoutScopeGetsCeiling() async throws {
        let (server, storage) = try ClientCredentialsFixtures.makeServer()
        try await Self.saveCeilinged(storage, ceiling: ["push:register", "push:read"])

        let response = try await server.handleAuthorizationRequest(Self.authorize(scope: nil))
        let code = try #require(await storage.getAuthorizationCode(code: response.code))
        #expect(code.scope == "push:read push:register")
    }

    @Test("The device flow is held to the ceiling too")
    func deviceFlowBeyondCeilingRefused() async throws {
        let (server, storage) = try ClientCredentialsFixtures.makeServer()
        try await Self.saveCeilinged(storage, ceiling: ["push:read"])

        await #expect(throws: OAuthError.self) {
            _ = try await server.authorizeDevice(clientId: "app", scope: "push:send:fleet")
        }
    }

    @Test("A database from an earlier release gains the ceiling column")
    func upgradeAddsCeilingColumn() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("oauth-ceiling-\(UUID().uuidString).sqlite").path
        // SECURITY: removes only the uniquely-named temp file this test just created.
        defer { try? FileManager.default.removeItem(atPath: path) }

        _ = try OAuthStorage(path: path, schemaVersion: 6)
        let upgraded = try OAuthStorage(path: path)
        try await Self.saveCeilinged(upgraded, ceiling: ["push:read"])

        #expect(try await upgraded.getClient(clientId: "app")?.scopeCeiling == ["push:read"])
    }
}
