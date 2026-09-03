import Foundation
import Testing
import SwiftOAuthCore
import SwiftOAuthClient
import SwiftOAuthProvider

/// The two halves, checked against each other.
///
/// `SwiftOAuthClient` and `SwiftOAuthProvider` do not depend on one another — that is
/// deliberate, so a consumer that only issues tokens never links client code. The cost is
/// that nothing otherwise checks they agree on the wire. Each half has passed its own tests
/// against its own idea of the format for as long as both existed.
///
/// A mismatch here is not a compile error and not a test failure in either suite. It is a
/// client that cannot talk to the server in the same package.
@Suite("Conformance — the halves agree on the wire")
struct WireConformanceTests {

    /// The provider's metadata must decode into the client's discovery type, with every
    /// field the client needs actually populated.
    @Test("Provider metadata decodes as client discovery metadata")
    func metadataRoundTrips() async throws {
        let server = try await makeServer()
        let published = await server.getMetadata()

        let data = try JSONEncoder().encode(published)
        let discovered = try JSONDecoder().decode(AuthorizationServerMetadata.self, from: data)

        #expect(discovered.issuer == published.issuer)
        #expect(discovered.authorizationEndpoint == published.authorizationEndpoint)
        #expect(discovered.tokenEndpoint == published.tokenEndpoint)
        #expect(discovered.registrationEndpoint == published.registrationEndpoint)
        #expect(discovered.codeChallengeMethodsSupported == ["S256"])
    }

    /// And must survive being turned into a configuration — the point of discovery.
    @Test("Discovered metadata becomes a usable configuration")
    func metadataBecomesConfiguration() async throws {
        // The test server issues `http://localhost` endpoints, which discovery refuses. That
        // refusal is the correct behaviour, so the agreement is checked against an issuer
        // shaped the way a deployed server's would be.
        let server = OAuthServer(
            storage: try makeStorage(), issuer: "https://mcp.example.com")
        let published = await server.getMetadata()
        let data = try JSONEncoder().encode(published)
        let discovered = try JSONDecoder().decode(AuthorizationServerMetadata.self, from: data)

        let configuration = try discovered.configuration(identifier: "mcp")
        #expect(configuration.authorizationEndpoint.absoluteString
                == "https://mcp.example.com/authorize")
        #expect(configuration.tokenEndpoint.absoluteString == "https://mcp.example.com/token")
        #expect(configuration.scope.contains("mcp:tools"))
    }

    /// A server that advertises no PKCE support must be refused rather than used, since the
    /// flow would then run with no protection against code interception.
    @Test("A server without S256 is refused at configuration")
    func serverWithoutPKCERefused() throws {
        let metadata = AuthorizationServerMetadata(
            issuer: "https://legacy.example.com",
            authorizationEndpoint: "https://legacy.example.com/authorize",
            tokenEndpoint: "https://legacy.example.com/token",
            codeChallengeMethodsSupported: nil)

        #expect(throws: DiscoveryError.pkceUnsupported) {
            try metadata.configuration(identifier: "legacy")
        }
    }

    /// The client's registration request must be what the provider expects to receive, and
    /// the provider's response must be what the client expects to read. This is the exchange
    /// an MCP client cannot avoid — it has no pre-registered credentials.
    @Test("A client registration request round-trips through the provider")
    func registrationRoundTrips() async throws {
        let server = try await makeServer()

        let clientRequest = SwiftOAuthClient.ClientRegistrationRequest(
            clientName: "Conformance Client",
            redirectUris: ["https://app.example/cb"],
            scope: "mcp:tools")

        // Encode as the client would send it, decode as the provider would receive it.
        let requestData = try JSONEncoder().encode(clientRequest)
        let providerRequest = try JSONDecoder().decode(
            SwiftOAuthProvider.ClientRegistrationRequest.self, from: requestData)

        #expect(providerRequest.clientName == "Conformance Client")
        #expect(providerRequest.redirectUris == ["https://app.example/cb"])
        #expect(providerRequest.tokenEndpointAuthMethod == "none")

        let providerResponse = try await server.registerClient(providerRequest)

        // And back the other way.
        let responseData = try JSONEncoder().encode(providerResponse)
        let clientResponse = try JSONDecoder().decode(
            SwiftOAuthClient.ClientRegistrationResponse.self, from: responseData)

        #expect(clientResponse.clientId == providerResponse.clientId)
        #expect(!clientResponse.clientId.isEmpty)

        // Registered with `none`, so no secret should come back — and the client must
        // therefore choose `none` at the token endpoint rather than `client_secret_basic`.
        #expect(clientResponse.clientSecret == nil)
        #expect(clientResponse.authenticationMethod == .none)
    }

    /// A confidential client gets a secret, and must then authenticate with it.
    @Test("A confidential registration yields a secret and the matching method")
    func confidentialRegistration() async throws {
        let server = try await makeServer()

        let providerRequest = SwiftOAuthProvider.ClientRegistrationRequest(
            clientName: "Confidential Client",
            redirectUris: ["https://app.example/cb"],
            grantTypes: ["authorization_code", "refresh_token"],
            tokenEndpointAuthMethod: "client_secret_basic",
            scope: nil)

        let providerResponse = try await server.registerClient(providerRequest)
        let data = try JSONEncoder().encode(providerResponse)
        let clientResponse = try JSONDecoder().decode(
            SwiftOAuthClient.ClientRegistrationResponse.self, from: data)

        #expect(clientResponse.clientSecret?.isEmpty == false)
        #expect(clientResponse.authenticationMethod == .clientSecretBasic)
    }

    /// The provider's error responses must decode as the client's `OAuthError`.
    ///
    /// This is the pairing that was actually broken: `OAuthError` used the synthesized
    /// `Codable` conformance, which emits `{"invalidRequest":{"_0":…}}`. Both halves passed
    /// their own suites while being unable to exchange a single error.
    @Test("Provider errors decode as client errors")
    func errorsRoundTrip() throws {
        let cases: [(OAuthError, String)] = [
            (.invalidRequest(nil), "invalid_request"),
            (.invalidClient(nil), "invalid_client"),
            (.invalidGrant("already rotated"), "invalid_grant"),
            (.unauthorizedClient(nil), "unauthorized_client"),
            (.unsupportedGrantType(nil), "unsupported_grant_type"),
            (.invalidScope(nil), "invalid_scope"),
            (.serverError("boom"), "server_error"),
            (.temporarilyUnavailable(nil), "temporarily_unavailable"),
            (.accessDenied(nil), "access_denied")
        ]

        for (error, expectedCode) in cases {
            let data = try JSONEncoder().encode(error)

            // The shape a peer actually sees.
            let raw = try #require(
                try JSONSerialization.jsonObject(with: data) as? [String: Any])
            #expect(raw["error"] as? String == expectedCode,
                    "\(expectedCode) did not encode as an OAuth error object")
            #expect(raw["error_description"] is String)

            let decoded = try JSONDecoder().decode(OAuthError.self, from: data)
            #expect(decoded.code == expectedCode)
        }
    }

    /// A detail supplied by the server must survive the trip, since it is the only part of
    /// an error that says anything specific.
    @Test("An error detail survives the round trip")
    func errorDetailSurvives() throws {
        let original = OAuthError.invalidGrant("this refresh token was already rotated")
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(OAuthError.self, from: data)
        #expect(decoded == original)
    }

    /// The provider's token response must decode as the client's, or a successful
    /// authorization ends in a decode failure.
    @Test("A provider token response decodes as a client token response")
    func tokenResponseRoundTrips() async throws {
        let server = try await makeServer()
        // Registered the way a client actually registers — through the client's own request
        // type, which asks for `refresh_token`. The provider's type defaults to
        // `authorization_code` alone; see `refreshlessRegistrationIsRefusedLegibly`.
        let client = try await server.registerClient(
            try providerRequest(from: SwiftOAuthClient.ClientRegistrationRequest(
                clientName: "Token Client",
                redirectUris: ["https://app.example/cb"])))

        let verifier = PKCE.generateCodeVerifier()
        let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

        let authorization = try await server.handleAuthorizationRequest(
            AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "https://app.example/cb",
                scope: "mcp:tools",
                state: "state",
                codeChallenge: challenge,
                codeChallengeMethod: "S256"))

        let issued = try await server.handleTokenRequest(
            TokenRequest(
                grantType: "authorization_code",
                code: authorization.code,
                redirectUri: "https://app.example/cb",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: verifier,
                refreshToken: nil))

        let data = try JSONEncoder().encode(issued)
        let decoded = try JSONDecoder().decode(TokenResponse.self, from: data)

        #expect(decoded.accessToken == issued.accessToken)
        #expect(decoded.tokenType == "Bearer")
        #expect(decoded.expiresIn > 0)

        // A credential must be constructible from it, or the client cannot store the result
        // of a flow the server considers complete.
        let credential = try #require(
            StoredCredential(from: decoded, received: Date(timeIntervalSince1970: 1_767_225_600)))
        #expect(credential.accessToken == issued.accessToken)
    }

    /// The two halves default differently, and the difference is only visible at the end.
    ///
    /// `SwiftOAuthClient.ClientRegistrationRequest` asks for `refresh_token`;
    /// `SwiftOAuthProvider.ClientRegistrationRequest` defaults to `authorization_code` alone.
    /// Register the provider's way and the flow succeeds all the way through token issuance —
    /// then the client refuses to store the result, because a credential with no refresh
    /// token stops working within the hour and storing it would promise otherwise.
    ///
    /// The refusal is correct. This test exists so that it stays legible rather than becoming
    /// a mysterious nil at the end of a working flow.
    @Test("A registration without refresh_token yields a credential the client refuses")
    func refreshlessRegistrationIsRefusedLegibly() async throws {
        let server = try await makeServer()
        let client = try await server.registerClient(
            SwiftOAuthProvider.ClientRegistrationRequest(
                clientName: "Refreshless Client",
                redirectUris: ["https://app.example/cb"]))

        let verifier = PKCE.generateCodeVerifier()
        let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)
        let authorization = try await server.handleAuthorizationRequest(
            AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "https://app.example/cb",
                scope: "mcp:tools",
                state: "state",
                codeChallenge: challenge,
                codeChallengeMethod: "S256"))

        let issued = try await server.handleTokenRequest(
            TokenRequest(
                grantType: "authorization_code",
                code: authorization.code,
                redirectUri: "https://app.example/cb",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: verifier,
                refreshToken: nil))

        // The server considers this a complete success.
        #expect(!issued.accessToken.isEmpty)
        #expect(issued.refreshToken == nil)

        // The client will not store it, and that is the right answer.
        let data = try JSONEncoder().encode(issued)
        let decoded = try JSONDecoder().decode(TokenResponse.self, from: data)
        #expect(StoredCredential(from: decoded, received: Date(timeIntervalSince1970: 1_767_225_600)) == nil,
                "a credential that cannot be renewed was stored anyway")
    }

    /// The client generates the PKCE pair and the provider verifies it. Both use Core's
    /// implementation, so this checks the *flow* rather than the algorithm: that what
    /// `beginAuthorization` produces is what the server will accept.
    @Test("A client-generated PKCE pair verifies at the provider")
    func pkcePairVerifiesEndToEnd() async throws {
        let server = try await makeServer()
        let registered = try await server.registerClient(
            SwiftOAuthProvider.ClientRegistrationRequest(
                clientName: "PKCE Client",
                redirectUris: ["https://app.example/cb"]))

        let connection = OAuthConnection(
            configuration: ProviderConfiguration(
                identifier: "mcp",
                authorizationEndpoint: try #require(URL(string: "https://mcp.example.com/authorize")),
                tokenEndpoint: try #require(URL(string: "https://mcp.example.com/token")),
                scope: "mcp:tools",
                authenticationMethod: .none),
            credentials: ClientCredentials(
                environment: "test", clientID: registered.clientId, clientSecret: ""),
            storage: InMemoryClientStorage(),
            connection: ConnectionID(tenant: "t", provider: "mcp"))

        let begun = await connection.beginAuthorization(redirectURI: "https://app.example/cb")

        // Pull the challenge back out of the URL the client built — that is what the server
        // would actually receive.
        let components = try #require(
            URLComponents(url: begun.url, resolvingAgainstBaseURL: false))
        let challenge = try #require(
            components.queryItems?.first { $0.name == "code_challenge" }?.value)

        let authorization = try await server.handleAuthorizationRequest(
            AuthorizationRequest(
                responseType: "code",
                clientId: registered.clientId,
                redirectUri: "https://app.example/cb",
                scope: "mcp:tools",
                state: begun.pending.state,
                codeChallenge: challenge,
                codeChallengeMethod: "S256"))

        // The verifier the client kept must redeem the code the server issued.
        let issued = try await server.handleTokenRequest(
            TokenRequest(
                grantType: "authorization_code",
                code: authorization.code,
                redirectUri: "https://app.example/cb",
                clientId: registered.clientId,
                clientSecret: nil,
                codeVerifier: begun.pending.verifier,
                refreshToken: nil))

        #expect(!issued.accessToken.isEmpty)

        // And a *different* verifier must not, or PKCE is verifying nothing.
        let second = try await server.handleAuthorizationRequest(
            AuthorizationRequest(
                responseType: "code",
                clientId: registered.clientId,
                redirectUri: "https://app.example/cb",
                scope: "mcp:tools",
                state: "state-2",
                codeChallenge: challenge,
                codeChallengeMethod: "S256"))

        await #expect(throws: OAuthError.self) {
            _ = try await server.handleTokenRequest(
                TokenRequest(
                    grantType: "authorization_code",
                    code: second.code,
                    redirectUri: "https://app.example/cb",
                    clientId: registered.clientId,
                    clientSecret: nil,
                    codeVerifier: PKCE.generateCodeVerifier(),
                    refreshToken: nil))
        }
    }
}

// MARK: - Helpers

/// Sends a client's registration request through JSON, as it would reach a server.
private func providerRequest(
    from request: SwiftOAuthClient.ClientRegistrationRequest
) throws -> SwiftOAuthProvider.ClientRegistrationRequest {
    try JSONDecoder().decode(
        SwiftOAuthProvider.ClientRegistrationRequest.self,
        from: try JSONEncoder().encode(request))
}

private func makeStorage() throws -> OAuthStorage {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return try OAuthStorage(path: directory.appendingPathComponent("oauth.db").path)
}

private func makeServer() async throws -> OAuthServer {
    OAuthServer(storage: try makeStorage(), issuer: "https://mcp.example.com",
            // These suites predate RFC 8707 and exercise other things — grants, PKCE, consent, wire
            // shapes. Strict resource indicators would make every one of them carry a `resource`
            // parameter that has nothing to do with what they test. The strict default has its own
            // coverage in ResourceIndicatorTests and AudienceBindingTests.
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
}
