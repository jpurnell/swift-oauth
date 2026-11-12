import Foundation
import Testing
import CSQLite
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// RFC 7009: a provider that can be asked to revoke a token.
///
/// Expected values come from the RFC: §2.1 (request; the hint is a hint; revoking a refresh token
/// SHOULD end the access tokens of the same grant; the token must belong to the requesting
/// client), §2.2 (200 for success and for an invalid token) and §2.2.1 (503 means the token
/// still exists).
@Suite("RFC 7009 revocation endpoint")
struct RevocationEndpointTests {

    static let issuer = "https://auth.example.com"

    private static func makeServer(
        _ storage: any OAuthProviderStorage
    ) throws -> OAuthServer {
        OAuthServer(
            storage: storage, issuer: issuer, scopesSupported: ["read", "write"],
            served: try ServedCapabilities(
                grantTypes: [.authorizationCode, .refreshToken],
                clientAuthenticationMethods: [.clientSecretBasic, .clientSecretPost, .none],
                revocation: "\(issuer)/revoke"),
            resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
    }

    /// A registered client and the credential it would present.
    struct Registered {
        let clientId: String
        let secret: String?
    }

    private static func register(_ server: OAuthServer, confidential: Bool) async throws -> Registered {
        let response = try await server.registerClient(ClientRegistrationRequest(
            clientName: "App", redirectUris: ["https://app.example.com/cb"],
            grantTypes: ["authorization_code", "refresh_token"],
            tokenEndpointAuthMethod: confidential ? "client_secret_post" : "none"))
        return Registered(clientId: response.clientId, secret: response.clientSecret)
    }

    /// The authorization code grant, run to completion for `client`.
    private static func issue(_ server: OAuthServer, client: Registered) async throws -> TokenResponse {
        let verifier = PKCE.generateCodeVerifier()
        let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)
        let authorization = try await server.handleAuthorizationRequest(
            AuthorizationRequest(
                responseType: "code", clientId: client.clientId,
                redirectUri: "https://app.example.com/cb", scope: "read", state: nil,
                codeChallenge: challenge, codeChallengeMethod: "S256"),
            subject: "alice")
        return try await server.handleTokenRequest(TokenRequest(
            grantType: "authorization_code", code: authorization.code,
            redirectUri: "https://app.example.com/cb", clientId: client.clientId,
            clientSecret: client.secret, codeVerifier: verifier, refreshToken: nil))
    }

    private static func refresh(
        _ server: OAuthServer, client: Registered, token: String
    ) async throws -> TokenResponse {
        try await server.handleTokenRequest(TokenRequest(
            grantType: "refresh_token", code: nil, redirectUri: nil, clientId: client.clientId,
            clientSecret: client.secret, codeVerifier: nil, refreshToken: token))
    }

    private static func form(
        token: String?, hint: String? = nil, client: Registered?, withSecret: Bool = true
    ) -> String {
        var pairs: [String] = []
        if let token { pairs.append("token=\(token)") }
        if let hint { pairs.append("token_type_hint=\(hint)") }
        if let client {
            pairs.append("client_id=\(client.clientId)")
            if withSecret, let secret = client.secret { pairs.append("client_secret=\(secret)") }
        }
        return pairs.joined(separator: "&")
    }

    private static func isActive(_ server: OAuthServer, _ token: String) async throws -> Bool {
        try await server.introspect(token: token).active
    }

    // MARK: - §2.1: the whole grant

    @Test("Revoking a refresh token ends the refresh grant and every access token of the grant (§2.1)",
          arguments: StoreKind.allCases)
    func refreshRevocationTakesTheGrant(store kind: StoreKind) async throws {
        let server = try Self.makeServer(try kind.makeStore())
        let handler = OAuthHTTPHandler(server: server)
        let client = try await Self.register(server, confidential: true)
        let first = try await Self.issue(server, client: client)
        let firstRefresh = try #require(first.refreshToken)
        let second = try await Self.refresh(server, client: client, token: firstRefresh)
        // Whichever refresh token is current: the same one, or its replacement under rotation.
        let current = second.refreshToken ?? firstRefresh
        #expect(try await Self.isActive(server, first.accessToken))
        #expect(try await Self.isActive(server, second.accessToken))

        let response = await handler.handleRevocationRequest(
            body: Self.form(token: current, hint: "refresh_token", client: client), authHeader: nil)

        #expect(response.statusCode == 200)
        #expect(try await Self.isActive(server, first.accessToken) == false)
        #expect(try await Self.isActive(server, second.accessToken) == false)
        await #expect(throws: OAuthError.self) {
            _ = try await Self.refresh(server, client: client, token: current)
        }
    }

    @Test("Revoking an access token leaves its refresh token (§2.1 says only that it may)",
          arguments: StoreKind.allCases)
    func accessRevocationLeavesRefreshToken(store kind: StoreKind) async throws {
        let server = try Self.makeServer(try kind.makeStore())
        let handler = OAuthHTTPHandler(server: server)
        let client = try await Self.register(server, confidential: true)
        let issued = try await Self.issue(server, client: client)
        let refreshToken = try #require(issued.refreshToken)

        let response = await handler.handleRevocationRequest(
            body: Self.form(token: issued.accessToken, hint: "access_token", client: client),
            authHeader: nil)

        #expect(response.statusCode == 200)
        #expect(try await Self.isActive(server, issued.accessToken) == false)
        let refreshed = try await Self.refresh(server, client: client, token: refreshToken)
        #expect(try await Self.isActive(server, refreshed.accessToken))
    }

    // MARK: - §2.1: the hint is only a hint

    @Test("A wrong token_type_hint still finds the token (§2.1: the server MUST extend its search)",
          arguments: StoreKind.allCases)
    func wrongHintStillWorks(store kind: StoreKind) async throws {
        let server = try Self.makeServer(try kind.makeStore())
        let handler = OAuthHTTPHandler(server: server)
        let client = try await Self.register(server, confidential: true)
        let issued = try await Self.issue(server, client: client)
        let refreshToken = try #require(issued.refreshToken)

        // An access token declared a refresh token, and the other way round.
        _ = await handler.handleRevocationRequest(
            body: Self.form(token: issued.accessToken, hint: "refresh_token", client: client),
            authHeader: nil)
        #expect(try await Self.isActive(server, issued.accessToken) == false)
        _ = await handler.handleRevocationRequest(
            body: Self.form(token: refreshToken, hint: "access_token", client: client),
            authHeader: nil)
        await #expect(throws: OAuthError.self) {
            _ = try await Self.refresh(server, client: client, token: refreshToken)
        }
    }

    @Test("An unrecognised hint is ignored, not an error (§2.2: an invalid hint does not change the response)",
          arguments: StoreKind.allCases)
    func unrecognisedHintIsIgnored(store kind: StoreKind) async throws {
        let server = try Self.makeServer(try kind.makeStore())
        let handler = OAuthHTTPHandler(server: server)
        let client = try await Self.register(server, confidential: true)
        let issued = try await Self.issue(server, client: client)

        let response = await handler.handleRevocationRequest(
            body: Self.form(token: issued.accessToken, hint: "id_token", client: client),
            authHeader: nil)

        #expect(response.statusCode == 200)
        #expect(try await Self.isActive(server, issued.accessToken) == false)
    }

    // MARK: - §2.2: the response

    @Test("An unknown or already revoked token answers 200 with an empty body (§2.2)",
          arguments: StoreKind.allCases)
    func invalidTokenIs200(store kind: StoreKind) async throws {
        let server = try Self.makeServer(try kind.makeStore())
        let handler = OAuthHTTPHandler(server: server)
        let client = try await Self.register(server, confidential: true)
        let issued = try await Self.issue(server, client: client)

        let unknown = await handler.handleRevocationRequest(
            body: Self.form(token: "never-issued", client: client), authHeader: nil)
        #expect(unknown.statusCode == 200)
        #expect(unknown.body.isEmpty)

        _ = await handler.handleRevocationRequest(
            body: Self.form(token: issued.accessToken, client: client), authHeader: nil)
        let again = await handler.handleRevocationRequest(
            body: Self.form(token: issued.accessToken, client: client), authHeader: nil)
        #expect(again.statusCode == 200)
        #expect(again.body.isEmpty)
    }

    @Test("A request without a token is invalid_request (§2.1: token is REQUIRED)",
          arguments: StoreKind.allCases)
    func missingTokenIsInvalidRequest(store kind: StoreKind) async throws {
        let server = try Self.makeServer(try kind.makeStore())
        let handler = OAuthHTTPHandler(server: server)
        let client = try await Self.register(server, confidential: true)

        let response = await handler.handleRevocationRequest(
            body: Self.form(token: nil, client: client), authHeader: nil)

        #expect(response.statusCode == 400)
        #expect(response.body.contains("invalid_request"))
    }

    // MARK: - §2.1: the token must belong to the requesting client

    @Test("Another client's token is refused with invalid_grant (§2.1) and is not revoked; an unknown token is still 200 (§2.2)",
          arguments: StoreKind.allCases)
    func otherClientsTokenIsRefused(store kind: StoreKind) async throws {
        let server = try Self.makeServer(try kind.makeStore())
        let handler = OAuthHTTPHandler(server: server)
        let victim = try await Self.register(server, confidential: true)
        let attacker = try await Self.register(server, confidential: true)
        let issued = try await Self.issue(server, client: victim)
        let refreshToken = try #require(issued.refreshToken)

        let foreign = await handler.handleRevocationRequest(
            body: Self.form(token: issued.accessToken, client: attacker), authHeader: nil)
        let foreignRefresh = await handler.handleRevocationRequest(
            body: Self.form(token: refreshToken, client: attacker), authHeader: nil)
        let unknown = await handler.handleRevocationRequest(
            body: Self.form(token: "never-issued", client: attacker), authHeader: nil)

        // §2.1: "If this validation fails, the request is refused and the client is informed of the
        // error"; RFC 6749 §5.2's invalid_grant is the code for "issued to another client".
        for response in [foreign, foreignRefresh] {
            #expect(response.statusCode == 400)
            #expect(response.body.contains("invalid_grant"))
        }
        // §2.2: "invalid tokens do not cause an error response". A string nobody holds is 200.
        #expect(unknown.statusCode == 200)
        #expect(unknown.body.isEmpty)
        // And the refusal revoked nothing: the victim's tokens still work.
        #expect(try await Self.isActive(server, issued.accessToken))
        _ = try await Self.refresh(server, client: victim, token: refreshToken)
    }

    @Test("A client still revokes its own access and refresh tokens, with the same 200",
          arguments: StoreKind.allCases)
    func ownTokensStillRevoke(store kind: StoreKind) async throws {
        let server = try Self.makeServer(try kind.makeStore())
        let handler = OAuthHTTPHandler(server: server)
        let client = try await Self.register(server, confidential: true)
        let issued = try await Self.issue(server, client: client)
        let refreshToken = try #require(issued.refreshToken)

        let own = await handler.handleRevocationRequest(
            body: Self.form(token: refreshToken, client: client), authHeader: nil)

        #expect(own.statusCode == 200)
        #expect(!(try await Self.isActive(server, issued.accessToken)), "§2.1: the grant's access tokens go too")
    }

    // MARK: - Client authentication

    @Test("A confidential client that does not authenticate is refused, and nothing is revoked",
          arguments: StoreKind.allCases)
    func unauthenticatedClientIsRefused(store kind: StoreKind) async throws {
        let server = try Self.makeServer(try kind.makeStore())
        let handler = OAuthHTTPHandler(server: server)
        let client = try await Self.register(server, confidential: true)
        let issued = try await Self.issue(server, client: client)

        let noSecret = await handler.handleRevocationRequest(
            body: Self.form(token: issued.accessToken, client: client, withSecret: false), authHeader: nil)
        let wrongSecret = await handler.handleRevocationRequest(
            body: Self.form(token: issued.accessToken, client: client) + "x", authHeader: nil)
        let noClient = await handler.handleRevocationRequest(
            body: Self.form(token: issued.accessToken, client: nil), authHeader: nil)

        for response in [noSecret, wrongSecret, noClient] {
            #expect(response.statusCode == 401)
            #expect(response.body.contains("invalid_client"))
        }
        #expect(try await Self.isActive(server, issued.accessToken), "refused, so not revoked")
    }

    @Test("HTTP Basic authentication works as at the token endpoint",
          arguments: StoreKind.allCases)
    func basicAuthentication(store kind: StoreKind) async throws {
        let server = try Self.makeServer(try kind.makeStore())
        let handler = OAuthHTTPHandler(server: server)
        // client_secret_basic, which the registration helper above does not offer.
        let registered = try await server.registerClient(ClientRegistrationRequest(
            clientName: "Basic", redirectUris: ["https://app.example.com/cb"],
            grantTypes: ["authorization_code", "refresh_token"],
            tokenEndpointAuthMethod: "client_secret_basic"))
        let client = Registered(clientId: registered.clientId, secret: registered.clientSecret)
        let issued = try await Self.issue(server, client: client)
        let credential = Data("\(client.clientId):\(try #require(client.secret))".utf8).base64EncodedString()

        let response = await handler.handleRevocationRequest(
            body: "token=\(issued.accessToken)", authHeader: "Basic \(credential)")

        #expect(response.statusCode == 200)
        #expect(try await Self.isActive(server, issued.accessToken) == false)
    }

    @Test("A public client revokes its own token with its client_id, and no one else's",
          arguments: StoreKind.allCases)
    func publicClient(store kind: StoreKind) async throws {
        let server = try Self.makeServer(try kind.makeStore())
        let handler = OAuthHTTPHandler(server: server)
        let mine = try await Self.register(server, confidential: false)
        let theirs = try await Self.register(server, confidential: false)
        let issued = try await Self.issue(server, client: mine)

        _ = await handler.handleRevocationRequest(
            body: Self.form(token: issued.accessToken, client: theirs), authHeader: nil)
        #expect(try await Self.isActive(server, issued.accessToken))
        _ = await handler.handleRevocationRequest(
            body: Self.form(token: issued.accessToken, client: mine), authHeader: nil)
        #expect(try await Self.isActive(server, issued.accessToken) == false)
    }

    // MARK: - §2.2.1: 503

    /// RFC 7009 §2.2.1: a 503 tells the client to "assume the token still exists", which is the
    /// truth when the store could not be written. Never a 200 for a revocation that did not
    /// happen, and never a 500, which a client cannot tell from "your request was wrong".
    @Test("A store that cannot be written answers 503, not 200")
    func storeFailureIs503() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("oauth-revoke-503-\(UUID().uuidString).sqlite").path
        let storage = try OAuthStorage(path: path)
        let server = try Self.makeServer(storage)
        let handler = OAuthHTTPHandler(server: server)
        let client = try await Self.register(server, confidential: true)
        let issued = try await Self.issue(server, client: client)
        let refreshToken = try #require(issued.refreshToken)

        // Break the store the way a failing disk would: from underneath it.
        var db: OpaquePointer?
        #expect(sqlite3_open(path, &db) == SQLITE_OK)
        #expect(sqlite3_exec(db, "DROP TABLE refresh_tokens; DROP TABLE access_tokens;", nil, nil, nil) == SQLITE_OK)
        sqlite3_close(db)

        let response = await handler.handleRevocationRequest(
            body: Self.form(token: refreshToken, client: client), authHeader: nil)

        #expect(response.statusCode == 503)
        #expect(response.body.contains("temporarily_unavailable"))
    }

    // MARK: - Metadata (RFC 8414 §2)

    @Test("The metadata names the revocation endpoint exactly when the deployment serves it")
    func metadataAdvertisesWhatIsServed() async throws {
        let served = try await Self.makeServer(InMemoryOAuthStorage()).getMetadata()
        #expect(served.revocationEndpoint == "\(Self.issuer)/revoke")
        // The methods the endpoint authenticates with are the token endpoint's: both call
        // `authenticateClient`.
        #expect(served.revocationEndpointAuthMethodsSupported == served.tokenEndpointAuthMethodsSupported)

        let unserved = OAuthServer(
            storage: InMemoryOAuthStorage(), issuer: Self.issuer, scopesSupported: ["read"],
            served: .core, resourceIdentity: .colocated)
        let metadata = await unserved.getMetadata()
        #expect(metadata.revocationEndpoint == nil)
        #expect(metadata.revocationEndpointAuthMethodsSupported == nil)
        let json = String(decoding: try JSONEncoder().encode(metadata), as: UTF8.self)
        #expect(!json.contains("revocation_endpoint"), "a document must not name what is not served")
        let wire = try #require(
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(served)) as? [String: Any])
        #expect(wire["revocation_endpoint"] as? String == "\(Self.issuer)/revoke")
        #expect(wire["revocation_endpoint_auth_methods_supported"] as? [String]
                == ["client_secret_basic", "client_secret_post", "none"])
    }
}
