import Foundation
import Testing
import CSQLite
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// Every access token this provider issues says *who* — `sub` and `iss` on introspection.
///
/// RFC 7662 §2.2 defines both. Without `sub` a resource server learns that a token is good and
/// not whose it is, so it cannot use this provider as an identity source at all; without `iss`
/// it cannot tell which issuer a subject belongs to when it trusts more than one. RFC 9068 §2.2
/// (the JWT access-token profile, which names the convention) sets `sub` to the client's own
/// identifier for a grant with no resource owner, so `client_credentials` carries its
/// `client_id`.
@Suite("Token subject — sub and iss on what the provider issues")
struct TokenSubjectTests {

    static let issuer = "https://auth.example.com"

    private static func makeServer(
        served: ServedCapabilities? = nil
    ) throws -> (OAuthServer, OAuthStorage) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(
            storage: storage, issuer: issuer, scopesSupported: ["read", "write"],
            served: try served ?? ServedCapabilities(
                grantTypes: [.authorizationCode, .refreshToken, .clientCredentials, .deviceCode,
                             .tokenExchange],
                clientAuthenticationMethods: [.clientSecretBasic, .clientSecretPost, .none],
                deviceAuthorization: "\(issuer)/device_authorization"),
            resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        return (server, storage)
    }

    /// A public client that may use the code and refresh grants.
    private static func registerPublicClient(_ server: OAuthServer) async throws -> String {
        try await server.registerClient(ClientRegistrationRequest(
            clientName: "App", redirectUris: ["https://app.example.com/cb"],
            grantTypes: ["authorization_code", "refresh_token"],
            tokenEndpointAuthMethod: "none")).clientId
    }

    /// Runs the authorization code grant for `subject`, returning the token response.
    private static func codeGrant(
        _ server: OAuthServer, clientId: String, subject: String?
    ) async throws -> TokenResponse {
        let verifier = PKCE.generateCodeVerifier()
        let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)
        let authorization = try await server.handleAuthorizationRequest(
            AuthorizationRequest(
                responseType: "code", clientId: clientId,
                redirectUri: "https://app.example.com/cb", scope: "read", state: nil,
                codeChallenge: challenge, codeChallengeMethod: "S256"),
            subject: subject)
        return try await server.handleTokenRequest(TokenRequest(
            grantType: "authorization_code", code: authorization.code,
            redirectUri: "https://app.example.com/cb", clientId: clientId, clientSecret: nil,
            codeVerifier: verifier, refreshToken: nil))
    }

    // MARK: - Each grant

    @Test("The device grant's token carries the approver as sub, and the issuer as iss")
    func deviceGrantCarriesApprover() async throws {
        let (server, _) = try Self.makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")
        try await server.approveDeviceCode(userCode: issued.userCode, subject: "user-ada")

        let tokens = try await server.redeemDeviceCode(issued.deviceCode, clientId: "tv-app")
        let introspected = try await server.introspect(token: tokens.accessToken)

        #expect(introspected.active)
        #expect(introspected.subject == "user-ada")
        #expect(introspected.issuer == Self.issuer)
        #expect(introspected.clientId == "tv-app")
    }

    @Test("A client_credentials token carries its own client_id as sub")
    func clientCredentialsCarriesClientId() async throws {
        let (server, _) = try Self.makeServer()
        let service = try await server.createServiceClient(name: "svc", scopes: ["read"])

        let tokens = try await server.handleTokenRequest(TokenRequest(
            grantType: "client_credentials", code: nil, redirectUri: nil,
            clientId: service.clientId, clientSecret: service.clientSecret, codeVerifier: nil,
            refreshToken: nil))
        let introspected = try await server.introspect(token: tokens.accessToken)

        #expect(introspected.subject == service.clientId)
        #expect(introspected.issuer == Self.issuer)
    }

    @Test("An authorization code granted for a subject issues a token carrying it")
    func authorizationCodeCarriesSubject() async throws {
        let (server, _) = try Self.makeServer()
        let clientId = try await Self.registerPublicClient(server)

        let tokens = try await Self.codeGrant(server, clientId: clientId, subject: "user-ada")
        let introspected = try await server.introspect(token: tokens.accessToken)

        #expect(introspected.subject == "user-ada")
        #expect(introspected.issuer == Self.issuer)
    }

    /// A deployment that does not say who approved gets a token naming nobody — and the
    /// introspection still names the issuer. A subject is never invented.
    @Test("A code granted with no subject issues a token with no sub, never an invented one")
    func authorizationCodeWithoutSubject() async throws {
        let (server, _) = try Self.makeServer()
        let clientId = try await Self.registerPublicClient(server)

        let tokens = try await Self.codeGrant(server, clientId: clientId, subject: nil)
        let introspected = try await server.introspect(token: tokens.accessToken)

        #expect(introspected.active)
        #expect(introspected.subject == nil)
        #expect(introspected.issuer == Self.issuer)
    }

    /// The subject comes from the deployment that authenticated the user, never from the
    /// consent form — the browser controls the form, and a `subject` field in it is whatever
    /// the browser says.
    @Test("Consent over HTTP takes the subject from the caller, not the form", arguments: [
        ("user-ada", "user-ada"), (nil, nil)
    ] as [(String?, String?)])
    func consentTakesSubjectFromCaller(given: String?, expected: String?) async throws {
        let (server, _) = try Self.makeServer()
        let clientId = try await Self.registerPublicClient(server)
        let handler = OAuthHTTPHandler(server: server)
        let verifier = PKCE.generateCodeVerifier()
        let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)
        let csrf = try await server.generateCSRFToken(
            clientId: clientId, redirectUri: "https://app.example.com/cb")

        let redirect = await handler.handleConsentSubmission(formParams: [
            "action": "approve", "client_id": clientId,
            "redirect_uri": "https://app.example.com/cb", "csrf_token": csrf, "scope": "read",
            "code_challenge": challenge, "code_challenge_method": "S256",
            "subject": "forged-by-the-browser"
        ], subject: given)
        let location = try #require(redirect.headers["Location"])
        let code = try #require(URLComponents(string: location)?.queryItems?
            .first { $0.name == "code" }?.value)
        let tokens = try await server.handleTokenRequest(TokenRequest(
            grantType: "authorization_code", code: code,
            redirectUri: "https://app.example.com/cb", clientId: clientId, clientSecret: nil,
            codeVerifier: verifier, refreshToken: nil))

        #expect(try await server.introspect(token: tokens.accessToken).subject == expected)
    }

    @Test("A refreshed token keeps the subject the refresh token was issued for")
    func refreshKeepsSubject() async throws {
        let (server, _) = try Self.makeServer()
        let clientId = try await Self.registerPublicClient(server)
        let first = try await Self.codeGrant(server, clientId: clientId, subject: "user-ada")
        let refreshToken = try #require(first.refreshToken)

        let refreshed = try await server.handleTokenRequest(TokenRequest(
            grantType: "refresh_token", code: nil, redirectUri: nil, clientId: clientId,
            clientSecret: nil, codeVerifier: nil, refreshToken: refreshToken))
        let introspected = try await server.introspect(token: refreshed.accessToken)

        #expect(introspected.subject == "user-ada")
    }

    /// RFC 8693 §1.1: the exchanged token acts for the same subject. Delegation that dropped
    /// the subject would make the downstream service unable to say on whose behalf it acts.
    @Test("An exchanged token keeps the subject token's subject")
    func exchangeKeepsSubject() async throws {
        let (server, storage) = try Self.makeServer()
        try await storage.saveAccessToken(
            token: "subject-token", clientId: "gateway", scope: "read write",
            expiresAt: Date().addingTimeInterval(3600), audience: nil, subject: "user-ada")

        let exchanged = try await server.exchangeToken(
            TokenExchangeRequest(
                subjectToken: "subject-token", subjectTokenType: .accessToken, scope: "read"),
            clientId: "gateway")
        let introspected = try await server.introspect(token: exchanged.accessToken)

        #expect(introspected.subject == "user-ada")
    }

    @Test("Validation reports the subject a token was issued for")
    func validationReportsSubject() async throws {
        let (_, storage) = try Self.makeServer()
        try await storage.saveAccessToken(
            token: "live", clientId: "app", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: nil, subject: "user-ada")

        let result = try await storage.validateAccessToken(token: "live")
        guard case .valid(let token) = result else {
            Issue.record("expected a valid token, got \(result)")
            return
        }
        #expect(token.subject == "user-ada")
    }

    // MARK: - What an inactive answer still withholds

    /// RFC 7662 §2.2: an inactive response carries nothing but `active`. Adding `iss` to active
    /// answers must not leak onto inactive ones, where it would confirm which server a dead
    /// token came from.
    @Test("An inactive answer is still {\"active\":false} and nothing else")
    func inactiveCarriesNoIssuer() async throws {
        let (server, _) = try Self.makeServer()
        let introspected = try await server.introspect(token: "never-issued")

        #expect(introspected == .inactive)
        #expect(String(decoding: try JSONEncoder().encode(introspected), as: UTF8.self)
                == #"{"active":false}"#)
    }

    @Test("Over HTTP, an active answer's body carries sub and iss")
    func httpBodyCarriesSubAndIss() async throws {
        let (server, _) = try Self.makeServer()
        let service = try await server.createServiceClient(name: "svc", scopes: ["read"])
        let tokens = try await server.handleTokenRequest(TokenRequest(
            grantType: "client_credentials", code: nil, redirectUri: nil,
            clientId: service.clientId, clientSecret: service.clientSecret, codeVerifier: nil,
            refreshToken: nil))
        let handler = OAuthHTTPHandler(server: server)

        let response = await handler.handleIntrospectionRequest(
            body: "token=\(tokens.accessToken)",
            authHeader: "Basic " + Data("\(service.clientId):\(service.clientSecret)".utf8)
                .base64EncodedString())
        let body = try #require(
            try JSONSerialization.jsonObject(with: Data(response.body.utf8)) as? [String: Any])

        #expect(response.statusCode == 200)
        #expect(body["sub"] as? String == service.clientId)
        #expect(body["iss"] as? String == Self.issuer)
    }

    // MARK: - Upgrade

    /// A token stored before subjects were recorded keeps working, and names nobody — the
    /// honest answer, since nobody was recorded.
    @Test("Upgrading keeps an earlier release's tokens, with no subject")
    func upgradeKeepsTokens() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("subject-\(UUID().uuidString).db").path
        // SECURITY: removes only the uniquely-named temp file this test just created.
        defer { try? FileManager.default.removeItem(atPath: path) }

        _ = try OAuthStorage(path: path, schemaVersion: 8)
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK, let db else {
            Issue.record("could not open the database to plant a row")
            return
        }
        let hash = TokenGenerator.sha256Hash("old-token")
        let expiry = Date().addingTimeInterval(3600).timeIntervalSince1970
        let insert = """
            INSERT INTO access_tokens (token_hash, client_id, scope, expires_at, created_at, revoked)
            VALUES ('\(hash)', 'app', 'read', \(expiry), 0, 0)
            """
        let planted = sqlite3_exec(db, insert, nil, nil, nil)
        sqlite3_close(db)
        #expect(planted == SQLITE_OK)

        let upgraded = try OAuthStorage(path: path)
        let introspected = try await upgraded.introspectAccessToken(token: "old-token")
        #expect(introspected.active)
        #expect(introspected.subject == nil)
    }
}
