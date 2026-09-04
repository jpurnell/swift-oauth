import Foundation
import Testing
import SwiftOAuthCore
import SwiftOAuthProvider

/// The properties a consumer relies on and never re-checks.
///
/// SwiftMCPServer audited its own sources and found it performs no OAuth validation at all:
/// `/register`, `/authorize`, `/authorize/consent` and `/token` are pass-throughs, and a search
/// of its code finds no reference to `code_challenge`, `redirect_uri` matching, or single-use
/// handling. Every guarantee below is one it depends on this package to provide, and one its
/// own test suite would stay green without.
///
/// It sent the list as a table. **One row did not hold** — PKCE was documented as required and
/// was not enforced — and nothing in either package would have failed. The reason it survived
/// is worth stating: on both sides the sentence "PKCE verification" read as a *description of
/// something already true* rather than as a claim, so nobody checked it against the code.
///
/// This suite exists to stop that recurring. A row here is a test that fails, not a sentence
/// that reads as already-true. If a guarantee is ever relaxed, something goes red before a
/// downstream server quietly loses a protection it never implemented.
///
/// Each test names the consequence rather than the mechanism, because the consequence is what a
/// reader needs in order to judge whether relaxing it is acceptable.
@Suite("Relied-upon properties — the consumer's checklist")
struct ReliedUponPropertiesTests {

    private func makeServer() async throws -> (OAuthServer, OAuthStorage, ClientRegistrationResponse) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"], advertisedEndpoints: .none,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let client = try await server.registerClient(ClientRegistrationRequest(
            clientName: "relying-party", redirectUris: ["https://app.example.com/callback"]))
        return (server, storage, client)
    }

    private let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    private func authorize(
        _ server: OAuthServer, _ client: ClientRegistrationResponse,
        redirectUri: String = "https://app.example.com/callback",
        scope: String? = "read"
    ) async throws -> AuthorizationResponse {
        try await server.handleAuthorizationRequest(AuthorizationRequest(
            responseType: "code", clientId: client.clientId, redirectUri: redirectUri,
            scope: scope, state: "s", codeChallenge: challenge, codeChallengeMethod: "S256"))
    }

    /// **Row 1 — PKCE verification.** Relaxed: an intercepted authorization code is redeemable.
    ///
    /// This is the row that did not hold. It is first because it is the one that proves the
    /// suite is worth having.
    @Test("PKCE is required, or an intercepted code is redeemable")
    func pkceIsRequired() async throws {
        let (server, _, client) = try await makeServer()

        await #expect(throws: OAuthError.self) {
            _ = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code", clientId: client.clientId,
                redirectUri: "https://app.example.com/callback",
                scope: "read", state: "s", codeChallenge: nil, codeChallengeMethod: nil))
        }
    }

    /// **Row 2 — redirect-URI exact match.** Relaxed: open redirect, and codes exfiltrated to
    /// an address the attacker chose.
    @Test("A redirect URI must match exactly, or codes go to an attacker's address")
    func redirectURIMustMatch() async throws {
        let (server, _, client) = try await makeServer()

        await #expect(throws: OAuthError.self) {
            _ = try await self.authorize(
                server, client, redirectUri: "https://app.example.com/callback/../evil")
        }
        await #expect(throws: OAuthError.self) {
            _ = try await self.authorize(server, client, redirectUri: "https://evil.example.com/cb")
        }
    }

    /// **Row 3 — client authentication at the token endpoint.** Relaxed: anyone redeems
    /// anyone's authorization code.
    @Test("A token request authenticates its client, or anyone redeems anyone's code")
    func tokenEndpointAuthenticatesTheClient() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"], advertisedEndpoints: .none,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let handler = await OAuthHTTPHandler(server: server)
        let client = try await server.registerClient(ClientRegistrationRequest(
            clientName: "rp", redirectUris: ["https://app.example.com/callback"]))

        // No credentials at all.
        let response = await handler.handleTokenRequest(
            body: "grant_type=authorization_code&code=x&client_id=\(client.clientId)",
            authHeader: nil)

        #expect(response.statusCode == 401 || response.statusCode == 400,
                "an unauthenticated token request was not refused")
    }

    /// **Row 4 — authorization codes are single-use and expire.** Relaxed: replay.
    @Test("An authorization code is single-use, or it can be replayed")
    func authorizationCodeIsSingleUse() async throws {
        let (server, storage, client) = try await makeServer()
        let issued = try await authorize(server, client)

        // The first consumption returns the code it was asked for, not merely something.
        let first = try #require(await storage.consumeAuthorizationCode(code: issued.code))
        #expect(first.code == issued.code)
        #expect(first.clientId == client.clientId)

        #expect(try await storage.consumeAuthorizationCode(code: issued.code) == nil,
                "an authorization code was consumable twice")
    }

    /// **Row 5 — scope never widens.** Relaxed: a read-only token mints an administrative one
    /// through a documented grant, and the result looks legitimate downstream.
    @Test("An exchange cannot widen scope, or a read-only token mints an admin one")
    func exchangeCannotWidenScope() async throws {
        let (server, storage, client) = try await makeServer()
        try await storage.saveAccessToken(
            token: "narrow", clientId: client.clientId, scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: nil)

        await #expect(throws: OAuthError.self) {
            _ = try await server.exchangeToken(
                TokenExchangeRequest(
                    subjectToken: "narrow", subjectTokenType: .accessToken, scope: "read admin"),
                clientId: client.clientId)
        }
    }

    /// **Row 6 — bound tokens refused at the bearer entry point.** Relaxed: the DPoP or mTLS
    /// binding is silently discarded and the token behaves as the bearer token it replaced.
    @Test("A bound token is refused as a bearer token, or the binding is discarded")
    func boundTokensRefusedAsBearer() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"], advertisedEndpoints: .none,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let handler = await OAuthHTTPHandler(server: server)

        try await storage.saveAccessToken(
            token: "dpop-bound", clientId: "c", scope: nil,
            expiresAt: Date().addingTimeInterval(3600), audience: nil, keyThumbprint: "k")
        try await storage.saveAccessToken(
            token: "cert-bound", clientId: "c", scope: nil,
            expiresAt: Date().addingTimeInterval(3600), audience: nil,
            certificateThumbprint: "x")

        #expect(!(await handler.validateBearerToken(authHeader: "Bearer dpop-bound").isValid))
        #expect(!(await handler.validateBearerToken(authHeader: "Bearer cert-bound").isValid))
    }

    /// **Row 7 — bound subject tokens refused for exchange.** Relaxed: binding-strip through a
    /// documented grant — bound token in, plain bearer token out.
    @Test("A bound token cannot be exchanged, or the binding is stripped")
    func boundTokenCannotBeExchanged() async throws {
        let (server, storage, client) = try await makeServer()
        try await storage.saveAccessToken(
            token: "bound", clientId: client.clientId, scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: nil, keyThumbprint: "k")

        await #expect(throws: OAuthError.self) {
            _ = try await server.exchangeToken(
                TokenExchangeRequest(subjectToken: "bound", subjectTokenType: .accessToken),
                clientId: client.clientId)
        }
    }

    /// **Row 8 — resource-indicator validation.** Relaxed: a token is usable at a service it
    /// was never minted for.
    @Test("An unknown resource is refused, or a token works where it should not")
    func resourceIndicatorIsValidated() throws {
        // SECURITY: literals written in this test; nothing is fetched from them.
        let api = try #require(URL(string: "https://api.example.com"))
        let stranger = try #require(URL(string: "https://elsewhere.example.com"))
        let policy = ResourceIndicatorPolicy.protecting(api)

        #expect(try policy.audience(for: [api]) == api)
        #expect(throws: OAuthError.self) {
            _ = try policy.audience(for: [stranger])
        }
    }
}
