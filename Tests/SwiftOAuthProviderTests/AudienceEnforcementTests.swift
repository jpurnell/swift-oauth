import Testing
import Foundation
@testable import SwiftOAuthProvider
import SwiftOAuthCore

/// RFC 8707's second half: a resource server refusing a token minted for somewhere else.
///
/// Issuing binds an audience and is well covered — by this package and by its consumers. That
/// half is testable with one server. **Consuming** needs two servers and a token deliberately
/// carried between them, which no single-server suite constructs, so the property the audiences
/// exist to provide was never asserted anywhere: not here, and not in a consumer running seven
/// services with strict resource indicators and correct audiences on every token.
///
/// The gap was demonstrated in production before it was reported — a token minted at one origin,
/// planted in a second origin's store so that absence could not explain a refusal, and accepted
/// with 200 OK.
@Suite("Audience enforcement at the resource server")
struct AudienceEnforcementTests {

    private func makeHandler(
        issuer: String = "https://a.example.com",
        identity: ResourceIdentity = .colocated
    ) throws -> (OAuthHTTPHandler, OAuthStorage) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(
            storage: storage, issuer: issuer,
            scopesSupported: ["read"], served: .core, resourceIdentity: identity,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        return (OAuthHTTPHandler(server: server), storage)
    }

    /// Plants a token directly, so that a refusal cannot be explained by the token being absent.
    private func plant(_ token: String, audience: URL?, in storage: OAuthStorage) async throws {
        try await storage.saveAccessToken(
            token: token, clientId: "c1", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: audience)
    }

    @Test("A token whose audience names this deployment is honoured")
    func ownAudienceAccepted() async throws {
        let (handler, storage) = try makeHandler()
        try await plant("t-own", audience: URL(string: "https://a.example.com"), in: storage)

        let result = await handler.validateBearerToken(authHeader: "Bearer t-own")
        #expect(result.isValid, "A token minted for this resource must be honoured")
    }

    @Test("A token minted for another resource is refused")
    func foreignAudienceRefused() async throws {
        let (handler, storage) = try makeHandler()
        // Present in this server's store, unexpired, structurally perfect — and minted for
        // somewhere else. The only thing wrong with it is the audience.
        try await plant("t-foreign", audience: URL(string: "https://b.example.com"), in: storage)

        let result = await handler.validateBearerToken(authHeader: "Bearer t-foreign")
        #expect(!result.isValid,
                "A token whose audience names another resource must not be honoured here")
    }

    @Test("A token bound to no audience is still honoured")
    func unboundAudienceAccepted() async throws {
        let (handler, storage) = try makeHandler()
        // The permissive contract, which `ValidatedToken.audience` documents: nil means bound to
        // none. Refusing these would break every deployment that has not adopted RFC 8707, and
        // the absence of a binding is that deployment's stated position rather than a mismatch.
        try await plant("t-unbound", audience: nil, in: storage)

        let result = await handler.validateBearerToken(authHeader: "Bearer t-unbound")
        #expect(result.isValid, "An unbound token is the permissive contract, not a mismatch")
    }

    @Test("The comparison uses the identifier the deployment advertises, not the issuer")
    func comparesAgainstAdvertisedIdentity() async throws {
        // A resource server whose authorization server is elsewhere: the issuer and the resource
        // are different strings, and the audience names the resource. Comparing against the
        // issuer would refuse a correct token — the same colocated assumption that beta.2 fixed
        // in the metadata document, reappearing in enforcement.
        let identity = try ResourceIdentity(
            resource: "https://api.example.com",
            authorizationServers: ["https://auth.example.com"])
        let (handler, storage) = try makeHandler(issuer: "https://auth.example.com",
                                                 identity: identity)
        try await plant("t-split", audience: URL(string: "https://api.example.com"), in: storage)

        let result = await handler.validateBearerToken(authHeader: "Bearer t-split")
        #expect(result.isValid,
                "The audience must be compared against the advertised resource, not the issuer")
    }

    @Test("Honouring a foreign audience requires asking for it")
    func foreignAudienceOptIn() async throws {
        let (handler, storage) = try makeHandler()
        try await plant("t-gateway", audience: URL(string: "https://b.example.com"), in: storage)

        let result = await handler.validateBearerToken(
            authHeader: "Bearer t-gateway", acceptingAudiences: .any)
        #expect(result.isValid,
                "A caller that has decided to honour foreign audiences may say so explicitly")
    }

    @Test("A token request authenticating with client_secret_basic needs no client_id in the body")
    func basicAuthNeedsNoClientIdParameter() async throws {
        let (handler, storage) = try makeHandler()
        let registered = try await OAuthServer(
            storage: storage, issuer: "https://a.example.com",
            scopesSupported: ["read"], served: .core, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true)
        ).registerClient(ClientRegistrationRequest(
            clientName: "Basic Client",
            redirectUris: ["https://client.example.com/cb"],
            tokenEndpointAuthMethod: "client_secret_basic"))
        let secret = try #require(registered.clientSecret)
        let credential = Data("\(registered.clientId):\(secret)".utf8).base64EncodedString()

        // RFC 6749 §2.3.1: the id is in the header. A conformant client sends no `client_id`
        // parameter, and this endpoint answered `invalid_request` for exactly that request.
        let response = await handler.handleTokenRequest(
            body: "grant_type=client_credentials&scope=read",
            authHeader: "Basic \(credential)")

        #expect(!response.body.contains("invalid_request"),
                "The client id is in the Basic credential; requiring it in the body is a deviation from RFC 6749 §2.3.1")
    }
}
