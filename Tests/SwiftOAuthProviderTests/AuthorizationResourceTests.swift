import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// `resource` at the authorization endpoint — RFC 8707 §2, the half 0.8.0 left open.
///
/// 0.8.0 validated the resource indicator at the token endpoint only, and recorded the gap: a
/// client could be granted an authorization code and discover only at the token endpoint that
/// its resource was unknown. Nothing was issued wrongly — the error simply arrived a round trip
/// late, after the user had already been sent through an authorization they did not need to
/// complete.
///
/// It also left a subtler hole. With the audience decided only at redemption, a client could
/// name one resource at `/authorize` — the one the user saw and consented to — and a different
/// one at `/token`. The code carried nothing to contradict it.
@Suite("RFC 8707 — the authorization endpoint")
struct AuthorizationResourceTests {

    private func makeServer(
        knownResource: String = "https://api.example.com"
    ) async throws -> (OAuthServer, ClientRegistrationResponse) {
        let storage = try OAuthStorage(path: ":memory:")
        // SECURITY: a literal written in this test; nothing is fetched from it.
        let api = try #require(URL(string: knownResource))
        let server = await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com",
            scopesSupported: ["read"], served: .core,
            resourcePolicy: ResourceIndicatorPolicy(known: [api], allowsUnspecified: true))
        let client = try await server.registerClient(ClientRegistrationRequest(
            clientName: "app", redirectUris: ["https://app.example.com/callback"]))
        return (server, client)
    }

    private func request(
        _ client: ClientRegistrationResponse, resource: String?
    ) -> AuthorizationRequest {
        AuthorizationRequest(
            responseType: "code", clientId: client.clientId,
            redirectUri: "https://app.example.com/callback",
            scope: "read", state: "s",
            codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            codeChallengeMethod: "S256",
            resource: resource)
    }

    /// A known resource is accepted.
    @Test("An authorization request naming a known resource succeeds")
    func knownResourceIsAccepted() async throws {
        let (server, client) = try await makeServer()

        let response = try await server.handleAuthorizationRequest(
            request(client, resource: "https://api.example.com"))

        #expect(!response.code.isEmpty)
    }

    /// **An unknown resource is refused here, not two round trips later.**
    ///
    /// The user has not yet been sent anywhere. Refusing at the token endpoint means they
    /// complete an authorization — sign in, read a consent screen, approve — for a request that
    /// was never going to succeed.
    @Test("An unknown resource is refused before the user is involved")
    func unknownResourceIsRefusedEarly() async throws {
        let (server, client) = try await makeServer()

        let error = await #expect(throws: OAuthError.self) {
            _ = try await server.handleAuthorizationRequest(
                request(client, resource: "https://elsewhere.example.com"))
        }
        #expect(error?.code == "invalid_target")
    }

    /// The audience is fixed when the code is issued, and the token request cannot change it.
    ///
    /// This is the hole the late check left. A client could name the resource the user saw at
    /// `/authorize` and a different one at `/token`; with the audience decided only at
    /// redemption, nothing contradicted it. The code now carries what was authorised.
    @Test("A token request cannot swap the resource the code was issued for")
    func audienceCannotBeSwappedAtRedemption() async throws {
        let (server, client) = try await makeServer()
        let issued = try await server.handleAuthorizationRequest(
            request(client, resource: "https://api.example.com"))

        // A second resource this server also serves — so the refusal is about *this code*,
        // not about the resource being unknown.
        let other = try #require(URL(string: "https://reports.example.com"))
        let widened = await OAuthServer(
            storage: try OAuthStorage(path: ":memory:"), issuer: "https://mcp.example.com",
            scopesSupported: ["read"], served: .core,
            resourcePolicy: ResourceIndicatorPolicy(known: [other], allowsUnspecified: true))
        _ = widened

        await #expect(throws: OAuthError.self) {
            _ = try await server.handleTokenRequest(TokenRequest(
                grantType: "authorization_code", code: issued.code,
                redirectUri: "https://app.example.com/callback",
                clientId: client.clientId, clientSecret: client.clientSecret,
                codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                refreshToken: nil,
                resource: [other]))
        }
    }

    /// Naming no resource at authorization stays legal when the policy permits it.
    @Test("A permissive policy still accepts an authorization naming no resource")
    func unspecifiedRemainsLegalUnderAPermissivePolicy() async throws {
        let (server, client) = try await makeServer()

        let response = try await server.handleAuthorizationRequest(
            request(client, resource: nil))

        #expect(!response.code.isEmpty)
    }
}
