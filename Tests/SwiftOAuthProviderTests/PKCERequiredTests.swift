import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// PKCE is required, not optional — OAuth 2.1 §4.1 and RFC 7636.
///
/// This package's `GrantType` documentation has always said "PKCE is required with it", and the
/// implementation did not enforce it: `code_challenge` was optional at the authorization
/// endpoint, and the token endpoint verified a challenge only `if` the code carried one. A
/// client that simply omitted it got a code with no challenge and redeemed it with no verifier.
///
/// The consequence is the one PKCE exists to prevent: an intercepted authorization code is
/// redeemable by whoever intercepted it.
///
/// Found by auditing this package against a consumer's list of properties it relies on and
/// never re-checks. It had "PKCE verification" on that list, and was right to expect it — the
/// documentation promised it — but nothing enforced it and nothing here would have failed.
@Suite("OAuth 2.1 — PKCE is required")
struct PKCERequiredTests {

    private func makeServer() async throws -> (OAuthServer, ClientRegistrationResponse) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"], advertisedEndpoints: .none,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let client = try await server.registerClient(ClientRegistrationRequest(
            clientName: "app", redirectUris: ["https://app.example.com/callback"]))
        return (server, client)
    }

    /// An authorization request with no `code_challenge` is refused.
    ///
    /// Refused here rather than at the token endpoint, because by then a code has been issued
    /// and the client is mid-flow; here the error still reaches whoever can fix it.
    @Test("An authorization request without a code challenge is refused")
    func authorizationWithoutChallengeIsRefused() async throws {
        let (server, client) = try await makeServer()

        await #expect(throws: OAuthError.self) {
            _ = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "https://app.example.com/callback",
                scope: "read",
                state: "xyz",
                codeChallenge: nil,
                codeChallengeMethod: nil))
        }
    }

    /// One carrying an S256 challenge is accepted, so the requirement is narrow.
    @Test("An authorization request with an S256 challenge is accepted")
    func authorizationWithChallengeIsAccepted() async throws {
        let (server, client) = try await makeServer()
        let verifier = PKCE.generateCodeVerifier()
        let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

        let response = try await server.handleAuthorizationRequest(AuthorizationRequest(
            responseType: "code",
            clientId: client.clientId,
            redirectUri: "https://app.example.com/callback",
            scope: "read",
            state: "xyz",
            codeChallenge: challenge,
            codeChallengeMethod: PKCE.ChallengeMethod.s256.rawValue))

        #expect(!response.code.isEmpty)
    }
}

/// The token endpoint enforces PKCE on its own, not by trusting the authorization endpoint.
///
/// After the authorization endpoint began requiring a challenge, verifying one at the token
/// endpoint "if the code carried it" became equivalent *for codes minted afterwards*. Two edges
/// remained, and the second is the one that matters:
///
/// 1. **Codes already stored.** One issued before the upgrade carries no challenge and redeems
///    with no verifier — a window the length of the code lifetime, closing on its own, and
///    exactly the window an attacker holding an intercepted code is standing in.
/// 2. **Defence in depth.** The token endpoint's safety became a property of a *different*
///    endpoint. Any future path that creates a code — an admin tool, a fixture, a migration, a
///    grant type not yet written — reopens it silently, and the token endpoint would not object.
///
/// So the check is unconditional here. A stored code without a challenge is refused, whatever
/// put it there. Raised by the SwiftMCPServer session after adopting the fix and reading the
/// token endpoint rather than the release note.
@Suite("OAuth 2.1 — the token endpoint enforces PKCE itself")
struct TokenEndpointPKCETests {

    /// A code in storage with no challenge cannot be redeemed, however it got there.
    ///
    /// Planted directly, because the authorization endpoint can no longer produce one — which
    /// is the point: this asserts the token endpoint's own behaviour, not the pair's.
    @Test("A stored code with no challenge is refused at the token endpoint")
    func storedCodeWithoutChallengeIsRefused() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"], advertisedEndpoints: .none,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let client = try await server.registerClient(ClientRegistrationRequest(
            clientName: "app", redirectUris: ["https://app.example.com/callback"]))

        // A code as a pre-upgrade release would have left it: no challenge, no method.
        try await storage.saveAuthorizationCode(AuthorizationCode(
            code: "legacy-code",
            clientId: client.clientId,
            redirectUri: "https://app.example.com/callback",
            scope: "read",
            codeChallenge: nil,
            codeChallengeMethod: nil,
            expiresAt: Date().addingTimeInterval(600),
            createdAt: Date()))

        await #expect(throws: OAuthError.self) {
            _ = try await server.handleTokenRequest(TokenRequest(
                grantType: "authorization_code",
                code: "legacy-code",
                redirectUri: "https://app.example.com/callback",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: nil,
                refreshToken: nil))
        }
    }
}
