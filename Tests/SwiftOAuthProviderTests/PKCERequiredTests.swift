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
            storage: storage, issuer: "https://mcp.example.com",
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
