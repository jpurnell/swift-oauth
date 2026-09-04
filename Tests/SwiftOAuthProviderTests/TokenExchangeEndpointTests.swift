import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// Token exchange on the provider — RFC 8693 §2.
///
/// The rule that makes this grant safe, and the one a naive implementation gets wrong:
/// **an exchange may narrow privilege and must never widen it.** The whole purpose is a service
/// reducing what it holds before passing it on. A server that grants the scope a client asked
/// for, without checking what the subject token actually carried, has built a privilege
/// escalation with a specification reference attached.
@Suite("RFC 8693 — the exchange endpoint")
struct TokenExchangeEndpointTests {

    private func makeServer() async throws -> (OAuthServer, OAuthStorage) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"], advertisedEndpoints: .none,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        return (server, storage)
    }

    /// A valid subject token exchanges for a new one.
    @Test("A live subject token exchanges")
    func liveSubjectExchanges() async throws {
        let (server, storage) = try await makeServer()
        try await storage.saveAccessToken(
            token: "subject", clientId: "gateway", scope: "read write",
            expiresAt: Date().addingTimeInterval(3600), audience: nil)

        let response = try await server.exchangeToken(TokenExchangeRequest(
            subjectToken: "subject", subjectTokenType: .accessToken, scope: "read"),
            clientId: "gateway")

        #expect(!response.accessToken.isEmpty)
        #expect(response.accessToken != "subject", "the exchange returned the same token")
        #expect(response.issuedTokenType == .accessToken)
    }

    /// **Narrowing works.** Asking for less than the subject carries yields less.
    @Test("An exchange may narrow scope")
    func exchangeNarrowsScope() async throws {
        let (server, storage) = try await makeServer()
        try await storage.saveAccessToken(
            token: "wide", clientId: "gateway", scope: "read write admin",
            expiresAt: Date().addingTimeInterval(3600), audience: nil)

        let response = try await server.exchangeToken(TokenExchangeRequest(
            subjectToken: "wide", subjectTokenType: .accessToken, scope: "read"),
            clientId: "gateway")

        #expect(response.scope == "read")
    }

    /// **Widening does not.** This is the test the grant exists for.
    ///
    /// A server that granted `admin` here would let any holder of a read-only token mint an
    /// administrative one, using a documented grant type, and the resulting token would look
    /// entirely legitimate to everything downstream.
    @Test("An exchange cannot widen scope beyond the subject token")
    func exchangeCannotWidenScope() async throws {
        let (server, storage) = try await makeServer()
        try await storage.saveAccessToken(
            token: "narrow", clientId: "gateway", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: nil)

        await #expect(throws: OAuthError.self) {
            _ = try await server.exchangeToken(TokenExchangeRequest(
                subjectToken: "narrow", subjectTokenType: .accessToken, scope: "read admin"),
                clientId: "gateway")
        }
    }

    /// Asking for nothing yields the subject's scope, not everything the server can issue.
    @Test("An exchange without a requested scope inherits the subject's")
    func absentScopeInheritsSubject() async throws {
        let (server, storage) = try await makeServer()
        try await storage.saveAccessToken(
            token: "inherit", clientId: "gateway", scope: "read write",
            expiresAt: Date().addingTimeInterval(3600), audience: nil)

        let response = try await server.exchangeToken(TokenExchangeRequest(
            subjectToken: "inherit", subjectTokenType: .accessToken),
            clientId: "gateway")

        #expect(response.scope == "read write")
    }

    /// An expired subject token cannot be exchanged.
    ///
    /// Otherwise expiry means nothing: a dead token buys a live one, and the exchange endpoint
    /// becomes a way to launder an expired credential into a fresh one.
    @Test("An expired subject token is refused")
    func expiredSubjectIsRefused() async throws {
        let (server, storage) = try await makeServer()
        try await storage.saveAccessToken(
            token: "dead", clientId: "gateway", scope: "read",
            expiresAt: Date().addingTimeInterval(-60), audience: nil)

        await #expect(throws: OAuthError.self) {
            _ = try await server.exchangeToken(TokenExchangeRequest(
                subjectToken: "dead", subjectTokenType: .accessToken), clientId: "gateway")
        }
    }

    /// An unknown subject token is refused.
    @Test("An unknown subject token is refused")
    func unknownSubjectIsRefused() async throws {
        let (server, _) = try await makeServer()

        await #expect(throws: OAuthError.self) {
            _ = try await server.exchangeToken(TokenExchangeRequest(
                subjectToken: "never-issued", subjectTokenType: .accessToken),
                clientId: "gateway")
        }
    }

    /// A bound token cannot be exchanged for an unbound one.
    ///
    /// Otherwise the exchange endpoint strips a binding: a DPoP- or certificate-bound token
    /// goes in, an ordinary bearer token comes out, and everything the binding was protecting
    /// against is available to whoever holds the result.
    ///
    /// **A consumer depends on this refusal as its entire protection.** SwiftMCPServer
    /// implements no exchange-like endpoint of its own and delegates every grant here, so this
    /// check is the whole of its defence against binding-strip — it said so explicitly rather
    /// than leave the assumption unwritten.
    ///
    /// Recorded because the failure mode of relaxing it is silent: nothing in this package
    /// would break, its tests would stay green, and a downstream server would quietly lose a
    /// guarantee it never implemented because this one made it. Anyone tempted to soften this —
    /// to support a legitimate-looking re-binding, say — is changing a security property
    /// somebody else is standing on, and should say so out loud first.
    @Test("A bound subject token cannot be laundered into a bearer token")
    func boundTokenCannotBeStripped() async throws {
        let (server, storage) = try await makeServer()
        try await storage.saveAccessToken(
            token: "bound-subject", clientId: "gateway", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: nil,
            keyThumbprint: "thumb-abc")

        await #expect(throws: OAuthError.self) {
            _ = try await server.exchangeToken(TokenExchangeRequest(
                subjectToken: "bound-subject", subjectTokenType: .accessToken),
                clientId: "gateway")
        }
    }

    /// An ID token cannot be exchanged, because this package does not validate one.
    ///
    /// Accepting it would mean treating an unverified assertion of identity as authorisation,
    /// which is the exact misuse the OIDC boundary exists to prevent.
    @Test("An ID token subject is refused")
    func idTokenSubjectIsRefused() async throws {
        let (server, _) = try await makeServer()

        await #expect(throws: OAuthError.self) {
            _ = try await server.exchangeToken(TokenExchangeRequest(
                subjectToken: "some.jwt.here", subjectTokenType: .idToken),
                clientId: "gateway")
        }
    }
}
