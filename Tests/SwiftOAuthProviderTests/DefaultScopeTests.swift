import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// What `/authorize` grants a client that names no scope — FullSpecConformance §18.
///
/// RFC 6749 §3.3: when the scope is omitted the server "MUST either process the request using a
/// pre-defined default value or fail the request indicating an invalid scope". The default used
/// to be three MCP scopes written into this package, granted whatever the deployment offered.
/// It is now the deployment's own `scopesSupported`, and with nothing offered there is no
/// default to fall back on, so the request is refused.
@Suite("Default scope at /authorize")
struct DefaultScopeTests {

    private static let redirect = "https://app.example.com/cb"

    private static func makeServer(scopesSupported: [String]?) async throws -> (OAuthServer, OAuthStorage) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(
            storage: storage, issuer: "https://files.example.com",
            scopesSupported: scopesSupported, served: .core, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        try await storage.saveClient(RegisteredClient(
            clientId: "app", clientSecret: nil, clientName: "App",
            redirectUris: [redirect], grantTypes: ["authorization_code"],
            tokenEndpointAuthMethod: "none", registrationDate: Date()))
        return (server, storage)
    }

    private static func authorize(scope: String?) -> AuthorizationRequest {
        AuthorizationRequest(
            responseType: "code", clientId: "app", redirectUri: redirect,
            scope: scope, state: "s",
            codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            codeChallengeMethod: "S256")
    }

    private static func grantedScope(_ server: OAuthServer, _ storage: OAuthStorage, scope: String?) async throws -> String? {
        let response = try await server.handleAuthorizationRequest(authorize(scope: scope))
        return try #require(try await storage.getAuthorizationCode(code: response.code)).scope
    }

    @Test("No scope requested: the deployment's offered scopes, in the order it declared them")
    func defaultIsWhatTheDeploymentOffers() async throws {
        let (server, storage) = try await Self.makeServer(scopesSupported: ["files:read", "files:write"])

        let granted = try await Self.grantedScope(server, storage, scope: nil)

        #expect(granted == "files:read files:write")
    }

    @Test("A blank scope is treated as none requested")
    func blankScopeIsAbsent() async throws {
        let (server, storage) = try await Self.makeServer(scopesSupported: ["files:read"])

        let granted = try await Self.grantedScope(server, storage, scope: "  ")

        #expect(granted == "files:read")
    }

    @Test("A deployment that offers no MCP scopes never grants one")
    func noMCPScopesInvented() async throws {
        let (server, storage) = try await Self.makeServer(scopesSupported: ["files:read"])

        let granted = try #require(try await Self.grantedScope(server, storage, scope: nil))

        #expect(!granted.contains("mcp:"))
    }

    @Test("A requested scope is still passed through unchanged")
    func requestedScopeUnchanged() async throws {
        let (server, storage) = try await Self.makeServer(scopesSupported: ["files:read", "files:write"])

        let granted = try await Self.grantedScope(server, storage, scope: "files:read")

        #expect(granted == "files:read")
    }

    @Test("Offering nothing and requesting nothing is invalid_scope, before consent",
          arguments: [nil, [String]()])
    func noDefaultRefused(offered: [String]?) async throws {
        let (server, _) = try await Self.makeServer(scopesSupported: offered)

        await #expect(throws: OAuthError.invalidScope(Self.noDefaultMessage)) {
            _ = try await server.validateAuthorizationRequest(Self.authorize(scope: nil))
        }
        await #expect(throws: OAuthError.invalidScope(Self.noDefaultMessage)) {
            _ = try await server.handleAuthorizationRequest(Self.authorize(scope: nil))
        }
    }

    @Test("Offering nothing still lets a client that names its scope through")
    func noDefaultButRequestedScopeAccepted() async throws {
        let (server, storage) = try await Self.makeServer(scopesSupported: nil)

        let granted = try await Self.grantedScope(server, storage, scope: "openid")

        #expect(granted == "openid")
    }

    private static let noDefaultMessage =
        "No scope was requested, and this server offers none to default to. Name the scope to request."
}
