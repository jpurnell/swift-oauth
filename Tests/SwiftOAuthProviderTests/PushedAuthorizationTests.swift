import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// Pushed authorization requests — RFC 9126.
///
/// Ordinarily a client puts its authorization request in a URL and sends the user's browser
/// there. Every parameter is then visible to the browser, its history, any extension, and every
/// intermediary that logs a URL — and, worse, is modifiable by all of them before the
/// authorization server sees it.
///
/// PAR moves that to a back-channel POST the client authenticates. The server hands back a
/// `request_uri`, and the browser carries only that opaque reference. What the user's agent can
/// see it can no longer change, which is the whole point.
@Suite("RFC 9126 — pushed authorization requests")
struct PushedAuthorizationTests {

    private func makeServer() async throws -> (OAuthServer, ClientRegistrationResponse) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"], served: .core,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let client = try await server.registerClient(ClientRegistrationRequest(
            clientName: "pusher",
            redirectUris: ["https://app.example.com/callback"]))
        return (server, client)
    }

    /// A pushed request comes back as an opaque reference with a lifetime.
    @Test("Pushing a request returns a request_uri and its lifetime")
    func pushReturnsRequestURI() async throws {
        let (server, client) = try await makeServer()

        let pushed = try await server.pushAuthorizationRequest(
            clientId: client.clientId,
            redirectUri: "https://app.example.com/callback",
            scope: "read",
            state: "xyz",
            codeChallenge: "challenge",
            codeChallengeMethod: "S256")

        // §2.2: the URN form, so a server can tell a pushed reference from any other URI it
        // might be handed.
        #expect(pushed.requestURI.hasPrefix("urn:ietf:params:oauth:request_uri:"))
        #expect(pushed.expiresIn > 0)
    }

    /// The reference is unguessable. It travels through a browser, so anything short enough to
    /// guess is a way to make a user authorise a request they never saw.
    @Test("The request_uri is long enough not to be guessed")
    func requestURIIsUnguessable() async throws {
        let (server, client) = try await makeServer()

        let pushed = try await server.pushAuthorizationRequest(
            clientId: client.clientId,
            redirectUri: "https://app.example.com/callback",
            scope: nil, state: nil, codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", codeChallengeMethod: "S256")

        let reference = pushed.requestURI
            .replacingOccurrences(of: "urn:ietf:params:oauth:request_uri:", with: "")
        #expect(reference.count >= 32)
    }

    /// Redeeming it yields the parameters that were pushed, not what the browser carried.
    @Test("The pushed parameters are what the authorization request uses")
    func pushedParametersAreRecovered() async throws {
        let (server, client) = try await makeServer()
        let pushed = try await server.pushAuthorizationRequest(
            clientId: client.clientId,
            redirectUri: "https://app.example.com/callback",
            scope: "read write",
            state: "state-1",
            codeChallenge: "abc",
            codeChallengeMethod: "S256")

        let recovered = try await server.consumePushedRequest(
            requestURI: pushed.requestURI, clientId: client.clientId)

        #expect(recovered.scope == "read write")
        #expect(recovered.state == "state-1")
        #expect(recovered.codeChallenge == "abc")
        #expect(recovered.redirectUri == "https://app.example.com/callback")
    }

    /// Single-use — §2.2. A reference that can be replayed is one a browser extension can
    /// harvest and reuse.
    @Test("A request_uri cannot be used twice")
    func requestURIIsSingleUse() async throws {
        let (server, client) = try await makeServer()
        let pushed = try await server.pushAuthorizationRequest(
            clientId: client.clientId,
            redirectUri: "https://app.example.com/callback",
            scope: nil, state: nil, codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", codeChallengeMethod: "S256")
        _ = try await server.consumePushedRequest(
            requestURI: pushed.requestURI, clientId: client.clientId)

        await #expect(throws: OAuthError.self) {
            _ = try await server.consumePushedRequest(
                requestURI: pushed.requestURI, clientId: client.clientId)
        }
    }

    /// It belongs to the client that pushed it.
    ///
    /// Without this, a reference observed in a redirect URL is usable by any client that can
    /// name its own id — and the parameters it carries, including the redirect URI, were chosen
    /// by someone else.
    @Test("Another client cannot consume a pushed request")
    func requestURIIsBoundToItsClient() async throws {
        let (server, client) = try await makeServer()
        let pushed = try await server.pushAuthorizationRequest(
            clientId: client.clientId,
            redirectUri: "https://app.example.com/callback",
            scope: nil, state: nil, codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", codeChallengeMethod: "S256")

        await #expect(throws: OAuthError.self) {
            _ = try await server.consumePushedRequest(
                requestURI: pushed.requestURI, clientId: "someone-else")
        }
    }

    /// An unknown reference and a spent one answer the same way, so a caller cannot probe which
    /// references exist.
    @Test("An unknown request_uri is refused like a spent one")
    func unknownRequestURIIsRefused() async throws {
        let (server, client) = try await makeServer()

        await #expect(throws: OAuthError.self) {
            _ = try await server.consumePushedRequest(
                requestURI: "urn:ietf:params:oauth:request_uri:never-existed",
                clientId: client.clientId)
        }
    }
}
