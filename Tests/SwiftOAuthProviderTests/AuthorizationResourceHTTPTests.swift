import Testing
import Foundation
@testable import SwiftOAuthProvider
import SwiftOAuthCore

/// RFC 8707 through the HTTP layer, under a strict policy.
///
/// The suites that already cover resource indicators build an `AuthorizationRequest` by hand and
/// hand it to `OAuthServer`, which tests the half that was never broken: the validation. The
/// `resource` parameter arrives over HTTP, and between the query string and that struct sit two
/// constructions and a consent form. Every one of them dropped it, so `request.resource` was
/// unconditionally `nil` for any client that could only speak HTTP — which is all of them.
///
/// Under a permissive policy that is invisible: `nil` is allowed, so the flow succeeds and the
/// audience is simply absent. Under a strict one it refuses every authorization, including one
/// whose error text tells the client to send the parameter it is already sending.
///
/// So these tests are strict on purpose. The permissive suites cannot see this defect, and that
/// is the whole reason it survived.
@Suite("Authorization resource over HTTP")
struct AuthorizationResourceHTTPTests {

    /// Kept in step with the literal in `makeServer()` by this test: a policy built over a
    /// different resource than the requests name would refuse everything, and the suite would
    /// pass its negative case for the wrong reason.
    static let resource = "https://mcp.example.com"

    @Test("The suite's resource constant matches the policy the server is built with")
    func constantMatchesPolicy() async throws {
        let (handler, _, clientId) = try await makeHandler()
        let response = await handler.handleConsentSubmission(formParams: [
            "action": "approve", "client_id": clientId,
            "redirect_uri": "https://client.example.com/callback",
            "csrf_token": "not-a-valid-token", "resource": Self.resource])
        // Whatever else fails here, it must not be the target: the constant names the resource
        // the server actually protects.
        #expect(!(response.headers["Location"] ?? "").contains("error=invalid_target"),
                "The suite constant has drifted from the policy in makeServer()")
    }

    /// A server that issues tokens for exactly one resource and refuses a request naming none.
    private func makeServer() throws -> (OAuthServer, OAuthStorage) {
        let storage = try OAuthStorage(path: ":memory:")
        let identifier = try #require(URL(string: "https://mcp.example.com"))
        let server = OAuthServer(
            storage: storage, issuer: "https://mcp.example.com",
            scopesSupported: ["mcp:tools"], served: .core, resourceIdentity: .colocated,
            resourcePolicy: .protecting(identifier))
        return (server, storage)
    }

    /// The handler, its storage, and a registered client — one server, so the client is
    /// registered in the same storage the handler reads.
    private func makeHandler() async throws -> (OAuthHTTPHandler, OAuthStorage, String) {
        let (server, storage) = try makeServer()
        let clientId = try await server.registerClient(ClientRegistrationRequest(
            clientName: "Test Client",
            redirectUris: ["https://client.example.com/callback"])).clientId
        return (OAuthHTTPHandler(server: server), storage, clientId)
    }

    // There is no separate "GET /authorize forwards the resource" test, and the absence is
    // deliberate. One was written and removed: it asserted that a request naming the resource
    // reaches the consent page, which it does whether or not the parameter survives — the GET
    // path validates the client and the redirect URI, and consults the resource policy nowhere.
    // It passed against the broken handler. The rendered form below is the only observable the
    // GET path has, so that test is this one.

    @Test("The consent page carries the resource as a hidden field")
    func consentPageCarriesResource() async throws {
        let (handler, _, clientId) = try await makeHandler()

        let response = await handler.handleAuthorizationRequest(queryParams: [
            "response_type": "code",
            "client_id": clientId,
            "redirect_uri": "https://client.example.com/callback",
            "scope": "mcp:tools",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "resource": Self.resource
        ])

        // Forwarding `formParams["resource"]` on the POST is not enough on its own. A browser
        // posts what the page rendered, not what the original query string held, so a resource
        // absent from the form is a resource the user's approval silently drops — the same bug
        // through a narrower door, reachable only from a real browser and not from a test that
        // supplies the form fields itself.
        #expect(response.body.contains("name=\"resource\""),
                "The form must carry the resource, or the browser round trip loses it")
        #expect(response.body.contains("value=\"\(Self.resource)\""),
                "The hidden field must carry the value that was requested")
    }

    @Test("Consent approval under a strict policy issues a code")
    func consentApprovalHonoursResource() async throws {
        let (handler, storage, clientId) = try await makeHandler()
        let csrfToken = try await storage.generateCSRFToken(
            clientId: clientId, redirectUri: "https://client.example.com/callback")

        let response = await handler.handleConsentSubmission(formParams: [
            "action": "approve",
            "client_id": clientId,
            "redirect_uri": "https://client.example.com/callback",
            "csrf_token": csrfToken,
            "scope": "mcp:tools",
            "state": "test-state",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "resource": Self.resource
        ])

        let location = response.headers["Location"] ?? ""
        #expect(response.statusCode == 302, "Should redirect")
        #expect(location.contains("code="), "Should carry an authorization code")
        #expect(!location.contains("error=invalid_target"),
                "The form named the resource; invalid_target means the approve action dropped it")
    }

    @Test("A strict policy still refuses an authorization naming no resource")
    func strictStillRefusesOmission() async throws {
        let (handler, storage, clientId) = try await makeHandler()
        let csrfToken = try await storage.generateCSRFToken(
            clientId: clientId, redirectUri: "https://client.example.com/callback")

        // The negative control. Without it, forwarding the parameter and hardcoding the audience
        // would both pass every test above, and this suite would prove only that the flow
        // completes — not that the value did anything.
        let response = await handler.handleConsentSubmission(formParams: [
            "action": "approve",
            "client_id": clientId,
            "redirect_uri": "https://client.example.com/callback",
            "csrf_token": csrfToken,
            "scope": "mcp:tools",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256"
        ])

        let location = response.headers["Location"] ?? ""
        #expect(location.contains("error=invalid_target"),
                "A strict policy must refuse a request that named no resource")
    }
}
