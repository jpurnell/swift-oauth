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
/// ## This suite has been seen to fail
///
/// Verified against the broken shape by reverting all four forwarding sites: **the build
/// reported 0 errors** and three of the five tests failed — the hidden field, the consent
/// approval, and the browser round trip on all three of its assertions. The build-error count
/// is part of the result, not a detail: a suite that fails to compile and a suite that detects
/// the bug are the same red in a terminal, and both of us were fooled by that today.
///
/// Repeat it by replacing the three `resource:` arguments in `OAuthHTTPHandler` with `nil` and
/// deleting the hidden-field line from `ConsentPage.render()`.
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

    // MARK: - The browser round trip

    /// The fields a browser would submit: every `<input>` inside the `<form>`, decoded.
    ///
    /// Contributed by the SwiftMCPServer session, which used it to catch this bug from the
    /// outside. Three weaknesses it stated when handing it over, and what was done about each:
    ///
    /// 1. **It did not know what a `<form>` was**, so it collected inputs anywhere on the page
    ///    and would still have passed with the resource field rendered outside the form — one
    ///    of the failures the string assertions already miss. Fixed rather than documented,
    ///    because this package owns the page: the scan is bounded to the form element.
    /// 2. **It took the last of a duplicate name**, where a browser submits both. A page
    ///    rendering `resource` twice with different values would look correct here and send
    ///    something ambiguous in reality. Now a duplicate throws.
    /// 3. **It did not decode entities.** Not hypothetical: ``ConsentPage`` escapes `&`, and a
    ///    resource identifier carrying a query string is ordinary, so an undecoded value would
    ///    fail to match for a reason that has nothing to do with the code under test.
    ///
    /// It is a parser for one page whose exact markup this package emits, not a general one.
    private func renderedFields(in html: String) throws -> [String: String] {
        let formStart = try #require(html.range(of: "<form"), "The consent page must have a form")
        let formEnd = try #require(
            html.range(of: "</form>", range: formStart.upperBound..<html.endIndex),
            "The consent form must be closed")
        let form = String(html[formStart.upperBound..<formEnd.lowerBound])

        func decode(_ value: String) -> String {
            // Ampersand last: decoding it first would turn "&amp;lt;" into "<".
            value.replacingOccurrences(of: "&quot;", with: "\"")
                .replacingOccurrences(of: "&#39;", with: "'")
                .replacingOccurrences(of: "&lt;", with: "<")
                .replacingOccurrences(of: "&gt;", with: ">")
                .replacingOccurrences(of: "&amp;", with: "&")
        }

        func quoted(after attribute: String, in tag: Substring) -> String? {
            guard let range = tag.range(of: attribute) else { return nil }
            let rest = tag[range.upperBound...]
            guard let open = rest.firstIndex(of: "\""),
                  let close = rest[rest.index(after: open)...].firstIndex(of: "\"")
            else { return nil }
            return decode(String(rest[rest.index(after: open)..<close]))
        }

        var fields: [String: String] = [:]
        for tag in form.components(separatedBy: "<input").dropFirst() {
            guard let name = quoted(after: "name=", in: tag[...]),
                  let value = quoted(after: "value=", in: tag[...]) else { continue }
            // A browser submits both of a duplicate pair. Keeping the last would hide a
            // double-rendered hidden field, which is a real rendering bug.
            #expect(fields[name] == nil, "The form rendered '\(name)' more than once")
            fields[name] = value
        }
        return fields
    }

    @Test("A browser round trip: submit only what the page rendered")
    func browserRoundTrip() async throws {
        let (handler, _, clientId) = try await makeHandler()

        let page = await handler.handleAuthorizationRequest(queryParams: [
            "response_type": "code",
            "client_id": clientId,
            "redirect_uri": "https://client.example.com/callback",
            "scope": "mcp:tools",
            "state": "test-state",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "resource": Self.resource
        ])

        // The whole point: what a browser posts is what the page contains, not what the
        // original query string held. Nothing is added here except the button that was pressed.
        var fields = try renderedFields(in: page.body)
        #expect(fields["resource"] == Self.resource,
                "The form must submit the resource the authorization request named")
        fields["action"] = "approve"

        let response = await handler.handleConsentSubmission(formParams: fields)
        let location = response.headers["Location"] ?? ""
        #expect(location.contains("code="), "The round trip must yield an authorization code")
        #expect(!location.contains("error=invalid_target"),
                "invalid_target here means the browser round trip lost the resource")
    }
}
