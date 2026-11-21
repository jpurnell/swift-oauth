import Testing
import Foundation
@testable import SwiftOAuthProvider
import SwiftOAuthCore

/// The consent page's optional sign-in field: a deployment that wants the approver to prove who
/// they are on the page itself, rather than through a browser's own credential dialog.
///
/// The field is structured data (a label, a hint, an error), never raw HTML from the host, so
/// that what a deployment puts in it cannot become markup.
@Suite("Consent page sign-in field")
struct ConsentSignInTests {

    private static func page(signIn: ConsentSignIn?) -> String {
        ConsentPage(
            clientName: "Test Client", clientId: "client-1", scope: "mcp:tools",
            redirectUri: "http://localhost:9000/callback", state: "s", csrfToken: "csrf",
            codeChallenge: nil, codeChallengeMethod: nil, signIn: signIn
        ).render()
    }

    @Test("Without a sign-in, the page has no password field: nothing changes for existing deployments")
    func absentByDefault() {
        let html = Self.page(signIn: nil)
        #expect(!html.contains("type=\"password\""))
        #expect(!html.contains("owner_secret"))
    }

    @Test("With a sign-in, the page asks for the secret in a labelled password field")
    func fieldIsRendered() {
        let html = Self.page(signIn: ConsentSignIn(
            label: "Owner secret", hint: "Find it in the server's secret file."))
        #expect(html.contains("<input type=\"password\""))
        #expect(html.contains("name=\"owner_secret\""))
        #expect(html.contains("autocomplete=\"current-password\""))
        #expect(html.contains("<label for=\"owner_secret\">Owner secret</label>"))
        #expect(html.contains("Find it in the server&#39;s secret file.") || html.contains("Find it in the server's secret file."))
    }

    @Test("Deny does not demand the secret, because declining needs no proof of who you are")
    func denyBypassesValidation() throws {
        let html = Self.page(signIn: ConsentSignIn(label: "Owner secret", hint: "h"))
        let deny = try #require(html.range(of: "value=\"deny\""))
        let tagStart = try #require(html[..<deny.lowerBound].range(of: "<button", options: .backwards))
        let tagEnd = try #require(html[deny.upperBound...].range(of: ">"))
        let tag = html[tagStart.lowerBound..<tagEnd.upperBound]
        #expect(tag.contains("formnovalidate"))
        #expect(html.contains("name=\"owner_secret\"") && html.contains("required"))
    }

    @Test("An error is shown, escaped, and the field takes focus")
    func errorIsShown() {
        let html = Self.page(signIn: ConsentSignIn(
            label: "Owner secret", hint: "h", errorMessage: "That secret <b>isn't</b> right."))
        #expect(html.contains("role=\"alert\""))
        #expect(html.contains("That secret &lt;b&gt;isn"))
        #expect(!html.contains("<b>isn"))
        #expect(html.contains("autofocus"))
    }

    @Test("A label or hint containing markup is escaped, not rendered")
    func hostTextIsEscaped() {
        let html = Self.page(signIn: ConsentSignIn(
            label: "<script>alert(1)</script>", hint: "\"><img src=x onerror=alert(1)>"))
        #expect(!html.contains("<script>alert(1)"))
        #expect(!html.contains("<img src=x"))
    }

    @Test("The field name is not one the page already uses, so it cannot collide with a hidden field")
    func fieldNameIsDistinct() {
        let hidden = ["client_id", "redirect_uri", "csrf_token", "state", "scope",
                      "code_challenge", "code_challenge_method", "resource", "action"]
        #expect(!hidden.contains(ConsentSignIn.fieldName))
    }

    @Test("GET /authorize carries the sign-in through to the page it renders")
    func handlerRendersSignIn() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(
            storage: storage, issuer: "https://mcp.example.com",
            scopesSupported: ["mcp:tools"], served: .core, resourceIdentity: .colocated)
        let clientId = try await server.registerClient(ClientRegistrationRequest(
            clientName: "Test Client", redirectUris: ["https://client.example.com/callback"])).clientId
        let handler = OAuthHTTPHandler(server: server)
        let query = ["response_type": "code", "client_id": clientId,
                     "redirect_uri": "https://client.example.com/callback", "scope": "mcp:tools"]

        let plain = await handler.handleAuthorizationRequest(queryParams: query)
        #expect(plain.statusCode == 200)
        #expect(!plain.body.contains("owner_secret"))

        let signedIn = await handler.handleAuthorizationRequest(
            queryParams: query, signIn: ConsentSignIn(label: "Owner secret", hint: "h"))
        #expect(signedIn.statusCode == 200)
        #expect(signedIn.body.contains("name=\"owner_secret\""))
    }
}
