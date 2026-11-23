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

    // MARK: Password-manager hints
    //
    // A password manager keys an entry on a username and a password in the same form. A lone password
    // field gives it nothing to key on, so it neither offers to save the secret nor fills it later.
    // The username is shown read-only: it is the account the secret belongs to, not something typed.

    @Test("A named username is a read-only username field before the password field, inside the form")
    func usernameFieldPrecedesPassword() throws {
        let html = Self.page(signIn: ConsentSignIn(label: "Owner secret", hint: "h", username: "owner"))
        let formStart = try #require(html.range(of: "<form method=\"POST\" action=\"/authorize/consent\">"))
        let formEnd = try #require(html.range(of: "</form>"))
        let user = try #require(html.range(of: "autocomplete=\"username\""))
        let pass = try #require(html.range(of: "autocomplete=\"current-password\""))
        #expect(formStart.upperBound <= user.lowerBound)
        #expect(user.lowerBound < pass.lowerBound)
        #expect(pass.upperBound <= formEnd.lowerBound)
        #expect(html.contains("name=\"\(ConsentSignIn.usernameFieldName)\""))
        #expect(html.contains("value=\"owner\""))
        #expect(html.contains("readonly"))
    }

    @Test("Without a username the page is exactly what it was: no username field")
    func noUsernameByDefault() {
        let html = Self.page(signIn: ConsentSignIn(label: "Owner secret", hint: "h"))
        #expect(!html.contains("autocomplete=\"username\""))
        #expect(!html.contains(ConsentSignIn.usernameFieldName))
    }

    @Test("A username containing markup is escaped in the attribute, not rendered")
    func usernameIsEscaped() {
        let html = Self.page(signIn: ConsentSignIn(
            label: "l", hint: "h", username: "\"><script>alert(1)</script>"))
        #expect(!html.contains("<script>alert(1)"))
        #expect(!html.contains("\"><script>"))
    }

    @Test("The username field name is not one the page already uses, and differs from the secret's")
    func usernameFieldNameIsDistinct() {
        let used = ["client_id", "redirect_uri", "csrf_token", "state", "scope", "code_challenge",
                    "code_challenge_method", "resource", "action", ConsentSignIn.fieldName]
        #expect(!used.contains(ConsentSignIn.usernameFieldName))
    }

    @Test("The username is not required, so Deny still needs nothing typed")
    func usernameDoesNotBlockDeny() throws {
        let html = Self.page(signIn: ConsentSignIn(label: "l", hint: "h", username: "owner"))
        let tag = try #require(html.range(of: "autocomplete=\"username\""))
        let open = try #require(html[..<tag.lowerBound].range(of: "<input", options: .backwards))
        let close = try #require(html[tag.upperBound...].range(of: ">"))
        #expect(!html[open.lowerBound..<close.upperBound].contains("required"))
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
