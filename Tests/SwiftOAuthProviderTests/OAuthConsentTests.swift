import Testing
import Foundation
@testable import SwiftOAuthProvider
import SwiftOAuthCore

/// Test suite for OAuth Consent UI
///
/// Tests verify:
/// - Consent page HTML rendering
/// - CSRF token generation and validation
/// - Approve flow returns authorization code
/// - Deny flow returns access_denied error
/// - Security: expired tokens, invalid clients
@Suite("OAuth Consent UI Tests")
struct OAuthConsentTests {

    // MARK: - ConsentPage Rendering Tests

    @Test("ConsentPage - Renders valid HTML")
    func testConsentPageRendersValidHTML() async throws {
        let page = ConsentPage(
            clientName: "Test Client",
            clientId: "test-client-id",
            scope: "mcp:tools mcp:resources",
            redirectUri: "http://localhost:8080/callback",
            state: "test-state",
            csrfToken: "csrf-token-123",
            codeChallenge: nil,
            codeChallengeMethod: nil
        )

        let html = page.render()

        // Basic HTML structure
        #expect(html.contains("<!DOCTYPE html>"), "Should have DOCTYPE")
        #expect(html.contains("<html"), "Should have html tag")
        #expect(html.contains("</html>"), "Should close html tag")
        #expect(html.contains("<head>"), "Should have head tag")
        #expect(html.contains("<body>"), "Should have body tag")
        #expect(html.contains("<form"), "Should have form element")
    }

    @Test("ConsentPage - Includes all required fields")
    func testConsentPageIncludesRequiredFields() async throws {
        let page = ConsentPage(
            clientName: "My MCP Client",
            clientId: "client-abc123",
            scope: "mcp:tools mcp:resources",
            redirectUri: "http://localhost:8080/callback",
            state: "state-xyz",
            csrfToken: "csrf-token-456",
            codeChallenge: "challenge123",
            codeChallengeMethod: "S256"
        )

        let html = page.render()

        // Client information displayed
        #expect(html.contains("My MCP Client"), "Should display client name")

        // Scope displayed
        #expect(html.contains("mcp:tools"), "Should display requested scopes")
        #expect(html.contains("mcp:resources"), "Should display requested scopes")

        // Hidden form fields
        #expect(html.contains("name=\"client_id\""), "Should have client_id field")
        #expect(html.contains("value=\"client-abc123\""), "Should have client_id value")
        #expect(html.contains("name=\"redirect_uri\""), "Should have redirect_uri field")
        #expect(html.contains("name=\"csrf_token\""), "Should have csrf_token field")
        #expect(html.contains("value=\"csrf-token-456\""), "Should have csrf_token value")
        #expect(html.contains("name=\"state\""), "Should have state field")
        #expect(html.contains("name=\"code_challenge\""), "Should have code_challenge field")
        #expect(html.contains("name=\"code_challenge_method\""), "Should have code_challenge_method field")

        // Approve/Deny buttons
        #expect(html.contains("name=\"action\""), "Should have action field")
        #expect(html.contains("value=\"approve\""), "Should have approve action")
        #expect(html.contains("value=\"deny\""), "Should have deny action")
    }

    @Test("ConsentPage - Escapes HTML in client name (XSS prevention)")
    func testConsentPageEscapesHTML() async throws {
        let page = ConsentPage(
            clientName: "<script>alert('xss')</script>",
            clientId: "test-client",
            scope: "mcp:tools",
            redirectUri: "http://localhost:8080/callback",
            state: nil,
            csrfToken: "csrf-token",
            codeChallenge: nil,
            codeChallengeMethod: nil
        )

        let html = page.render()

        // Should NOT contain raw script tag
        #expect(!html.contains("<script>alert"), "Should escape script tags")
        // Should contain escaped version
        #expect(html.contains("&lt;script&gt;") || html.contains("&#60;script&#62;"), "Should contain escaped HTML")
    }

    // MARK: - CSRF Token Tests

    @Test("CSRF - Token generation creates unique tokens")
    func testCSRFTokenGeneration() async throws {
        let storage = try OAuthStorage(path: ":memory:")

        let token1 = try await storage.generateCSRFToken(
            clientId: "client1",
            redirectUri: "http://localhost:8080/callback"
        )
        let token2 = try await storage.generateCSRFToken(
            clientId: "client1",
            redirectUri: "http://localhost:8080/callback"
        )

        #expect(!token1.isEmpty, "Token should not be empty")
        #expect(token1.count >= 32, "Token should be at least 32 characters")
        #expect(token1 != token2, "Each token should be unique")
    }

    @Test("CSRF - Valid token is accepted")
    func testCSRFTokenValidation() async throws {
        let storage = try OAuthStorage(path: ":memory:")

        let token = try await storage.generateCSRFToken(
            clientId: "client1",
            redirectUri: "http://localhost:8080/callback"
        )

        let result = try await storage.validateCSRFToken(
            token: token,
            clientId: "client1",
            redirectUri: "http://localhost:8080/callback"
        )

        #expect(result.isValid, "Valid token should be accepted")
    }

    @Test("CSRF - Invalid token is rejected")
    func testCSRFInvalidTokenRejected() async throws {
        let storage = try OAuthStorage(path: ":memory:")

        // Generate a real token
        _ = try await storage.generateCSRFToken(
            clientId: "client1",
            redirectUri: "http://localhost:8080/callback"
        )

        // Try to validate with wrong token
        let result = try await storage.validateCSRFToken(
            token: "invalid-token-xyz",
            clientId: "client1",
            redirectUri: "http://localhost:8080/callback"
        )

        #expect(!result.isValid, "Invalid token should be rejected")
    }

    @Test("CSRF - Token with wrong client_id is rejected")
    func testCSRFWrongClientRejected() async throws {
        let storage = try OAuthStorage(path: ":memory:")

        let token = try await storage.generateCSRFToken(
            clientId: "client1",
            redirectUri: "http://localhost:8080/callback"
        )

        let result = try await storage.validateCSRFToken(
            token: token,
            clientId: "different-client",
            redirectUri: "http://localhost:8080/callback"
        )

        #expect(!result.isValid, "Token with wrong client_id should be rejected")
    }

    @Test("CSRF - Expired token is rejected")
    func testCSRFExpiredTokenRejected() async throws {
        let storage = try OAuthStorage(path: ":memory:")

        // Generate token with very short expiration (for testing)
        let token = try await storage.generateCSRFToken(
            clientId: "client1",
            redirectUri: "http://localhost:8080/callback",
            expiresIn: 0.1 // 100ms
        )

        // Wait for expiration
        try await Task.sleep(nanoseconds: 200_000_000) // 200ms

        let result = try await storage.validateCSRFToken(
            token: token,
            clientId: "client1",
            redirectUri: "http://localhost:8080/callback"
        )

        #expect(!result.isValid, "Expired token should be rejected")
    }

    @Test("CSRF - Token is single-use (consumed after validation)")
    func testCSRFTokenSingleUse() async throws {
        let storage = try OAuthStorage(path: ":memory:")

        let token = try await storage.generateCSRFToken(
            clientId: "client1",
            redirectUri: "http://localhost:8080/callback"
        )

        // First validation should succeed
        let result1 = try await storage.validateCSRFToken(
            token: token,
            clientId: "client1",
            redirectUri: "http://localhost:8080/callback"
        )
        #expect(result1.isValid, "First validation should succeed")

        // Second validation should fail (token consumed)
        let result2 = try await storage.validateCSRFToken(
            token: token,
            clientId: "client1",
            redirectUri: "http://localhost:8080/callback"
        )
        #expect(!result2.isValid, "Token should be consumed after first use")
    }

    // MARK: - Consent Submission Tests

    @Test("Consent - Approve returns authorization code")
    func testConsentApproveReturnsCode() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(storage: storage, issuer: "http://localhost:8080",
            // These suites predate RFC 8707 and exercise other things — grants, PKCE, consent, wire
            // shapes. Strict resource indicators would make every one of them carry a `resource`
            // parameter that has nothing to do with what they test. The strict default has its own
            // coverage in ResourceIndicatorTests and AudienceBindingTests.
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let handler = OAuthHTTPHandler(server: server)

        // Register a client first
        let clientResponse = try await server.registerClient(ClientRegistrationRequest(
            clientName: "Test Client",
            redirectUris: ["http://localhost:8080/callback"]
        ))

        // Generate CSRF token
        let csrfToken = try await storage.generateCSRFToken(
            clientId: clientResponse.clientId,
            redirectUri: "http://localhost:8080/callback"
        )

        // Submit consent approval
        let response = await handler.handleConsentSubmission(formParams: [
            "action": "approve",
            "client_id": clientResponse.clientId,
            "redirect_uri": "http://localhost:8080/callback",
            "csrf_token": csrfToken,
            "scope": "mcp:tools",
            "state": "test-state"
        ])

        #expect(response.statusCode == 302, "Should redirect")
        let location = response.headers["Location"] ?? ""
        #expect(location.contains("code="), "Should include authorization code")
        #expect(location.contains("state=test-state"), "Should preserve state")
        #expect(!location.contains("error="), "Should not have error")
    }

    @Test("Consent - Deny returns access_denied error")
    func testConsentDenyReturnsError() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(storage: storage, issuer: "http://localhost:8080",
            // These suites predate RFC 8707 and exercise other things — grants, PKCE, consent, wire
            // shapes. Strict resource indicators would make every one of them carry a `resource`
            // parameter that has nothing to do with what they test. The strict default has its own
            // coverage in ResourceIndicatorTests and AudienceBindingTests.
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let handler = OAuthHTTPHandler(server: server)

        // Register a client first
        let clientResponse = try await server.registerClient(ClientRegistrationRequest(
            clientName: "Test Client",
            redirectUris: ["http://localhost:8080/callback"]
        ))

        // Generate CSRF token
        let csrfToken = try await storage.generateCSRFToken(
            clientId: clientResponse.clientId,
            redirectUri: "http://localhost:8080/callback"
        )

        // Submit consent denial
        let response = await handler.handleConsentSubmission(formParams: [
            "action": "deny",
            "client_id": clientResponse.clientId,
            "redirect_uri": "http://localhost:8080/callback",
            "csrf_token": csrfToken,
            "state": "test-state"
        ])

        #expect(response.statusCode == 302, "Should redirect")
        let location = response.headers["Location"] ?? ""
        #expect(location.contains("error=access_denied"), "Should have access_denied error")
        #expect(location.contains("state=test-state"), "Should preserve state")
        #expect(!location.contains("code="), "Should not have authorization code")
    }

    @Test("Consent - Invalid CSRF token rejected")
    func testConsentInvalidCSRFRejected() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(storage: storage, issuer: "http://localhost:8080",
            // These suites predate RFC 8707 and exercise other things — grants, PKCE, consent, wire
            // shapes. Strict resource indicators would make every one of them carry a `resource`
            // parameter that has nothing to do with what they test. The strict default has its own
            // coverage in ResourceIndicatorTests and AudienceBindingTests.
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let handler = OAuthHTTPHandler(server: server)

        // Register a client first
        let clientResponse = try await server.registerClient(ClientRegistrationRequest(
            clientName: "Test Client",
            redirectUris: ["http://localhost:8080/callback"]
        ))

        // Submit with invalid CSRF token
        let response = await handler.handleConsentSubmission(formParams: [
            "action": "approve",
            "client_id": clientResponse.clientId,
            "redirect_uri": "http://localhost:8080/callback",
            "csrf_token": "invalid-csrf-token",
            "state": "test-state"
        ])

        // Should return error (either 400 or 403)
        #expect(response.statusCode == 400 || response.statusCode == 403, "Should reject invalid CSRF")
        #expect(response.body.contains("invalid") || response.body.contains("csrf"), "Should mention CSRF error")
    }

    @Test("Consent - Invalid client_id rejected")
    func testConsentInvalidClientRejected() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(storage: storage, issuer: "http://localhost:8080",
            // These suites predate RFC 8707 and exercise other things — grants, PKCE, consent, wire
            // shapes. Strict resource indicators would make every one of them carry a `resource`
            // parameter that has nothing to do with what they test. The strict default has its own
            // coverage in ResourceIndicatorTests and AudienceBindingTests.
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let handler = OAuthHTTPHandler(server: server)

        // Submit with non-existent client
        let response = await handler.handleConsentSubmission(formParams: [
            "action": "approve",
            "client_id": "non-existent-client",
            "redirect_uri": "http://localhost:8080/callback",
            "csrf_token": "some-token",
            "state": "test-state"
        ])

        // Should return error
        #expect(response.statusCode == 400 || response.statusCode == 404, "Should reject invalid client")
    }

    @Test("Consent - Missing required params rejected")
    func testConsentMissingParamsRejected() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(storage: storage, issuer: "http://localhost:8080",
            // These suites predate RFC 8707 and exercise other things — grants, PKCE, consent, wire
            // shapes. Strict resource indicators would make every one of them carry a `resource`
            // parameter that has nothing to do with what they test. The strict default has its own
            // coverage in ResourceIndicatorTests and AudienceBindingTests.
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let handler = OAuthHTTPHandler(server: server)

        // Missing action
        let response1 = await handler.handleConsentSubmission(formParams: [
            "client_id": "test",
            "redirect_uri": "http://localhost:8080/callback",
            "csrf_token": "token"
        ])
        #expect(response1.statusCode == 400, "Should reject missing action")

        // Missing client_id
        let response2 = await handler.handleConsentSubmission(formParams: [
            "action": "approve",
            "redirect_uri": "http://localhost:8080/callback",
            "csrf_token": "token"
        ])
        #expect(response2.statusCode == 400, "Should reject missing client_id")

        // Missing csrf_token
        let response3 = await handler.handleConsentSubmission(formParams: [
            "action": "approve",
            "client_id": "test",
            "redirect_uri": "http://localhost:8080/callback"
        ])
        #expect(response3.statusCode == 400, "Should reject missing csrf_token")
    }

    // MARK: - Authorization Request Shows Consent Page

    @Test("Authorization - Returns consent page HTML")
    func testAuthorizationReturnsConsentPage() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(storage: storage, issuer: "http://localhost:8080",
            // These suites predate RFC 8707 and exercise other things — grants, PKCE, consent, wire
            // shapes. Strict resource indicators would make every one of them carry a `resource`
            // parameter that has nothing to do with what they test. The strict default has its own
            // coverage in ResourceIndicatorTests and AudienceBindingTests.
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let handler = OAuthHTTPHandler(server: server)

        // Register a client first
        let clientResponse = try await server.registerClient(ClientRegistrationRequest(
            clientName: "My Test Application",
            redirectUris: ["http://localhost:8080/callback"]
        ))

        // Make authorization request
        let response = await handler.handleAuthorizationRequest(queryParams: [
            "response_type": "code",
            "client_id": clientResponse.clientId,
            "redirect_uri": "http://localhost:8080/callback",
            "scope": "mcp:tools",
            "state": "test-state"
        ])

        // Should return HTML consent page, not redirect
        #expect(response.statusCode == 200, "Should return 200 with consent page")
        #expect(response.contentType.contains("text/html"), "Should be HTML content type")
        #expect(response.body.contains("My Test Application"), "Should show client name")
        #expect(response.body.contains("mcp:tools"), "Should show requested scope")
        #expect(response.body.contains("<form"), "Should have consent form")
    }

    @Test("Authorization - Invalid redirect_uri returns error page")
    func testAuthorizationInvalidRedirectUri() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(storage: storage, issuer: "http://localhost:8080",
            // These suites predate RFC 8707 and exercise other things — grants, PKCE, consent, wire
            // shapes. Strict resource indicators would make every one of them carry a `resource`
            // parameter that has nothing to do with what they test. The strict default has its own
            // coverage in ResourceIndicatorTests and AudienceBindingTests.
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let handler = OAuthHTTPHandler(server: server)

        // Register a client
        let clientResponse = try await server.registerClient(ClientRegistrationRequest(
            clientName: "Test Client",
            redirectUris: ["http://localhost:8080/callback"]
        ))

        // Use wrong redirect URI
        let response = await handler.handleAuthorizationRequest(queryParams: [
            "response_type": "code",
            "client_id": clientResponse.clientId,
            "redirect_uri": "https://attacker.example/callback", // Not registered
            "scope": "mcp:tools"
        ])

        // Should NOT redirect to the attacker URI — return the error directly
        #expect(response.statusCode == 400, "Should return 400 for invalid redirect_uri")
        #expect(!response.headers.keys.contains("Location"), "Should not redirect")
    }
}
