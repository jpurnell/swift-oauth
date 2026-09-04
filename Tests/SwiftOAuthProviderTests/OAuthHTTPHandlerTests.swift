import Testing
import Foundation
@testable import SwiftOAuthProvider
import SwiftOAuthCore

/// Tests for OAuth 2.0 HTTP Handler
@Suite("OAuth HTTP Handler")
struct OAuthHTTPHandlerTests {

    // MARK: - Test Helpers

    static func makeTestHandler() async throws -> OAuthHTTPHandler {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(storage: storage, issuer: "https://example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"], served: .core,
            // These suites predate RFC 8707 and exercise other things — grants, PKCE, consent, wire
            // shapes. Strict resource indicators would make every one of them carry a `resource`
            // parameter that has nothing to do with what they test. The strict default has its own
            // coverage in ResourceIndicatorTests and AudienceBindingTests.
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        return OAuthHTTPHandler(server: server)
    }

    // MARK: - Metadata Endpoint Tests

    @Suite("Metadata Endpoint")
    struct MetadataEndpointTests {

        @Test("Returns valid JSON metadata")
        func returnsValidJSONMetadata() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let response = await handler.handleMetadataRequest()

            #expect(response.statusCode == 200)
            #expect(response.contentType == "application/json")
            #expect(response.body.contains("issuer"))
            #expect(response.body.contains("authorization_endpoint"))
            #expect(response.body.contains("token_endpoint"))
        }

        @Test("Metadata is RFC 8414 compliant")
        func metadataIsRFC8414Compliant() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let response = await handler.handleMetadataRequest()

            let data = Data(response.body.utf8)
            let metadata = try JSONDecoder().decode(ServerMetadata.self, from: data)

            #expect(metadata.issuer == "https://example.com")
            #expect(metadata.authorizationEndpoint == "https://example.com/authorize")
            #expect(metadata.tokenEndpoint == "https://example.com/token")
            #expect(metadata.responseTypesSupported.contains("code"))
        }
    }

    // MARK: - Protected Resource Metadata Tests

    @Suite("Protected Resource Metadata Endpoint")
    struct ProtectedResourceMetadataTests {

        @Test("Returns valid JSON protected resource metadata")
        func returnsValidJSON() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let response = await handler.handleProtectedResourceMetadata()

            #expect(response.statusCode == 200)
            #expect(response.contentType == "application/json")
            #expect(response.body.contains("resource"))
            #expect(response.body.contains("authorization_servers"))
            #expect(response.body.contains("scopes_supported"))
        }

        @Test("Protected resource metadata is RFC 9728 compliant")
        func metadataIsRFC9728Compliant() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let response = await handler.handleProtectedResourceMetadata()

            let data = Data(response.body.utf8)
            let metadata = try JSONDecoder().decode(ProtectedResourceMetadata.self, from: data)

            #expect(metadata.resource == "https://example.com")
            #expect(metadata.authorizationServers == ["https://example.com"])
            // Required, not optional-chained: the field being absent is a distinct failure
            // from it being present and wrong, and `?.contains() == true` would report both
            // the same way.
            let scopes = try #require(metadata.scopesSupported)
            #expect(scopes.contains("mcp:tools"))
            #expect(scopes.contains("mcp:resources"))
            #expect(scopes.contains("mcp:prompts"))
            #expect(metadata.bearerMethodsSupported.contains("header"))
        }
    }

    // MARK: - Registration Endpoint Tests

    @Suite("Registration Endpoint")
    struct RegistrationEndpointTests {

        @Test("Registers client with valid request")
        func registersClientWithValidRequest() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let requestBody = """
            {
                "client_name": "Test Client",
                "redirect_uris": ["http://localhost:8080/callback"]
            }
            """

            let response = await handler.handleRegistrationRequest(body: requestBody)

            #expect(response.statusCode == 201)
            #expect(response.contentType == "application/json")
            #expect(response.body.contains("client_id"))
            #expect(response.body.contains("client_secret"))
        }

        @Test("Returns error for invalid JSON")
        func returnsErrorForInvalidJSON() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let response = await handler.handleRegistrationRequest(body: "invalid json")

            #expect(response.statusCode == 400)
            #expect(response.body.contains("error"))
        }

        @Test("Returns error for missing required fields")
        func returnsErrorForMissingFields() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let requestBody = """
            {
                "client_name": "Test Client"
            }
            """

            let response = await handler.handleRegistrationRequest(body: requestBody)

            #expect(response.statusCode == 400)
        }
    }

    // MARK: - Authorization Endpoint Tests

    @Suite("Authorization Endpoint")
    struct AuthorizationEndpointTests {

        @Test("Returns redirect with code for valid request")
        func returnsRedirectWithCode() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            // First register a client
            let regBody = """
            {
                "client_name": "Auth Test",
                "redirect_uris": ["http://localhost/callback"]
            }
            """
            let regResponse = await handler.handleRegistrationRequest(body: regBody)
            let regData = Data(regResponse.body.utf8)
            let client = try JSONDecoder().decode(ClientRegistrationResponse.self, from: regData)

            // Make authorization request
            let params: [String: String] = [
                "response_type": "code",
                "client_id": client.clientId,
                "redirect_uri": "http://localhost/callback",
                "state": "test_state_123"
            ]

            // Authorization request now returns consent page
            let response = await handler.handleAuthorizationRequest(queryParams: params)

            #expect(response.statusCode == 200, "Should return consent page")
            #expect(response.contentType.contains("text/html"), "Should be HTML")
            #expect(response.body.contains("Auth Test"), "Should show client name")
            #expect(response.body.contains("csrf_token"), "Should have CSRF token")
        }

        @Test("Returns error for missing parameters")
        func returnsErrorForMissingParams() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let params: [String: String] = [
                "response_type": "code"
                // Missing client_id and redirect_uri
            ]

            let response = await handler.handleAuthorizationRequest(queryParams: params)

            #expect(response.statusCode == 400)
        }

        @Test("Returns error for unknown client")
        func returnsErrorForUnknownClient() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let params: [String: String] = [
                "response_type": "code",
                "client_id": "unknown_client",
                "redirect_uri": "http://localhost/callback",
                "state": "test_state"
            ]

            let response = await handler.handleAuthorizationRequest(queryParams: params)

            // Should return error directly (not redirect to unknown redirect_uri)
            #expect(response.statusCode == 401 || response.statusCode == 400, "Should return error status")
        }
    }

    // MARK: - Token Endpoint Tests

    @Suite("Token Endpoint")
    struct TokenEndpointTests {

        @Test("Exchanges code for tokens")
        func exchangesCodeForTokens() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            // Register client with client_secret_post auth method
            let regBody = """
            {
                "client_name": "Token Test",
                "redirect_uris": ["http://localhost/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "client_secret_post"
            }
            """
            let regResponse = await handler.handleRegistrationRequest(body: regBody)
            let regData = Data(regResponse.body.utf8)
            let client = try JSONDecoder().decode(ClientRegistrationResponse.self, from: regData)
            let clientSecret = try #require(client.clientSecret)

            // Get authorization code with PKCE
            let verifier = PKCE.generateCodeVerifier()
            let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

            let authParams: [String: String] = [
                "response_type": "code",
                "client_id": client.clientId,
                "redirect_uri": "http://localhost/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256"
            ]

            // Get consent page
            let consentResponse = await handler.handleAuthorizationRequest(queryParams: authParams)
            let csrfToken = try #require(OAuthHTTPHandlerTests.extractCSRFToken(from: consentResponse.body))

            // Submit consent
            let consentParams: [String: String] = [
                "action": "approve",
                "client_id": client.clientId,
                "redirect_uri": "http://localhost/callback",
                "csrf_token": csrfToken,
                "code_challenge": challenge,
                "code_challenge_method": "S256"
            ]

            let authResponse = await handler.handleConsentSubmission(formParams: consentParams)
            let location = try #require(authResponse.headers["Location"])
            let code = try #require(extractCodeFromRedirect(location))

            // Exchange code for tokens (URL-encode values)
            let tokenBody = buildFormBody([
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost/callback",
                "client_id": client.clientId,
                "client_secret": clientSecret,
                "code_verifier": verifier
            ])

            let tokenResponse = await handler.handleTokenRequest(body: tokenBody, authHeader: nil)

            #expect(tokenResponse.statusCode == 200)
            #expect(tokenResponse.contentType == "application/json")
            #expect(tokenResponse.body.contains("access_token"))
            #expect(tokenResponse.body.contains("refresh_token"))
            #expect(tokenResponse.headers["Cache-Control"] == "no-store")
        }

        @Test("Returns error for missing grant_type")
        func returnsErrorForMissingGrantType() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let response = await handler.handleTokenRequest(
                body: "client_id=test",
                authHeader: nil
            )

            #expect(response.statusCode == 400)
            #expect(response.body.contains("invalid_request"))
        }

        @Test("Returns error for invalid client")
        func returnsErrorForInvalidClient() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let body = [
                "grant_type=authorization_code",
                "client_id=unknown",
                "client_secret=wrong",
                "code=fake_code",
                "redirect_uri=http://localhost/callback"
            ].joined(separator: "&")

            let response = await handler.handleTokenRequest(body: body, authHeader: nil)

            #expect(response.statusCode == 401)
            #expect(response.body.contains("invalid_client"))
        }

        @Test("Refreshes access token")
        func refreshesAccessToken() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            // Setup: register client with client_secret_post and get tokens
            let regBody = """
            {
                "client_name": "Refresh Test",
                "redirect_uris": ["http://localhost/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "client_secret_post"
            }
            """
            let regResponse = await handler.handleRegistrationRequest(body: regBody)
            let regData = Data(regResponse.body.utf8)
            let client = try JSONDecoder().decode(ClientRegistrationResponse.self, from: regData)
            let clientSecret = try #require(client.clientSecret)

            let verifier = PKCE.generateCodeVerifier()
            let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

            // Get consent page
            let consentResponse = await handler.handleAuthorizationRequest(queryParams: [
                "response_type": "code",
                "client_id": client.clientId,
                "redirect_uri": "http://localhost/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256"
            ])
            let csrfToken = try #require(OAuthHTTPHandlerTests.extractCSRFToken(from: consentResponse.body))

            // Submit consent
            let authResponse = await handler.handleConsentSubmission(formParams: [
                "action": "approve",
                "client_id": client.clientId,
                "redirect_uri": "http://localhost/callback",
                "csrf_token": csrfToken,
                "code_challenge": challenge,
                "code_challenge_method": "S256"
            ])
            let redirectLocation = try #require(authResponse.headers["Location"])
            let code = try #require(extractCodeFromRedirect(redirectLocation))

            let initialTokenBody = buildFormBody([
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost/callback",
                "client_id": client.clientId,
                "client_secret": clientSecret,
                "code_verifier": verifier
            ])

            let initialTokenResponse = await handler.handleTokenRequest(body: initialTokenBody, authHeader: nil)
            let initialData = Data(initialTokenResponse.body.utf8)
            let initialTokens = try JSONDecoder().decode(TokenResponse.self, from: initialData)
            let refreshToken = try #require(initialTokens.refreshToken)

            // Refresh
            let refreshBody = buildFormBody([
                "grant_type": "refresh_token",
                "refresh_token": refreshToken,
                "client_id": client.clientId,
                "client_secret": clientSecret
            ])

            let refreshResponse = await handler.handleTokenRequest(body: refreshBody, authHeader: nil)

            #expect(refreshResponse.statusCode == 200)
            #expect(refreshResponse.body.contains("access_token"))
        }
    }

    // MARK: - Token Validation Tests

    @Suite("Token Validation")
    struct TokenValidationTests {

        @Test("Validates bearer token")
        func validatesBearerToken() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            // Get a valid token
            let regBody = """
            {
                "client_name": "Validation Test",
                "redirect_uris": ["http://localhost/callback"],
                "token_endpoint_auth_method": "client_secret_post"
            }
            """
            let regResponse = await handler.handleRegistrationRequest(body: regBody)
            let regData = Data(regResponse.body.utf8)
            let client = try JSONDecoder().decode(ClientRegistrationResponse.self, from: regData)
            let clientSecret = try #require(client.clientSecret)

            let verifier = PKCE.generateCodeVerifier()
            let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

            // Get consent page
            let consentResponse = await handler.handleAuthorizationRequest(queryParams: [
                "response_type": "code",
                "client_id": client.clientId,
                "redirect_uri": "http://localhost/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "mcp:tools"
            ])
            let csrfToken = try #require(OAuthHTTPHandlerTests.extractCSRFToken(from: consentResponse.body))

            // Submit consent
            let authResponse = await handler.handleConsentSubmission(formParams: [
                "action": "approve",
                "client_id": client.clientId,
                "redirect_uri": "http://localhost/callback",
                "csrf_token": csrfToken,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "mcp:tools"
            ])
            let redirectLocation = try #require(authResponse.headers["Location"])
            let code = try #require(extractCodeFromRedirect(redirectLocation))

            let tokenBody = buildFormBody([
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost/callback",
                "client_id": client.clientId,
                "client_secret": clientSecret,
                "code_verifier": verifier
            ])

            let tokenResponse = await handler.handleTokenRequest(body: tokenBody, authHeader: nil)
            let tokenData = Data(tokenResponse.body.utf8)
            let tokens = try JSONDecoder().decode(TokenResponse.self, from: tokenData)

            // Validate the token
            let result = await handler.validateBearerToken(authHeader: "Bearer \(tokens.accessToken)")

            #expect(result.isValid)
            if case .valid(let token) = result {
                #expect(token.clientId == client.clientId)
                #expect(token.scope == "mcp:tools")
            }
        }

        @Test("Rejects invalid bearer token")
        func rejectsInvalidBearerToken() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let result = await handler.validateBearerToken(authHeader: "Bearer invalid_token")

            #expect(result.isValid == false)
        }

        @Test("Rejects missing authorization header")
        func rejectsMissingAuthHeader() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let result = await handler.validateBearerToken(authHeader: nil)

            #expect(result.isValid == false)
        }

        @Test("Rejects non-bearer authorization")
        func rejectsNonBearerAuth() async throws {
            let handler = try await OAuthHTTPHandlerTests.makeTestHandler()

            let result = await handler.validateBearerToken(authHeader: "Basic dXNlcjpwYXNz")

            #expect(result.isValid == false)
        }
    }

    // MARK: - Helpers

    static func extractCodeFromRedirect(_ location: String) -> String? {
        guard let components = URLComponents(string: location),
              let code = components.queryItems?.first(where: { $0.name == "code" })?.value else {
            return nil
        }
        return code
    }

    static func extractCSRFToken(from html: String) -> String? {
        // Look for: name="csrf_token" value="..."
        guard let range = html.range(of: "name=\"csrf_token\" value=\"") else {
            return nil
        }
        let start = range.upperBound
        guard let endRange = html[start...].range(of: "\"") else {
            return nil
        }
        return String(html[start..<endRange.lowerBound])
    }

    static func buildFormBody(_ params: [String: String]) -> String {
        params.map { key, value in
            let encodedKey = key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? key
            let encodedValue = value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
            return "\(encodedKey)=\(encodedValue)"
        }.joined(separator: "&")
    }
}

// Make helpers accessible to nested types
private func extractCodeFromRedirect(_ location: String) -> String? {
    OAuthHTTPHandlerTests.extractCodeFromRedirect(location)
}

private func buildFormBody(_ params: [String: String]) -> String {
    OAuthHTTPHandlerTests.buildFormBody(params)
}
