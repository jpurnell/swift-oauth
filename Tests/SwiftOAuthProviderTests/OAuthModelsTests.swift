import Testing
import Foundation
@testable import SwiftOAuthProvider
import SwiftOAuthCore

/// Tests for OAuth 2.0 model types
/// Reference: RFC 6749, RFC 7591
@Suite("OAuth Models")
struct OAuthModelsTests {

    // MARK: - RegisteredClient Tests

    @Suite("RegisteredClient")
    struct RegisteredClientTests {

        @Test("Initializes with all required fields")
        func initializesWithRequiredFields() {
            let client = RegisteredClient(
                clientId: "test-client-123",
                clientSecret: "secret-456",
                clientName: "Test Application",
                redirectUris: ["http://localhost:8080/callback"],
                grantTypes: ["authorization_code", "refresh_token"],
                tokenEndpointAuthMethod: "client_secret_basic",
                registrationDate: Date()
            )

            #expect(client.clientId == "test-client-123")
            #expect(client.clientSecret == "secret-456")
            #expect(client.clientName == "Test Application")
            #expect(client.redirectUris == ["http://localhost:8080/callback"])
            #expect(client.grantTypes == ["authorization_code", "refresh_token"])
            #expect(client.tokenEndpointAuthMethod == "client_secret_basic")
        }

        @Test("Supports public clients with nil secret")
        func supportsPublicClients() {
            let client = RegisteredClient(
                clientId: "public-client",
                clientSecret: nil,
                clientName: "Public App",
                redirectUris: ["myapp://callback"],
                grantTypes: ["authorization_code"],
                tokenEndpointAuthMethod: "none",
                registrationDate: Date()
            )

            #expect(client.clientSecret == nil)
            #expect(client.tokenEndpointAuthMethod == "none")
        }

        @Test("Encodes to JSON correctly")
        func encodesToJSON() throws {
            let date = Date(timeIntervalSince1970: 1710432000)
            let client = RegisteredClient(
                clientId: "test-client",
                clientSecret: "secret",
                clientName: "Test App",
                redirectUris: ["http://localhost/callback"],
                grantTypes: ["authorization_code"],
                tokenEndpointAuthMethod: "client_secret_basic",
                registrationDate: date
            )

            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .secondsSince1970
            let data = try encoder.encode(client)
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]

            #expect(json?["client_id"] as? String == "test-client")
            #expect(json?["client_name"] as? String == "Test App")
        }

        @Test("Decodes from JSON correctly")
        func decodesFromJSON() throws {
            let json = """
            {
                "client_id": "decoded-client",
                "client_secret": "decoded-secret",
                "client_name": "Decoded App",
                "redirect_uris": ["http://example.com/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "client_secret_post",
                "registration_date": 1710432000
            }
            """

            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .secondsSince1970
            let client = try decoder.decode(RegisteredClient.self, from: json.data(using: .utf8)!)

            #expect(client.clientId == "decoded-client")
            #expect(client.clientSecret == "decoded-secret")
            #expect(client.redirectUris.count == 1)
        }

        @Test("Is Sendable")
        func isSendable() async {
            let client = RegisteredClient(
                clientId: "sendable-test",
                clientSecret: nil,
                clientName: "Sendable App",
                redirectUris: [],
                grantTypes: [],
                tokenEndpointAuthMethod: "none",
                registrationDate: Date()
            )

            // Verify can be sent across isolation boundaries
            let task = Task { @Sendable in
                return client.clientId
            }
            let result = await task.value
            #expect(result == "sendable-test")
        }
    }

    // MARK: - ClientRegistrationRequest Tests

    @Suite("ClientRegistrationRequest")
    struct ClientRegistrationRequestTests {

        @Test("Initializes with required fields")
        func initializesWithRequiredFields() {
            let request = ClientRegistrationRequest(
                clientName: "New Client",
                redirectUris: ["http://localhost:3000/callback"],
                grantTypes: ["authorization_code"],
                tokenEndpointAuthMethod: "client_secret_basic",
                scope: "mcp:tools mcp:resources"
            )

            #expect(request.clientName == "New Client")
            #expect(request.redirectUris.count == 1)
            #expect(request.scope == "mcp:tools mcp:resources")
        }

        @Test("Decodes from JSON with snake_case keys")
        func decodesFromSnakeCaseJSON() throws {
            let json = """
            {
                "client_name": "JSON Client",
                "redirect_uris": ["http://example.com/cb"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "none",
                "scope": "mcp:tools"
            }
            """

            let request = try JSONDecoder().decode(
                ClientRegistrationRequest.self,
                from: json.data(using: .utf8)!
            )

            #expect(request.clientName == "JSON Client")
            #expect(request.tokenEndpointAuthMethod == "none")
        }

        @Test("Has default values for optional fields")
        func hasDefaultValues() {
            let request = ClientRegistrationRequest(
                clientName: "Minimal Client",
                redirectUris: ["http://localhost/callback"]
            )

            #expect(request.grantTypes == ["authorization_code"])
            #expect(request.tokenEndpointAuthMethod == "client_secret_basic")
            #expect(request.scope == nil)
        }
    }

    // MARK: - TokenResponse Tests

    @Suite("TokenResponse")
    struct TokenResponseTests {

        @Test("Initializes with all fields")
        func initializesWithAllFields() {
            let response = TokenResponse(
                accessToken: "access_token_123",
                tokenType: "Bearer",
                expiresIn: 86400,
                refreshToken: "refresh_token_456",
                scope: "mcp:tools mcp:resources"
            )

            #expect(response.accessToken == "access_token_123")
            #expect(response.tokenType == "Bearer")
            #expect(response.expiresIn == 86400)
            #expect(response.refreshToken == "refresh_token_456")
            #expect(response.scope == "mcp:tools mcp:resources")
        }

        @Test("Encodes to RFC 6749 compliant JSON")
        func encodesToRFCCompliantJSON() throws {
            let response = TokenResponse(
                accessToken: "abc123",
                tokenType: "Bearer",
                expiresIn: 3600,
                refreshToken: "xyz789",
                scope: "read write"
            )

            let encoder = JSONEncoder()
            let data = try encoder.encode(response)
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]

            // RFC 6749 §5.1 requires snake_case
            #expect(json?["access_token"] as? String == "abc123")
            #expect(json?["token_type"] as? String == "Bearer")
            #expect(json?["expires_in"] as? Int == 3600)
            #expect(json?["refresh_token"] as? String == "xyz789")
        }

        @Test("Supports optional refresh token")
        func supportsOptionalRefreshToken() {
            let response = TokenResponse(
                accessToken: "access_only",
                tokenType: "Bearer",
                expiresIn: 3600,
                refreshToken: nil,
                scope: nil
            )

            #expect(response.refreshToken == nil)
            #expect(response.scope == nil)
        }
    }

    // MARK: - TokenValidationResult Tests

    @Suite("TokenValidationResult")
    struct TokenValidationResultTests {

        @Test("Valid result contains client and scope")
        func validResultContainsInfo() {
            let result = TokenValidationResult.valid(
                clientId: "client-123",
                scope: "mcp:tools"
            )

            if case .valid(let clientId, let scope) = result {
                #expect(clientId == "client-123")
                #expect(scope == "mcp:tools")
            } else {
                Issue.record("Expected valid result")
            }
        }

        @Test("Invalid result contains reason")
        func invalidResultContainsReason() {
            let result = TokenValidationResult.invalid(reason: "Token expired")

            if case .invalid(let reason) = result {
                #expect(reason == "Token expired")
            } else {
                Issue.record("Expected invalid result")
            }
        }

        @Test("Provides isValid convenience property")
        func providesIsValidProperty() {
            let valid = TokenValidationResult.valid(clientId: "c", scope: nil)
            let invalid = TokenValidationResult.invalid(reason: "bad")

            #expect(valid.isValid == true)
            #expect(invalid.isValid == false)
        }
    }

    // MARK: - OAuthError Tests

    @Suite("OAuthError")
    struct OAuthErrorTests {

        @Test("Has RFC 6749 compliant error codes")
        func hasRFCCompliantErrorCodes() {
            // RFC 6749 §5.2 defines these error codes
            #expect(OAuthError.invalidRequest(nil).code == "invalid_request")
            #expect(OAuthError.invalidClient(nil).code == "invalid_client")
            #expect(OAuthError.invalidGrant(nil).code == "invalid_grant")
            #expect(OAuthError.unauthorizedClient(nil).code == "unauthorized_client")
            #expect(OAuthError.unsupportedGrantType(nil).code == "unsupported_grant_type")
            #expect(OAuthError.invalidScope(nil).code == "invalid_scope")
        }

        /// `detail` is what the server chose to say; `standardDescription` is what the
        /// code means per RFC 6749 §5.2. An error raised without a detail still has to
        /// render as something a reader can act on, which is what gets encoded.
        @Test("Provides human-readable descriptions")
        func providesDescriptions() {
            let bare = OAuthError.invalidGrant(nil)
            #expect(bare.detail == nil)
            #expect(bare.standardDescription.isEmpty == false)

            let detailed = OAuthError.invalidGrant("this refresh token was already rotated")
            #expect(detailed.detail == "this refresh token was already rotated")
        }

        @Test("Encodes to JSON error response")
        func encodesToJSONErrorResponse() throws {
            let error = OAuthError.invalidRequest(nil)

            let encoder = JSONEncoder()
            let data = try encoder.encode(error)
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]

            #expect(json?["error"] as? String == "invalid_request")
            let errorDesc = try #require(json?["error_description"] as? String)
            #expect(errorDesc.count >= 5)
        }
    }

    // MARK: - AuthorizationCode Tests

    @Suite("AuthorizationCode")
    struct AuthorizationCodeTests {

        @Test("Initializes with all fields")
        func initializesWithAllFields() {
            let code = AuthorizationCode(
                code: "auth_code_abc",
                clientId: "client-123",
                redirectUri: "http://localhost/callback",
                scope: "mcp:tools",
                codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                codeChallengeMethod: "S256",
                expiresAt: Date().addingTimeInterval(600),
                createdAt: Date()
            )

            #expect(code.code == "auth_code_abc")
            #expect(code.clientId == "client-123")
            #expect(code.codeChallengeMethod == "S256")
        }

        @Test("Detects expired codes")
        func detectsExpiredCodes() {
            let expiredCode = AuthorizationCode(
                code: "expired",
                clientId: "client",
                redirectUri: "http://localhost",
                scope: nil,
                codeChallenge: nil,
                codeChallengeMethod: nil,
                expiresAt: Date().addingTimeInterval(-60), // 1 minute ago
                createdAt: Date().addingTimeInterval(-120)
            )

            #expect(expiredCode.isExpired == true)

            let validCode = AuthorizationCode(
                code: "valid",
                clientId: "client",
                redirectUri: "http://localhost",
                scope: nil,
                codeChallenge: nil,
                codeChallengeMethod: nil,
                expiresAt: Date().addingTimeInterval(600), // 10 minutes from now
                createdAt: Date()
            )

            #expect(validCode.isExpired == false)
        }
    }
}
