import Testing
import Foundation
@testable import SwiftOAuthProvider
import SwiftOAuthCore

/// Tests for OAuth 2.0 Server implementation
@Suite("OAuth Server")
struct OAuthServerTests {

    // MARK: - Test Helpers

    static func makeTestServer() async throws -> OAuthServer {
        let storage = try OAuthStorage(path: ":memory:")
        return await OAuthServer(storage: storage, issuer: "https://example.com")
    }

    // MARK: - Server Metadata Tests

    @Suite("Server Metadata")
    struct ServerMetadataTests {

        @Test("Returns RFC 8414 compliant metadata")
        func returnsRFC8414Metadata() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let metadata = await server.getMetadata()

            #expect(metadata.issuer == "https://example.com")
            #expect(metadata.authorizationEndpoint == "https://example.com/authorize")
            #expect(metadata.tokenEndpoint == "https://example.com/token")
            #expect(metadata.registrationEndpoint == "https://example.com/register")
        }

        @Test("Metadata includes supported features")
        func metadataIncludesSupportedFeatures() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let metadata = await server.getMetadata()

            #expect(metadata.responseTypesSupported.contains("code"))
            #expect(metadata.grantTypesSupported.contains("authorization_code"))
            #expect(metadata.grantTypesSupported.contains("refresh_token"))
            #expect(metadata.codeChallengeMethodsSupported.contains("S256"))
            #expect(metadata.tokenEndpointAuthMethodsSupported.contains("client_secret_basic"))
            #expect(metadata.tokenEndpointAuthMethodsSupported.contains("client_secret_post"))
            #expect(metadata.tokenEndpointAuthMethodsSupported.contains("none"))
        }

        @Test("Metadata includes MCP scopes")
        func metadataIncludesMCPScopes() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let metadata = await server.getMetadata()

            #expect(metadata.scopesSupported?.contains("mcp:tools") == true)
            #expect(metadata.scopesSupported?.contains("mcp:resources") == true)
            #expect(metadata.scopesSupported?.contains("mcp:prompts") == true)
        }
    }

    // MARK: - Client Registration Tests

    @Suite("Client Registration")
    struct ClientRegistrationTests {

        @Test("Registers new client")
        func registersNewClient() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let request = ClientRegistrationRequest(
                clientName: "Test Client",
                redirectUris: ["http://localhost:8080/callback"]
            )

            let response = try await server.registerClient(request)

            #expect(response.clientId.count >= 8)
            let secret = try #require(response.clientSecret)
            #expect(secret.count >= 8)
            #expect(response.clientName == "Test Client")
            #expect(response.redirectUris == ["http://localhost:8080/callback"])
        }

        @Test("Generates unique client IDs")
        func generatesUniqueClientIds() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            var clientIds = Set<String>()
            for i in 0..<10 {
                let request = ClientRegistrationRequest(
                    clientName: "Client \(i)",
                    redirectUris: ["http://localhost/callback"]
                )
                let response = try await server.registerClient(request)
                #expect(!clientIds.contains(response.clientId))
                clientIds.insert(response.clientId)
            }
        }

        @Test("Respects requested grant types")
        func respectsRequestedGrantTypes() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let request = ClientRegistrationRequest(
                clientName: "Custom Grants Client",
                redirectUris: ["http://localhost/callback"],
                grantTypes: ["authorization_code", "refresh_token"]
            )

            let response = try await server.registerClient(request)

            #expect(response.grantTypes.contains("authorization_code"))
            #expect(response.grantTypes.contains("refresh_token"))
        }

        @Test("Supports public clients")
        func supportsPublicClients() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let request = ClientRegistrationRequest(
                clientName: "Public Client",
                redirectUris: ["myapp://callback"],
                tokenEndpointAuthMethod: "none"
            )

            let response = try await server.registerClient(request)

            #expect(response.clientSecret == nil)
            #expect(response.tokenEndpointAuthMethod == "none")
        }

        @Test("Validates redirect URIs")
        func validatesRedirectUris() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let request = ClientRegistrationRequest(
                clientName: "Invalid Client",
                redirectUris: [] // Empty is invalid
            )

            do {
                _ = try await server.registerClient(request)
                Issue.record("Should have thrown error for empty redirect URIs")
            } catch {
                #expect(true, "Correctly rejected empty redirect URIs")
            }
        }
    }

    // MARK: - Authorization Request Tests

    @Suite("Authorization Request")
    struct AuthorizationRequestTests {

        @Test("Creates authorization code for valid request")
        func createsAuthCodeForValidRequest() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            // Register client first
            let clientRequest = ClientRegistrationRequest(
                clientName: "Auth Test Client",
                redirectUris: ["http://localhost/callback"]
            )
            let client = try await server.registerClient(clientRequest)

            // Create authorization request
            let authRequest = AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: "mcp:tools",
                state: "random_state_123",
                codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                codeChallengeMethod: "S256"
            )

            let response = try await server.handleAuthorizationRequest(authRequest)

            #expect(!response.code.isEmpty)
            #expect(response.state == "random_state_123")
        }

        /// `plain` means the code challenge *is* the verifier, sent in the clear in the
        /// authorization request. Anyone positioned to intercept the authorization code has
        /// therefore also seen what redeems it — which is the one attack PKCE exists to stop.
        /// MCP's authorization spec requires S256, and this server refuses anything else.
        ///
        /// Refused at the authorization endpoint rather than the token endpoint: by then a
        /// code has been issued and the client is mid-flow.
        @Test("Refuses the plain PKCE method")
        func refusesPlainChallengeMethod() async throws {
            let server = try await OAuthServerTests.makeTestServer()
            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Plain PKCE Client",
                redirectUris: ["http://localhost/callback"]))

            let verifier = PKCE.generateCodeVerifier()
            let authRequest = AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: "mcp:tools",
                state: "state",
                // Under `plain` the challenge is the verifier verbatim.
                codeChallenge: verifier,
                codeChallengeMethod: "plain")

            do {
                _ = try await server.handleAuthorizationRequest(authRequest)
                Issue.record("a plain PKCE challenge was accepted")
            } catch let error as OAuthError {
                #expect(error.code == "invalid_request")
            }
        }

        /// An unrecognised method must not fall through to being treated as S256 — that
        /// would let any future weak method through by simply not being named here.
        @Test("Refuses an unrecognised PKCE method")
        func refusesUnknownChallengeMethod() async throws {
            let server = try await OAuthServerTests.makeTestServer()
            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Odd PKCE Client",
                redirectUris: ["http://localhost/callback"]))

            for method in ["S1", "sha256", "s256", "PLAIN", ""] {
                let request = AuthorizationRequest(
                    responseType: "code",
                    clientId: client.clientId,
                    redirectUri: "http://localhost/callback",
                    scope: "mcp:tools",
                    state: "state",
                    codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    codeChallengeMethod: method)

                await #expect(throws: OAuthError.self,
                              "method \"\(method)\" was accepted") {
                    _ = try await server.handleAuthorizationRequest(request)
                }
            }
        }

        /// The metadata must not advertise what the endpoint refuses; a client that trusts
        /// it would build a flow that fails at authorization.
        @Test("Metadata advertises only S256")
        func metadataAdvertisesOnlyS256() async throws {
            let server = try await OAuthServerTests.makeTestServer()
            let metadata = await server.getMetadata()
            #expect(metadata.codeChallengeMethodsSupported == ["S256"])
        }

        @Test("Rejects unknown client")
        func rejectsUnknownClient() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let authRequest = AuthorizationRequest(
                responseType: "code",
                clientId: "unknown-client",
                redirectUri: "http://localhost/callback",
                scope: nil,
                state: nil,
                codeChallenge: nil,
                codeChallengeMethod: nil
            )

            do {
                _ = try await server.handleAuthorizationRequest(authRequest)
                Issue.record("Should have thrown error for unknown client")
            } catch let error as OAuthError {
                #expect(error == .invalidClient(nil))
            }
        }

        @Test("Rejects mismatched redirect URI")
        func rejectsMismatchedRedirectUri() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let clientRequest = ClientRegistrationRequest(
                clientName: "Redirect Test",
                redirectUris: ["http://localhost/callback"]
            )
            let client = try await server.registerClient(clientRequest)

            let authRequest = AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "https://attacker.example/callback", // Wrong URI
                scope: nil,
                state: nil,
                codeChallenge: nil,
                codeChallengeMethod: nil
            )

            do {
                _ = try await server.handleAuthorizationRequest(authRequest)
                Issue.record("Should have thrown error for mismatched redirect URI")
            } catch let error as OAuthError {
                #expect(error == .invalidRequest(nil))
            }
        }

        @Test("Rejects unsupported response type")
        func rejectsUnsupportedResponseType() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let clientRequest = ClientRegistrationRequest(
                clientName: "Response Type Test",
                redirectUris: ["http://localhost/callback"]
            )
            let client = try await server.registerClient(clientRequest)

            let authRequest = AuthorizationRequest(
                responseType: "token", // Implicit flow not supported
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: nil,
                state: nil,
                codeChallenge: nil,
                codeChallengeMethod: nil
            )

            do {
                _ = try await server.handleAuthorizationRequest(authRequest)
                Issue.record("Should have thrown error for unsupported response type")
            } catch let error as OAuthError {
                #expect(error == .invalidRequest(nil))
            }
        }
    }

    // MARK: - Token Exchange Tests

    @Suite("Token Exchange")
    struct TokenExchangeTests {

        @Test("Exchanges authorization code for tokens")
        func exchangesCodeForTokens() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            // Setup: register client with refresh_token grant and get auth code
            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Token Test",
                redirectUris: ["http://localhost/callback"],
                grantTypes: ["authorization_code", "refresh_token"]
            ))

            let verifier = PKCE.generateCodeVerifier()
            let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

            let authResponse = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: "mcp:tools",
                state: nil,
                codeChallenge: challenge,
                codeChallengeMethod: "S256"
            ))

            // Exchange code for tokens
            let tokenRequest = TokenRequest(
                grantType: "authorization_code",
                code: authResponse.code,
                redirectUri: "http://localhost/callback",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: verifier,
                refreshToken: nil
            )

            let tokenResponse = try await server.handleTokenRequest(tokenRequest)

            #expect(tokenResponse.accessToken.hasPrefix("mcp_at_"))
            #expect(tokenResponse.refreshToken?.hasPrefix("mcp_rt_") == true)
            #expect(tokenResponse.tokenType == "Bearer")
            #expect(tokenResponse.expiresIn > 0)
            #expect(tokenResponse.scope == "mcp:tools")
        }

        @Test("Validates PKCE code verifier")
        func validatesPKCECodeVerifier() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "PKCE Test",
                redirectUris: ["http://localhost/callback"]
            ))

            let verifier = PKCE.generateCodeVerifier()
            let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

            let authResponse = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: nil,
                state: nil,
                codeChallenge: challenge,
                codeChallengeMethod: "S256"
            ))

            // Try with wrong verifier
            let wrongVerifier = PKCE.generateCodeVerifier()
            let tokenRequest = TokenRequest(
                grantType: "authorization_code",
                code: authResponse.code,
                redirectUri: "http://localhost/callback",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: wrongVerifier,
                refreshToken: nil
            )

            do {
                _ = try await server.handleTokenRequest(tokenRequest)
                Issue.record("Should have thrown error for wrong PKCE verifier")
            } catch let error as OAuthError {
                #expect(error == .invalidGrant(nil))
            }
        }

        @Test("Authorization code is single-use")
        func authCodeIsSingleUse() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Single Use Test",
                redirectUris: ["http://localhost/callback"]
            ))

            let verifier = PKCE.generateCodeVerifier()
            let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

            let authResponse = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: nil,
                state: nil,
                codeChallenge: challenge,
                codeChallengeMethod: "S256"
            ))

            let tokenRequest = TokenRequest(
                grantType: "authorization_code",
                code: authResponse.code,
                redirectUri: "http://localhost/callback",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: verifier,
                refreshToken: nil
            )

            // First use should succeed
            _ = try await server.handleTokenRequest(tokenRequest)

            // Second use should fail
            do {
                _ = try await server.handleTokenRequest(tokenRequest)
                Issue.record("Should have thrown error for reused auth code")
            } catch let error as OAuthError {
                #expect(error == .invalidGrant(nil))
            }
        }

        @Test("Rejects expired authorization code")
        func rejectsExpiredAuthCode() async throws {
            let server = try await OAuthServerTests.makeTestServer(codeLifetime: -60) // Expired immediately

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Expired Code Test",
                redirectUris: ["http://localhost/callback"]
            ))

            let authResponse = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: nil,
                state: nil,
                codeChallenge: nil,
                codeChallengeMethod: nil
            ))

            let tokenRequest = TokenRequest(
                grantType: "authorization_code",
                code: authResponse.code,
                redirectUri: "http://localhost/callback",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: nil,
                refreshToken: nil
            )

            do {
                _ = try await server.handleTokenRequest(tokenRequest)
                Issue.record("Should have thrown error for expired auth code")
            } catch let error as OAuthError {
                #expect(error == .invalidGrant(nil))
            }
        }
    }

    // MARK: - Refresh Token Tests

    @Suite("Refresh Token")
    struct RefreshTokenTests {

        @Test("Refreshes access token")
        func refreshesAccessToken() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            // Setup: get initial tokens
            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Refresh Test",
                redirectUris: ["http://localhost/callback"],
                grantTypes: ["authorization_code", "refresh_token"]
            ))

            let verifier = PKCE.generateCodeVerifier()
            let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

            let authResponse = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: "mcp:tools",
                state: nil,
                codeChallenge: challenge,
                codeChallengeMethod: "S256"
            ))

            let initialTokens = try await server.handleTokenRequest(TokenRequest(
                grantType: "authorization_code",
                code: authResponse.code,
                redirectUri: "http://localhost/callback",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: verifier,
                refreshToken: nil
            ))

            // Refresh the tokens
            let refreshRequest = TokenRequest(
                grantType: "refresh_token",
                code: nil,
                redirectUri: nil,
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: nil,
                refreshToken: initialTokens.refreshToken
            )

            let newTokens = try await server.handleTokenRequest(refreshRequest)

            #expect(newTokens.accessToken != initialTokens.accessToken)
            #expect(newTokens.accessToken.hasPrefix("mcp_at_"))
            #expect(newTokens.scope == "mcp:tools")
        }

        @Test("Rejects invalid refresh token")
        func rejectsInvalidRefreshToken() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Invalid Refresh Test",
                redirectUris: ["http://localhost/callback"],
                grantTypes: ["authorization_code", "refresh_token"]
            ))

            let refreshRequest = TokenRequest(
                grantType: "refresh_token",
                code: nil,
                redirectUri: nil,
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: nil,
                refreshToken: "invalid_refresh_token"
            )

            do {
                _ = try await server.handleTokenRequest(refreshRequest)
                Issue.record("Should have thrown error for invalid refresh token")
            } catch let error as OAuthError {
                #expect(error == .invalidGrant(nil))
            }
        }

        @Test("Rejects refresh without grant type")
        func rejectsRefreshWithoutGrantType() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            // Register client WITHOUT refresh_token grant
            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "No Refresh Client",
                redirectUris: ["http://localhost/callback"],
                grantTypes: ["authorization_code"] // No refresh_token
            ))

            // Try to refresh with a fake token - should fail because client
            // doesn't have refresh_token grant type
            let refreshRequest = TokenRequest(
                grantType: "refresh_token",
                code: nil,
                redirectUri: nil,
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: nil,
                refreshToken: "mcp_rt_fake_token_for_testing_grant_type"
            )

            do {
                _ = try await server.handleTokenRequest(refreshRequest)
                Issue.record("Should have thrown error for unauthorized grant type")
            } catch let error as OAuthError {
                #expect(error == .unauthorizedClient(nil))
            }
        }
    }

    // MARK: - Token Validation Tests

    @Suite("Token Validation")
    struct TokenValidationTests {

        @Test("Validates issued access token")
        func validatesIssuedToken() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            // Get a token
            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Validation Test",
                redirectUris: ["http://localhost/callback"]
            ))

            let verifier = PKCE.generateCodeVerifier()
            let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

            let authResponse = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: "mcp:tools",
                state: nil,
                codeChallenge: challenge,
                codeChallengeMethod: "S256"
            ))

            let tokens = try await server.handleTokenRequest(TokenRequest(
                grantType: "authorization_code",
                code: authResponse.code,
                redirectUri: "http://localhost/callback",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: verifier,
                refreshToken: nil
            ))

            // Validate the token
            let result = try await server.validateAccessToken(tokens.accessToken)

            #expect(result.isValid)
            if case .valid(let clientId, let scope) = result {
                #expect(clientId == client.clientId)
                #expect(scope == "mcp:tools")
            }
        }

        @Test("Rejects revoked token")
        func rejectsRevokedToken() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Revocation Test",
                redirectUris: ["http://localhost/callback"]
            ))

            let verifier = PKCE.generateCodeVerifier()
            let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

            let authResponse = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: nil,
                state: nil,
                codeChallenge: challenge,
                codeChallengeMethod: "S256"
            ))

            let tokens = try await server.handleTokenRequest(TokenRequest(
                grantType: "authorization_code",
                code: authResponse.code,
                redirectUri: "http://localhost/callback",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: verifier,
                refreshToken: nil
            ))

            // Revoke the token
            try await server.revokeToken(tokens.accessToken)

            // Validate should fail
            let result = try await server.validateAccessToken(tokens.accessToken)
            #expect(result.isValid == false)
        }
    }

    // MARK: - Scope Leniency Tests

    @Suite("Scope Leniency")
    struct ScopeLeniencyTests {

        @Test("Accepts nil scope and defaults to all MCP scopes")
        func acceptsNilScopeWithDefault() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Nil Scope Client",
                redirectUris: ["http://localhost/callback"],
                grantTypes: ["authorization_code", "refresh_token"]
            ))

            let verifier = PKCE.generateCodeVerifier()
            let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

            // Auth request with nil scope should succeed
            let authResponse = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: nil,
                state: nil,
                codeChallenge: challenge,
                codeChallengeMethod: "S256"
            ))

            #expect(!authResponse.code.isEmpty)

            // Exchange code and verify scope defaults to all MCP scopes
            let tokenResponse = try await server.handleTokenRequest(TokenRequest(
                grantType: "authorization_code",
                code: authResponse.code,
                redirectUri: "http://localhost/callback",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: verifier,
                refreshToken: nil
            ))

            let scope = try #require(tokenResponse.scope)
            let scopes = Set(scope.split(separator: " ").map(String.init))
            #expect(scopes.contains("mcp:tools"))
            #expect(scopes.contains("mcp:resources"))
            #expect(scopes.contains("mcp:prompts"))
        }

        @Test("Accepts empty scope and defaults to all MCP scopes")
        func acceptsEmptyScopeWithDefault() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Empty Scope Client",
                redirectUris: ["http://localhost/callback"],
                grantTypes: ["authorization_code", "refresh_token"]
            ))

            let verifier = PKCE.generateCodeVerifier()
            let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

            // Auth request with empty scope should succeed and default
            let authResponse = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: "",
                state: nil,
                codeChallenge: challenge,
                codeChallengeMethod: "S256"
            ))

            #expect(!authResponse.code.isEmpty)

            let tokenResponse = try await server.handleTokenRequest(TokenRequest(
                grantType: "authorization_code",
                code: authResponse.code,
                redirectUri: "http://localhost/callback",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: verifier,
                refreshToken: nil
            ))

            let scope = try #require(tokenResponse.scope)
            let scopes = Set(scope.split(separator: " ").map(String.init))
            #expect(scopes.contains("mcp:tools"))
            #expect(scopes.contains("mcp:resources"))
            #expect(scopes.contains("mcp:prompts"))
        }

        @Test("Accepts whitespace-only scope and defaults to all MCP scopes")
        func acceptsWhitespaceScopeWithDefault() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Whitespace Scope Client",
                redirectUris: ["http://localhost/callback"]
            ))

            // Auth request with whitespace-only scope should succeed
            let authResponse = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: "   ",
                state: nil,
                codeChallenge: nil,
                codeChallengeMethod: nil
            ))

            #expect(!authResponse.code.isEmpty)
        }

        @Test("Accepts unknown scopes without rejection")
        func acceptsUnknownScopes() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Unknown Scope Client",
                redirectUris: ["http://localhost/callback"],
                grantTypes: ["authorization_code", "refresh_token"]
            ))

            let verifier = PKCE.generateCodeVerifier()
            let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

            // Auth request with non-MCP scopes should succeed (not throw invalidScope)
            let authResponse = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: "openid profile",
                state: nil,
                codeChallenge: challenge,
                codeChallengeMethod: "S256"
            ))

            #expect(!authResponse.code.isEmpty)

            let tokenResponse = try await server.handleTokenRequest(TokenRequest(
                grantType: "authorization_code",
                code: authResponse.code,
                redirectUri: "http://localhost/callback",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: verifier,
                refreshToken: nil
            ))

            #expect(tokenResponse.scope == "openid profile")
        }

        @Test("Accepts mixed known and unknown scopes")
        func acceptsMixedScopes() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Mixed Scope Client",
                redirectUris: ["http://localhost/callback"],
                grantTypes: ["authorization_code", "refresh_token"]
            ))

            let verifier = PKCE.generateCodeVerifier()
            let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

            let authResponse = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: "mcp:tools openid",
                state: nil,
                codeChallenge: challenge,
                codeChallengeMethod: "S256"
            ))

            #expect(!authResponse.code.isEmpty)

            let tokenResponse = try await server.handleTokenRequest(TokenRequest(
                grantType: "authorization_code",
                code: authResponse.code,
                redirectUri: "http://localhost/callback",
                clientId: client.clientId,
                clientSecret: client.clientSecret,
                codeVerifier: verifier,
                refreshToken: nil
            ))

            #expect(tokenResponse.scope == "mcp:tools openid")
        }

        @Test("Valid MCP scopes still work")
        func validMCPScopesStillWork() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Valid Scope Client",
                redirectUris: ["http://localhost/callback"]
            ))

            let authResponse = try await server.handleAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: "mcp:tools mcp:resources mcp:prompts",
                state: nil,
                codeChallenge: nil,
                codeChallengeMethod: nil
            ))

            #expect(!authResponse.code.isEmpty)
        }

        @Test("validateAuthorizationRequest also accepts unknown scopes")
        func validateAlsoAcceptsUnknownScopes() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Validate Scope Client",
                redirectUris: ["http://localhost/callback"]
            ))

            // validateAuthorizationRequest should not throw for unknown scopes
            let validatedClient = try await server.validateAuthorizationRequest(AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "http://localhost/callback",
                scope: "openid profile email",
                state: nil,
                codeChallenge: nil,
                codeChallengeMethod: nil
            ))

            #expect(validatedClient.clientId == client.clientId)
        }
    }

    // MARK: - Protected Resource Metadata Tests

    @Suite("Protected Resource Metadata")
    struct ProtectedResourceMetadataTests {

        @Test("Returns RFC 9728 compliant metadata")
        func returnsRFC9728Metadata() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let metadata = await server.getProtectedResourceMetadata()

            #expect(metadata.resource == "https://example.com")
            #expect(metadata.authorizationServers == ["https://example.com"])
            #expect(metadata.scopesSupported.contains("mcp:tools"))
            #expect(metadata.scopesSupported.contains("mcp:resources"))
            #expect(metadata.scopesSupported.contains("mcp:prompts"))
            #expect(metadata.bearerMethodsSupported.contains("header"))
        }
    }

    // MARK: - Client Authentication Tests

    @Suite("Client Authentication")
    struct ClientAuthenticationTests {

        @Test("Authenticates with client_secret_basic")
        func authenticatesWithBasic() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Basic Auth Client",
                redirectUris: ["http://localhost/callback"],
                tokenEndpointAuthMethod: "client_secret_basic"
            ))

            // Create auth header value
            let clientSecret = try #require(client.clientSecret)
            let credentials = "\(client.clientId):\(clientSecret)"
            let encoded = Data(credentials.utf8).base64EncodedString()
            let authHeader = "Basic \(encoded)"

            let isValid = try await server.authenticateClient(
                clientId: client.clientId,
                authHeader: authHeader,
                bodyClientSecret: nil
            )

            #expect(isValid)
        }

        @Test("Authenticates with client_secret_post")
        func authenticatesWithPost() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Post Auth Client",
                redirectUris: ["http://localhost/callback"],
                tokenEndpointAuthMethod: "client_secret_post"
            ))

            let isValid = try await server.authenticateClient(
                clientId: client.clientId,
                authHeader: nil,
                bodyClientSecret: client.clientSecret
            )

            #expect(isValid)
        }

        @Test("Authenticates public client")
        func authenticatesPublicClient() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Public Auth Client",
                redirectUris: ["myapp://callback"],
                tokenEndpointAuthMethod: "none"
            ))

            let isValid = try await server.authenticateClient(
                clientId: client.clientId,
                authHeader: nil,
                bodyClientSecret: nil
            )

            #expect(isValid)
        }

        @Test("Rejects wrong secret")
        func rejectsWrongSecret() async throws {
            let server = try await OAuthServerTests.makeTestServer()

            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Wrong Secret Client",
                redirectUris: ["http://localhost/callback"],
                tokenEndpointAuthMethod: "client_secret_post"
            ))

            let isValid = try await server.authenticateClient(
                clientId: client.clientId,
                authHeader: nil,
                bodyClientSecret: "wrong_secret"
            )

            #expect(isValid == false)
        }
    }
}

// MARK: - Test Helper Extension

extension OAuthServerTests {
    static func makeTestServer(codeLifetime: TimeInterval = 600) async throws -> OAuthServer {
        let storage = try OAuthStorage(path: ":memory:")
        return await OAuthServer(
            storage: storage,
            issuer: "https://example.com",
            authorizationCodeLifetime: codeLifetime
        )
    }
}

/// The invariant that made excluding `client_credentials` from ``GrantType``
/// look necessary — and which survives without it.
///
/// A client-credentials token has no resource owner and no consent step. A
/// provider issuing one would hand out access with no user involved, which is
/// the arrangement OAuth exists to make deliberate. Making the grant
/// unconstructible looked like it prevented that, but the protection never came
/// from the enum: ``OAuthServer/handleTokenRequest(_:)`` dispatches on the raw
/// wire string and rejects anything it does not implement. These tests pin that,
/// so the client half can request the grant from third parties while the
/// provider half still refuses to issue it.
@Suite("Provider refuses client credentials")
struct ProviderRejectsClientCredentials {

    @Test("A client_credentials token request is rejected")
    func rejectsClientCredentialsGrant() async throws {
        let server = try await OAuthServerTests.makeTestServer()
        do {
            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "CC Test",
                redirectUris: ["http://localhost/callback"],
                grantTypes: ["authorization_code", "refresh_token"]
            ))
            let request = TokenRequest(
                grantType: GrantType.clientCredentials.rawValue,
                code: nil, redirectUri: nil,
                clientId: client.clientId, clientSecret: client.clientSecret,
                codeVerifier: nil, refreshToken: nil
            )
            await #expect(throws: OAuthError.unsupportedGrantType(nil)) {
                _ = try await server.handleTokenRequest(request)
            }
        }
    }

    /// Still true of the grants OAuth 2.1 removed, which remain unconstructible.
    @Test("Removed grants are rejected too", arguments: ["password", "implicit"])
    func rejectsRemovedGrants(grant: String) async throws {
        let server = try await OAuthServerTests.makeTestServer()
        do {
            let client = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Removed Test",
                redirectUris: ["http://localhost/callback"],
                grantTypes: ["authorization_code"]
            ))
            let request = TokenRequest(
                grantType: grant, code: nil, redirectUri: nil,
                clientId: client.clientId, clientSecret: client.clientSecret,
                codeVerifier: nil, refreshToken: nil
            )
            await #expect(throws: OAuthError.unsupportedGrantType(nil)) {
                _ = try await server.handleTokenRequest(request)
            }
        }
    }
}
