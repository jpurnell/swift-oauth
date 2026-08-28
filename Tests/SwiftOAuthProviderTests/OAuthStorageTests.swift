import Testing
import Foundation
@testable import SwiftOAuthProvider
import SwiftOAuthCore

/// Tests for OAuth 2.0 SQLite storage layer
@Suite("OAuth Storage")
struct OAuthStorageTests {

    // MARK: - Test Helpers

    /// Creates an in-memory storage instance for testing
    static func makeTestStorage() throws -> OAuthStorage {
        try OAuthStorage(path: ":memory:")
    }

    // MARK: - Initialization Tests

    @Suite("Initialization")
    struct InitializationTests {

        @Test("Creates in-memory database")
        func createsInMemoryDatabase() throws {
            let storage = try OAuthStorageTests.makeTestStorage()
            #expect(true, "Storage created successfully: \(type(of: storage))")
        }

        @Test("Creates file-based database")
        func createsFileBasedDatabase() throws {
            let tempURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("test_oauth_\(UUID().uuidString).db")

            defer { try? FileManager.default.removeItem(at: tempURL) }

            let storage = try OAuthStorage(path: tempURL.path)
            #expect(type(of: storage) == OAuthStorage.self)
            #expect(try tempURL.checkResourceIsReachable())
        }

        @Test("Creates required tables")
        func createsRequiredTables() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            // Tables should exist after initialization
            let tables = try await storage.listTables()
            #expect(tables.contains("clients"))
            #expect(tables.contains("authorization_codes"))
            #expect(tables.contains("access_tokens"))
            #expect(tables.contains("refresh_tokens"))
        }
    }

    // MARK: - Client Storage Tests

    @Suite("Client Storage")
    struct ClientStorageTests {

        @Test("Stores and retrieves client")
        func storesAndRetrievesClient() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let client = RegisteredClient(
                clientId: "test-client-123",
                clientSecret: "secret-456",
                clientName: "Test Application",
                redirectUris: ["http://localhost:8080/callback"],
                grantTypes: ["authorization_code", "refresh_token"],
                tokenEndpointAuthMethod: "client_secret_basic",
                registrationDate: Date()
            )

            try await storage.saveClient(client)
            let retrieved = try #require(await storage.getClient(clientId: "test-client-123"))

            #expect(retrieved.clientId == client.clientId)
            #expect(retrieved.clientSecret == client.clientSecret)
            #expect(retrieved.clientName == client.clientName)
            #expect(retrieved.redirectUris == client.redirectUris)
            #expect(retrieved.grantTypes == client.grantTypes)
        }

        @Test("Returns nil for non-existent client")
        func returnsNilForNonExistentClient() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let client = try await storage.getClient(clientId: "non-existent")
            #expect(client == nil)
        }

        @Test("Updates existing client")
        func updatesExistingClient() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let original = RegisteredClient(
                clientId: "update-test",
                clientSecret: "secret1",
                clientName: "Original Name",
                redirectUris: ["http://localhost/callback"],
                grantTypes: ["authorization_code"],
                tokenEndpointAuthMethod: "client_secret_basic",
                registrationDate: Date()
            )

            try await storage.saveClient(original)

            let updated = RegisteredClient(
                clientId: "update-test",
                clientSecret: "secret2",
                clientName: "Updated Name",
                redirectUris: ["http://localhost/callback", "http://localhost/callback2"],
                grantTypes: ["authorization_code", "refresh_token"],
                tokenEndpointAuthMethod: "client_secret_post",
                registrationDate: original.registrationDate
            )

            try await storage.saveClient(updated)

            let retrieved = try await storage.getClient(clientId: "update-test")
            #expect(retrieved?.clientName == "Updated Name")
            #expect(retrieved?.clientSecret == "secret2")
            #expect(retrieved?.redirectUris.count == 2)
        }

        @Test("Deletes client")
        func deletesClient() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let client = RegisteredClient(
                clientId: "delete-test",
                clientSecret: nil,
                clientName: "To Delete",
                redirectUris: [],
                grantTypes: [],
                tokenEndpointAuthMethod: "none",
                registrationDate: Date()
            )

            try await storage.saveClient(client)
            _ = try #require(await storage.getClient(clientId: "delete-test"))

            try await storage.deleteClient(clientId: "delete-test")
            #expect(try await storage.getClient(clientId: "delete-test") == nil)
        }

        @Test("Stores public client without secret")
        func storesPublicClientWithoutSecret() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let publicClient = RegisteredClient(
                clientId: "public-client",
                clientSecret: nil,
                clientName: "Public App",
                redirectUris: ["myapp://callback"],
                grantTypes: ["authorization_code"],
                tokenEndpointAuthMethod: "none",
                registrationDate: Date()
            )

            try await storage.saveClient(publicClient)
            let retrieved = try await storage.getClient(clientId: "public-client")

            #expect(retrieved?.clientSecret == nil)
            #expect(retrieved?.tokenEndpointAuthMethod == "none")
        }
    }

    // MARK: - Authorization Code Storage Tests

    @Suite("Authorization Code Storage")
    struct AuthorizationCodeStorageTests {

        @Test("Stores and retrieves authorization code")
        func storesAndRetrievesCode() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let code = AuthorizationCode(
                code: "auth_code_123",
                clientId: "client-abc",
                redirectUri: "http://localhost/callback",
                scope: "mcp:tools mcp:resources",
                codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                codeChallengeMethod: "S256",
                expiresAt: Date().addingTimeInterval(600),
                createdAt: Date()
            )

            try await storage.saveAuthorizationCode(code)
            let retrieved = try #require(await storage.getAuthorizationCode(code: "auth_code_123"))

            #expect(retrieved.code == code.code)
            #expect(retrieved.clientId == code.clientId)
            #expect(retrieved.codeChallenge == code.codeChallenge)
            #expect(retrieved.scope == code.scope)
        }

        @Test("Consumes authorization code (single use)")
        func consumesAuthorizationCode() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let code = AuthorizationCode(
                code: "single_use_code",
                clientId: "client",
                redirectUri: "http://localhost",
                scope: nil,
                codeChallenge: nil,
                codeChallengeMethod: nil,
                expiresAt: Date().addingTimeInterval(600),
                createdAt: Date()
            )

            try await storage.saveAuthorizationCode(code)

            // First retrieval should succeed
            _ = try #require(await storage.consumeAuthorizationCode(code: "single_use_code"))

            // Second retrieval should fail (code consumed)
            let second = try await storage.consumeAuthorizationCode(code: "single_use_code")
            #expect(second == nil)
        }

        @Test("Returns nil for non-existent code")
        func returnsNilForNonExistentCode() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let code = try await storage.getAuthorizationCode(code: "non-existent")
            #expect(code == nil)
        }

        @Test("Stores code without PKCE")
        func storesCodeWithoutPKCE() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let code = AuthorizationCode(
                code: "no_pkce_code",
                clientId: "client",
                redirectUri: "http://localhost",
                scope: nil,
                codeChallenge: nil,
                codeChallengeMethod: nil,
                expiresAt: Date().addingTimeInterval(600),
                createdAt: Date()
            )

            try await storage.saveAuthorizationCode(code)
            let retrieved = try await storage.getAuthorizationCode(code: "no_pkce_code")

            #expect(retrieved?.codeChallenge == nil)
            #expect(retrieved?.codeChallengeMethod == nil)
        }
    }

    // MARK: - Access Token Storage Tests

    @Suite("Access Token Storage")
    struct AccessTokenStorageTests {

        @Test("Stores and validates access token")
        func storesAndValidatesToken() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let token = TokenGenerator.generateAccessToken()
            let expiresAt = Date().addingTimeInterval(86400) // 24 hours

            try await storage.saveAccessToken(
                token: token,
                clientId: "client-123",
                scope: "mcp:tools",
                expiresAt: expiresAt
            )

            let result = try await storage.validateAccessToken(token: token)

            #expect(result.isValid)
            if case .valid(let clientId, let scope) = result {
                #expect(clientId == "client-123")
                #expect(scope == "mcp:tools")
            }
        }

        @Test("Stores token hash, not raw token")
        func storesTokenHash() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let token = TokenGenerator.generateAccessToken()
            try await storage.saveAccessToken(
                token: token,
                clientId: "client",
                scope: nil,
                expiresAt: Date().addingTimeInterval(3600)
            )

            // Verify raw token is not stored (implementation detail test)
            let hasRawToken = try await storage.containsRawToken(token)
            #expect(hasRawToken == false)
        }

        @Test("Rejects expired token")
        func rejectsExpiredToken() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let token = TokenGenerator.generateAccessToken()
            try await storage.saveAccessToken(
                token: token,
                clientId: "client",
                scope: nil,
                expiresAt: Date().addingTimeInterval(-60) // Expired 1 minute ago
            )

            let result = try await storage.validateAccessToken(token: token)
            #expect(result.isValid == false)
        }

        @Test("Rejects unknown token")
        func rejectsUnknownToken() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let result = try await storage.validateAccessToken(token: "unknown_token")
            #expect(result.isValid == false)
        }

        @Test("Revokes access token")
        func revokesAccessToken() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let token = TokenGenerator.generateAccessToken()
            try await storage.saveAccessToken(
                token: token,
                clientId: "client",
                scope: nil,
                expiresAt: Date().addingTimeInterval(3600)
            )

            // Valid before revocation
            #expect((try await storage.validateAccessToken(token: token)).isValid)

            try await storage.revokeAccessToken(token: token)

            // Invalid after revocation
            #expect((try await storage.validateAccessToken(token: token)).isValid == false)
        }

        @Test("Revokes all tokens for client")
        func revokesAllClientTokens() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            // Create multiple tokens for same client
            for i in 0..<3 {
                try await storage.saveAccessToken(
                    token: "mcp_at_client_token_\(i)",
                    clientId: "multi-token-client",
                    scope: nil,
                    expiresAt: Date().addingTimeInterval(3600)
                )
            }

            // All should be valid
            for i in 0..<3 {
                let result = try await storage.validateAccessToken(token: "mcp_at_client_token_\(i)")
                #expect(result.isValid)
            }

            // Revoke all
            try await storage.revokeAllTokensForClient(clientId: "multi-token-client")

            // All should be invalid
            for i in 0..<3 {
                let result = try await storage.validateAccessToken(token: "mcp_at_client_token_\(i)")
                #expect(result.isValid == false)
            }
        }
    }

    // MARK: - Refresh Token Storage Tests

    @Suite("Refresh Token Storage")
    struct RefreshTokenStorageTests {

        @Test("Stores and retrieves refresh token")
        func storesAndRetrievesToken() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let token = TokenGenerator.generateRefreshToken()
            let expiresAt = Date().addingTimeInterval(90 * 24 * 3600) // 90 days

            try await storage.saveRefreshToken(
                token: token,
                clientId: "client-123",
                scope: "mcp:tools mcp:resources",
                expiresAt: expiresAt
            )

            let info = try #require(await storage.getRefreshTokenInfo(token: token))

            #expect(info.clientId == "client-123")
            #expect(info.scope == "mcp:tools mcp:resources")
        }

        @Test("Rejects expired refresh token")
        func rejectsExpiredToken() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let token = TokenGenerator.generateRefreshToken()
            try await storage.saveRefreshToken(
                token: token,
                clientId: "client",
                scope: nil,
                expiresAt: Date().addingTimeInterval(-60)
            )

            let info = try await storage.getRefreshTokenInfo(token: token)
            #expect(info == nil) // Expired tokens should not be returned
        }

        @Test("Revokes refresh token")
        func revokesRefreshToken() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let token = TokenGenerator.generateRefreshToken()
            try await storage.saveRefreshToken(
                token: token,
                clientId: "client",
                scope: nil,
                expiresAt: Date().addingTimeInterval(3600)
            )

            _ = try #require(await storage.getRefreshTokenInfo(token: token))

            try await storage.revokeRefreshToken(token: token)

            #expect(try await storage.getRefreshTokenInfo(token: token) == nil)
        }
    }

    // MARK: - Cleanup Tests

    @Suite("Token Cleanup")
    struct TokenCleanupTests {

        @Test("Removes expired tokens")
        func removesExpiredTokens() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            // Create expired token
            try await storage.saveAccessToken(
                token: "mcp_at_expired",
                clientId: "client",
                scope: nil,
                expiresAt: Date().addingTimeInterval(-3600)
            )

            // Create valid token
            try await storage.saveAccessToken(
                token: "mcp_at_valid",
                clientId: "client",
                scope: nil,
                expiresAt: Date().addingTimeInterval(3600)
            )

            let removed = try await storage.cleanupExpiredTokens()
            #expect(removed >= 1)

            // Valid token should still work
            let result = try await storage.validateAccessToken(token: "mcp_at_valid")
            #expect(result.isValid)
        }

        @Test("Removes expired authorization codes")
        func removesExpiredAuthCodes() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            // Create expired code
            let expiredCode = AuthorizationCode(
                code: "expired_code",
                clientId: "client",
                redirectUri: "http://localhost",
                scope: nil,
                codeChallenge: nil,
                codeChallengeMethod: nil,
                expiresAt: Date().addingTimeInterval(-60),
                createdAt: Date().addingTimeInterval(-120)
            )
            try await storage.saveAuthorizationCode(expiredCode)

            let removed = try await storage.cleanupExpiredTokens()
            #expect(removed >= 1)

            let code = try await storage.getAuthorizationCode(code: "expired_code")
            #expect(code == nil)
        }
    }

    // MARK: - Concurrency Tests

    @Suite("Concurrency")
    struct ConcurrencyTests {

        @Test("Handles concurrent token operations")
        func handlesConcurrentOperations() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            // Create many tokens concurrently
            await withTaskGroup(of: Void.self) { group in
                for i in 0..<50 {
                    group.addTask {
                        try? await storage.saveAccessToken(
                            token: "mcp_at_concurrent_\(i)",
                            clientId: "client",
                            scope: nil,
                            expiresAt: Date().addingTimeInterval(3600)
                        )
                    }
                }
            }

            // Validate all tokens exist
            var validCount = 0
            for i in 0..<50 {
                let result = try await storage.validateAccessToken(token: "mcp_at_concurrent_\(i)")
                if result.isValid {
                    validCount += 1
                }
            }

            #expect(validCount == 50)
        }

        @Test("Actor isolation prevents data races")
        func actorIsolationPreventsRaces() async throws {
            let storage = try OAuthStorageTests.makeTestStorage()

            let token = TokenGenerator.generateAccessToken()
            try await storage.saveAccessToken(
                token: token,
                clientId: "client",
                scope: nil,
                expiresAt: Date().addingTimeInterval(3600)
            )

            // Concurrent validate and revoke
            async let validate = storage.validateAccessToken(token: token)
            async let revoke: Void = storage.revokeAccessToken(token: token)

            // Both should complete without crashing
            let result = try await validate
            _ = try await revoke
            #expect(true, "Concurrent validate (\(result)) and revoke completed without data race")
        }
    }
}
