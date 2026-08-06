import Testing
import Foundation
@testable import SwiftOAuthCore

/// Tests for secure token generation utilities
@Suite("Token Generator")
struct TokenGeneratorTests {

    // MARK: - Token Generation Tests

    @Suite("Token Generation")
    struct TokenGenerationTests {

        @Test("Generates tokens of specified length")
        func generatesTokensOfSpecifiedLength() {
            let token32 = TokenGenerator.generateToken(byteLength: 32)
            let token16 = TokenGenerator.generateToken(byteLength: 16)

            // Base64 encoding: 4 characters per 3 bytes, rounded up
            // 32 bytes -> 44 base64 chars (with padding) or 43 without
            // 16 bytes -> 22 base64 chars (with padding) or 22 without
            #expect(token32.count >= 42) // URL-safe base64 without padding
            #expect(token16.count >= 21)
        }

        @Test("Generates unique tokens")
        func generatesUniqueTokens() {
            var tokens = Set<String>()
            for _ in 0..<100 {
                let token = TokenGenerator.generateToken(byteLength: 32)
                #expect(!tokens.contains(token), "Token collision detected")
                tokens.insert(token)
            }
        }

        @Test("Generates URL-safe tokens")
        func generatesURLSafeTokens() {
            let token = TokenGenerator.generateToken(byteLength: 32)

            // URL-safe base64 should not contain +, /, or =
            #expect(!token.contains("+"))
            #expect(!token.contains("/"))
            // Padding is optional, but if present should be URL-safe
        }

        @Test("Uses cryptographically secure random")
        func usesCryptographicallySecureRandom() {
            // Generate many tokens and verify distribution looks random
            // (not a rigorous test, but catches obvious issues)
            var charCounts: [Character: Int] = [:]

            for _ in 0..<1000 {
                let token = TokenGenerator.generateToken(byteLength: 16)
                for char in token {
                    charCounts[char, default: 0] += 1
                }
            }

            // Should have reasonable distribution across base64 alphabet
            #expect(charCounts.count > 30, "Expected diverse character distribution")
        }
    }

    // MARK: - Client ID Generation Tests

    @Suite("Client ID Generation")
    struct ClientIDGenerationTests {

        @Test("Generates valid client IDs")
        func generatesValidClientIDs() {
            let clientId = TokenGenerator.generateClientId()

            #expect(!clientId.isEmpty)
            #expect(clientId.count >= 16, "Client ID should be at least 16 characters")
        }

        @Test("Client IDs are unique")
        func clientIDsAreUnique() {
            var ids = Set<String>()
            for _ in 0..<100 {
                let id = TokenGenerator.generateClientId()
                #expect(!ids.contains(id), "Client ID collision detected")
                ids.insert(id)
            }
        }

        @Test("Client IDs are URL-safe")
        func clientIDsAreURLSafe() {
            let clientId = TokenGenerator.generateClientId()

            // Should be alphanumeric + URL-safe characters
            let allowedChars = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
            let idChars = CharacterSet(charactersIn: clientId)
            #expect(idChars.isSubset(of: allowedChars))
        }
    }

    // MARK: - Client Secret Generation Tests

    @Suite("Client Secret Generation")
    struct ClientSecretGenerationTests {

        @Test("Generates secrets with sufficient entropy")
        func generatesSecretsWithSufficientEntropy() {
            let secret = TokenGenerator.generateClientSecret()

            // Should be at least 32 bytes of entropy (256 bits)
            #expect(secret.count >= 32, "Secret should have sufficient length")
        }

        @Test("Secrets are unique")
        func secretsAreUnique() {
            var secrets = Set<String>()
            for _ in 0..<100 {
                let secret = TokenGenerator.generateClientSecret()
                #expect(!secrets.contains(secret), "Secret collision detected")
                secrets.insert(secret)
            }
        }
    }

    // MARK: - Access Token Generation Tests

    @Suite("Access Token Generation")
    struct AccessTokenGenerationTests {

        @Test("Generates valid access tokens")
        func generatesValidAccessTokens() {
            let token = TokenGenerator.generateAccessToken()

            #expect(!token.isEmpty)
            #expect(token.count >= 32, "Access token should be at least 32 characters")
        }

        @Test("Access tokens have proper prefix")
        func accessTokensHaveProperPrefix() {
            let token = TokenGenerator.generateAccessToken()

            // Access tokens should be identifiable
            #expect(token.hasPrefix("mcp_at_"), "Access token should have mcp_at_ prefix")
        }
    }

    // MARK: - Refresh Token Generation Tests

    @Suite("Refresh Token Generation")
    struct RefreshTokenGenerationTests {

        @Test("Generates valid refresh tokens")
        func generatesValidRefreshTokens() {
            let token = TokenGenerator.generateRefreshToken()

            #expect(!token.isEmpty)
            #expect(token.count >= 32, "Refresh token should be at least 32 characters")
        }

        @Test("Refresh tokens have proper prefix")
        func refreshTokensHaveProperPrefix() {
            let token = TokenGenerator.generateRefreshToken()

            #expect(token.hasPrefix("mcp_rt_"), "Refresh token should have mcp_rt_ prefix")
        }
    }

    // MARK: - Authorization Code Generation Tests

    @Suite("Authorization Code Generation")
    struct AuthorizationCodeGenerationTests {

        @Test("Generates valid authorization codes")
        func generatesValidAuthorizationCodes() {
            let code = TokenGenerator.generateAuthorizationCode()

            #expect(!code.isEmpty)
            #expect(code.count >= 32, "Auth code should be at least 32 characters")
        }
    }

    // MARK: - Hashing Tests

    @Suite("SHA-256 Hashing")
    struct HashingTests {

        @Test("Hashes strings consistently")
        func hashesStringsConsistently() {
            let input = "test_token_12345"
            let hash1 = TokenGenerator.sha256Hash(input)
            let hash2 = TokenGenerator.sha256Hash(input)

            #expect(hash1 == hash2, "Same input should produce same hash")
        }

        @Test("Different inputs produce different hashes")
        func differentInputsProduceDifferentHashes() {
            let hash1 = TokenGenerator.sha256Hash("token_a")
            let hash2 = TokenGenerator.sha256Hash("token_b")

            #expect(hash1 != hash2, "Different inputs should produce different hashes")
        }

        @Test("Hash output is hex encoded")
        func hashOutputIsHexEncoded() {
            let hash = TokenGenerator.sha256Hash("test")

            // SHA-256 produces 32 bytes = 64 hex characters
            #expect(hash.count == 64, "SHA-256 hex string should be 64 characters")

            // Should only contain hex characters
            let hexChars = CharacterSet(charactersIn: "0123456789abcdef")
            let hashChars = CharacterSet(charactersIn: hash.lowercased())
            #expect(hashChars.isSubset(of: hexChars))
        }

        @Test("Matches known SHA-256 test vector")
        func matchesKnownTestVector() {
            // Known SHA-256 test vector
            let hash = TokenGenerator.sha256Hash("hello")
            let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

            #expect(hash.lowercased() == expected)
        }
    }

    // MARK: - Timing-Safe Comparison Tests

    @Suite("Timing-Safe Comparison")
    struct TimingSafeComparisonTests {

        @Test("Equal strings compare as equal")
        func equalStringsCompareAsEqual() {
            let a = "test_token_12345"
            let b = "test_token_12345"

            #expect(TokenGenerator.timingSafeCompare(a, b) == true)
        }

        @Test("Different strings compare as not equal")
        func differentStringsCompareAsNotEqual() {
            let a = "test_token_12345"
            let b = "test_token_12346"

            #expect(TokenGenerator.timingSafeCompare(a, b) == false)
        }

        @Test("Different length strings compare as not equal")
        func differentLengthStringsCompareAsNotEqual() {
            let a = "short"
            let b = "longer_string"

            #expect(TokenGenerator.timingSafeCompare(a, b) == false)
        }

        @Test("Empty strings compare as equal")
        func emptyStringsCompareAsEqual() {
            #expect(TokenGenerator.timingSafeCompare("", "") == true)
        }

        @Test("Comparison uses constant time")
        func comparisonUsesConstantTime() {
            // This is a smoke test - we can't truly verify timing in a unit test,
            // but we verify the comparison completes for various inputs
            let base = "a" + String(repeating: "b", count: 1000)
            let earlyDiff = "x" + String(repeating: "b", count: 1000)
            let lateDiff = "a" + String(repeating: "b", count: 999) + "x"

            #expect(TokenGenerator.timingSafeCompare(base, earlyDiff) == false)
            #expect(TokenGenerator.timingSafeCompare(base, lateDiff) == false)
            #expect(TokenGenerator.timingSafeCompare(base, base) == true)
        }
    }
}
