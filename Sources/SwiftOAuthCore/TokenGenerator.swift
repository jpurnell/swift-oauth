import Foundation
import Crypto

/// Secure token generation utilities for OAuth 2.0
///
/// Provides cryptographically secure random token generation and
/// timing-safe comparison operations.
///
/// ## Overview
///
/// `TokenGenerator` provides all the secure random value generation
/// needed for OAuth 2.0 implementation:
///
/// - Access tokens and refresh tokens
/// - Client IDs and secrets
/// - Authorization codes
/// - SHA-256 hashing for storage
///
/// All random generation uses `SystemRandomNumberGenerator` which
/// provides cryptographically secure random numbers on all platforms.
///
/// ## Example
///
/// ```swift
/// // Generate tokens
/// let accessToken = TokenGenerator.generateAccessToken()
/// let refreshToken = TokenGenerator.generateRefreshToken()
///
/// // Hash for storage
/// let hash = TokenGenerator.sha256Hash(accessToken)
///
/// // Timing-safe validation
/// let isValid = TokenGenerator.timingSafeCompare(provided, stored)
/// ```
///
/// ## Topics
///
/// ### Token Generation
/// - ``generateToken(byteLength:)``
/// - ``generateAccessToken()``
/// - ``generateRefreshToken()``
/// - ``generateAuthorizationCode()``
/// - ``generateClientId()``
/// - ``generateClientSecret()``
///
/// ### Hashing
/// - ``sha256Hash(_:)``
///
/// ### Comparison
/// - ``timingSafeCompare(_:_:)``
public enum TokenGenerator {

    // MARK: - Token Generation

    /// Generates a cryptographically secure random token
    ///
    /// - Parameters:
    ///   - byteLength: Number of random bytes (default 32 = 256 bits)
    ///   - rng: Random number generator to use
    /// - Returns: URL-safe base64 encoded random string
    public static func generateToken(byteLength: Int = 32, using rng: inout some RandomNumberGenerator) -> String {
        var bytes = [UInt8](repeating: 0, count: byteLength)

        for i in 0..<byteLength {
            bytes[i] = UInt8.random(in: 0...255, using: &rng)
        }

        // URL-safe base64 encoding without padding
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Generates a cryptographically secure random token using the system RNG
    ///
    /// - Parameter byteLength: Number of random bytes (default 32 = 256 bits)
    /// - Returns: URL-safe base64 encoded random string
    public static func generateToken(byteLength: Int = 32) -> String {
        var rng = SystemRandomNumberGenerator() // stochastic:exempt convenience wrapper; injectable overload above
        return generateToken(byteLength: byteLength, using: &rng)
    }

    /// Generates a client ID
    ///
    /// Client IDs are URL-safe identifiers suitable for use in URLs and headers.
    ///
    /// - Returns: A unique client ID (URL-safe, 24+ characters)
    public static func generateClientId() -> String {
        // Use 16 bytes = 128 bits of entropy
        generateToken(byteLength: 16)
    }

    /// Generates a client secret
    ///
    /// Client secrets have high entropy for secure authentication.
    ///
    /// - Returns: A secure client secret (256 bits of entropy)
    public static func generateClientSecret() -> String {
        // Use 32 bytes = 256 bits of entropy
        generateToken(byteLength: 32)
    }

    /// Generates an access token
    ///
    /// Access tokens include a prefix for easy identification in logs
    /// while maintaining security.
    ///
    /// - Returns: An access token with `mcp_at_` prefix
    public static func generateAccessToken() -> String {
        "mcp_at_" + generateToken(byteLength: 32)
    }

    /// Generates a refresh token
    ///
    /// Refresh tokens include a prefix for easy identification.
    ///
    /// - Returns: A refresh token with `mcp_rt_` prefix
    public static func generateRefreshToken() -> String {
        "mcp_rt_" + generateToken(byteLength: 32)
    }

    /// Generates an authorization code
    ///
    /// Authorization codes are short-lived and single-use.
    ///
    /// - Returns: An authorization code (256 bits of entropy)
    public static func generateAuthorizationCode() -> String {
        generateToken(byteLength: 32)
    }

    // MARK: - Hashing

    /// Computes SHA-256 hash of a string
    ///
    /// Used for storing tokens securely - only the hash is persisted,
    /// never the raw token.
    ///
    /// - Parameter input: String to hash
    /// - Returns: Lowercase hexadecimal SHA-256 hash (64 characters)
    public static func sha256Hash(_ input: String) -> String {
        let data = Data(input.utf8)
        let digest = SHA256.hash(data: data)
        return digest.map { ($0 < 16 ? "0" : "") + String($0, radix: 16, uppercase: false) }.joined()
    }

    // MARK: - Comparison

    /// Performs timing-safe string comparison
    ///
    /// This comparison takes constant time regardless of where strings differ,
    /// preventing timing attacks that could reveal token prefixes.
    ///
    /// - Parameters:
    ///   - a: First string
    ///   - b: Second string
    /// - Returns: `true` if strings are equal, `false` otherwise
    public static func timingSafeCompare(_ a: String, _ b: String) -> Bool {
        let aBytes = Array(a.utf8)
        let bBytes = Array(b.utf8)

        // Always compare all bytes to prevent timing leaks
        guard aBytes.count == bBytes.count else {
            // Still do some work to avoid leaking length difference timing
            var result: UInt8 = 1
            for byte in aBytes {
                result |= byte ^ byte
            }
            return false
        }

        var result: UInt8 = 0
        for (aByte, bByte) in zip(aBytes, bBytes) {
            result |= aByte ^ bByte
        }

        return result == 0
    }
}
