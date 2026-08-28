import Foundation
import Crypto

/// PKCE (Proof Key for Code Exchange) implementation per RFC 7636
///
/// PKCE protects against authorization code interception attacks by requiring
/// clients to prove possession of a secret that was used when requesting the
/// authorization code.
///
/// ## Overview
///
/// The PKCE flow works as follows:
/// 1. Client generates a random `code_verifier`
/// 2. Client derives a `code_challenge` from the verifier
/// 3. Client includes the challenge in the authorization request
/// 4. Server stores the challenge with the authorization code
/// 5. Client includes the verifier in the token request
/// 6. Server verifies the verifier matches the stored challenge
///
/// ## Example
///
/// ```swift
/// // Client side - authorization request
/// let verifier = PKCE.generateCodeVerifier()
/// let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)
/// // Store verifier securely, send challenge with auth request
///
/// // Server side - token request. The verifier arrives from the client; the
/// // challenge is the one stored when the authorization request was made.
/// let receivedVerifier = verifier
/// let storedChallenge = challenge
/// let isValid = try PKCE.verifyCodeChallenge(
///     verifier: receivedVerifier,
///     challenge: storedChallenge,
///     method: .s256
/// )
/// ```
///
/// ## Topics
///
/// ### Code Verifier
/// - ``generateCodeVerifier()``
/// - ``isValidCodeVerifier(_:)``
///
/// ### Code Challenge
/// - ``generateCodeChallenge(verifier:method:)``
/// - ``verifyCodeChallenge(verifier:challenge:method:)``
///
/// ### Challenge Method
/// - ``ChallengeMethod``
public enum PKCE {

    // MARK: - Challenge Method

    /// PKCE code challenge methods per RFC 7636 §4.2
    ///
    /// S256 is REQUIRED by servers and SHOULD be used by clients.
    /// The only challenge method this package supports.
    ///
    /// RFC 7636 also defines `plain`, where the challenge *is* the verifier.
    /// OAuth 2.1 removes it, and it is deliberately absent here: `plain` offers
    /// no protection against the interception attack PKCE exists to prevent —
    /// an attacker who intercepts the authorization request has the challenge,
    /// which under `plain` is the verifier.
    ///
    /// Modelled as an enum with one case rather than dropped entirely so the
    /// `code_challenge_method` parameter still round-trips, and so adding a
    /// future method is additive.
    public enum ChallengeMethod: String, Codable, Sendable, CaseIterable {
        /// `BASE64URL(SHA256(code_verifier))` — RFC 7636 §4.2.
        case s256 = "S256"
    }

    // MARK: - Code Verifier

    /// Generates a cryptographically random code verifier
    ///
    /// - Parameter rng: Random number generator to use
    /// - Returns: A URL-safe random string suitable for use as a code verifier
    public static func generateCodeVerifier(using rng: inout some RandomNumberGenerator) -> String {
        // Generate 32 bytes of random data (256 bits of entropy)
        var bytes = [UInt8](repeating: 0, count: 32)

        for i in 0..<32 {
            bytes[i] = UInt8.random(in: 0...255, using: &rng)
        }

        // URL-safe base64 encoding without padding
        // 32 bytes -> 43 base64 characters (without padding)
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Generates a cryptographically random code verifier using the system RNG
    ///
    /// - Returns: A URL-safe random string suitable for use as a code verifier
    public static func generateCodeVerifier() -> String {
        var rng = SystemRandomNumberGenerator() // stochastic:exempt convenience wrapper; injectable overload above
        return generateCodeVerifier(using: &rng)
    }

    /// Validates a code verifier per RFC 7636 §4.1
    ///
    /// The code verifier must:
    /// - Be between 43 and 128 characters long
    /// - Contain only unreserved URI characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
    ///
    /// - Parameter verifier: The code verifier to validate
    /// - Returns: `true` if the verifier is valid, `false` otherwise
    public static func isValidCodeVerifier(_ verifier: String) -> Bool {
        // RFC 7636 §4.1: length must be 43-128 characters
        guard verifier.count >= 43 && verifier.count <= 128 else {
            return false
        }

        // RFC 7636 §4.1: unreserved characters only
        let allowedCharacters = CharacterSet(charactersIn:
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        let verifierCharacters = CharacterSet(charactersIn: verifier)

        return verifierCharacters.isSubset(of: allowedCharacters)
    }

    // MARK: - Code Challenge

    /// Generates a code challenge from a code verifier
    ///
    /// Per RFC 7636 §4.2: `BASE64URL(SHA256(code_verifier))`.
    ///
    /// - Parameters:
    ///   - verifier: The code verifier
    ///   - method: The challenge method.
    /// - Returns: The code challenge
    /// - Throws: `PKCEError.invalidVerifier` if the verifier is invalid
    public static func generateCodeChallenge(
        verifier: String,
        method: ChallengeMethod
    ) throws -> String {
        guard isValidCodeVerifier(verifier) else {
            throw PKCEError.invalidVerifier
        }

        switch method {
        case .s256:
            return computeS256Challenge(verifier: verifier)
        }
    }

    /// Verifies a code challenge against a code verifier
    ///
    /// This is used by the authorization server when processing the token
    /// request to verify the client possesses the original verifier.
    ///
    /// - Parameters:
    ///   - verifier: The code verifier from the token request
    ///   - challenge: The code challenge stored with the authorization code
    ///   - method: The challenge method used
    /// - Returns: `true` if the verifier matches the challenge, `false` otherwise
    /// - Throws: `PKCEError.invalidVerifier` if the verifier format is invalid
    public static func verifyCodeChallenge(
        verifier: String,
        challenge: String,
        method: ChallengeMethod
    ) throws -> Bool {
        let computedChallenge = try generateCodeChallenge(
            verifier: verifier,
            method: method
        )

        // Use timing-safe comparison to prevent timing attacks
        return timingSafeCompare(computedChallenge, challenge)
    }

    // MARK: - Private Helpers

    /// Computes S256 challenge: BASE64URL(SHA256(code_verifier))
    private static func computeS256Challenge(verifier: String) -> String {
        let data = Data(verifier.utf8)
        let digest = SHA256.hash(data: data)

        // Convert to URL-safe base64 without padding
        return Data(digest).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Timing-safe string comparison
    private static func timingSafeCompare(_ a: String, _ b: String) -> Bool {
        let aBytes = Array(a.utf8)
        let bBytes = Array(b.utf8)

        guard aBytes.count == bBytes.count else {
            return false
        }

        var result: UInt8 = 0
        for (aByte, bByte) in zip(aBytes, bBytes) {
            result |= aByte ^ bByte
        }

        return result == 0
    }
}

// MARK: - PKCEError

/// Errors that can occur during PKCE operations
public enum PKCEError: Error, Sendable {
    /// The code verifier does not meet RFC 7636 requirements
    case invalidVerifier
}
