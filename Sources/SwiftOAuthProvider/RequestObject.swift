import Foundation
import Crypto
import SwiftOAuthCore

/// An authorization request carried as a signed JWT — RFC 9101.
///
/// PAR (RFC 9126) hides the request's parameters from the browser. JAR proves who wrote them.
/// They compose and neither replaces the other: a pushed request is opaque but unsigned, and a
/// signed request in a URL is authentic but visible.
///
/// ## Never fall back
///
/// The rule this type exists to enforce: **a request object that does not verify is refused,
/// and the query parameters are not used instead.** A server that verifies a signature and, on
/// failure, proceeds with whatever was in the URL has built a signature that means nothing —
/// an attacker supplies a broken one, or omits it, and is no worse off than before it existed.
///
/// There is deliberately no API here that returns parameters without verifying, so a caller
/// cannot construct that fallback by accident.
public struct RequestObject: Sendable, Equatable {

    /// Where to return the user.
    public let redirectUri: String
    /// What is being asked for.
    public let scope: String?
    /// The client's opaque state.
    public let state: String?
    /// The response type requested.
    public let responseType: String?
    /// The PKCE challenge, when the object carries one.
    public let codeChallenge: String?
    /// How that challenge was derived.
    public let codeChallengeMethod: String?

    /// What can be wrong with a request object.
    public enum Failure: Error, Equatable {
        /// The claims were not a JSON object.
        case malformedClaims
        /// `iss` was absent or was not this client.
        case wrongIssuer
        /// `aud` did not include this server.
        case wrongAudience
        /// The `client_id` inside disagreed with the one outside.
        case clientIdMismatch
        /// `exp` had passed.
        case expired
        /// `redirect_uri` was absent — RFC 9101 requires the object to be self-contained.
        case missingRedirectURI
    }

    /// Verifies a request object and returns what it asks for.
    ///
    /// - Parameters:
    ///   - token: The compact JWS.
    ///   - clientId: The `client_id` the request carried outside the object. RFC 9101 §4
    ///     requires it, and it must match what is inside: otherwise the server authenticates
    ///     one client and honours another's parameters.
    ///   - issuer: This server's identifier, which the object's `aud` must contain. Without
    ///     this check a request object addressed to a different authorization server is
    ///     replayable against this one.
    ///   - key: The client's public key.
    /// - Returns: The verified parameters.
    /// - Throws: `CompactJWS.Failure` if the signature is not good, or ``Failure`` if a claim
    ///   is wrong. Either way the caller gets nothing usable — there is no partial result.
    public static func verify(
        _ token: String,
        clientId: String,
        issuer: String,
        using key: P256.Signing.PublicKey
    ) throws -> RequestObject {
        // Signature first. Nothing below this line runs for a token that does not verify.
        let payload = try CompactJWS.verify(token, using: key)

        // silent: claims that will not parse are a malformed request object, thrown by this guard
        guard let claims = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
            throw Failure.malformedClaims
        }

        guard claims["iss"] as? String == clientId else { throw Failure.wrongIssuer }
        guard claims["client_id"] as? String == clientId else { throw Failure.clientIdMismatch }

        // RFC 7519 §4.1.3: `aud` is a string or an array of strings.
        let audiences: [String]
        if let single = claims["aud"] as? String {
            audiences = [single]
        } else {
            audiences = claims["aud"] as? [String] ?? []
        }
        guard audiences.contains(issuer) else { throw Failure.wrongAudience }

        if let expiry = claims["exp"] as? TimeInterval {
            guard Date(timeIntervalSince1970: expiry) > Date() else { throw Failure.expired }
        }

        guard let redirectUri = claims["redirect_uri"] as? String else {
            throw Failure.missingRedirectURI
        }

        return RequestObject(
            redirectUri: redirectUri,
            scope: claims["scope"] as? String,
            state: claims["state"] as? String,
            responseType: claims["response_type"] as? String,
            codeChallenge: claims["code_challenge"] as? String,
            codeChallengeMethod: claims["code_challenge_method"] as? String)
    }
}
