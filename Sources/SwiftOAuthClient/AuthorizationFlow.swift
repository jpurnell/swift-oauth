import Foundation
import SwiftOAuthCore

/// What a client must keep between sending a user to authorise and hearing back.
///
/// Both fields are secrets of a kind, and for different reasons.
///
/// The **verifier** never leaves the client. Only its SHA-256 digest travels, in the
/// authorization request; presenting the verifier at the token endpoint is what proves the
/// party redeeming the code is the party that requested it. A verifier that leaked would make
/// PKCE decorative.
///
/// The **state** is what proves a callback belongs to a flow this client started. Without it,
/// an attacker who can cause the user's browser to hit the redirect URI carrying the
/// attacker's own authorization code gets the user's application connected to the attacker's
/// account — and the user sees a working connection rather than an error.
///
/// Hold one of these per in-flight authorization, keyed however the redirect is routed back.
/// Discard it once used: a callback replayed against a still-valid pending authorization is
/// a second attempt at the same code.
public struct PendingAuthorization: Sendable, Equatable {

    /// The opaque value sent to the provider and expected back.
    public let state: String

    /// The PKCE verifier. Never sent to the authorization endpoint.
    public let verifier: String

    /// The redirect URI this flow was started with. Sent again at the token endpoint, where
    /// RFC 6749 §4.1.3 requires it to match.
    public let redirectURI: String

    /// Creates a pending authorization.
    ///
    /// - Parameters:
    ///   - state: The opaque value to expect back.
    ///   - verifier: The PKCE verifier.
    ///   - redirectURI: Where the provider will send the user.
    public init(state: String, verifier: String, redirectURI: String) {
        self.state = state
        self.verifier = verifier
        self.redirectURI = redirectURI
    }
}

/// A started authorization: where to send the user, and what to keep until they return.
public struct BegunAuthorization: Sendable, Equatable {

    /// The URL to open.
    public let url: URL

    /// What to hold until the callback arrives.
    public let pending: PendingAuthorization

    /// Creates a begun authorization.
    public init(url: URL, pending: PendingAuthorization) {
        self.url = url
        self.pending = pending
    }
}

/// Why a callback could not be accepted.
public enum CallbackError: Error, Equatable, Sendable {

    /// The `state` was absent or did not match the pending authorization.
    ///
    /// Not necessarily an attack — a stale browser tab produces this too — but it must be
    /// refused either way, because the two are indistinguishable from here.
    case stateMismatch

    /// The provider reported a failure instead of issuing a code.
    case provider(OAuthError)

    /// Neither a code nor an error was present.
    case missingCode
}

/// Reads an authorization callback.
///
/// Separate from ``OAuthConnection`` because the check has to be possible without one: a
/// callback usually arrives on an HTTP handler that has no idea which connection it belongs
/// to until the state is matched.
public enum AuthorizationCallback {

    /// Extracts the authorization code from a callback, having checked it belongs here.
    ///
    /// The order matters and is the point of this function. The state is compared **first** —
    /// before a code is read, before a provider error is believed. A forged callback carrying
    /// `error=access_denied` is still forged, and treating its error as authoritative lets an
    /// attacker steer the client's behaviour.
    ///
    /// - Parameters:
    ///   - callback: The redirect URI as received, query intact.
    ///   - pending: What was kept when the flow started.
    /// - Returns: The authorization code.
    /// - Throws: ``CallbackError``.
    public static func code(from callback: URL, matching pending: PendingAuthorization) throws -> String {
        let items = queryItems(of: callback)

        // First, and unconditionally. Compared in constant time: the comparison is against a
        // value an attacker supplies and can vary at will, which is the shape that makes a
        // byte-at-a-time early exit worth exploiting.
        guard let state = items["state"],
              TokenGenerator.timingSafeCompare(state, pending.state) else {
            throw CallbackError.stateMismatch
        }

        if let error = items["error"] {
            throw CallbackError.provider(
                OAuthError(code: error, description: items["error_description"]))
        }

        guard let code = items["code"], !code.isEmpty else {
            throw CallbackError.missingCode
        }
        return code
    }

    /// The callback's query parameters.
    ///
    /// Percent-decoding is `URLComponents`' job here; a code or state arrives encoded and
    /// comparing the encoded form against a decoded one would fail for values that happen to
    /// contain a reserved character.
    private static func queryItems(of callback: URL) -> [String: String] {
        guard let components = URLComponents(url: callback, resolvingAgainstBaseURL: false),
              let items = components.queryItems else {
            return [:]
        }
        // Last-wins would let an appended `&state=…` override the real one; first-wins means
        // a duplicated parameter cannot be used to smuggle a second value past the check.
        var result: [String: String] = [:]
        for item in items where result[item.name] == nil {
            result[item.name] = item.value
        }
        return result
    }
}
