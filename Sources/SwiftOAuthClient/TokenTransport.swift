import Foundation
#if canImport(FoundationNetworking)
// `URLSession` and `URLRequest` live here on Linux rather than in Foundation. Without this the
// whole file fails to compile there, which is how this package was Linux-broken while every
// macOS build stayed green.
import FoundationNetworking
#endif
import SwiftOAuthCore

/// Carries a token request to a provider and brings back its answer.
///
/// Abstracted so no test in this package touches the network. The rotation behaviour that
/// makes a client hard — concurrent refresh, a crash mid-write, a token replaced out from
/// under you — is nearly impossible to exercise against a live provider, and trivial
/// against a stub.
public protocol TokenTransport: Sendable {

    /// Posts form parameters to a token endpoint.
    ///
    /// - Parameters:
    ///   - endpoint: Where to send it.
    ///   - parameters: The form body, unencoded.
    ///   - credentials: Used for client authentication.
    ///   - method: How the credentials should be presented.
    /// - Returns: The provider's token response.
    /// - Throws: `OAuthError` for anything the provider rejected, or a transport error.
    func exchange(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws -> TokenResponse
}

/// A transport over `URLSession`.
///
/// ## Redirects are not followed
///
/// A token, refresh or revocation request carries a client secret, an authorization code and
/// its PKCE verifier, or a refresh token. If the endpoint answers with a redirect, the request
/// is **not** repeated anywhere — not on another origin and not on the same one — and
/// ``exchange(endpoint:parameters:credentials:method:)`` throws ``OAuthRedirectRefused``
/// naming the origin the redirect pointed at. This holds for a session you supply as much as
/// for the default: the refusal is attached to each request, not to the session.
///
/// RFC 6749 §3.2 and RFC 7009 §2.1 define these requests as a `POST` to the endpoint and
/// describe no redirect as an answer to one.
///
/// `URLSession` is thread-safe and documented as such, but corelibs-foundation does not mark
/// it `Sendable` — so the stored property passes the check on Apple platforms and fails on
/// Linux alone. The value is immutable and never mutated after init.
// Justification: URLSession is thread-safe; the stored session is immutable after init.
public struct URLSessionTokenTransport: TokenTransport, @unchecked Sendable {

    private let session: URLSession

    /// Creates a transport.
    ///
    /// - Parameter session: The session to use. Defaults to `.shared`. Whatever its
    ///   configuration or delegate, a redirect is not followed on it.
    public init(session: URLSession = .shared) {
        self.session = session
    }

    /// Posts the form to the endpoint over HTTP.
    ///
    /// - Parameters:
    ///   - endpoint: Where to send it.
    ///   - parameters: The form body, unencoded.
    ///   - credentials: Used for client authentication.
    ///   - method: How the credentials should be presented.
    /// - Returns: The provider's token response.
    /// - Throws: `OAuthError` for anything the provider rejected, ``OAuthRedirectRefused`` if
    ///   the endpoint answered with a redirect — which is not followed — or a transport error.
    public func exchange(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws -> TokenResponse {
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        var body = parameters
        switch method {
        case .clientSecretBasic:
            let pair = "\(credentials.clientID):\(credentials.clientSecret)"
            let encoded = Data(pair.utf8).base64EncodedString()
            request.setValue("Basic \(encoded)", forHTTPHeaderField: "Authorization")
        case .clientSecretPost:
            // Permitted, and discouraged: parameters are logged by intermediaries far more
            // often than headers are.
            body["client_id"] = credentials.clientID
            body["client_secret"] = credentials.clientSecret
        case .none:
            body["client_id"] = credentials.clientID
        case .tlsClientAuth, .selfSignedTLSClientAuth:
            // RFC 8705 §2: the client is identified by `client_id` and authenticated by the
            // certificate it presented in the TLS handshake. No secret is sent, and sending
            // one would be a second, weaker credential travelling alongside a strong one.
            //
            // This transport cannot present a client certificate — `URLSession` on Linux has
            // no way to answer a client-certificate challenge, which the group E spike
            // established. A request assembled here with an mTLS method will therefore be
            // rejected by the server as unauthenticated. Use the NIO-backed transport, which
            // exists for exactly this.
            body["client_id"] = credentials.clientID
        }

        request.httpBody = Data(Self.formEncode(body).utf8)

        // Through the one door every credential-bearing request uses, which follows no
        // redirect: see `CredentialRequest`.
        let (data, http) = try await CredentialRequest.send(request, on: session)

        guard (200..<300).contains(http.statusCode) else {
            // A provider returns its reason in the body; the status alone does not
            // distinguish "wrong secret" from "revoked grant", and those need different
            // responses from the caller.
            // silent: a body that will not decode leaves only the status to report, which
            // the fallback below does
            if let body = try? JSONDecoder().decode(OAuthErrorResponse.self, from: data) {
                throw body.oauthError
            }
            throw OAuthError.serverError("HTTP \(http.statusCode)")
        }

        do {
            return try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw OAuthError.serverError("the token response could not be decoded")
        }
    }

    /// Percent-encodes form parameters.
    ///
    /// Sorted by key so the body is byte-identical for the same input — `Dictionary`
    /// iterates in a per-process order, which would otherwise make request bodies vary
    /// between runs and defeat any recorded-request testing.
    static func formEncode(_ parameters: [String: String]) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return parameters
            .sorted { $0.key < $1.key }
            .map { key, value in
                let k = key.addingPercentEncoding(withAllowedCharacters: allowed) ?? key
                let v = value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
                return "\(k)=\(v)"
            }
            .joined(separator: "&")
    }
}
