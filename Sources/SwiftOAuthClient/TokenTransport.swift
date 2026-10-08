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

    /// Asks a revocation endpoint to revoke a token — RFC 7009 §2.1.
    ///
    /// Separate from ``exchange(endpoint:parameters:credentials:method:)`` because the answer
    /// is a different thing. RFC 7009 §2.2: "The authorization server responds with HTTP
    /// status code 200 if the token has been revoked successfully or if the client submitted
    /// an invalid token", and "the content of the response body is ignored by the client as
    /// all necessary information is conveyed in the response code." A successful revocation
    /// has no token response to decode, so a transport that insists on one reports every
    /// success as a failure.
    ///
    /// The default implementation calls ``exchange(endpoint:parameters:credentials:method:)``
    /// and discards what it returns, which is right for a transport that answers from a
    /// script. **A transport that talks to a real server should implement this**, returning
    /// normally for a `2xx` whatever the body and throwing otherwise.
    ///
    /// - Parameters:
    ///   - endpoint: The revocation endpoint.
    ///   - parameters: The form body, unencoded: `token`, and optionally `token_type_hint`.
    ///   - credentials: Used for client authentication.
    ///   - method: How the credentials should be presented.
    /// - Throws: If the request could not be made or the endpoint did not answer with
    ///   success. Returning normally means the provider confirmed the revocation.
    func revoke(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws
}

extension TokenTransport {

    /// Revokes by making an exchange and discarding its result.
    ///
    /// - Parameters:
    ///   - endpoint: The revocation endpoint.
    ///   - parameters: The form body, unencoded.
    ///   - credentials: Used for client authentication.
    ///   - method: How the credentials should be presented.
    /// - Throws: Whatever the exchange throws.
    public func revoke(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws {
        _ = try await exchange(
            endpoint: endpoint, parameters: parameters, credentials: credentials, method: method)
    }
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
/// ## The default session keeps nothing
///
/// ``init()`` sends on a session of this package's own: ephemeral, with no cookie storage, no
/// credential storage and no cache. A cookie a token endpoint sets is not stored and not
/// returned, and a `401` challenge is not answered from the process's credential store. It
/// was `URLSession.shared` until this version, which does both.
///
/// ``init(session:)`` uses the session you give it, as configured — cookie jar, credential
/// storage, cache, proxy, timeouts. Pass `URLSession.shared` to have the old behaviour back.
/// On Linux the request is made on a short-lived session built from that session's
/// `configuration`, so its configuration is honoured and its *delegate* is not consulted;
/// swift-corelibs-foundation offers no other way to stop reading a response part-way.
///
/// ## The answer is bounded
///
/// No more than ``OAuthResponseTooLarge/maximumResponseBytes`` of a response body is read. A
/// longer one cancels the transfer and throws ``OAuthResponseTooLarge``.
///
/// `URLSession` is thread-safe and documented as such, but corelibs-foundation has not always
/// marked it `Sendable` — so the stored property passes the check on Apple platforms and has
/// failed on Linux alone. The value is immutable and never mutated after init.
// Justification: URLSession is thread-safe; the stored session is immutable after init.
public struct URLSessionTokenTransport: TokenTransport, @unchecked Sendable {

    private let session: URLSession

    /// A certificate to accept in tests; always `nil` for a transport a caller can build.
    private let trust: TestServerTrust?

    /// Creates a transport on this package's own session, which keeps no cookies, stored
    /// credentials or cache between requests.
    public init() {
        self.session = CredentialRequest.isolatedSession
        self.trust = nil
    }

    /// Creates a transport on a session you supply.
    ///
    /// - Parameter session: The session to use, with whatever cookie storage, credential
    ///   storage and cache its configuration has. Whatever its configuration or delegate, a
    ///   redirect is not followed on it and a response past the size limit is not read. On
    ///   Linux its configuration is used and its delegate is not; see the type's discussion.
    public init(session: URLSession) {
        self.session = session
        self.trust = nil
    }

    #if !canImport(FoundationNetworking)
    /// Creates a transport that accepts a named server certificate. **Tests only.**
    ///
    /// Internal, and the only way a ``TestServerTrust`` reaches a token request: nothing a
    /// caller of the public API can pass, set or configure produces one.
    ///
    /// - Parameter trust: The certificates to accept.
    init(trusting trust: TestServerTrust) {
        self.session = CredentialRequest.isolatedSession
        self.trust = trust
    }
    #endif

    /// Posts the form to the endpoint over HTTP.
    ///
    /// - Parameters:
    ///   - endpoint: Where to send it.
    ///   - parameters: The form body, unencoded.
    ///   - credentials: Used for client authentication.
    ///   - method: How the credentials should be presented.
    /// - Returns: The provider's token response.
    /// - Throws: `OAuthError` for anything the provider rejected, ``OAuthRedirectRefused`` if
    ///   the endpoint answered with a redirect — which is not followed —
    ///   ``OAuthResponseTooLarge`` if it sent more than this package reads, or a transport
    ///   error.
    public func exchange(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws -> TokenResponse {
        let (data, http) = try await post(
            endpoint: endpoint, parameters: parameters, credentials: credentials, method: method)
        try Self.requireSuccess(http, data)

        do {
            return try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw OAuthError.serverError("the token response could not be decoded")
        }
    }

    /// Posts a revocation request and reads only the status of the answer.
    ///
    /// RFC 7009 §2.2: a `200` means the token is revoked, or was not valid to begin with, and
    /// "the content of the response body is ignored by the client". Any `2xx` is taken as
    /// that confirmation, since a `204` says the same thing with less. Anything else throws —
    /// including a `503`, after which §2.2.1 has the client "assume the token still exists".
    ///
    /// - Parameters:
    ///   - endpoint: The revocation endpoint.
    ///   - parameters: The form body, unencoded: `token`, and optionally `token_type_hint`.
    ///   - credentials: Used for client authentication.
    ///   - method: How the credentials should be presented.
    /// - Throws: `OAuthError` for a refusal the provider explained or a status that is not
    ///   success, ``OAuthRedirectRefused`` for a redirect, ``OAuthResponseTooLarge`` for an
    ///   answer past the size limit, or a transport error.
    public func revoke(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws {
        let (data, http) = try await post(
            endpoint: endpoint, parameters: parameters, credentials: credentials, method: method)
        try Self.requireSuccess(http, data)
    }

    /// Throws unless the status is a `2xx`.
    ///
    /// - Parameters:
    ///   - http: The response.
    ///   - data: Its body, read for the provider's reason.
    /// - Throws: The provider's `OAuthError`, or `OAuthError.serverError` naming the status.
    private static func requireSuccess(_ http: HTTPURLResponse, _ data: Data) throws {
        guard (200..<300).contains(http.statusCode) else {
            // A provider returns its reason in the body; the status alone does not
            // distinguish "wrong secret" from "revoked grant", and those need different
            // responses from the caller.
            // silent: a body that will not decode leaves only the status to report, which the fallback below does
            if let body = try? JSONDecoder().decode(OAuthErrorResponse.self, from: data) {
                throw body.oauthError
            }
            throw OAuthError.serverError("HTTP \(http.statusCode)")
        }
    }

    /// Builds the form request, authenticates it, and sends it.
    ///
    /// - Parameters:
    ///   - endpoint: Where to send it.
    ///   - parameters: The form body, unencoded.
    ///   - credentials: Used for client authentication.
    ///   - method: How the credentials should be presented.
    /// - Returns: The body and the response, whatever its status.
    /// - Throws: ``OAuthRedirectRefused``, ``OAuthResponseTooLarge``, or a transport error.
    private func post(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws -> (Data, HTTPURLResponse) {
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
        return try await CredentialRequest.send(request, on: session, trust: trust)
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
