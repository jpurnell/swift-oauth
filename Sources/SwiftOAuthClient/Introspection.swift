import Foundation
#if canImport(FoundationNetworking)
// `URLSession` and `URLRequest` live here on Linux rather than in Foundation.
import FoundationNetworking
#endif
import SwiftOAuthCore

/// How an introspection request reaches the network.
///
/// A protocol for the same reason the token transport is one: the behaviour worth testing is
/// what this package sends and how it reads the answer, and neither needs a socket.
public protocol IntrospectionTransport: Sendable {
    /// Posts a form-encoded body and returns the response with its status.
    func post(url: URL, body: String, authorization: String?) async throws -> (Data, Int)
}

/// Asks an authorization server about a token — RFC 7662, client half.
///
/// This is what a resource server uses. A bearer token is opaque to whoever receives it, so
/// without this a resource server either trusts the string it was handed or builds this itself
/// on top of the package.
///
/// ## Inactive is a result, not an error
///
/// ``introspect(token:)`` returns an inactive result rather than throwing for a token that is
/// expired, revoked or unknown, and throws only when the request itself failed. Collapsing the
/// two would leave a caller unable to tell a revoked token from an unreachable authorization
/// server — the first means reject the request, the second means retry or fail open, and they
/// are never the same decision.
public struct TokenIntrospector: Sendable {

    /// What this resource server authenticates as.
    public struct Credentials: Sendable {
        /// The client identifier issued to this resource server.
        public let clientId: String
        /// Its secret.
        public let clientSecret: String

        /// Creates credentials for the introspection endpoint.
        public init(clientId: String, clientSecret: String) {
            self.clientId = clientId
            self.clientSecret = clientSecret
        }

        /// The `Authorization` header value, as RFC 6749 §2.3.1 defines it.
        var basicAuthorization: String {
            let pair = Data("\(clientId):\(clientSecret)".utf8).base64EncodedString()
            return "Basic \(pair)"
        }
    }

    private let endpoint: URL
    private let credentials: Credentials
    private let transport: any IntrospectionTransport

    /// Creates an introspector.
    ///
    /// - Parameters:
    ///   - endpoint: The authorization server's introspection endpoint.
    ///   - credentials: What this resource server authenticates as. The endpoint is protected
    ///     — RFC 7662 §2.1 — so there is no unauthenticated form of this call.
    ///   - transport: How the request reaches the network.
    public init(
        endpoint: URL,
        credentials: Credentials,
        transport: any IntrospectionTransport = URLSessionIntrospectionTransport()
    ) {
        self.endpoint = endpoint
        self.credentials = credentials
        self.transport = transport
    }

    /// Asks whether a token is active, and what it is for.
    ///
    /// - Parameter token: The token to ask about.
    /// - Returns: The server's answer, active or not.
    /// - Throws: If the request failed or the response could not be read. **Not** for an
    ///   inactive token, which is an answer.
    public func introspect(token: String) async throws -> IntrospectionResult {
        // Form-encoded body, not a query string. A token in a URL is a token in access logs,
        // proxy logs and anything else that records a path — RFC 7662 §2.1 specifies a body
        // for that reason.
        let body = "token=\(Self.formEncoded(token))"
        let (data, status) = try await transport.post(
            url: endpoint, body: body, authorization: credentials.basicAuthorization)

        guard (200..<300).contains(status) else {
            throw OAuthError.serverError(
                "The introspection endpoint answered \(status).")
        }
        return try JSONDecoder().decode(IntrospectionResult.self, from: data)
    }

    /// Percent-encodes a form value.
    private static func formEncoded(_ value: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }
}

/// The default transport, over `URLSession`.
public struct URLSessionIntrospectionTransport: IntrospectionTransport {

    /// Creates a transport.
    public init() {}

    /// Posts the form body and returns the response with its status.
    public func post(url: URL, body: String, authorization: String?) async throws -> (Data, Int) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue(authorization, forHTTPHeaderField: "Authorization")
        request.httpBody = Data(body.utf8)

        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        return (data, status)
    }
}
