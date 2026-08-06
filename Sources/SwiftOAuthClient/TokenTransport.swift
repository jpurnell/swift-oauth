import Foundation
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
    /// - Throws: ``OAuthError`` for anything the provider rejected, or a transport error.
    func exchange(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws -> TokenResponse
}

/// A transport over `URLSession`.
public struct URLSessionTokenTransport: TokenTransport {

    private let session: URLSession

    /// Creates a transport.
    ///
    /// - Parameter session: The session to use. Defaults to `.shared`.
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
    /// - Throws: ``OAuthError`` for anything the provider rejected, or a transport error.
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
        }

        request.httpBody = Data(Self.formEncode(body).utf8)

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw OAuthError.serverError("the response was not HTTP")
        }

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
