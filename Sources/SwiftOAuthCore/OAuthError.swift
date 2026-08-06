import Foundation

/// An OAuth error, per RFC 6749 §5.2.
///
/// The error codes are a closed set defined by the specification, and both
/// halves need them: a provider emits them, a client interprets them. A client
/// that treats every failure alike cannot tell "retry with a different scope"
/// from "the user revoked you, ask again" — remedies that are not interchangeable.
public enum OAuthError: Error, Sendable, Equatable, Codable {

    /// The request is missing a parameter, or repeats one.
    case invalidRequest(String?)

    /// Client authentication failed.
    ///
    /// Worth special attention: a provider must not distinguish "no such client"
    /// from "wrong secret", so this arrives with no detail by design — which is
    /// also why it is miserable to debug. The usual cause is credentials from
    /// one environment presented to another.
    case invalidClient(String?)

    /// The grant — authorization code, refresh token — is invalid, expired,
    /// revoked, or was issued to another client.
    ///
    /// For a client holding a refresh token, this is the signal to re-authorise.
    /// It does *not* distinguish a revoked grant from one lost to a rotation the
    /// client failed to persist.
    case invalidGrant(String?)

    /// The client is not permitted this grant type.
    case unauthorizedClient(String?)

    /// The grant type is not supported by this server.
    case unsupportedGrantType(String?)

    /// The requested scope is invalid, unknown, or exceeds what was granted.
    case invalidScope(String?)

    /// The server failed in a way the specification does not enumerate.
    case serverError(String?)

    /// The server is temporarily unable to handle the request.
    case temporarilyUnavailable(String?)

    /// The resource owner or server denied the request.
    case accessDenied(String?)

    /// The wire value, per RFC 6749 §5.2.
    public var code: String {
        switch self {
        case .invalidRequest: return "invalid_request"
        case .invalidClient: return "invalid_client"
        case .invalidGrant: return "invalid_grant"
        case .unauthorizedClient: return "unauthorized_client"
        case .unsupportedGrantType: return "unsupported_grant_type"
        case .invalidScope: return "invalid_scope"
        case .serverError: return "server_error"
        case .temporarilyUnavailable: return "temporarily_unavailable"
        case .accessDenied: return "access_denied"
        }
    }

    /// The human-readable detail, when the server supplied one.
    public var detail: String? {
        switch self {
        case .invalidRequest(let d), .invalidClient(let d), .invalidGrant(let d),
             .unauthorizedClient(let d), .unsupportedGrantType(let d),
             .invalidScope(let d), .serverError(let d),
             .temporarilyUnavailable(let d), .accessDenied(let d):
            return d
        }
    }

    /// Builds an error from a wire code.
    ///
    /// An unrecognised code becomes ``serverError(_:)`` carrying the original,
    /// rather than being discarded: a provider may emit an extension code, and
    /// losing it leaves an operator with nothing to search for.
    ///
    /// - Parameters:
    ///   - code: The `error` field.
    ///   - description: The `error_description` field, if present.
    public init(code: String, description: String? = nil) {
        switch code {
        case "invalid_request": self = .invalidRequest(description)
        case "invalid_client": self = .invalidClient(description)
        case "invalid_grant": self = .invalidGrant(description)
        case "unauthorized_client": self = .unauthorizedClient(description)
        case "unsupported_grant_type": self = .unsupportedGrantType(description)
        case "invalid_scope": self = .invalidScope(description)
        case "server_error": self = .serverError(description)
        case "temporarily_unavailable": self = .temporarilyUnavailable(description)
        case "access_denied": self = .accessDenied(description)
        default: self = .serverError(description.map { "\(code): \($0)" } ?? code)
        }
    }

    /// Whether retrying the same request might succeed.
    ///
    /// Only two codes are transient. Retrying an `invalid_grant` cannot help and
    /// costs the user a wait before the re-authorisation they actually need.
    public var isTransient: Bool {
        switch self {
        case .temporarilyUnavailable, .serverError: return true
        default: return false
        }
    }

    /// Whether the remedy is for the user to authorise again.
    ///
    /// A client that retries these forever, rather than prompting, leaves the
    /// user with an application that silently does nothing.
    public var requiresReauthorization: Bool {
        switch self {
        case .invalidGrant, .accessDenied: return true
        default: return false
        }
    }
}

extension OAuthError: CustomStringConvertible {

    /// The code, with the server's detail when there is one.
    public var description: String {
        detail.map { "\(code): \($0)" } ?? code
    }
}

/// The error body an authorization server returns, per RFC 6749 §5.2.
public struct OAuthErrorResponse: Codable, Sendable, Equatable {

    /// The error code.
    public let error: String

    /// Human-readable detail.
    public let errorDescription: String?

    /// A page describing the error.
    public let errorURI: String?

    private enum CodingKeys: String, CodingKey {
        case error
        case errorDescription = "error_description"
        case errorURI = "error_uri"
    }

    /// Creates an error response.
    public init(error: String, errorDescription: String? = nil, errorURI: String? = nil) {
        self.error = error
        self.errorDescription = errorDescription
        self.errorURI = errorURI
    }

    /// Creates an error response from a typed error.
    public init(_ error: OAuthError) {
        self.error = error.code
        self.errorDescription = error.detail
        self.errorURI = nil
    }

    /// The typed error this body describes.
    public var oauthError: OAuthError {
        OAuthError(code: error, description: errorDescription)
    }
}
