import Foundation

/// A token response, per RFC 6749 §5.1.
///
/// The one model both halves must agree on: a provider produces it, a client
/// consumes it. Its coding keys are the wire names, so it decodes a third
/// party's response — Intuit's, Google's — as readily as one this package issued.
public struct TokenResponse: Codable, Sendable, Equatable {

    /// The access token itself.
    public let accessToken: String

    /// The token type. Always `Bearer` in practice; RFC 6750 defines no other in
    /// common use.
    public let tokenType: String

    /// Lifetime of the access token, in seconds from issuance.
    ///
    /// Seconds rather than an absolute date because that is what the wire
    /// carries — converting to a `Date` requires knowing when the response was
    /// *received*, which only the caller does. ``expiry(from:)`` does that
    /// conversion where the receipt time is known.
    public let expiresIn: Int

    /// A refresh token, when the provider issued one.
    public let refreshToken: String?

    /// The granted scope.
    ///
    /// May differ from what was requested: RFC 6749 §3.3 permits a provider to
    /// grant less. A client that assumes it received what it asked for will fail
    /// later, at a call it has no reason to associate with the grant.
    public let scope: String?

    /// How long the refresh token remains valid, in seconds, when the provider
    /// says.
    ///
    /// Not in RFC 6749. Intuit and others send `x_refresh_token_expires_in`, and
    /// a client that ignores it cannot tell a connection that is about to lapse
    /// from one that is healthy.
    public let refreshTokenExpiresIn: Int?

    private enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case scope
        case refreshTokenExpiresIn = "x_refresh_token_expires_in"
    }

    /// Creates a token response.
    public init(
        accessToken: String,
        tokenType: String = "Bearer",
        expiresIn: Int,
        refreshToken: String? = nil,
        scope: String? = nil,
        refreshTokenExpiresIn: Int? = nil
    ) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.refreshToken = refreshToken
        self.scope = scope
        self.refreshTokenExpiresIn = refreshTokenExpiresIn
    }

    /// When the access token expires, given when this response was received.
    ///
    /// - Parameter received: When the response arrived.
    /// - Returns: The absolute expiry.
    public func expiry(from received: Date) -> Date {
        received.addingTimeInterval(TimeInterval(expiresIn))
    }

    /// When the refresh token expires, if the provider said.
    ///
    /// - Parameter received: When the response arrived.
    /// - Returns: The absolute expiry, or `nil` if unstated.
    public func refreshExpiry(from received: Date) -> Date? {
        refreshTokenExpiresIn.map { received.addingTimeInterval(TimeInterval($0)) }
    }

    /// The scopes granted, split on the space RFC 6749 §3.3 specifies.
    public var scopes: [String] {
        scope?.split(separator: " ").map(String.init) ?? []
    }
}

extension TokenResponse: CustomStringConvertible, CustomDebugStringConvertible {

    /// Redacts both tokens.
    ///
    /// Interpolating a token response into a log is the ordinary way an access
    /// token escapes. Making the default rendering safe means exposing one takes
    /// deliberate effort.
    public var description: String {
        let refresh = refreshToken == nil ? "none" : "<redacted>"
        return """
            TokenResponse(accessToken: <redacted>, tokenType: \(tokenType), \
            expiresIn: \(expiresIn), refreshToken: \(refresh), \
            scope: \(scope ?? "none"))
            """
    }

    /// The same redacted rendering, so `String(reflecting:)` cannot expose what
    /// ``description`` hides.
    public var debugDescription: String { description }
}
