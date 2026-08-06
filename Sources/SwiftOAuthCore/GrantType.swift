import Foundation

/// The grant types this package supports.
///
/// Two, deliberately. RFC 6749 defines four; OAuth 2.1 removes two of them, and
/// they are absent here rather than merely discouraged:
///
/// - **Implicit** (`response_type=token`) returns an access token in a redirect
///   fragment, where it lands in browser history and referrer headers. The
///   authorization code flow with PKCE covers the same case without that.
/// - **Resource owner password credentials** requires the user to hand their
///   password to the client, which is the arrangement OAuth exists to avoid.
///
/// Modelling the omission as *absence* rather than a rejected case means a
/// provider built on this cannot accidentally support them, and a client cannot
/// request them.
public enum GrantType: String, Codable, Sendable, Equatable, CaseIterable {

    /// Exchange an authorization code for tokens. RFC 6749 §4.1.
    ///
    /// The only flow for obtaining a first token here, and PKCE is required with
    /// it — see ``PKCE``.
    case authorizationCode = "authorization_code"

    /// Exchange a refresh token for a new access token. RFC 6749 §6.
    case refreshToken = "refresh_token"
}

/// The response types this package supports.
///
/// One: `code`. `token` is the implicit flow, which OAuth 2.1 removes.
public enum ResponseType: String, Codable, Sendable, Equatable, CaseIterable {

    /// An authorization code, to be exchanged at the token endpoint.
    case code
}

/// How a client authenticates at the token endpoint.
public enum ClientAuthenticationMethod: String, Codable, Sendable, Equatable, CaseIterable {

    /// HTTP Basic, with the client id and secret as the credentials.
    /// RFC 6749 §2.3.1 states servers *should* support this, and most require it.
    case clientSecretBasic = "client_secret_basic"

    /// The client id and secret in the request body.
    ///
    /// Permitted but discouraged: parameters are logged by intermediaries far
    /// more often than headers are.
    case clientSecretPost = "client_secret_post"

    /// No client authentication.
    ///
    /// For public clients — native and browser applications — which cannot keep
    /// a secret. PKCE is what protects these, which is why it is not optional.
    case none
}
