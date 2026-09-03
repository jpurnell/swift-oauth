import Foundation

/// The grant types this package supports.
///
/// Two of RFC 6749's four are absent here rather than merely discouraged,
/// because OAuth 2.1 removes them:
///
/// - **Implicit** (`response_type=token`) returns an access token in a redirect
///   fragment, where it lands in browser history and referrer headers. The
///   authorization code flow with PKCE covers the same case without that.
/// - **Resource owner password credentials** requires the user to hand their
///   password to the client, which is the arrangement OAuth exists to avoid.
///
/// Modelling those omissions as *absence* rather than rejected cases means a
/// provider built on this cannot accidentally support them, and a client cannot
/// request them.
///
/// ## Why client credentials is present
///
/// ``clientCredentials`` was once excluded alongside those two. That conflated
/// two different things. OAuth 2.1 keeps the client-credentials grant — it is
/// the standard way one machine authenticates to another, with no resource owner
/// because there genuinely is no user in the interaction. Excluding it did not
/// make anything safer; it made this package unable to consume a large class of
/// third-party APIs at all, since many offer no alternative.
///
/// The safety concern it appeared to address is real but lives elsewhere: a
/// *provider* issuing client-credentials tokens would grant access with no user
/// involved. That is prevented where it should be —
/// `OAuthServer.handleTokenRequest(_:)` dispatches on the raw wire string and
/// rejects any grant it does not implement — not by making the value
/// unconstructible for clients that legitimately need to request it.
public enum GrantType: String, Codable, Sendable, Equatable, CaseIterable {

    /// Exchange an authorization code for tokens. RFC 6749 §4.1.
    ///
    /// The only flow for obtaining a first token here, and PKCE is required with
    /// it — see ``PKCE``.
    case authorizationCode = "authorization_code"

    /// Exchange a refresh token for a new access token. RFC 6749 §6.
    case refreshToken = "refresh_token"

    /// Authenticate as the client itself, with no resource owner. RFC 6749 §4.4.
    ///
    /// For machine-to-machine access where no user is involved and none should
    /// be. **Client-side only**: this package's provider does not issue these,
    /// and requesting one from an `OAuthServer` returns `unsupported_grant_type`.
    case clientCredentials = "client_credentials"

    /// Sign in on a device that cannot open a browser. RFC 8628.
    ///
    /// The wire value is a URN rather than a short name, which the specification requires and
    /// which is easy to get wrong: a server matching on `"device_code"` refuses every
    /// conformant client, and the refusal looks like an unsupported grant rather than a typo.
    case deviceCode = "urn:ietf:params:oauth:grant-type:device_code"
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
