import Foundation
import Testing
@testable import SwiftOAuthCore

/// These models are the contract between the two halves, and with every
/// third-party provider. A wrong coding key decodes to `nil` rather than
/// failing, so an absent field and a misnamed one look identical.
@Suite("TokenResponse — the wire")
struct TokenResponseTests {

    /// Shaped as a real provider sends it, snake_case throughout.
    private let json = """
    {
      "access_token": "the-access-token",
      "token_type": "Bearer",
      "expires_in": 3600,
      "refresh_token": "the-refresh-token",
      "scope": "com.intuit.quickbooks.accounting openid",
      "x_refresh_token_expires_in": 8726400
    }
    """

    @Test("A provider's response decodes")
    func decodes() throws {
        let response = try JSONDecoder().decode(TokenResponse.self, from: Data(json.utf8))
        #expect(response.accessToken == "the-access-token")
        #expect(response.tokenType == "Bearer")
        #expect(response.expiresIn == 3600)
        #expect(response.refreshToken == "the-refresh-token")
        #expect(response.refreshTokenExpiresIn == 8_726_400)
    }

    /// A misnamed key decodes to `nil` rather than throwing, so absence and
    /// misspelling are indistinguishable without asserting the value.
    @Test("Optional fields are absent, not silently nil from a wrong key")
    func absentFieldsAreAbsent() throws {
        let minimal = """
        {"access_token":"t","token_type":"Bearer","expires_in":3600}
        """
        let response = try JSONDecoder().decode(TokenResponse.self, from: Data(minimal.utf8))
        #expect(response.refreshToken == nil)
        #expect(response.scope == nil)
        #expect(response.refreshTokenExpiresIn == nil)
        // And the required fields did arrive, so the keys are right.
        #expect(response.accessToken == "t")
        #expect(response.expiresIn == 3600)
    }

    @Test("It round-trips through encoding")
    func roundTrips() throws {
        let original = try JSONDecoder().decode(TokenResponse.self, from: Data(json.utf8))
        let encoded = try JSONEncoder().encode(original)
        let restored = try JSONDecoder().decode(TokenResponse.self, from: encoded)
        #expect(restored == original)
    }

    /// `expires_in` is a duration; only the caller knows when the response
    /// arrived, so the conversion takes that as an argument.
    @Test("Expiry is computed from when the response was received")
    func expiryFromReceipt() throws {
        let response = try JSONDecoder().decode(TokenResponse.self, from: Data(json.utf8))
        let received = Date(timeIntervalSince1970: 1_000_000)
        #expect(response.expiry(from: received) == received.addingTimeInterval(3600))
        #expect(response.refreshExpiry(from: received)
                == received.addingTimeInterval(8_726_400))
    }

    /// RFC 6749 §3.3 lets a provider grant *less* scope than requested. A client
    /// that assumes otherwise fails later, at a call it will not connect to the grant.
    @Test("Granted scopes are split on spaces")
    func scopesSplit() throws {
        let response = try JSONDecoder().decode(TokenResponse.self, from: Data(json.utf8))
        #expect(response.scopes == ["com.intuit.quickbooks.accounting", "openid"])

        let none = TokenResponse(accessToken: "t", expiresIn: 60)
        #expect(none.scopes.isEmpty)
    }

    /// Interpolating a token response into a log is the ordinary way an access
    /// token escapes.
    @Test("Neither token appears in a rendered description")
    func tokensRedacted() throws {
        let response = try JSONDecoder().decode(TokenResponse.self, from: Data(json.utf8))
        for rendered in ["\(response)", String(reflecting: response)] {
            #expect(!rendered.contains("the-access-token"), "access token was rendered")
            #expect(!rendered.contains("the-refresh-token"), "refresh token was rendered")
            #expect(rendered.contains("<redacted>"))
        }
        // Non-secret fields stay visible, or the rendering is useless.
        #expect("\(response)".contains("3600"))
    }
}

@Suite("OAuthError — the closed set")
struct OAuthErrorTests {

    @Test("Every case maps to its RFC 6749 §5.2 code", arguments: [
        (OAuthError.invalidRequest(nil), "invalid_request"),
        (.invalidClient(nil), "invalid_client"),
        (.invalidGrant(nil), "invalid_grant"),
        (.unauthorizedClient(nil), "unauthorized_client"),
        (.unsupportedGrantType(nil), "unsupported_grant_type"),
        (.invalidScope(nil), "invalid_scope"),
        (.serverError(nil), "server_error"),
        (.temporarilyUnavailable(nil), "temporarily_unavailable"),
        (.accessDenied(nil), "access_denied")
    ])
    func codesMatchSpec(error: OAuthError, code: String) {
        #expect(error.code == code)
        #expect(OAuthError(code: code).code == code, "\(code) did not round-trip")
    }

    /// A provider may emit an extension code. Discarding it leaves an operator
    /// with nothing to search for.
    @Test("An unrecognised code is preserved rather than discarded")
    func unknownCodePreserved() {
        let error = OAuthError(code: "consent_required", description: "user must approve")
        #expect(error.code == "server_error")
        let detail = error.detail ?? ""
        #expect(detail.contains("consent_required"), "the original code was lost: \(detail)")
        #expect(detail.contains("user must approve"))
    }

    /// Retrying an `invalid_grant` cannot help, and costs the user a wait before
    /// the re-authorisation they actually need.
    @Test("Only genuinely transient failures are retryable")
    func transienceIsNarrow() {
        #expect(OAuthError.temporarilyUnavailable(nil).isTransient)
        #expect(OAuthError.serverError(nil).isTransient)
        for permanent: OAuthError in [.invalidGrant(nil), .invalidClient(nil),
                                      .invalidScope(nil), .accessDenied(nil)] {
            #expect(!permanent.isTransient, "\(permanent.code) was treated as retryable")
        }
    }

    /// A client that retries these forever, rather than prompting, leaves the
    /// user with an application that silently does nothing.
    @Test("Re-authorisation is signalled where it is the only remedy")
    func reauthorizationSignalled() {
        #expect(OAuthError.invalidGrant(nil).requiresReauthorization)
        #expect(OAuthError.accessDenied(nil).requiresReauthorization)
        #expect(!OAuthError.serverError(nil).requiresReauthorization)
        #expect(!OAuthError.temporarilyUnavailable(nil).requiresReauthorization)
    }

    @Test("An error body decodes and converts both ways")
    func errorBodyRoundTrips() throws {
        let body = """
        {"error":"invalid_grant","error_description":"Token expired"}
        """
        let decoded = try JSONDecoder().decode(OAuthErrorResponse.self, from: Data(body.utf8))
        #expect(decoded.oauthError == .invalidGrant("Token expired"))
        #expect(OAuthErrorResponse(decoded.oauthError).error == "invalid_grant")
    }
}

@Suite("Grant types — what is absent")
struct GrantTypeTests {

    /// OAuth 2.1 removes implicit and password. Modelling the omission as
    /// absence rather than a rejected case means a provider built on this cannot
    /// accidentally support them.
    @Test("The grants OAuth 2.1 removes stay unconstructible")
    func removedGrantsAbsent() {
        #expect(GrantType(rawValue: "password") == nil, "the password grant is constructible")
        #expect(GrantType(rawValue: "implicit") == nil)
    }

    /// `client_credentials` is a different case from those two and was previously
    /// lumped in with them. OAuth 2.1 keeps it — it is the standard grant for
    /// machine-to-machine access, and a client consuming a third-party API often
    /// has no other option. Excluding it did not make anything safer; it made this
    /// package unable to talk to providers like eBay's Browse API at all.
    ///
    /// Safety is preserved where it actually matters: ``OAuthServer`` dispatches on
    /// the raw wire string with a rejecting `default`, so a provider built on this
    /// still cannot issue client-credentials tokens. See ``ProviderRejectsClientCredentials``.
    @Test("client_credentials is available to the client half")
    func clientCredentialsAvailable() {
        #expect(GrantType(rawValue: "client_credentials") == .clientCredentials)
        #expect(GrantType.clientCredentials.rawValue == "client_credentials")
        // The full set, pinned deliberately. The two grants OAuth 2.1 removes are absent
        // rather than rejected, and this assertion is what would notice one reappearing.
        // `deviceCode` joined it in 0.10.0 — RFC 8628, for anything without a browser —
        // and `tokenExchange` in 0.14.0, RFC 8693, for a service acting with a token it was
        // given rather than one it obtained.
        #expect(Set(GrantType.allCases)
            == [.authorizationCode, .refreshToken, .clientCredentials,
                .deviceCode, .tokenExchange])
    }

    @Test("Only the code response type exists")
    func onlyCodeResponse() {
        #expect(ResponseType.allCases == [.code])
        #expect(ResponseType(rawValue: "token") == nil, "the implicit flow is constructible")
    }

    @Test("Grant types carry their wire values")
    func wireValues() {
        #expect(GrantType.authorizationCode.rawValue == "authorization_code")
        #expect(GrantType.refreshToken.rawValue == "refresh_token")
    }

    @Test("Client authentication methods cover the registered set")
    func authMethods() {
        // Pinned deliberately, so a new method is a decision rather than an accident. The two
        // mTLS methods joined in 0.13.0 — RFC 8705, where a client is authenticated by the
        // certificate it presents in the handshake rather than by a secret it sends.
        #expect(Set(ClientAuthenticationMethod.allCases)
                == [.clientSecretBasic, .clientSecretPost, .none,
                    .tlsClientAuth, .selfSignedTLSClientAuth])
        #expect(ClientAuthenticationMethod.clientSecretBasic.rawValue == "client_secret_basic")
    }
}
