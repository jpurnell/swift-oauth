import Foundation
import SwiftOAuthCore

/// Where an ``OAuthServer`` keeps its clients, codes and tokens.
///
/// The server is written against this protocol and cannot tell one conforming store from
/// another. Two ship in the package: ``OAuthStorage``, the SQLite store a deployment runs on,
/// and ``InMemoryOAuthStorage``, for tests and single-process use. A deployment that keeps its
/// state somewhere else writes a third, and proves it with `SwiftOAuthProviderConformance`: the
/// suite there is the definition of "conforms", and both shipped stores pass it unchanged.
///
/// ## What a store promises
///
/// - **Credentials are not kept in the clear.** Access, refresh and device tokens, pushed
///   request references, user codes and client secrets are held as digests, so reading the
///   store yields nothing redeemable. A client read back carries no secret.
/// - **Single-use means once.** An authorization code, a CSRF token, a pushed request and a
///   device code are each spent by the first caller that presents them, including when two
///   callers present one at the same instant.
/// - **A subject is data, and `nil` is a value.** The subject saved with a code, token or
///   approval is returned with it unchanged, `nil` included. A store never invents one.
/// - **Dead credentials look alike.** Unknown, expired, revoked and belonging-to-another-client
///   are not told apart where telling them apart would let a caller probe what exists.
///
/// ## What the requirements are
///
/// Exactly the operations ``OAuthServer`` performs, and no more. ``OAuthStorage`` has further
/// public methods (cleanup, schema inspection, DPoP proof identifiers); those are the SQLite
/// store's own and a conforming store need not offer them.
///
/// The requirements carry no default arguments, because a protocol requirement cannot. A caller
/// holding the concrete ``OAuthStorage`` keeps its defaults; a caller holding
/// `any OAuthProviderStorage` passes every argument.
///
/// Errors a store raises are ``OAuthStorageError``. A requirement that answers "not found"
/// returns `nil` or `false` rather than throwing.
public protocol OAuthProviderStorage: Sendable {

    // MARK: Clients

    /// Saves or updates a client registration.
    ///
    /// The secret, when there is one, is stored as a digest and never returned. Saving a client
    /// with no secret keeps the one already stored, so updating a client's other fields cannot
    /// erase its credential; saving one with a secret replaces it. A client saved with
    /// `token_endpoint_auth_method` `none` keeps no secret at all.
    func saveClient(_ client: RegisteredClient) async throws

    /// A client by identifier, with `clientSecret == nil`; `nil` if there is no such client.
    func getClient(clientId: String) async throws -> RegisteredClient?

    /// Whether `presented` is the secret this client was registered with.
    ///
    /// `false` for an unknown client and for a client with no secret, so a public client can
    /// never authenticate as a confidential one.
    func clientSecretMatches(clientId: String, presented: String) async throws -> Bool

    /// Deletes a client and its tokens and authorization codes.
    func deleteClient(clientId: String) async throws

    // MARK: Authorization codes

    /// Saves an authorization code, with its subject, audience and PKCE challenge.
    func saveAuthorizationCode(_ code: AuthorizationCode) async throws

    /// Returns the code and spends it, or `nil` if it is unknown or already spent.
    ///
    /// RFC 6749 §4.1.2: a code is single-use. Concurrent callers presenting one code are
    /// answered with it exactly once between them.
    func consumeAuthorizationCode(code: String) async throws -> AuthorizationCode?

    // MARK: CSRF tokens

    /// Issues a token binding a consent form to one client and redirect URI.
    ///
    /// - Parameters:
    ///   - clientId: The client the consent form is for.
    ///   - redirectUri: The redirect URI the form will send the user to.
    ///   - expiresIn: Its lifetime in seconds. ``OAuthStorage`` defaults to ten minutes.
    func generateCSRFToken(clientId: String, redirectUri: String, expiresIn: TimeInterval) async throws -> String

    /// Validates a token for this client and redirect URI, and spends it if valid.
    func validateCSRFToken(token: String, clientId: String, redirectUri: String) async throws -> CSRFValidationResult

    // MARK: Access tokens

    /// Saves an access token under its digest.
    func saveAccessToken(
        token: String,
        clientId: String,
        scope: String?,
        expiresAt: Date,
        audience: URL?,
        keyThumbprint: String?,
        certificateThumbprint: String?,
        subject: String?
    ) async throws

    /// Whether a token may be honoured, and what is known about it when it may.
    func validateAccessToken(token: String) async throws -> TokenValidationResult

    /// What RFC 7662 §2.2 reports about a token: its claims if active, and
    /// `IntrospectionResult.inactive` — alike — for one that is expired, revoked or unknown.
    func introspectAccessToken(token: String) async throws -> IntrospectionResult

    /// Revokes one access token. Revoking an unknown token is not an error (RFC 7009 §2.2).
    func revokeAccessToken(token: String) async throws

    /// Revokes every access and refresh token issued to a client.
    func revokeAllTokensForClient(clientId: String) async throws

    // MARK: Refresh tokens

    /// Saves a refresh token under its digest.
    func saveRefreshToken(
        token: String, clientId: String, scope: String?, expiresAt: Date, subject: String?
    ) async throws

    /// A live refresh token's client, scope, expiry and subject; `nil` if it is unknown,
    /// expired or revoked.
    func getRefreshTokenInfo(token: String) async throws -> RefreshTokenInfo?

    // MARK: Device codes (RFC 8628)

    /// Stores a device code and the user code a person will type, both as digests.
    ///
    /// - Parameters:
    ///   - deviceCode: The device's credential.
    ///   - userCode: The code a person will type.
    ///   - clientId: The client the codes belong to.
    ///   - scope: What it asked for.
    ///   - expiresAt: When both codes stop working.
    ///   - interval: The polling interval the device was told, in seconds.
    ///   - now: When the codes were issued.
    func saveDeviceCode(
        deviceCode: String,
        userCode: String,
        clientId: String,
        scope: String?,
        expiresAt: Date,
        interval: TimeInterval,
        now: Date
    ) async throws

    /// Approves a live, unanswered user code, recording who approved it.
    ///
    /// A user code is matched however it was typed: case and punctuation do not matter.
    ///
    /// - Returns: `false` for a code that is unknown, expired or already answered — one answer
    ///   for all three.
    func approveDeviceCode(userCode: String, subject: String, now: Date) async throws -> Bool

    /// Denies a live, unanswered user code. Same answers as ``approveDeviceCode(userCode:subject:now:)``.
    func denyDeviceCode(userCode: String, subject: String, now: Date) async throws -> Bool

    /// The client and scope behind a live, unanswered user code, or `nil`.
    func pendingDeviceCode(userCode: String, now: Date) async throws -> (clientId: String, scope: String?)?

    /// Records a poll and says whether it came sooner than the code's interval after the last.
    ///
    /// A poll that is too soon widens the interval by five seconds for this and every later
    /// poll — RFC 8628 §3.5 `slow_down`. The first poll is never too soon. Unknown codes are
    /// never too soon.
    func pacePendingPoll(deviceCode: String, now: Date) async throws -> Bool

    /// What a device code currently is, for the client redeeming it. Another client's code,
    /// and an unknown one, are both ``DeviceCodeState/unknown``.
    func deviceCodeState(deviceCode: String, clientId: String, now: Date) async throws -> DeviceCodeState

    /// Spends a device code. `true` for exactly one of any number of concurrent callers.
    @discardableResult
    func markDeviceCodeRedeemed(deviceCode: String) async throws -> Bool

    // MARK: Pushed authorization requests (RFC 9126)

    /// Stores a pushed request under the digest of its reference.
    func savePushedRequest(
        requestURI: String,
        clientId: String,
        redirectUri: String,
        scope: String?,
        state: String?,
        codeChallenge: String?,
        codeChallengeMethod: String?,
        expiresAt: Date
    ) async throws

    /// Returns what was pushed and spends it; `nil` if the reference is unknown, expired,
    /// spent, or another client's — one answer for all four.
    func consumePushedRequest(requestURI: String, clientId: String) async throws -> PushedAuthorizationRequest?
}

extension OAuthStorage: OAuthProviderStorage {}
