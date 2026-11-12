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
/// public methods (cleanup, schema inspection); those are the SQLite
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
    ///
    /// `grantId` is the grant this token was issued under, or `nil` for a token that belongs to
    /// none (a `client_credentials` or exchanged token, or a caller that does not track grants).
    /// See ``revokeGrant(grantId:)``.
    func saveAccessToken(
        token: String,
        clientId: String,
        scope: String?,
        expiresAt: Date,
        audience: URL?,
        keyThumbprint: String?,
        certificateThumbprint: String?,
        subject: String?,
        grantId: String?
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

    /// Ends everything one user holds: access and refresh tokens on every client, authorization
    /// codes not yet spent, and device codes the user approved but the device has not redeemed.
    ///
    /// The codes matter. Revoking only the tokens would leave a disabled user's approved device
    /// grant, or a code issued a moment ago, to mint fresh ones afterwards. A code is ended by
    /// marking it spent, a device code by marking it redeemed, so each then fails as any spent
    /// credential does.
    ///
    /// **Rows with no subject are not reachable.** A token, code or approval stored with a
    /// `nil` subject (every row from before schema 9, and any grant a deployment made without
    /// saying who approved) matches no subject and is left alone; those are revocable by client
    /// only. A device code names nobody until a user answers it, so a pending one is likewise
    /// out of reach.
    ///
    /// - Parameter subject: The user, exactly as it was recorded when the grant was made.
    /// - Returns: How many credentials changed state: those that were live and now are not.
    ///   Credentials already revoked, spent or redeemed are not counted, so a second call
    ///   returns 0, as does a subject nobody holds anything for.
    @discardableResult
    func revokeAllTokens(forSubject subject: String) async throws -> Int

    // MARK: Refresh tokens

    /// Saves a refresh token under its digest.
    ///
    /// `grantId` is the grant this token was issued under, or `nil`. See ``revokeGrant(grantId:)``.
    func saveRefreshToken(
        token: String, clientId: String, scope: String?, expiresAt: Date, subject: String?,
        grantId: String?
    ) async throws

    /// A live refresh token's client, scope, expiry, subject and grant; `nil` if it is unknown,
    /// expired, revoked, or already spent by ``claimRefreshToken(token:clientId:defaultGrantId:now:)``.
    func getRefreshTokenInfo(token: String) async throws -> RefreshTokenInfo?

    /// Spends a refresh token so that it can be exchanged for a successor — rotation, RFC 9700
    /// §4.14.2 — once, and remembers that it was spent.
    ///
    /// The row is kept, marked, not deleted: "information about the relationship is retained by
    /// the authorization server", so a second presentation reads as ``RefreshTokenClaim/replayed(grantId:)``
    /// and not as an unknown token. Concurrent callers presenting one token are answered
    /// ``RefreshTokenClaim/claimed(_:)`` exactly once between them and the rest as replays.
    /// A token spent this way is no longer returned by ``getRefreshTokenInfo(token:)``.
    ///
    /// A token with no grant (from before schema 11, or saved with none) is given
    /// `defaultGrantId` by this call, so that its successors share a grant and its replay can
    /// reach them. A token that has one keeps it.
    ///
    /// Only the client the token was issued to can claim it, or replay it: for any other client
    /// the answer is ``RefreshTokenClaim/unusable`` and the token is left as it was.
    ///
    /// - Parameters:
    ///   - token: The refresh token as presented.
    ///   - clientId: The authenticated client presenting it.
    ///   - defaultGrantId: A grant to give the token if it has none.
    ///   - now: The time to judge expiry by.
    func claimRefreshToken(
        token: String, clientId: String, defaultGrantId: String, now: Date
    ) async throws -> RefreshTokenClaim

    /// Revokes a refresh token on behalf of the client it was issued to, and with it the rest of
    /// its grant — RFC 7009 §2.1: "the authorization server SHOULD also invalidate all access
    /// tokens based on the same authorization grant".
    ///
    /// Finds the row in whatever state it is in. An expired or already revoked token is still
    /// the client's to revoke, and the grant's other tokens may still be live. A token issued
    /// to another client is left exactly as it is and reads as not found: a client must not be
    /// able to end another's grant, or to learn that a token exists.
    ///
    /// A token with no grant (every row from before schema 11) revokes only itself.
    ///
    /// - Returns: How many live tokens were revoked, the refresh token included (a refresh token
    ///   already spent by rotation is not live and is not counted); 0 for an unknown token, another client's, or one whose grant was already ended.
    @discardableResult
    func revokeRefreshToken(token: String, clientId: String) async throws -> Int

    /// Revokes every access and refresh token issued under one grant.
    ///
    /// A grant is the authorization a user gave once: the label the server puts on the access
    /// and refresh tokens that one code (or approved device code) produced, and on every token
    /// refreshed from them. Tokens with no grant are never matched.
    ///
    /// - Returns: How many tokens changed from live to revoked. 0 for an unknown grant and for
    ///   one already ended.
    @discardableResult
    func revokeGrant(grantId: String) async throws -> Int

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

    // MARK: DPoP proof identifiers (RFC 9449 §11.1)

    /// Records a DPoP proof's `jti`, refusing one already recorded.
    ///
    /// `true` for exactly one of any number of callers presenting the same identifier, including
    /// concurrently: the store decides, not a read followed by a write. `expiresAt` is no earlier
    /// than the proof stops being acceptable; a record may be dropped after it.
    func claimProofIdentifier(_ identifier: String, expiresAt: Date) async throws -> Bool

    /// Drops proof identifiers whose `expiresAt` is at or before `now`; returns how many.
    ///
    /// After this an identifier whose window has passed can be claimed again, which is safe
    /// because a proof that old fails the freshness check before it reaches the store.
    @discardableResult
    func sweepExpiredProofIdentifiers(now: Date) async throws -> Int
}

extension OAuthProviderStorage {

    /// Saves an access token that belongs to no grant.
    ///
    /// The requirement takes a `grantId`; this is the call as it was before grants existed, for
    /// a caller (a `client_credentials` token, a test) that has none.
    public func saveAccessToken(
        token: String,
        clientId: String,
        scope: String?,
        expiresAt: Date,
        audience: URL?,
        keyThumbprint: String?,
        certificateThumbprint: String?,
        subject: String?
    ) async throws {
        try await saveAccessToken(
            token: token, clientId: clientId, scope: scope, expiresAt: expiresAt,
            audience: audience, keyThumbprint: keyThumbprint,
            certificateThumbprint: certificateThumbprint, subject: subject, grantId: nil)
    }

    /// Saves a refresh token that belongs to no grant. See
    /// ``saveAccessToken(token:clientId:scope:expiresAt:audience:keyThumbprint:certificateThumbprint:subject:)``.
    public func saveRefreshToken(
        token: String, clientId: String, scope: String?, expiresAt: Date, subject: String?
    ) async throws {
        try await saveRefreshToken(
            token: token, clientId: clientId, scope: scope, expiresAt: expiresAt,
            subject: subject, grantId: nil)
    }
}

extension OAuthStorage: OAuthProviderStorage {}
