import Foundation
import Crypto
import SwiftOAuthCore

/// A provider store that lives in memory and goes away with the process.
///
/// For tests, and for a single process that does not need its grants to outlive it — a
/// development server, a demonstration. It is **not durable**: a restart forgets every client,
/// code and token, so every client must register again and every user sign in again. A
/// deployment that serves real users uses ``OAuthStorage``, or its own store, instead.
///
/// It is the same store as ``OAuthStorage`` from the server's side. Both pass
/// `SwiftOAuthProviderConformance`'s suite unchanged, and `OAuthServer` is written against
/// ``OAuthProviderStorage`` and cannot tell them apart. The semantics are copied rather than
/// reinvented: credentials are held under the same SHA-256 digests (so a token's raw value is
/// never a dictionary key), expiry is judged by the same comparisons against the same clock,
/// and the same operations are single-use. Being an actor makes each operation atomic, which is
/// what the SQLite store gets from its own actor.
///
/// ```swift
/// let server = OAuthServer(
///     storage: InMemoryOAuthStorage(),
///     issuer: "https://auth.example.com",
///     scopesSupported: ["read"], served: .none, resourceIdentity: identity)
/// ```
///
/// Nothing is ever evicted on its own. ``cleanupExpiredTokens()`` and
/// ``cleanupExpiredCSRFTokens()`` do what their ``OAuthStorage`` namesakes do; a process that
/// runs long enough to matter calls them.
public actor InMemoryOAuthStorage: OAuthProviderStorage {

    // MARK: - Records

    private struct ClientRecord {
        var client: RegisteredClient
        /// SHA-256 of the secret, or `nil`.
        var secretDigest: String?
    }

    private struct CodeRecord {
        var code: AuthorizationCode
        var consumed: Bool
    }

    private struct CSRFRecord {
        var clientId: String
        var redirectUri: String
        var expiresAt: Date
        var consumed: Bool
    }

    private struct AccessRecord {
        var clientId: String
        var scope: String?
        var expiresAt: Date
        var createdAt: Date
        var revoked: Bool
        var audience: URL?
        var keyThumbprint: String?
        var certificateThumbprint: String?
        var subject: String?
    }

    private struct RefreshRecord {
        var clientId: String
        var scope: String?
        var expiresAt: Date
        var revoked: Bool
        var subject: String?
    }

    private struct DeviceRecord {
        var userCodeDigest: String
        var clientId: String
        var scope: String?
        var subject: String?
        var approved: Bool
        var redeemed: Bool
        var denied: Bool
        var expiresAt: Date
        var lastPolledAt: Date?
        var pollInterval: TimeInterval
    }

    private struct PushedRecord {
        var clientId: String
        var request: PushedAuthorizationRequest
        var consumed: Bool
        var expiresAt: Date
    }

    // MARK: - State

    private var clients: [String: ClientRecord] = [:]
    private var codes: [String: CodeRecord] = [:]
    private var csrfTokens: [String: CSRFRecord] = [:]
    private var accessTokens: [String: AccessRecord] = [:]
    private var refreshTokens: [String: RefreshRecord] = [:]
    private var deviceCodes: [String: DeviceRecord] = [:]
    private var pushedRequests: [String: PushedRecord] = [:]

    /// RFC 8628 §3.2's default interval, used when a stored one is not usable.
    private static let defaultPollInterval: TimeInterval = 5

    /// What `slow_down` adds to the interval — RFC 8628 §3.5 names five seconds.
    private static let slowDownIncrement: TimeInterval = 5

    /// Creates an empty store.
    public init() {}

    // MARK: - Clients

    /// Saves or updates a client registration. See ``OAuthProviderStorage/saveClient(_:)``.
    public func saveClient(_ client: RegisteredClient) throws {
        // What is kept is the client without its secret, which is held only as a digest.
        let stored = RegisteredClient(
            clientId: client.clientId, clientSecret: nil, clientName: client.clientName,
            redirectUris: client.redirectUris, grantTypes: client.grantTypes,
            tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
            registrationDate: client.registrationDate, applicationType: client.applicationType,
            scopeCeiling: client.scopeCeiling)
        let presented = client.clientSecret.map(OAuthStorage.sha256Hex)
        if let existing = clients[client.clientId] {
            // As the SQLite upsert: a public client keeps no secret, anything else keeps the
            // one it has unless a new one is presented.
            let digest = client.tokenEndpointAuthMethod == "none"
                ? nil : (presented ?? existing.secretDigest)
            clients[client.clientId] = ClientRecord(client: stored, secretDigest: digest)
        } else {
            clients[client.clientId] = ClientRecord(client: stored, secretDigest: presented)
        }
    }

    /// A client by identifier, without its secret.
    public func getClient(clientId: String) throws -> RegisteredClient? {
        clients[clientId]?.client
    }

    /// Whether `presented` is the secret this client was registered with.
    public func clientSecretMatches(clientId: String, presented: String) throws -> Bool {
        guard let stored = clients[clientId]?.secretDigest else { return false }
        return TokenGenerator.timingSafeCompare(OAuthStorage.sha256Hex(presented), stored)
    }

    /// Deletes a client and its tokens and authorization codes.
    public func deleteClient(clientId: String) throws {
        accessTokens = accessTokens.filter { $0.value.clientId != clientId }
        refreshTokens = refreshTokens.filter { $0.value.clientId != clientId }
        codes = codes.filter { $0.value.code.clientId != clientId }
        clients[clientId] = nil
    }

    // MARK: - Authorization codes

    /// Saves an authorization code, replacing one with the same value and clearing its spent mark.
    public func saveAuthorizationCode(_ code: AuthorizationCode) throws {
        codes[code.code] = CodeRecord(code: code, consumed: false)
    }

    /// Returns the code and spends it, or `nil` if it is unknown or already spent.
    public func consumeAuthorizationCode(code: String) throws -> AuthorizationCode? {
        guard var record = codes[code], !record.consumed else { return nil }
        record.consumed = true
        codes[code] = record
        return record.code
    }

    // MARK: - CSRF tokens

    /// Issues a CSRF token binding a consent form to one client and redirect URI.
    public func generateCSRFToken(
        clientId: String,
        redirectUri: String,
        expiresIn: TimeInterval = 600
    ) throws -> String {
        let key = SymmetricKey(size: .bits256)
        let token = key.withUnsafeBytes { bytes in
            bytes.map { ($0 < 16 ? "0" : "") + String($0, radix: 16, uppercase: false) }.joined()
        }
        csrfTokens[token] = CSRFRecord(
            clientId: clientId, redirectUri: redirectUri,
            expiresAt: Date().addingTimeInterval(expiresIn), consumed: false)
        return token
    }

    /// Validates a CSRF token for this client and redirect URI, and spends it if valid.
    public func validateCSRFToken(
        token: String,
        clientId: String,
        redirectUri: String
    ) throws -> CSRFValidationResult {
        guard var record = csrfTokens[token] else {
            return CSRFValidationResult(isValid: false, error: "Token not found")
        }
        if record.consumed {
            return CSRFValidationResult(isValid: false, error: "Token already used")
        }
        if Date() >= record.expiresAt {
            return CSRFValidationResult(isValid: false, error: "Token expired")
        }
        if record.clientId != clientId {
            return CSRFValidationResult(isValid: false, error: "Client ID mismatch")
        }
        if record.redirectUri != redirectUri {
            return CSRFValidationResult(isValid: false, error: "Redirect URI mismatch")
        }
        record.consumed = true
        csrfTokens[token] = record
        return CSRFValidationResult(isValid: true)
    }

    /// Removes expired CSRF tokens, returning how many.
    @discardableResult
    public func cleanupExpiredCSRFTokens() throws -> Int {
        let now = Date()
        let before = csrfTokens.count
        csrfTokens = csrfTokens.filter { $0.value.expiresAt >= now }
        return before - csrfTokens.count
    }

    // MARK: - Access tokens

    /// Saves an access token under its digest, replacing one with the same value.
    public func saveAccessToken(
        token: String,
        clientId: String,
        scope: String?,
        expiresAt: Date,
        audience: URL? = nil,
        keyThumbprint: String? = nil,
        certificateThumbprint: String? = nil,
        subject: String? = nil
    ) throws {
        accessTokens[OAuthStorage.sha256Hex(token)] = AccessRecord(
            clientId: clientId, scope: scope, expiresAt: expiresAt, createdAt: Date(),
            revoked: false, audience: audience, keyThumbprint: keyThumbprint,
            certificateThumbprint: certificateThumbprint, subject: subject)
    }

    /// Whether a token may be honoured, and what is known about it when it may.
    public func validateAccessToken(token: String) throws -> TokenValidationResult {
        guard let record = accessTokens[OAuthStorage.sha256Hex(token)] else {
            return .invalid(reason: "Token not found")
        }
        if record.revoked {
            return .invalid(reason: "Token revoked")
        }
        if Date() >= record.expiresAt {
            return .invalid(reason: "Token expired")
        }
        return .valid(TokenValidationResult.ValidatedToken(
            clientId: record.clientId, scope: record.scope, audience: record.audience,
            keyThumbprint: record.keyThumbprint,
            certificateThumbprint: record.certificateThumbprint, subject: record.subject))
    }

    /// Everything RFC 7662 reports about an access token; inactive, alike, when it is not live.
    public func introspectAccessToken(token: String) throws -> IntrospectionResult {
        guard let record = accessTokens[OAuthStorage.sha256Hex(token)],
              !record.revoked, Date() < record.expiresAt else {
            return .inactive
        }
        // No `iss` here: storage does not know which issuer it serves. `OAuthServer` adds it.
        return IntrospectionResult(
            active: true,
            scope: record.scope,
            clientId: record.clientId,
            subject: record.subject,
            audience: record.audience.map { [$0.absoluteString] },
            expiry: record.expiresAt,
            issuedAt: record.createdAt)
    }

    /// Revokes one access token. An unknown token is not an error.
    public func revokeAccessToken(token: String) throws {
        accessTokens[OAuthStorage.sha256Hex(token)]?.revoked = true
    }

    /// Revokes every access and refresh token issued to a client.
    public func revokeAllTokensForClient(clientId: String) throws {
        for key in accessTokens.keys where accessTokens[key]?.clientId == clientId {
            accessTokens[key]?.revoked = true
        }
        for key in refreshTokens.keys where refreshTokens[key]?.clientId == clientId {
            refreshTokens[key]?.revoked = true
        }
    }

    /// Ends everything one user holds. See ``OAuthProviderStorage/revokeAllTokens(forSubject:)``.
    @discardableResult
    public func revokeAllTokens(forSubject subject: String) throws -> Int {
        var changed = 0
        for key in accessTokens.keys where accessTokens[key]?.subject == subject && accessTokens[key]?.revoked == false {
            accessTokens[key]?.revoked = true
            changed += 1
        }
        for key in refreshTokens.keys where refreshTokens[key]?.subject == subject && refreshTokens[key]?.revoked == false {
            refreshTokens[key]?.revoked = true
            changed += 1
        }
        for key in codes.keys where codes[key]?.code.subject == subject && codes[key]?.consumed == false {
            codes[key]?.consumed = true
            changed += 1
        }
        for key in deviceCodes.keys {
            guard let record = deviceCodes[key], record.subject == subject,
                  record.approved, !record.denied, !record.redeemed else { continue }
            deviceCodes[key]?.redeemed = true
            changed += 1
        }
        return changed
    }

    // MARK: - Refresh tokens

    /// Saves a refresh token under its digest, replacing one with the same value.
    public func saveRefreshToken(
        token: String,
        clientId: String,
        scope: String?,
        expiresAt: Date,
        subject: String? = nil
    ) throws {
        refreshTokens[OAuthStorage.sha256Hex(token)] = RefreshRecord(
            clientId: clientId, scope: scope, expiresAt: expiresAt, revoked: false, subject: subject)
    }

    /// A live refresh token's details, or `nil` if it is unknown, expired or revoked.
    public func getRefreshTokenInfo(token: String) throws -> RefreshTokenInfo? {
        guard let record = refreshTokens[OAuthStorage.sha256Hex(token)] else { return nil }
        if record.revoked || Date() >= record.expiresAt { return nil }
        return RefreshTokenInfo(
            clientId: record.clientId, scope: record.scope,
            expiresAt: record.expiresAt, subject: record.subject)
    }

    /// Removes expired access tokens, refresh tokens and authorization codes, returning how many.
    @discardableResult
    public func cleanupExpiredTokens() throws -> Int {
        let now = Date()
        let before = accessTokens.count + refreshTokens.count + codes.count
        accessTokens = accessTokens.filter { $0.value.expiresAt >= now }
        refreshTokens = refreshTokens.filter { $0.value.expiresAt >= now }
        codes = codes.filter { $0.value.code.expiresAt >= now }
        return before - (accessTokens.count + refreshTokens.count + codes.count)
    }

    // MARK: - Device codes

    /// Stores a device code and its user code, both as digests.
    ///
    /// - Throws: ``OAuthStorageError`` if either code is already stored, as the SQLite store's
    ///   uniqueness constraints do.
    public func saveDeviceCode(
        deviceCode: String,
        userCode: String,
        clientId: String,
        scope: String?,
        expiresAt: Date,
        interval: TimeInterval = 5,
        now: Date = Date()
    ) throws {
        let key = OAuthStorage.sha256Hex(deviceCode)
        let userDigest = OAuthStorage.userCodeDigest(userCode)
        guard deviceCodes[key] == nil, !deviceCodes.values.contains(where: { $0.userCodeDigest == userDigest }) else {
            throw OAuthStorageError.databaseError("Execution failed: UNIQUE constraint failed: device_codes")
        }
        deviceCodes[key] = DeviceRecord(
            userCodeDigest: userDigest, clientId: clientId, scope: scope, subject: nil,
            approved: false, redeemed: false, denied: false, expiresAt: expiresAt,
            lastPolledAt: nil, pollInterval: interval)
    }

    /// The key of the live, unanswered device code a user code names, if any.
    private func unansweredKey(userCode: String, now: Date) -> String? {
        let digest = OAuthStorage.userCodeDigest(userCode)
        return deviceCodes.first { _, record in
            record.userCodeDigest == digest && !record.approved && !record.denied
                && !record.redeemed && record.expiresAt > now
        }?.key
    }

    /// Approves a live, unanswered user code, recording who approved it.
    public func approveDeviceCode(
        userCode: String, subject: String, now: Date = Date()
    ) throws -> Bool {
        guard let key = unansweredKey(userCode: userCode, now: now) else { return false }
        deviceCodes[key]?.approved = true
        deviceCodes[key]?.subject = subject
        return true
    }

    /// Denies a live, unanswered user code.
    public func denyDeviceCode(
        userCode: String, subject: String, now: Date = Date()
    ) throws -> Bool {
        guard let key = unansweredKey(userCode: userCode, now: now) else { return false }
        deviceCodes[key]?.denied = true
        deviceCodes[key]?.subject = subject
        return true
    }

    /// The client and scope behind a live, unanswered user code, or `nil`.
    public func pendingDeviceCode(
        userCode: String, now: Date = Date()
    ) throws -> (clientId: String, scope: String?)? {
        guard let key = unansweredKey(userCode: userCode, now: now),
              let record = deviceCodes[key] else { return nil }
        return (record.clientId, record.scope)
    }

    /// Records a poll, and says whether it came too soon — RFC 8628 §3.5 `slow_down`.
    public func pacePendingPoll(deviceCode: String, now: Date = Date()) throws -> Bool {
        let key = OAuthStorage.sha256Hex(deviceCode)
        guard let record = deviceCodes[key] else { return false }
        let interval = record.pollInterval.isFinite && record.pollInterval > 0
            ? record.pollInterval : Self.defaultPollInterval
        let tooSoon = record.lastPolledAt.map { now.timeIntervalSince($0) < interval } ?? false
        deviceCodes[key]?.lastPolledAt = now
        deviceCodes[key]?.pollInterval = tooSoon ? interval + Self.slowDownIncrement : interval
        return tooSoon
    }

    /// What a device code currently is, for the client redeeming it.
    public func deviceCodeState(
        deviceCode: String, clientId: String, now: Date = Date()
    ) throws -> DeviceCodeState {
        guard let record = deviceCodes[OAuthStorage.sha256Hex(deviceCode)] else { return .unknown }
        // The client check comes before everything else: a device code seen in transit is
        // otherwise redeemable by anyone who can name a client id.
        guard record.clientId == clientId else { return .unknown }
        guard !record.redeemed else { return .alreadyRedeemed }
        guard now < record.expiresAt else { return .expired }
        guard !record.denied else { return .denied }
        return record.approved ? .approved(scope: record.scope, subject: record.subject) : .pending
    }

    /// Spends a device code. `true` only for the call that spent it.
    @discardableResult
    public func markDeviceCodeRedeemed(deviceCode: String) throws -> Bool {
        let key = OAuthStorage.sha256Hex(deviceCode)
        guard let record = deviceCodes[key], !record.redeemed else { return false }
        deviceCodes[key]?.redeemed = true
        return true
    }

    // MARK: - Pushed authorization requests

    /// Stores a pushed request under the digest of its reference.
    ///
    /// - Throws: ``OAuthStorageError`` if the reference is already stored.
    public func savePushedRequest(
        requestURI: String,
        clientId: String,
        redirectUri: String,
        scope: String?,
        state: String?,
        codeChallenge: String?,
        codeChallengeMethod: String?,
        expiresAt: Date
    ) throws {
        let key = OAuthStorage.sha256Hex(requestURI)
        guard pushedRequests[key] == nil else {
            throw OAuthStorageError.databaseError("Execution failed: UNIQUE constraint failed: pushed_requests")
        }
        pushedRequests[key] = PushedRecord(
            clientId: clientId,
            request: PushedAuthorizationRequest(
                redirectUri: redirectUri, scope: scope, state: state,
                codeChallenge: codeChallenge, codeChallengeMethod: codeChallengeMethod),
            consumed: false, expiresAt: expiresAt)
    }

    /// Returns what was pushed and spends it; `nil` if unknown, expired, spent or another client's.
    public func consumePushedRequest(
        requestURI: String, clientId: String
    ) throws -> PushedAuthorizationRequest? {
        let key = OAuthStorage.sha256Hex(requestURI)
        guard let record = pushedRequests[key], record.clientId == clientId,
              !record.consumed, record.expiresAt > Date() else { return nil }
        pushedRequests[key]?.consumed = true
        return record.request
    }
}
