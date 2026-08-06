import Foundation
import SwiftOAuthCore

/// Why a connection could not produce a usable token.
public enum ConnectionError: Error, Equatable, Sendable {

    /// Nothing is stored for this connection — it was never authorised, or was disconnected.
    case notConnected

    /// The provider rejected the grant. The user must authorise again.
    ///
    /// Carries whether a *previous* refresh token was on record, because that distinguishes
    /// the two causes: with one, this may be a rotation the client failed to persist; with
    /// none, the user revoked access.
    case reauthorizationRequired(hadPreviousToken: Bool)

    /// The provider returned tokens with no refresh token.
    ///
    /// Refused rather than stored: a connection that cannot be renewed will stop working
    /// within the hour, and storing it promises something that is not true.
    case noRefreshTokenIssued

    /// The credential could not be persisted.
    ///
    /// Serious after a rotation, because the token just replaced is already dead at the
    /// provider. The new one is returned to the caller so a retry has something to store.
    case storageFailed(recovered: StoredCredential)
}

/// One application's connection to one account at one provider.
///
/// ## What this is for
///
/// Callers want an access token. They should not have to know about expiry, rotation, or
/// persistence — those are the parts everyone gets subtly differently, and the differences
/// only show up as a user locked out of their own data.
///
/// So the interface is one method: ``validAccessToken()``.
///
/// ## The three hazards it exists to handle
///
/// Presenting a refresh token returns a new pair and **expires the one presented**. Three
/// failures follow, and every one of them ends with a user re-authorising rather than an
/// error anyone can read.
///
/// **Concurrent refresh.** Two requests find an expired token, both refresh, both succeed —
/// and the second invalidates the first's refresh token. Whichever stored last wins; the
/// other holds a dead credential.
///
/// > This is an actor, and a refresh in flight is awaited rather than duplicated. Concurrent
/// > callers get the same result from one exchange.
///
/// **A crash between receiving and persisting.** The old token is already dead at the
/// provider; the new one exists only in memory.
///
/// > The credential is written **before** the new access token is returned. A crash costs a
/// > request rather than the connection. If the write fails, the new credential comes back
/// > inside ``ConnectionError/storageFailed(recovered:)`` so a caller can retry rather than
/// > lose it.
///
/// **A revocation that looks like a lost rotation.** `invalid_grant` means either — and the
/// remedies are opposite.
///
/// > ``StoredCredential/previousRefreshToken`` is retained, and
/// > ``ConnectionError/reauthorizationRequired(hadPreviousToken:)`` reports whether one
/// > existed, so the two can be told apart after the fact.
public actor OAuthConnection {

    private let configuration: ProviderConfiguration
    private let credentials: ClientCredentials
    private let storage: any OAuthClientStorage
    private let transport: any TokenTransport
    private let connection: ConnectionID
    private let now: @Sendable () -> Date

    /// A refresh already under way, awaited by anyone who arrives during it.
    private var refreshInFlight: Task<StoredCredential, Error>?

    /// Creates a connection.
    ///
    /// - Parameters:
    ///   - configuration: The provider's endpoints and scope.
    ///   - credentials: The application's client identifier and secret.
    ///   - storage: Where credentials live.
    ///   - connection: Which tenant, provider and account this is.
    ///   - transport: How requests reach the provider. Injectable so tests never touch the
    ///     network.
    ///   - now: The current time. Injectable so expiry is testable without waiting.
    public init(
        configuration: ProviderConfiguration,
        credentials: ClientCredentials,
        storage: any OAuthClientStorage,
        connection: ConnectionID,
        transport: any TokenTransport = URLSessionTokenTransport(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.configuration = configuration
        self.credentials = credentials
        self.storage = storage
        self.connection = connection
        self.transport = transport
        self.now = now
    }

    // MARK: - Authorising

    /// Where to send the user to authorise this connection.
    ///
    /// - Parameters:
    ///   - state: An opaque value returned on the callback. Generate it unpredictably and
    ///     check it there — it is what prevents an attacker completing a flow the user did
    ///     not start.
    ///   - challenge: A PKCE challenge. Keep its verifier; it is needed at ``exchange(authorizationCode:verifier:)``.
    ///   - redirectURI: Where the provider sends the user back. Must match one registered
    ///     with the provider exactly.
    /// - Returns: The URL to open.
    public func authorizationURL(
        state: String,
        challenge: String,
        redirectURI: String
    ) -> URL {
        var components = URLComponents(
            url: configuration.authorizationEndpoint,
            resolvingAgainstBaseURL: false)

        components?.queryItems = [
            URLQueryItem(name: "response_type", value: ResponseType.code.rawValue),
            URLQueryItem(name: "client_id", value: credentials.clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "scope", value: configuration.scope),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: PKCE.ChallengeMethod.s256.rawValue)
        ]
        return components?.url ?? configuration.authorizationEndpoint
    }

    /// Starts an authorization: generates the state and PKCE pair, and builds the URL.
    ///
    /// Preferred over calling ``authorizationURL(state:challenge:redirectURI:)`` directly,
    /// because it makes the two things a caller must not get wrong impossible to get wrong:
    /// the state is generated rather than chosen, and the verifier is kept rather than sent.
    /// A caller who assembles the URL by hand can pick a predictable state, and a predictable
    /// state is no protection.
    ///
    /// - Parameter redirectURI: Where the provider sends the user back. Must match one
    ///   registered with the provider exactly.
    /// - Returns: The URL to open, and what to hold until the callback arrives.
    public func beginAuthorization(redirectURI: String) -> BegunAuthorization {
        let state = TokenGenerator.generateToken()
        let verifier = PKCE.generateCodeVerifier()

        // A verifier this function just generated is valid by construction; the throwing path
        // exists for verifiers from elsewhere. Falling back to the verifier itself would be
        // `plain` by accident, so an empty challenge is used instead — the provider rejects
        // it, which is the correct outcome for a state that should be unreachable.
        // silent: unreachable for a generated verifier, and the fallback fails closed
        let challenge = (try? PKCE.generateCodeChallenge(verifier: verifier, method: .s256)) ?? ""

        return BegunAuthorization(
            url: authorizationURL(state: state, challenge: challenge, redirectURI: redirectURI),
            pending: PendingAuthorization(
                state: state, verifier: verifier, redirectURI: redirectURI))
    }

    /// Completes an authorization from the provider's callback.
    ///
    /// The callback is validated **before** anything is sent to the token endpoint. Exchanging
    /// first and checking afterwards would burn the code and, worse, tell an attacker whose
    /// forged callback it was that their code was accepted.
    ///
    /// - Parameters:
    ///   - callback: The redirect URI as received, query intact.
    ///   - pending: What ``beginAuthorization(redirectURI:)`` returned.
    /// - Returns: The stored credential.
    /// - Throws: ``CallbackError`` if the callback is not this flow's, otherwise
    ///   ``ConnectionError`` or ``OAuthError``.
    @discardableResult
    public func completeAuthorization(
        callback: URL,
        pending: PendingAuthorization
    ) async throws -> StoredCredential {
        let code = try AuthorizationCallback.code(from: callback, matching: pending)
        return try await exchange(
            authorizationCode: code,
            verifier: pending.verifier,
            redirectURI: pending.redirectURI)
    }

    /// Exchanges an authorization code for tokens, and stores them.
    ///
    /// - Parameters:
    ///   - authorizationCode: The code from the callback. Single-use and short-lived.
    ///   - verifier: The PKCE verifier matching the challenge sent earlier.
    ///   - redirectURI: The same value sent to the authorization endpoint.
    /// - Returns: The stored credential.
    /// - Throws: ``ConnectionError`` or ``OAuthError``.
    @discardableResult
    public func exchange(
        authorizationCode: String,
        verifier: String,
        redirectURI: String
    ) async throws -> StoredCredential {
        let response = try await transport.exchange(
            endpoint: configuration.tokenEndpoint,
            parameters: [
                "grant_type": GrantType.authorizationCode.rawValue,
                "code": authorizationCode,
                "redirect_uri": redirectURI,
                "code_verifier": verifier
            ],
            credentials: credentials,
            method: configuration.authenticationMethod)

        guard let credential = StoredCredential(from: response, received: now()) else {
            throw ConnectionError.noRefreshTokenIssued
        }
        try await persist(credential)
        return credential
    }

    // MARK: - Using

    /// An access token that is valid now, refreshing first if necessary.
    ///
    /// The whole interface for a caller. Expiry, rotation and persistence do not surface.
    ///
    /// - Returns: A token safe to present on an API call.
    /// - Throws: ``ConnectionError`` or ``OAuthError``.
    public func validAccessToken() async throws -> String {
        guard let stored = try await storage.credential(for: connection) else {
            throw ConnectionError.notConnected
        }
        guard stored.needsRefresh(at: now()) else {
            return stored.accessToken
        }
        return try await refreshed(from: stored).accessToken
    }

    /// The stored credential, if any. For inspection — a caller wanting a token should use
    /// ``validAccessToken()``.
    public func currentCredential() async throws -> StoredCredential? {
        try await storage.credential(for: connection)
    }

    /// Forgets this connection, and revokes it at the provider where possible.
    ///
    /// The local credential is removed **even if revocation fails**: a user who asked to
    /// disconnect should not remain connected because the provider was unreachable. Where
    /// the provider offers no revocation endpoint, the access token stays valid at the
    /// provider until it expires, and there is nothing a client can do about that.
    public func disconnect() async throws {
        // silent: a credential we cannot read is one we cannot revoke; removal still proceeds
        let stored = try? await storage.credential(for: connection)
        try await storage.remove(connection)

        guard let endpoint = configuration.revocationEndpoint, let stored else { return }
        // The local credential is already gone; an unreachable provider must not undo that.
        // silent: revocation is best-effort, and its failure changes nothing the caller can act on
        _ = try? await transport.exchange(
            endpoint: endpoint,
            parameters: ["token": stored.refreshToken, "token_type_hint": "refresh_token"],
            credentials: credentials,
            method: configuration.authenticationMethod)
    }

    // MARK: - Refreshing

    /// Refreshes, joining a refresh already under way rather than starting a second.
    private func refreshed(from stored: StoredCredential) async throws -> StoredCredential {
        // Two callers arriving at once must not both refresh: the second exchange would
        // invalidate the first's new refresh token, and one of them would be left holding a
        // credential the provider has already forgotten.
        if let existing = refreshInFlight {
            return try await existing.value
        }

        let task = Task<StoredCredential, Error> { [configuration, credentials, transport, now] in
            let response = try await transport.exchange(
                endpoint: configuration.tokenEndpoint,
                parameters: [
                    "grant_type": GrantType.refreshToken.rawValue,
                    "refresh_token": stored.refreshToken
                ],
                credentials: credentials,
                method: configuration.authenticationMethod)

            let received = now()
            // A provider that rotates returns a new refresh token; one that does not omits
            // it, and the existing token remains valid. Both are legitimate.
            let credential = StoredCredential(
                accessToken: response.accessToken,
                refreshToken: response.refreshToken ?? stored.refreshToken,
                accessExpiry: response.expiry(from: received),
                refreshExpiry: response.refreshExpiry(from: received) ?? stored.refreshExpiry,
                previousRefreshToken: stored.refreshToken,
                rotatedAt: received,
                scope: response.scope ?? stored.scope)
            return credential
        }
        refreshInFlight = task

        defer { refreshInFlight = nil }

        do {
            let credential = try await task.value
            try await persist(credential)
            return credential
        } catch let error as OAuthError where error.requiresReauthorization {
            // Either the user revoked access, or a rotation was lost. The remedies differ,
            // and only the presence of a previous token distinguishes them.
            throw ConnectionError.reauthorizationRequired(
                hadPreviousToken: stored.previousRefreshToken != nil)
        }
    }

    /// Writes a credential, and reports a failure in a form the caller can act on.
    ///
    /// Persisting *before* the token is used is what makes a crash survivable. When the
    /// write itself fails the new credential is handed back inside the error, because the
    /// token it replaced is already dead at the provider — losing it here costs the user
    /// their connection.
    private func persist(_ credential: StoredCredential) async throws {
        do {
            try await storage.store(credential, for: connection)
        } catch {
            throw ConnectionError.storageFailed(recovered: credential)
        }
    }
}
