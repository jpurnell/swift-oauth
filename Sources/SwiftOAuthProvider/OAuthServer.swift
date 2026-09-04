import Foundation
import SwiftOAuthCore

/// OAuth 2.0 Authorization Server implementation
///
/// Implements RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 7591 (Dynamic Client Registration),
/// and RFC 8414 (Authorization Server Metadata).
///
/// ## Overview
///
/// `OAuthServer` provides the complete OAuth 2.0 authorization code flow:
/// 1. Client registration (dynamic or pre-configured)
/// 2. Authorization request handling
/// 3. Token issuance and refresh
/// 4. Token validation and revocation
///
/// ## Example
///
/// ```swift
/// // The three request values arrive from the wire; this shows what the server
/// // does with them, not how they are parsed.
/// func serve(
///     request: ClientRegistrationRequest,
///     authRequest: AuthorizationRequest,
///     tokenRequest: TokenRequest
/// ) async throws {
///     let storage = try OAuthStorage(path: "~/.businessmath-mcp/oauth.db")
///     let server = await OAuthServer(
///         storage: storage,
///         issuer: "https://mcp.example.com",
///         // What this deployment offers, and what it routes. Neither has a default: a
///         // document that promises scopes or endpoints nobody serves is worse than one that
///         // promises nothing.
///         scopesSupported: ["files:read", "files:write"],
///         served: .core)
///
///     // Get server metadata
///     let metadata = await server.getMetadata()
///
///     // Register a client
///     let client = try await server.registerClient(request)
///
///     // Handle authorization
///     let authResponse = try await server.handleAuthorizationRequest(authRequest)
///
///     // Exchange code for tokens
///     let tokens = try await server.handleTokenRequest(tokenRequest)
/// }
/// ```
public actor OAuthServer {

    // MARK: - Properties

    private let storage: OAuthStorage
    private let issuer: String

    /// The scopes this deployment offers, advertised in both metadata documents.
    ///
    /// Supplied by the consumer with **no default**. A default of `[]` produces an empty
    /// document silently; any other default invents scopes the deployment never chose, which is
    /// what this package did until now — one consumer advertised three MCP scopes purely
    /// because this code named them. `nil` means "advertise none", and it is a decision a
    /// caller makes rather than inherits.
    private let scopesSupported: [String]?

    /// What this deployment actually serves, as opposed to what this package implements.
    private let served: ServedCapabilities

    /// How long a pushed authorization request is good for — RFC 9126 §2.2 suggests
    /// "relatively short", on the order of a minute, since the client redirects immediately.
    private let pushedRequestLifetime: TimeInterval = 90

    /// How long a device code is good for — RFC 8628 suggests a value in this range.
    private let deviceCodeLifetime: TimeInterval = 1800

    /// How long a device should wait between polls. §3.2's own default.
    private let devicePollInterval: TimeInterval = 5

    /// Which resources this server issues tokens for — RFC 8707.
    ///
    /// Defaults to the server's own identifier, so a deployment that already serves correct
    /// protected-resource metadata needs no configuration. Supply one explicitly when the
    /// resource identifier legitimately differs from the issuer.
    public let resourcePolicy: ResourceIndicatorPolicy
    private let accessTokenLifetime: TimeInterval
    private let refreshTokenLifetime: TimeInterval
    private let authorizationCodeLifetime: TimeInterval

    // MARK: - Initialization

    /// Creates a new OAuth server
    ///
    /// - Parameters:
    ///   - storage: Storage backend for clients and tokens
    ///   - issuer: Base URL of this authorization server
    ///   - accessTokenLifetime: Access token lifetime in seconds (default: 24 hours)
    ///   - refreshTokenLifetime: Refresh token lifetime in seconds (default: 90 days)
    ///   - authorizationCodeLifetime: Auth code lifetime in seconds (default: 10 minutes)
    ///   - scopesSupported: The scopes this deployment offers, advertised in both metadata
    ///     documents. No default: `nil` means "advertise none", and it is a decision a caller
    ///     makes rather than inherits. This package previously invented three MCP scopes, which
    ///     one consumer advertised without ever having chosen them.
    ///   - served: What this deployment actually serves — its grants, its client
    ///     authentication methods and its routed endpoints. No default, because a client reads
    ///     the metadata as a list of things it may do, and anything advertised but not served
    ///     fails at the client rather than here. ``ServedCapabilities/core`` is the ordinary
    ///     deployment.
    ///   - resourcePolicy: Which resources this server issues tokens for — RFC 8707. Defaults
    ///     to ``ResourceIndicatorPolicy/protecting(_:)`` over the issuer, which is the value the
    ///     server already publishes as its own resource identifier.
    public init(
        storage: OAuthStorage,
        issuer: String,
        scopesSupported: [String]?,
        served: ServedCapabilities,
        accessTokenLifetime: TimeInterval = 86400,        // 24 hours
        refreshTokenLifetime: TimeInterval = 7776000,     // 90 days
        authorizationCodeLifetime: TimeInterval = 600,    // 10 minutes
        resourcePolicy: ResourceIndicatorPolicy? = nil
    ) {
        self.storage = storage
        self.issuer = issuer
        self.scopesSupported = scopesSupported
        self.served = served
        // Defaulted from the issuer, which is what this server already publishes as its
        // resource identifier in RFC 9728 metadata. Asking an operator to repeat that value
        // invites the two to drift, and a server that advertises a resource then refuses it
        // breaks the most conformant clients first — they read the metadata and obeyed it.
        self.resourcePolicy = resourcePolicy
            // SECURITY: parses this server's own configured issuer; nothing is fetched from it.
            ?? URL(string: issuer).map { ResourceIndicatorPolicy.protecting($0) }
            ?? ResourceIndicatorPolicy(known: [], allowsUnspecified: true)
        self.accessTokenLifetime = accessTokenLifetime
        self.refreshTokenLifetime = refreshTokenLifetime
        self.authorizationCodeLifetime = authorizationCodeLifetime
    }

    // MARK: - Server Metadata (RFC 8414)

    /// Returns OAuth 2.0 Authorization Server Metadata
    public func getMetadata() -> ServerMetadata {
        ServerMetadata(
            issuer: issuer,
            authorizationEndpoint: "\(issuer)/authorize",
            tokenEndpoint: "\(issuer)/token",
            registrationEndpoint: "\(issuer)/register",
            responseTypesSupported: ["code"],
            // Named from `GrantType` rather than written out again: two lists drift, one does
            // not, and this is a test about drift. `clientCredentials` is absent deliberately —
            // this provider does not issue those, and advertising a grant it refuses is worse
            // than omitting one it honours.
            // What this deployment honours, not what this package implements.
            grantTypesSupported: served.grantTypes.map(\.rawValue),
            codeChallengeMethodsSupported: [PKCE.ChallengeMethod.s256.rawValue],
            tokenEndpointAuthMethodsSupported:
                served.clientAuthenticationMethods.map(\.rawValue),
            // The consumer's, or none. This package no longer invents scopes.
            scopesSupported: scopesSupported,
            // What the deployment serves, not what this package implements. Advertising an
            // endpoint the consumer does not route makes a discoverable 404, and that failure
            // lands on their clients rather than here.
            introspectionEndpoint: served.introspection,
            pushedAuthorizationRequestEndpoint: served.pushedAuthorizationRequest,
            deviceAuthorizationEndpoint: served.deviceAuthorization,
            // Advertised only by a deployment that honours proofs. The algorithms are this
            // package's — `CompactJWS` accepts ES256 and nothing else — but *whether* a proof
            // is accepted at all is the consumer's request handling.
            dpopSigningAlgValuesSupported: served.honoursDPoPProofs ? ["ES256"] : nil
        )
    }

    // MARK: - Protected Resource Metadata (RFC 9728)

    /// Describes a token — RFC 7662 token introspection.
    ///
    /// How a resource server answers the only question it has about a bearer string it was
    /// handed: is this still good, and what is it for? Without it a resource server either
    /// trusts what it received or reaches past this package to find out.
    ///
    /// An expired, revoked or unknown token is reported as inactive rather than raised as an
    /// error. That is RFC 7662 §2.2, and it matters: a server answering 401 for an expired
    /// token makes every caller treat "this token is no good" as a transport failure, which is
    /// a different condition handled in a different place, usually with a retry that cannot
    /// help.
    ///
    /// - Parameter token: The access token to describe.
    /// - Returns: The introspection response, active or not.
    /// - Throws: Only if storage cannot be read. A token being bad is an answer, not an error.
    public func introspect(token: String) async throws -> IntrospectionResult {
        try await storage.introspectAccessToken(token: token)
    }

    // MARK: - Token Exchange (RFC 8693)

    /// Exchanges one token for another — RFC 8693 §2.
    ///
    /// For a service acting with a token it was given: an API gateway calling a backend, or a
    /// service narrowing its own privilege before calling something less trusted.
    ///
    /// ## The rule that makes this safe
    ///
    /// **An exchange may narrow privilege and never widens it.** That is the whole purpose, and
    /// it is what a naive implementation gets wrong: granting the scope the client asked for,
    /// without checking what the subject token actually carried, lets any holder of a read-only
    /// token mint an administrative one through a documented grant type — and the result looks
    /// entirely legitimate to everything downstream.
    ///
    /// Three further refusals, each closing a way the endpoint could launder a credential:
    ///
    /// - An **expired or unknown** subject token, or expiry means nothing and a dead credential
    ///   buys a live one.
    /// - A **bound** subject token, because exchanging it would strip the binding — a DPoP- or
    ///   certificate-bound token in, an ordinary bearer token out, and everything the binding
    ///   protected against available to whoever holds the result.
    /// - An **ID token**, because this package does not validate one. Accepting it would treat
    ///   an unverified assertion of identity as authorisation, which is the misuse the OIDC
    ///   boundary exists to prevent.
    ///
    /// - Parameters:
    ///   - request: What to exchange, and for what.
    ///   - clientId: The client performing the exchange.
    /// - Returns: The issued token and what kind it is.
    /// - Throws: `OAuthError.invalidGrant(_:)` for a subject that cannot be exchanged, or
    ///   `OAuthError.invalidScope(_:)` for a request that would widen privilege.
    public func exchangeToken(
        _ request: TokenExchangeRequest, clientId: String
    ) async throws -> TokenExchangeResponse {
        guard request.subjectTokenType == .accessToken else {
            throw OAuthError.invalidRequest(
                "This server exchanges access tokens only. \(request.subjectTokenType.rawValue) "
                + "is not a token type it can validate.")
        }

        let validated = try await storage.validateAccessToken(token: request.subjectToken)
        guard case .valid(let subject) = validated else {
            throw OAuthError.invalidGrant("The subject token is not valid.")
        }

        guard subject.keyThumbprint == nil, subject.certificateThumbprint == nil else {
            throw OAuthError.invalidGrant(
                "The subject token is bound to a key or certificate. Exchanging it would issue "
                + "an unbound token, discarding that binding.")
        }

        // Narrowing only. A requested scope must be a subset of what the subject carries;
        // absent, the subject's scope is inherited rather than the server's full set.
        let held = Set((subject.scope ?? "").split(separator: " ").map(String.init))
        let issuedScope: String?
        if let requested = request.scope {
            let asked = Set(requested.split(separator: " ").map(String.init))
            let widening = asked.subtracting(held)
            guard widening.isEmpty else {
                throw OAuthError.invalidScope(
                    "An exchange cannot grant scopes the subject token does not carry: "
                    + widening.sorted().joined(separator: ", ") + ".")
            }
            issuedScope = requested
        } else {
            issuedScope = subject.scope
        }

        let issued = TokenGenerator.generateAccessToken()
        try await storage.saveAccessToken(
            token: issued, clientId: clientId, scope: issuedScope,
            expiresAt: Date().addingTimeInterval(accessTokenLifetime),
            audience: request.resource)

        return TokenExchangeResponse(
            accessToken: issued,
            issuedTokenType: .accessToken,
            tokenType: "Bearer",
            expiresIn: Int(accessTokenLifetime),
            scope: issuedScope)
    }

    // MARK: - Pushed Authorization Requests (RFC 9126)

    /// Accepts an authorization request ahead of time — RFC 9126 §2.
    ///
    /// Ordinarily the request travels in a URL through the user's browser, where every
    /// parameter is visible to the browser, its history, any extension, and every intermediary
    /// that logs a URL — and modifiable by all of them before this server sees it. Pushing it
    /// over an authenticated back channel means the browser carries only an opaque reference,
    /// so what the user's agent can see it can no longer change.
    ///
    /// - Returns: The reference and its lifetime.
    /// - Throws: `OAuthStorageError` if it cannot be stored.
    public func pushAuthorizationRequest(
        clientId: String,
        redirectUri: String,
        scope: String?,
        state: String?,
        codeChallenge: String?,
        codeChallengeMethod: String?
    ) async throws -> PushedAuthorizationResponse {
        // §2.2 requires this URN form, so a server can tell a pushed reference from any other
        // URI a client might hand it — including one pointing somewhere it should not fetch.
        let requestURI = "urn:ietf:params:oauth:request_uri:"
            + TokenGenerator.generateToken(byteLength: 32)
        let expiresAt = Date().addingTimeInterval(pushedRequestLifetime)

        try await storage.savePushedRequest(
            requestURI: requestURI, clientId: clientId, redirectUri: redirectUri,
            scope: scope, state: state, codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod, expiresAt: expiresAt)

        return PushedAuthorizationResponse(
            requestURI: requestURI, expiresIn: pushedRequestLifetime)
    }

    /// Redeems a pushed reference for the parameters it stands for — RFC 9126 §4.
    ///
    /// Single-use. A reference that can be replayed is one a browser extension can harvest and
    /// present again.
    ///
    /// - Throws: `OAuthError.invalidRequest(_:)` when no live, unspent request matches this
    ///   client. Unknown, expired, spent and belonging-to-someone-else are one answer, so a
    ///   caller cannot probe which references exist.
    public func consumePushedRequest(
        requestURI: String, clientId: String
    ) async throws -> PushedAuthorizationRequest {
        guard let request = try await storage.consumePushedRequest(
            requestURI: requestURI, clientId: clientId) else {
            throw OAuthError.invalidRequest(
                "That request_uri is not valid for this client, or has already been used.")
        }
        return request
    }

    // MARK: - Device Authorization Grant (RFC 8628)

    /// Starts a device flow — RFC 8628 §3.1.
    ///
    /// For a client that cannot open a browser. It receives a device code to poll with and a
    /// short user code to display; the user enters that code somewhere with a keyboard.
    ///
    /// - Parameters:
    ///   - clientId: The client asking.
    ///   - scope: What it is asking for.
    /// - Returns: The codes and where to send the user.
    /// - Throws: `OAuthStorageError` if the codes cannot be stored.
    public func authorizeDevice(
        clientId: String, scope: String?
    ) async throws -> DeviceAuthorizationResponse {
        let deviceCode = TokenGenerator.generateDeviceCode()
        let userCode = TokenGenerator.generateUserCode()
        let expiresAt = Date().addingTimeInterval(deviceCodeLifetime)

        try await storage.saveDeviceCode(
            deviceCode: deviceCode, userCode: userCode, clientId: clientId,
            scope: scope, expiresAt: expiresAt)

        // SECURITY: builds this server's own verification URL from its configured issuer.
        let verificationURI = URL(string: issuer + "/device")
            ?? URL(fileURLWithPath: "/device")

        return DeviceAuthorizationResponse(
            deviceCode: deviceCode,
            userCode: userCode,
            verificationURI: verificationURI,
            expiresIn: deviceCodeLifetime,
            interval: devicePollInterval)
    }

    /// Records that a user approved a device — RFC 8628 §3.3.
    ///
    /// - Parameters:
    ///   - userCode: The code the user typed.
    ///   - subject: Who approved it.
    /// - Throws: `OAuthError.invalidGrant(_:)` if no live, unapproved code matches. Unknown
    ///   and expired are not distinguished: the approval page would otherwise confirm which
    ///   short codes exist, and they are short by design.
    public func approveDeviceCode(userCode: String, subject: String) async throws {
        let approved = try await storage.approveDeviceCode(userCode: userCode, subject: subject)
        guard approved else {
            throw OAuthError.invalidGrant("That code is not valid, or has expired.")
        }
    }

    /// Exchanges an approved device code for tokens — RFC 8628 §3.4.
    ///
    /// - Parameters:
    ///   - deviceCode: The code the device has been polling with.
    ///   - clientId: The client redeeming it.
    /// - Returns: The tokens, once the user has approved.
    /// - Throws: `OAuthError.authorizationPending(_:)` while the user has not finished —
    ///   the expected answer for most of the flow — or `OAuthError.expiredToken(_:)`,
    ///   or `OAuthError.invalidGrant(_:)` for a code that is unknown, not this client's, or
    ///   already spent.
    public func redeemDeviceCode(
        _ deviceCode: String, clientId: String
    ) async throws -> TokenResponse {
        switch try await storage.deviceCodeState(deviceCode: deviceCode, clientId: clientId) {
        case .pending:
            throw OAuthError.authorizationPending(nil)
        case .expired:
            throw OAuthError.expiredToken(nil)
        case .unknown, .alreadyRedeemed:
            // One answer for both. A device code is single-use, and telling a caller that a
            // code exists but is spent distinguishes it from one that never existed.
            throw OAuthError.invalidGrant(nil)
        case .approved(let scope):
            // Marked spent before the token is issued. The other order leaves a window in
            // which two concurrent polls both see an approved code and both collect a token.
            try await storage.markDeviceCodeRedeemed(deviceCode: deviceCode)

            let accessToken = TokenGenerator.generateAccessToken()
            let refreshToken = TokenGenerator.generateRefreshToken()
            let now = Date()

            try await storage.saveAccessToken(
                token: accessToken, clientId: clientId, scope: scope,
                expiresAt: now.addingTimeInterval(accessTokenLifetime), audience: nil)
            try await storage.saveRefreshToken(
                token: refreshToken, clientId: clientId, scope: scope,
                expiresAt: now.addingTimeInterval(refreshTokenLifetime))

            return TokenResponse(
                accessToken: accessToken,
                tokenType: "Bearer",
                expiresIn: Int(accessTokenLifetime),
                refreshToken: refreshToken,
                scope: scope)
        }
    }

    /// Returns OAuth 2.0 Protected Resource Metadata
    ///
    /// Per RFC 9728, this tells clients which authorization server protects
    /// this resource and which scopes are available.
    public func getProtectedResourceMetadata() -> ProtectedResourceMetadata {
        ProtectedResourceMetadata(
            resource: issuer,
            authorizationServers: [issuer],
            // One source for both documents. A client may read either, and two literals would
            // drift into disagreeing about one deployment.
            scopesSupported: scopesSupported,
            bearerMethodsSupported: ["header"]
        )
    }

    // MARK: - Client Registration (RFC 7591)

    /// Registers a new OAuth client
    ///
    /// - Parameter request: Client registration request
    /// - Returns: Registered client with generated credentials
    /// - Throws: `OAuthError.invalidRequest(nil)` if request is invalid
    public func registerClient(_ request: ClientRegistrationRequest) async throws -> ClientRegistrationResponse {
        // Validate request
        guard !request.redirectUris.isEmpty else {
            throw OAuthError.invalidRequest(nil)
        }

        // Generate credentials
        let clientId = TokenGenerator.generateClientId()
        let clientSecret: String?

        if request.tokenEndpointAuthMethod == "none" {
            clientSecret = nil
        } else {
            clientSecret = TokenGenerator.generateClientSecret()
        }

        let client = RegisteredClient(
            clientId: clientId,
            clientSecret: clientSecret,
            clientName: request.clientName,
            redirectUris: request.redirectUris,
            grantTypes: request.grantTypes,
            tokenEndpointAuthMethod: request.tokenEndpointAuthMethod,
            registrationDate: Date(),
            applicationType: request.applicationType
        )

        try await storage.saveClient(client)

        return ClientRegistrationResponse(
            clientId: clientId,
            clientSecret: clientSecret,
            clientName: request.clientName,
            redirectUris: request.redirectUris,
            grantTypes: request.grantTypes,
            tokenEndpointAuthMethod: request.tokenEndpointAuthMethod,
            applicationType: request.applicationType
        )
    }

    // MARK: - Authorization Endpoint

    /// Handles an authorization request
    ///
    /// - Parameter request: Authorization request parameters
    /// - Returns: Authorization response with code
    /// - Throws: `OAuthError` if request is invalid
    public func handleAuthorizationRequest(_ request: AuthorizationRequest) async throws -> AuthorizationResponse {
        // Validate response type
        guard request.responseType == "code" else {
            throw OAuthError.invalidRequest(nil)
        }

        // Validate client
        guard let client = try await storage.getClient(clientId: request.clientId) else {
            throw OAuthError.invalidClient(nil)
        }

        // Validate redirect URI
        guard client.redirectUris.contains(request.redirectUri) else {
            throw OAuthError.invalidRequest(nil)
        }

        // Refuse `plain` here rather than at the token endpoint. By then the code has been
        // issued and the client is mid-flow; here the error still reaches whoever can fix it.
        //
        // `plain` means the challenge *is* the verifier, sent in the clear in this very
        // request — so anyone positioned to intercept the authorization code has also seen
        // what redeems it, which is the single attack PKCE exists to stop. An absent method
        // is still accepted; RFC 7636 §4.3 defaults it to `plain`, but this server only ever
        // verifies with S256, so an absent method that later presents a challenge is checked
        // as S256 and a genuine `plain` client fails closed at the token endpoint.
        // PKCE is required, not merely supported.
        //
        // OAuth 2.1 §4.1 requires it for the authorization code grant, and this package's own
        // `GrantType` documentation has always said so. The implementation did not enforce it:
        // the challenge was optional here, and the token endpoint verified one only `if` the
        // code carried it — so a client that simply omitted it got a code with no challenge and
        // redeemed it with no verifier.
        //
        // The consequence is exactly what PKCE exists to prevent: an intercepted authorization
        // code is redeemable by whoever intercepted it.
        //
        // Refused here rather than at the token endpoint, for the same reason `plain` is: by
        // then a code has been issued and the client is mid-flow, whereas here the error still
        // reaches whoever can fix it.
        guard let challenge = request.codeChallenge, !challenge.isEmpty else {
            throw OAuthError.invalidRequest(
                "A code_challenge is required. This server implements OAuth 2.1, which requires "
                + "PKCE on the authorization code grant.")
        }

        if let method = request.codeChallengeMethod,
           method != PKCE.ChallengeMethod.s256.rawValue {
            throw OAuthError.invalidRequest(nil)
        }

        // Normalize scope: default to all MCP scopes when not provided or empty.
        // Accept any scope the client requests per RFC 6749 §3.3.
        let defaultScope = "mcp:tools mcp:resources mcp:prompts"
        let effectiveScope: String
        if let scope = request.scope, !scope.trimmingCharacters(in: .whitespaces).isEmpty {
            effectiveScope = scope
        } else {
            effectiveScope = defaultScope
        }

        // Generate authorization code
        let code = TokenGenerator.generateAuthorizationCode()
        let now = Date()

        // RFC 8707 at the authorization endpoint, which 0.8.0 left open.
        //
        // Refused here, before the user is sent anywhere. Validating only at the token endpoint
        // meant a client naming a resource this server does not serve still sent the user
        // through a full authorization — sign in, read a consent screen, approve — for a
        // request that was never going to succeed.
        //
        // Fixing the audience onto the code also closes a subtler hole: with it decided at
        // redemption, a client could name the resource the user saw here and a different one at
        // `/token`, and nothing on the code contradicted it.
        //
        // SECURITY: parses a client-supplied identifier; nothing is fetched from it.
        let requestedResource = request.resource.flatMap { URL(string: $0) }
        let audience = try resourcePolicy.audience(for: requestedResource.map { [$0] } ?? [])

        let authCode = AuthorizationCode(
            code: code,
            clientId: request.clientId,
            redirectUri: request.redirectUri,
            scope: effectiveScope,
            codeChallenge: request.codeChallenge,
            codeChallengeMethod: request.codeChallengeMethod,
            expiresAt: now.addingTimeInterval(authorizationCodeLifetime),
            createdAt: now,
            audience: audience
        )

        try await storage.saveAuthorizationCode(authCode)

        return AuthorizationResponse(
            code: code,
            state: request.state,
            issuer: issuer
        )
    }

    /// Validates an authorization request without generating a code
    ///
    /// Use this to validate the request before showing the consent page.
    /// Call `handleAuthorizationRequest` after user approves.
    ///
    /// - Parameter request: Authorization request parameters
    /// - Returns: The validated client for display in consent page
    /// - Throws: `OAuthError` if request is invalid
    public func validateAuthorizationRequest(_ request: AuthorizationRequest) async throws -> RegisteredClient {
        // Validate response type
        guard request.responseType == "code" else {
            throw OAuthError.invalidRequest(nil)
        }

        // Validate client
        guard let client = try await storage.getClient(clientId: request.clientId) else {
            throw OAuthError.invalidClient(nil)
        }

        // Validate redirect URI
        guard client.redirectUris.contains(request.redirectUri) else {
            throw OAuthError.invalidRequest(nil)
        }

        // Scope validation: accept any scope the client requests.
        // Unknown scopes are passed through per RFC 6749 §3.3.

        return client
    }

    /// Gets a registered client by ID
    ///
    /// - Parameter clientId: The client ID to look up
    /// - Returns: The client if found, nil otherwise
    public func getClient(clientId: String) async throws -> RegisteredClient? {
        return try await storage.getClient(clientId: clientId)
    }

    // MARK: - CSRF Token Operations

    /// Generates a CSRF token for consent page protection
    ///
    /// - Parameters:
    ///   - clientId: Client requesting authorization
    ///   - redirectUri: Redirect URI from authorization request
    /// - Returns: The generated CSRF token
    public func generateCSRFToken(clientId: String, redirectUri: String) async throws -> String {
        return try await storage.generateCSRFToken(clientId: clientId, redirectUri: redirectUri)
    }

    /// Validates and consumes a CSRF token
    ///
    /// - Parameters:
    ///   - token: The CSRF token to validate
    ///   - clientId: Expected client ID
    ///   - redirectUri: Expected redirect URI
    /// - Returns: Validation result
    public func validateCSRFToken(token: String, clientId: String, redirectUri: String) async throws -> CSRFValidationResult {
        return try await storage.validateCSRFToken(token: token, clientId: clientId, redirectUri: redirectUri)
    }

    // MARK: - Token Endpoint

    /// Handles a token request
    ///
    /// - Parameter request: Token request parameters
    /// - Returns: Token response with access and refresh tokens
    /// - Throws: `OAuthError` if request is invalid
    public func handleTokenRequest(_ request: TokenRequest) async throws -> TokenResponse {
        switch request.grantType {
        case "authorization_code":
            return try await handleAuthorizationCodeGrant(request)
        case "refresh_token":
            return try await handleRefreshTokenGrant(request)
        default:
            throw OAuthError.unsupportedGrantType(nil)
        }
    }

    private func handleAuthorizationCodeGrant(_ request: TokenRequest) async throws -> TokenResponse {
        guard let code = request.code else {
            throw OAuthError.invalidRequest(nil)
        }

        // Consume the authorization code (single-use)
        guard let authCode = try await storage.consumeAuthorizationCode(code: code) else {
            throw OAuthError.invalidGrant(nil)
        }

        // Check expiration
        guard !authCode.isExpired else {
            throw OAuthError.invalidGrant(nil)
        }

        // Validate client
        guard authCode.clientId == request.clientId else {
            throw OAuthError.invalidClient(nil)
        }

        // Validate redirect URI
        guard authCode.redirectUri == request.redirectUri else {
            throw OAuthError.invalidRequest(nil)
        }

        // Validate PKCE if code challenge was provided
        // Unconditional, not "if the code carried a challenge".
        //
        // Once the authorization endpoint began requiring one, the conditional form became
        // equivalent for codes minted afterwards — and that equivalence is the problem. It made
        // this endpoint's safety a property of a *different* endpoint, so any future path that
        // creates a code (an admin tool, a fixture, a migration, a grant type not yet written)
        // would reopen the hole silently and this code would not object.
        //
        // It also fails closed for codes stored before the upgrade, which carry no challenge
        // and would otherwise redeem with no verifier for the length of a code lifetime — the
        // exact window an attacker holding an intercepted code is standing in.
        guard let codeChallenge = authCode.codeChallenge else {
            throw OAuthError.invalidGrant(
                "This authorization code carries no PKCE challenge and cannot be redeemed. "
                + "Start a new authorization request.")
        }
        try validatePKCE(
            verifier: request.codeVerifier,
            challenge: codeChallenge,
            methodName: authCode.codeChallengeMethod)

        // Get client to check grant types
        guard let client = try await storage.getClient(clientId: request.clientId) else {
            throw OAuthError.invalidClient(nil)
        }

        // Generate tokens
        let accessToken = TokenGenerator.generateAccessToken()
        let refreshToken: String?

        if client.grantTypes.contains("refresh_token") {
            refreshToken = TokenGenerator.generateRefreshToken()
        } else {
            refreshToken = nil
        }

        let now = Date()

        // RFC 8707: what this token is for. The audience was fixed when the code was granted,
        // so this endpoint honours that rather than deciding again — a client that named one
        // resource at `/authorize` and another here is substituting an audience the user never
        // saw, and the code is the only record of what they did see.
        let audience: URL?
        if let requested = request.resource.first {
            guard authCode.audience == requested else {
                throw OAuthError.invalidTarget(
                    "This authorization code was granted for a different resource than the one "
                    + "requested. Start a new authorization request naming the resource you want.")
            }
            audience = authCode.audience
        } else {
            audience = authCode.audience
        }

        // Store tokens
        try await storage.saveAccessToken(
            token: accessToken,
            clientId: request.clientId,
            scope: authCode.scope,
            expiresAt: now.addingTimeInterval(accessTokenLifetime),
            audience: audience
        )

        if let rt = refreshToken {
            try await storage.saveRefreshToken(
                token: rt,
                clientId: request.clientId,
                scope: authCode.scope,
                expiresAt: now.addingTimeInterval(refreshTokenLifetime)
            )
        }

        return TokenResponse(
            accessToken: accessToken,
            tokenType: "Bearer",
            expiresIn: Int(accessTokenLifetime),
            refreshToken: refreshToken,
            scope: authCode.scope
        )
    }

    private func validatePKCE(verifier: String?, challenge: String, methodName: String?) throws {
        guard let verifier = verifier else {
            throw OAuthError.invalidRequest(nil)
        }
        // Only S256 is verifiable here. A stored `plain` method can only come from a code
        // issued before this server refused them, and it fails closed rather than being
        // honoured: the verifier will not match an S256 digest of itself.
        _ = methodName
        let method = PKCE.ChallengeMethod.s256
        let valid: Bool
        do {
            valid = try PKCE.verifyCodeChallenge(verifier: verifier, challenge: challenge, method: method)
        } catch {
            throw OAuthError.invalidGrant(nil)
        }
        guard valid else {
            throw OAuthError.invalidGrant(nil)
        }
    }

    private func handleRefreshTokenGrant(_ request: TokenRequest) async throws -> TokenResponse {
        // First check if client exists and can use refresh_token grant
        guard let client = try await storage.getClient(clientId: request.clientId) else {
            throw OAuthError.invalidClient(nil)
        }

        guard client.grantTypes.contains("refresh_token") else {
            throw OAuthError.unauthorizedClient(nil)
        }

        guard let refreshToken = request.refreshToken else {
            throw OAuthError.invalidRequest(nil)
        }

        // Validate refresh token
        guard let tokenInfo = try await storage.getRefreshTokenInfo(token: refreshToken) else {
            throw OAuthError.invalidGrant(nil)
        }

        guard tokenInfo.clientId == request.clientId else {
            throw OAuthError.invalidGrant(nil)
        }

        // Generate new access token
        let newAccessToken = TokenGenerator.generateAccessToken()
        let now = Date()

        // Checked on refresh too. A token that could shed its audience by being refreshed
        // would make the binding good only until the first renewal.
        let audience = try resourcePolicy.audience(for: request.resource)

        try await storage.saveAccessToken(
            token: newAccessToken,
            clientId: request.clientId,
            scope: tokenInfo.scope,
            expiresAt: now.addingTimeInterval(accessTokenLifetime),
            audience: audience
        )

        // Optionally rotate refresh token (we'll keep the same one for simplicity)
        return TokenResponse(
            accessToken: newAccessToken,
            tokenType: "Bearer",
            expiresIn: Int(accessTokenLifetime),
            refreshToken: refreshToken, // Return same refresh token
            scope: tokenInfo.scope
        )
    }

    // MARK: - Token Validation

    /// Validates an access token
    ///
    /// - Parameter token: The access token to validate
    /// - Returns: Validation result with client and scope info
    public func validateAccessToken(_ token: String) async throws -> TokenValidationResult {
        try await storage.validateAccessToken(token: token)
    }

    // MARK: - Token Revocation

    /// Revokes an access token
    ///
    /// - Parameter token: The token to revoke
    public func revokeToken(_ token: String) async throws {
        try await storage.revokeAccessToken(token: token)
    }

    // MARK: - Client Authentication

    /// Authenticates a client using various methods
    ///
    /// - Parameters:
    ///   - clientId: The client ID
    ///   - authHeader: Optional Authorization header value
    ///   - bodyClientSecret: Optional client_secret from request body
    /// - Returns: `true` if authentication succeeds
    public func authenticateClient(
        clientId: String,
        authHeader: String?,
        bodyClientSecret: String?
    ) async throws -> Bool {
        guard let client = try await storage.getClient(clientId: clientId) else {
            return false
        }

        switch client.tokenEndpointAuthMethod {
        case "none":
            // Public client - no authentication required
            return true

        case "client_secret_basic":
            // HTTP Basic authentication
            guard let header = authHeader,
                  header.hasPrefix("Basic ") else {
                return false
            }

            let base64 = String(header.dropFirst(6))
            guard let data = Data(base64Encoded: base64),
                  let credentials = String(data: data, encoding: .utf8) else {
                return false
            }

            let parts = credentials.split(separator: ":", maxSplits: 1)
            guard parts.count == 2,
                  String(parts[0]) == clientId,
                  let secret = client.clientSecret else {
                return false
            }

            return TokenGenerator.timingSafeCompare(String(parts[1]), secret)

        case "client_secret_post":
            // Client secret in request body
            guard let providedSecret = bodyClientSecret,
                  let storedSecret = client.clientSecret else {
                return false
            }

            return TokenGenerator.timingSafeCompare(providedSecret, storedSecret)

        default:
            return false
        }
    }
}

// MARK: - Server Metadata

/// What a deployment actually serves — RFC 8414 §2.
///
/// This package implements more than any one deployment exposes. Which endpoints are routed,
/// which grants are reachable and which authentication methods the TLS layer can honour are all
/// facts about the consumer, not about this package — and only the consumer knows them.
///
/// The distinction matters because of who reads the metadata. A conformant client treats the
/// document as a list of things it may do, so anything advertised and not served is a failure
/// that surfaces at the client rather than at the server that made the claim:
///
/// - An endpoint not routed is a discoverable 404.
/// - A grant whose endpoint is absent is a flow that cannot be started.
/// - An authentication method the TLS layer never requests is a handshake that cannot happen.
///
/// All four were real. Each was found by a consumer running the change and reading its own
/// document, and each was reported one release after the last — which is why this is a single
/// value rather than a parameter per field: the ways a document can over-promise are not a list
/// anybody has finished enumerating.
///
/// ## Which fields belong here
///
/// A field belongs to the deployment exactly when **the deployment can serve less than this
/// package implements**. Endpoints, grants, authentication methods and DPoP all can: a consumer
/// routes a subset, declines a grant, lacks the TLS configuration for mTLS, or never learned the
/// `DPoP` scheme in its request handling.
///
/// `response_types_supported` and `code_challenge_methods_supported` do not. This package issues
/// `code` and verifies `S256`, and a deployment cannot serve less without the package failing
/// outright — there is no subset to choose. They are true for every deployment because they
/// cannot be otherwise, which is different from being true by coincidence.
///
/// The distinction matters when the next field arrives: place it by that test rather than by
/// whichever list is easier to add to.
public struct ServedCapabilities: Sendable, Equatable {

    /// A declaration that cannot be honoured.
    public enum Inconsistency: Error, Equatable {
        /// The device grant was declared without the endpoint that begins it.
        case deviceGrantWithoutEndpoint
        /// No client authentication method was declared.
        case noAuthenticationMethod
        /// The authorization code grant was omitted.
        ///
        /// **This refusal holds a metadata field on the package side, and relaxing it moves
        /// that field.** `response_types_supported: ["code"]` is unconditionally true only
        /// because every deployment must offer the authorization code grant. Permit a
        /// client-credentials-only deployment and it serves no response types at all — so the
        /// field stops being a package fact and becomes the deployment's, exactly like the four
        /// that moved before it.
        ///
        /// Identified by SwiftMCPServer while trying to falsify the rule that decides where a
        /// field belongs. Recorded here rather than in the metadata code because this is where
        /// someone would come to relax the constraint, and the consequence is a document that
        /// silently over-promises somewhere else.
        case missingAuthorizationCodeGrant
    }

    /// The grants this deployment will honour.
    public let grantTypes: [GrantType]

    /// The client authentication methods its token endpoint can actually accept.
    ///
    /// The mTLS methods belong here only if the TLS layer requests a client certificate.
    /// Advertising one otherwise offers a client a handshake that will never ask for what it
    /// is being told to present.
    public let clientAuthenticationMethods: [ClientAuthenticationMethod]

    /// Where token introspection is routed — RFC 7662.
    public let introspection: String?
    /// Where pushed authorization requests are routed — RFC 9126.
    public let pushedAuthorizationRequest: String?
    /// Where device authorization is routed — RFC 8628.
    public let deviceAuthorization: String?
    /// Where token revocation is routed — RFC 7009.
    public let revocation: String?

    /// Whether this deployment honours DPoP proofs — RFC 9449.
    ///
    /// A fact about the consumer's request handling, not about this package: accepting a
    /// `DPoP`-scheme `Authorization` header is something the consumer's HTTP layer either does
    /// or does not do, and one that only matches `Bearer` will refuse a correctly-presented
    /// bound token.
    ///
    /// This is the claim most likely to be believed, because a client reading it has no cheap
    /// way to test it before relying on it — it obtains a bound token first, and discovers the
    /// truth when the request it was designed for is turned away.
    ///
    /// Whether, not which: the algorithms are this package's to state, since `CompactJWS`
    /// accepts ES256 and nothing else. A consumer choosing the list could advertise one this
    /// package refuses.
    public let honoursDPoPProofs: Bool

    /// The deployment every consumer of this package has: the authorization code and refresh
    /// grants, secret-based client authentication, and no optional endpoints.
    ///
    /// Named rather than defaulted, so a reader can tell "this is what we serve" from "nobody
    /// thought about it".
    public static let core = ServedCapabilities(
        checkedGrantTypes: [.authorizationCode, .refreshToken],
        clientAuthenticationMethods: [.clientSecretBasic, .clientSecretPost, .none],
        introspection: nil, pushedAuthorizationRequest: nil,
        deviceAuthorization: nil, revocation: nil, honoursDPoPProofs: false)

    /// Declares what this deployment serves.
    ///
    /// - Throws: ``Inconsistency`` when the declaration cannot be honoured — most importantly
    ///   the device grant without the endpoint that begins it, which produces a document
    ///   offering a flow no client can start. Refused rather than filtered: dropping the grant
    ///   silently would hand back a document the caller did not ask for, and quiet correction
    ///   is how the original defect stayed invisible.
    public init(
        grantTypes: [GrantType],
        clientAuthenticationMethods: [ClientAuthenticationMethod],
        introspection: String? = nil,
        pushedAuthorizationRequest: String? = nil,
        deviceAuthorization: String? = nil,
        revocation: String? = nil,
        honoursDPoPProofs: Bool = false
    ) throws {
        guard grantTypes.contains(.authorizationCode) else {
            throw Inconsistency.missingAuthorizationCodeGrant
        }
        guard !clientAuthenticationMethods.isEmpty else {
            throw Inconsistency.noAuthenticationMethod
        }
        guard !grantTypes.contains(.deviceCode) || deviceAuthorization != nil else {
            throw Inconsistency.deviceGrantWithoutEndpoint
        }
        self.init(
            checkedGrantTypes: grantTypes,
            clientAuthenticationMethods: clientAuthenticationMethods,
            introspection: introspection,
            pushedAuthorizationRequest: pushedAuthorizationRequest,
            deviceAuthorization: deviceAuthorization,
            revocation: revocation,
            honoursDPoPProofs: honoursDPoPProofs)
    }

    /// The unchecked path, for ``core`` — whose values are written here and cannot be
    /// inconsistent.
    private init(
        checkedGrantTypes: [GrantType],
        clientAuthenticationMethods: [ClientAuthenticationMethod],
        introspection: String?,
        pushedAuthorizationRequest: String?,
        deviceAuthorization: String?,
        revocation: String?,
        honoursDPoPProofs: Bool
    ) {
        self.grantTypes = checkedGrantTypes
        self.clientAuthenticationMethods = clientAuthenticationMethods
        self.introspection = introspection
        self.pushedAuthorizationRequest = pushedAuthorizationRequest
        self.deviceAuthorization = deviceAuthorization
        self.revocation = revocation
        self.honoursDPoPProofs = honoursDPoPProofs
    }
}

/// OAuth 2.0 Authorization Server Metadata per RFC 8414
public struct ServerMetadata: Codable, Sendable {
    /// The authorization server's issuer identifier URL
    public let issuer: String
    /// URL of the authorization endpoint
    public let authorizationEndpoint: String
    /// URL of the token endpoint
    public let tokenEndpoint: String
    /// URL of the dynamic client registration endpoint
    public let registrationEndpoint: String?
    /// Supported OAuth 2.0 response types
    public let responseTypesSupported: [String]
    /// Supported grant types
    public let grantTypesSupported: [String]
    /// Supported PKCE code challenge methods
    public let codeChallengeMethodsSupported: [String]
    /// Supported token endpoint authentication methods
    public let tokenEndpointAuthMethodsSupported: [String]
    /// Supported OAuth scopes
    public let scopesSupported: [String]?

    /// Where a resource server introspects a token — RFC 7662 §2.
    ///
    /// Absent from this document, the endpoint is unreachable by a conformant client however
    /// completely it is implemented: a client does not guess endpoints.
    public let introspectionEndpoint: String?

    /// Where a client pushes an authorization request — RFC 9126 §5.
    public let pushedAuthorizationRequestEndpoint: String?

    /// Where a device begins a browserless sign-in — RFC 8628 §4.
    public let deviceAuthorizationEndpoint: String?

    /// The DPoP proof algorithms this server verifies — RFC 9449 §5.1.
    ///
    /// Exactly what it accepts, never more: a client chooses from this list, so advertising an
    /// algorithm this server refuses invites proofs it will reject.
    public let dpopSigningAlgValuesSupported: [String]?

    private enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case registrationEndpoint = "registration_endpoint"
        case responseTypesSupported = "response_types_supported"
        case grantTypesSupported = "grant_types_supported"
        case codeChallengeMethodsSupported = "code_challenge_methods_supported"
        case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
        case scopesSupported = "scopes_supported"
        case introspectionEndpoint = "introspection_endpoint"
        case pushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint"
        case deviceAuthorizationEndpoint = "device_authorization_endpoint"
        case dpopSigningAlgValuesSupported = "dpop_signing_alg_values_supported"
    }
}

// MARK: - Protected Resource Metadata

/// OAuth 2.0 Protected Resource Metadata per RFC 9728
public struct ProtectedResourceMetadata: Codable, Sendable {
    /// The protected resource identifier
    public let resource: String
    /// URLs of authorization servers that protect this resource
    public let authorizationServers: [String]
    /// The scopes this resource offers, when it names any.
    ///
    /// Optional per RFC 9728 §2, and for the reason that matters: an absent field and an empty
    /// array say different things. Absent means "this document does not enumerate scopes";
    /// empty means "this resource offers none". A non-optional field forced the second whenever
    /// the first was true.
    public let scopesSupported: [String]?
    /// Supported bearer token methods
    public let bearerMethodsSupported: [String]

    private enum CodingKeys: String, CodingKey {
        case resource
        case authorizationServers = "authorization_servers"
        case scopesSupported = "scopes_supported"
        case bearerMethodsSupported = "bearer_methods_supported"
    }
}

// MARK: - Client Registration Response

/// Response from dynamic client registration
public struct ClientRegistrationResponse: Codable, Sendable {
    /// The assigned client identifier
    public let clientId: String
    /// The assigned client secret (if applicable)
    public let clientSecret: String?
    /// The registered client name
    public let clientName: String
    /// Registered redirect URIs
    public let redirectUris: [String]
    /// Authorized grant types for this client
    public let grantTypes: [String]
    /// Token endpoint authentication method for this client
    public let tokenEndpointAuthMethod: String
    /// The kind of application this client registered as.
    ///
    /// Echoed back so the client can confirm the server recorded what it declared, which is the
    /// point of MCP `2026-07-28` requiring the field: a silent disagreement here is exactly the
    /// redirect-URI conflict it guards against.
    public let applicationType: ApplicationType

    private enum CodingKeys: String, CodingKey {
        case clientId = "client_id"
        case clientSecret = "client_secret"
        case clientName = "client_name"
        case redirectUris = "redirect_uris"
        case grantTypes = "grant_types"
        case tokenEndpointAuthMethod = "token_endpoint_auth_method"
        case applicationType = "application_type"
    }
}

// MARK: - Authorization Request

/// OAuth 2.0 authorization request parameters
public struct AuthorizationRequest: Sendable {
    /// The requested response type (e.g. "code")
    public let responseType: String
    /// The client identifier
    public let clientId: String
    /// The redirect URI for the authorization response
    public let redirectUri: String
    /// The requested scope
    public let scope: String?
    /// Opaque state value for CSRF protection
    public let state: String?
    /// PKCE code challenge
    public let codeChallenge: String?
    /// PKCE code challenge method (e.g. "S256")
    public let codeChallengeMethod: String?

    /// The `resource` parameter — RFC 8707. The API the eventual token is for.
    ///
    /// Validated here rather than only at the token endpoint, so a client naming a resource
    /// this server does not serve is refused before the user is sent anywhere — rather than
    /// after they have signed in, read a consent screen and approved a request that was never
    /// going to succeed.
    public let resource: String?

    /// Creates a new authorization request
    public init(
        responseType: String,
        clientId: String,
        redirectUri: String,
        scope: String?,
        state: String?,
        codeChallenge: String?,
        codeChallengeMethod: String?,
        resource: String? = nil
    ) {
        self.responseType = responseType
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.scope = scope
        self.state = state
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
        self.resource = resource
    }
}

// MARK: - Authorization Response

/// OAuth 2.0 authorization response
public struct AuthorizationResponse: Sendable {
    /// The authorization code
    public let code: String
    /// The state parameter echoed back from the request
    public let state: String?
    /// The identifier of the authorization server that issued this code.
    ///
    /// Required by RFC 9207 and by MCP `2026-07-28`. A client must validate it against the
    /// issuer it recorded before redeeming the code: without it, a code issued by one
    /// authorization server can be replayed against another the client also trusts.
    public let issuer: String?

    /// Creates a new authorization response
    public init(code: String, state: String?, issuer: String? = nil) {
        self.code = code
        self.state = state
        self.issuer = issuer
    }
}

// MARK: - Token Request

/// OAuth 2.0 token request parameters
public struct TokenRequest: Sendable {
    /// The grant type (e.g. "authorization_code", "refresh_token")
    public let grantType: String
    /// The authorization code (for authorization_code grant)
    public let code: String?
    /// The redirect URI used in the authorization request
    public let redirectUri: String?
    /// The client identifier
    public let clientId: String
    /// The client secret (for confidential clients)
    public let clientSecret: String?
    /// The PKCE code verifier
    public let codeVerifier: String?
    /// The refresh token (for refresh_token grant)
    public let refreshToken: String?

    /// The `resource` parameters on the request — RFC 8707 resource indicators.
    ///
    /// An array because the parameter may repeat. Empty means the request named none, which a
    /// strict policy refuses.
    public let resource: [URL]

    /// Creates a new token request
    public init(
        grantType: String,
        code: String?,
        redirectUri: String?,
        clientId: String,
        clientSecret: String?,
        codeVerifier: String?,
        refreshToken: String?,
        resource: [URL] = []
    ) {
        self.resource = resource
        self.grantType = grantType
        self.code = code
        self.redirectUri = redirectUri
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.codeVerifier = codeVerifier
        self.refreshToken = refreshToken
    }
}
