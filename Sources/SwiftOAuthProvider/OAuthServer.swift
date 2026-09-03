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
///     let server = await OAuthServer(storage: storage, issuer: "https://mcp.example.com")
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
    public init(
        storage: OAuthStorage,
        issuer: String,
        accessTokenLifetime: TimeInterval = 86400,        // 24 hours
        refreshTokenLifetime: TimeInterval = 7776000,     // 90 days
        authorizationCodeLifetime: TimeInterval = 600,    // 10 minutes
        resourcePolicy: ResourceIndicatorPolicy? = nil
    ) {
        self.storage = storage
        self.issuer = issuer
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
            grantTypesSupported: ["authorization_code", "refresh_token"],
            codeChallengeMethodsSupported: [PKCE.ChallengeMethod.s256.rawValue],
            tokenEndpointAuthMethodsSupported: ["client_secret_basic", "client_secret_post", "none"],
            scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"]
        )
    }

    // MARK: - Protected Resource Metadata (RFC 9728)

    /// Returns OAuth 2.0 Protected Resource Metadata
    ///
    /// Per RFC 9728, this tells clients which authorization server protects
    /// this resource and which scopes are available.
    public func getProtectedResourceMetadata() -> ProtectedResourceMetadata {
        ProtectedResourceMetadata(
            resource: issuer,
            authorizationServers: [issuer],
            scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"],
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

        let authCode = AuthorizationCode(
            code: code,
            clientId: request.clientId,
            redirectUri: request.redirectUri,
            scope: effectiveScope,
            codeChallenge: request.codeChallenge,
            codeChallengeMethod: request.codeChallengeMethod,
            expiresAt: now.addingTimeInterval(authorizationCodeLifetime),
            createdAt: now
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
        if let codeChallenge = authCode.codeChallenge {
            try validatePKCE(verifier: request.codeVerifier, challenge: codeChallenge, methodName: authCode.codeChallengeMethod)
        }

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

        // RFC 8707: what this token is for, decided before it is issued. A token stored
        // without an audience is one every resource accepts.
        let audience = try resourcePolicy.audience(for: request.resource)

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
    }
}

// MARK: - Protected Resource Metadata

/// OAuth 2.0 Protected Resource Metadata per RFC 9728
public struct ProtectedResourceMetadata: Codable, Sendable {
    /// The protected resource identifier
    public let resource: String
    /// URLs of authorization servers that protect this resource
    public let authorizationServers: [String]
    /// Scopes supported by this resource
    public let scopesSupported: [String]
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

    /// Creates a new authorization request
    public init(
        responseType: String,
        clientId: String,
        redirectUri: String,
        scope: String?,
        state: String?,
        codeChallenge: String?,
        codeChallengeMethod: String?
    ) {
        self.responseType = responseType
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.scope = scope
        self.state = state
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
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
