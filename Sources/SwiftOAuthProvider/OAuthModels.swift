import Foundation
import SwiftOAuthCore

// MARK: - RegisteredClient

/// A registered OAuth 2.0 client
///
/// Represents a client application that has been registered with the OAuth server.
/// Clients can be confidential (with a secret) or public (without a secret).
///
/// ## Topics
///
/// ### Creating Clients
/// - ``init(clientId:clientSecret:clientName:redirectUris:grantTypes:tokenEndpointAuthMethod:registrationDate:)``
///
/// ### Client Properties
/// - ``clientId``
/// - ``clientSecret``
/// - ``clientName``
/// - ``redirectUris``
/// - ``grantTypes``
/// - ``tokenEndpointAuthMethod``
/// - ``registrationDate``
///
/// ## MCP Schema
///
/// **REQUIRED STRUCTURE (JSON):**
/// ```json
/// {
///   "client_id": "abc123",
///   "client_secret": "secret456",
///   "client_name": "My MCP Client",
///   "redirect_uris": ["http://localhost:8080/callback"],
///   "grant_types": ["authorization_code", "refresh_token"],
///   "token_endpoint_auth_method": "client_secret_basic",
///   "registration_date": 1710432000
/// }
/// ```
public struct RegisteredClient: Codable, Sendable, Equatable {
    /// Unique identifier for the client
    public let clientId: String

    /// Client secret for confidential clients (nil for public clients)
    public let clientSecret: String?

    /// Human-readable name of the client application
    public let clientName: String

    /// Valid redirect URIs for authorization responses
    public let redirectUris: [String]

    /// OAuth grant types this client is authorized to use
    public let grantTypes: [String]

    /// Authentication method for the token endpoint
    public let tokenEndpointAuthMethod: String

    /// When this client was registered
    public let registrationDate: Date

    /// Creates a new registered client
    /// - Parameters:
    ///   - clientId: Unique identifier for the client
    ///   - clientSecret: Secret for confidential clients (nil for public clients)
    ///   - clientName: Human-readable application name
    ///   - redirectUris: Valid redirect URIs
    ///   - grantTypes: Authorized grant types
    ///   - tokenEndpointAuthMethod: Token endpoint auth method
    ///   - registrationDate: Registration timestamp
    public init(
        clientId: String,
        clientSecret: String?,
        clientName: String,
        redirectUris: [String],
        grantTypes: [String],
        tokenEndpointAuthMethod: String,
        registrationDate: Date
    ) {
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.clientName = clientName
        self.redirectUris = redirectUris
        self.grantTypes = grantTypes
        self.tokenEndpointAuthMethod = tokenEndpointAuthMethod
        self.registrationDate = registrationDate
    }

    // MARK: - Codable

    private enum CodingKeys: String, CodingKey {
        case clientId = "client_id"
        case clientSecret = "client_secret"
        case clientName = "client_name"
        case redirectUris = "redirect_uris"
        case grantTypes = "grant_types"
        case tokenEndpointAuthMethod = "token_endpoint_auth_method"
        case registrationDate = "registration_date"
    }
}

// MARK: - ClientRegistrationRequest

/// Request to register a new OAuth client
///
/// Used by clients to dynamically register with the OAuth server per RFC 7591.
///
/// ## MCP Schema
///
/// **REQUIRED STRUCTURE (JSON):**
/// ```json
/// {
///   "client_name": "My MCP Client",
///   "redirect_uris": ["http://localhost:8080/callback"],
///   "grant_types": ["authorization_code", "refresh_token"],
///   "token_endpoint_auth_method": "client_secret_basic",
///   "scope": "mcp:tools mcp:resources"
/// }
/// ```
public struct ClientRegistrationRequest: Codable, Sendable, Equatable {
    /// Human-readable name for the client
    public let clientName: String

    /// Redirect URIs for authorization responses
    public let redirectUris: [String]

    /// Requested grant types (defaults to ["authorization_code"])
    public let grantTypes: [String]

    /// Requested token endpoint auth method (defaults to "client_secret_basic")
    public let tokenEndpointAuthMethod: String

    /// Requested scope (optional)
    public let scope: String?

    /// Creates a client registration request
    /// - Parameters:
    ///   - clientName: Human-readable name for the client
    ///   - redirectUris: Redirect URIs for authorization responses
    ///   - grantTypes: Requested grant types
    ///   - tokenEndpointAuthMethod: Token endpoint auth method
    ///   - scope: Requested scope
    public init(
        clientName: String,
        redirectUris: [String],
        grantTypes: [String] = ["authorization_code"],
        tokenEndpointAuthMethod: String = "client_secret_basic",
        scope: String? = nil
    ) {
        self.clientName = clientName
        self.redirectUris = redirectUris
        self.grantTypes = grantTypes
        self.tokenEndpointAuthMethod = tokenEndpointAuthMethod
        self.scope = scope
    }

    // MARK: - Codable

    private enum CodingKeys: String, CodingKey {
        case clientName = "client_name"
        case redirectUris = "redirect_uris"
        case grantTypes = "grant_types"
        case tokenEndpointAuthMethod = "token_endpoint_auth_method"
        case scope
    }

    /// Decodes a client registration request from the given decoder
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.clientName = try container.decode(String.self, forKey: .clientName)
        self.redirectUris = try container.decode([String].self, forKey: .redirectUris)
        self.grantTypes = try container.decodeIfPresent([String].self, forKey: .grantTypes) ?? ["authorization_code"]
        self.tokenEndpointAuthMethod = try container.decodeIfPresent(String.self, forKey: .tokenEndpointAuthMethod) ?? "client_secret_basic"
        self.scope = try container.decodeIfPresent(String.self, forKey: .scope)
    }
}

// MARK: - TokenValidationResult

/// Result of validating an access token
public enum TokenValidationResult: Sendable, Equatable {
    /// Token is valid with associated client and scope
    case valid(clientId: String, scope: String?)

    /// Token is invalid with reason
    case invalid(reason: String)

    /// Convenience property to check if token is valid
    public var isValid: Bool {
        if case .valid = self {
            return true
        }
        return false
    }
}

// MARK: - AuthorizationCode

/// An OAuth authorization code issued during the authorization flow
///
/// Authorization codes are short-lived and single-use.
public struct AuthorizationCode: Codable, Sendable, Equatable {
    /// The authorization code value
    public let code: String

    /// Client that requested this code
    public let clientId: String

    /// Redirect URI used in the request
    public let redirectUri: String

    /// Scope requested (optional)
    public let scope: String?

    /// PKCE code challenge (optional)
    public let codeChallenge: String?

    /// PKCE code challenge method (optional, typically "S256")
    public let codeChallengeMethod: String?

    /// When this code expires
    public let expiresAt: Date

    /// When this code was created
    public let createdAt: Date

    /// Whether this code has expired
    public var isExpired: Bool {
        Date() >= expiresAt
    }

    /// Creates an authorization code
    /// - Parameters:
    ///   - code: The code value
    ///   - clientId: Client that requested this code
    ///   - redirectUri: Redirect URI from the request
    ///   - scope: Requested scope
    ///   - codeChallenge: PKCE code challenge
    ///   - codeChallengeMethod: PKCE method
    ///   - expiresAt: Expiration time
    ///   - createdAt: Creation time
    public init(
        code: String,
        clientId: String,
        redirectUri: String,
        scope: String?,
        codeChallenge: String?,
        codeChallengeMethod: String?,
        expiresAt: Date,
        createdAt: Date
    ) {
        self.code = code
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.scope = scope
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
        self.expiresAt = expiresAt
        self.createdAt = createdAt
    }

    // MARK: - Codable

    private enum CodingKeys: String, CodingKey {
        case code
        case clientId = "client_id"
        case redirectUri = "redirect_uri"
        case scope
        case codeChallenge = "code_challenge"
        case codeChallengeMethod = "code_challenge_method"
        case expiresAt = "expires_at"
        case createdAt = "created_at"
    }
}

// MARK: - CSRFValidationResult

/// Result of CSRF token validation
///
/// Used by the consent page submission handler to verify
/// that the form submission is legitimate.
public struct CSRFValidationResult: Sendable, Equatable {
    /// Whether the CSRF token is valid
    public let isValid: Bool

    /// Error message if validation failed
    public let error: String?

    /// Creates a validation result
    /// - Parameters:
    ///   - isValid: Whether the token is valid
    ///   - error: Error message if invalid
    public init(isValid: Bool, error: String? = nil) {
        self.isValid = isValid
        self.error = error
    }
}
