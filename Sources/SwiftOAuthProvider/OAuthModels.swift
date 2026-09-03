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
/// - ``init(clientId:clientSecret:clientName:redirectUris:grantTypes:tokenEndpointAuthMethod:registrationDate:applicationType:)``
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

    /// The kind of application this client is.
    ///
    /// Recorded at registration so redirect-URI validation can distinguish a native client from
    /// a web one, which is the conflict MCP `2026-07-28` requires clients to declare against.
    public let applicationType: ApplicationType

    /// Creates a new registered client
    /// - Parameters:
    ///   - clientId: Unique identifier for the client
    ///   - clientSecret: Secret for confidential clients (nil for public clients)
    ///   - clientName: Human-readable application name
    ///   - redirectUris: Valid redirect URIs
    ///   - grantTypes: Authorized grant types
    ///   - tokenEndpointAuthMethod: Token endpoint auth method
    ///   - registrationDate: Registration timestamp
    ///   - applicationType: Whether the client is a web or native application. Defaults to
    ///     ``ApplicationType/web`` per RFC 7591, which is also the correct reading of a record
    ///     written before this field existed.
    public init(
        clientId: String,
        clientSecret: String?,
        clientName: String,
        redirectUris: [String],
        grantTypes: [String],
        tokenEndpointAuthMethod: String,
        registrationDate: Date,
        applicationType: ApplicationType = .web
    ) {
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.clientName = clientName
        self.redirectUris = redirectUris
        self.grantTypes = grantTypes
        self.tokenEndpointAuthMethod = tokenEndpointAuthMethod
        self.registrationDate = registrationDate
        self.applicationType = applicationType
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
        case applicationType = "application_type"
    }

    /// Decodes a registered client, defaulting `application_type` when it is absent.
    ///
    /// The field was added for MCP `2026-07-28`. Every client registered before then is already
    /// persisted without it, so requiring it would make those records undecodable — the store
    /// would lose every client it had. RFC 7591 makes `web` the default, which is also the
    /// correct reading of a record written when the field did not exist.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        clientId = try container.decode(String.self, forKey: .clientId)
        clientSecret = try container.decodeIfPresent(String.self, forKey: .clientSecret)
        clientName = try container.decode(String.self, forKey: .clientName)
        redirectUris = try container.decode([String].self, forKey: .redirectUris)
        grantTypes = try container.decode([String].self, forKey: .grantTypes)
        tokenEndpointAuthMethod = try container.decode(
            String.self, forKey: .tokenEndpointAuthMethod)
        registrationDate = try container.decode(Date.self, forKey: .registrationDate)
        applicationType =
            try container.decodeIfPresent(ApplicationType.self, forKey: .applicationType) ?? .web
    }
}

// MARK: - ApplicationType

/// The kind of application registering as an OAuth client.
///
/// MCP `2026-07-28` requires clients to declare this during Dynamic Client Registration, to
/// avoid the OpenID Connect redirect-URI conflicts that arise when a native and a web client
/// register the same URI. RFC 7591 defines `web` as the default when the field is omitted.
public enum ApplicationType: String, Codable, Sendable, Equatable {
    /// A client whose redirect URIs are https URLs it controls.
    case web
    /// A client installed on a device, using a custom scheme or loopback redirect.
    case native
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

    /// The kind of application registering.
    ///
    /// Required by MCP `2026-07-28`. Defaults to ``ApplicationType/web`` per RFC 7591 when a
    /// client omits it — not to `nil`, which would leave the redirect-URI conflict this field
    /// exists to prevent unresolved.
    public let applicationType: ApplicationType

    /// Creates a client registration request
    /// - Parameters:
    ///   - clientName: Human-readable name for the client
    ///   - redirectUris: Redirect URIs for authorization responses
    ///   - grantTypes: Requested grant types
    ///   - tokenEndpointAuthMethod: Token endpoint auth method
    ///   - scope: Requested scope
    ///   - applicationType: Whether the client is a web or native application. Required by MCP
    ///     `2026-07-28`; defaults to ``ApplicationType/web`` per RFC 7591 when omitted.
    public init(
        clientName: String,
        redirectUris: [String],
        grantTypes: [String] = ["authorization_code"],
        tokenEndpointAuthMethod: String = "client_secret_basic",
        scope: String? = nil,
        applicationType: ApplicationType = .web
    ) {
        self.clientName = clientName
        self.redirectUris = redirectUris
        self.grantTypes = grantTypes
        self.tokenEndpointAuthMethod = tokenEndpointAuthMethod
        self.scope = scope
        self.applicationType = applicationType
    }

    // MARK: - Codable

    private enum CodingKeys: String, CodingKey {
        case clientName = "client_name"
        case redirectUris = "redirect_uris"
        case grantTypes = "grant_types"
        case tokenEndpointAuthMethod = "token_endpoint_auth_method"
        case scope
        case applicationType = "application_type"
    }

    /// Decodes a client registration request from the given decoder
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.clientName = try container.decode(String.self, forKey: .clientName)
        self.redirectUris = try container.decode([String].self, forKey: .redirectUris)
        self.grantTypes = try container.decodeIfPresent([String].self, forKey: .grantTypes) ?? ["authorization_code"]
        self.tokenEndpointAuthMethod = try container.decodeIfPresent(String.self, forKey: .tokenEndpointAuthMethod) ?? "client_secret_basic"
        self.scope = try container.decodeIfPresent(String.self, forKey: .scope)
        self.applicationType =
            try container.decodeIfPresent(ApplicationType.self, forKey: .applicationType) ?? .web
    }
}

// MARK: - TokenValidationResult

/// Result of validating an access token
public enum TokenValidationResult: Sendable, Equatable {
    /// Token is valid, with the client it was issued to, its scope, and the audience it was
    /// bound to.
    ///
    /// `audience` is RFC 8707's resource indicator: the API this token is *for*. `nil` means
    /// the token is not bound to one — either the server permits that, or the token predates
    /// audiences being recorded. A resource server checking its own identifier against this is
    /// what stops a token minted elsewhere from being accepted here.
    case valid(clientId: String, scope: String?, audience: URL?)

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

// MARK: - DeviceCodeState

/// What a device code currently is — RFC 8628 §3.5.
///
/// ``unknown`` covers both "no such code" and "not yours", deliberately. Distinguishing them
/// tells a caller holding someone else's device code that it exists, which is the one thing
/// they should not learn.
public enum DeviceCodeState: Sendable, Equatable {
    /// No such code, or it belongs to another client.
    case unknown
    /// Issued, and the user has not finished.
    case pending
    /// Approved and ready to exchange.
    case approved(scope: String?)
    /// Already exchanged. Single-use, so a second attempt is a refusal.
    case alreadyRedeemed
    /// Issued, but the user did not finish in time.
    case expired
}
