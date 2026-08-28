import Foundation
import SwiftOAuthCore

/// What a client asks for when registering itself, per RFC 7591.
///
/// Registration exists for the case where a client cannot have been configured in advance:
/// a user points it at a server nobody anticipated, and it has to obtain credentials on the
/// spot. That is the ordinary case for MCP, and the reason this type exists at all.
public struct ClientRegistrationRequest: Codable, Sendable, Equatable {

    /// A human-readable name, shown on the consent screen.
    public let clientName: String

    /// Every URI the server may redirect to. The server will accept no others.
    public let redirectUris: [String]

    /// The grants this client intends to use.
    public let grantTypes: [String]

    /// How this client will authenticate at the token endpoint.
    public let tokenEndpointAuthMethod: String

    /// The scopes this client wants.
    public let scope: String?

    private enum CodingKeys: String, CodingKey {
        case clientName = "client_name"
        case redirectUris = "redirect_uris"
        case grantTypes = "grant_types"
        case tokenEndpointAuthMethod = "token_endpoint_auth_method"
        case scope
    }

    /// Creates a registration request.
    ///
    /// - Parameters:
    ///   - clientName: The name to show a user.
    ///   - redirectUris: Where the server may redirect.
    ///   - grantTypes: Defaults to authorization code plus refresh, which is what
    ///     ``OAuthConnection`` uses. Requesting more than is used widens what a leaked
    ///     credential can do.
    ///   - tokenEndpointAuthMethod: Defaults to `none` — a public client. An application that
    ///     cannot keep a secret should not be issued one, and a native client cannot.
    ///   - scope: The scopes wanted.
    public init(
        clientName: String,
        redirectUris: [String],
        grantTypes: [String] = [
            GrantType.authorizationCode.rawValue,
            GrantType.refreshToken.rawValue
        ],
        tokenEndpointAuthMethod: String = ClientAuthenticationMethod.none.rawValue,
        scope: String? = nil
    ) {
        self.clientName = clientName
        self.redirectUris = redirectUris
        self.grantTypes = grantTypes
        self.tokenEndpointAuthMethod = tokenEndpointAuthMethod
        self.scope = scope
    }
}

/// What a server returns when it registers a client.
public struct ClientRegistrationResponse: Codable, Sendable, Equatable {

    /// The issued client identifier.
    public let clientId: String

    /// The issued secret, if this client is confidential.
    ///
    /// Absent for a public client — which is correct, not a failure. A native application
    /// cannot keep a secret, and one embedded in a shipped binary is public by definition.
    public let clientSecret: String?

    /// The name as registered.
    public let clientName: String?

    /// The redirect URIs as registered.
    public let redirectUris: [String]?

    private enum CodingKeys: String, CodingKey {
        case clientId = "client_id"
        case clientSecret = "client_secret"
        case clientName = "client_name"
        case redirectUris = "redirect_uris"
    }

    /// Creates a registration response.
    public init(
        clientId: String,
        clientSecret: String? = nil,
        clientName: String? = nil,
        redirectUris: [String]? = nil
    ) {
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.clientName = clientName
        self.redirectUris = redirectUris
    }

    /// The issued credentials, ready for ``OAuthConnection``.
    ///
    /// - Parameter environment: A label for these credentials.
    /// - Returns: The credentials. A public client gets an empty secret, and the
    ///   authentication method it must then use is `ClientAuthenticationMethod.none`.
    public func credentials(environment: String) -> ClientCredentials {
        ClientCredentials(
            environment: environment,
            clientID: clientId,
            clientSecret: clientSecret ?? "")
    }

    /// How a client holding these credentials must authenticate.
    ///
    /// Derived rather than chosen. Presenting `client_secret_basic` with no secret fails at
    /// the token endpoint with `invalid_client`, which reads like wrong credentials rather
    /// than like the wrong method.
    public var authenticationMethod: ClientAuthenticationMethod {
        clientSecret == nil ? .none : .clientSecretBasic
    }
}
