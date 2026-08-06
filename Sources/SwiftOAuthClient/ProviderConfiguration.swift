import Foundation
import SwiftOAuthCore

/// Where a provider's OAuth endpoints are, and what to ask it for.
public struct ProviderConfiguration: Sendable, Equatable {

    /// A short identifier — `"quickbooks"`. Used in ``ConnectionID``.
    public let identifier: String

    /// Where the user is sent to authorise.
    public let authorizationEndpoint: URL

    /// Where codes and refresh tokens are exchanged.
    public let tokenEndpoint: URL

    /// Where a token is revoked, if the provider offers it.
    ///
    /// Optional because many do not. Its absence is why ``OAuthConnection/disconnect()``
    /// cannot always guarantee the provider forgot you.
    public let revocationEndpoint: URL?

    /// The scopes to request, space-separated per RFC 6749 §3.3.
    public let scope: String

    /// How the client authenticates at the token endpoint.
    public let authenticationMethod: ClientAuthenticationMethod

    /// Creates a provider configuration.
    public init(
        identifier: String,
        authorizationEndpoint: URL,
        tokenEndpoint: URL,
        revocationEndpoint: URL? = nil,
        scope: String,
        authenticationMethod: ClientAuthenticationMethod = .clientSecretBasic
    ) {
        self.identifier = identifier
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.revocationEndpoint = revocationEndpoint
        self.scope = scope
        self.authenticationMethod = authenticationMethod
    }
}

/// An application's credentials for one provider **environment**.
///
/// The environment is carried *by* the credential rather than held alongside it. Sandbox and
/// production use different client identifiers against different hosts, and presenting one
/// environment's credentials to the other fails with a bare `invalid_client` and no further
/// explanation — a genuinely miserable thing to debug. Binding them makes the mismatch
/// unrepresentable rather than a thing to remember.
public struct ClientCredentials: Sendable, Equatable {

    /// Which environment these belong to — `"sandbox"`, `"production"`.
    public let environment: String

    /// The client identifier. Semi-public: it travels in authorization URLs.
    public let clientID: String

    /// The client secret. **A credential.** Never logged, never committed.
    public let clientSecret: String

    /// Creates credentials. Prefer ``fromEnvironment(provider:environment:reading:)``.
    public init(environment: String, clientID: String, clientSecret: String) {
        self.environment = environment
        self.clientID = clientID
        self.clientSecret = clientSecret
    }

    /// The environment variable holding a client identifier.
    public static func clientIDVariable(provider: String, environment: String) -> String {
        "\(provider.uppercased())_\(environment.uppercased())_CLIENT_ID"
    }

    /// The environment variable holding a client secret.
    public static func clientSecretVariable(provider: String, environment: String) -> String {
        "\(provider.uppercased())_\(environment.uppercased())_CLIENT_SECRET"
    }

    /// Loads credentials from the process environment.
    ///
    /// Variables are namespaced by provider *and* environment, so several can be present at
    /// once with no chance of one being used against another's host.
    ///
    /// - Parameters:
    ///   - provider: The provider identifier.
    ///   - environment: The environment name.
    ///   - variables: Where to read from. Defaults to the process environment.
    /// - Returns: The credentials.
    /// - Throws: ``ClientCredentialError/missing(variable:)``.
    public static func fromEnvironment(
        provider: String,
        environment: String,
        reading variables: [String: String] = ProcessInfo.processInfo.environment
    ) throws -> ClientCredentials {
        let idKey = clientIDVariable(provider: provider, environment: environment)
        let secretKey = clientSecretVariable(provider: provider, environment: environment)

        guard let id = variables[idKey], !id.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw ClientCredentialError.missing(variable: idKey)
        }
        guard let secret = variables[secretKey],
              !secret.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw ClientCredentialError.missing(variable: secretKey)
        }
        return ClientCredentials(environment: environment, clientID: id, clientSecret: secret)
    }
}

/// Why credentials could not be loaded.
public enum ClientCredentialError: Error, Equatable, Sendable {

    /// A required environment variable was absent or blank.
    ///
    /// Blank counts as absent: an empty secret fails at the provider with the same opaque
    /// `invalid_client` as a wrong one, so catching it here saves the debugging.
    case missing(variable: String)
}

extension ClientCredentials: CustomStringConvertible, CustomDebugStringConvertible {

    /// Redacts the secret, and shortens the identifier.
    ///
    /// String interpolation is how credentials reach logs. Making the default rendering safe
    /// means exposing one has to be written on purpose.
    public var description: String {
        "ClientCredentials(environment: \(environment), clientID: \(Self.redact(clientID)), clientSecret: <redacted>)"
    }

    /// The same redacted rendering, so `String(reflecting:)` cannot expose what
    /// ``description`` hides.
    public var debugDescription: String { description }

    /// Shows enough of a value to recognise it, never enough to use it.
    static func redact(_ value: String) -> String {
        guard value.count > 8 else { return "<redacted>" }
        return value.prefix(4) + "…" + value.suffix(4)
    }
}
