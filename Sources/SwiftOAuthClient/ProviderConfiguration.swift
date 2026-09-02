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

    /// The API a token from this provider is *for* — RFC 8707's resource indicator.
    ///
    /// Without it a token is audience-less. An authorization server protecting several
    /// resources issues something all of them accept, so a token obtained for one service can
    /// be replayed against another; naming the resource is what lets the server bind an
    /// audience, and what lets a resource reject a token minted for somewhere else.
    ///
    /// MCP's 2025-06-18 revision **requires** clients to send this, as the canonical URI of
    /// the MCP server.
    ///
    /// Normalised on the way in: RFC 8707 §2 requires an absolute URI with no fragment, and a
    /// fragment is a client-side concept the server never sees — leaving one on makes two
    /// clients asking for the same audience look like they asked for different ones.
    ///
    /// One resource, not several. RFC 8707 permits the parameter to repeat; token requests
    /// here carry form parameters as a dictionary, which cannot express a repeated key, and
    /// the case needing several has no consumer yet.
    public let resource: URL?

    /// Creates a provider configuration.
    public init(
        identifier: String,
        authorizationEndpoint: URL,
        tokenEndpoint: URL,
        revocationEndpoint: URL? = nil,
        scope: String,
        authenticationMethod: ClientAuthenticationMethod = .clientSecretBasic,
        resource: URL? = nil
    ) {
        self.identifier = identifier
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.revocationEndpoint = revocationEndpoint
        self.scope = scope
        self.authenticationMethod = authenticationMethod
        self.resource = Self.canonical(resource)
    }

    /// The form RFC 8707 §2 requires: absolute, and without a fragment.
    ///
    /// - Parameter resource: The resource as configured.
    /// - Returns: The canonical URI, or `nil` if there was none or it is not absolute.
    private static func canonical(_ resource: URL?) -> URL? {
        guard let resource,
              var components = URLComponents(url: resource, resolvingAgainstBaseURL: false),
              components.scheme != nil else {
            return nil
        }
        components.fragment = nil
        return components.url
    }

    /// The resource indicator as a request parameter, when there is one.
    ///
    /// A single place so the authorization request, the code exchange and the refresh cannot
    /// disagree about it — RFC 8707 requires it on all three, and a token refreshed without it
    /// can come back audienced to something else long after the sign-in that would explain it.
    var resourceParameter: String? {
        resource?.absoluteString
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

    /// Creates credentials. Prefer ``fromEnvironment(provider:environment:prefix:reading:)``.
    public init(environment: String, clientID: String, clientSecret: String) {
        self.environment = environment
        self.clientID = clientID
        self.clientSecret = clientSecret
    }

    /// The environment variable holding a client identifier.
    ///
    /// - Parameters:
    ///   - provider: The provider identifier.
    ///   - environment: The environment name.
    ///   - prefix: An application name, where the unprefixed variable would be ambiguous.
    /// - Returns: The variable name.
    public static func clientIDVariable(
        provider: String,
        environment: String,
        prefix: String = ""
    ) -> String {
        variableName(provider: provider, environment: environment, prefix: prefix, suffix: "CLIENT_ID")
    }

    /// The environment variable holding a client secret.
    ///
    /// - Parameters:
    ///   - provider: The provider identifier.
    ///   - environment: The environment name.
    ///   - prefix: An application name, where the unprefixed variable would be ambiguous.
    /// - Returns: The variable name.
    public static func clientSecretVariable(
        provider: String,
        environment: String,
        prefix: String = ""
    ) -> String {
        variableName(provider: provider, environment: environment, prefix: prefix, suffix: "CLIENT_SECRET")
    }

    /// Composes a variable name from its parts, omitting an absent prefix entirely.
    ///
    /// A blank prefix must not leave a leading underscore: `_INTUIT_SANDBOX_CLIENT_ID` is a
    /// different variable from `INTUIT_SANDBOX_CLIENT_ID`, and nothing would ever set it.
    private static func variableName(
        provider: String,
        environment: String,
        prefix: String,
        suffix: String
    ) -> String {
        let parts = [prefix, provider, environment]
            .map { $0.trimmingCharacters(in: .whitespaces).uppercased() }
            .filter { !$0.isEmpty }
        return (parts + [suffix]).joined(separator: "_")
    }

    /// Loads credentials from the process environment.
    ///
    /// Variables are namespaced by provider *and* environment, so several can be present at
    /// once with no chance of one being used against another's host.
    ///
    /// - Parameters:
    ///   - provider: The provider identifier.
    ///   - environment: The environment name.
    ///   - prefix: An application name. Supply one where several applications on a machine
    ///     register as separate apps at the same provider — without it they share a variable
    ///     and read each other's credentials.
    ///   - variables: Where to read from. Defaults to the process environment.
    /// - Returns: The credentials.
    /// - Throws: ``ClientCredentialError/missing(variable:)``.
    public static func fromEnvironment(
        provider: String,
        environment: String,
        prefix: String = "",
        reading variables: [String: String] = ProcessInfo.processInfo.environment
    ) throws -> ClientCredentials {
        let idKey = clientIDVariable(provider: provider, environment: environment, prefix: prefix)
        let secretKey = clientSecretVariable(provider: provider, environment: environment, prefix: prefix)

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
