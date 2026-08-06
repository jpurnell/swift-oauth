import Foundation
import SwiftOAuthCore

/// An authorization server's advertised capabilities, per RFC 8414.
///
/// A client that hardcodes endpoints works until the server moves one. A client that reads
/// them works, and — more usefully — can talk to a server it was never configured for. That
/// is the case MCP actually has: a client is pointed at a server URL by a user and has to
/// find everything else out.
public struct AuthorizationServerMetadata: Codable, Sendable, Equatable {

    /// The server's issuer identifier.
    public let issuer: String

    /// Where the user is sent to authorise.
    public let authorizationEndpoint: String

    /// Where codes and refresh tokens are exchanged.
    public let tokenEndpoint: String

    /// Where a client may register itself, if the server allows it.
    public let registrationEndpoint: String?

    /// The PKCE methods the server will accept.
    ///
    /// Optional on the wire, and its absence is not "anything goes" — RFC 8414 says a server
    /// that omits it does not support PKCE at all.
    public let codeChallengeMethodsSupported: [String]?

    /// The grant types the server will honour.
    public let grantTypesSupported: [String]?

    /// The scopes the server recognises.
    public let scopesSupported: [String]?

    /// Where a token may be revoked, if the server offers it.
    public let revocationEndpoint: String?

    private enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case registrationEndpoint = "registration_endpoint"
        case codeChallengeMethodsSupported = "code_challenge_methods_supported"
        case grantTypesSupported = "grant_types_supported"
        case scopesSupported = "scopes_supported"
        case revocationEndpoint = "revocation_endpoint"
    }

    /// Creates metadata.
    public init(
        issuer: String,
        authorizationEndpoint: String,
        tokenEndpoint: String,
        registrationEndpoint: String? = nil,
        codeChallengeMethodsSupported: [String]? = nil,
        grantTypesSupported: [String]? = nil,
        scopesSupported: [String]? = nil,
        revocationEndpoint: String? = nil
    ) {
        self.issuer = issuer
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.registrationEndpoint = registrationEndpoint
        self.codeChallengeMethodsSupported = codeChallengeMethodsSupported
        self.grantTypesSupported = grantTypesSupported
        self.scopesSupported = scopesSupported
        self.revocationEndpoint = revocationEndpoint
    }
}

/// Why discovered metadata could not be used.
public enum DiscoveryError: Error, Equatable, Sendable {

    /// An advertised endpoint was not a usable URL.
    case malformedEndpoint(String)

    /// An advertised endpoint was not HTTPS.
    ///
    /// Refused rather than warned about. Every secret in this protocol — the code, the
    /// verifier, the client secret, the tokens themselves — crosses these endpoints, and a
    /// server that can be talked out of TLS by its own metadata protects none of them.
    case insecureEndpoint(String)

    /// The server does not support S256, so PKCE cannot protect this flow.
    case pkceUnsupported

    /// An advertised endpoint pointed somewhere other than the issuer.
    ///
    /// Metadata is fetched over the network and names the hosts this client will shortly
    /// send an authorization code, a client secret and a refresh token to. A document that
    /// can nominate *any* host turns discovery into an instruction to post credentials
    /// wherever the document says — including at an address only reachable from inside the
    /// network the client is running in.
    ///
    /// RFC 8414 §3.3 requires the `issuer` in the document to match the one discovery was
    /// performed against; requiring the endpoints to share its origin is the same principle
    /// applied to the fields that actually receive secrets.
    case endpointOutsideIssuer(String)
}

extension AuthorizationServerMetadata {

    /// Converts discovered metadata into a usable configuration.
    ///
    /// Validating rather than trusting. Metadata arrives over the network, and the endpoints
    /// in it are where this client will shortly send an authorization code and a client
    /// secret. Anything not HTTPS is refused, as is a server that cannot do S256 — accepting
    /// one would mean running the flow with no PKCE protection at all.
    ///
    /// - Parameters:
    ///   - identifier: A short name for this provider, used in ``ConnectionID``.
    ///   - scope: The scopes to request. Defaults to everything the server advertises.
    /// - Returns: A configuration.
    /// - Throws: ``DiscoveryError``.
    public func configuration(
        identifier: String,
        scope: String? = nil
    ) throws -> ProviderConfiguration {
        guard let methods = codeChallengeMethodsSupported,
              methods.contains(PKCE.ChallengeMethod.s256.rawValue) else {
            throw DiscoveryError.pkceUnsupported
        }

        let origin = try Self.secureURL(issuer)
        return ProviderConfiguration(
            identifier: identifier,
            authorizationEndpoint: try Self.endpoint(authorizationEndpoint, within: origin),
            tokenEndpoint: try Self.endpoint(tokenEndpoint, within: origin),
            revocationEndpoint: try revocationEndpoint.map { try Self.endpoint($0, within: origin) },
            scope: scope ?? (scopesSupported ?? []).joined(separator: " "))
    }

    /// The registration endpoint as a validated URL, if the server offers one.
    ///
    /// - Returns: The endpoint, or `nil` if registration is not offered.
    /// - Throws: ``DiscoveryError`` if one is offered but unusable.
    public func registrationURL() throws -> URL? {
        let origin = try Self.secureURL(issuer)
        return try registrationEndpoint.map { try Self.endpoint($0, within: origin) }
    }

    /// Parses an advertised endpoint, validating it before it can be used.
    ///
    /// Construction and validation are deliberately the same function. Every string reaching
    /// here came out of a document fetched over the network, and it names a host this client
    /// will shortly post an authorization code, a client secret or a refresh token to. A
    /// check that lives somewhere else is a check a later caller can forget.
    ///
    /// Two rules, both refusals rather than warnings:
    ///
    /// - **HTTPS.** Every secret in this protocol crosses these endpoints, and a document
    ///   that can talk the client out of TLS protects none of them.
    /// - **The issuer's origin**, when one is given. Host and port both, compared
    ///   case-insensitively because RFC 3986 §3.2.2 makes a host case-insensitive. Without
    ///   this a metadata document is an instruction to post credentials to whatever host it
    ///   names — including one reachable only from inside the network the client runs in.
    ///
    /// - Parameters:
    ///   - string: The advertised endpoint.
    ///   - allowedOrigin: The issuer this endpoint must belong to. `nil` only when parsing
    ///     the issuer itself, which comes from the caller rather than from the network.
    /// - Returns: The validated URL.
    /// - Throws: ``DiscoveryError``.
    static func validatedURL(_ string: String, allowedOrigin: URL?) throws -> URL {
        // Parsed into components rather than straight into a `URL`. The scheme, host and
        // port are exactly what has to be checked, and this way the URL is finally built
        // *from the validated components* rather than from the untrusted string — there is
        // no point at which a URL exists that has not been through the rules below.
        guard let components = URLComponents(string: string),
              let host = components.host?.lowercased(),
              !host.isEmpty else {
            throw DiscoveryError.malformedEndpoint(string)
        }

        // Compared lowercased: RFC 3986 §3.1 makes the scheme case-insensitive, so `HTTPS`
        // is legitimate and would otherwise be refused for the wrong reason.
        guard components.scheme?.lowercased() == "https" else {
            throw DiscoveryError.insecureEndpoint(string)
        }

        if let allowedOrigin {
            guard let expected = allowedOrigin.host?.lowercased(), host == expected else {
                throw DiscoveryError.endpointOutsideIssuer(string)
            }
            // A differing port is a different origin, and moving the token endpoint to
            // another port on the same host is the same manoeuvre as moving it elsewhere.
            guard components.port == allowedOrigin.port else {
                throw DiscoveryError.endpointOutsideIssuer(string)
            }
        }

        guard let url = components.url else {
            throw DiscoveryError.malformedEndpoint(string)
        }
        return url
    }

    /// Parses the issuer itself, which is supplied by the caller rather than the network.
    static func secureURL(_ string: String) throws -> URL {
        try validatedURL(string, allowedOrigin: nil)
    }

    /// Parses an advertised endpoint and confirms it belongs to the issuer.
    static func endpoint(_ string: String, within origin: URL) throws -> URL {
        try validatedURL(string, allowedOrigin: origin)
    }

    /// The well-known path RFC 8414 §3 defines for an issuer.
    ///
    /// The path is inserted *before* any path the issuer carries, rather than appended —
    /// `https://host/tenant` discovers at `https://host/.well-known/…/tenant`, not
    /// `https://host/tenant/.well-known/…`. Appending is the common mistake and it silently
    /// finds nothing on a multi-tenant server.
    ///
    /// - Parameter issuer: The issuer identifier.
    /// - Returns: Where to fetch metadata.
    /// - Throws: ``DiscoveryError/malformedEndpoint(_:)``.
    public static func discoveryURL(issuer: String) throws -> URL {
        let base = try secureURL(issuer)
        guard var components = URLComponents(url: base, resolvingAgainstBaseURL: false) else {
            throw DiscoveryError.malformedEndpoint(issuer)
        }
        let issuerPath = components.path.hasSuffix("/")
            ? String(components.path.dropLast())
            : components.path
        components.path = "/.well-known/oauth-authorization-server" + issuerPath
        guard let url = components.url else {
            throw DiscoveryError.malformedEndpoint(issuer)
        }
        return url
    }
}
