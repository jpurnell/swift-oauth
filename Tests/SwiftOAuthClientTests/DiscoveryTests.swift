import Foundation
import Testing
import SwiftOAuthCore
@testable import SwiftOAuthClient

/// Discovery reads a document off the network and turns it into the list of hosts this
/// client will post an authorization code, a client secret and a refresh token to. Every
/// test here is about refusing a document that abuses that.
@Suite("Discovery — validating what the network said")
struct DiscoveryValidationTests {

    /// The ordinary case.
    @Test("Well-formed metadata becomes a configuration")
    func wellFormedMetadata() throws {
        let configuration = try metadata().configuration(identifier: "mcp")

        #expect(configuration.authorizationEndpoint.absoluteString
                == "https://mcp.example.com/authorize")
        #expect(configuration.tokenEndpoint.absoluteString == "https://mcp.example.com/token")
        #expect(configuration.revocationEndpoint?.absoluteString
                == "https://mcp.example.com/revoke")
        #expect(configuration.scope == "mcp:tools mcp:resources")
    }

    /// The endpoints are where the secrets go. A document that can name any host is an
    /// instruction to post credentials wherever it says.
    @Test("An endpoint on another host is refused")
    func foreignHostRefused() {
        for hostile in [
            "https://attacker.example/token",
            "https://mcp.example.com.attacker.example/token",
            "https://attacker.example/?x=mcp.example.com"
        ] {
            #expect(throws: DiscoveryError.endpointOutsideIssuer(hostile),
                    "\(hostile) was accepted") {
                try metadata(tokenEndpoint: hostile).configuration(identifier: "mcp")
            }
        }
    }

    /// Including a host only reachable from inside the network this client runs in — the
    /// case that turns a metadata document into an SSRF primitive.
    @Test("An internal-only endpoint is refused")
    func internalHostRefused() {
        for internalHost in [
            "https://169.254.169.254/latest/meta-data/token",
            "https://localhost/token",
            "https://10.0.0.1/token"
        ] {
            #expect(throws: DiscoveryError.endpointOutsideIssuer(internalHost),
                    "\(internalHost) was accepted") {
                try metadata(tokenEndpoint: internalHost).configuration(identifier: "mcp")
            }
        }
    }

    /// Same host, different port is a different origin, and moving the token endpoint to
    /// one is the same manoeuvre as moving it to another host.
    @Test("A differing port is refused")
    func differingPortRefused() {
        #expect(throws: DiscoveryError.endpointOutsideIssuer("https://mcp.example.com:8443/token")) {
            try metadata(tokenEndpoint: "https://mcp.example.com:8443/token")
                .configuration(identifier: "mcp")
        }
    }

    /// A host is case-insensitive, so a differently-cased one is the same origin and must
    /// not be refused for the wrong reason.
    @Test("Case differences in the host are accepted")
    func hostCaseAccepted() throws {
        let configuration = try metadata(tokenEndpoint: "https://MCP.Example.COM/token")
            .configuration(identifier: "mcp")
        #expect(configuration.tokenEndpoint.host()?.lowercased() == "mcp.example.com")
    }

    /// Every secret in the protocol crosses these endpoints.
    @Test("A non-HTTPS endpoint is refused")
    func insecureEndpointRefused() {
        #expect(throws: DiscoveryError.insecureEndpoint("http://mcp.example.com/token")) {
            try metadata(tokenEndpoint: "http://mcp.example.com/token")
                .configuration(identifier: "mcp")
        }
    }

    /// The scheme is case-insensitive, so an upper-cased one is legitimate.
    @Test("An upper-cased HTTPS scheme is accepted")
    func upperCasedSchemeAccepted() throws {
        let configuration = try metadata(tokenEndpoint: "HTTPS://mcp.example.com/token")
            .configuration(identifier: "mcp")
        #expect(configuration.tokenEndpoint.scheme?.lowercased() == "https")
    }

    /// Absent PKCE support is not "anything goes" — RFC 8414 says a server that omits the
    /// field does not support PKCE, and running the flow without it means no protection
    /// against code interception at all.
    @Test("A server advertising no S256 is refused")
    func missingPKCERefused() {
        #expect(throws: DiscoveryError.pkceUnsupported) {
            try metadata(challengeMethods: nil).configuration(identifier: "mcp")
        }
        #expect(throws: DiscoveryError.pkceUnsupported) {
            try metadata(challengeMethods: ["plain"]).configuration(identifier: "mcp")
        }
    }

    /// The registration endpoint receives the client's name and redirect URIs and returns
    /// its credentials, so it is bound to the issuer exactly as the others are.
    @Test("The registration endpoint is bound to the issuer too")
    func registrationEndpointBound() throws {
        #expect(try metadata().registrationURL()?.absoluteString
                == "https://mcp.example.com/register")

        #expect(throws: DiscoveryError.endpointOutsideIssuer("https://attacker.example/register")) {
            try metadata(registrationEndpoint: "https://attacker.example/register")
                .registrationURL()
        }

        #expect(try metadata(registrationEndpoint: nil).registrationURL() == nil)
    }
}

@Suite("Discovery — the well-known URL")
struct DiscoveryURLTests {

    /// RFC 8414 §3 inserts the well-known path *before* the issuer's path. Appending is the
    /// common mistake, and on a multi-tenant server it silently finds nothing.
    @Test("The well-known path precedes the issuer path")
    func wellKnownPrecedesIssuerPath() throws {
        #expect(try AuthorizationServerMetadata.discoveryURL(issuer: "https://host.example")
                .absoluteString == "https://host.example/.well-known/oauth-authorization-server")

        #expect(try AuthorizationServerMetadata.discoveryURL(issuer: "https://host.example/tenant")
                .absoluteString
                == "https://host.example/.well-known/oauth-authorization-server/tenant")
    }

    /// A trailing slash on the issuer must not produce a doubled one.
    @Test("A trailing slash on the issuer is handled")
    func trailingSlashHandled() throws {
        #expect(try AuthorizationServerMetadata.discoveryURL(issuer: "https://host.example/tenant/")
                .absoluteString
                == "https://host.example/.well-known/oauth-authorization-server/tenant")
    }

    /// Discovery itself must not be talked out of TLS.
    @Test("A non-HTTPS issuer is refused")
    func insecureIssuerRefused() {
        #expect(throws: DiscoveryError.insecureEndpoint("http://host.example")) {
            try AuthorizationServerMetadata.discoveryURL(issuer: "http://host.example")
        }
    }
}

// MARK: - Helpers

private func metadata(
    tokenEndpoint: String = "https://mcp.example.com/token",
    registrationEndpoint: String? = "https://mcp.example.com/register",
    challengeMethods: [String]? = ["S256"]
) -> AuthorizationServerMetadata {
    AuthorizationServerMetadata(
        issuer: "https://mcp.example.com",
        authorizationEndpoint: "https://mcp.example.com/authorize",
        tokenEndpoint: tokenEndpoint,
        registrationEndpoint: registrationEndpoint,
        codeChallengeMethodsSupported: challengeMethods,
        scopesSupported: ["mcp:tools", "mcp:resources"],
        revocationEndpoint: "https://mcp.example.com/revoke")
}
