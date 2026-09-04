import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// The metadata must describe the server that is actually running.
///
/// A conformant client reads `/.well-known/oauth-authorization-server` to decide what it may
/// attempt. Everything absent from that document is a capability the client will never try,
/// however completely it is implemented.
///
/// Across seven releases this package gained the device grant, token exchange, PAR,
/// introspection and two mTLS authentication methods, and the metadata continued to advertise
/// two grants and three authentication methods. Each release added a capability and a test
/// proving the capability worked; none checked that the server still described itself.
///
/// These tests compare the advertisement against the implementation, so the two cannot drift
/// again without something going red.
@Suite("Metadata accuracy — the server describes itself")
struct MetadataAccuracyTests {

    private func makeServer(scopes: [String]? = ["read"]) async throws -> OAuthServer {
        let storage = try OAuthStorage(path: ":memory:")
        return await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com",
            scopesSupported: scopes,
            // These tests assert what is advertised, so they declare the full set — a
            // deployment routing everything. `AdvertisedEndpointsTests` covers the subset case.
            served: try ServedCapabilities(
                grantTypes: [.authorizationCode, .refreshToken, .deviceCode, .tokenExchange],
                clientAuthenticationMethods: [
                    .clientSecretBasic, .clientSecretPost, .none,
                    .tlsClientAuth, .selfSignedTLSClientAuth],
                introspection: "https://mcp.example.com/introspect",
                pushedAuthorizationRequest: "https://mcp.example.com/par",
                deviceAuthorization: "https://mcp.example.com/device_authorization"), resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
    }

    /// Every grant this server implements is advertised.
    ///
    /// Compared against `GrantType` rather than a second literal list, because two lists drift
    /// and this is a test about drift. `clientCredentials` is excluded deliberately: the
    /// provider does not issue those, and advertising a grant it refuses is worse than not
    /// advertising one it honours.
    @Test("The advertised grants are the grants this server honours")
    func advertisedGrantsMatchImplementation() async throws {
        let metadata = try await makeServer().getMetadata()
        let advertised = Set(metadata.grantTypesSupported)

        let honoured: Set<String> = [
            GrantType.authorizationCode.rawValue,
            GrantType.refreshToken.rawValue,
            GrantType.deviceCode.rawValue,
            GrantType.tokenExchange.rawValue
        ]

        #expect(advertised == honoured,
                "the metadata and the implementation disagree about which grants exist")
        #expect(!advertised.contains(GrantType.clientCredentials.rawValue),
                "advertising a grant this provider refuses is worse than omitting one it honours")
    }

    /// The mTLS authentication methods are advertised, or no client will use them.
    @Test("The advertised authentication methods include the mTLS ones")
    func advertisedAuthMethodsIncludeMTLS() async throws {
        let metadata = try await makeServer().getMetadata()
        let advertised = Set(metadata.tokenEndpointAuthMethodsSupported)

        #expect(advertised.contains(ClientAuthenticationMethod.tlsClientAuth.rawValue))
        #expect(advertised.contains(ClientAuthenticationMethod.selfSignedTLSClientAuth.rawValue))
    }

    /// The endpoints added since 0.9.0 are discoverable.
    ///
    /// An endpoint absent from the metadata is one a conformant client will not call, so
    /// implementing it and not advertising it leaves the work unreachable.
    @Test("Introspection, PAR and device authorization endpoints are advertised")
    func newEndpointsAreAdvertised() async throws {
        let metadata = try await makeServer().getMetadata()

        #expect(metadata.introspectionEndpoint == "https://mcp.example.com/introspect")
        #expect(metadata.pushedAuthorizationRequestEndpoint
            == "https://mcp.example.com/par")
        #expect(metadata.deviceAuthorizationEndpoint
            == "https://mcp.example.com/device_authorization")
    }

    /// DPoP is not advertised here: whether a deployment honours proofs is its own fact, and
    /// this fixture declares the full set. See `MetadataFieldOwnershipTests`, which supersedes
    /// the assertion that used to live here — it asserted the algorithms were advertised
    /// unconditionally, which was the fourth instance of the library-versus-deployment defect.

    /// Scopes come from the consumer, and there is no default.
    @Test("Advertised scopes are the ones the consumer supplied")
    func scopesComeFromTheConsumer() async throws {
        let metadata = try await makeServer(scopes: ["files:read", "files:write"]).getMetadata()

        #expect(metadata.scopesSupported == ["files:read", "files:write"])
    }

    /// A consumer that supplies none advertises none — rather than three MCP scopes it never
    /// chose.
    ///
    /// This is the change §18 asked for. The previous default was load-bearing for at least one
    /// consumer, which supplied nothing and advertised three scopes purely because this package
    /// invented them.
    @Test("A consumer supplying no scopes advertises no scopes")
    func absentScopesAreNotInvented() async throws {
        let metadata = try await makeServer(scopes: nil).getMetadata()

        #expect(metadata.scopesSupported == nil,
                "this package invented scopes the consumer never chose")
    }

    /// The protected-resource document agrees with the authorization-server document.
    ///
    /// Two documents describing one deployment, and a client may read either. They are built
    /// separately, so nothing but a test keeps them saying the same thing.
    @Test("Both metadata documents advertise the same scopes")
    func bothDocumentsAgree() async throws {
        let server = try await makeServer(scopes: ["read", "write"])

        let authorizationServer = await server.getMetadata()
        let protectedResource = await server.getProtectedResourceMetadata()

        #expect(authorizationServer.scopesSupported == protectedResource.scopesSupported)
    }
}
