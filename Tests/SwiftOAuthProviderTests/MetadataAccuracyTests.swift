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
            advertisedEndpoints: AdvertisedEndpoints(
                introspection: "https://mcp.example.com/introspect",
                pushedAuthorizationRequest: "https://mcp.example.com/par",
                deviceAuthorization: "https://mcp.example.com/device_authorization"),
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

    /// DPoP is advertised with the algorithm this server verifies, and only that one.
    ///
    /// A client choosing an algorithm from this list must find only ES256, because that is the
    /// only one `CompactJWS` accepts — advertising more would invite proofs this server refuses.
    @Test("DPoP advertises exactly the algorithm this server verifies")
    func dpopAlgorithmIsAdvertisedAccurately() async throws {
        let metadata = try await makeServer().getMetadata()

        #expect(metadata.dpopSigningAlgValuesSupported == ["ES256"])
    }

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

/// The document describes the deployment, not the library.
///
/// Advertising what this package *implements* is right for a package and wrong for a document.
/// A consumer routes some subset of these endpoints, and the metadata is read by clients who
/// will call whatever it names — so an endpoint advertised and not routed is a discoverable
/// 404, which is a worse failure than not advertising it at all.
///
/// Found by SwiftMCPServer running the change before it was tagged. It routes `/authorize`,
/// `/token`, `/register` and the two well-known documents, and does not route introspection,
/// PAR, device authorization or revocation. Under the first version of this change its servers
/// would have advertised three endpoints a conformant client could discover and could not
/// reach — and that failure lands on the consumer, not here, which is exactly why it could not
/// be found from inside this package.
///
/// So the consumer states what it serves, with no default, on the same argument as the scopes:
/// forgetting produces a compile error rather than a document promising what nobody answers.
@Suite("Metadata accuracy — the document describes the deployment")
struct AdvertisedEndpointsTests {

    private func makeServer(_ endpoints: AdvertisedEndpoints) async throws -> OAuthServer {
        let storage = try OAuthStorage(path: ":memory:")
        return await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com",
            scopesSupported: ["read"], advertisedEndpoints: endpoints,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
    }

    /// A deployment serving none advertises none.
    ///
    /// This is SwiftMCPServer's case: it routes the core three and nothing else.
    @Test("A deployment routing no optional endpoints advertises none")
    func servingNoneAdvertisesNone() async throws {
        let metadata = try await makeServer(.none).getMetadata()

        #expect(metadata.introspectionEndpoint == nil)
        #expect(metadata.pushedAuthorizationRequestEndpoint == nil)
        #expect(metadata.deviceAuthorizationEndpoint == nil)
    }

    /// A deployment serving some advertises exactly those.
    @Test("A deployment advertises exactly the endpoints it routes")
    func advertisesExactlyWhatIsRouted() async throws {
        let metadata = try await makeServer(AdvertisedEndpoints(
            introspection: "https://mcp.example.com/introspect")).getMetadata()

        #expect(metadata.introspectionEndpoint == "https://mcp.example.com/introspect")
        #expect(metadata.pushedAuthorizationRequestEndpoint == nil,
                "an endpoint that is not routed was advertised")
        #expect(metadata.deviceAuthorizationEndpoint == nil)
    }

    /// The DPoP algorithms are a library fact, not a deployment one, so they stay.
    ///
    /// Nothing about routing changes which algorithm `CompactJWS` verifies — a client that
    /// presents a proof does so at the token endpoint, which every deployment routes.
    @Test("DPoP algorithms are advertised regardless of optional endpoints")
    func dpopIsALibraryFact() async throws {
        let metadata = try await makeServer(.none).getMetadata()

        #expect(metadata.dpopSigningAlgValuesSupported == ["ES256"])
    }
}
