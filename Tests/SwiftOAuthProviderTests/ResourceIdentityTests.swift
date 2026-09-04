import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// Who this deployment is, as a protected resource — RFC 9728 §2.
///
/// `resource` and `authorization_servers` were both the issuer, and neither was configurable.
/// That is correct exactly when the deployment is a combined authorization server and resource
/// server at one origin, which is the common shape and not the only one.
///
/// RFC 9728 keeps the two separate because they routinely are not, and this package supports the
/// separated role already: `introspect` and `TokenIntrospector` exist precisely so a resource
/// server can validate a token it did not issue. A deployment in that shape must publish
/// metadata naming the *external* authorization server, and hardcoding the issuer named itself.
///
/// The fifth instance of one defect, found by SwiftMCPServer reading rather than running — it
/// weighted the finding as narrower than the previous four, since it does not affect any
/// deployment that exists today. It is fixed anyway, because a supported role with unreachable
/// configuration is a role this package does not really support.
@Suite("RFC 9728 — the deployment's identity as a resource")
struct ResourceIdentityTests {

    private func makeServer(_ identity: ResourceIdentity) async throws -> OAuthServer {
        let storage = try OAuthStorage(path: ":memory:")
        return await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com",
            scopesSupported: ["read"], served: .core, resourceIdentity: identity,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
    }

    /// The common shape: one origin that both issues and protects.
    @Test("A colocated deployment names itself in both fields")
    func colocatedNamesItself() async throws {
        let metadata = try await makeServer(.colocated).getProtectedResourceMetadata()

        #expect(metadata.resource == "https://mcp.example.com")
        #expect(metadata.authorizationServers == ["https://mcp.example.com"])
    }

    /// A resource server delegating to an external authorization server names that server.
    ///
    /// Without this the document tells a client to authorize against the resource itself, which
    /// issues nothing — the client is sent to an endpoint that will not answer.
    @Test("A delegating resource names its external authorization server")
    func delegatingNamesTheExternalServer() async throws {
        let metadata = try await makeServer(ResourceIdentity(
            resource: "https://api.example.com",
            authorizationServers: ["https://auth.example.com"]))
            .getProtectedResourceMetadata()

        #expect(metadata.resource == "https://api.example.com")
        #expect(metadata.authorizationServers == ["https://auth.example.com"])
    }

    /// More than one authorization server is legal — §2 allows a list.
    @Test("Several authorization servers can be named")
    func severalAuthorizationServers() async throws {
        let metadata = try await makeServer(ResourceIdentity(
            resource: "https://api.example.com",
            authorizationServers: ["https://a.example.com", "https://b.example.com"]))
            .getProtectedResourceMetadata()

        #expect(metadata.authorizationServers.count == 2)
    }

    /// A resource naming no authorization server is refused: a protected resource that names
    /// none tells a client nowhere to go, which is a document with no purpose.
    @Test("A resource naming no authorization server is refused")
    func noAuthorizationServerIsRefused() {
        #expect(throws: ResourceIdentity.Inconsistency.self) {
            _ = try ResourceIdentity(
                resource: "https://api.example.com", authorizationServers: [])
        }
    }
}
