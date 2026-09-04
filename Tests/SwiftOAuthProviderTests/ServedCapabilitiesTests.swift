import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// What a deployment serves — endpoints, grants and authentication methods together.
///
/// Three fields were derived from what this *package implements* rather than what a *deployment
/// serves*, and each was found the same way: a consumer ran the change and reported a document
/// that promised something its own HTTP layer could not answer.
///
/// - Endpoints: introspection, PAR and device authorization advertised but not routed — a
///   discoverable 404.
/// - Grants: `device_code` advertised while the device authorization endpoint it requires is
///   absent — a document that contradicts itself.
/// - Authentication methods: `tls_client_auth` advertised by a deployment whose TLS never
///   requests a client certificate — a handshake that cannot happen.
///
/// One value describes all three, rather than a parameter per field as each is discovered. That
/// is the shape SwiftMCPServer proposed after the second one, and it is right: the list of ways
/// a document can over-promise is not one anybody has finished enumerating.
@Suite("Served capabilities — the deployment's own account of itself")
struct ServedCapabilitiesTests {

    private func makeServer(_ served: ServedCapabilities) async throws -> OAuthServer {
        let storage = try OAuthStorage(path: ":memory:")
        return await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com",
            scopesSupported: ["read"], served: served,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
    }

    /// The core deployment: the three endpoints everyone routes, two grants, secret-based auth.
    @Test("A core deployment advertises only what it serves")
    func coreDeploymentAdvertisesCore() async throws {
        let metadata = try await makeServer(.core).getMetadata()

        #expect(metadata.grantTypesSupported == [
            GrantType.authorizationCode.rawValue, GrantType.refreshToken.rawValue])
        #expect(!metadata.tokenEndpointAuthMethodsSupported.contains("tls_client_auth"))
        #expect(metadata.deviceAuthorizationEndpoint == nil)
        #expect(metadata.introspectionEndpoint == nil)
    }

    /// A deployment that routes and supports more advertises more.
    @Test("A fuller deployment advertises what it adds")
    func fullerDeploymentAdvertisesMore() async throws {
        let served = try ServedCapabilities(
            grantTypes: [.authorizationCode, .refreshToken, .deviceCode],
            clientAuthenticationMethods: [.clientSecretBasic, .tlsClientAuth],
            introspection: "https://mcp.example.com/introspect",
            deviceAuthorization: "https://mcp.example.com/device_authorization")

        let metadata = try await makeServer(served).getMetadata()

        #expect(metadata.grantTypesSupported.contains(GrantType.deviceCode.rawValue))
        #expect(metadata.tokenEndpointAuthMethodsSupported.contains("tls_client_auth"))
        #expect(metadata.deviceAuthorizationEndpoint == "https://mcp.example.com/device_authorization")
    }

    /// **The device grant requires its endpoint, and the contradiction is refused.**
    ///
    /// RFC 8628 begins at the device authorization endpoint. A document offering the grant
    /// without naming that endpoint describes a flow a client cannot start — and this is the
    /// exact document SwiftMCPServer produced, because the grant list came from the package and
    /// the endpoint list came from the deployment.
    ///
    /// Refused at construction rather than filtered silently: dropping the grant would give a
    /// caller a document they did not ask for, and dropping it *quietly* is how the original
    /// defect stayed invisible.
    @Test("Advertising the device grant without its endpoint is refused")
    func deviceGrantWithoutEndpointIsRefused() throws {
        #expect(throws: ServedCapabilities.Inconsistency.self) {
            _ = try ServedCapabilities(
                grantTypes: [.authorizationCode, .deviceCode],
                clientAuthenticationMethods: [.clientSecretBasic])
        }
    }

    /// The same pair, declared together, is accepted.
    @Test("The device grant with its endpoint is accepted")
    func deviceGrantWithEndpointIsAccepted() throws {
        let served = try ServedCapabilities(
            grantTypes: [.authorizationCode, .deviceCode],
            clientAuthenticationMethods: [.clientSecretBasic],
            deviceAuthorization: "https://mcp.example.com/device_authorization")

        #expect(served.grantTypes.contains(.deviceCode))
    }

    /// A deployment must claim at least one authentication method, or no client can present
    /// credentials at all and the document says so by omission.
    @Test("A deployment with no authentication method is refused")
    func noAuthenticationMethodIsRefused() throws {
        #expect(throws: ServedCapabilities.Inconsistency.self) {
            _ = try ServedCapabilities(
                grantTypes: [.authorizationCode], clientAuthenticationMethods: [])
        }
    }

    /// The authorization code grant is always required — it is the only way this package issues
    /// a first token, so a deployment that omits it is not an OAuth server.
    @Test("Omitting the authorization code grant is refused")
    func omittingAuthorizationCodeIsRefused() throws {
        #expect(throws: ServedCapabilities.Inconsistency.self) {
            _ = try ServedCapabilities(
                grantTypes: [.refreshToken], clientAuthenticationMethods: [.clientSecretBasic])
        }
    }
}
