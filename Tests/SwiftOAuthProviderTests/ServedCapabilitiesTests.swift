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

/// Which metadata fields are the deployment's to declare, and which are the library's.
///
/// SwiftMCPServer's generalisation, after the fourth instance: *every field of an
/// authorization-server metadata document is a claim about the deployment, so any field derived
/// from the library is wrong by default and right only by coincidence.*
///
/// That is the right instinct, and the line is sharper than "everything moves". A field belongs
/// to the deployment exactly when **the deployment can serve less than the library implements**:
///
/// - Optional endpoints — a consumer routes a subset. Deployment's.
/// - Grants — a consumer may decline to expose one. Deployment's.
/// - Client authentication methods — mTLS needs the TLS layer to request a certificate, which
///   this package does not control. Deployment's.
/// - DPoP algorithms — accepting a `DPoP`-scheme header is the consumer's request handling.
///   Deployment's, and the one most likely to be believed, because a client reading it has no
///   cheap way to test the claim before relying on it.
///
/// Against that: `response_types_supported` and `code_challenge_methods_supported` are library
/// facts. This package issues `code` and verifies `S256`, and a deployment cannot serve less
/// without the package failing outright — there is no subset to choose. They are true for every
/// deployment because they cannot be otherwise, not by coincidence.
///
/// These tests pin that division, so a future field is placed by the rule rather than by
/// whichever list it was easiest to add to.
@Suite("Served capabilities — deployment facts and library facts")
struct MetadataFieldOwnershipTests {

    private func makeServer(_ served: ServedCapabilities) async throws -> OAuthServer {
        let storage = try OAuthStorage(path: ":memory:")
        return await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com",
            scopesSupported: ["read"], served: served,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
    }

    /// A deployment that does not handle the DPoP scheme does not advertise DPoP.
    ///
    /// This is the fourth instance and the worst of them. A client that reads the claim, obtains
    /// a bound token and presents it correctly is refused — not because the token is bad, but
    /// because the deployment's request handling never learned the scheme. The endpoint case
    /// gives a client a 404 it can see; this one turns away a client that did everything right.
    @Test("A deployment not handling DPoP does not advertise it")
    func dpopIsNotAdvertisedByDefault() async throws {
        let metadata = try await makeServer(.core).getMetadata()

        #expect(metadata.dpopSigningAlgValuesSupported == nil,
                "a deployment that cannot honour a DPoP proof advertised that it could")
    }

    /// One that does handle it advertises exactly what this package verifies.
    ///
    /// The value is not the consumer's to choose: `CompactJWS` accepts ES256 and nothing else,
    /// so a consumer declaring DPoP support gets that list rather than one of their own. What
    /// they are declaring is *whether* they honour proofs, not which algorithms — the second
    /// would let them advertise one this package refuses.
    @Test("A deployment handling DPoP advertises what the package verifies")
    func dpopAlgorithmsComeFromTheLibrary() async throws {
        let served = try ServedCapabilities(
            grantTypes: [.authorizationCode, .refreshToken],
            clientAuthenticationMethods: [.clientSecretBasic],
            honoursDPoPProofs: true)

        let metadata = try await makeServer(served).getMetadata()

        #expect(metadata.dpopSigningAlgValuesSupported == ["ES256"])
    }

    /// Library facts are advertised whatever the deployment declares, because there is no
    /// subset of them to serve.
    @Test("Response types and challenge methods are library facts")
    func libraryFactsAreAlwaysAdvertised() async throws {
        let metadata = try await makeServer(.core).getMetadata()

        #expect(metadata.responseTypesSupported == ["code"])
        #expect(metadata.codeChallengeMethodsSupported == ["S256"])
    }
}

/// What an absent field means on the wire.
///
/// `scopesSupported: nil` omits the key rather than emitting `[]`, and the distinction matters:
/// an absent key is silence, `[]` is a claim to offer nothing. That behaviour comes from Swift's
/// synthesised `encodeIfPresent` rather than from a decision, which is exactly why it needs a
/// test — it is load-bearing and nobody chose it.
@Suite("Metadata encoding — absent is not empty")
struct MetadataEncodingTests {

    private func encoded(scopes: [String]?) async throws -> [String: Any] {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com",
            scopesSupported: scopes, served: .core,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let data = try JSONEncoder().encode(await server.getMetadata())
        return try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    @Test("Absent scopes omit the key entirely")
    func absentScopesOmitTheKey() async throws {
        let object = try await encoded(scopes: nil)

        #expect(object["scopes_supported"] == nil,
                "an absent value was emitted as a claim rather than as silence")
    }

    @Test("Declared scopes are emitted")
    func declaredScopesAreEmitted() async throws {
        let object = try await encoded(scopes: ["read"])

        #expect(object["scopes_supported"] as? [String] == ["read"])
    }

    /// An endpoint a deployment does not serve is absent, not empty-string.
    @Test("Unserved endpoints omit their keys")
    func unservedEndpointsOmitTheirKeys() async throws {
        let object = try await encoded(scopes: ["read"])

        #expect(object["introspection_endpoint"] == nil)
        #expect(object["device_authorization_endpoint"] == nil)
        #expect(object["dpop_signing_alg_values_supported"] == nil)
    }
}
