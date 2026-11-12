import Foundation
import Testing
import SwiftOAuthCore
import SwiftOAuthClient
import SwiftOAuthProvider

/// RFC 7009, the client half against the provider half, over the provider's HTTP handler.
///
/// The client has revoked on `disconnect()` since 0.12 and the provider had no endpoint to
/// receive it: each half passed its own tests. These cross the boundary the way a socket would.
@Suite("Conformance — revocation across the halves, over HTTP")
struct RevocationCrossHalfTests {

    static let issuer = "https://mcp.example.com"

    static func provider(revocation: String?) throws -> DeviceGrantCrossHalfTests.Provider {
        let clock = SharedClock()
        let server = OAuthServer(
            storage: try OAuthStorage(path: ":memory:"), issuer: issuer,
            scopesSupported: ["mcp:tools"],
            served: try ServedCapabilities(
                grantTypes: [.authorizationCode, .refreshToken, .deviceCode],
                clientAuthenticationMethods: [.none, .clientSecretBasic],
                deviceAuthorization: "\(issuer)/device_authorization", revocation: revocation),
            resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true),
            now: { clock.now })
        let handler = OAuthHTTPHandler(server: server)
        return DeviceGrantCrossHalfTests.Provider(
            server: server, handler: handler, wire: ProviderOverHTTP(handler: handler), clock: clock)
    }

    /// What the client reads out of the provider's published document.
    @Test("The client discovers the revocation endpoint the provider serves, and none it does not")
    func endpointIsDiscovered() async throws {
        let served = try Self.provider(revocation: "\(Self.issuer)/revoke")
        let published = await served.handler.handleMetadataRequest()
        let discovered = try JSONDecoder().decode(
            AuthorizationServerMetadata.self, from: Data(published.body.utf8))
        #expect(try discovered.configuration(identifier: "mcp").revocationEndpoint?.absoluteString
                == "\(Self.issuer)/revoke")

        let unserved = try Self.provider(revocation: nil)
        let bare = await unserved.handler.handleMetadataRequest()
        let none = try JSONDecoder().decode(AuthorizationServerMetadata.self, from: Data(bare.body.utf8))
        #expect(try none.configuration(identifier: "mcp").revocationEndpoint == nil)
    }

    /// The client's own revocation request, with the parameters `disconnect()` sends, ends the
    /// grant at the provider.
    @Test("What disconnect() sends revokes the grant at the provider")
    func disconnectRequestRevokes() async throws {
        let provider = try Self.provider(revocation: "\(Self.issuer)/revoke")
        let registration = await provider.handler.handleRegistrationRequest(body: """
            {"client_name":"Terminal","redirect_uris":[],
             "grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],
             "token_endpoint_auth_method":"none"}
            """)
        let registered: SwiftOAuthProvider.ClientRegistrationResponse = try ProviderOverHTTP.read(registration)
        let credentials = ClientCredentials(
            environment: "test", clientID: registered.clientId, clientSecret: "")
        let issued = try await provider.server.authorizeDevice(clientId: credentials.clientID, scope: "mcp:tools")
        try await provider.server.approveDeviceCode(userCode: issued.userCode, subject: "ada")
        provider.clock.advance(6)
        let tokens = try await provider.server.redeemDeviceCode(issued.deviceCode, clientId: credentials.clientID)
        let refreshToken = try #require(tokens.refreshToken)
        #expect(try await provider.server.introspect(token: tokens.accessToken).active)

        try await provider.wire.revoke(
            endpoint: try #require(URL(string: "\(Self.issuer)/revoke")),
            parameters: ["token": refreshToken, "token_type_hint": "refresh_token"],
            credentials: credentials, method: .none)

        #expect(try await provider.server.introspect(token: tokens.accessToken).active == false)
    }
}
