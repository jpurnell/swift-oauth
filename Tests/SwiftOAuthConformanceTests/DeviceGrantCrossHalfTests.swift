import Foundation
import Testing
import SwiftOAuthCore
import SwiftOAuthClient
import SwiftOAuthProvider

/// The device grant, the client half against the provider half.
///
/// The provider has issued device codes and redeemed them since the grant was added; until
/// `DeviceAuthorizationClient` the client could not ask for one, so nothing checked that the two
/// agree. This runs the client's sign-in against the provider's own grant.
///
/// **Through the provider's Swift API, not its HTTP handler.** `OAuthHTTPHandler` routes no
/// device authorization endpoint and its token endpoint does not dispatch the device grant, so
/// there is no HTTP surface to run against. The bridge below still crosses the wire *format*:
/// every answer the provider gives is encoded to JSON and decoded by the client's own types,
/// and every refusal crosses as an RFC 6749 §5.2 body — which is where the halves have
/// disagreed before.
@Suite("Conformance — the device grant across the halves")
struct DeviceGrantCrossHalfTests {

    static let issuer = "https://mcp.example.com"

    private static func makeServer(served: ServedCapabilities = .core) throws -> OAuthServer {
        OAuthServer(
            storage: try OAuthStorage(path: ":memory:"), issuer: issuer,
            scopesSupported: ["mcp:tools"], served: served, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
    }

    /// The provider advertises the endpoint, and the client reads it into a configuration
    /// that will start the grant.
    @Test("The provider's device authorization endpoint is discovered by the client")
    func endpointIsDiscovered() async throws {
        let served = try ServedCapabilities(
            grantTypes: [.authorizationCode, .deviceCode],
            clientAuthenticationMethods: [.none],
            deviceAuthorization: "\(Self.issuer)/device_authorization")
        let server = try Self.makeServer(served: served)

        let published = try JSONEncoder().encode(await server.getMetadata())
        let discovered = try JSONDecoder().decode(AuthorizationServerMetadata.self, from: published)
        let configuration = try discovered.configuration(identifier: "mcp")

        #expect(configuration.deviceAuthorizationEndpoint?.absoluteString
                == "https://mcp.example.com/device_authorization")
        _ = try DeviceAuthorizationClient(
            configuration: configuration,
            credentials: ClientCredentials(environment: "test", clientID: "cli", clientSecret: ""))
    }

    /// The whole grant: the client requests, the provider issues, the user approves on the
    /// provider after two polls, and the client collects tokens the provider then honours.
    @Test("A sign-in completes against the provider, and the token it yields is active there")
    func signInCompletes() async throws {
        let server = try Self.makeServer()
        let bridge = ProviderBridge(server: server)
        let client = try DeviceAuthorizationClient(
            configuration: Self.configuration(),
            credentials: ClientCredentials(environment: "test", clientID: "cli", clientSecret: ""),
            transport: bridge)
        let sleeper = ApprovingSleeper(approveOnWait: 2) { userCode in
            try await server.approveDeviceCode(userCode: userCode, subject: "ada")
        }

        let tokens = try await client.signIn(sleeper: sleeper, elapsed: { 0 }, present: { shown in
            await sleeper.remember(shown.userCode)
        })

        // Two `authorization_pending` polls at the provider's stated interval, then tokens.
        #expect(await sleeper.waits == [5, 5])
        #expect(await bridge.redeemCount == 3)
        let introspected = try await server.introspect(token: tokens.accessToken)
        #expect(introspected.active)
        #expect(introspected.clientId == "cli")
        #expect(introspected.scope == "mcp:tools")
    }

    /// A refusal on the provider's side reaches the client as itself, through a §5.2 body.
    @Test("A refusal on the provider reaches the client as itself, and ends the loop")
    func refusalCrosses() async throws {
        let server = try Self.makeServer()
        let bridge = ProviderBridge(server: server)
        let client = try DeviceAuthorizationClient(
            configuration: Self.configuration(),
            credentials: ClientCredentials(environment: "test", clientID: "cli", clientSecret: ""),
            transport: bridge)

        let authorization = try await client.requestDeviceAuthorization()
        // Another client's identifier: the provider answers `invalid_grant`, which is not a
        // polling state, and the loop must stop on it.
        let stranger = try DeviceAuthorizationClient(
            configuration: Self.configuration(),
            credentials: ClientCredentials(environment: "test", clientID: "other", clientSecret: ""),
            transport: bridge)

        await #expect(throws: OAuthError.invalidGrant(nil)) {
            _ = try await stranger.poll(authorization, sleeper: ApprovingSleeper(approveOnWait: 0) { _ in },
                                        elapsed: { 0 })
        }
    }

    private static func configuration() throws -> ProviderConfiguration {
        let deviceEndpoint = try #require(URL(string: "\(issuer)/device_authorization"))
        return ProviderConfiguration(
            identifier: "mcp",
            authorizationEndpoint: try #require(URL(string: "\(issuer)/authorize")),
            tokenEndpoint: try #require(URL(string: "\(issuer)/token")),
            deviceAuthorizationEndpoint: deviceEndpoint,
            scope: "mcp:tools",
            authenticationMethod: .none)
    }
}

/// Carries the client's requests to the provider's device grant, through JSON both ways.
private actor ProviderBridge: DeviceAuthorizationTransport {

    private let server: OAuthServer
    private(set) var redeemCount = 0

    init(server: OAuthServer) {
        self.server = server
    }

    func requestDeviceAuthorization(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws -> DeviceAuthorizationResponse {
        do {
            return try Self.acrossTheWire(
                try await server.authorizeDevice(
                    clientId: credentials.clientID, scope: parameters["scope"]))
        } catch let refusal as OAuthError {
            throw try Self.acrossTheWire(refusal)
        }
    }

    func exchange(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws -> TokenResponse {
        guard parameters["grant_type"] == GrantType.deviceCode.rawValue,
              let deviceCode = parameters["device_code"] else {
            throw OAuthError.unsupportedGrantType(nil)
        }
        redeemCount += 1
        do {
            return try Self.acrossTheWire(
                try await server.redeemDeviceCode(deviceCode, clientId: credentials.clientID))
        } catch let refusal as OAuthError {
            throw try Self.acrossTheWire(refusal)
        }
    }

    /// The provider's answer as JSON, read back by the client's types.
    private static func acrossTheWire<Answer: Codable>(_ answer: Answer) throws -> Answer {
        try JSONDecoder().decode(Answer.self, from: try JSONEncoder().encode(answer))
    }

    /// A refusal as an RFC 6749 §5.2 body, read back the way `URLSessionTokenTransport` reads
    /// one.
    private static func acrossTheWire(_ refusal: OAuthError) throws -> OAuthError {
        let body = try JSONEncoder().encode(OAuthErrorResponse(refusal))
        return try JSONDecoder().decode(OAuthErrorResponse.self, from: body).oauthError
    }
}

/// Records each wait and, on the given one, approves the code the user was shown — standing in
/// for a person who types it in while the device polls.
private actor ApprovingSleeper: DeviceFlowSleeper {

    private let approveOnWait: Int
    private let approve: @Sendable (String) async throws -> Void
    private var userCode: String?
    private(set) var waits: [TimeInterval] = []

    init(approveOnWait: Int, approve: @escaping @Sendable (String) async throws -> Void) {
        self.approveOnWait = approveOnWait
        self.approve = approve
    }

    func remember(_ code: String) {
        userCode = code
    }

    func sleep(for interval: TimeInterval) async throws {
        waits.append(interval)
        if waits.count == approveOnWait, let userCode {
            try await approve(userCode)
        }
    }
}
