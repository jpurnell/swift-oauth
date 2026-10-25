import Foundation
import Testing
import SwiftOAuthCore
import SwiftOAuthClient
import SwiftOAuthProvider

/// The device grant, the client half against the provider half — over the provider's HTTP
/// endpoints.
///
/// This ran through `OAuthServer`'s Swift API while the provider had no HTTP surface for the
/// grant. It now crosses `OAuthHTTPHandler`: the client registers at `/register`, asks at the
/// device authorization endpoint, and polls the token endpoint, each request a form body and
/// each answer a status and JSON the client reads with its own types (``ProviderOverHTTP``).
/// The user approves on the provider's `/device` page.
@Suite("Conformance — the device grant across the halves, over HTTP")
struct DeviceGrantCrossHalfTests {

    static let issuer = "https://mcp.example.com"

    static func served() throws -> ServedCapabilities {
        try ServedCapabilities(
            grantTypes: [.authorizationCode, .refreshToken, .deviceCode],
            clientAuthenticationMethods: [.none, .clientSecretBasic],
            introspection: "\(issuer)/introspect",
            deviceAuthorization: "\(issuer)/device_authorization")
    }

    struct Provider {
        let server: OAuthServer
        let handler: OAuthHTTPHandler
        let wire: ProviderOverHTTP
        let clock: SharedClock
    }

    static func provider() throws -> Provider {
        let clock = SharedClock()
        let server = OAuthServer(
            storage: try OAuthStorage(path: ":memory:"), issuer: issuer,
            scopesSupported: ["mcp:tools"], served: try served(), resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true),
            now: { clock.now })
        let handler = OAuthHTTPHandler(server: server)
        return Provider(
            server: server, handler: handler, wire: ProviderOverHTTP(handler: handler),
            clock: clock)
    }

    /// Registers a public client for the device grant through `/register`, as a command-line
    /// tool would, and returns its credentials.
    static func registerDeviceClient(_ provider: Provider) async throws -> ClientCredentials {
        let response = await provider.handler.handleRegistrationRequest(body: """
            {"client_name":"Terminal","redirect_uris":[],
             "grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],
             "token_endpoint_auth_method":"none"}
            """)
        let registered: SwiftOAuthProvider.ClientRegistrationResponse = try ProviderOverHTTP.read(response)
        return ClientCredentials(environment: "test", clientID: registered.clientId, clientSecret: "")
    }

    /// The user approving on the provider's `/device` page, as `subject`.
    static func approveOnThePage(
        _ provider: Provider, userCode: String, subject: String
    ) async throws {
        let entry = await provider.handler.handleDeviceVerificationPage(
            queryParams: ["user_code": userCode], subject: subject)
        let csrf = try csrfToken(in: entry.body)
        let confirmation = await provider.handler.handleDeviceVerificationSubmission(
            formParams: ["action": "confirm", "user_code": userCode, "csrf_token": csrf],
            subject: subject)
        let approved = await provider.handler.handleDeviceVerificationSubmission(
            formParams: ["action": "approve", "user_code": userCode,
                         "csrf_token": try csrfToken(in: confirmation.body)],
            subject: subject)
        guard approved.statusCode == 200 else {
            throw OAuthError.serverError("approval page answered \(approved.statusCode)")
        }
    }

    static func csrfToken(in page: String) throws -> String {
        let marker = #"name="csrf_token" value=""#
        let start = try #require(page.range(of: marker))
        let rest = page[start.upperBound...]
        let end = try #require(rest.firstIndex(of: "\""))
        return String(rest[..<end])
    }

    /// The provider advertises the endpoint, and the client reads it into a configuration
    /// that will start the grant.
    @Test("The provider's device authorization endpoint is discovered by the client")
    func endpointIsDiscovered() async throws {
        let provider = try Self.provider()

        let published = await provider.handler.handleMetadataRequest()
        let discovered = try JSONDecoder().decode(
            AuthorizationServerMetadata.self, from: Data(published.body.utf8))
        let configuration = try discovered.configuration(identifier: "mcp")

        #expect(configuration.deviceAuthorizationEndpoint?.absoluteString
                == "https://mcp.example.com/device_authorization")
        _ = try DeviceAuthorizationClient(
            configuration: configuration,
            credentials: ClientCredentials(environment: "test", clientID: "cli", clientSecret: ""))
    }

    /// The whole grant: the client registers, requests, shows the code; the user approves on
    /// the provider's page after two polls; the client collects tokens the provider honours.
    @Test("A sign-in completes over HTTP, and the token it yields is active there")
    func signInCompletes() async throws {
        let provider = try Self.provider()
        let credentials = try await Self.registerDeviceClient(provider)
        let client = try DeviceAuthorizationClient(
            configuration: Self.configuration(), credentials: credentials,
            transport: provider.wire)
        let sleeper = ApprovingSleeper(approveOnWait: 2, clock: provider.clock) { userCode in
            try await Self.approveOnThePage(provider, userCode: userCode, subject: "ada")
        }

        let tokens = try await client.signIn(sleeper: sleeper, elapsed: { 0 }, present: { shown in
            await sleeper.remember(shown.userCode)
        })

        // Two `authorization_pending` polls at the provider's stated interval, then tokens —
        // and no `slow_down`, because the client waited as long as it was told to.
        #expect(await sleeper.waits == [5, 5])
        #expect(await provider.wire.tokenRequests == 3)
        let introspected = try await provider.server.introspect(token: tokens.accessToken)
        #expect(introspected.active)
        #expect(introspected.clientId == credentials.clientID)
        #expect(introspected.scope == "mcp:tools")
        #expect(introspected.subject == "ada")
        #expect(introspected.issuer == Self.issuer)
    }

    /// A device that polls faster than it was told is slowed, and the client widens its
    /// interval by the five seconds the provider added.
    ///
    /// The sleeper here leaves the provider's clock where it is, so every wait is, as far as
    /// the provider can tell, no wait at all. The client polls once before it waits: that poll
    /// is `authorization_pending` (there is no earlier poll to be too close to), every later
    /// one is `slow_down`, and each widens the interval by five seconds, so the client waits
    /// five, then ten, then fifteen.
    @Test("slow_down from the provider widens the client's interval by five seconds")
    func slowDownCrosses() async throws {
        let provider = try Self.provider()
        let credentials = try await Self.registerDeviceClient(provider)
        let client = try DeviceAuthorizationClient(
            configuration: Self.configuration(), credentials: credentials,
            transport: provider.wire)
        let sleeper = ApprovingSleeper(
            approveOnWait: 3, clock: provider.clock, advancesClock: false
        ) { userCode in
            try await provider.server.approveDeviceCode(userCode: userCode, subject: "ada")
        }

        _ = try await client.signIn(sleeper: sleeper, elapsed: { 0 }, present: { shown in
            await sleeper.remember(shown.userCode)
        })

        let waits = await sleeper.waits
        #expect(waits == [5, 10, 15], "waits were \(waits)")
    }

    /// A refusal on the provider's side reaches the client as itself, through a §5.2 body.
    @Test("A refusal on the provider reaches the client as itself, and ends the loop")
    func refusalCrosses() async throws {
        let provider = try Self.provider()
        let owner = try await Self.registerDeviceClient(provider)
        let stranger = try await Self.registerDeviceClient(provider)
        let client = try DeviceAuthorizationClient(
            configuration: Self.configuration(), credentials: owner, transport: provider.wire)
        let authorization = try await client.requestDeviceAuthorization()
        // Another registered client's identifier: the provider answers `invalid_grant`, which
        // is not a polling state, and the loop must stop on it.
        let thief = try DeviceAuthorizationClient(
            configuration: Self.configuration(), credentials: stranger, transport: provider.wire)

        // Matched by case: the provider's answer carries its standard description, which the
        // client reads back, so it is not equal to `invalidGrant(nil)`.
        await #expect {
            _ = try await thief.poll(
                authorization,
                sleeper: ApprovingSleeper(approveOnWait: 0, clock: provider.clock) { _ in },
                elapsed: { 0 })
        } throws: { error in
            if case .invalidGrant = error as? OAuthError { return true }
            return false
        }
    }

    @Test("A user's refusal on the page reaches the client as access_denied")
    func denialCrosses() async throws {
        let provider = try Self.provider()
        let credentials = try await Self.registerDeviceClient(provider)
        let client = try DeviceAuthorizationClient(
            configuration: Self.configuration(), credentials: credentials,
            transport: provider.wire)
        let sleeper = ApprovingSleeper(approveOnWait: 1, clock: provider.clock) { userCode in
            try await provider.server.denyDeviceCode(userCode: userCode, subject: "ada")
        }

        await #expect(throws: OAuthError.self) {
            _ = try await client.signIn(sleeper: sleeper, elapsed: { 0 }, present: { shown in
                await sleeper.remember(shown.userCode)
            })
        }
        #expect(await provider.wire.tokenRequests == 2)
    }

    static func configuration() throws -> ProviderConfiguration {
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
