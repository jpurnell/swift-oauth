import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthClient

/// Beginning a device grant from the client — RFC 8628 §3.1–3.5, end to end.
///
/// Until this existed the client could poll for a device grant's tokens and could not ask for
/// the device code those polls redeem, so nobody could start the grant through this package.
///
/// The expected values are RFC 8628's own, copied from the RFC text rather than derived from
/// this code: §3.2's example response, §3.1's example request, and §3.4's example token
/// request. A test whose expectation was produced by the implementation it checks would agree
/// with any implementation.
@Suite("RFC 8628 — requesting a device code and redeeming it")
struct DeviceAuthorizationClientTests {

    // MARK: - RFC 8628's example values

    /// RFC 8628 §3.2, page 7, the example response body — as printed in the RFC, line break
    /// inside `verification_uri_complete` and all. That break falls between a member's name
    /// and its value, where JSON permits whitespace, so the text is valid JSON as it stands.
    static let rfcExampleResponse = """
        {
          "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
          "user_code": "WDJB-MJHT",
          "verification_uri": "https://example.com/device",
          "verification_uri_complete":
              "https://example.com/device?user_code=WDJB-MJHT",
          "expires_in": 1800,
          "interval": 5
        }
        """

    /// RFC 8628 §3.1's example client identifier, and the scope from the same example.
    static let rfcClientID = "1406020730"
    static let rfcScope = "example_scope"

    /// The RFC's example device code, for the redeem.
    static let rfcDeviceCode = "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS"

    @Test("The §3.2 example response is read as the RFC states it")
    func rfcExampleResponseIsRead() async throws {
        let transport = ScriptedDeviceTransport(authorization: .json(Self.rfcExampleResponse))
        let client = try Self.client(transport: transport)

        let authorization = try await client.requestDeviceAuthorization()

        #expect(authorization.deviceCode == "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS")
        #expect(authorization.userCode == "WDJB-MJHT")
        #expect(authorization.verificationURI.absoluteString == "https://example.com/device")
        #expect(authorization.verificationURIComplete?.absoluteString
                == "https://example.com/device?user_code=WDJB-MJHT")
        #expect(authorization.expiresIn == 1800)
        #expect(authorization.interval == 5)
    }

    // MARK: - What the request carries

    /// §3.1: a public client sends `client_id`, and `scope` when it has one. The transport adds
    /// `client_id` for `.none`, exactly as it does at the token endpoint, so the parameters the
    /// client hands it name the scope and nothing else — the byte-level body is asserted
    /// against §3.1's example in `DeviceAuthorizationWireTests`.
    @Test("A public client's request names the scope and authenticates as public")
    func publicClientRequest() async throws {
        let transport = ScriptedDeviceTransport(authorization: .json(Self.rfcExampleResponse))
        let client = try Self.client(transport: transport, method: .none)

        _ = try await client.requestDeviceAuthorization()

        let sent = try #require(await transport.authorizationRequests.first)
        #expect(await transport.authorizationRequests.count == 1)
        #expect(sent.endpoint == Self.deviceEndpoint)
        #expect(sent.parameters == ["scope": Self.rfcScope])
        #expect(sent.method == .none)
        #expect(sent.credentials.clientID == Self.rfcClientID)
    }

    /// §3.1: "confidential clients … authenticate in the same manner as when making requests
    /// to the token endpoint". The same credentials and the same method reach the transport for
    /// both requests, so one cannot authenticate differently from the other.
    @Test("A confidential client authenticates here as it does at the token endpoint")
    func confidentialClientAuthenticates() async throws {
        let transport = ScriptedDeviceTransport(
            authorization: .json(Self.rfcExampleResponse), polls: [.issued])
        let client = try Self.client(transport: transport, method: .clientSecretBasic)

        _ = try await client.signIn(sleeper: RecordingSleeper(), elapsed: { 0 }, present: { _ in })

        let authorization = try #require(await transport.authorizationRequests.first)
        let redeem = try #require(await transport.tokenRequests.first)
        #expect(authorization.method == .clientSecretBasic)
        #expect(redeem.method == .clientSecretBasic)
        #expect(authorization.credentials == Self.credentials)
        #expect(redeem.credentials == Self.credentials)
    }

    /// §3.1 lists `scope` as OPTIONAL, and "parameters sent without a value MUST be treated as
    /// if they were omitted". An empty configured scope is sent as no parameter at all.
    @Test("An empty scope is omitted rather than sent empty")
    func emptyScopeIsOmitted() async throws {
        let transport = ScriptedDeviceTransport(authorization: .json(Self.rfcExampleResponse))
        let client = try Self.client(transport: transport, scope: "")

        _ = try await client.requestDeviceAuthorization()

        #expect(await transport.authorizationRequests.first?.parameters == [:])
    }

    /// RFC 8707: the resource travels on the request that begins the grant and on the token
    /// request, as it does on the authorization code grant's two requests. A token redeemed
    /// without it can come back audienced to something else, or to nothing.
    @Test("A configured resource is sent on both requests")
    func resourceIsSentOnBothRequests() async throws {
        let transport = ScriptedDeviceTransport(
            authorization: .json(Self.rfcExampleResponse), polls: [.issued])
        let resource = try #require(URL(string: "https://api.example.com/mcp"))
        let client = try Self.client(transport: transport, resource: resource)

        _ = try await client.signIn(sleeper: RecordingSleeper(), elapsed: { 0 }, present: { _ in })

        #expect(await transport.authorizationRequests.first?.parameters["resource"]
                == "https://api.example.com/mcp")
        #expect(await transport.tokenRequests.first?.parameters["resource"]
                == "https://api.example.com/mcp")
    }

    /// §3.4: the extension grant type, spelled out in full, and the device code from §3.2,
    /// posted to the token endpoint. The grant type is compared with the RFC's literal rather
    /// than with ``GrantType/deviceCode``, so a typo in the enum cannot pass by agreeing with
    /// itself.
    @Test("The redeem carries §3.4's grant type and the device code")
    func redeemParameters() async throws {
        let transport = ScriptedDeviceTransport(
            authorization: .json(Self.rfcExampleResponse), polls: [.issued])
        let client = try Self.client(transport: transport, method: .none)

        _ = try await client.redeem(deviceCode: Self.rfcDeviceCode)

        let sent = try #require(await transport.tokenRequests.first)
        #expect(sent.endpoint == Self.tokenEndpoint)
        #expect(sent.parameters == [
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS"
        ])
        #expect(sent.method == .none)
        #expect(sent.credentials.clientID == Self.rfcClientID)
    }

    // MARK: - End to end

    /// The proposal's line, with RFC 8628's example values: two `authorization_pending` polls
    /// at the stated five seconds, then tokens.
    @Test("Pending twice, then issued: the sleeper records [5, 5]")
    func pendingTwiceThenIssued() async throws {
        let transport = ScriptedDeviceTransport(
            authorization: .json(Self.rfcExampleResponse), polls: [.pending, .pending, .issued])
        let client = try Self.client(transport: transport)
        let sleeper = RecordingSleeper()

        let tokens = try await client.signIn(sleeper: sleeper, elapsed: { 0 }, present: { _ in })

        #expect(tokens.accessToken == ScriptedDeviceTransport.issuedFixture)
        #expect(await sleeper.waits == [5, 5])
        #expect(await transport.tokenRequests.count == 3)
    }

    /// §3.5: `slow_down` means "the interval MUST be increased by 5 seconds for this and all
    /// subsequent requests" — so the wait after it is ten.
    @Test("Pending, slow_down, then issued: the sleeper records [5, 10]")
    func slowDownWidensTheWait() async throws {
        let transport = ScriptedDeviceTransport(
            authorization: .json(Self.rfcExampleResponse), polls: [.pending, .slowDown, .issued])
        let client = try Self.client(transport: transport)
        let sleeper = RecordingSleeper()

        _ = try await client.signIn(sleeper: sleeper, elapsed: { 0 }, present: { _ in })

        #expect(await sleeper.waits == [5, 10])
    }

    /// The user has to see the code before anything is polled — there is nothing to wait for
    /// until they have it. The caller is handed the response the server sent, once, and the
    /// first poll comes after.
    @Test("The response is presented once, before the first poll")
    func presentedBeforePolling() async throws {
        let transport = ScriptedDeviceTransport(
            authorization: .json(Self.rfcExampleResponse), polls: [.pending, .issued])
        let client = try Self.client(transport: transport)

        _ = try await client.signIn(sleeper: RecordingSleeper(), elapsed: { 0 }, present: { shown in
            await transport.note("presented \(shown.userCode) \(shown.verificationURI.absoluteString)")
        })

        #expect(await transport.events == [
            "device authorization",
            "presented WDJB-MJHT https://example.com/device",
            "token",
            "token"
        ])
    }

    /// A caller whose presentation fails — the user dismissed it, the screen went away — has
    /// nobody to wait for. Nothing is polled.
    @Test("A presentation that throws ends the sign-in before any poll")
    func throwingPresentationStopsTheFlow() async throws {
        let transport = ScriptedDeviceTransport(
            authorization: .json(Self.rfcExampleResponse), polls: [.issued])
        let client = try Self.client(transport: transport)

        await #expect(throws: CancellationError.self) {
            _ = try await client.signIn(
                sleeper: RecordingSleeper(), elapsed: { 0 }, present: { _ in throw CancellationError() })
        }

        #expect(await transport.tokenRequests.isEmpty)
    }

    /// §3.5: `access_denied` is the end of the flow, and reaches the caller as itself.
    @Test("A refusal reaches the caller as access_denied")
    func denialReachesTheCaller() async throws {
        let transport = ScriptedDeviceTransport(
            authorization: .json(Self.rfcExampleResponse), polls: [.pending, .denied])
        let client = try Self.client(transport: transport)

        let error = await #expect(throws: OAuthError.self) {
            _ = try await client.signIn(sleeper: RecordingSleeper(), elapsed: { 0 }, present: { _ in })
        }

        #expect(error?.code == "access_denied")
    }

    /// The device authorization endpoint's own refusal — §3.2: "the authorization server
    /// responds in the same way as the token endpoint" — is not swallowed into a polling state.
    @Test("A refused device authorization request is thrown, and nothing is presented")
    func refusedRequestIsThrown() async throws {
        let transport = ScriptedDeviceTransport(
            authorization: .failure(OAuthError.invalidClient("unknown client")))
        let client = try Self.client(transport: transport)

        await #expect(throws: OAuthError.invalidClient("unknown client")) {
            _ = try await client.signIn(sleeper: RecordingSleeper(), elapsed: { 0 }, present: { _ in
                Issue.record("a code was presented for a request the server refused")
            })
        }
        #expect(await transport.tokenRequests.isEmpty)
    }

    // MARK: - The server's answer is checked before it is shown

    /// What a hostile or broken server might send in place of §3.2's response, and the field
    /// the refusal names. Each is checked before the user is shown anything: a verification
    /// URI is somewhere the user is about to type their password, and a user code is printed to
    /// a terminal.
    static let unusableResponses: [(String, String)] = [
        // SECURITY: plain-HTTP verification URI under test — a user sent there signs in over cleartext.
        (#"{"device_code":"d","user_code":"WDJB-MJHT","verification_uri":"http://example.com/device","expires_in":1800}"#, "verification_uri"),
        (#"{"device_code":"d","user_code":"WDJB-MJHT","verification_uri":"https://example.com/device","verification_uri_complete":"javascript:alert(1)","expires_in":1800}"#, "verification_uri_complete"),
        (#"{"device_code":"d","user_code":"WDJB-MJHT","verification_uri":"/device","expires_in":1800}"#, "verification_uri"),
        (#"{"device_code":"","user_code":"WDJB-MJHT","verification_uri":"https://example.com/device","expires_in":1800}"#, "device_code"),
        (#"{"device_code":"d","user_code":"","verification_uri":"https://example.com/device","expires_in":1800}"#, "user_code"),
        // An escape sequence: on a terminal, this rewrites what the user sees.
        (#"{"device_code":"d","user_code":"WDJB\u001b[2J-MJHT","verification_uri":"https://example.com/device","expires_in":1800}"#, "user_code"),
        // A bidirectional override: the code displays in an order other than the one it has.
        (#"{"device_code":"d","user_code":"WDJB‮-MJHT","verification_uri":"https://example.com/device","expires_in":1800}"#, "user_code"),
        (#"{"device_code":"d","user_code":"WDJB-MJHT","verification_uri":"https://example.com/device","expires_in":0}"#, "expires_in"),
        (#"{"device_code":"d","user_code":"WDJB-MJHT","verification_uri":"https://example.com/device","expires_in":1800,"interval":-5}"#, "interval")
    ]

    @Test("An unusable response is refused before anything is presented",
          arguments: unusableResponses)
    func unusableResponseIsRefused(body: String, field: String) async throws {
        let transport = ScriptedDeviceTransport(authorization: .json(body), polls: [.issued])
        let client = try Self.client(transport: transport)

        let error = await #expect(throws: OAuthError.self) {
            _ = try await client.signIn(sleeper: RecordingSleeper(), elapsed: { 0 }, present: { _ in
                Issue.record("an unusable response was presented")
            })
        }

        #expect(error?.code == "server_error")
        #expect(error?.detail?.contains(field) == true,
                "the refusal does not name \(field): \(String(describing: error))")
        #expect(await transport.tokenRequests.isEmpty)
    }

    // MARK: - Configuration

    @Test("A configuration with no device authorization endpoint is refused at creation")
    func missingEndpointIsRefused() throws {
        let configuration = ProviderConfiguration(
            identifier: "corp",
            authorizationEndpoint: try #require(URL(string: "https://auth.example.com/authorize")),
            tokenEndpoint: Self.tokenEndpoint,
            scope: Self.rfcScope)

        #expect(throws: DeviceGrantConfigurationError.noDeviceAuthorizationEndpoint(provider: "corp")) {
            _ = try DeviceAuthorizationClient(
                configuration: configuration, credentials: Self.credentials,
                transport: ScriptedDeviceTransport(authorization: .json("{}")))
        }
    }

    /// §3.1: "All requests from the device MUST use the Transport Layer Security (TLS)
    /// protocol". Both endpoints, since a redeem carries the device code — a bearer credential
    /// for the tokens the user is approving.
    @Test("An endpoint that is not HTTPS is refused at creation", arguments: ["device", "token"])
    func insecureEndpointIsRefused(which: String) throws {
        // SECURITY: the plaintext endpoint under test — RFC 8628 §3.1 requires TLS, and this asserts the refusal.
        let insecure = try #require(URL(string: "http://auth.example.com/\(which)"))
        let configuration = ProviderConfiguration(
            identifier: "corp",
            authorizationEndpoint: try #require(URL(string: "https://auth.example.com/authorize")),
            tokenEndpoint: which == "token" ? insecure : Self.tokenEndpoint,
            deviceAuthorizationEndpoint: which == "device" ? insecure : Self.deviceEndpoint,
            scope: Self.rfcScope)

        #expect(throws: DeviceGrantConfigurationError.insecureEndpoint(insecure)) {
            _ = try DeviceAuthorizationClient(
                configuration: configuration, credentials: Self.credentials,
                transport: ScriptedDeviceTransport(authorization: .json("{}")))
        }
    }

    // MARK: - Fixtures

    static let deviceEndpoint = URL(string: "https://server.example.com/device_authorization")
        ?? URL(fileURLWithPath: "/")
    static let tokenEndpoint = URL(string: "https://server.example.com/token")
        ?? URL(fileURLWithPath: "/")
    static let credentials = ClientCredentials(
        environment: "test", clientID: rfcClientID, clientSecret: "fixture-client-passphrase")

    static func client(
        transport: ScriptedDeviceTransport,
        method: ClientAuthenticationMethod = .none,
        scope: String = rfcScope,
        resource: URL? = nil
    ) throws -> DeviceAuthorizationClient {
        let configuration = ProviderConfiguration(
            identifier: "rfc8628",
            authorizationEndpoint: try #require(URL(string: "https://server.example.com/authorize")),
            tokenEndpoint: tokenEndpoint,
            deviceAuthorizationEndpoint: deviceEndpoint,
            scope: scope,
            authenticationMethod: method,
            resource: resource)
        return try DeviceAuthorizationClient(
            configuration: configuration, credentials: credentials, transport: transport)
    }
}

/// Answers a device authorization request and the polls that follow from a script, and
/// records each request with how it was authenticated.
actor ScriptedDeviceTransport: DeviceAuthorizationTransport {

    /// What the device authorization endpoint answers.
    enum Authorization: Sendable {
        /// A body, decoded exactly as a server's would be.
        case json(String)
        /// A refusal.
        case failure(OAuthError)
    }

    /// What one poll of the token endpoint answers.
    enum Poll: Sendable {
        case pending, slowDown, denied, issued
    }

    /// One request, as the transport received it.
    struct Sent: Sendable {
        let endpoint: URL
        let parameters: [String: String]
        let credentials: ClientCredentials
        let method: ClientAuthenticationMethod
    }

    static let issuedFixture = "fixture-issued-access"

    private let authorization: Authorization
    private var polls: [Poll]
    private(set) var authorizationRequests: [Sent] = []
    private(set) var tokenRequests: [Sent] = []
    /// Every request and every note, in the order they happened.
    private(set) var events: [String] = []

    init(authorization: Authorization, polls: [Poll] = []) {
        self.authorization = authorization
        self.polls = polls
    }

    /// Records something that happened outside the transport, in sequence with what did not.
    func note(_ event: String) {
        events.append(event)
    }

    func requestDeviceAuthorization(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws -> DeviceAuthorizationResponse {
        authorizationRequests.append(
            Sent(endpoint: endpoint, parameters: parameters, credentials: credentials, method: method))
        events.append("device authorization")
        switch authorization {
        case .json(let body):
            return try JSONDecoder().decode(DeviceAuthorizationResponse.self, from: Data(body.utf8))
        case .failure(let error):
            throw error
        }
    }

    func exchange(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws -> TokenResponse {
        tokenRequests.append(
            Sent(endpoint: endpoint, parameters: parameters, credentials: credentials, method: method))
        events.append("token")
        guard !polls.isEmpty else { throw OAuthError.serverError("the script ran out of polls") }
        switch polls.removeFirst() {
        case .pending: throw OAuthError.authorizationPending(nil)
        case .slowDown: throw OAuthError.slowDown(nil)
        case .denied: throw OAuthError.accessDenied(nil)
        case .issued:
            return TokenResponse(
                accessToken: Self.issuedFixture, tokenType: "Bearer",
                expiresIn: 3600, refreshToken: nil, scope: nil)
        }
    }
}
