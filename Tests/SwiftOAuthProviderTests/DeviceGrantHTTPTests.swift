import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// The device grant over HTTP — RFC 8628 §3.1–3.5, at the provider's endpoints.
///
/// The metadata has advertised `device_authorization_endpoint` and the device grant whenever a
/// deployment declared them, and the endpoints refused both. These hold the endpoints to the
/// wire the RFC describes: the device authorization request and response (§3.1, §3.2), the
/// token request and its four polling errors (§3.4, §3.5), and the page where the user enters
/// the code (§3.3).
@Suite("RFC 8628 — the device grant over HTTP")
struct DeviceGrantHTTPTests {

    static let issuer = "https://auth.example.com"
    static let deviceGrant = GrantType.deviceCode.rawValue

    struct Fixture {
        let server: OAuthServer
        let storage: OAuthStorage
        let handler: OAuthHTTPHandler
        let clock: ManualClock
    }

    static func serving() throws -> ServedCapabilities {
        try ServedCapabilities(
            grantTypes: [.authorizationCode, .refreshToken, .deviceCode],
            clientAuthenticationMethods: [.none, .clientSecretBasic, .clientSecretPost],
            deviceAuthorization: "\(issuer)/device_authorization")
    }

    static func fixture(served: ServedCapabilities? = nil) async throws -> Fixture {
        let storage = try OAuthStorage(path: ":memory:")
        let clock = ManualClock()
        let server = OAuthServer(
            storage: storage, issuer: issuer, scopesSupported: ["read", "write"],
            served: try served ?? serving(), resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true),
            now: { clock.now })
        // A public command-line client, registered for the device grant only.
        try await storage.saveClient(RegisteredClient(
            clientId: "cli", clientSecret: nil, clientName: "Terminal <b>CLI</b>",
            redirectUris: [], grantTypes: [deviceGrant, "refresh_token"],
            tokenEndpointAuthMethod: "none", registrationDate: Date()))
        // A confidential client for the same grant.
        try await storage.saveClient(RegisteredClient(
            clientId: "tv", clientSecret: "tv-secret", clientName: "Television",
            redirectUris: [], grantTypes: [deviceGrant],
            tokenEndpointAuthMethod: "client_secret_basic", registrationDate: Date()))
        // A client that never asked for the device grant.
        try await storage.saveClient(RegisteredClient(
            clientId: "web", clientSecret: nil, clientName: "Web app",
            redirectUris: ["https://web.example.com/cb"], grantTypes: ["authorization_code"],
            tokenEndpointAuthMethod: "none", registrationDate: Date()))
        return Fixture(
            server: server, storage: storage, handler: OAuthHTTPHandler(server: server),
            clock: clock)
    }

    static func json(_ response: OAuthHTTPResponse) throws -> [String: Any] {
        try #require(
            try JSONSerialization.jsonObject(with: Data(response.body.utf8)) as? [String: Any])
    }

    static func basic(_ id: String, _ secret: String) -> String {
        "Basic " + Data("\(id):\(secret)".utf8).base64EncodedString()
    }

    /// Starts a flow as `cli` and returns the decoded §3.2 response.
    static func start(_ fixture: Fixture) async throws -> DeviceAuthorizationResponse {
        let response = await fixture.handler.handleDeviceAuthorizationRequest(
            body: "client_id=cli&scope=read", authHeader: nil)
        #expect(response.statusCode == 200, "\(response.body)")
        return try JSONDecoder().decode(
            DeviceAuthorizationResponse.self, from: Data(response.body.utf8))
    }

    static func poll(
        _ fixture: Fixture, _ deviceCode: String, client: String = "cli"
    ) async -> OAuthHTTPResponse {
        let encoded = deviceCode.addingPercentEncoding(withAllowedCharacters: .alphanumerics)
            ?? deviceCode
        return await fixture.handler.handleTokenRequest(
            body: "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
                + "&device_code=\(encoded)&client_id=\(client)",
            authHeader: nil)
    }

    static func errorCode(_ response: OAuthHTTPResponse) throws -> String? {
        try json(response)["error"] as? String
    }

    /// A CSRF token from the verification page, as `subject` would load it.
    static func csrf(_ fixture: Fixture, subject: String, userCode: String? = nil) async throws -> String {
        let page = await fixture.handler.handleDeviceVerificationPage(
            queryParams: userCode.map { ["user_code": $0] } ?? [:], subject: subject)
        #expect(page.statusCode == 200)
        let marker = #"name="csrf_token" value=""#
        let start = try #require(page.body.range(of: marker))
        let rest = page.body[start.upperBound...]
        let end = try #require(rest.firstIndex(of: "\""))
        return String(rest[..<end])
    }

    // MARK: - §3.1 / §3.2 — the device authorization endpoint

    @Test("A device authorization request answers 200 with every §3.2 field, uncached")
    func deviceAuthorizationResponds() async throws {
        let fixture = try await Self.fixture()
        let response = await fixture.handler.handleDeviceAuthorizationRequest(
            body: "client_id=cli&scope=read", authHeader: nil)
        let body = try Self.json(response)

        #expect(response.statusCode == 200)
        #expect(response.contentType == "application/json")
        #expect(response.headers["Cache-Control"] == "no-store")
        let userCode = try #require(body["user_code"] as? String)
        #expect(userCode.count == 9)
        #expect((body["device_code"] as? String)?.hasPrefix("mcp_dc_") == true)
        #expect(body["verification_uri"] as? String == "\(Self.issuer)/device")
        #expect(body["verification_uri_complete"] as? String
                == "\(Self.issuer)/device?user_code=\(userCode)")
        #expect(body["expires_in"] as? Double == 1800)
        #expect(body["interval"] as? Double == 5)
    }

    @Test("A confidential client authenticates at the device endpoint, as at the token endpoint")
    func confidentialClientAuthenticates() async throws {
        let fixture = try await Self.fixture()

        let good = await fixture.handler.handleDeviceAuthorizationRequest(
            body: "scope=read", authHeader: Self.basic("tv", "tv-secret"))
        let bad = await fixture.handler.handleDeviceAuthorizationRequest(
            body: "scope=read", authHeader: Self.basic("tv", "wrong"))

        #expect(good.statusCode == 200)
        #expect(bad.statusCode == 401)
        #expect(try Self.errorCode(bad) == "invalid_client")
    }

    @Test("An unknown client is invalid_client")
    func unknownClientRefused() async throws {
        let fixture = try await Self.fixture()
        let response = await fixture.handler.handleDeviceAuthorizationRequest(
            body: "client_id=nobody", authHeader: nil)

        #expect(response.statusCode == 401)
        #expect(try Self.errorCode(response) == "invalid_client")
    }

    @Test("A client not registered for the device grant is unauthorized_client")
    func clientWithoutGrantRefused() async throws {
        let fixture = try await Self.fixture()
        let response = await fixture.handler.handleDeviceAuthorizationRequest(
            body: "client_id=web", authHeader: nil)

        #expect(response.statusCode == 400)
        #expect(try Self.errorCode(response) == "unauthorized_client")
    }

    @Test("A deployment that does not serve the grant refuses it at both endpoints")
    func notServedRefused() async throws {
        let fixture = try await Self.fixture(served: .core)

        let start = await fixture.handler.handleDeviceAuthorizationRequest(
            body: "client_id=cli", authHeader: nil)
        let poll = await Self.poll(fixture, "anything")

        #expect(start.statusCode == 400)
        #expect(try Self.errorCode(start) == "unsupported_grant_type")
        #expect(poll.statusCode == 400)
        #expect(try Self.errorCode(poll) == "unsupported_grant_type")
    }

    @Test("The scope a device asked for is the scope its tokens carry")
    func scopeIsCarried() async throws {
        let fixture = try await Self.fixture()
        let started = try await Self.start(fixture)
        try await fixture.server.approveDeviceCode(userCode: started.userCode, subject: "ada")

        let tokens = try Self.json(await Self.poll(fixture, started.deviceCode))
        #expect(tokens["scope"] as? String == "read")
    }

    // MARK: - §3.4 / §3.5 — the token endpoint

    @Test("Polling before approval is a 400 authorization_pending")
    func pendingOverHTTP() async throws {
        let fixture = try await Self.fixture()
        let started = try await Self.start(fixture)

        let response = await Self.poll(fixture, started.deviceCode)

        #expect(response.statusCode == 400)
        #expect(try Self.errorCode(response) == "authorization_pending")
    }

    @Test("Polling too soon is a 400 slow_down")
    func slowDownOverHTTP() async throws {
        let fixture = try await Self.fixture()
        let started = try await Self.start(fixture)

        _ = await Self.poll(fixture, started.deviceCode)
        fixture.clock.advance(1)
        let response = await Self.poll(fixture, started.deviceCode)

        #expect(response.statusCode == 400)
        #expect(try Self.errorCode(response) == "slow_down")
    }

    /// §3.5 reuses RFC 6749 §5.2's error response for `access_denied`, which is a 400. The
    /// authorization endpoint's redirect-carried `access_denied` has no status of its own;
    /// at the token endpoint, a 403 would be a shape no device client parses.
    @Test("A denied code is a 400 access_denied")
    func deniedOverHTTP() async throws {
        let fixture = try await Self.fixture()
        let started = try await Self.start(fixture)
        try await fixture.server.denyDeviceCode(userCode: started.userCode, subject: "ada")

        let response = await Self.poll(fixture, started.deviceCode)

        #expect(response.statusCode == 400)
        #expect(try Self.errorCode(response) == "access_denied")
    }

    @Test("An expired code is a 400 expired_token")
    func expiredOverHTTP() async throws {
        let fixture = try await Self.fixture()
        let started = try await Self.start(fixture)
        fixture.clock.advance(started.expiresIn + 1)

        let response = await Self.poll(fixture, started.deviceCode)

        #expect(response.statusCode == 400)
        #expect(try Self.errorCode(response) == "expired_token")
    }

    @Test("An approved code is 200 with tokens once, and invalid_grant after")
    func approvedOverHTTP() async throws {
        let fixture = try await Self.fixture()
        let started = try await Self.start(fixture)
        try await fixture.server.approveDeviceCode(userCode: started.userCode, subject: "ada")

        let first = await Self.poll(fixture, started.deviceCode)
        let second = await Self.poll(fixture, started.deviceCode)

        #expect(first.statusCode == 200)
        #expect(first.headers["Cache-Control"] == "no-store")
        let tokens = try JSONDecoder().decode(TokenResponse.self, from: Data(first.body.utf8))
        #expect(try await fixture.server.introspect(token: tokens.accessToken).subject == "ada")
        #expect(second.statusCode == 400)
        #expect(try Self.errorCode(second) == "invalid_grant")
    }

    @Test("Another client's device code is invalid_grant")
    func otherClientsCode() async throws {
        let fixture = try await Self.fixture()
        let started = try await Self.start(fixture)
        try await fixture.server.approveDeviceCode(userCode: started.userCode, subject: "ada")

        let response = await fixture.handler.handleTokenRequest(
            body: "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
                + "&device_code=\(started.deviceCode)",
            authHeader: Self.basic("tv", "tv-secret"))

        #expect(try Self.errorCode(response) == "invalid_grant")
    }

    @Test("A device-grant token request without device_code is invalid_request")
    func missingDeviceCode() async throws {
        let fixture = try await Self.fixture()
        let response = await fixture.handler.handleTokenRequest(
            body: "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id=cli",
            authHeader: nil)

        #expect(response.statusCode == 400)
        #expect(try Self.errorCode(response) == "invalid_request")
    }

    @Test("A client not registered for the grant cannot poll with it")
    func pollRequiresGrant() async throws {
        let fixture = try await Self.fixture()
        let response = await Self.poll(fixture, "anything", client: "web")

        #expect(try Self.errorCode(response) == "unauthorized_client")
    }

    // MARK: - §3.3 — the verification page

    @Test("The verification page offers a form, prefilled from verification_uri_complete")
    func verificationPagePrefills() async throws {
        let fixture = try await Self.fixture()
        let started = try await Self.start(fixture)
        let complete = try #require(started.verificationURIComplete)
        let query = try #require(URLComponents(url: complete, resolvingAgainstBaseURL: false)?
            .queryItems)

        let page = await fixture.handler.handleDeviceVerificationPage(
            queryParams: Dictionary(uniqueKeysWithValues: query.map { ($0.name, $0.value ?? "") }),
            subject: "ada")

        #expect(page.statusCode == 200)
        #expect(page.contentType.hasPrefix("text/html"))
        #expect(page.headers["Cache-Control"] == "no-store")
        #expect(page.body.contains(#"value="\#(started.userCode)""#))
        #expect(page.body.contains(#"name="csrf_token""#))
    }

    @Test("What is not a user code is not reflected into the page")
    func verificationPageDoesNotReflect() async throws {
        let fixture = try await Self.fixture()
        let page = await fixture.handler.handleDeviceVerificationPage(
            queryParams: ["user_code": "\"><script>alert(1)</script>"], subject: "ada")

        #expect(page.statusCode == 200)
        #expect(!page.body.contains("<script>"))
        #expect(!page.body.contains("alert(1)"))
    }

    /// §5.4: the user is shown which client is asking before they approve, so a code read to
    /// them by someone else is something they can notice is not their own device's.
    @Test("Continuing shows the client and scope, escaped, and approves nothing yet")
    func confirmationNamesTheClient() async throws {
        let fixture = try await Self.fixture()
        let started = try await Self.start(fixture)
        let token = try await Self.csrf(fixture, subject: "ada")

        let page = await fixture.handler.handleDeviceVerificationSubmission(
            formParams: ["action": "confirm", "user_code": started.userCode.lowercased(),
                         "csrf_token": token],
            subject: "ada")

        #expect(page.statusCode == 200)
        #expect(page.body.contains("Terminal &lt;b&gt;CLI&lt;/b&gt;"))
        #expect(!page.body.contains("<b>CLI</b>"))
        #expect(page.body.contains("read"))
        #expect(page.body.contains(#"value="approve""#))
        #expect(page.body.contains(#"value="deny""#))
        #expect(try Self.errorCode(await Self.poll(fixture, started.deviceCode))
                == "authorization_pending")
    }

    @Test("Approving through the page lets the device collect tokens naming the user")
    func approveThroughThePage() async throws {
        let fixture = try await Self.fixture()
        let started = try await Self.start(fixture)
        let token = try await Self.csrf(fixture, subject: "ada")

        let page = await fixture.handler.handleDeviceVerificationSubmission(
            formParams: ["action": "approve", "user_code": started.userCode, "csrf_token": token],
            subject: "ada")
        let polled = await Self.poll(fixture, started.deviceCode)

        #expect(page.statusCode == 200)
        #expect(polled.statusCode == 200)
        let tokens = try JSONDecoder().decode(TokenResponse.self, from: Data(polled.body.utf8))
        #expect(try await fixture.server.introspect(token: tokens.accessToken).subject == "ada")
    }

    @Test("Denying through the page ends the device's flow with access_denied")
    func denyThroughThePage() async throws {
        let fixture = try await Self.fixture()
        let started = try await Self.start(fixture)
        let token = try await Self.csrf(fixture, subject: "ada")

        let page = await fixture.handler.handleDeviceVerificationSubmission(
            formParams: ["action": "deny", "user_code": started.userCode, "csrf_token": token],
            subject: "ada")

        #expect(page.statusCode == 200)
        #expect(try Self.errorCode(await Self.poll(fixture, started.deviceCode)) == "access_denied")
    }

    /// The forged-approval attack: a page elsewhere posts `action=approve` with the attacker's
    /// user code from the victim's browser. A CSRF token is bound to the user it was issued
    /// to, so one the attacker fetched as themselves approves nothing as the victim.
    @Test("A CSRF token issued to one user does not approve as another")
    func csrfIsBoundToTheUser() async throws {
        let fixture = try await Self.fixture()
        let started = try await Self.start(fixture)
        let attackers = try await Self.csrf(fixture, subject: "mallory")

        let page = await fixture.handler.handleDeviceVerificationSubmission(
            formParams: ["action": "approve", "user_code": started.userCode,
                         "csrf_token": attackers],
            subject: "ada")

        #expect(page.statusCode == 400)
        #expect(try Self.errorCode(await Self.poll(fixture, started.deviceCode))
                == "authorization_pending")
    }

    @Test("A CSRF token is single use")
    func csrfIsSingleUse() async throws {
        let fixture = try await Self.fixture()
        let first = try await Self.start(fixture)
        let second = try await Self.start(fixture)
        let token = try await Self.csrf(fixture, subject: "ada")

        let used = await fixture.handler.handleDeviceVerificationSubmission(
            formParams: ["action": "approve", "user_code": first.userCode, "csrf_token": token],
            subject: "ada")
        let replayed = await fixture.handler.handleDeviceVerificationSubmission(
            formParams: ["action": "approve", "user_code": second.userCode, "csrf_token": token],
            subject: "ada")

        #expect(used.statusCode == 200)
        #expect(replayed.statusCode == 400)
    }

    @Test("A wrong code on the page is a 400 that says only that the code did not match")
    func wrongCodeOnThePage() async throws {
        let fixture = try await Self.fixture()
        let token = try await Self.csrf(fixture, subject: "ada")

        let page = await fixture.handler.handleDeviceVerificationSubmission(
            formParams: ["action": "approve", "user_code": "BBBB-BBBB", "csrf_token": token],
            subject: "ada")

        #expect(page.statusCode == 400)
        #expect(page.contentType.hasPrefix("text/html"))
        #expect(page.body.contains("not valid"))
    }

    // MARK: - Registration

    /// RFC 7591 §2: `redirect_uris` is required "for use in redirect-based flows". The device
    /// grant is not one, and refusing a registration that names none left a command-line
    /// client no way to register for the grant this provider advertises.
    @Test("A client registering for the device grant alone needs no redirect URI")
    func deviceOnlyRegistration() async throws {
        let fixture = try await Self.fixture()
        let response = await fixture.handler.handleRegistrationRequest(body: """
            {"client_name":"CLI","redirect_uris":[],
             "grant_types":["urn:ietf:params:oauth:grant-type:device_code"],
             "token_endpoint_auth_method":"none"}
            """)

        #expect(response.statusCode == 201, "\(response.body)")
    }

    @Test("A client registering for the code grant still needs a redirect URI")
    func codeRegistrationStillNeedsRedirect() async throws {
        let fixture = try await Self.fixture()
        let response = await fixture.handler.handleRegistrationRequest(body: """
            {"client_name":"App","redirect_uris":[],
             "grant_types":["authorization_code","urn:ietf:params:oauth:grant-type:device_code"],
             "token_endpoint_auth_method":"none"}
            """)

        #expect(response.statusCode == 400)
    }
}
