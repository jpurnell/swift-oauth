import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import RedirectWireStub
import Testing
@testable import SwiftOAuthClient
@testable import SwiftOAuthCore

/// The device authorization request on the wire, against a loopback server that records it.
///
/// The stub-transport tests check what the client asks the transport to send. These check what
/// `URLSessionTokenTransport` actually puts on the network and how it reads the answer — the
/// form body byte for byte against RFC 8628's own examples, and the error statuses RFC 6749
/// §5.2 describes. Redirects, the size limit and the TLS downgrade are covered with the other
/// credential-bearing requests, through `CredentialRedirectWireTests.Kind.deviceAuthorization`.
@Suite("RFC 8628 — the device authorization request on the wire")
struct DeviceAuthorizationWireTests {

    private static func endpoint(on server: RedirectWireServer) throws -> URL {
        try #require(server.url(path: "/device_authorization"))
    }

    private static let publicClient = ClientCredentials(
        environment: "test",
        clientID: DeviceAuthorizationClientTests.rfcClientID,
        clientSecret: "")

    /// RFC 8628 §3.1's example body is `client_id=1406020730&scope=example_scope`. A public
    /// client with that identifier and scope must put exactly those bytes on the wire.
    @Test("The body is §3.1's example, byte for byte", .timeLimit(.minutes(1)))
    func bodyMatchesTheRFCExample() async throws {
        let server = try await RedirectWireServer.start {
            .respond(status: 200, headers: ["Content-Type": "application/json"],
                     body: DeviceAuthorizationClientTests.rfcExampleResponse)
        }

        let response = try await URLSessionTokenTransport().requestDeviceAuthorization(
            endpoint: try Self.endpoint(on: server),
            parameters: ["scope": DeviceAuthorizationClientTests.rfcScope],
            credentials: Self.publicClient, method: .none)

        let sent = try #require(server.requests.first)
        #expect(sent.method == "POST")
        #expect(sent.target == "/device_authorization")
        #expect(sent.header("content-type") == "application/x-www-form-urlencoded")
        #expect(sent.body == "client_id=1406020730&scope=example_scope")
        #expect(sent.header("authorization") == nil, "a public client sent an Authorization header")
        #expect(response.userCode == "WDJB-MJHT")
        try await server.stop()
    }

    /// §3.2: "In the event of an error … the authorization server responds in the same way as
    /// the token endpoint", which is RFC 6749 §5.2 — a `400` (or `401`) and a JSON body naming
    /// the error. That reason reaches the caller as the matching `OAuthError`, not as a status.
    @Test("An RFC 6749 §5.2 error body becomes the matching OAuthError", .timeLimit(.minutes(1)),
          arguments: [
            (400, #"{"error":"invalid_client","error_description":"no such client"}"#,
             OAuthError.invalidClient("no such client")),
            (401, #"{"error":"invalid_client"}"#, OAuthError.invalidClient(nil)),
            (400, #"{"error":"invalid_scope","error_description":"nope"}"#, OAuthError.invalidScope("nope")),
            (400, #"{"error":"unauthorized_client"}"#, OAuthError.unauthorizedClient(nil))
          ])
    func errorBodyIsMapped(status: Int, body: String, expected: OAuthError) async throws {
        let server = try await RedirectWireServer.start {
            .respond(status: status, headers: ["Content-Type": "application/json"], body: body)
        }

        await #expect(throws: expected) {
            _ = try await URLSessionTokenTransport().requestDeviceAuthorization(
                endpoint: try Self.endpoint(on: server), parameters: [:],
                credentials: .testCredentials, method: .clientSecretBasic)
        }
        try await server.stop()
    }

    /// A failure with no body to explain it is reported by its status.
    @Test("A failure without an error body is reported by status", .timeLimit(.minutes(1)))
    func bareFailureIsReportedByStatus() async throws {
        let server = try await RedirectWireServer.start {
            .respond(status: 503, headers: [:], body: "")
        }

        await #expect(throws: OAuthError.serverError("HTTP 503")) {
            _ = try await URLSessionTokenTransport().requestDeviceAuthorization(
                endpoint: try Self.endpoint(on: server), parameters: [:],
                credentials: .testCredentials, method: .clientSecretBasic)
        }
        try await server.stop()
    }

    /// A `200` whose body is not §3.2's response — a token response, say — is the server's
    /// error, reported as one rather than as a decoding failure the caller cannot interpret.
    @Test("A success that is not a device authorization response is the server's error",
          .timeLimit(.minutes(1)))
    func wrongShapeIsTheServersError() async throws {
        let server = try await RedirectWireServer.start {
            .respond(status: 200, headers: ["Content-Type": "application/json"],
                     body: #"{"access_token":"x","token_type":"Bearer","expires_in":3600}"#)
        }

        await #expect(throws: OAuthError.serverError(
            "the device authorization response could not be decoded")) {
            _ = try await URLSessionTokenTransport().requestDeviceAuthorization(
                endpoint: try Self.endpoint(on: server), parameters: [:],
                credentials: .testCredentials, method: .clientSecretBasic)
        }
        try await server.stop()
    }
}

/// The whole grant over TLS: request, present, poll, redeem — against a scripted loopback
/// server, through the public client and the real transport.
@Suite("RFC 8628 — a device sign-in end to end, over TLS")
struct DeviceSignInWireTests {

    /// One scripted answer per request, in order.
    // Justification: `answers` and `index` are read and written only under `lock`.
    final class Script: @unchecked Sendable {
        private let lock = NSLock()
        private let answers: [RedirectWireServer.Behaviour]
        private var index = 0

        init(_ answers: [RedirectWireServer.Behaviour]) {
            self.answers = answers
        }

        func next() -> RedirectWireServer.Behaviour {
            lock.lock()
            defer { lock.unlock() }
            guard index < answers.count else {
                return .respond(status: 500, headers: [:], body: "")
            }
            defer { index += 1 }
            return answers[index]
        }
    }

    static func json(_ status: Int, _ body: String) -> RedirectWireServer.Behaviour {
        .respond(status: status, headers: ["Content-Type": "application/json"], body: body)
    }

    static let tokens = json(200, #"{"access_token":"wire-issued","token_type":"Bearer","expires_in":3600}"#)

    /// The proposal's line, on the wire: RFC 8628 §3.2's response, two polls answered
    /// `authorization_pending` and one with tokens — waits of [5, 5]; with `slow_down` in the
    /// middle, [5, 10]. And every redeem is §3.4's example request.
    @Test("Request, present, poll, redeem",
          .enabled(if: TLSFixture.isAvailable, "no loopback TLS certificate this platform's URLSession trusts"),
          .timeLimit(.minutes(1)),
          arguments: [("authorization_pending", [5.0, 5.0]), ("slow_down", [5.0, 10.0])])
    func signInEndToEnd(secondPoll: String, expectedWaits: [TimeInterval]) async throws {
        let fixture = try TLSFixture.make()
        let script = Script([
            Self.json(200, DeviceAuthorizationClientTests.rfcExampleResponse),
            Self.json(400, #"{"error":"authorization_pending"}"#),
            Self.json(400, #"{"error":"\#(secondPoll)"}"#),
            Self.tokens
        ])
        let server = try await RedirectWireServer.start(tls: fixture.certificate) { script.next() }

        let deviceEndpoint = try #require(server.url(path: "/device_authorization"))
        let configuration = ProviderConfiguration(
            identifier: "loopback",
            authorizationEndpoint: try #require(server.url(path: "/authorize")),
            tokenEndpoint: try #require(server.url(path: "/token")),
            deviceAuthorizationEndpoint: deviceEndpoint,
            scope: DeviceAuthorizationClientTests.rfcScope,
            authenticationMethod: .none)
        let client = try DeviceAuthorizationClient(
            configuration: configuration,
            credentials: ClientCredentials(
                environment: "test", clientID: DeviceAuthorizationClientTests.rfcClientID,
                clientSecret: ""),
            transport: fixture.token)
        let sleeper = RecordingSleeper()

        let issued = try await client.signIn(sleeper: sleeper, elapsed: { 0 }, present: { shown in
            #expect(shown.userCode == "WDJB-MJHT")
        })

        #expect(issued.accessToken == "wire-issued")
        #expect(await sleeper.waits == expectedWaits)

        let requests = server.requests
        #expect(requests.map(\.target) == ["/device_authorization", "/token", "/token", "/token"])
        #expect(requests.first?.body == "client_id=1406020730&scope=example_scope")
        // RFC 8628 §3.4's example, whose line breaks "are for display purposes only". The
        // parameters are compared as a set: the RFC prints them in one order and this package
        // sorts them, and form parameters have no order.
        let rfcRedeem: Set<Substring> = [
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
            "device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            "client_id=1406020730"
        ]
        for redeem in requests.dropFirst() {
            #expect(Set(redeem.body.split(separator: "&")) == rfcRedeem)
        }
        try await server.stop()
    }
}
