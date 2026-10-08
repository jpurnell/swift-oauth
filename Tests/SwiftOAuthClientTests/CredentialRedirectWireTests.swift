import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import RedirectWireStub
import Testing
@testable import SwiftOAuthClient
@testable import SwiftOAuthCore

/// What a redirect does to a request that carries a credential.
///
/// Every request this package makes itself is a `POST` holding something that must reach one
/// host only: a client secret, an authorization code and its PKCE verifier, a refresh token,
/// or a token being revoked or asked about. No specification this package implements provides
/// for a token, revocation or introspection endpoint answering with a redirect — RFC 6749
/// §3.2, RFC 7009 §2.1 and RFC 7662 §2.1 define the request and say nothing of one — so the
/// only safe reading of a `3xx` is "this is not the endpoint", not "send it over there".
///
/// Two loopback servers: the first redirects, the second records. The assertion is on the
/// second, and it is that nothing arrived.
@Suite("A credential-bearing request is never redirected")
struct CredentialRedirectWireTests {

    /// Each request this package puts on the wire.
    enum Kind: String, Sendable, CaseIterable, CustomTestStringConvertible {
        case codeExchangeBasic
        case codeExchangePost
        case codeExchangePublic
        case refresh
        case revocation
        case introspection

        var testDescription: String { rawValue }
    }

    static let statuses = [301, 302, 303, 307, 308]

    // Values that would be credentials in a real exchange. Each is distinct, so finding one in
    // a recorded request says which field travelled.
    static let clientIdentifierFixture = "fixture-client"
    static let clientPassphraseFixture = "fixture-client-passphrase"
    static let codeFixture = "fixture-authorization-code"
    static let verifierFixture = "fixture-pkce-verifier"
    static let refreshFixture = "fixture-refresh-value"
    static let inspectedFixture = "fixture-inspected-value"
    static let locationQueryFixture = "trace=fixture-location-query"

    /// Everything above, for searching a recorded request or an error's text.
    static let sensitiveFixtures = [
        clientPassphraseFixture, codeFixture, verifierFixture, refreshFixture, inspectedFixture
    ]

    private static func credentials() -> ClientCredentials {
        ClientCredentials(
            environment: "test",
            clientID: clientIdentifierFixture,
            clientSecret: clientPassphraseFixture)
    }

    /// Makes one request of the given kind against `endpoint`, on `session`.
    static func perform(_ kind: Kind, endpoint: URL, session: URLSession = .shared) async throws {
        let transport = URLSessionTokenTransport(session: session)
        let codeExchange = [
            "grant_type": GrantType.authorizationCode.rawValue,
            "code": codeFixture,
            "code_verifier": verifierFixture,
            "redirect_uri": "http://127.0.0.1/callback"
        ]
        switch kind {
        case .codeExchangeBasic:
            _ = try await transport.exchange(
                endpoint: endpoint, parameters: codeExchange,
                credentials: credentials(), method: .clientSecretBasic)
        case .codeExchangePost:
            _ = try await transport.exchange(
                endpoint: endpoint, parameters: codeExchange,
                credentials: credentials(), method: .clientSecretPost)
        case .codeExchangePublic:
            _ = try await transport.exchange(
                endpoint: endpoint, parameters: codeExchange,
                credentials: credentials(), method: .none)
        case .refresh:
            _ = try await transport.exchange(
                endpoint: endpoint,
                parameters: [
                    "grant_type": GrantType.refreshToken.rawValue,
                    "refresh_token": refreshFixture
                ],
                credentials: credentials(), method: .clientSecretBasic)
        case .revocation:
            _ = try await transport.exchange(
                endpoint: endpoint,
                parameters: ["token": refreshFixture, "token_type_hint": "refresh_token"],
                credentials: credentials(), method: .clientSecretBasic)
        case .introspection:
            let introspector = TokenIntrospector(
                endpoint: endpoint,
                credentials: .init(
                    clientId: clientIdentifierFixture, clientSecret: clientPassphraseFixture))
            _ = try await introspector.introspect(token: inspectedFixture)
        }
    }

    /// Two servers: `first` redirects every request to `second`, which records and answers.
    static func pair(status: Int) async throws -> (first: RedirectWireServer, second: RedirectWireServer) {
        let second = try await RedirectWireServer.start { .answer }
        let location = "\(second.origin)/elsewhere/collect?\(locationQueryFixture)"
        let first = try await RedirectWireServer.start { .redirect(status: status, location: location) }
        return (first, second)
    }

    private static func endpoint(on server: RedirectWireServer) throws -> URL {
        try #require(server.url(path: "/oauth/endpoint"))
    }

    @Test(
        "A redirect to another origin is refused, and nothing is sent there",
        arguments: Kind.allCases, statuses)
    func crossOriginRedirectIsRefused(kind: Kind, status: Int) async throws {
        let (first, second) = try await Self.pair(status: status)

        let refusal = await #expect(throws: OAuthRedirectRefused.self) {
            try await Self.perform(kind, endpoint: try Self.endpoint(on: first))
        }

        let arrived = second.requests
        #expect(arrived.isEmpty, "the second origin received \(arrived.map(Self.summary))")
        #expect(first.requests.count == 1)

        // The error says where the redirect pointed, by origin only, and what was asked.
        #expect(refusal?.status == status)
        #expect(refusal?.destination == second.origin)
        #expect(refusal?.endpoint == first.origin)
        let text = [refusal.map { String(describing: $0) }, refusal?.localizedDescription]
            .compactMap { $0 }.joined(separator: "\n")
        #expect(text.contains(second.origin))
        #expect(!text.contains("/elsewhere"), "the error carries the Location's path")
        #expect(!text.contains(Self.locationQueryFixture), "the error carries the Location's query")
        for fixture in Self.sensitiveFixtures {
            #expect(!text.contains(fixture), "the error carries \(fixture)")
        }

        try await first.stop()
        try await second.stop()
    }

    /// The rule is "not followed", not "not followed off-origin". A token endpoint that
    /// redirects within its own origin is still not the endpoint that was configured, and a
    /// `301`/`302`/`303` would arrive there as a body-less `GET` — a request that cannot mean
    /// what the `POST` meant.
    @Test(
        "A redirect within the origin is refused too",
        arguments: [Kind.codeExchangeBasic, Kind.introspection], statuses)
    func sameOriginRedirectIsRefused(kind: Kind, status: Int) async throws {
        let server = try await RedirectWireServer.start {
            .redirect(status: status, location: "/moved")
        }

        let refusal = await #expect(throws: OAuthRedirectRefused.self) {
            try await Self.perform(kind, endpoint: try Self.endpoint(on: server))
        }

        #expect(server.requests.count == 1, "the redirect was followed: \(server.requests.map(Self.summary))")
        #expect(refusal?.destination == server.origin)
        try await server.stop()
    }

    /// The refusal belongs to the request, not to the session. A caller who supplies a session
    /// through the public initialiser — to set a timeout, a proxy, a protocol class — gets the
    /// same behaviour as one who takes the default.
    @Test("A session the caller supplies is held to the same rule", arguments: statuses)
    func suppliedSessionIsHeldToTheRule(status: Int) async throws {
        let (first, second) = try await Self.pair(status: status)
        let session = URLSession(configuration: .ephemeral)
        defer { session.finishTasksAndInvalidate() }

        await #expect(throws: OAuthRedirectRefused.self) {
            try await Self.perform(
                .codeExchangeBasic, endpoint: try Self.endpoint(on: first), session: session)
        }

        #expect(second.requests.isEmpty, "the second origin received \(second.requests.map(Self.summary))")
        try await first.stop()
        try await second.stop()
    }

    /// The other half of the claim: a request that is *not* redirected still works, so the
    /// tests above are not passing because nothing can be sent at all.
    @Test("A request that is not redirected is delivered", arguments: Kind.allCases)
    func unredirectedRequestIsDelivered(kind: Kind) async throws {
        let server = try await RedirectWireServer.start { .answer }

        try await Self.perform(kind, endpoint: try Self.endpoint(on: server))

        let arrived = try #require(server.requests.first)
        #expect(server.requests.count == 1)
        #expect(arrived.method == "POST")
        #expect(arrived.header("content-type") == "application/x-www-form-urlencoded")
        try await server.stop()
    }

    /// The request is made by a hand-built bridge from a data task to `async`, because the
    /// task has to exist before it starts for its delegate to be set. A bridge that stopped
    /// *waiting* on cancellation without stopping the *transfer* would leave a request the
    /// caller abandoned on the wire until the session timed it out.
    ///
    /// The error is the evidence. `URLError.cancelled` is produced by the data task's own
    /// completion handler and by nothing else here, so receiving it means the task itself
    /// was cancelled.
    @Test("Cancelling the caller cancels the transfer", .timeLimit(.minutes(1)))
    func cancellationEndsTheRequest() async throws {
        let server = try await RedirectWireServer.start { .silence }
        let endpoint = try Self.endpoint(on: server)

        let exchange = Task {
            try await Self.perform(.codeExchangeBasic, endpoint: endpoint)
        }
        // The request is on the wire and will never be answered.
        await server.waitForRequest()
        exchange.cancel()

        let failure = await #expect(throws: URLError.self) {
            try await exchange.value
        }
        #expect(failure?.code == .cancelled)
        try await server.stop()
    }

    /// What one recorded request held, for a failure message: enough to say which credential
    /// crossed, without the test output becoming a place they are printed in full.
    static func summary(_ request: RedirectWireServer.Request) -> String {
        let carried = sensitiveFixtures.filter { request.body.contains($0) }
        let authorization = request.header("authorization") == nil ? "no" : "yes"
        return "\(request.method) \(request.target) authorization=\(authorization) "
            + "body=\(request.body.utf8.count)B carrying=\(carried)"
    }
}
