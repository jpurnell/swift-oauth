import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import RedirectWireStub
import Testing
@testable import SwiftOAuthClient
@testable import SwiftOAuthCore

/// What this package does with the *answer* to a request that carried a credential.
///
/// The redirect tests are about where a request goes. These are about what comes back, from a
/// server that is not behaving: a body that does not end, a cookie it would like returned, a
/// `3xx` that names nowhere.
@Suite("A credential-bearing request's answer is bounded")
struct ResponseSizeWireTests {

    typealias Kind = CredentialRedirectWireTests.Kind

    static let limit = OAuthResponseTooLarge.maximumResponseBytes

    /// Enough to be unmistakable, and an end so that a client which reads it all produces a
    /// failed assertion rather than an exhausted machine.
    static let offered = 64 * limit

    private static func endpoint(on server: RedirectWireServer) throws -> URL {
        try #require(server.url(path: "/oauth/endpoint"))
    }

    /// A token response of exactly `count` bytes, padded in a field the decoder ignores.
    static func tokenResponse(ofBytes count: Int) -> String {
        let open = #"{"access_token":"issued","token_type":"Bearer","expires_in":3600,"active":true,"pad":""#
        let close = #""}"#
        let padding = max(0, count - open.utf8.count - close.utf8.count)
        return open + String(repeating: "a", count: padding) + close
    }

    /// The claim is "cut off", not "discarded after reading": the server is asked how much it
    /// managed to send before the connection went away, and it must be far short of what it
    /// had to offer.
    @Test(
        "A body that keeps coming is cut off at the limit",
        .timeLimit(.minutes(2)),
        arguments: [Kind.codeExchangeBasic, .refresh, .revocation, .introspection])
    func endlessBodyIsCutOff(kind: Kind) async throws {
        let server = try await RedirectWireServer.start {
            .stream(chunk: 64 * 1024, total: Self.offered)
        }

        let refusal = await #expect(throws: OAuthResponseTooLarge.self) {
            try await CredentialRedirectWireTests.perform(kind, endpoint: try Self.endpoint(on: server))
        }

        #expect(refusal?.limit == Self.limit)
        #expect(refusal?.endpoint == server.origin)
        await server.waitForDisconnect()
        let sent = server.bodyBytesWritten
        #expect(sent < Self.offered / 2, "the server sent \(sent) of \(Self.offered) bytes")
        try await server.stop()
    }

    /// A server that says how much is coming is refused on its word, before any of it is read.
    @Test("A declared length past the limit is refused at the headers", .timeLimit(.minutes(1)))
    func declaredLengthIsRefused() async throws {
        let server = try await RedirectWireServer.start {
            .respond(
                status: 200,
                headers: ["Content-Type": "application/json", "Content-Length": String(Self.limit + 1)],
                body: "{}")
        }

        await #expect(throws: OAuthResponseTooLarge.self) {
            try await CredentialRedirectWireTests.perform(
                .codeExchangeBasic, endpoint: try Self.endpoint(on: server))
        }
        try await server.stop()
    }

    @Test("A body of exactly the limit is read; one byte more is not", .timeLimit(.minutes(1)))
    func boundaryIsExact() async throws {
        let atLimit = try await RedirectWireServer.start {
            .respond(
                status: 200, headers: ["Content-Type": "application/json"],
                body: Self.tokenResponse(ofBytes: Self.limit))
        }
        let transport = URLSessionTokenTransport()
        let response = try await transport.exchange(
            endpoint: try Self.endpoint(on: atLimit),
            parameters: ["grant_type": "refresh_token", "refresh_token": "fixture"],
            credentials: .testCredentials, method: .clientSecretBasic)
        #expect(response.accessToken == "issued")
        try await atLimit.stop()

        let overLimit = try await RedirectWireServer.start {
            .respond(
                status: 200, headers: ["Content-Type": "application/json"],
                body: Self.tokenResponse(ofBytes: Self.limit + 1))
        }
        await #expect(throws: OAuthResponseTooLarge.self) {
            _ = try await transport.exchange(
                endpoint: try Self.endpoint(on: overLimit),
                parameters: ["grant_type": "refresh_token", "refresh_token": "fixture"],
                credentials: .testCredentials, method: .clientSecretBasic)
        }
        try await overLimit.stop()
    }

    /// An error answer is bounded like any other: the size limit is not something a server
    /// escapes by choosing a `400`.
    @Test("An oversized error body is refused as too large, not read for its reason", .timeLimit(.minutes(1)))
    func oversizedErrorBodyIsRefused() async throws {
        let server = try await RedirectWireServer.start {
            .respond(
                status: 400, headers: ["Content-Type": "application/json"],
                body: Self.tokenResponse(ofBytes: Self.limit + 1))
        }

        await #expect(throws: OAuthResponseTooLarge.self) {
            try await CredentialRedirectWireTests.perform(
                .codeExchangeBasic, endpoint: try Self.endpoint(on: server))
        }
        try await server.stop()
    }
}

/// A `3xx` that names nowhere to go.
///
/// It is still the endpoint saying "not here", and it used to surface as whatever each caller
/// made of an unexpected status — "HTTP 302", "answered 302" — with nothing to say that a
/// redirect had been attempted at all.
@Suite("A redirect with no Location is a refused redirect")
struct RedirectWithoutLocationTests {

    typealias Kind = CredentialRedirectWireTests.Kind

    @Test(
        "A 3xx without a Location throws the redirect refusal, saying there was none",
        arguments: [Kind.codeExchangeBasic, .revocation, .introspection], [300, 301, 302, 303, 307, 308])
    func redirectWithoutLocationIsRefused(kind: Kind, status: Int) async throws {
        let server = try await RedirectWireServer.start {
            .respond(status: status, headers: [:], body: "")
        }
        let endpoint = try #require(server.url(path: "/oauth/endpoint"))

        let refusal = await #expect(throws: OAuthRedirectRefused.self) {
            try await CredentialRedirectWireTests.perform(kind, endpoint: endpoint)
        }

        #expect(refusal?.status == status)
        #expect(refusal?.endpoint == server.origin)
        #expect(refusal?.destination == OAuthRedirectRefused.noLocation)
        let text = refusal.map { String(describing: $0) } ?? ""
        #expect(text.contains("no Location"), "the error does not say what was wrong: \(text)")
        #expect(text.contains(String(status)))
        #expect(server.requests.count == 1)
        try await server.stop()
    }
}

/// What the default session remembers between requests: nothing.
///
/// `URLSession.shared` keeps a cookie jar, a credential store and a cache for the whole
/// process. A token endpoint that set a cookie had it returned on the next token request —
/// and on any other request the application made to that host on the shared session.
@Suite("The default session keeps nothing between requests")
struct DefaultSessionIsolationTests {

    static let cookieFixture = "fixture-cookie-value"

    private static let answerDocument =
        #"{"access_token":"issued","token_type":"Bearer","expires_in":3600,"active":true}"#

    private static func cookieSettingServer() async throws -> RedirectWireServer {
        try await RedirectWireServer.start {
            .respond(
                status: 200,
                headers: [
                    "Content-Type": "application/json",
                    "Set-Cookie": "oauth_session=\(cookieFixture); Path=/"
                ],
                body: answerDocument)
        }
    }

    @Test(
        "A cookie set by one answer is not sent with the next request",
        arguments: [CredentialRedirectWireTests.Kind.refresh, .introspection])
    func cookieIsNotReturned(kind: CredentialRedirectWireTests.Kind) async throws {
        let server = try await Self.cookieSettingServer()
        let endpoint = try #require(server.url(path: "/oauth/endpoint"))

        try await CredentialRedirectWireTests.perform(kind, endpoint: endpoint)
        try await CredentialRedirectWireTests.perform(kind, endpoint: endpoint)

        let arrived = server.requests
        #expect(arrived.count == 2)
        for request in arrived {
            #expect(request.header("cookie") == nil, "the request carried Cookie: \(request.header("cookie") ?? "")")
        }
        try await server.stop()
    }

    /// The default is a default. A caller who wants a cookie jar passes a session that has
    /// one, and it is used as given.
    @Test("A session the caller supplies keeps its own cookie storage")
    func suppliedSessionIsHonoured() async throws {
        let server = try await Self.cookieSettingServer()
        let endpoint = try #require(server.url(path: "/oauth/endpoint"))
        let session = URLSession(configuration: .ephemeral)
        defer { session.finishTasksAndInvalidate() }

        try await CredentialRedirectWireTests.perform(.refresh, endpoint: endpoint, session: session)
        try await CredentialRedirectWireTests.perform(.refresh, endpoint: endpoint, session: session)

        let arrived = server.requests
        #expect(arrived.count == 2)
        #expect(arrived.last?.header("cookie") == "oauth_session=\(Self.cookieFixture)")
        try await server.stop()
    }

    /// A caller's session may have a delegate of its own. The response to a token request is
    /// read by this package, for this package: it is not handed to that delegate piece by
    /// piece on the way.
    @Test("A supplied session's delegate is not handed the token response")
    func suppliedSessionDelegateDoesNotSeeTheBody() async throws {
        let server = try await RedirectWireServer.start { .answer }
        let endpoint = try #require(server.url(path: "/oauth/endpoint"))
        let observer = BodyObserver()
        let session = URLSession(configuration: .ephemeral, delegate: observer, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        try await CredentialRedirectWireTests.perform(.refresh, endpoint: endpoint, session: session)

        #expect(server.requests.count == 1)
        #expect(observer.bytesSeen == 0)
        try await server.stop()
    }

    @Test("The default session has no cookie storage, no credential storage and no cache")
    func defaultSessionConfiguration() {
        let configuration = CredentialRequest.isolatedSession.configuration
        #expect(configuration.httpCookieStorage == nil)
        #expect(configuration.urlCredentialStorage == nil)
        #expect(configuration.urlCache == nil)
        #expect(configuration.httpShouldSetCookies == false)
        #expect(configuration.requestCachePolicy == .reloadIgnoringLocalCacheData)
    }

    /// The credential store is the other thing a shared session carries. A `401` asking for
    /// Basic authentication is answered from it without the caller being asked — so a
    /// password stored for a host by anything in the process would be sent to that host's
    /// token endpoint.
    @Test("A stored credential is not offered to an endpoint that challenges for one", .timeLimit(.minutes(1)))
    func storedCredentialIsNotOffered() async throws {
        let server = try await RedirectWireServer.start {
            .respond(
                status: 401,
                headers: ["WWW-Authenticate": #"Basic realm="fixture-realm""#],
                body: "")
        }
        let endpoint = try #require(server.url(path: "/oauth/endpoint"))
        let space = URLProtectionSpace(
            host: "127.0.0.1", port: server.port, protocol: "http",
            realm: "fixture-realm", authenticationMethod: NSURLAuthenticationMethodHTTPBasic)
        let planted = URLCredential(
            user: "fixture-stored-user", password: "fixture-stored-passphrase", persistence: .forSession)
        URLCredentialStorage.shared.setDefaultCredential(planted, for: space)
        defer { URLCredentialStorage.shared.remove(planted, for: space) }

        // A public client, so the request has no `Authorization` of its own to confuse the
        // question of where one came from.
        await #expect(throws: OAuthError.self) {
            try await CredentialRedirectWireTests.perform(.codeExchangePublic, endpoint: endpoint)
        }

        // Not asserted: how many requests arrived. Apple's Foundation answers a `401` that
        // carries a Basic challenge by sending the request a second time, with or without a
        // credential to add — measured here as two identical `POST`s. What this test is about
        // is whether either of them carried something this package did not put there.
        let arrived = server.requests
        #expect(!arrived.isEmpty)
        for request in arrived {
            #expect(request.header("authorization") == nil, "a stored credential was sent")
        }
        try await server.stop()
    }
}

/// A refusal that arrives the way RFC 6749 §5.2 says a failed Basic authentication should:
/// `401`, with a `WWW-Authenticate: Basic` header.
///
/// To an HTTP client library that header is an authentication challenge, and what each
/// Foundation does with a challenge it has no credential for is its own. The caller needs one
/// thing from it: the provider's answer, promptly.
@Suite("A 401 with a Basic challenge is the provider's answer")
struct BasicChallengeTests {

    private static func challengingServer() async throws -> RedirectWireServer {
        try await RedirectWireServer.start {
            .respond(
                status: 401,
                headers: [
                    "Content-Type": "application/json",
                    "WWW-Authenticate": #"Basic realm="fixture-oauth""#
                ],
                body: #"{"error":"invalid_client","error_description":"wrong client secret"}"#)
        }
    }

    @Test("A token request is answered with the provider's invalid_client", .timeLimit(.minutes(1)))
    func tokenRequestReportsTheRefusal() async throws {
        let server = try await Self.challengingServer()
        let endpoint = try #require(server.url(path: "/oauth/endpoint"))

        let refusal = await #expect(throws: OAuthError.self) {
            try await CredentialRedirectWireTests.perform(.codeExchangeBasic, endpoint: endpoint)
        }

        #expect(refusal == .invalidClient("wrong client secret"))
        try await server.stop()
    }

    @Test("An introspection request is answered with the status", .timeLimit(.minutes(1)))
    func introspectionReportsTheRefusal() async throws {
        let server = try await Self.challengingServer()
        let endpoint = try #require(server.url(path: "/oauth/endpoint"))

        let refusal = await #expect(throws: OAuthError.self) {
            try await CredentialRedirectWireTests.perform(.introspection, endpoint: endpoint)
        }

        #expect(refusal == .serverError("The introspection endpoint answered 401."))
        try await server.stop()
    }
}

/// A session delegate that counts the body bytes it is shown.
// Justification: the one mutable field is read and written only under `lock`.
final class BodyObserver: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    var bytesSeen: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        defer { lock.unlock() }
        count += data.count
    }
}
