import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthClient

/// Calling introspection from the client half — RFC 7662, the other end.
///
/// A resource server built on this package needs to ask an authorization server about a token
/// it was handed. Until now it could only take the bearer string on trust.
@Suite("RFC 7662 — introspecting from the client")
struct IntrospectionClientTests {

    private func url(_ string: String) throws -> URL {
        // SECURITY: parses a literal written in this test; no request is issued from it.
        try #require(URL(string: string))
    }

    /// The happy path: a live token comes back active, with its claims.
    @Test("An active token is reported active")
    func activeTokenIsReported() async throws {
        let transport = StubIntrospectionTransport(
            body: #"{"active":true,"scope":"read","client_id":"c1","exp":1788000000}"#)
        let introspector = TokenIntrospector(
            endpoint: try url("https://auth.example.com/introspect"),
            credentials: .init(clientId: "resource-server", clientSecret: "s3cret"),
            transport: transport)

        let result = try await introspector.introspect(token: "live-token")

        #expect(result.active)
        #expect(result.scope == "read")
    }

    /// An inactive answer is a result, not a thrown error.
    ///
    /// This is the whole point of RFC 7662 §2.2 reaching the caller: "the token is dead" and
    /// "the introspection request failed" are different conditions, and a client that raises
    /// both as errors cannot tell a revoked token from an unreachable server.
    @Test("An inactive token is returned, not thrown")
    func inactiveTokenIsReturned() async throws {
        let transport = StubIntrospectionTransport(body: #"{"active":false}"#)
        let introspector = TokenIntrospector(
            endpoint: try url("https://auth.example.com/introspect"),
            credentials: .init(clientId: "resource-server", clientSecret: "s3cret"),
            transport: transport)

        let result = try await introspector.introspect(token: "dead-token")

        #expect(!result.active)
    }

    /// The request authenticates, and carries the token in the body rather than the query.
    ///
    /// A token in a query string is a token in access logs, proxy logs and browser history.
    /// RFC 7662 §2.1 specifies a form-encoded body for exactly that reason.
    @Test("The request authenticates and puts the token in the body")
    func requestIsAuthenticatedAndFormEncoded() async throws {
        let transport = StubIntrospectionTransport(body: #"{"active":true}"#)
        let introspector = TokenIntrospector(
            endpoint: try url("https://auth.example.com/introspect"),
            credentials: .init(clientId: "resource-server", clientSecret: "s3cret"),
            transport: transport)

        _ = try await introspector.introspect(token: "some-token")

        let sent = try #require(await transport.lastRequest)
        #expect(sent.body.contains("token=some-token"))
        #expect(sent.authorization?.hasPrefix("Basic ") == true)
        #expect(!sent.url.absoluteString.contains("some-token"),
                "the token appeared in the URL, where it will be logged")
    }

    /// A server that answers with an error status is a failure, distinct from an inactive
    /// token — the distinction the previous test's suite exists to preserve.
    @Test("A transport failure throws rather than reading as inactive")
    func transportFailureThrows() async throws {
        let transport = StubIntrospectionTransport(body: "", statusCode: 503)
        let introspector = TokenIntrospector(
            endpoint: try url("https://auth.example.com/introspect"),
            credentials: .init(clientId: "resource-server", clientSecret: "s3cret"),
            transport: transport)

        await #expect(throws: (any Error).self) {
            _ = try await introspector.introspect(token: "any")
        }
    }
}

/// Records what was sent and answers from a script.
private actor StubIntrospectionTransport: IntrospectionTransport {
    struct Sent: Sendable {
        let url: URL
        let body: String
        let authorization: String?
    }

    private let body: String
    private let statusCode: Int
    private(set) var lastRequest: Sent?

    init(body: String, statusCode: Int = 200) {
        self.body = body
        self.statusCode = statusCode
    }

    func post(url: URL, body: String, authorization: String?) async throws -> (Data, Int) {
        lastRequest = Sent(url: url, body: body, authorization: authorization)
        return (Data(self.body.utf8), statusCode)
    }
}
