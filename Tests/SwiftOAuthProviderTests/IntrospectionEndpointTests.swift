import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// The introspection endpoint — RFC 7662, provider half.
///
/// The rules here are security rules rather than plumbing, and each one exists because the
/// obvious implementation gets it wrong.
@Suite("RFC 7662 — the introspection endpoint")
struct IntrospectionEndpointTests {

    /// The server and the storage behind it.
    ///
    /// Returned as a pair rather than reaching into the server for its storage: seeding a
    /// token is this test's business, and a `storageForTesting` hatch on the production type
    /// would be a permanent API carrying a temporary need.
    private func makeServer(
        issuer: String = "https://mcp.example.com"
    ) async throws -> (server: OAuthServer, storage: OAuthStorage) {
        let storage = try OAuthStorage(path: ":memory:")
        return (await OAuthServer(storage: storage, issuer: issuer), storage)
    }

    private func url(_ string: String) throws -> URL {
        // SECURITY: parses a literal written in this test; no request is issued from it.
        try #require(URL(string: string))
    }

    /// A live token describes itself.
    @Test("An active token introspects with its claims")
    func activeTokenIntrospects() async throws {
        let (server, storage) = try await makeServer()
        let api = try url("https://mcp.example.com")
        let expiry = Date().addingTimeInterval(3600)
        try await storage.saveAccessToken(
            token: "live-token", clientId: "client-1", scope: "read write",
            expiresAt: expiry, audience: api)

        let result = try await server.introspect(token: "live-token")

        #expect(result.active)
        #expect(result.scope == "read write")
        #expect(result.clientId == "client-1")
        #expect(result.audience == [api.absoluteString])
        // The stored expiry, to the second. Asserting only that it is non-nil would pass for
        // a server reporting the epoch, which is exactly the bug a resource server acts on.
        let reported = try #require(result.expiry)
        #expect(abs(reported.timeIntervalSince(expiry)) < 1)
    }

    /// An expired token is `active: false` — **not** an error.
    ///
    /// RFC 7662 §2.2. This is the distinction implementations most often get wrong, and the
    /// consequence of getting it wrong is that every caller has to treat "this token is no
    /// good" as a transport failure — a different condition, handled elsewhere, usually with a
    /// retry that cannot help.
    @Test("An expired token is inactive, not an error")
    func expiredTokenIsInactive() async throws {
        let (server, storage) = try await makeServer()
        try await storage.saveAccessToken(
            token: "dead-token", clientId: "client-1", scope: "read",
            expiresAt: Date().addingTimeInterval(-60), audience: nil)

        let result = try await server.introspect(token: "dead-token")

        #expect(!result.active)
    }

    /// A token that was never issued is inactive too, and for the same reason: the caller
    /// learns nothing either way, which is the point.
    @Test("An unknown token is inactive rather than an error")
    func unknownTokenIsInactive() async throws {
        let (server, storage) = try await makeServer()

        let result = try await server.introspect(token: "never-existed")

        #expect(!result.active)
    }

    /// A revoked token is inactive.
    @Test("A revoked token is inactive")
    func revokedTokenIsInactive() async throws {
        let (server, storage) = try await makeServer()
        try await storage.saveAccessToken(
            token: "revoked-token", clientId: "client-1", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: nil)
        try await storage.revokeAccessToken(token: "revoked-token")

        let result = try await server.introspect(token: "revoked-token")

        #expect(!result.active)
    }

    /// An inactive response carries nothing else — RFC 7662 §2.2.
    ///
    /// A response that leaks the scope or the client of a dead token is an oracle: it answers
    /// questions about tokens the caller does not hold and has not proven anything about.
    /// Checked on the encoded form, because that is what leaves the process.
    @Test("An inactive response reveals nothing about the token")
    func inactiveResponseRevealsNothing() async throws {
        let (server, storage) = try await makeServer()
        try await storage.saveAccessToken(
            token: "expired-with-claims", clientId: "secret-client", scope: "admin:everything",
            expiresAt: Date().addingTimeInterval(-60), audience: nil)

        let result = try await server.introspect(token: "expired-with-claims")
        let encoded = try JSONEncoder().encode(result)
        let json = String(decoding: encoded, as: UTF8.self)

        #expect(!json.contains("secret-client"), "the response named the client of a dead token")
        #expect(!json.contains("admin:everything"), "the response named the scope of a dead token")
        let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        #expect(object.count == 1, "an inactive response carried \(object.keys.sorted())")
    }
}
