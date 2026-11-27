import Foundation
import Testing
import CSQLite
import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// A valid bearer token while the database is locked.
///
/// Found in a two-process run: a token that was valid was refused as `401 Unauthorized` for as
/// long as the other process held the lock, because the validation helper turned every storage
/// failure into "invalid". A client reads 401 as "re-authenticate" and loops. A lock is not a
/// verdict on the token, so it must be told apart from one.
@Suite("Bearer validation — a locked database is not an invalid token")
struct OAuthStorageBusyValidationTests {

    typealias Rival = OAuthStorageBusyTests.Rival

    static func rig(path: String, timeout: TimeInterval = 0.1) async throws
        -> (storage: OAuthStorage, handler: OAuthHTTPHandler)
    {
        let storage = try OAuthStorage(path: path, busyTimeout: timeout)
        let server = OAuthServer(
            storage: storage, issuer: "https://example.com", scopesSupported: ["mcp:tools"],
            served: .core, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        try await storage.saveClient(OAuthStorageBusyTests.client("c1"))
        try await storage.saveAccessToken(
            token: "live-token", clientId: "c1", scope: "mcp:tools",
            expiresAt: Date().addingTimeInterval(3600))
        return (storage, OAuthHTTPHandler(server: server))
    }

    @Test("A valid token validates while nobody holds the lock (control)")
    func controlValid() async throws {
        let path = OAuthStorageBusyTests.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let (_, handler) = try await Self.rig(path: path)
        #expect(await handler.validateBearerToken(authHeader: "Bearer live-token").isValid)
    }

    @Test("A valid token is temporarilyUnavailable, not invalid, while the lock is held")
    func busyIsNotInvalid() async throws {
        let path = OAuthStorageBusyTests.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let (_, handler) = try await Self.rig(path: path)
        let rival = try Rival(path: path)
        try rival.run("BEGIN EXCLUSIVE")

        let result = await handler.validateBearerToken(authHeader: "Bearer live-token")
        #expect(result == .temporarilyUnavailable(retryAfter: 5), "got \(result)")
        #expect(!result.isValid)

        try rival.run("ROLLBACK")
        #expect(await handler.validateBearerToken(authHeader: "Bearer live-token").isValid,
                "the token must validate again once the lock is released")
    }

    @Test("An unknown token while the database is healthy is still invalid")
    func unknownStaysInvalid() async throws {
        let path = OAuthStorageBusyTests.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let (_, handler) = try await Self.rig(path: path)
        let result = await handler.validateBearerToken(authHeader: "Bearer nope")
        #expect(result == .invalid(reason: "Token not found"))
    }

    @Test("A storage failure that is not a lock stays invalid: fail closed, and no claim that retrying helps")
    func nonBusyFailureStaysInvalid() async throws {
        let path = OAuthStorageBusyTests.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let (_, handler) = try await Self.rig(path: path)
        let rival = try Rival(path: path)
        try rival.run("DROP TABLE access_tokens")

        guard case .invalid(let reason) = await handler.validateBearerToken(authHeader: "Bearer live-token") else {
            Issue.record("a broken table is not a transient condition")
            return
        }
        #expect(reason == "Token validation failed")
    }

    @Test("The 503 a resource server sends carries Retry-After and an OAuth error body")
    func responseShape() {
        let response = OAuthHTTPHandler.temporarilyUnavailableResponse(retryAfter: 7)
        #expect(response.statusCode == 503)
        #expect(response.headers["Retry-After"] == "7")
        #expect(response.body.contains("temporarily_unavailable"))
        #expect(response.contentType == "application/json")
    }

    @Test("Device verification answers 503, not 500, while the database is locked")
    func deviceVerificationBusy() async throws {
        let path = OAuthStorageBusyTests.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let (_, handler) = try await Self.rig(path: path)
        let rival = try Rival(path: path)
        try rival.run("BEGIN EXCLUSIVE")
        defer { try? rival.run("ROLLBACK") }

        let response = await handler.handleDeviceVerificationSubmission(
            formParams: ["csrf_token": "x", "action": "confirm", "user_code": "ABCD-EFGH"],
            subject: "alice")
        #expect(response.statusCode == 503)
        #expect(response.headers["Retry-After"] == OAuthHTTPHandler.retryAfterSeconds)
    }
}
