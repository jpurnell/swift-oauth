import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// Binding the audience into what is issued — the half of RFC 8707 that does the work.
///
/// Validating `resource` and then issuing an unaudienced token would be theatre: the check
/// would pass, the token would still be good at every resource trusting this server, and the
/// only thing gained would be an error message. The point of a resource indicator is that the
/// issued token carries the audience it was asked for, so a resource can reject one minted for
/// somewhere else.
@Suite("RFC 8707 — audience binding")
struct AudienceBindingTests {

    private func url(_ string: String) throws -> URL {
        // SECURITY: parses a literal written in this test; no request is issued from it.
        try #require(URL(string: string))
    }

    /// A token saved for a resource reports that audience when validated.
    @Test("An issued token carries the audience it was issued for")
    func tokenCarriesAudience() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let api = try url("https://api.example.com")

        try await storage.saveAccessToken(
            token: "tok-1", clientId: "client-1", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: api)

        let result = try await storage.validateAccessToken(token: "tok-1")
        guard case .valid(_, _, let audience) = result else {
            Issue.record("expected a valid token, got \(result)")
            return
        }
        #expect(audience == api)
    }

    /// A token issued without one reports none, rather than reporting something invented.
    @Test("A token issued without an audience reports none")
    func unaudiencedTokenReportsNone() async throws {
        let storage = try OAuthStorage(path: ":memory:")

        try await storage.saveAccessToken(
            token: "tok-2", clientId: "client-1", scope: nil,
            expiresAt: Date().addingTimeInterval(3600), audience: nil)

        let result = try await storage.validateAccessToken(token: "tok-2")
        guard case .valid(_, _, let audience) = result else {
            Issue.record("expected a valid token, got \(result)")
            return
        }
        #expect(audience == nil)
    }

    /// A database created before this column existed must gain it.
    ///
    /// The schema is built with `CREATE TABLE IF NOT EXISTS` and the create deliberately omits
    /// this column, so on an existing database the create is a no-op and the column can only
    /// arrive by migration. Without one, every query naming it would fail at runtime — on
    /// deployed installations only, and never in a test starting from `:memory:`.
    ///
    /// What this proves: a database whose `access_tokens` table has no `audience` column gains
    /// one when reopened, and writes naming it then succeed. What it does not prove: that rows
    /// written before the migration survive it — `ALTER TABLE ADD COLUMN` preserves them by
    /// construction, and asserting it here would need raw SQL to plant a row the current API
    /// can no longer write.
    @Test("A database predating the audience column gains it")
    func existingDatabaseIsMigrated() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("oauth-migration-\(UUID().uuidString).sqlite").path
        // SECURITY: removes only the uniquely-named temp file this test just created.
        defer { try? FileManager.default.removeItem(atPath: path) }

        // A database as an earlier version left it: the table exists, the column does not.
        _ = try OAuthStorage(path: path, schemaVersion: 0)

        // Reopening at the current version must migrate rather than fail.
        let migrated = try OAuthStorage(path: path)
        let api = try url("https://api.example.com")
        try await migrated.saveAccessToken(
            token: "tok-migrated", clientId: "client-1", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: api)

        let result = try await migrated.validateAccessToken(token: "tok-migrated")
        guard case .valid(let clientId, _, let audience) = result else {
            Issue.record("the migrated database could not store an audience: \(result)")
            return
        }
        #expect(clientId == "client-1")
        #expect(audience == api)
    }

    /// Running the migration twice is not an error.
    ///
    /// A server restarts. If the second open tried to add a column that is already there,
    /// every restart after the first would fail to start.
    @Test("Reopening an already-migrated database succeeds")
    func migrationIsIdempotent() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("oauth-idempotent-\(UUID().uuidString).sqlite").path
        // SECURITY: removes only the uniquely-named temp file this test just created.
        defer { try? FileManager.default.removeItem(atPath: path) }

        _ = try OAuthStorage(path: path, schemaVersion: 0)
        _ = try OAuthStorage(path: path)
        let third = try OAuthStorage(path: path)

        try await third.saveAccessToken(
            token: "tok-3", clientId: "client-1", scope: nil,
            expiresAt: Date().addingTimeInterval(3600), audience: nil)
        #expect(try await third.validateAccessToken(token: "tok-3").isValid)
    }
}
