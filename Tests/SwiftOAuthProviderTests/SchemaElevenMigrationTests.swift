import Foundation
import Testing
import CSQLite
@testable import SwiftOAuthProvider

/// Schema 11, built the way an earlier release left the database and then migrated.
///
/// A fresh `:memory:` store is created at the current schema and never migrates from anything,
/// so a migration is only exercised by building an older database on disk and reopening it.
@Suite("Schema 11 — grants and subject indexes")
struct SchemaElevenMigrationTests {

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("oauth-schema11-\(UUID().uuidString).sqlite").path
    }

    private static func run(_ path: String, _ sql: String) throws {
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("could not open \(path)")
        }
        defer { sqlite3_close(db) }
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("could not run \(sql)")
        }
    }

    /// Every row of a one-column query, as strings (NULL as nil).
    private static func column(_ path: String, _ sql: String) throws -> [String?] {
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("could not open \(path)")
        }
        defer { sqlite3_close(db) }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("could not prepare \(sql)")
        }
        defer { sqlite3_finalize(stmt) }
        var rows: [String?] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            rows.append(sqlite3_column_text(stmt, 0).map { String(cString: $0) })
        }
        return rows
    }

    /// A schema-10 database holding one live token pair for `alice`, one with no subject, and a
    /// token pair from the same client that a grant could never have linked.
    private static func schemaTenDatabase() throws -> String {
        let path = tempPath()
        _ = try OAuthStorage(path: path, schemaVersion: 10)
        let far = Date().addingTimeInterval(3600).timeIntervalSince1970
        let now = Date().timeIntervalSince1970
        // Written with the column list of schema 10: there is no grant_id to name.
        try run(path, """
            INSERT INTO access_tokens (token_hash, client_id, scope, expires_at, created_at, revoked, subject)
            VALUES ('at-alice', 'app', 'read', \(far), \(now), 0, 'alice'),
                   ('at-nobody', 'app', 'read', \(far), \(now), 0, NULL);
            INSERT INTO refresh_tokens (token_hash, client_id, scope, expires_at, created_at, revoked, subject)
            VALUES ('rt-alice', 'app', 'read', \(far), \(now), 0, 'alice'),
                   ('rt-nobody', 'app', 'read', \(far), \(now), 0, NULL);
        """)
        return path
    }

    @Test("A schema-10 database gains grant_id on both token tables, and keeps its rows")
    func gainsGrantColumns() async throws {
        let path = try Self.schemaTenDatabase()
        #expect(try Self.column(path, "PRAGMA user_version") == ["10"])
        for table in ["access_tokens", "refresh_tokens"] {
            #expect(try Self.column(path, "SELECT name FROM pragma_table_info('\(table)') WHERE name = 'grant_id'").isEmpty)
        }

        _ = try OAuthStorage(path: path)

        #expect(try Self.column(path, "PRAGMA user_version") == ["11"])
        for table in ["access_tokens", "refresh_tokens"] {
            #expect(try Self.column(path, "SELECT name FROM pragma_table_info('\(table)') WHERE name = 'grant_id'") == ["grant_id"])
            // Existing rows: a grant is something the server records when it issues, and nothing
            // was recorded for these, so none is invented. They revoke one at a time.
            #expect(try Self.column(path, "SELECT grant_id FROM \(table) ORDER BY token_hash") == [nil, nil])
            // A NULL subject stays NULL, and a recorded one is untouched.
            #expect(try Self.column(path, "SELECT subject FROM \(table) ORDER BY token_hash") == ["alice", nil])
        }
    }

    @Test("The subject and grant indexes exist after migration")
    func gainsIndexes() async throws {
        let path = try Self.schemaTenDatabase()
        _ = try OAuthStorage(path: path)

        let indexes = Set(try Self.column(path, "SELECT name FROM sqlite_master WHERE type = 'index'").compactMap { $0 })
        for expected in [
            "idx_access_tokens_subject", "idx_refresh_tokens_subject",
            "idx_authorization_codes_subject", "idx_device_codes_subject",
            "idx_access_tokens_grant", "idx_refresh_tokens_grant"
        ] {
            #expect(indexes.contains(expected), "missing \(expected)")
        }
    }

    @Test("Reopening a migrated database is safe, and a fresh one has the same schema")
    func idempotentAndFreshAgree() async throws {
        let migrated = try Self.schemaTenDatabase()
        _ = try OAuthStorage(path: migrated)
        _ = try OAuthStorage(path: migrated)
        let fresh = Self.tempPath()
        _ = try OAuthStorage(path: fresh)

        let query = "SELECT name FROM sqlite_master WHERE type = 'index' ORDER BY name"
        #expect(try Self.column(migrated, query) == (try Self.column(fresh, query)))
        for table in ["access_tokens", "refresh_tokens", "authorization_codes", "device_codes"] {
            let columns = "SELECT name FROM pragma_table_info('\(table)') ORDER BY name"
            #expect(try Self.column(migrated, columns) == (try Self.column(fresh, columns)), "\(table)")
        }
    }

    @Test("Rows from before the migration are still tokens, and a legacy refresh token revokes only itself")
    func legacyRowsBehave() async throws {
        let path = try Self.schemaTenDatabase()
        let storage = try OAuthStorage(path: path)

        // The raw credentials are not stored, so plant a token whose hash we can compute.
        try await storage.saveRefreshToken(token: "fresh", clientId: "app", scope: "read",
                                           expiresAt: Date().addingTimeInterval(60), subject: "alice")
        #expect(try await storage.getRefreshTokenInfo(token: "fresh")?.grantId == nil)

        // Revoking by subject reaches migrated rows (the subject survived)...
        #expect(try await storage.revokeAllTokens(forSubject: "alice") == 3)
        // ...and the row with no subject stays out of reach.
        let remaining = try Self.column(path, "SELECT token_hash FROM refresh_tokens WHERE revoked = 0")
        #expect(remaining == ["rt-nobody"])
    }
}
