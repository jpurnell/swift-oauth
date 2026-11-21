import Foundation
import Testing
import CSQLite
@testable import SwiftOAuthProvider

/// Schema 12: `refresh_tokens.replaced_by`, read by the refresh grace window.
///
/// Built the way schema 11 left the database, then reopened: a fresh `:memory:` store is created
/// at the current schema and never migrates from anything.
@Suite("Schema 12 — replaced_by")
struct SchemaTwelveMigrationTests {

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("oauth-schema12-\(UUID().uuidString).sqlite").path
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

    private static func column(_ path: String, _ sql: String) throws -> [String?] {
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("could not open \(path)")
        }
        defer { sqlite3_close(db) }
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("could not prepare \(sql)")
        }
        var rows: [String?] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            rows.append(sqlite3_column_text(stmt, 0).map { String(cString: $0) })
        }
        return rows
    }

    /// A schema-11 database holding a refresh token that was spent (rotated) a moment ago, and
    /// its live successor: exactly what a grace window must NOT treat as retryable, because
    /// nothing recorded which token replaced which.
    private static func schemaElevenDatabase(token: String, successor: String) throws -> String {
        let path = tempPath()
        _ = try OAuthStorage(path: path, schemaVersion: 11)
        let far = Date().addingTimeInterval(3600).timeIntervalSince1970
        let now = Date().timeIntervalSince1970
        try run(path, """
            INSERT INTO refresh_tokens
              (token_hash, client_id, scope, expires_at, created_at, revoked, subject, grant_id, rotated_at)
            VALUES ('\(OAuthStorage.sha256Hex(token))', 'app', 'read', \(far), \(now), 0, 'alice', 'g1', \(now)),
                   ('\(OAuthStorage.sha256Hex(successor))', 'app', 'read', \(far), \(now), 0, 'alice', 'g1', NULL);
        """)
        return path
    }

    @Test("A schema-11 database gains replaced_by, NULL for every existing row")
    func gainsReplacedBy() async throws {
        let path = try Self.schemaElevenDatabase(token: "spent", successor: "live")
        #expect(try Self.column(path, "PRAGMA user_version") == ["11"])
        #expect(try Self.column(path, "SELECT name FROM pragma_table_info('refresh_tokens') WHERE name = 'replaced_by'").isEmpty)

        _ = try OAuthStorage(path: path)

        #expect(try Self.column(path, "PRAGMA user_version") == ["12"])
        #expect(try Self.column(path, "SELECT name FROM pragma_table_info('refresh_tokens') WHERE name = 'replaced_by'") == ["replaced_by"])
        #expect(try Self.column(path, "SELECT replaced_by FROM refresh_tokens ORDER BY token_hash") == [nil, nil])
    }

    @Test("Reopening a schema-12 database changes nothing and does not fail")
    func reopeningIsIdempotent() async throws {
        let path = try Self.schemaElevenDatabase(token: "spent", successor: "live")
        _ = try OAuthStorage(path: path)
        _ = try OAuthStorage(path: path)
        #expect(try Self.column(path, "PRAGMA user_version") == ["12"])
        #expect(try Self.column(path, "SELECT COUNT(*) FROM pragma_table_info('refresh_tokens') WHERE name = 'replaced_by'") == ["1"])
    }

    @Test("A token spent before schema 12 is never regranted, even inside the window")
    func legacySpentTokenFailsSafe() async throws {
        let path = try Self.schemaElevenDatabase(token: "spent", successor: "live")
        let store = try OAuthStorage(path: path)

        // Spent a moment ago, successor live and unspent: every condition of the window holds
        // but the record of which token replaced which, which schema 11 never kept. Without it
        // the store cannot tell a lost response from a replay, so it must answer as it did.
        let claim = try await store.rotateRefreshToken(
            token: "spent", clientId: "app", defaultGrantId: "unused", successor: "next",
            gracePeriod: 30, now: Date())
        #expect(claim == .replayed(grantId: "g1"))
        // And nothing was written for it: the live successor is still the only live token.
        #expect(try await store.getRefreshTokenInfo(token: "live")?.grantId == "g1")
        #expect(try await store.getRefreshTokenInfo(token: "next") == nil)
    }

    @Test("A database already at schema 12 is read unharmed by a build that expects 11")
    func rollbackIsABinarySwap() async throws {
        let path = try Self.schemaElevenDatabase(token: "spent", successor: "live")
        _ = try OAuthStorage(path: path)
        // The older build asks for 11 and finds 12: it must open, and see its rows.
        let older = try OAuthStorage(path: path, schemaVersion: 11)
        #expect(try await older.getRefreshTokenInfo(token: "live")?.grantId == "g1")
        #expect(try Self.column(path, "PRAGMA user_version") == ["12"])
    }
}
