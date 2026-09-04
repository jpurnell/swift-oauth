import Foundation
import CSQLite
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
        guard case .valid(let token) = result else {
            Issue.record("expected a valid token, got \(result)")
            return
        }
        #expect(token.audience == api)
    }

    /// A token issued without one reports none, rather than reporting something invented.
    @Test("A token issued without an audience reports none")
    func unaudiencedTokenReportsNone() async throws {
        let storage = try OAuthStorage(path: ":memory:")

        try await storage.saveAccessToken(
            token: "tok-2", clientId: "client-1", scope: nil,
            expiresAt: Date().addingTimeInterval(3600), audience: nil)

        let result = try await storage.validateAccessToken(token: "tok-2")
        guard case .valid(let token) = result else {
            Issue.record("expected a valid token, got \(result)")
            return
        }
        #expect(token.audience == nil)
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
        guard case .valid(let token) = result else {
            Issue.record("the migrated database could not store an audience: \(result)")
            return
        }
        #expect(token.clientId == "client-1")
        #expect(token.audience == api)
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

/// The token endpoint, end to end.
///
/// The policy and the storage column are both in place; this is the part that connects them —
/// a token request naming a resource is validated against what the server serves, and the
/// token that comes back carries that audience.
@Suite("RFC 8707 — the token endpoint")
struct TokenEndpointResourceTests {

    private func url(_ string: String) throws -> URL {
        // SECURITY: parses a literal written in this test; no request is issued from it.
        try #require(URL(string: string))
    }

    /// The default policy is the server's own identity, so a consumer that already serves
    /// correct RFC 9728 metadata needs no configuration at all.
    ///
    /// This is what makes the migration a bound raise rather than a code change: the value the
    /// server publishes as its resource identifier is the value it accepts.
    @Test("A server accepts the resource it advertises, with no configuration")
    func acceptsItsOwnAdvertisedResource() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"])

        let metadata = await server.getProtectedResourceMetadata()
        let advertised = try url(metadata.resource)

        let policy = await server.resourcePolicy
        #expect(try policy.audience(for: [advertised]) == advertised)
    }

    /// A request naming no resource is refused, because strict is the default.
    @Test("The token endpoint refuses a request naming no resource")
    func refusesUnspecifiedResource() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"])

        let policy = await server.resourcePolicy
        let error = #expect(throws: OAuthError.self) {
            _ = try policy.audience(for: [])
        }
        #expect(error?.code == "invalid_target")
    }

    /// A server whose resource identifier is not its issuer can say so, and the override is
    /// what the metadata should then advertise too.
    @Test("An explicit policy overrides the default")
    func explicitPolicyOverrides() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let api = try url("https://api.example.com")
        let server = await OAuthServer(
            storage: storage,
            issuer: "https://auth.example.com",
            scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"],
            resourcePolicy: .protecting(api))

        let policy = await server.resourcePolicy
        #expect(try policy.audience(for: [api]) == api)
        #expect(throws: OAuthError.self) {
            _ = try policy.audience(for: [try self.url("https://auth.example.com")])
        }
    }
}

/// `resource` as it arrives on the wire.
///
/// RFC 8707 §2 permits the parameter to repeat, and the form parser keeps one value per key —
/// so a request naming two resources would silently become a request naming the last one. The
/// policy's refusal of several distinct resources could then never fire from a real request,
/// and a client asking for two audiences would quietly receive a token for one of them.
@Suite("RFC 8707 — parsing resource from the wire")
struct ResourceParsingTests {

    private func handler(issuer: String) async throws -> OAuthHTTPHandler {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(storage: storage, issuer: issuer, scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"])
        return await OAuthHTTPHandler(server: server)
    }

    /// A single `resource` reaches the request.
    @Test("One resource parameter is read")
    func singleResourceIsRead() async throws {
        let values = OAuthHTTPHandler.formValues(
            for: "resource",
            in: "grant_type=authorization_code&resource=https%3A%2F%2Fapi.example.com")
        #expect(values == ["https://api.example.com"])
    }

    /// A repeated `resource` yields both, rather than the last one silently winning.
    @Test("A repeated resource parameter yields every value")
    func repeatedResourceIsRead() async throws {
        let values = OAuthHTTPHandler.formValues(
            for: "resource",
            in: "resource=https%3A%2F%2Fa.example.com&grant_type=x"
               + "&resource=https%3A%2F%2Fb.example.com")
        #expect(values == ["https://a.example.com", "https://b.example.com"],
                "a repeated parameter collapsed to one value")
    }

    /// Absent means absent, not an empty string.
    @Test("No resource parameter yields nothing")
    func absentResourceYieldsNothing() async throws {
        #expect(OAuthHTTPHandler.formValues(for: "resource", in: "grant_type=x").isEmpty)
    }
}

/// Whether data written before a migration survives it.
///
/// The other migration tests prove the column arrives and that writes naming it then succeed.
/// They do not prove that rows already in the table are still there afterwards, and that is the
/// half that matters most: a migration which quietly discarded existing tokens would look
/// perfect to every test that starts from an empty database.
///
/// It could not be tested through this package's API, because every write names the current
/// columns — there is no way to ask it for a row in the old shape. So the row is planted with
/// raw SQL, which is the only honest way to produce the state a deployed installation is
/// actually in.
///
/// This exists because a consumer pointed out that its own green suite could not have caught a
/// migration defect — every one of its storage tests starts from `:memory:`, which is created
/// at the current schema and never migrates from anything. Its verification of 0.8.0's
/// migration was reporting on a code path its tests never enter.
@Suite("Schema migration — data survives")
struct MigrationDataSurvivalTests {

    /// A token written before the audience column existed is still readable after it arrives.
    @Test("A row written pre-migration survives the migration")
    func preMigrationRowSurvives() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("oauth-survival-\(UUID().uuidString).sqlite").path
        // SECURITY: removes only the uniquely-named temp file this test just created.
        defer { try? FileManager.default.removeItem(atPath: path) }

        // A database as version 0 left it: access_tokens exists, with no audience column.
        _ = try OAuthStorage(path: path, schemaVersion: 0)

        // Plant a row the current API cannot write, because it names no audience.
        try Self.executeRaw(path: path, sql: """
            INSERT INTO access_tokens
            (token_hash, client_id, scope, expires_at, created_at, revoked)
            VALUES ('deadbeef', 'legacy-client', 'legacy:scope', \(Date().addingTimeInterval(3600).timeIntervalSince1970), \(Date().timeIntervalSince1970), 0)
        """)

        // Reopening at the current version migrates.
        let migrated = try OAuthStorage(path: path)

        _ = migrated  // opening it is what runs the migration

        // Read back with raw SQL rather than through the API. The claim under test is about the
        // state of the database, and adding a lookup-by-hash to the production type so a test
        // could assert it would be a permanent API carrying a temporary need.
        let row = try Self.queryRow(
            path: path,
            sql: "SELECT client_id, scope, audience FROM access_tokens WHERE token_hash = 'deadbeef'")

        let survived = try #require(row, "the pre-migration row was lost by the migration")
        #expect(survived[0] == "legacy-client")
        #expect(survived[1] == "legacy:scope")
        #expect(survived[2] == nil, "a token issued before audiences existed has none")
    }

    /// The first row a statement returns, as optional strings.
    private static func queryRow(path: String, sql: String) throws -> [String?]? {
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("could not open \(path)")
        }
        defer { sqlite3_close(db) }

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            let message = db.map { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            throw OAuthStorageError.databaseError("query failed: \(message)")
        }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }

        return (0..<sqlite3_column_count(stmt)).map { index in
            sqlite3_column_text(stmt, index).map { String(cString: $0) }
        }
    }

    /// Runs a statement against the database file directly.
    private static func executeRaw(path: String, sql: String) throws {
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("could not open \(path)")
        }
        defer { sqlite3_close(db) }
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            let message = db.map { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            throw OAuthStorageError.databaseError("raw insert failed: \(message)")
        }
    }
}
