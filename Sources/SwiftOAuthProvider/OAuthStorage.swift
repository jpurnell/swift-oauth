import Foundation
import SwiftOAuthCore
import CSQLite
import Crypto

/// Thread-safe OAuth 2.0 storage using SQLite
///
/// Provides persistent storage for OAuth clients, authorization codes,
/// and tokens. Uses SQLite for storage and an actor for thread safety.
///
/// ## Overview
///
/// `OAuthStorage` handles all persistent data for the OAuth server:
/// - Client registrations
/// - Authorization codes (short-lived, single-use)
/// - Access tokens (hashed for security)
/// - Refresh tokens (hashed for security)
///
/// ## Security
///
/// Tokens are never stored in plain text. Only SHA-256 hashes are persisted,
/// so even if the database is compromised, tokens cannot be extracted.
///
/// ## Example
///
/// ```swift
/// func persist(client: RegisteredClient, token: String) async throws {
///     let storage = try OAuthStorage(path: "~/.businessmath-mcp/oauth.db")
///
///     // Store a client
///     try await storage.saveClient(client)
///
///     // Validate a token
///     let result = try await storage.validateAccessToken(token: token)
///     if result.isValid {
///         // Token is valid
///     }
/// }
/// ```
public actor OAuthStorage {

    // MARK: - Properties

    // Justification: SQLite with serialized threading mode is thread-safe; all access is through actor-isolated methods
    private nonisolated(unsafe) let db: OpaquePointer
    private let path: String

    // MARK: - Initialization

    /// Creates a new OAuth storage instance
    ///
    /// - Parameters:
    ///   - path: Path to the SQLite database file.
    ///     Use ":memory:" for an in-memory database (useful for testing).
    ///   - schemaVersion: The schema version to bring the database up to. Defaults to
    ///     ``currentSchemaVersion``. A lower value exists so a test can produce a database as
    ///     an earlier release left it, which is the only way to exercise a migration.
    /// - Throws: `OAuthStorageError` if database cannot be opened
    public init(path: String, schemaVersion: Int = OAuthStorage.currentSchemaVersion) throws {
        self.path = path

        // Create parent directory if needed
        if path != ":memory:" {
            let directoryURL = URL(fileURLWithPath: (path as NSString).deletingLastPathComponent).standardized
            if !directoryURL.path.isEmpty {
                try FileManager.default.createDirectory(
                    at: directoryURL,
                    withIntermediateDirectories: true
                )
            }
        }

        // Open database
        var dbHandle: OpaquePointer?
        if sqlite3_open(path, &dbHandle) != SQLITE_OK {
            let error = dbHandle.map { String(cString: sqlite3_errmsg($0)) } ?? "Unknown error"
            if let db = dbHandle {
                sqlite3_close(db)
            }
            throw OAuthStorageError.databaseError("Failed to open database: \(error)")
        }

        guard let validDb = dbHandle else {
            throw OAuthStorageError.databaseError("Database handle is nil")
        }

        self.db = validDb

        // Enable foreign keys and create tables
        try Self.initializeDatabase(db: validDb, targetVersion: schemaVersion)
    }

    deinit {
        sqlite3_close(db)
    }

    /// The schema this build expects.
    ///
    /// Raised whenever the shape of a table changes. Version 1 added `access_tokens.audience`
    /// for RFC 8707; version 2 added `device_codes` for RFC 8628; version 3 added
    /// `pushed_requests` for RFC 9126; version 4 added `access_tokens.key_thumbprint` and
    /// `dpop_proofs` for RFC 9449; version 5 added `access_tokens.certificate_thumbprint`
    /// for RFC 8705; version 6 added `authorization_codes.audience`, closing the RFC 8707
    /// authorization-endpoint gap 0.8.0 left open; version 7 replaced every plaintext
    /// `clients.client_secret` with its SHA-256 and added `clients.scope_ceiling`; version 8
    /// added `clients.application_type`, which until then was dropped on save; version 9 added
    /// `subject` to `access_tokens`, `refresh_tokens` and `authorization_codes`, so a token can
    /// say whose it is (RFC 7662 `sub`).
    public static let currentSchemaVersion = 9

    /// Static helper to initialize database schema (runs before actor isolation)
    ///
    /// - Parameters:
    ///   - db: The open database.
    ///   - targetVersion: The schema version to bring the database up to. Defaults to
    ///     ``currentSchemaVersion``; a lower value exists so a test can produce a database as
    ///     an earlier release left it, which is the only way to exercise a migration.
    private static func initializeDatabase(db: OpaquePointer, targetVersion: Int) throws {
        try executeStatic(db: db, sql: "PRAGMA foreign_keys = ON")

        // Clients table
        try executeStatic(db: db, sql: """
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                client_secret TEXT,
                client_name TEXT NOT NULL,
                redirect_uris TEXT NOT NULL,
                grant_types TEXT NOT NULL,
                token_endpoint_auth_method TEXT NOT NULL,
                registration_date REAL NOT NULL
            )
        """)

        // Authorization codes table
        try executeStatic(db: db, sql: """
            CREATE TABLE IF NOT EXISTS authorization_codes (
                code TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scope TEXT,
                code_challenge TEXT,
                code_challenge_method TEXT,
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL,
                consumed INTEGER DEFAULT 0
            )
        """)

        // Access tokens table (stores hash, not raw token)
        try executeStatic(db: db, sql: """
            CREATE TABLE IF NOT EXISTS access_tokens (
                token_hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scope TEXT,
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL,
                revoked INTEGER DEFAULT 0
            )
        """)

        // Refresh tokens table (stores hash, not raw token)
        try executeStatic(db: db, sql: """
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scope TEXT,
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL,
                revoked INTEGER DEFAULT 0
            )
        """)

        // CSRF tokens table
        try executeStatic(db: db, sql: """
            CREATE TABLE IF NOT EXISTS csrf_tokens (
                token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL,
                consumed INTEGER DEFAULT 0
            )
        """)

        // Indexes
        try executeStatic(db: db, sql: "CREATE INDEX IF NOT EXISTS idx_access_tokens_expires ON access_tokens(expires_at)")
        try executeStatic(db: db, sql: "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at)")
        try executeStatic(db: db, sql: "CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON authorization_codes(expires_at)")
        try executeStatic(db: db, sql: "CREATE INDEX IF NOT EXISTS idx_access_tokens_client ON access_tokens(client_id)")
        try executeStatic(db: db, sql: "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON refresh_tokens(client_id)")
        try executeStatic(db: db, sql: "CREATE INDEX IF NOT EXISTS idx_csrf_tokens_expires ON csrf_tokens(expires_at)")

        try migrate(db: db, to: targetVersion)
    }

    /// Brings an existing database up to `targetVersion`.
    ///
    /// The tables above are created with `CREATE TABLE IF NOT EXISTS`, which is why this is
    /// needed and why its absence would have been hard to notice: on a fresh database the
    /// `CREATE` includes every column and everything works, while on a database that already
    /// exists the `CREATE` is skipped entirely and a newly added column never appears. The
    /// failure would then be a query naming a column that is not there — at runtime, on
    /// deployed installations only, and never in a test that starts from `:memory:`.
    ///
    /// `PRAGMA user_version` is SQLite's own slot for this and costs nothing to read.
    private static func migrate(db: OpaquePointer, to targetVersion: Int) throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to read the schema version.")
        }
        var version = 0
        if sqlite3_step(stmt) == SQLITE_ROW {
            version = Int(sqlite3_column_int(stmt, 0))
        }
        sqlite3_finalize(stmt)

        // Version 1: RFC 8707 — the audience a token was issued for.
        //
        // Added rather than recreated, so existing tokens survive. A token issued before
        // audiences existed has none, which is the honest answer: it was never bound to one.
        //
        // The `CREATE TABLE` above deliberately does NOT include this column. If it did, a
        // fresh database would get it from the create and never take this path, so the
        // migration would only ever run on upgrades — the case hardest to test and easiest to
        // ship broken. Leaving it out means every database, new or old, arrives here.
        if version < 1 && targetVersion >= 1 {
            if try !columnExists(db: db, table: "access_tokens", column: "audience") {
                try executeStatic(db: db, sql: "ALTER TABLE access_tokens ADD COLUMN audience TEXT")
            }
        }

        // Version 2: RFC 8628 — the device grant's codes.
        //
        // A whole table rather than a column, and created here rather than alongside the
        // others for the same reason: a database that already exists skips every
        // `CREATE TABLE IF NOT EXISTS` in the schema block, so a table added there would never
        // appear on an upgrade. `IF NOT EXISTS` still, so running it twice is safe.
        if version < 2 && targetVersion >= 2 {
            try executeStatic(db: db, sql: """
                CREATE TABLE IF NOT EXISTS device_codes (
                    device_code_hash TEXT PRIMARY KEY,
                    user_code TEXT NOT NULL UNIQUE,
                    client_id TEXT NOT NULL,
                    scope TEXT,
                    subject TEXT,
                    approved INTEGER DEFAULT 0,
                    redeemed INTEGER DEFAULT 0,
                    expires_at REAL NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            try executeStatic(
                db: db,
                sql: "CREATE INDEX IF NOT EXISTS idx_device_codes_expires ON device_codes(expires_at)")
        }

        // Version 3: RFC 9126 — pushed authorization requests.
        if version < 3 && targetVersion >= 3 {
            try executeStatic(db: db, sql: """
                CREATE TABLE IF NOT EXISTS pushed_requests (
                    request_uri_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    scope TEXT,
                    state TEXT,
                    code_challenge TEXT,
                    code_challenge_method TEXT,
                    consumed INTEGER DEFAULT 0,
                    expires_at REAL NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            try executeStatic(
                db: db,
                sql: "CREATE INDEX IF NOT EXISTS idx_pushed_requests_expires ON pushed_requests(expires_at)")
        }

        // Version 4: RFC 9449 — the key a token is bound to, and the proofs already seen.
        if version < 4 && targetVersion >= 4 {
            if try !columnExists(db: db, table: "access_tokens", column: "key_thumbprint") {
                try executeStatic(
                    db: db, sql: "ALTER TABLE access_tokens ADD COLUMN key_thumbprint TEXT")
            }
            // One row per proof, kept only until the proof could no longer be fresh. Keeping
            // them forever would grow without bound; forgetting too early re-opens the replay
            // window. The expiry is what makes the table finite.
            try executeStatic(db: db, sql: """
                CREATE TABLE IF NOT EXISTS dpop_proofs (
                    jti TEXT PRIMARY KEY,
                    expires_at REAL NOT NULL
                )
            """)
            try executeStatic(
                db: db,
                sql: "CREATE INDEX IF NOT EXISTS idx_dpop_proofs_expires ON dpop_proofs(expires_at)")
        }

        // Version 5: RFC 8705 — the certificate a token is bound to.
        //
        // A second column rather than a reuse of `key_thumbprint`: the two are different
        // identifiers of different things — a JWK thumbprint of a key the client generated,
        // against a SHA-256 of a certificate someone issued — and a single column would make
        // "which kind of binding is this" a question the schema could not answer.
        if version < 5 && targetVersion >= 5 {
            if try !columnExists(db: db, table: "access_tokens", column: "certificate_thumbprint") {
                try executeStatic(
                    db: db,
                    sql: "ALTER TABLE access_tokens ADD COLUMN certificate_thumbprint TEXT")
            }
        }

        // Version 6: RFC 8707 — the audience an authorization code was granted for.
        //
        // Without it the audience is decided at redemption, so a client can name one resource
        // at `/authorize` — the one the user saw and consented to — and a different one at
        // `/token`, with nothing on the code to contradict it.
        if version < 6 && targetVersion >= 6 {
            if try !columnExists(db: db, table: "authorization_codes", column: "audience") {
                try executeStatic(
                    db: db, sql: "ALTER TABLE authorization_codes ADD COLUMN audience TEXT")
            }
        }

        // Version 7: client secrets at rest are hashes, as tokens already were.
        //
        // Every existing secret is hashed in place, so each client keeps working with the
        // secret it holds and none stays readable on disk. One transaction, with the version
        // bump inside it: a crash part-way through must leave either every secret plaintext
        // at version 6 or every secret hashed at version 7. Anything between would be hashed
        // a second time on the next open, locking those clients out for good.
        //
        // The same version adds `clients.scope_ceiling`: the most a client may be granted,
        // set by an operator. Existing clients have none, which is what they had.
        if version < 7 && targetVersion >= 7 {
            try executeStatic(db: db, sql: "BEGIN IMMEDIATE")
            do {
                if try !columnExists(db: db, table: "clients", column: "scope_ceiling") {
                    try executeStatic(
                        db: db, sql: "ALTER TABLE clients ADD COLUMN scope_ceiling TEXT")
                }
                try hashPlaintextClientSecrets(db: db)
                try executeStatic(db: db, sql: "PRAGMA user_version = 7")
                try executeStatic(db: db, sql: "COMMIT")
            } catch let migrationError {
                // Reported rather than swallowed: a failed rollback leaves the transaction
                // open on this connection, and the caller needs to know that too.
                do {
                    try executeStatic(db: db, sql: "ROLLBACK")
                } catch {
                    throw OAuthStorageError.databaseError(
                        "Hashing client secrets failed (\(migrationError)) and the rollback "
                        + "failed too (\(error)).")
                }
                throw migrationError
            }
        }

        // Version 8: `clients.application_type` (RFC 7591 / OpenID registration). There was no
        // column for it, so every client read back was `.web`, a native one included. Existing
        // rows stay NULL, which reads as `.web` — what every read of them returned before.
        if version < 8 && targetVersion >= 8 {
            if try !columnExists(db: db, table: "clients", column: "application_type") {
                try executeStatic(
                    db: db, sql: "ALTER TABLE clients ADD COLUMN application_type TEXT")
            }
        }

        // Version 9: who a token, refresh token or authorization code was issued for — the
        // resource owner, RFC 7662's `sub`. Existing rows stay NULL: nobody was recorded for
        // them, and inventing someone would be worse than naming nobody.
        if version < 9 && targetVersion >= 9 {
            for table in ["access_tokens", "refresh_tokens", "authorization_codes"] {
                if try !columnExists(db: db, table: table, column: "subject") {
                    try executeStatic(db: db, sql: "ALTER TABLE \(table) ADD COLUMN subject TEXT")
                }
            }
        }

        if version < targetVersion {
            try executeStatic(db: db, sql: "PRAGMA user_version = \(targetVersion)")
        }
    }

    /// Replaces each `clients.client_secret` with its SHA-256. Run once, by the version 7
    /// migration, inside its transaction.
    private static func hashPlaintextClientSecrets(db: OpaquePointer) throws {
        var select: OpaquePointer?
        defer { sqlite3_finalize(select) }
        guard sqlite3_prepare_v2(
            db, "SELECT client_id, client_secret FROM clients WHERE client_secret IS NOT NULL",
            -1, &select, nil) == SQLITE_OK
        else {
            throw OAuthStorageError.databaseError("Failed to read client secrets.")
        }
        var rows: [(clientId: String, hash: String)] = []
        while sqlite3_step(select) == SQLITE_ROW {
            guard let id = sqlite3_column_text(select, 0),
                  let secret = sqlite3_column_text(select, 1) else { continue }
            rows.append((String(cString: id), sha256Hex(String(cString: secret))))
        }

        var update: OpaquePointer?
        defer { sqlite3_finalize(update) }
        guard sqlite3_prepare_v2(
            db, "UPDATE clients SET client_secret = ? WHERE client_id = ?",
            -1, &update, nil) == SQLITE_OK
        else {
            throw OAuthStorageError.databaseError("Failed to prepare the secret migration.")
        }
        for row in rows {
            sqlite3_reset(update)
            sqlite3_bind_text(update, 1, row.hash, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(update, 2, row.clientId, -1, SQLITE_TRANSIENT)
            guard sqlite3_step(update) == SQLITE_DONE else {
                throw OAuthStorageError.databaseError("Failed to hash a client secret.")
            }
        }
    }

    /// Whether a table already has a column, so a migration can be run twice safely.
    private static func columnExists(db: OpaquePointer, table: String, column: String) throws -> Bool {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, "PRAGMA table_info(\(table))", -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to inspect \(table).")
        }
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let name = sqlite3_column_text(stmt, 1), String(cString: name) == column {
                return true
            }
        }
        return false
    }

    /// Static SQL execution helper for initialization
    private static func executeStatic(db: OpaquePointer, sql: String) throws {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            let error = String(cString: sqlite3_errmsg(db))
            throw OAuthStorageError.databaseError("Failed to prepare: \(error)")
        }

        let result = sqlite3_step(stmt)
        if result != SQLITE_DONE && result != SQLITE_ROW {
            let error = String(cString: sqlite3_errmsg(db))
            throw OAuthStorageError.databaseError("Execution failed: \(error)")
        }
    }

    // MARK: - Schema

    /// Lists all tables in the database (for testing)
    public func listTables() throws -> [String] {
        var tables: [String] = []
        var stmt: OpaquePointer?

        let sql = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"

        if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK {
            while sqlite3_step(stmt) == SQLITE_ROW {
                if let name = sqlite3_column_text(stmt, 0) {
                    tables.append(String(cString: name))
                }
            }
        }
        sqlite3_finalize(stmt)

        return tables
    }

    // MARK: - Client Operations

    /// Saves or updates a client registration
    ///
    /// The secret, when there is one, is stored as its SHA-256 and never returned: a client read
    /// back by ``getClient(clientId:)`` has `clientSecret == nil`. Saving such a client again
    /// keeps the secret already stored, so updating a client's other fields cannot erase its
    /// credential; saving one with a secret replaces it. A client saved with
    /// `token_endpoint_auth_method` `none` keeps no secret at all.
    public func saveClient(_ client: RegisteredClient) throws {
        let redirectUris = try encodeJSON(client.redirectUris)
        let grantTypes = try encodeJSON(client.grantTypes)

        try execute("""
            INSERT INTO clients
            (client_id, client_secret, client_name, redirect_uris, grant_types,
             token_endpoint_auth_method, registration_date, scope_ceiling, application_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(client_id) DO UPDATE SET
                client_secret = CASE
                    WHEN excluded.token_endpoint_auth_method = 'none' THEN NULL
                    ELSE COALESCE(excluded.client_secret, clients.client_secret)
                END,
                client_name = excluded.client_name,
                redirect_uris = excluded.redirect_uris,
                grant_types = excluded.grant_types,
                token_endpoint_auth_method = excluded.token_endpoint_auth_method,
                registration_date = excluded.registration_date,
                scope_ceiling = excluded.scope_ceiling,
                application_type = excluded.application_type
        """, parameters: [
            client.clientId,
            client.clientSecret.map(Self.sha256Hex) as Any,
            client.clientName,
            redirectUris,
            grantTypes,
            client.tokenEndpointAuthMethod,
            client.registrationDate.timeIntervalSince1970,
            client.scopeCeiling.map { $0.sorted().joined(separator: " ") } as Any,
            client.applicationType.rawValue
        ])
    }

    /// Retrieves a client by ID
    public func getClient(clientId: String) throws -> RegisteredClient? {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        let sql = "SELECT * FROM clients WHERE client_id = ?"

        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to prepare statement")
        }

        sqlite3_bind_text(stmt, 1, clientId, -1, SQLITE_TRANSIENT)

        guard sqlite3_step(stmt) == SQLITE_ROW else {
            return nil
        }

        return try parseClient(from: stmt)
    }

    /// Whether `presented` is the secret this client was registered with.
    ///
    /// Compares hashes in constant time. `false` for an unknown client and for a client with
    /// no secret, so a public client can never authenticate as a confidential one.
    public func clientSecretMatches(clientId: String, presented: String) throws -> Bool {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        let sql = "SELECT client_secret FROM clients WHERE client_id = ?"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to prepare statement")
        }
        sqlite3_bind_text(stmt, 1, clientId, -1, SQLITE_TRANSIENT)

        guard sqlite3_step(stmt) == SQLITE_ROW,
              let stored = sqlite3_column_text(stmt, 0) else {
            return false
        }
        return TokenGenerator.timingSafeCompare(Self.sha256Hex(presented), String(cString: stored))
    }

    /// Deletes a client and all associated tokens
    public func deleteClient(clientId: String) throws {
        try execute("DELETE FROM access_tokens WHERE client_id = ?", parameters: [clientId])
        try execute("DELETE FROM refresh_tokens WHERE client_id = ?", parameters: [clientId])
        try execute("DELETE FROM authorization_codes WHERE client_id = ?", parameters: [clientId])
        try execute("DELETE FROM clients WHERE client_id = ?", parameters: [clientId])
    }

    // MARK: - Authorization Code Operations

    /// Saves an authorization code
    public func saveAuthorizationCode(_ code: AuthorizationCode) throws {
        try execute("""
            INSERT OR REPLACE INTO authorization_codes
            (code, client_id, redirect_uri, scope, code_challenge, code_challenge_method,
             expires_at, created_at, consumed, audience, subject)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        """, parameters: [
            code.code,
            code.clientId,
            code.redirectUri,
            code.scope as Any,
            code.codeChallenge as Any,
            code.codeChallengeMethod as Any,
            code.expiresAt.timeIntervalSince1970,
            code.createdAt.timeIntervalSince1970,
            code.audience?.absoluteString as Any,
            code.subject as Any
        ])
    }

    /// Retrieves an authorization code without consuming it
    public func getAuthorizationCode(code: String) throws -> AuthorizationCode? {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        let sql = "SELECT * FROM authorization_codes WHERE code = ? AND consumed = 0"

        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to prepare statement")
        }

        sqlite3_bind_text(stmt, 1, code, -1, SQLITE_TRANSIENT)

        guard sqlite3_step(stmt) == SQLITE_ROW else {
            return nil
        }

        return parseAuthorizationCode(from: stmt)
    }

    /// Retrieves and marks an authorization code as consumed (single-use)
    public func consumeAuthorizationCode(code: String) throws -> AuthorizationCode? {
        guard let authCode = try getAuthorizationCode(code: code) else {
            return nil
        }

        try execute(
            "UPDATE authorization_codes SET consumed = 1 WHERE code = ?",
            parameters: [code]
        )

        return authCode
    }

    // MARK: - CSRF Token Operations

    /// Generates a CSRF token for consent page protection
    ///
    /// - Parameters:
    ///   - clientId: Client requesting authorization
    ///   - redirectUri: Redirect URI from authorization request
    ///   - expiresIn: Token lifetime in seconds (default: 10 minutes)
    /// - Returns: The generated CSRF token
    /// - Throws: `OAuthStorageError` if token cannot be stored
    public func generateCSRFToken(
        clientId: String,
        redirectUri: String,
        expiresIn: TimeInterval = 600 // 10 minutes
    ) throws -> String {
        // Generate cryptographically secure random token
        let token = generateSecureToken(length: 32)
        let now = Date()
        let expiresAt = now.addingTimeInterval(expiresIn)

        try execute("""
            INSERT INTO csrf_tokens (token, client_id, redirect_uri, expires_at, created_at, consumed)
            VALUES (?, ?, ?, ?, ?, 0)
        """, parameters: [
            token,
            clientId,
            redirectUri,
            expiresAt.timeIntervalSince1970,
            now.timeIntervalSince1970
        ])

        return token
    }

    /// Validates and consumes a CSRF token (single-use)
    ///
    /// - Parameters:
    ///   - token: The CSRF token to validate
    ///   - clientId: Expected client ID
    ///   - redirectUri: Expected redirect URI
    /// - Returns: Validation result
    /// - Throws: `OAuthStorageError` on database errors
    public func validateCSRFToken(
        token: String,
        clientId: String,
        redirectUri: String
    ) throws -> CSRFValidationResult {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        let sql = """
            SELECT client_id, redirect_uri, expires_at, consumed
            FROM csrf_tokens
            WHERE token = ?
        """

        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to prepare statement")
        }

        sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT)

        guard sqlite3_step(stmt) == SQLITE_ROW else {
            return CSRFValidationResult(isValid: false, error: "Token not found")
        }

        let storedClientId = String(cString: sqlite3_column_text(stmt, 0))
        let storedRedirectUri = String(cString: sqlite3_column_text(stmt, 1))
        let expiresAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 2))
        let consumed = sqlite3_column_int(stmt, 3) != 0

        // Check if already consumed
        if consumed {
            return CSRFValidationResult(isValid: false, error: "Token already used")
        }

        // Check expiration
        if Date() >= expiresAt {
            return CSRFValidationResult(isValid: false, error: "Token expired")
        }

        // Check client_id matches
        if storedClientId != clientId {
            return CSRFValidationResult(isValid: false, error: "Client ID mismatch")
        }

        // Check redirect_uri matches
        if storedRedirectUri != redirectUri {
            return CSRFValidationResult(isValid: false, error: "Redirect URI mismatch")
        }

        // Mark token as consumed (single-use)
        try execute(
            "UPDATE csrf_tokens SET consumed = 1 WHERE token = ?",
            parameters: [token]
        )

        return CSRFValidationResult(isValid: true)
    }

    /// Removes expired CSRF tokens
    ///
    /// - Returns: Number of tokens removed
    @discardableResult
    public func cleanupExpiredCSRFTokens() throws -> Int {
        let now = Date().timeIntervalSince1970

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        // Count before deletion
        let countSql = "SELECT COUNT(*) FROM csrf_tokens WHERE expires_at < ?"
        guard sqlite3_prepare_v2(db, countSql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to prepare statement")
        }
        sqlite3_bind_double(stmt, 1, now)

        var count = 0
        if sqlite3_step(stmt) == SQLITE_ROW {
            count = Int(sqlite3_column_int(stmt, 0))
        }

        // Delete expired tokens
        try execute("DELETE FROM csrf_tokens WHERE expires_at < ?", parameters: [now])

        return count
    }

    // MARK: - Access Token Operations

    /// Saves an access token (stores hash only)
    public func saveAccessToken(
        token: String,
        clientId: String,
        scope: String?,
        expiresAt: Date,
        audience: URL? = nil,
        keyThumbprint: String? = nil,
        certificateThumbprint: String? = nil,
        subject: String? = nil
    ) throws {
        let tokenHash = hashToken(token)

        try execute("""
            INSERT OR REPLACE INTO access_tokens
            (token_hash, client_id, scope, expires_at, created_at, revoked, audience,
             key_thumbprint, certificate_thumbprint, subject)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
        """, parameters: [
            tokenHash,
            clientId,
            scope as Any,
            expiresAt.timeIntervalSince1970,
            Date().timeIntervalSince1970,
            audience?.absoluteString as Any,
            keyThumbprint as Any,
            certificateThumbprint as Any,
            subject as Any
        ])
    }

    /// Validates an access token
    public func validateAccessToken(token: String) throws -> TokenValidationResult {
        let tokenHash = hashToken(token)

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        let sql = """
            SELECT client_id, scope, expires_at, revoked, audience, key_thumbprint,
                   certificate_thumbprint, subject
            FROM access_tokens
            WHERE token_hash = ?
        """

        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to prepare statement")
        }

        sqlite3_bind_text(stmt, 1, tokenHash, -1, SQLITE_TRANSIENT)

        guard sqlite3_step(stmt) == SQLITE_ROW else {
            return .invalid(reason: "Token not found")
        }

        let clientId = String(cString: sqlite3_column_text(stmt, 0))
        let scope = sqlite3_column_text(stmt, 1).map { String(cString: $0) }
        let expiresAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 2))
        let revoked = sqlite3_column_int(stmt, 3) != 0
        // A token stored before audiences existed has NULL here, which reads as "bound to
        // nothing" — the honest answer, since it never was.
        let audience = sqlite3_column_text(stmt, 4)
            .map { String(cString: $0) }
            .flatMap { URL(string: $0) }

        if revoked {
            return .invalid(reason: "Token revoked")
        }

        if Date() >= expiresAt {
            return .invalid(reason: "Token expired")
        }

        let thumbprint = sqlite3_column_text(stmt, 5).map { String(cString: $0) }
        let certificate = sqlite3_column_text(stmt, 6).map { String(cString: $0) }
        let subject = sqlite3_column_text(stmt, 7).map { String(cString: $0) }
        return .valid(TokenValidationResult.ValidatedToken(
            clientId: clientId, scope: scope, audience: audience,
            keyThumbprint: thumbprint, certificateThumbprint: certificate, subject: subject))
    }

    /// Everything RFC 7662 reports about an access token.
    ///
    /// Separate from ``validateAccessToken(token:)`` rather than an extension of it. That
    /// method answers "may this request proceed" and returns an enum whose shape is already a
    /// published contract — widening it again for `exp` and `iat` would be a second source
    /// break in consecutive releases for callers who do not introspect at all.
    ///
    /// Returns `IntrospectionResult.inactive` for a token that is expired, revoked or
    /// unknown, and the three are indistinguishable to the caller on purpose: RFC 7662 §2.2
    /// requires that an inactive response say nothing else, because a caller holding a dead
    /// token has proven nothing and a response carrying claims is an oracle.
    ///
    /// - Parameter token: The token to describe.
    /// - Returns: The introspection response to send.
    /// - Throws: `OAuthStorageError` if the database cannot be read.
    public func introspectAccessToken(token: String) throws -> IntrospectionResult {
        let tokenHash = hashToken(token)

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        let sql = """
            SELECT client_id, scope, expires_at, revoked, audience, created_at, subject
            FROM access_tokens
            WHERE token_hash = ?
        """

        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to prepare statement")
        }
        sqlite3_bind_text(stmt, 1, tokenHash, -1, SQLITE_TRANSIENT)

        guard sqlite3_step(stmt) == SQLITE_ROW else {
            return .inactive
        }

        let expiresAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 2))
        let revoked = sqlite3_column_int(stmt, 3) != 0
        guard !revoked, Date() < expiresAt else {
            return .inactive
        }

        let clientId = String(cString: sqlite3_column_text(stmt, 0))
        let scope = sqlite3_column_text(stmt, 1).map { String(cString: $0) }
        let audience = sqlite3_column_text(stmt, 4).map { String(cString: $0) }
        let issuedAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 5))
        let subject = sqlite3_column_text(stmt, 6).map { String(cString: $0) }

        // No `iss` here: storage does not know which issuer it serves. `OAuthServer` adds it.
        return IntrospectionResult(
            active: true,
            scope: scope,
            clientId: clientId,
            subject: subject,
            audience: audience.map { [$0] },
            expiry: expiresAt,
            issuedAt: issuedAt)
    }

    /// Stores a device code and the short code the user will type — RFC 8628.
    ///
    /// The device code is hashed, like every other credential here: it is a bearer credential
    /// until redeemed, so a database read must not yield something redeemable.
    ///
    /// The user code is stored in the clear, deliberately. It has to be looked up by exactly
    /// what a person typed, it is short-lived, and it is useless without the device code —
    /// approving one authorises a session the approver cannot themselves collect.
    public func saveDeviceCode(
        deviceCode: String,
        userCode: String,
        clientId: String,
        scope: String?,
        expiresAt: Date
    ) throws {
        try execute("""
            INSERT INTO device_codes
            (device_code_hash, user_code, client_id, scope, subject, approved, redeemed,
             expires_at, created_at)
            VALUES (?, ?, ?, ?, NULL, 0, 0, ?, ?)
        """, parameters: [
            hashToken(deviceCode),
            userCode,
            clientId,
            scope as Any,
            expiresAt.timeIntervalSince1970,
            Date().timeIntervalSince1970
        ])
    }

    /// Marks the user code approved, recording who approved it.
    ///
    /// - Returns: `false` if no unexpired, unapproved code matches — which is what an unknown
    ///   or stale code looks like, and is not distinguished from it on purpose. The approval
    ///   page would otherwise be an oracle for guessing codes that are short by design.
    public func approveDeviceCode(userCode: String, subject: String) throws -> Bool {
        try execute("""
            UPDATE device_codes SET approved = 1, subject = ?
            WHERE user_code = ? AND redeemed = 0 AND expires_at > ?
        """, parameters: [subject, userCode, Date().timeIntervalSince1970])
        return sqlite3_changes(db) > 0
    }

    /// What a device code currently is, for a client redeeming it.
    public func deviceCodeState(
        deviceCode: String, clientId: String
    ) throws -> DeviceCodeState {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        let sql = """
            SELECT client_id, scope, subject, approved, redeemed, expires_at
            FROM device_codes WHERE device_code_hash = ?
        """
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to prepare statement")
        }
        sqlite3_bind_text(stmt, 1, hashToken(deviceCode), -1, SQLITE_TRANSIENT)

        guard sqlite3_step(stmt) == SQLITE_ROW else { return .unknown }

        let owner = String(cString: sqlite3_column_text(stmt, 0))
        let scope = sqlite3_column_text(stmt, 1).map { String(cString: $0) }
        let subject = sqlite3_column_text(stmt, 2).map { String(cString: $0) }
        let approved = sqlite3_column_int(stmt, 3) != 0
        let redeemed = sqlite3_column_int(stmt, 4) != 0
        let expiresAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 5))

        // The client check comes before everything else. A device code seen in transit is
        // otherwise redeemable by anyone who can name a client id, and client ids are public
        // by design.
        guard owner == clientId else { return .unknown }
        guard !redeemed else { return .alreadyRedeemed }
        guard Date() < expiresAt else { return .expired }
        return approved ? .approved(scope: scope, subject: subject) : .pending
    }

    /// Marks a device code redeemed, so it cannot be used again.
    public func markDeviceCodeRedeemed(deviceCode: String) throws {
        try execute(
            "UPDATE device_codes SET redeemed = 1 WHERE device_code_hash = ?",
            parameters: [hashToken(deviceCode)])
    }

    /// Stores a pushed authorization request — RFC 9126 §2.
    ///
    /// The reference is hashed, like every other credential here. It travels through a
    /// browser, so a database read must not yield something usable.
    public func savePushedRequest(
        requestURI: String,
        clientId: String,
        redirectUri: String,
        scope: String?,
        state: String?,
        codeChallenge: String?,
        codeChallengeMethod: String?,
        expiresAt: Date
    ) throws {
        try execute("""
            INSERT INTO pushed_requests
            (request_uri_hash, client_id, redirect_uri, scope, state, code_challenge,
             code_challenge_method, consumed, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        """, parameters: [
            hashToken(requestURI), clientId, redirectUri, scope as Any, state as Any,
            codeChallenge as Any, codeChallengeMethod as Any,
            expiresAt.timeIntervalSince1970, Date().timeIntervalSince1970
        ])
    }

    /// Consumes a pushed request, returning what was pushed.
    ///
    /// Single-use: the row is marked spent in the same step that reads it, so two concurrent
    /// authorization requests cannot both succeed on one reference.
    ///
    /// - Returns: `nil` when no live, unspent request matches this client. Unknown, expired,
    ///   spent and belonging-to-someone-else are one answer, because distinguishing them lets a
    ///   caller probe which references exist.
    public func consumePushedRequest(
        requestURI: String, clientId: String
    ) throws -> PushedAuthorizationRequest? {
        let hash = hashToken(requestURI)

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        let sql = """
            SELECT redirect_uri, scope, state, code_challenge, code_challenge_method
            FROM pushed_requests
            WHERE request_uri_hash = ? AND client_id = ? AND consumed = 0 AND expires_at > ?
        """
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to prepare statement")
        }
        sqlite3_bind_text(stmt, 1, hash, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, clientId, -1, SQLITE_TRANSIENT)
        sqlite3_bind_double(stmt, 3, Date().timeIntervalSince1970)

        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }

        let request = PushedAuthorizationRequest(
            redirectUri: String(cString: sqlite3_column_text(stmt, 0)),
            scope: sqlite3_column_text(stmt, 1).map { String(cString: $0) },
            state: sqlite3_column_text(stmt, 2).map { String(cString: $0) },
            codeChallenge: sqlite3_column_text(stmt, 3).map { String(cString: $0) },
            codeChallengeMethod: sqlite3_column_text(stmt, 4).map { String(cString: $0) })

        try execute(
            "UPDATE pushed_requests SET consumed = 1 WHERE request_uri_hash = ?",
            parameters: [hash])

        return request
    }

    /// Records a proof identifier, refusing one already seen — RFC 9449 §11.1.
    ///
    /// This is the whole of replay protection, and it is the half the proof type cannot do:
    /// verifying a signature says the holder of a key made this proof, and says nothing about
    /// whether they made it a moment ago or an hour ago and it has been in a log since.
    ///
    /// The insert is what decides, not a preceding read. `INSERT` on a primary key either
    /// succeeds or violates the constraint, atomically — a check-then-insert would let two
    /// concurrent requests both find the identifier absent and both proceed, which is exactly
    /// the replay this exists to stop.
    ///
    /// - Parameters:
    ///   - identifier: The proof's `jti`.
    ///   - expiresAt: When the record may be swept — no earlier than the proof stops being
    ///     fresh, or the window re-opens.
    /// - Returns: `true` if this identifier had not been seen.
    public func claimProofIdentifier(_ identifier: String, expiresAt: Date) throws -> Bool {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        let sql = "INSERT OR IGNORE INTO dpop_proofs (jti, expires_at) VALUES (?, ?)"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to prepare statement")
        }
        sqlite3_bind_text(stmt, 1, identifier, -1, SQLITE_TRANSIENT)
        sqlite3_bind_double(stmt, 2, expiresAt.timeIntervalSince1970)
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw OAuthStorageError.databaseError("Failed to record the proof identifier")
        }
        return sqlite3_changes(db) > 0
    }

    /// Removes proof identifiers that can no longer be replayed.
    ///
    /// - Returns: How many were removed.
    public func sweepExpiredProofIdentifiers() throws -> Int {
        try execute(
            "DELETE FROM dpop_proofs WHERE expires_at <= ?",
            parameters: [Date().timeIntervalSince1970])
        return Int(sqlite3_changes(db))
    }

    /// Revokes an access token
    public func revokeAccessToken(token: String) throws {
        let tokenHash = hashToken(token)
        try execute(
            "UPDATE access_tokens SET revoked = 1 WHERE token_hash = ?",
            parameters: [tokenHash]
        )
    }

    /// Revokes all tokens for a client
    public func revokeAllTokensForClient(clientId: String) throws {
        try execute(
            "UPDATE access_tokens SET revoked = 1 WHERE client_id = ?",
            parameters: [clientId]
        )
        try execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE client_id = ?",
            parameters: [clientId]
        )
    }

    /// Checks if the raw token value exists in the database (for testing)
    /// Should always return false since we only store hashes
    public func containsRawToken(_ token: String) throws -> Bool {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        // Check if the raw token exists as a hash (it shouldn't)
        let sql = "SELECT COUNT(*) FROM access_tokens WHERE token_hash = ?"

        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to prepare statement")
        }

        // Bind the raw token, not its hash
        sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT)

        guard sqlite3_step(stmt) == SQLITE_ROW else {
            return false
        }

        return sqlite3_column_int(stmt, 0) > 0
    }

    // MARK: - Refresh Token Operations

    /// Saves a refresh token (stores hash only)
    public func saveRefreshToken(
        token: String,
        clientId: String,
        scope: String?,
        expiresAt: Date,
        subject: String? = nil
    ) throws {
        let tokenHash = hashToken(token)

        try execute("""
            INSERT OR REPLACE INTO refresh_tokens
            (token_hash, client_id, scope, expires_at, created_at, revoked, subject)
            VALUES (?, ?, ?, ?, ?, 0, ?)
        """, parameters: [
            tokenHash,
            clientId,
            scope as Any,
            expiresAt.timeIntervalSince1970,
            Date().timeIntervalSince1970,
            subject as Any
        ])
    }

    /// Gets refresh token info if valid
    public func getRefreshTokenInfo(token: String) throws -> RefreshTokenInfo? {
        let tokenHash = hashToken(token)

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        let sql = """
            SELECT client_id, scope, expires_at, revoked, subject
            FROM refresh_tokens
            WHERE token_hash = ?
        """

        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to prepare statement")
        }

        sqlite3_bind_text(stmt, 1, tokenHash, -1, SQLITE_TRANSIENT)

        guard sqlite3_step(stmt) == SQLITE_ROW else {
            return nil
        }

        let clientId = String(cString: sqlite3_column_text(stmt, 0))
        let scope = sqlite3_column_text(stmt, 1).map { String(cString: $0) }
        let expiresAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 2))
        let revoked = sqlite3_column_int(stmt, 3) != 0

        if revoked || Date() >= expiresAt {
            return nil
        }

        let subject = sqlite3_column_text(stmt, 4).map { String(cString: $0) }
        return RefreshTokenInfo(
            clientId: clientId, scope: scope, expiresAt: expiresAt, subject: subject)
    }

    /// Revokes a refresh token
    public func revokeRefreshToken(token: String) throws {
        let tokenHash = hashToken(token)
        try execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?",
            parameters: [tokenHash]
        )
    }

    // MARK: - Cleanup

    /// Removes expired tokens and codes
    /// - Returns: Number of records removed
    @discardableResult
    public func cleanupExpiredTokens() throws -> Int {
        let now = Date().timeIntervalSince1970
        var removed = 0

        // Count before deletion
        let accessCount = try countExpired(
            table: "access_tokens",
            expiresColumn: "expires_at",
            threshold: now
        )
        let refreshCount = try countExpired(
            table: "refresh_tokens",
            expiresColumn: "expires_at",
            threshold: now
        )
        let codeCount = try countExpired(
            table: "authorization_codes",
            expiresColumn: "expires_at",
            threshold: now
        )

        // Delete expired records
        try execute(
            "DELETE FROM access_tokens WHERE expires_at < ?",
            parameters: [now]
        )
        try execute(
            "DELETE FROM refresh_tokens WHERE expires_at < ?",
            parameters: [now]
        )
        try execute(
            "DELETE FROM authorization_codes WHERE expires_at < ?",
            parameters: [now]
        )

        removed = accessCount + refreshCount + codeCount
        return removed
    }

    private func countExpired(table: String, expiresColumn: String, threshold: Double) throws -> Int {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        let sql = "SELECT COUNT(*) FROM \(table) WHERE \(expiresColumn) < ?"

        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw OAuthStorageError.databaseError("Failed to prepare statement")
        }

        sqlite3_bind_double(stmt, 1, threshold)

        guard sqlite3_step(stmt) == SQLITE_ROW else {
            return 0
        }

        return Int(sqlite3_column_int(stmt, 0))
    }

    // MARK: - Private Helpers

    private func execute(_ sql: String, parameters: [Any] = []) throws {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            let error = String(cString: sqlite3_errmsg(db))
            throw OAuthStorageError.databaseError("Failed to prepare: \(error)")
        }

        for (index, param) in parameters.enumerated() {
            let position = Int32(index + 1)

            switch param {
            case let value as String:
                sqlite3_bind_text(stmt, position, value, -1, SQLITE_TRANSIENT)
            case let value as Int:
                sqlite3_bind_int64(stmt, position, Int64(value))
            case let value as Double:
                sqlite3_bind_double(stmt, position, value)
            case is NSNull:
                sqlite3_bind_null(stmt, position)
            case Optional<Any>.none:
                sqlite3_bind_null(stmt, position)
            default:
                if let optional = param as Any?,
                   case Optional<Any>.none = optional {
                    sqlite3_bind_null(stmt, position)
                } else {
                    sqlite3_bind_text(stmt, position, String(describing: param), -1, SQLITE_TRANSIENT)
                }
            }
        }

        let result = sqlite3_step(stmt)
        if result != SQLITE_DONE && result != SQLITE_ROW {
            let error = String(cString: sqlite3_errmsg(db))
            throw OAuthStorageError.databaseError("Execution failed: \(error)")
        }
    }

    private func hashToken(_ token: String) -> String {
        Self.sha256Hex(token)
    }

    /// The lowercase hex SHA-256 of a credential: how tokens and client secrets are kept.
    ///
    /// A fast hash is the right one here. Every value stored this way is 256 bits of
    /// generator output, so there is no dictionary to slow down, and a password KDF would cost
    /// every token request its latency for nothing.
    private static func sha256Hex(_ value: String) -> String {
        let digest = SHA256.hash(data: Data(value.utf8))
        return digest.map { ($0 < 16 ? "0" : "") + String($0, radix: 16, uppercase: false) }.joined()
    }

    /// Generates a cryptographically secure random token
    ///
    /// Uses Swift Crypto's SymmetricKey for cross-platform random generation
    /// (works on both macOS and Linux)
    private func generateSecureToken(length: Int) -> String {
        // SymmetricKey generates cryptographically secure random bytes
        let key = SymmetricKey(size: .bits256)
        return key.withUnsafeBytes { bytes in
            bytes.prefix(length).map { ($0 < 16 ? "0" : "") + String($0, radix: 16, uppercase: false) }.joined()
        }
    }

    private func encodeJSON<T: Encodable>(_ value: T) throws -> String {
        let data = try JSONEncoder().encode(value)
        return String(data: data, encoding: .utf8) ?? "[]"
    }

    private func decodeJSON<T: Decodable>(_ json: String, as type: T.Type) throws -> T {
        guard let data = json.data(using: .utf8) else {
            throw OAuthStorageError.databaseError("Invalid JSON string")
        }
        return try JSONDecoder().decode(type, from: data)
    }

    private func parseClient(from stmt: OpaquePointer?) throws -> RegisteredClient {
        guard let stmt = stmt else {
            throw OAuthStorageError.databaseError("Invalid statement")
        }

        let clientId = String(cString: sqlite3_column_text(stmt, 0))
        // Column 1 holds a hash of the secret, which is not the secret and is not returned.
        let clientName = String(cString: sqlite3_column_text(stmt, 2))
        let redirectUrisJson = String(cString: sqlite3_column_text(stmt, 3))
        let grantTypesJson = String(cString: sqlite3_column_text(stmt, 4))
        let tokenEndpointAuthMethod = String(cString: sqlite3_column_text(stmt, 5))
        let registrationDate = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 6))
        let scopeCeiling = sqlite3_column_text(stmt, 7).map {
            Set(String(cString: $0).split(separator: " ").map(String.init))
        }
        // NULL is a row from before the column existed, read as `.web` as it always was. Any
        // other value this build does not know is refused rather than guessed at.
        let applicationType: ApplicationType
        if let raw = sqlite3_column_text(stmt, 8).map({ String(cString: $0) }) {
            guard let known = ApplicationType(rawValue: raw) else {
                throw OAuthStorageError.databaseError("Unknown application_type '\(raw)' for client \(clientId)")
            }
            applicationType = known
        } else {
            applicationType = .web
        }

        let redirectUris: [String] = try decodeJSON(redirectUrisJson, as: [String].self)
        let grantTypes: [String] = try decodeJSON(grantTypesJson, as: [String].self)

        return RegisteredClient(
            clientId: clientId,
            clientSecret: nil,
            clientName: clientName,
            redirectUris: redirectUris,
            grantTypes: grantTypes,
            tokenEndpointAuthMethod: tokenEndpointAuthMethod,
            registrationDate: registrationDate,
            applicationType: applicationType,
            scopeCeiling: scopeCeiling
        )
    }

    private func parseAuthorizationCode(from stmt: OpaquePointer?) -> AuthorizationCode? {
        guard let stmt = stmt else { return nil }

        let code = String(cString: sqlite3_column_text(stmt, 0))
        let clientId = String(cString: sqlite3_column_text(stmt, 1))
        let redirectUri = String(cString: sqlite3_column_text(stmt, 2))
        let scope = sqlite3_column_text(stmt, 3).map { String(cString: $0) }
        let codeChallenge = sqlite3_column_text(stmt, 4).map { String(cString: $0) }
        let codeChallengeMethod = sqlite3_column_text(stmt, 5).map { String(cString: $0) }
        let expiresAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 6))
        let createdAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 7))
        // Column 8 is `consumed`; 9 is the audience added in schema 6. A code stored before
        // that migration has NULL here, which reads as "granted for no particular resource" —
        // the honest answer, since it never was.
        let audience = sqlite3_column_text(stmt, 9)
            .map { String(cString: $0) }
            .flatMap { URL(string: $0) }
        // Column 10 is the subject added in schema 9; NULL for a code granted with nobody named.
        let subject = sqlite3_column_text(stmt, 10).map { String(cString: $0) }

        return AuthorizationCode(
            code: code,
            clientId: clientId,
            redirectUri: redirectUri,
            scope: scope,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod,
            expiresAt: expiresAt,
            createdAt: createdAt,
            audience: audience,
            subject: subject
        )
    }
}

// MARK: - RefreshTokenInfo

/// Information about a valid refresh token
public struct RefreshTokenInfo: Sendable {
    /// The client identifier that owns this token
    public let clientId: String
    /// The authorized scope for this token
    public let scope: String?
    /// When this token expires
    public let expiresAt: Date
    /// Who it was issued for — carried onto every access token it refreshes. `nil` when
    /// nobody was recorded.
    public let subject: String?
}

// MARK: - OAuthStorageError

/// Errors that can occur during OAuth storage operations
public enum OAuthStorageError: Error, Sendable {
    /// A database operation failed with the given message
    case databaseError(String)
}

// MARK: - SQLite Helpers

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
