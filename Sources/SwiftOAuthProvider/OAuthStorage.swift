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
/// let storage = try OAuthStorage(path: "~/.businessmath-mcp/oauth.db")
///
/// // Store a client
/// try await storage.saveClient(client)
///
/// // Validate a token
/// let result = try await storage.validateAccessToken(token: token)
/// if result.isValid {
///     // Token is valid
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
    /// - Parameter path: Path to the SQLite database file.
    ///   Use ":memory:" for an in-memory database (useful for testing).
    /// - Throws: `OAuthStorageError` if database cannot be opened
    public init(path: String) throws {
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
        try Self.initializeDatabase(db: validDb)
    }

    deinit {
        sqlite3_close(db)
    }

    /// Static helper to initialize database schema (runs before actor isolation)
    private static func initializeDatabase(db: OpaquePointer) throws {
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
    public func saveClient(_ client: RegisteredClient) throws {
        let redirectUris = try encodeJSON(client.redirectUris)
        let grantTypes = try encodeJSON(client.grantTypes)

        try execute("""
            INSERT OR REPLACE INTO clients
            (client_id, client_secret, client_name, redirect_uris, grant_types,
             token_endpoint_auth_method, registration_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, parameters: [
            client.clientId,
            client.clientSecret as Any,
            client.clientName,
            redirectUris,
            grantTypes,
            client.tokenEndpointAuthMethod,
            client.registrationDate.timeIntervalSince1970
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
             expires_at, created_at, consumed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
        """, parameters: [
            code.code,
            code.clientId,
            code.redirectUri,
            code.scope as Any,
            code.codeChallenge as Any,
            code.codeChallengeMethod as Any,
            code.expiresAt.timeIntervalSince1970,
            code.createdAt.timeIntervalSince1970
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
        expiresAt: Date
    ) throws {
        let tokenHash = hashToken(token)

        try execute("""
            INSERT OR REPLACE INTO access_tokens
            (token_hash, client_id, scope, expires_at, created_at, revoked)
            VALUES (?, ?, ?, ?, ?, 0)
        """, parameters: [
            tokenHash,
            clientId,
            scope as Any,
            expiresAt.timeIntervalSince1970,
            Date().timeIntervalSince1970
        ])
    }

    /// Validates an access token
    public func validateAccessToken(token: String) throws -> TokenValidationResult {
        let tokenHash = hashToken(token)

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        let sql = """
            SELECT client_id, scope, expires_at, revoked
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

        if revoked {
            return .invalid(reason: "Token revoked")
        }

        if Date() >= expiresAt {
            return .invalid(reason: "Token expired")
        }

        return .valid(clientId: clientId, scope: scope)
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
        expiresAt: Date
    ) throws {
        let tokenHash = hashToken(token)

        try execute("""
            INSERT OR REPLACE INTO refresh_tokens
            (token_hash, client_id, scope, expires_at, created_at, revoked)
            VALUES (?, ?, ?, ?, ?, 0)
        """, parameters: [
            tokenHash,
            clientId,
            scope as Any,
            expiresAt.timeIntervalSince1970,
            Date().timeIntervalSince1970
        ])
    }

    /// Gets refresh token info if valid
    public func getRefreshTokenInfo(token: String) throws -> RefreshTokenInfo? {
        let tokenHash = hashToken(token)

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        let sql = """
            SELECT client_id, scope, expires_at, revoked
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

        return RefreshTokenInfo(clientId: clientId, scope: scope, expiresAt: expiresAt)
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
        let data = Data(token.utf8)
        let digest = SHA256.hash(data: data)
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
        let clientSecret = sqlite3_column_text(stmt, 1).map { String(cString: $0) }
        let clientName = String(cString: sqlite3_column_text(stmt, 2))
        let redirectUrisJson = String(cString: sqlite3_column_text(stmt, 3))
        let grantTypesJson = String(cString: sqlite3_column_text(stmt, 4))
        let tokenEndpointAuthMethod = String(cString: sqlite3_column_text(stmt, 5))
        let registrationDate = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 6))

        let redirectUris: [String] = try decodeJSON(redirectUrisJson, as: [String].self)
        let grantTypes: [String] = try decodeJSON(grantTypesJson, as: [String].self)

        return RegisteredClient(
            clientId: clientId,
            clientSecret: clientSecret,
            clientName: clientName,
            redirectUris: redirectUris,
            grantTypes: grantTypes,
            tokenEndpointAuthMethod: tokenEndpointAuthMethod,
            registrationDate: registrationDate
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

        return AuthorizationCode(
            code: code,
            clientId: clientId,
            redirectUri: redirectUri,
            scope: scope,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod,
            expiresAt: expiresAt,
            createdAt: createdAt
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
}

// MARK: - OAuthStorageError

/// Errors that can occur during OAuth storage operations
public enum OAuthStorageError: Error, Sendable {
    /// A database operation failed with the given message
    case databaseError(String)
}

// MARK: - SQLite Helpers

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
