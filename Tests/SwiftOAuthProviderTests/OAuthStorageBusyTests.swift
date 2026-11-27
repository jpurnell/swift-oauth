import Foundation
import Testing
import CSQLite
import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// Two connections to one database file.
///
/// Production runs two server processes over one `oauth.db`. SQLite lets one writer in at a time;
/// a second connection that meets the lock is told `SQLITE_BUSY` unless it was set to wait.
/// These tests hold the lock on a second raw connection, which makes the collision
/// deterministic rather than a matter of timing luck.
@Suite("OAuth storage — a second connection holding the lock")
struct OAuthStorageBusyTests {

    static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("oauth-busy-\(UUID().uuidString).sqlite").path
    }

    static func client(_ id: String) -> RegisteredClient {
        RegisteredClient(
            clientId: id,
            clientSecret: nil,
            clientName: "Busy Test \(id)",
            redirectUris: ["http://localhost:8080/callback"],
            grantTypes: ["authorization_code"],
            tokenEndpointAuthMethod: "none",
            registrationDate: Date()
        )
    }

    /// A raw connection standing in for the other process.
    final class Rival {
        private var db: OpaquePointer?

        init(path: String) throws {
            guard sqlite3_open(path, &db) == SQLITE_OK else {
                throw OAuthStorageError.databaseError("rival could not open \(path)")
            }
        }

        deinit { sqlite3_close(db) }

        func run(_ sql: String) throws {
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
                throw OAuthStorageError.databaseError("rival could not run \(sql)")
            }
        }

        func journalMode() throws -> String {
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }
            guard sqlite3_prepare_v2(db, "PRAGMA journal_mode", -1, &stmt, nil) == SQLITE_OK,
                  sqlite3_step(stmt) == SQLITE_ROW,
                  let text = sqlite3_column_text(stmt, 0) else {
                throw OAuthStorageError.databaseError("rival could not read journal_mode")
            }
            return String(cString: text)
        }
    }

    @Test("A write that meets another connection's write lock waits and then succeeds")
    func writeWaitsForTheLock() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storage = try OAuthStorage(path: path)
        let rival = try Rival(path: path)

        try rival.run("BEGIN IMMEDIATE")
        let write = Task { try await storage.saveClient(Self.client("waits")) }
        try await Task.sleep(nanoseconds: 300_000_000)
        try rival.run("COMMIT")

        try await write.value
        #expect(try await storage.getClient(clientId: "waits")?.clientId == "waits")
    }

    @Test("A read that meets an exclusive lock waits, and does not report the row as absent")
    func readWaitsForTheLock() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storage = try OAuthStorage(path: path)
        try await storage.saveClient(Self.client("present"))
        let rival = try Rival(path: path)

        try rival.run("BEGIN EXCLUSIVE")
        let read = Task { try await storage.getClient(clientId: "present") }
        try await Task.sleep(nanoseconds: 300_000_000)
        try rival.run("COMMIT")

        // Before the fix this resolved to nil: a busy step was read as "no such client", which
        // the HTTP layer reports as 401 invalid_client for a client that is registered.
        let found = try await read.value
        #expect(found?.clientId == "present")
    }

    @Test("Several connections writing one file at once all succeed")
    func manyConnectionsWriteOneFile() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storages = try (0..<6).map { _ in try OAuthStorage(path: path) }

        let failures = await withTaskGroup(of: Int.self) { group in
            for (index, storage) in storages.enumerated() {
                group.addTask {
                    var failed = 0
                    for round in 0..<40 {
                        let id = "c\(index)-\(round)"
                        do {
                            try await storage.saveClient(Self.client(id))
                            _ = try await storage.generateCSRFToken(
                                clientId: id, redirectUri: "http://localhost:8080/callback")
                            try await storage.saveAuthorizationCode(AuthorizationCode(
                                code: "code-\(id)", clientId: id,
                                redirectUri: "http://localhost:8080/callback", scope: nil,
                                codeChallenge: nil, codeChallengeMethod: nil,
                                expiresAt: Date().addingTimeInterval(600), createdAt: Date()))
                        } catch {
                            failed += 1
                        }
                    }
                    return failed
                }
            }
            return await group.reduce(0, +)
        }
        #expect(failures == 0)
    }

    // MARK: - Still busy after the timeout

    @Test("A write still blocked when the timeout ends throws temporarily_unavailable, not a database error")
    func stillBusyIsTemporarilyUnavailable() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storage = try OAuthStorage(path: path, busyTimeout: 0.1)
        let rival = try Rival(path: path)
        try rival.run("BEGIN IMMEDIATE")
        defer { try? rival.run("ROLLBACK") }

        var code = "no error was thrown"
        do {
            try await storage.saveClient(Self.client("never"))
        } catch let error as OAuthError {
            code = error.code
        } catch {
            code = "\(error)"
        }
        #expect(code == "temporarily_unavailable")
    }

    @Test("A read still blocked when the timeout ends throws; it never answers nil")
    func stillBusyReadThrows() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storage = try OAuthStorage(path: path, busyTimeout: 0.1)
        try await storage.saveClient(Self.client("present"))
        let rival = try Rival(path: path)
        try rival.run("BEGIN EXCLUSIVE")
        defer { try? rival.run("ROLLBACK") }

        var code = "no error was thrown"
        do {
            let found = try await storage.getClient(clientId: "present")
            code = "returned \(String(describing: found))"
        } catch let error as OAuthError {
            code = error.code
        } catch {
            code = "\(error)"
        }
        #expect(code == "temporarily_unavailable")
    }

    @Test("POST /register answers 503 with Retry-After while the database stays locked")
    func registerAnswers503() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storage = try OAuthStorage(path: path, busyTimeout: 0.1)
        let server = OAuthServer(
            storage: storage, issuer: "https://example.com", scopesSupported: ["mcp:tools"],
            served: .core, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let handler = OAuthHTTPHandler(server: server)
        let rival = try Rival(path: path)
        try rival.run("BEGIN IMMEDIATE")
        defer { try? rival.run("ROLLBACK") }

        let response = await handler.handleRegistrationRequest(body: """
            {"client_name":"x","redirect_uris":["http://localhost:8080/cb"],\
            "grant_types":["authorization_code"],"token_endpoint_auth_method":"none"}
            """)

        #expect(response.statusCode == 503)
        #expect(response.body.contains("temporarily_unavailable"))
        #expect(response.headers["Retry-After"] == OAuthHTTPHandler.retryAfterSeconds)
    }

    @Test("GET /authorize answers 503, not 500 or 401, while the database stays locked")
    func authorizeAnswers503() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storage = try OAuthStorage(path: path, busyTimeout: 0.1)
        try await storage.saveClient(Self.client("known"))
        let server = OAuthServer(
            storage: storage, issuer: "https://example.com", scopesSupported: ["mcp:tools"],
            served: .core, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let handler = OAuthHTTPHandler(server: server)
        let rival = try Rival(path: path)
        try rival.run("BEGIN EXCLUSIVE")
        defer { try? rival.run("ROLLBACK") }

        let response = await handler.handleAuthorizationRequest(queryParams: [
            "response_type": "code", "client_id": "known",
            "redirect_uri": "http://localhost:8080/callback",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        ])

        #expect(response.statusCode == 503)
        #expect(response.headers["Retry-After"] == OAuthHTTPHandler.retryAfterSeconds)
    }

    @Test("The consent POST does not turn a busy database into invalid_request or invalid_client")
    func consentValidationAnswers503() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storage = try OAuthStorage(path: path, busyTimeout: 0.1)
        try await storage.saveClient(Self.client("known"))
        let token = try await storage.generateCSRFToken(
            clientId: "known", redirectUri: "http://localhost:8080/callback")
        let server = OAuthServer(
            storage: storage, issuer: "https://example.com", scopesSupported: ["mcp:tools"],
            served: .core, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let handler = OAuthHTTPHandler(server: server)
        let rival = try Rival(path: path)
        try rival.run("BEGIN EXCLUSIVE")
        defer { try? rival.run("ROLLBACK") }

        let response = await handler.handleConsentSubmission(formParams: [
            "client_id": "known", "redirect_uri": "http://localhost:8080/callback",
            "csrf_token": token, "action": "approve",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        ])

        #expect(response.statusCode == 503)
    }

    // MARK: - Configuration

    @Test("The default timeout is a few seconds")
    func defaultTimeoutIsSet() {
        #expect(OAuthStorage.defaultBusyTimeout >= 1)
        #expect(OAuthStorage.defaultBusyTimeout <= 30)
    }

    @Test("Default journal mode leaves an existing file as it was")
    func defaultLeavesJournalModeAlone() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        _ = try OAuthStorage(path: path)
        #expect(try Rival(path: path).journalMode() == "delete")
    }

    @Test("Opting in to WAL switches the file, and concurrent writers still succeed")
    func walIsOptIn() async throws {
        let path = Self.tempPath()
        defer {
            for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + suffix) }
        }
        let storages = try (0..<4).map { _ in try OAuthStorage(path: path, journalMode: .wal) }
        #expect(try Rival(path: path).journalMode() == "wal")

        let failures = await withTaskGroup(of: Int.self) { group in
            for (index, storage) in storages.enumerated() {
                group.addTask {
                    var failed = 0
                    for round in 0..<40 {
                        do { try await storage.saveClient(Self.client("w\(index)-\(round)")) } catch { failed += 1 }
                    }
                    return failed
                }
            }
            return await group.reduce(0, +)
        }
        #expect(failures == 0)
    }
}
