import CSQLite
import Foundation
import Testing
@testable import SwiftOAuthProvider
import SwiftOAuthCore

/// Client secrets are stored as hashes, as tokens already were.
///
/// A client secret was the one long-lived credential this store kept in plaintext: a copy of the
/// database — a backup, a leaked file — handed over every confidential client's secret, while
/// the tokens beside it were hashes. For a service client using `client_credentials`, the secret
/// is the whole credential, so the gap mattered more once that grant existed.
@Suite("Client secrets at rest")
struct ClientSecretStorageTests {

    private static func confidentialClient(
        id: String = "client-1", secret: String? = "s3cret-value"
    ) -> RegisteredClient {
        RegisteredClient(
            clientId: id, clientSecret: secret, clientName: "Confidential",
            redirectUris: ["https://client.example.com/cb"],
            grantTypes: ["authorization_code"],
            tokenEndpointAuthMethod: "client_secret_basic", registrationDate: Date())
    }

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("oauth-secrets-\(UUID().uuidString).sqlite").path
    }

    /// Every value in `clients.client_secret`, read with raw SQL so nothing the store does on
    /// the way out can hide what is on disk.
    private static func storedSecretColumn(path: String) throws -> [String] {
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK, let db else {
            throw OAuthStorageError.databaseError("could not open \(path)")
        }
        defer { sqlite3_close(db) }
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(
            db, "SELECT client_secret FROM clients WHERE client_secret IS NOT NULL",
            -1, &stmt, nil) == SQLITE_OK
        else { throw OAuthStorageError.databaseError("could not read clients") }
        var values: [String] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let text = sqlite3_column_text(stmt, 0) { values.append(String(cString: text)) }
        }
        return values
    }

    @Test("The secret is not on disk")
    func secretIsNotStoredRaw() async throws {
        let path = Self.tempPath()
        // SECURITY: removes only the uniquely-named temp file this test just created.
        defer { try? FileManager.default.removeItem(atPath: path) }
        let storage = try OAuthStorage(path: path)

        try await storage.saveClient(Self.confidentialClient())

        let column = try Self.storedSecretColumn(path: path)
        #expect(column.count == 1, "the client is confidential, so something must be stored")
        #expect(!column.contains("s3cret-value"), "the raw secret is on disk")
    }

    /// The store cannot hand back what it does not keep. The secret is returned once, by
    /// registration, and nowhere else.
    @Test("A retrieved client carries no secret")
    func retrievedClientCarriesNoSecret() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        try await storage.saveClient(Self.confidentialClient())

        let retrieved = try #require(await storage.getClient(clientId: "client-1"))
        #expect(retrieved.clientSecret == nil)
        #expect(retrieved.tokenEndpointAuthMethod == "client_secret_basic")
    }

    @Test("The right secret matches; a wrong one, an unknown client and a public client do not")
    func secretMatching() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        try await storage.saveClient(Self.confidentialClient())
        try await storage.saveClient(RegisteredClient(
            clientId: "public-1", clientSecret: nil, clientName: "Public",
            redirectUris: ["myapp://cb"], grantTypes: ["authorization_code"],
            tokenEndpointAuthMethod: "none", registrationDate: Date()))

        #expect(try await storage.clientSecretMatches(clientId: "client-1", presented: "s3cret-value"))
        #expect(try await !storage.clientSecretMatches(clientId: "client-1", presented: "s3cret-valuf"))
        #expect(try await !storage.clientSecretMatches(clientId: "client-1", presented: ""))
        #expect(try await !storage.clientSecretMatches(clientId: "nobody", presented: "s3cret-value"))
        #expect(try await !storage.clientSecretMatches(clientId: "public-1", presented: ""))
    }

    /// The trap the hashing opens: a retrieved client has no secret, so saving it back as it
    /// is — to change its name, say — must not erase the credential it was registered with.
    @Test("Saving a retrieved client back keeps its secret")
    func resavingKeepsSecret() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        try await storage.saveClient(Self.confidentialClient())
        let retrieved = try #require(await storage.getClient(clientId: "client-1"))

        try await storage.saveClient(retrieved)

        #expect(try await storage.clientSecretMatches(clientId: "client-1", presented: "s3cret-value"))
    }

    /// Saving with a new secret replaces the old one — the path rotation takes.
    @Test("Saving a new secret replaces the old one")
    func newSecretReplacesOld() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        try await storage.saveClient(Self.confidentialClient(secret: "first"))
        try await storage.saveClient(Self.confidentialClient(secret: "second"))

        #expect(try await !storage.clientSecretMatches(clientId: "client-1", presented: "first"))
        #expect(try await storage.clientSecretMatches(clientId: "client-1", presented: "second"))
    }

    /// **A database written by an earlier release has plaintext secrets, and they are hashed in
    /// place on upgrade.** Every client keeps working with the secret it already holds, and
    /// after the upgrade no secret is on disk.
    @Test("Upgrading hashes the plaintext secrets an earlier release stored")
    func upgradeHashesExistingSecrets() async throws {
        let path = Self.tempPath()
        // SECURITY: removes only the uniquely-named temp file this test just created.
        defer { try? FileManager.default.removeItem(atPath: path) }

        // A database as 1.0.0-beta.6 left it, with a row written the way that release wrote it.
        _ = try OAuthStorage(path: path, schemaVersion: 6)
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK, let db else {
            Issue.record("could not open the database to plant a row")
            return
        }
        let insert = """
            INSERT INTO clients (client_id, client_secret, client_name, redirect_uris,
                                 grant_types, token_endpoint_auth_method, registration_date)
            VALUES ('legacy', 'legacy-plaintext', 'Legacy', '["https://l.example.com/cb"]',
                    '["authorization_code"]', 'client_secret_post', 0)
            """
        let planted = sqlite3_exec(db, insert, nil, nil, nil)
        sqlite3_close(db)
        #expect(planted == SQLITE_OK)
        #expect(try Self.storedSecretColumn(path: path) == ["legacy-plaintext"])

        let upgraded = try OAuthStorage(path: path)

        #expect(try await upgraded.clientSecretMatches(clientId: "legacy", presented: "legacy-plaintext"))
        #expect(try !Self.storedSecretColumn(path: path).contains("legacy-plaintext"))
    }

    /// Opening an upgraded database again must not hash the hashes, or every client registered
    /// before the upgrade would be locked out on the first restart.
    @Test("Reopening an upgraded database does not hash twice")
    func reopeningDoesNotRehash() async throws {
        let path = Self.tempPath()
        // SECURITY: removes only the uniquely-named temp file this test just created.
        defer { try? FileManager.default.removeItem(atPath: path) }

        let first = try OAuthStorage(path: path)
        try await first.saveClient(Self.confidentialClient())
        _ = try OAuthStorage(path: path)
        let third = try OAuthStorage(path: path)

        #expect(try await third.clientSecretMatches(clientId: "client-1", presented: "s3cret-value"))
    }
}
