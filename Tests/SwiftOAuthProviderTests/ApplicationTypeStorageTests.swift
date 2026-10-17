import CSQLite
import Foundation
import Testing
@testable import SwiftOAuthProvider
import SwiftOAuthCore

/// A client's `application_type` survives storage.
///
/// `OAuthStorage` had no column for it, so every client read back was `.web` — a native client
/// registered through `/register` became a web client on its first retrieval, and the
/// registration response was the only place its real type ever appeared.
@Suite("Application type at rest")
struct ApplicationTypeStorageTests {

    private static func client(_ type: ApplicationType) -> RegisteredClient {
        RegisteredClient(
            clientId: "app", clientSecret: nil, clientName: "App",
            redirectUris: ["http://127.0.0.1/cb"], grantTypes: ["authorization_code"],
            tokenEndpointAuthMethod: "none", registrationDate: Date(),
            applicationType: type)
    }

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("oauth-apptype-\(UUID().uuidString).sqlite").path
    }

    @Test("Each application type round-trips", arguments: [ApplicationType.web, .native])
    func roundTrips(type: ApplicationType) async throws {
        let storage = try OAuthStorage(path: ":memory:")
        try await storage.saveClient(Self.client(type))

        let stored = try #require(try await storage.getClient(clientId: "app"))
        #expect(stored.applicationType == type)
    }

    @Test("A native client registered through /register is still native when read back")
    func registeredNativeClientStaysNative() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(
            storage: storage, issuer: "https://example.com",
            scopesSupported: ["read"], served: .core, resourceIdentity: .colocated)

        let registered = try await server.registerClient(ClientRegistrationRequest(
            clientName: "CLI", redirectUris: ["http://127.0.0.1/cb"], applicationType: .native))

        let stored = try #require(try await storage.getClient(clientId: registered.clientId))
        #expect(stored.applicationType == .native)
    }

    /// A row from before the column existed was registered with no recorded type. `.web` is
    /// what every read of it returned until now, so it is what it keeps.
    @Test("Upgrading reads an earlier release's clients as web, as that release did")
    func upgradeKeepsExistingClientsWeb() async throws {
        let path = Self.tempPath()
        // SECURITY: removes only the uniquely-named temp file this test just created.
        defer { try? FileManager.default.removeItem(atPath: path) }

        // A database as schema 7 left it, with a row written the way that schema wrote it.
        _ = try OAuthStorage(path: path, schemaVersion: 7)
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK, let db else {
            Issue.record("could not open the database to plant a row")
            return
        }
        let insert = """
            INSERT INTO clients (client_id, client_secret, client_name, redirect_uris,
                                 grant_types, token_endpoint_auth_method, registration_date)
            VALUES ('app', NULL, 'App', '["http://127.0.0.1/cb"]',
                    '["authorization_code"]', 'none', 0)
            """
        let planted = sqlite3_exec(db, insert, nil, nil, nil)
        sqlite3_close(db)
        #expect(planted == SQLITE_OK)

        let upgraded = try OAuthStorage(path: path)
        let stored = try #require(try await upgraded.getClient(clientId: "app"))
        #expect(stored.applicationType == .web)
        try await upgraded.saveClient(Self.client(.native))
        #expect(try await upgraded.getClient(clientId: "app")?.applicationType == .native)
    }
}
