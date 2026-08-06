import Foundation
import Testing
import Crypto
import SwiftOAuthCore
@testable import SwiftOAuthClient

/// Persistent credential storage.
///
/// The protocol's contract is that a store must not lose a credential it accepted, and that
/// matters more here than anywhere else: rotation means the token being replaced is already
/// dead at the provider by the time `store` is called, so a write that silently fails leaves
/// the connection unrecoverable.
@Suite("Encrypted file storage")
struct EncryptedFileStorageTests {

    /// The point of persistence: a new instance over the same file sees what the old one
    /// wrote. Without this the storage is an in-memory store with extra steps.
    @Test("A credential survives a new instance over the same file")
    func credentialSurvivesRestart() async throws {
        let location = temporaryFile()
        let key = SymmetricKey(size: .bits256)
        defer { try? FileManager.default.removeItem(at: location) }

        let first = try EncryptedFileClientStorage(url: location, key: key)
        try await first.store(credential(access: "the-token"), for: .testConnection)

        // A separate instance, as though the process had restarted.
        let second = try EncryptedFileClientStorage(url: location, key: key)
        let recovered = try await second.credential(for: .testConnection)

        #expect(recovered?.accessToken == "the-token")
        #expect(recovered?.refreshToken == "the-refresh")
    }

    /// Reading a store that does not exist yet is the first-run case, not a failure.
    @Test("An absent file reads as empty rather than failing")
    func absentFileIsEmpty() async throws {
        let location = temporaryFile()
        let storage = try EncryptedFileClientStorage(url: location, key: SymmetricKey(size: .bits256))

        #expect(try await storage.credential(for: .testConnection) == nil)
        #expect(try await storage.connections().isEmpty)
    }

    /// The tokens must not be readable by anything that can read the file.
    @Test("The file contains no plaintext token")
    func fileHasNoPlaintext() async throws {
        let location = temporaryFile()
        defer { try? FileManager.default.removeItem(at: location) }

        let storage = try EncryptedFileClientStorage(url: location, key: SymmetricKey(size: .bits256))
        try await storage.store(
            credential(access: "SECRET-ACCESS-TOKEN", refresh: "SECRET-REFRESH-TOKEN"),
            for: .testConnection)

        let raw = try Data(contentsOf: location)
        let asText = String(decoding: raw, as: UTF8.self)

        #expect(!asText.contains("SECRET-ACCESS-TOKEN"))
        #expect(!asText.contains("SECRET-REFRESH-TOKEN"))
        // Nor the connection it belongs to: which accounts someone has connected is itself
        // worth not disclosing.
        #expect(!asText.contains("acme"))
    }

    /// A file encrypted under one key must not open under another. Returning empty instead
    /// would look like a first run and quietly discard a working connection.
    @Test("The wrong key fails rather than reading as empty")
    func wrongKeyFails() async throws {
        let location = temporaryFile()
        defer { try? FileManager.default.removeItem(at: location) }

        let storage = try EncryptedFileClientStorage(url: location, key: SymmetricKey(size: .bits256))
        try await storage.store(credential(access: "the-token"), for: .testConnection)

        let wrongKey = try EncryptedFileClientStorage(url: location, key: SymmetricKey(size: .bits256))
        await #expect(throws: StorageError.cannotDecrypt) {
            try await wrongKey.credential(for: .testConnection)
        }
    }

    /// Tampering must be detected rather than producing plausible nonsense. AES-GCM
    /// authenticates, which is why it is used here and why this test can exist at all.
    @Test("A modified file is refused")
    func tamperedFileRefused() async throws {
        let location = temporaryFile()
        defer { try? FileManager.default.removeItem(at: location) }

        let key = SymmetricKey(size: .bits256)
        let storage = try EncryptedFileClientStorage(url: location, key: key)
        try await storage.store(credential(access: "the-token"), for: .testConnection)

        var raw = try Data(contentsOf: location)
        // Flip a bit somewhere in the ciphertext.
        let index = raw.count / 2
        raw[index] ^= 0x01
        try raw.write(to: location)

        let reopened = try EncryptedFileClientStorage(url: location, key: key)
        await #expect(throws: StorageError.cannotDecrypt) {
            try await reopened.credential(for: .testConnection)
        }
    }

    /// Several connections coexist, and removing one leaves the others.
    @Test("Connections are independent")
    func connectionsAreIndependent() async throws {
        let location = temporaryFile()
        defer { try? FileManager.default.removeItem(at: location) }

        let storage = try EncryptedFileClientStorage(url: location, key: SymmetricKey(size: .bits256))
        let first = ConnectionID(tenant: "acme", provider: "intuit", account: "1")
        let second = ConnectionID(tenant: "acme", provider: "intuit", account: "2")

        try await storage.store(credential(access: "first"), for: first)
        try await storage.store(credential(access: "second"), for: second)
        #expect(try await storage.connections().count == 2)

        try await storage.remove(first)
        #expect(try await storage.credential(for: first) == nil)
        #expect(try await storage.credential(for: second)?.accessToken == "second")
    }

    /// Storing again replaces, which is what every rotation does.
    @Test("Storing again replaces the previous credential")
    func storeReplaces() async throws {
        let location = temporaryFile()
        defer { try? FileManager.default.removeItem(at: location) }

        let storage = try EncryptedFileClientStorage(url: location, key: SymmetricKey(size: .bits256))
        try await storage.store(credential(access: "first"), for: .testConnection)
        try await storage.store(credential(access: "second"), for: .testConnection)

        #expect(try await storage.credential(for: .testConnection)?.accessToken == "second")
        #expect(try await storage.connections().count == 1)
    }

    /// Listed in a stable order, so a UI does not reshuffle between launches. `Dictionary`
    /// iterates by a per-process hash seed, which would otherwise vary every run.
    @Test("Connections list in a stable order")
    func connectionsAreOrdered() async throws {
        let location = temporaryFile()
        defer { try? FileManager.default.removeItem(at: location) }

        let storage = try EncryptedFileClientStorage(url: location, key: SymmetricKey(size: .bits256))
        for account in ["3", "1", "2"] {
            try await storage.store(
                credential(access: account),
                for: ConnectionID(tenant: "acme", provider: "intuit", account: account))
        }

        let listed = try await storage.connections().map(\.description)
        #expect(listed == listed.sorted())
    }

    /// A store that cannot be made durable must throw. A caller can retry a throw; it cannot
    /// detect a lie, and after a rotation the token it would be retrying with is already dead.
    @Test("An unwritable location throws rather than reporting success")
    func unwritableLocationThrows() async throws {
        // A path whose parent is a file, so no directory can be created.
        let blocker = temporaryFile()
        try Data("not a directory".utf8).write(to: blocker)
        defer { try? FileManager.default.removeItem(at: blocker) }

        let impossible = blocker.appendingPathComponent("nested/credentials.enc")
        let storage = try? EncryptedFileClientStorage(
            url: impossible, key: SymmetricKey(size: .bits256))

        if let storage {
            await #expect(throws: (any Error).self) {
                try await storage.store(credential(access: "x"), for: .testConnection)
            }
        }
        // Failing at construction is equally acceptable — what must not happen is a
        // successful-looking store that wrote nothing.
    }
}

// MARK: - Helpers

private func temporaryFile() -> URL {
    FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString)
        .appendingPathExtension("credentials")
}

private func credential(
    access: String,
    refresh: String = "the-refresh"
) -> StoredCredential {
    StoredCredential(
        accessToken: access,
        refreshToken: refresh,
        accessExpiry: Date(timeIntervalSince1970: 1_767_229_200),
        rotatedAt: Date(timeIntervalSince1970: 1_767_225_600))
}
