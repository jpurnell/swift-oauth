import Foundation
import Crypto
#if canImport(os)
import os
#endif

/// Why a stored credential could not be read or written.
public enum StorageError: Error, Equatable, Sendable {

    /// The file exists but could not be opened with the key supplied.
    ///
    /// A wrong key and a tampered file are indistinguishable from here, and both produce
    /// this. What matters is that neither reads as *empty*: an empty read looks like a first
    /// run, and a first run causes a caller to discard a connection that was in fact fine.
    case cannotDecrypt

    /// The decrypted contents were not what this store writes.
    case unreadable

    /// The write could not be made durable.
    case cannotWrite
}

/// Credentials kept in an encrypted file.
///
/// The persistent counterpart to ``InMemoryClientStorage``, for an application that should
/// not make its user authorise again after a restart.
///
/// ## What is protected, and from what
///
/// Contents are sealed with **AES-GCM**, which authenticates as well as encrypts. That is the
/// property that matters: a store which merely encrypted would decrypt a tampered file into
/// plausible nonsense, and a credential store returning plausible nonsense is worse than one
/// that fails.
///
/// The **whole file** is sealed, not each credential — so which providers a user has
/// connected, and to which accounts, is not readable either. A file of individually-encrypted
/// values still discloses how many there are and what they are keyed by.
///
/// This protects a file at rest, copied out of a backup or read off a disk. It does not
/// protect against a process that can already read this one's memory, and nothing at this
/// layer can.
///
/// ## The key
///
/// Supplied by the caller rather than derived here, because where it lives is the security
/// decision and it belongs to the application. On Apple platforms that means the Keychain;
/// a server might use its own secrets manager. A key held in the same directory as this file
/// protects nothing.
public actor EncryptedFileClientStorage: OAuthClientStorage {

    /// Logs why a read or write failed.
    ///
    /// The error thrown to a caller says *what* happened, deliberately: a caller can act on
    /// "could not write" and can do nothing with a `CocoaError` code. But a reason has to
    /// survive somewhere, or an operator debugging a store that will not open has nothing at
    /// all. Errors only — nothing here logs a credential.
    private static let logger = Logger(
        subsystem: "com.swiftoauth.client", category: "EncryptedFileClientStorage")

    private let url: URL
    private let key: SymmetricKey

    /// Credentials as last read or written, so the file is not re-opened per lookup.
    private var cache: [String: StoredCredential]?

    /// Creates a store over a file.
    ///
    /// The file need not exist; it is created on first write. The containing directory is
    /// created if it is missing, since a caller naming `~/.config/app/credentials` should not
    /// have to create the path first.
    ///
    /// - Parameters:
    ///   - url: Where the credentials live.
    ///   - key: The key to seal them with. See the note above on where it should come from.
    /// - Throws: If the containing directory could not be created.
    public init(url: URL, key: SymmetricKey) throws {
        self.url = url
        self.key = key

        // Created unconditionally: `withIntermediateDirectories` makes it succeed when the
        // directory is already there, and checking first would be a time-of-check race — the
        // directory can appear or vanish between the check and the use.
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    }

    /// The credential for this connection, if one is stored.
    ///
    /// - Parameter connection: Which connection.
    /// - Returns: The credential, or `nil` if none is held.
    /// - Throws: ``StorageError/cannotDecrypt`` if the file cannot be opened with this key.
    public func credential(for connection: ConnectionID) async throws -> StoredCredential? {
        try load()[connection.description]
    }

    /// Stores a credential, replacing any previous one.
    ///
    /// - Parameters:
    ///   - credential: What to store.
    ///   - connection: Which connection it belongs to.
    /// - Throws: ``StorageError/cannotWrite`` if the write could not be made durable.
    public func store(_ credential: StoredCredential, for connection: ConnectionID) async throws {
        var credentials = try load()
        credentials[connection.description] = credential
        try save(credentials)
    }

    /// Forgets a connection's credential.
    ///
    /// - Parameter connection: Which connection to forget.
    /// - Throws: ``StorageError/cannotWrite``.
    public func remove(_ connection: ConnectionID) async throws {
        var credentials = try load()
        credentials.removeValue(forKey: connection.description)
        try save(credentials)
    }

    /// Every connection with a stored credential, in a stable order.
    ///
    /// - Returns: The connections, sorted — `Dictionary` iterates by a per-process hash seed,
    ///   so an unsorted result would reorder itself between launches.
    /// - Throws: ``StorageError/cannotDecrypt``.
    public func connections() async throws -> [ConnectionID] {
        try load().keys.sorted().compactMap(Self.connection(from:))
    }

    // MARK: - The file

    /// Reads and decrypts, or returns what was already read.
    private func load() throws -> [String: StoredCredential] {
        if let cache { return cache }

        let sealed: Data
        do {
            sealed = try Data(contentsOf: url)
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            // First run. Read and handle rather than checking existence first: a file can be
            // created or removed between the check and the read, and the absent case has to
            // be handled here regardless.
            //
            // Distinct from "could not be opened", which throws — an unreadable file must not
            // be mistaken for a first run. Logged at debug because it is also the answer to
            // "why am I being asked to sign in again": the file was not there.
            Self.logger.debug(
                "no credential file yet; treating as first run: \(String(describing: error), privacy: .public)")
            cache = [:]
            return [:]
        } catch {
            throw StorageError.cannotDecrypt
        }

        let plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(combined: sealed)
            plaintext = try AES.GCM.open(box, using: key)
        } catch {
            // A wrong key and a tampered file arrive here identically, and both must throw.
            // Returning empty would look like a first run and invite a caller to overwrite a
            // file it could not read.
            Self.logger.error(
                "credential file could not be opened with this key: \(String(describing: error), privacy: .public)")
            throw StorageError.cannotDecrypt
        }

        do {
            let credentials = try JSONDecoder().decode(
                [String: StoredCredential].self, from: plaintext)
            cache = credentials
            return credentials
        } catch {
            Self.logger.error(
                "credential file decrypted but did not decode: \(String(describing: error), privacy: .public)")
            throw StorageError.unreadable
        }
    }

    /// Encrypts and writes.
    ///
    /// Written atomically. A partial write of a credential file is the failure this whole
    /// package exists to avoid: after a rotation the previous token is already dead at the
    /// provider, so a truncated file costs the connection rather than a request.
    private func save(_ credentials: [String: StoredCredential]) throws {
        let encoder = JSONEncoder()
        // Sorted keys so the same credentials produce the same plaintext. The ciphertext
        // still differs every time — AES-GCM uses a fresh nonce — but the input to it does
        // not depend on a per-process hash seed.
        encoder.outputFormatting = [.sortedKeys]

        let sealed: Data
        do {
            let plaintext = try encoder.encode(credentials)
            guard let combined = try AES.GCM.seal(plaintext, using: key).combined else {
                throw StorageError.cannotWrite
            }
            sealed = combined
            try sealed.write(to: url, options: [.atomic])
        } catch {
            // Every failure here is the same to a caller: nothing durable was written, and
            // after a rotation that costs the connection unless they retry. The reason is
            // logged because "could not write" alone leaves an operator nothing to go on.
            Self.logger.error(
                "credentials could not be written: \(String(describing: error), privacy: .public)")
            throw StorageError.cannotWrite
        }

        // Only after the write succeeded. Updating first would leave this store answering
        // from a state the file does not hold.
        cache = credentials
    }

    /// Rebuilds a connection identifier from its stored key.
    ///
    /// The inverse of ``ConnectionID/description``. A key that does not parse is skipped
    /// rather than guessed at.
    private static func connection(from key: String) -> ConnectionID? {
        let parts = key.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        switch parts.count {
        case 2: return ConnectionID(tenant: parts[0], provider: parts[1])
        case 3: return ConnectionID(tenant: parts[0], provider: parts[1], account: parts[2])
        default: return nil
        }
    }
}
