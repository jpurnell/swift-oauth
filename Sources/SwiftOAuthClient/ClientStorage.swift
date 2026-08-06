import Foundation

/// Where credentials obtained from other systems are kept.
///
/// The protocol says *what* must be persisted, not where. A service already running Postgres
/// should not stand up SQLite for its tokens, and a test should not touch disk.
///
/// `async throws` throughout, even where an implementation is synchronous: a protocol that
/// cannot express a database or network call would force every real implementation to block.
///
/// ## What an implementation must guarantee
///
/// **A store must not lose a credential it accepted.** That is a stronger requirement than it
/// sounds. Rotation means the token being replaced is *already dead at the provider* by the
/// time ``store(_:for:)`` is called — so a write that silently fails leaves the connection
/// unrecoverable, and the user must authorise again.
///
/// If a write cannot be made durable, throw. A caller can retry a throw; it cannot detect a
/// lie.
public protocol OAuthClientStorage: Sendable {

    /// The credential for a connection, if one is stored.
    func credential(for connection: ConnectionID) async throws -> StoredCredential?

    /// Stores a credential, replacing any previous one for the same connection.
    func store(_ credential: StoredCredential, for connection: ConnectionID) async throws

    /// Forgets a connection.
    ///
    /// Called when a user disconnects. Note that this does **not** revoke anything at the
    /// provider — that is a separate request, and forgetting a credential without revoking
    /// it leaves an access token valid until it expires.
    func remove(_ connection: ConnectionID) async throws

    /// Every connection with a stored credential.
    ///
    /// For a background task that refreshes connections before they lapse, and for showing
    /// a user what their account is connected to.
    func connections() async throws -> [ConnectionID]
}

/// Credentials held in memory.
///
/// For tests, and for a single-process tool where re-authorising on restart is acceptable.
/// **Not** for a server: every credential is lost on restart, and every user has to
/// authorise again.
public actor InMemoryClientStorage: OAuthClientStorage {

    private var credentials: [ConnectionID: StoredCredential] = [:]

    /// Creates an empty store.
    public init() {}

    /// The credential for this connection, if one is stored.
    ///
    /// - Parameter connection: Which connection.
    /// - Returns: The credential, or `nil` if none is held.
    public func credential(for connection: ConnectionID) async throws -> StoredCredential? {
        credentials[connection]
    }

    /// Stores a credential, replacing any previous one.
    ///
    /// - Parameters:
    ///   - credential: What to store.
    ///   - connection: Which connection it belongs to.
    /// - Throws: If the write could not be made durable.
    public func store(_ credential: StoredCredential, for connection: ConnectionID) async throws {
        credentials[connection] = credential
    }

    /// Forgets a connection's credential.
    ///
    /// - Parameter connection: Which connection to forget.
    public func remove(_ connection: ConnectionID) async throws {
        credentials.removeValue(forKey: connection)
    }

    /// Every connection with a stored credential, in a stable order.
    ///
    /// - Returns: The connections, sorted so the result does not vary between runs.
    public func connections() async throws -> [ConnectionID] {
        // Sorted: `Dictionary` iterates in an order derived from a per-process hash seed, so
        // an unsorted return would vary between runs of the same binary.
        credentials.keys.sorted { $0.description < $1.description }
    }
}

/// A store that fails on demand, for testing what happens when persistence does not work.
///
/// The interesting failure in this package is a write that fails *after* a rotation, when
/// the old refresh token is already dead at the provider. That path is unreachable with a
/// store that always succeeds, and it is the one whose handling determines whether a user
/// keeps their connection.
public actor FailingClientStorage: OAuthClientStorage {

    /// Why a store might fail.
    public enum Failure: Error, Equatable, Sendable {
        /// The write could not be made durable.
        case writeFailed
    }

    private var credentials: [ConnectionID: StoredCredential] = [:]
    private var failNextWrite = false

    /// Creates a store that succeeds until told otherwise.
    public init() {}

    /// Makes the next ``store(_:for:)`` throw.
    public func failNextStore() {
        failNextWrite = true
    }

    /// The credential for this connection, if one is stored.
    ///
    /// - Parameter connection: Which connection.
    /// - Returns: The credential, or `nil` if none is held.
    public func credential(for connection: ConnectionID) async throws -> StoredCredential? {
        credentials[connection]
    }

    /// Stores a credential, replacing any previous one.
    ///
    /// - Parameters:
    ///   - credential: What to store.
    ///   - connection: Which connection it belongs to.
    /// - Throws: If the write could not be made durable.
    public func store(_ credential: StoredCredential, for connection: ConnectionID) async throws {
        if failNextWrite {
            failNextWrite = false
            throw Failure.writeFailed
        }
        credentials[connection] = credential
    }

    /// Forgets a connection's credential.
    ///
    /// - Parameter connection: Which connection to forget.
    public func remove(_ connection: ConnectionID) async throws {
        credentials.removeValue(forKey: connection)
    }

    /// Every connection with a stored credential, in a stable order.
    ///
    /// - Returns: The connections, sorted so the result does not vary between runs.
    public func connections() async throws -> [ConnectionID] {
        credentials.keys.sorted { $0.description < $1.description }
    }
}
