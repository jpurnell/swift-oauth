import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import RedirectWireStub
import Testing
import SwiftOAuthCore
@testable import SwiftOAuthClient

/// What `disconnect()` tells its caller about the provider's half of a disconnect.
///
/// Two things happen: the stored credential is removed, and the provider is asked to revoke
/// the token. The first must happen whatever the second does — a user who asked to disconnect
/// should not stay connected because a server was down. But a caller told nothing about the
/// second believes the token is dead when it may be live until it expires, and that is the
/// difference between "signed out" and "signed out of this device".
@Suite("Disconnect — a revocation that did not happen is reported")
struct DisconnectTests {

    static let stored = StoredCredential(
        accessToken: "fixture-access",
        refreshToken: "fixture-refresh",
        accessExpiry: Date(timeIntervalSince1970: 1_767_229_200),
        rotatedAt: Date(timeIntervalSince1970: 1_767_225_600))

    private static func connection(
        storage: any OAuthClientStorage,
        transport: any TokenTransport,
        configuration: ProviderConfiguration = .testProvider
    ) -> OAuthConnection {
        OAuthConnection(
            configuration: configuration,
            credentials: .testCredentials,
            storage: storage,
            connection: .testConnection,
            transport: transport)
    }

    @Test("A refused revocation is thrown, and the local credential is gone all the same")
    func refusedRevocationReachesTheCaller() async throws {
        let storage = InMemoryClientStorage()
        try await storage.store(Self.stored, for: .testConnection)
        let transport = StubTransport([.failure(.invalidClient("this client may not revoke"))])
        let connection = Self.connection(storage: storage, transport: transport)

        let failure = await #expect(throws: OAuthRevocationFailed.self) {
            try await connection.disconnect()
        }

        #expect(failure?.step == .revocationRequest)
        #expect(failure?.underlying as? OAuthError == .invalidClient("this client may not revoke"))
        #expect(try await storage.credential(for: .testConnection) == nil)
        #expect(await transport.exchangeCount == 1)

        // The error says what kind of failure it was, and never the token it was about.
        let text = [failure.map { String(describing: $0) }, failure?.localizedDescription]
            .compactMap { $0 }.joined(separator: "\n")
        #expect(text.contains("invalid_client"))
        #expect(!text.contains("fixture-refresh"))
        #expect(!text.contains("fixture-access"))
    }

    @Test("A confirmed revocation returns normally, having sent the refresh token")
    func confirmedRevocationReturns() async throws {
        let storage = InMemoryClientStorage()
        try await storage.store(Self.stored, for: .testConnection)
        let transport = StubTransport([.tokens(access: "ignored", refresh: nil, expiresIn: 0)])
        let connection = Self.connection(storage: storage, transport: transport)

        try await connection.disconnect()

        #expect(try await storage.credential(for: .testConnection) == nil)
        let sent = await transport.requests
        #expect(sent == [["token": "fixture-refresh", "token_type_hint": "refresh_token"]])
    }

    @Test("With no revocation endpoint there is nothing to fail, and nothing is sent")
    func noEndpointIsNotAFailure() async throws {
        let storage = InMemoryClientStorage()
        try await storage.store(Self.stored, for: .testConnection)
        let transport = StubTransport([])
        let unrevocable = ProviderConfiguration(
            identifier: "test",
            authorizationEndpoint: ProviderConfiguration.testProvider.authorizationEndpoint,
            tokenEndpoint: ProviderConfiguration.testProvider.tokenEndpoint,
            scope: "accounting")
        let connection = Self.connection(
            storage: storage, transport: transport, configuration: unrevocable)

        try await connection.disconnect()

        #expect(try await storage.credential(for: .testConnection) == nil)
        #expect(await transport.exchangeCount == 0)
    }

    @Test("With nothing stored there is nothing to revoke, and nothing is sent")
    func nothingStoredIsNotAFailure() async throws {
        let transport = StubTransport([])
        let connection = Self.connection(storage: InMemoryClientStorage(), transport: transport)

        try await connection.disconnect()

        #expect(await transport.exchangeCount == 0)
    }

    /// The other way a revocation silently does not happen: the credential cannot be read, so
    /// there is no token to send. The removal still goes ahead — and the caller is told that
    /// nothing was revoked, rather than being left to assume it was.
    @Test("A credential that cannot be read is removed, and the missing revocation is reported")
    func unreadableCredentialIsReported() async throws {
        let storage = UnreadableStorage()
        let transport = StubTransport([])
        let connection = Self.connection(storage: storage, transport: transport)

        let failure = await #expect(throws: OAuthRevocationFailed.self) {
            try await connection.disconnect()
        }

        #expect(failure?.step == .readingStoredCredential)
        #expect(failure?.underlying as? UnreadableStorage.Unreadable == .corrupt)
        #expect(await storage.removals == [.testConnection])
        #expect(await transport.exchangeCount == 0)
    }

    // MARK: - On the wire

    private static func revocable(at endpoint: URL) -> ProviderConfiguration {
        ProviderConfiguration(
            identifier: "test",
            authorizationEndpoint: ProviderConfiguration.testProvider.authorizationEndpoint,
            tokenEndpoint: ProviderConfiguration.testProvider.tokenEndpoint,
            revocationEndpoint: endpoint,
            scope: "accounting")
    }

    /// Disconnects a stored credential against `server`, over the real transport.
    private static func disconnect(
        against server: RedirectWireServer
    ) async throws -> (storage: InMemoryClientStorage, result: Result<Void, any Error>) {
        let storage = InMemoryClientStorage()
        try await storage.store(stored, for: .testConnection)
        let endpoint = try #require(server.url(path: "/oauth/revoke"))
        let connection = connection(
            storage: storage, transport: URLSessionTokenTransport(),
            configuration: revocable(at: endpoint))
        do {
            try await connection.disconnect()
            return (storage, .success(()))
        } catch {
            return (storage, .failure(error))
        }
    }

    /// RFC 7009 §2.2: a `200` is the whole answer, and "the content of the response body is
    /// ignored by the client". A conforming server sends no token response to decode — so a
    /// disconnect that reported revocation failures while still reading the answer as a token
    /// response would report every success as one.
    @Test("A bare 200 from the revocation endpoint is success", arguments: ["", "{}", "revoked"])
    func bareSuccessIsSuccess(body: String) async throws {
        let server = try await RedirectWireServer.start {
            .respond(status: 200, headers: [:], body: body)
        }

        let (storage, result) = try await Self.disconnect(against: server)

        #expect(throws: Never.self) { try result.get() }
        #expect(try await storage.credential(for: .testConnection) == nil)
        let arrived = try #require(server.requests.first)
        #expect(arrived.method == "POST")
        #expect(arrived.body == "token=fixture-refresh&token_type_hint=refresh_token")
        try await server.stop()
    }

    /// RFC 7009 §2.2.1: on a `503` "the client must assume the token still exists".
    @Test("A 503 from the revocation endpoint is reported")
    func unavailableIsReported() async throws {
        let server = try await RedirectWireServer.start {
            .respond(status: 503, headers: ["Retry-After": "120"], body: "")
        }

        let (storage, result) = try await Self.disconnect(against: server)

        let failure = #expect(throws: OAuthRevocationFailed.self) { try result.get() }
        #expect(failure?.step == .revocationRequest)
        #expect(failure?.underlying as? OAuthError == .serverError("HTTP 503"))
        #expect(try await storage.credential(for: .testConnection) == nil)
        try await server.stop()
    }

    @Test("An OAuth error from the revocation endpoint is reported as that error")
    func refusalOnTheWireIsReported() async throws {
        let server = try await RedirectWireServer.start {
            .respond(
                status: 401, headers: ["Content-Type": "application/json"],
                body: #"{"error":"invalid_client","error_description":"unknown client"}"#)
        }

        let (storage, result) = try await Self.disconnect(against: server)

        let failure = #expect(throws: OAuthRevocationFailed.self) { try result.get() }
        #expect(failure?.underlying as? OAuthError == .invalidClient("unknown client"))
        #expect(try await storage.credential(for: .testConnection) == nil)
        try await server.stop()
    }

    @Test("A redirected revocation is reported, and nothing reaches the redirect's destination")
    func redirectedRevocationIsReported() async throws {
        let second = try await RedirectWireServer.start { .answer }
        let location = "\(second.origin)/elsewhere"
        let first = try await RedirectWireServer.start { .redirect(status: 307, location: location) }

        let (storage, result) = try await Self.disconnect(against: first)

        let failure = #expect(throws: OAuthRevocationFailed.self) { try result.get() }
        let refusal = failure?.underlying as? OAuthRedirectRefused
        #expect(refusal?.destination == second.origin)
        #expect(second.requests.isEmpty)
        #expect(try await storage.credential(for: .testConnection) == nil)
        try await first.stop()
        try await second.stop()
    }
}

/// A store that cannot be read and records what it was asked to forget.
actor UnreadableStorage: OAuthClientStorage {

    enum Unreadable: Error, Equatable {
        case corrupt
    }

    private(set) var removals: [ConnectionID] = []

    func credential(for connection: ConnectionID) async throws -> StoredCredential? {
        throw Unreadable.corrupt
    }

    func store(_ credential: StoredCredential, for connection: ConnectionID) async throws {}

    func remove(_ connection: ConnectionID) async throws {
        removals.append(connection)
    }

    func connections() async throws -> [ConnectionID] { [] }
}
