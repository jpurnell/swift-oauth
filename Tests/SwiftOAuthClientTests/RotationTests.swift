import Foundation
import Testing
import SwiftOAuthCore
@testable import SwiftOAuthClient

/// The three hazards this package exists to handle. Each ends, if unhandled, with a user
/// locked out of their own data rather than an error anyone can read.
@Suite("Rotation — concurrent refresh")
struct ConcurrentRefreshTests {

    /// Two callers find an expired token and both refresh. The second exchange invalidates
    /// the first's new refresh token, and whichever stored last wins — the other holds a
    /// credential the provider has already forgotten.
    ///
    /// One exchange, not two, is the whole requirement.
    @Test("Concurrent callers trigger exactly one exchange")
    func oneRefreshForConcurrentCallers() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([
            .tokens(access: "refreshed", refresh: "rotated-1", expiresIn: 3_600)
        ])
        try await storage.store(expiredCredential(at: clock.now), for: .testConnection)

        let connection = makeConnection(storage: storage, transport: transport, clock: clock)

        // Hold the exchange so the second caller arrives while the first is in flight.
        await transport.holdNextExchange()
        async let first = connection.validAccessToken()

        // Sequenced on the event, not on elapsed time: sleeping for a plausible interval
        // passes on an idle machine and fails on a loaded one, which is the fragility this
        // very suite exists to check for.
        await transport.waitUntilExchangeStarted()
        async let second = connection.validAccessToken()

        await transport.release()

        let tokens = try await [first, second]
        #expect(tokens == ["refreshed", "refreshed"])

        let exchanges = await transport.exchangeCount
        #expect(exchanges == 1,
                "made \(exchanges) exchanges; a second would have killed the first's token")
    }

    /// After a refresh completes, a later caller must not exchange again — the stored token
    /// is now valid.
    @Test("A later caller uses the stored token rather than refreshing again")
    func laterCallerReusesToken() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([
            .tokens(access: "refreshed", refresh: "rotated-1", expiresIn: 3_600)
        ])
        try await storage.store(expiredCredential(at: clock.now), for: .testConnection)
        let connection = makeConnection(storage: storage, transport: transport, clock: clock)

        _ = try await connection.validAccessToken()
        let again = try await connection.validAccessToken()

        #expect(again == "refreshed")
        let exchanges = await transport.exchangeCount
        #expect(exchanges == 1)
    }
}

@Suite("Rotation — persistence")
struct PersistenceTests {

    /// The credential must be written before the new access token is used, so a crash
    /// between the two costs a request rather than the connection.
    @Test("The new credential is stored before the token is returned")
    func credentialPersistedBeforeUse() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([
            .tokens(access: "refreshed", refresh: "rotated-1", expiresIn: 3_600)
        ])
        try await storage.store(expiredCredential(at: clock.now), for: .testConnection)
        let connection = makeConnection(storage: storage, transport: transport, clock: clock)

        let token = try await connection.validAccessToken()
        let stored = try #require(try await storage.credential(for: .testConnection))
        #expect(stored.accessToken == token)
        #expect(stored.refreshToken == "rotated-1")
    }

    /// The token just replaced is already dead at the provider, so a failed write would
    /// lose the connection. The new credential comes back inside the error, giving a caller
    /// something to retry with.
    @Test("A failed write returns the credential rather than losing it")
    func failedWriteReturnsCredential() async throws {
        let clock = TestClock()
        let storage = FailingClientStorage()
        let transport = StubTransport([
            .tokens(access: "refreshed", refresh: "rotated-1", expiresIn: 3_600)
        ])
        try await storage.store(expiredCredential(at: clock.now), for: .testConnection)
        await storage.failNextStore()

        let connection = makeConnection(storage: storage, transport: transport, clock: clock)

        do {
            _ = try await connection.validAccessToken()
            Issue.record("the failed write was not reported")
        } catch let error as ConnectionError {
            guard case .storageFailed(let recovered) = error else {
                Issue.record("wrong error: \(error)")
                return
            }
            #expect(recovered.refreshToken == "rotated-1",
                    "the credential was lost, and with it the connection")
            #expect(recovered.previousRefreshToken == "original-refresh")
        }
    }

    /// The predecessor is retained because a later `invalid_grant` is otherwise ambiguous.
    @Test("The replaced token is retained")
    func previousTokenRetained() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([
            .tokens(access: "refreshed", refresh: "rotated-1", expiresIn: 3_600)
        ])
        try await storage.store(expiredCredential(at: clock.now), for: .testConnection)
        let connection = makeConnection(storage: storage, transport: transport, clock: clock)

        _ = try await connection.validAccessToken()
        let stored = try #require(try await storage.credential(for: .testConnection))
        #expect(stored.previousRefreshToken == "original-refresh")
        #expect(stored.rotatedAt == clock.now)
    }

    /// A provider that does not rotate omits the refresh token, and the existing one stays
    /// valid. Treating that as "no token" would break every non-rotating provider.
    @Test("A provider that does not rotate keeps its existing refresh token")
    func nonRotatingProvider() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([
            .tokens(access: "refreshed", refresh: nil, expiresIn: 3_600)
        ])
        try await storage.store(expiredCredential(at: clock.now), for: .testConnection)
        let connection = makeConnection(storage: storage, transport: transport, clock: clock)

        _ = try await connection.validAccessToken()
        let stored = try #require(try await storage.credential(for: .testConnection))
        #expect(stored.refreshToken == "original-refresh")
    }
}

@Suite("Rotation — telling revocation from a lost rotation")
struct ReauthorizationTests {

    /// `invalid_grant` means either "the user revoked you" — ask again — or "you presented a
    /// token that was already replaced" — recoverable. Opposite remedies, and only the
    /// presence of a predecessor distinguishes them.
    @Test("A rejected grant reports whether a predecessor existed")
    func rejectedGrantReportsHistory() async throws {
        for hadPrevious in [true, false] {
            let clock = TestClock()
            let storage = InMemoryClientStorage()
            let transport = StubTransport([.failure(.invalidGrant("Token revoked"))])
            try await storage.store(
                expiredCredential(at: clock.now,
                                  previous: hadPrevious ? "an-older-token" : nil),
                for: .testConnection)
            let connection = makeConnection(storage: storage, transport: transport, clock: clock)

            do {
                _ = try await connection.validAccessToken()
                Issue.record("a revoked grant was not reported")
            } catch let error as ConnectionError {
                #expect(error == .reauthorizationRequired(hadPreviousToken: hadPrevious),
                        "got \(error) for hadPrevious=\(hadPrevious)")
            }
        }
    }

    /// A transient failure is not a revocation, and must not send the user through
    /// authorisation again.
    @Test("A transient failure is not treated as revocation")
    func transientFailureIsNotRevocation() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([.failure(.temporarilyUnavailable(nil))])
        try await storage.store(expiredCredential(at: clock.now), for: .testConnection)
        let connection = makeConnection(storage: storage, transport: transport, clock: clock)

        do {
            _ = try await connection.validAccessToken()
            Issue.record("the failure was swallowed")
        } catch let error as OAuthError {
            #expect(error.isTransient)
            #expect(!error.requiresReauthorization)
        }
    }
}

// MARK: - Helpers

private func makeConnection(
    storage: any OAuthClientStorage,
    transport: any TokenTransport,
    clock: TestClock
) -> OAuthConnection {
    OAuthConnection(
        configuration: .testProvider,
        credentials: .testCredentials,
        storage: storage,
        connection: .testConnection,
        transport: transport,
        now: { clock.now })
}

private func expiredCredential(at now: Date, previous: String? = nil) -> StoredCredential {
    StoredCredential(
        accessToken: "original-access",
        refreshToken: "original-refresh",
        // Already past, so any call refreshes.
        accessExpiry: now.addingTimeInterval(-1),
        previousRefreshToken: previous,
        rotatedAt: now.addingTimeInterval(-3_600))
}
