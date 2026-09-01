import Foundation
import Testing
import SwiftOAuthCore
@testable import SwiftOAuthClient

/// Refreshing a token the provider has already rejected.
///
/// ``OAuthConnection/validAccessToken()`` refreshes on a clock: it exchanges when the stored
/// credential is within its margin of expiry, and otherwise hands back what it holds. That is
/// right for the case it was built for, and it cannot help with the case where the *provider*
/// stops honouring a token that still looks valid here — a revoked grant, a clock that drifted,
/// a dynamic client registration that expired underneath the credential it issued.
///
/// In all of those the only evidence is a `401` from an API call, and the only recovery is an
/// exchange the local clock says is unnecessary.
@Suite("Forced refresh")
struct ForcedRefreshTests {

    /// The whole point: an exchange happens even though the stored token has not expired.
    @Test("A valid token is refreshed anyway when forced")
    func refreshesDespiteValidToken() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([
            .tokens(access: "second-access", refresh: "rotated-1", expiresIn: 3_600)
        ])
        try await storage.store(validCredential(at: clock.now), for: .testConnection)
        let connection = makeForcedConnection(storage: storage, transport: transport, clock: clock)

        // The clock says there is nothing to do.
        #expect(try await connection.validAccessToken() == "original-access")
        #expect(await transport.exchangeCount == 0)

        let refreshed = try await connection.refreshedAccessToken()

        #expect(refreshed == "second-access")
        #expect(await transport.exchangeCount == 1, "forcing a refresh did not exchange")
    }

    /// The exchange has to be a refresh-token grant presenting the token on file. Anything
    /// else is a different request that happens to return tokens.
    @Test("The forced exchange presents the stored refresh token")
    func presentsStoredRefreshToken() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([
            .tokens(access: "second-access", refresh: "rotated-1", expiresIn: 3_600)
        ])
        try await storage.store(validCredential(at: clock.now), for: .testConnection)
        let connection = makeForcedConnection(storage: storage, transport: transport, clock: clock)

        _ = try await connection.refreshedAccessToken()

        let sent = try #require(await transport.requests.first)
        #expect(sent["grant_type"] == "refresh_token")
        #expect(sent["refresh_token"] == "original-refresh")
    }

    /// A forced refresh persists like any other. A token returned but not stored would work
    /// for this process and be gone at the next launch, taking the rotation with it — the
    /// provider has already invalidated what was there before.
    @Test("The forced refresh is stored, not just returned")
    func storesTheResult() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([
            .tokens(access: "second-access", refresh: "rotated-1", expiresIn: 3_600)
        ])
        try await storage.store(validCredential(at: clock.now), for: .testConnection)
        let connection = makeForcedConnection(storage: storage, transport: transport, clock: clock)

        _ = try await connection.refreshedAccessToken()

        let stored = try #require(try await storage.credential(for: .testConnection))
        #expect(stored.accessToken == "second-access")
        #expect(stored.refreshToken == "rotated-1")
        #expect(stored.previousRefreshToken == "original-refresh",
                "the replaced token was not recorded; a lost rotation is now indistinguishable from a revoked grant")
    }

    /// The hazard this package exists for. Two forced refreshes must not both exchange: the
    /// second invalidates the first's rotated refresh token, and one caller is left holding a
    /// credential the provider has forgotten.
    @Test("Concurrent forced refreshes exchange exactly once")
    func concurrentForcedRefreshesExchangeOnce() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([
            .tokens(access: "second-access", refresh: "rotated-1", expiresIn: 3_600)
        ])
        try await storage.store(validCredential(at: clock.now), for: .testConnection)
        let connection = makeForcedConnection(storage: storage, transport: transport, clock: clock)

        await transport.holdNextExchange()
        async let first = connection.refreshedAccessToken()
        // Sequenced on the event rather than on elapsed time, as elsewhere in this suite.
        await transport.waitUntilExchangeStarted()
        async let second = connection.refreshedAccessToken()
        await transport.release()

        let tokens = try await [first, second]
        #expect(tokens == ["second-access", "second-access"])

        let exchanges = await transport.exchangeCount
        #expect(exchanges == 1,
                "made \(exchanges) exchanges; a second would have killed the first's token")
    }

    /// A forced refresh arriving while an ordinary one is in flight joins it rather than
    /// starting a second. The exchange already running is producing a fresh token; racing it
    /// would invalidate the token it is about to return.
    @Test("A forced refresh joins an ordinary one already in flight")
    func joinsAnInFlightRefresh() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([
            .tokens(access: "second-access", refresh: "rotated-1", expiresIn: 3_600)
        ])
        try await storage.store(expiredForcedCredential(at: clock.now), for: .testConnection)
        let connection = makeForcedConnection(storage: storage, transport: transport, clock: clock)

        await transport.holdNextExchange()
        async let ordinary = connection.validAccessToken()
        await transport.waitUntilExchangeStarted()
        async let forced = connection.refreshedAccessToken()
        await transport.release()

        let tokens = try await [ordinary, forced]
        #expect(tokens == ["second-access", "second-access"])
        #expect(await transport.exchangeCount == 1)
    }

    /// Nothing stored is not something to refresh. Reported as not connected, the same as
    /// asking for a valid token — a caller has one condition to handle, not two.
    @Test("Forcing a refresh with nothing stored reports not connected")
    func nothingStoredReportsNotConnected() async throws {
        let connection = makeForcedConnection(
            storage: InMemoryClientStorage(),
            transport: StubTransport([]),
            clock: TestClock())

        await #expect(throws: ConnectionError.notConnected) {
            try await connection.refreshedAccessToken()
        }
    }

    /// A provider that refuses the refresh token must say so as *re-authorization required*,
    /// not as a generic failure. This is the signal a caller acts on: forcing a refresh after
    /// a `401` either produces a token or establishes that no token is obtainable without the
    /// user, and those need opposite responses. `hadPreviousToken` distinguishes a revoked
    /// grant from a lost rotation, which need opposite responses again.
    @Test("A refused refresh reports that re-authorization is required")
    func refusedRefreshSurfacesError() async throws {
        let clock = TestClock()
        let storage = InMemoryClientStorage()
        let transport = StubTransport([.failure(.invalidGrant(nil))])
        try await storage.store(validCredential(at: clock.now), for: .testConnection)
        let connection = makeForcedConnection(storage: storage, transport: transport, clock: clock)

        await #expect(throws: ConnectionError.reauthorizationRequired(hadPreviousToken: false)) {
            try await connection.refreshedAccessToken()
        }
    }
}

// MARK: - Helpers

private func makeForcedConnection(
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

/// A credential with an hour left on it — nothing an ordinary refresh would touch.
private func validCredential(at now: Date) -> StoredCredential {
    StoredCredential(
        accessToken: "original-access",
        refreshToken: "original-refresh",
        accessExpiry: now.addingTimeInterval(3_600),
        rotatedAt: now)
}

/// A credential an ordinary refresh *would* touch, for the joining test.
private func expiredForcedCredential(at now: Date) -> StoredCredential {
    StoredCredential(
        accessToken: "original-access",
        refreshToken: "original-refresh",
        accessExpiry: now.addingTimeInterval(-1),
        rotatedAt: now.addingTimeInterval(-3_600))
}
