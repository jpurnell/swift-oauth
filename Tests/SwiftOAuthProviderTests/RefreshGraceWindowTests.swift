import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// The refresh-token grace window: `project/plans/proposals/2026-11-20_RefreshGraceWindow.md`.
///
/// RFC 9700 §4.14.2 revokes the grant when a spent refresh token is presented, and accepts that
/// the server "cannot determine which party" presented it. A client that lost the response to
/// its refresh is indistinguishable from a thief, so it loses its grant. The window is this
/// package's own mitigation, not RFC text, so each expectation below is the rule the proposal
/// states, written before the code.
///
/// The rule: a spent token is accepted again when (1) it was spent no more than the grace period
/// ago, (2) by the client it was issued to, (3) its successor has not itself been presented. The
/// window is anchored to the first spend and does not slide.
@Suite("Refresh-token grace window")
struct RefreshGraceWindowTests {

    static let issuer = "https://auth.example.com"

    /// A clock a test advances by hand, so the window is judged without waiting for it.
    final class Clock: Sendable {
        private let instant: Guarded<Date>
        init() { instant = Guarded(Date()) }
        var now: Date { instant.withLock { $0 } }
        func advance(by seconds: TimeInterval) {
            instant.withLock { $0 = $0.addingTimeInterval(seconds) }
        }
    }

    private static func makeServer(
        _ kind: StoreKind, grace: TimeInterval, policy: RefreshTokenRotationPolicy = .rotating,
        clock: Clock
    ) throws -> (OAuthServer, any OAuthProviderStorage) {
        let storage = try kind.makeStore()
        let served = try ServedCapabilities(
            grantTypes: [.authorizationCode, .refreshToken],
            clientAuthenticationMethods: [.clientSecretBasic, .clientSecretPost, .none])
        let server = OAuthServer(
            storage: storage, issuer: issuer, scopesSupported: ["read", "write"], served: served,
            resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true),
            rotationPolicy: policy,
            rotationGracePeriod: grace,
            now: { clock.now })
        return (server, storage)
    }

    private static func registerPublicClient(_ server: OAuthServer) async throws -> String {
        try await server.registerClient(ClientRegistrationRequest(
            clientName: "App", redirectUris: ["https://app.example.com/cb"],
            grantTypes: ["authorization_code", "refresh_token"],
            tokenEndpointAuthMethod: "none")).clientId
    }

    private static func issue(
        _ server: OAuthServer, clientId: String, subject: String? = "alice"
    ) async throws -> TokenResponse {
        let verifier = PKCE.generateCodeVerifier()
        let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)
        let response = try await server.handleAuthorizationRequest(
            AuthorizationRequest(
                responseType: "code", clientId: clientId,
                redirectUri: "https://app.example.com/cb", scope: "read", state: nil,
                codeChallenge: challenge, codeChallengeMethod: "S256"),
            subject: subject)
        return try await server.handleTokenRequest(TokenRequest(
            grantType: "authorization_code", code: response.code,
            redirectUri: "https://app.example.com/cb", clientId: clientId, clientSecret: nil,
            codeVerifier: verifier, refreshToken: nil))
    }

    private static func refresh(
        _ server: OAuthServer, clientId: String, token: String
    ) async throws -> TokenResponse {
        try await server.handleTokenRequest(TokenRequest(
            grantType: "refresh_token", code: nil, redirectUri: nil, clientId: clientId,
            clientSecret: nil, codeVerifier: nil, refreshToken: token))
    }

    private static func isInvalidGrant(_ error: any Error) -> Bool {
        if case .invalidGrant = error as? OAuthError { return true }
        return false
    }

    /// A grant whose first refresh response was "lost": the client holds `original`, the server
    /// has spent it, and `lost` is the successor nobody received.
    private static func lostResponse(
        _ kind: StoreKind, grace: TimeInterval = 30
    ) async throws -> (server: OAuthServer, storage: any OAuthProviderStorage, clock: Clock,
                       client: String, original: String, lost: TokenResponse) {
        let clock = Clock()
        let (server, storage) = try makeServer(kind, grace: grace, clock: clock)
        let client = try await registerPublicClient(server)
        let first = try await issue(server, clientId: client)
        let original = try #require(first.refreshToken)
        let lost = try await refresh(server, clientId: client, token: original)
        return (server, storage, clock, client, original, lost)
    }

    // MARK: - The retry the window exists for

    @Test("A retry inside the window gets a working pair under the same grant",
          arguments: StoreKind.allCases)
    func retryInsideWindowIsGranted(store kind: StoreKind) async throws {
        let s = try await Self.lostResponse(kind)
        s.clock.advance(by: 5)

        let retry = try await Self.refresh(s.server, clientId: s.client, token: s.original)
        let successor = try #require(retry.refreshToken)

        #expect(successor != s.original)
        #expect(try await s.server.introspect(token: retry.accessToken).active)
        // The pair works: the successor refreshes, and the grant is intact.
        _ = try await Self.refresh(s.server, clientId: s.client, token: successor)
    }

    @Test("A regrant keeps the original's scope, subject, grant and expiry",
          arguments: StoreKind.allCases)
    func regrantCarriesWhatTheOriginalHad(store kind: StoreKind) async throws {
        let s = try await Self.lostResponse(kind)
        let lostToken = try #require(s.lost.refreshToken)
        let lostInfo = try #require(try await s.storage.getRefreshTokenInfo(token: lostToken))
        s.clock.advance(by: 5)

        let retry = try await Self.refresh(s.server, clientId: s.client, token: s.original)
        let retryToken = try #require(retry.refreshToken)
        let after = try #require(try await s.storage.getRefreshTokenInfo(token: retryToken))

        #expect(after.scope == "read" && after.subject == "alice")
        #expect(after.grantId == lostInfo.grantId)
        #expect(after.expiresAt == lostInfo.expiresAt, "a retry must not extend what the user agreed to")
        #expect(retry.scope == "read")
    }

    @Test("The successor nobody received is spent: presenting it revokes the grant",
          arguments: StoreKind.allCases)
    func theLostSuccessorIsSpent(store kind: StoreKind) async throws {
        let s = try await Self.lostResponse(kind)
        s.clock.advance(by: 5)
        let retry = try await Self.refresh(s.server, clientId: s.client, token: s.original)
        let live = try #require(retry.refreshToken)

        // Whoever holds the first successor is not the client that retried. A plain revoke would
        // read as "unknown token" and leave the grant alive for the thief; a spent token reads as
        // reuse and ends it.
        let lostToken = try #require(s.lost.refreshToken)
        await #expect { _ = try await Self.refresh(s.server, clientId: s.client, token: lostToken) }
            throws: { Self.isInvalidGrant($0) }
        await #expect { _ = try await Self.refresh(s.server, clientId: s.client, token: live) }
            throws: { Self.isInvalidGrant($0) }
        #expect(try await s.server.introspect(token: retry.accessToken).active == false)
    }

    // MARK: - What must still be refused

    @Test("A retry after the window is a replay: the grant is revoked",
          arguments: StoreKind.allCases)
    func retryAfterWindowIsReplay(store kind: StoreKind) async throws {
        let s = try await Self.lostResponse(kind, grace: 30)
        s.clock.advance(by: 31)

        await #expect { _ = try await Self.refresh(s.server, clientId: s.client, token: s.original) }
            throws: { Self.isInvalidGrant($0) }
        // Revoked, not merely refused: the successor nobody received is dead too.
        let lostToken = try #require(s.lost.refreshToken)
        await #expect { _ = try await Self.refresh(s.server, clientId: s.client, token: lostToken) }
            throws: { Self.isInvalidGrant($0) }
        #expect(try await s.server.introspect(token: s.lost.accessToken).active == false)
    }

    @Test("A retry after the successor was used is reuse: the window does not apply",
          arguments: StoreKind.allCases)
    func retryAfterSuccessorUsedIsReuse(store kind: StoreKind) async throws {
        let s = try await Self.lostResponse(kind)
        // The client did receive the first response and used it. Inside the window, but the
        // successor has been presented, so this is no lost response.
        let usedToken = try #require(s.lost.refreshToken)
        let next = try await Self.refresh(s.server, clientId: s.client, token: usedToken)
        s.clock.advance(by: 5)

        await #expect { _ = try await Self.refresh(s.server, clientId: s.client, token: s.original) }
            throws: { Self.isInvalidGrant($0) }
        #expect(try await s.server.introspect(token: next.accessToken).active == false)
        let nextToken = try #require(next.refreshToken)
        await #expect { _ = try await Self.refresh(s.server, clientId: s.client, token: nextToken) }
            throws: { Self.isInvalidGrant($0) }
    }

    @Test("A different client presenting the spent token inside the window changes nothing",
          arguments: StoreKind.allCases)
    func anotherClientCannotUseTheWindow(store kind: StoreKind) async throws {
        let s = try await Self.lostResponse(kind)
        let other = try await Self.registerPublicClient(s.server)
        s.clock.advance(by: 5)

        await #expect { _ = try await Self.refresh(s.server, clientId: other, token: s.original) }
            throws: { Self.isInvalidGrant($0) }
        // The owner's grant is untouched: its successor still refreshes.
        let ownersToken = try #require(s.lost.refreshToken)
        _ = try await Self.refresh(s.server, clientId: s.client, token: ownersToken)
    }

    // MARK: - The window's shape

    @Test("The window does not slide: it is measured from the first spend",
          arguments: StoreKind.allCases)
    func windowDoesNotSlide(store kind: StoreKind) async throws {
        let s = try await Self.lostResponse(kind, grace: 30)

        s.clock.advance(by: 20)
        _ = try await Self.refresh(s.server, clientId: s.client, token: s.original)
        // 40 s after the first spend, 20 s after the retry. A sliding window would allow this.
        s.clock.advance(by: 20)
        await #expect { _ = try await Self.refresh(s.server, clientId: s.client, token: s.original) }
            throws: { Self.isInvalidGrant($0) }
    }

    @Test("Two retries inside the window both succeed, and leave exactly one live refresh token",
          arguments: StoreKind.allCases)
    func repeatedRetriesChain(store kind: StoreKind) async throws {
        let s = try await Self.lostResponse(kind, grace: 30)
        s.clock.advance(by: 5)
        let one = try await Self.refresh(s.server, clientId: s.client, token: s.original)
        s.clock.advance(by: 5)
        let two = try await Self.refresh(s.server, clientId: s.client, token: s.original)

        let tokens = [s.lost.refreshToken, one.refreshToken, two.refreshToken].compactMap { $0 }
        var live = 0
        for token in tokens where try await s.storage.getRefreshTokenInfo(token: token) != nil { live += 1 }
        #expect(live == 1, "each retry spends the successor before it, so one token is live")
        let latest = try #require(two.refreshToken)
        let latestInfo = try #require(try await s.storage.getRefreshTokenInfo(token: latest), "and it is the latest")
        #expect(latestInfo.clientId == s.client)
    }

    @Test("Concurrent retries leave exactly one live refresh token",
          arguments: StoreKind.allCases)
    func concurrentRetries(store kind: StoreKind) async throws {
        let s = try await Self.lostResponse(kind, grace: 30)
        s.clock.advance(by: 5)
        let server = s.server, client = s.client, original = s.original

        let results = await withTaskGroup(of: TokenResponse?.self) { group in
            for _ in 0..<8 {
                group.addTask { try? await Self.refresh(server, clientId: client, token: original) }
            }
            var granted: [TokenResponse] = []
            for await result in group { if let result { granted.append(result) } }
            return granted
        }

        #expect(results.isEmpty == false, "at least one retry inside the window is granted")
        var live = 0
        for response in results {
            if let token = response.refreshToken,
               try await s.storage.getRefreshTokenInfo(token: token) != nil { live += 1 }
        }
        #expect(live <= 1, "never two live refresh tokens for one grant")
    }

    // MARK: - Configuration

    @Test("A period of 0 is beta.11: a retry is a replay at once", arguments: StoreKind.allCases)
    func zeroIsOff(store kind: StoreKind) async throws {
        let s = try await Self.lostResponse(kind, grace: 0)
        await #expect { _ = try await Self.refresh(s.server, clientId: s.client, token: s.original) }
            throws: { Self.isInvalidGrant($0) }
        #expect(try await s.server.introspect(token: s.lost.accessToken).active == false)
    }

    @Test("A negative period is off, not an error", arguments: StoreKind.allCases)
    func negativeIsOff(store kind: StoreKind) async throws {
        let s = try await Self.lostResponse(kind, grace: -10)
        await #expect { _ = try await Self.refresh(s.server, clientId: s.client, token: s.original) }
            throws: { Self.isInvalidGrant($0) }
    }

    @Test("A period above 300 s is clamped to 300 s", arguments: StoreKind.allCases)
    func periodIsClamped(store kind: StoreKind) async throws {
        let inside = try await Self.lostResponse(kind, grace: 10_000)
        inside.clock.advance(by: 299)
        _ = try await Self.refresh(inside.server, clientId: inside.client, token: inside.original)

        let outside = try await Self.lostResponse(kind, grace: 10_000)
        outside.clock.advance(by: 301)
        await #expect { _ = try await Self.refresh(outside.server, clientId: outside.client, token: outside.original) }
            throws: { Self.isInvalidGrant($0) }
    }

    @Test("`.reusable` ignores the period: nothing is spent, so nothing is re-granted",
          arguments: StoreKind.allCases)
    func reusableIgnoresIt(store kind: StoreKind) async throws {
        let clock = Clock()
        let (server, _) = try Self.makeServer(kind, grace: 30, policy: .reusable, clock: clock)
        let client = try await Self.registerPublicClient(server)
        let first = try await Self.issue(server, clientId: client)
        let original = try #require(first.refreshToken)

        let again = try await Self.refresh(server, clientId: client, token: original)
        #expect(again.refreshToken == original)
    }
}
