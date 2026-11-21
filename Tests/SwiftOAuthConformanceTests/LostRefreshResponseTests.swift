import Foundation
import Testing
import SwiftOAuthCore
@testable import SwiftOAuthClient
import SwiftOAuthProvider

/// The measurement harness for the refresh grace window
/// (`project/plans/proposals/2026-11-20_RefreshGraceWindow.md` §4), for the package's own client.
///
/// A real `OAuthServer` and a real `OAuthConnection`, with a wire that lets the server **process**
/// a refresh and then loses the response: the server has spent the refresh token and issued a
/// successor, and the client never learns of it. What the client does next is what the window has
/// to cover.
///
/// What this establishes, and what it does not:
/// - It runs deterministically on a hand-moved clock, so it can sweep the retry delay and find
///   the boundary exactly. That is the right instrument for "does the window do what it says".
/// - The *distribution* of retry delays in the wild is not here. `OAuthConnection` has no retry of
///   its own: after a lost response its stored credential still holds the spent token, and the
///   next `validAccessToken()` presents it. That moment is the caller's, not the library's, so the
///   only delay this client contributes is how long it takes to notice the loss.
@Suite("Conformance — a lost refresh response, against the grace window")
struct LostRefreshResponseTests {

    static let issuer = "https://mcp.example.com"

    /// The refresh response is lost after the server has processed the request.
    struct ResponseLost: Error {}

    /// Passes everything to the provider, and for the next `drops` token exchanges throws after
    /// the provider has answered, taking `detectionDelay` of the shared clock to notice: a
    /// connection that resets at once is 0; one that hangs until the transport gives up is the
    /// transport's timeout.
    actor LossyWire: TokenTransport {
        private let inner: ProviderOverHTTP
        private let clock: SharedClock
        private let detectionDelay: TimeInterval
        private var drops = 0
        private(set) var processed = 0

        init(inner: ProviderOverHTTP, clock: SharedClock, detectionDelay: TimeInterval) {
            self.inner = inner
            self.clock = clock
            self.detectionDelay = detectionDelay
        }

        func dropNext(_ count: Int) { drops = count }

        func exchange(
            endpoint: URL, parameters: [String: String],
            credentials: ClientCredentials, method: ClientAuthenticationMethod
        ) async throws -> TokenResponse {
            let answer = try await inner.exchange(
                endpoint: endpoint, parameters: parameters, credentials: credentials, method: method)
            processed += 1
            if drops > 0 {
                drops -= 1
                clock.advance(detectionDelay)
                throw ResponseLost()
            }
            return answer
        }

        func revoke(
            endpoint: URL, parameters: [String: String],
            credentials: ClientCredentials, method: ClientAuthenticationMethod
        ) async throws {
            try await inner.revoke(
                endpoint: endpoint, parameters: parameters, credentials: credentials, method: method)
        }
    }

    /// A signed-in client whose next refresh response will be lost, and whose last refresh the
    /// server has already processed: it holds the spent token.
    struct Scene {
        let server: OAuthServer
        let connection: OAuthConnection
        let storage: InMemoryClientStorage
        let connectionID: ConnectionID
        let clock: SharedClock
        let wire: LossyWire
        /// The refresh token the client holds, which the server has spent.
        let spent: String
        /// An access token of the same grant, to ask the server whether the grant is alive.
        let originalAccess: String
    }

    private static func scene(grace: TimeInterval, detectionDelay: TimeInterval = 0) async throws -> Scene {
        let clock = SharedClock()
        let server = OAuthServer(
            storage: try OAuthStorage(path: ":memory:"), issuer: issuer,
            scopesSupported: ["mcp:tools"],
            served: try ServedCapabilities(
                grantTypes: [.authorizationCode, .refreshToken, .deviceCode],
                clientAuthenticationMethods: [.none, .clientSecretBasic],
                deviceAuthorization: "\(issuer)/device_authorization"),
            resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true),
            rotationPolicy: .rotating,
            rotationGracePeriod: grace,
            now: { clock.now })
        let wire = LossyWire(
            inner: ProviderOverHTTP(handler: OAuthHTTPHandler(server: server)),
            clock: clock, detectionDelay: detectionDelay)

        let handler = OAuthHTTPHandler(server: server)
        let registration = await handler.handleRegistrationRequest(body: """
            {"client_name":"Terminal","redirect_uris":[],
             "grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],
             "token_endpoint_auth_method":"none"}
            """)
        let registered: SwiftOAuthProvider.ClientRegistrationResponse = try ProviderOverHTTP.read(registration)
        let credentials = ClientCredentials(
            environment: "test", clientID: registered.clientId, clientSecret: "")
        let issued = try await server.authorizeDevice(clientId: credentials.clientID, scope: "mcp:tools")
        try await server.approveDeviceCode(userCode: issued.userCode, subject: "ada")
        clock.advance(6)
        let tokens = try await server.redeemDeviceCode(issued.deviceCode, clientId: credentials.clientID)
        let refreshToken = try #require(tokens.refreshToken)

        let storage = InMemoryClientStorage()
        let connectionID = ConnectionID(tenant: "t", provider: "mcp", account: "ada")
        try await storage.store(
            StoredCredential(
                accessToken: tokens.accessToken, refreshToken: refreshToken,
                accessExpiry: clock.now.addingTimeInterval(-1), rotatedAt: clock.now),
            for: connectionID)
        let connection = OAuthConnection(
            configuration: ProviderConfiguration(
                identifier: "mcp",
                authorizationEndpoint: try #require(URL(string: "\(issuer)/authorize")),
                tokenEndpoint: try #require(URL(string: "\(issuer)/token")),
                scope: "mcp:tools", authenticationMethod: .none),
            credentials: credentials, storage: storage, connection: connectionID,
            transport: wire, now: { clock.now })

        // The refresh whose response is lost.
        await wire.dropNext(1)
        do {
            _ = try await connection.validAccessToken()
            Issue.record("the refresh should have been lost")
        } catch is ResponseLost {
            // expected
        }
        let stored = try #require(try await storage.credential(for: connectionID))
        #expect(stored.refreshToken == refreshToken,
                "the client learned nothing, so it still holds the token the server spent")
        #expect(await wire.processed == 1, "the server did process the refresh")
        return Scene(
            server: server, connection: connection, storage: storage, connectionID: connectionID,
            clock: clock, wire: wire, spent: refreshToken, originalAccess: tokens.accessToken)
    }

    private static func isReauthorization(_ error: any Error) -> Bool {
        if case .reauthorizationRequired = error as? ConnectionError { return true }
        return false
    }

    // MARK: - The boundary

    /// Delays in seconds between the lost response being noticed and the client's next call.
    static let retryDelays: [TimeInterval] = [0, 1, 5, 30, 59, 60, 61, 120]

    @Test("With a 60 s window the client recovers exactly when its retry is inside it",
          arguments: retryDelays)
    func boundary(delay: TimeInterval) async throws {
        let s = try await Self.scene(grace: 60)
        s.clock.advance(delay)

        if delay <= 60 {
            let access = try await s.connection.validAccessToken()
            #expect(try await s.server.introspect(token: access).active)
            let stored = try #require(try await s.storage.credential(for: s.connectionID))
            #expect(stored.refreshToken != s.spent, "the client stored the regranted token")
            #expect(try await s.server.introspect(token: s.originalAccess).active,
                    "the grant survived, so is not ended by the retry")
        } else {
            await #expect { _ = try await s.connection.validAccessToken() }
                throws: { Self.isReauthorization($0) }
            #expect(try await s.server.introspect(token: s.originalAccess).active == false,
                    "a retry outside the window ends the grant, as in beta.11")
        }
    }

    @Test("A recovered client keeps refreshing: the next rotation works from what it stored")
    func recoveredClientKeepsRotating() async throws {
        let s = try await Self.scene(grace: 60)
        s.clock.advance(5)
        _ = try await s.connection.validAccessToken()

        for _ in 1...2 {
            let stored = try #require(try await s.storage.credential(for: s.connectionID))
            try await s.storage.store(
                StoredCredential(
                    accessToken: stored.accessToken, refreshToken: stored.refreshToken,
                    accessExpiry: s.clock.now.addingTimeInterval(-1),
                    previousRefreshToken: stored.previousRefreshToken, rotatedAt: stored.rotatedAt),
                for: s.connectionID)
            let access = try await s.connection.validAccessToken()
            #expect(try await s.server.introspect(token: access).active)
        }
    }

    @Test("With no window a lost response ends the grant however fast the client retries (beta.11)")
    func noWindowIsBetaEleven() async throws {
        let s = try await Self.scene(grace: 0)
        await #expect { _ = try await s.connection.validAccessToken() }
            throws: { Self.isReauthorization($0) }
        #expect(try await s.server.introspect(token: s.originalAccess).active == false)
    }

    // MARK: - Noticing the loss takes time

    /// The window runs from when the *server* spent the token. A connection that hangs is not
    /// noticed until the transport's timeout, so the client's earliest possible retry is that
    /// long after the spend: a window shorter than that can never help it.
    @Test("A connection that hangs for the transport timeout is only covered by a window longer than it",
          arguments: [(window: 30.0, recovers: false), (window: 59.0, recovers: false),
                      (window: 61.0, recovers: true), (window: 120.0, recovers: true)])
    func hungConnection(window: TimeInterval, recovers: Bool) async throws {
        let timeout = CredentialRequest.isolatedConfiguration().timeoutIntervalForRequest
        let s = try await Self.scene(grace: window, detectionDelay: timeout)
        // The caller retries at once: the best case for the window.
        if recovers {
            let access = try await s.connection.validAccessToken()
            #expect(try await s.server.introspect(token: access).active)
        } else {
            await #expect { _ = try await s.connection.validAccessToken() }
                throws: { Self.isReauthorization($0) }
        }
    }

    @Test("The default token session gives up after 60 s of silence, which is what the window is sized against")
    func defaultTransportTimeout() {
        // Pinned, not assumed: if the package sets its own timeout the sizing in the proposal
        // (§4) has to be redone, and this is where that is noticed.
        #expect(CredentialRequest.isolatedConfiguration().timeoutIntervalForRequest == 60)
    }
}
