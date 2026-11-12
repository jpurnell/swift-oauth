import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// RFC 9700 §2.2.2 and §4.14.2 (refresh-token rotation and reuse detection) and §4.2.4 (a
/// replayed authorization code): Gap C of the spec-gaps proposal.
///
/// §4.14.2: "the authorization server issues a new refresh token with every access token
/// refresh response. The previous refresh token is invalidated but information about the
/// relationship is retained by the authorization server. If a refresh token is compromised and
/// subsequently used by both the attacker and the legitimate client, one of them will present an
/// invalidated refresh token, which will inform the authorization server of the breach. The
/// authorization server cannot determine which party submitted the invalid refresh token, but it
/// will revoke the active refresh token."
///
/// §4.2.4: an authorization code "MUST be invalidated by the authorization server after their
/// first use", and the server "SHOULD revoke all tokens issued previously based on that code".
@Suite("Refresh-token rotation, reuse detection, and code replay")
struct RefreshRotationTests {

    static let issuer = "https://auth.example.com"
    static let resource = URL(string: "https://auth.example.com")

    private static func makeServer(
        _ kind: StoreKind, policy: RefreshTokenRotationPolicy? = nil
    ) throws -> (OAuthServer, any OAuthProviderStorage) {
        let storage = try kind.makeStore()
        let served = try ServedCapabilities(
            grantTypes: [.authorizationCode, .refreshToken],
            clientAuthenticationMethods: [.clientSecretBasic, .clientSecretPost, .none])
        let policyArgument = policy
        let server: OAuthServer
        if let policyArgument {
            server = OAuthServer(
                storage: storage, issuer: issuer, scopesSupported: ["read", "write"], served: served,
                resourceIdentity: .colocated,
                resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true),
                rotationPolicy: policyArgument)
        } else {
            // The default, not an argument: the point of one test is what a caller gets by asking for nothing.
            server = OAuthServer(
                storage: storage, issuer: issuer, scopesSupported: ["read", "write"], served: served,
                resourceIdentity: .colocated,
                resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        }
        return (server, storage)
    }

    private static func registerPublicClient(_ server: OAuthServer) async throws -> String {
        try await server.registerClient(ClientRegistrationRequest(
            clientName: "App", redirectUris: ["https://app.example.com/cb"],
            grantTypes: ["authorization_code", "refresh_token"],
            tokenEndpointAuthMethod: "none")).clientId
    }

    private static func authorize(
        _ server: OAuthServer, clientId: String, subject: String?
    ) async throws -> (code: String, verifier: String) {
        let verifier = PKCE.generateCodeVerifier()
        let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)
        let response = try await server.handleAuthorizationRequest(
            AuthorizationRequest(
                responseType: "code", clientId: clientId,
                redirectUri: "https://app.example.com/cb", scope: "read", state: nil,
                codeChallenge: challenge, codeChallengeMethod: "S256"),
            subject: subject)
        return (response.code, verifier)
    }

    private static func redeem(
        _ server: OAuthServer, clientId: String, code: String, verifier: String
    ) async throws -> TokenResponse {
        try await server.handleTokenRequest(TokenRequest(
            grantType: "authorization_code", code: code,
            redirectUri: "https://app.example.com/cb", clientId: clientId, clientSecret: nil,
            codeVerifier: verifier, refreshToken: nil))
    }

    private static func issue(
        _ server: OAuthServer, clientId: String, subject: String? = "alice"
    ) async throws -> TokenResponse {
        let issued = try await authorize(server, clientId: clientId, subject: subject)
        return try await redeem(server, clientId: clientId, code: issued.code, verifier: issued.verifier)
    }

    private static func refresh(
        _ server: OAuthServer, clientId: String, token: String, resource: [URL] = []
    ) async throws -> TokenResponse {
        try await server.handleTokenRequest(TokenRequest(
            grantType: "refresh_token", code: nil, redirectUri: nil, clientId: clientId,
            clientSecret: nil, codeVerifier: nil, refreshToken: token, resource: resource))
    }

    private static func isInvalidGrant(_ error: any Error) -> Bool {
        if case .invalidGrant = error as? OAuthError { return true }
        return false
    }

    // MARK: - Rotation

    @Test("A refresh returns a different refresh token, and the old one then fails (§4.14.2)",
          arguments: StoreKind.allCases)
    func rotates(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let client = try await Self.registerPublicClient(server)
        let first = try await Self.issue(server, clientId: client)
        let original = try #require(first.refreshToken)

        let second = try await Self.refresh(server, clientId: client, token: original)
        let replacement = try #require(second.refreshToken)

        #expect(replacement != original)
        #expect(try await server.introspect(token: second.accessToken).active)
        // The replacement works, and the old one does not.
        _ = try await Self.refresh(server, clientId: client, token: replacement)
        await #expect { _ = try await Self.refresh(server, clientId: client, token: original) }
            throws: { Self.isInvalidGrant($0) }
    }

    @Test("A refresh token that is never used is not affected by another's rotation",
          arguments: StoreKind.allCases)
    func independentGrantsAreIndependent(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let client = try await Self.registerPublicClient(server)
        let mine = try #require(try await Self.issue(server, clientId: client, subject: "alice").refreshToken)
        let yours = try #require(try await Self.issue(server, clientId: client, subject: "bob").refreshToken)

        _ = try await Self.refresh(server, clientId: client, token: mine)
        // Replaying mine ends alice's grant, not bob's.
        await #expect { _ = try await Self.refresh(server, clientId: client, token: mine) }
            throws: { Self.isInvalidGrant($0) }
        _ = try await Self.refresh(server, clientId: client, token: yours)
    }

    @Test("A rotated refresh token carries the original's scope, subject and expiry, not a fresh lifetime",
          arguments: StoreKind.allCases)
    func carriesWhatTheOriginalHad(store kind: StoreKind) async throws {
        let (server, storage) = try Self.makeServer(kind)
        let client = try await Self.registerPublicClient(server)
        let first = try await Self.issue(server, clientId: client, subject: "alice")
        let original = try #require(first.refreshToken)
        let before = try #require(try await storage.getRefreshTokenInfo(token: original))

        let second = try await Self.refresh(server, clientId: client, token: original)
        let replacement = try #require(second.refreshToken)
        let after = try #require(try await storage.getRefreshTokenInfo(token: replacement))

        #expect(after.clientId == before.clientId)
        #expect(after.scope == before.scope && after.scope == "read")
        #expect(after.subject == "alice")
        #expect(after.expiresAt == before.expiresAt, "rotation must not extend the 90 days a user agreed to")
        let grant = try #require(before.grantId)
        #expect(after.grantId == grant)
        #expect(second.scope == "read")
        let introspected = try await server.introspect(token: second.accessToken)
        #expect(introspected.subject == "alice")
        #expect(introspected.scope == "read")
    }

    @Test("A grant with no subject still rotates, and its replay is still detected",
          arguments: StoreKind.allCases)
    func nilSubjectRotates(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let client = try await Self.registerPublicClient(server)
        let first = try await Self.issue(server, clientId: client, subject: nil)
        let original = try #require(first.refreshToken)

        let second = try await Self.refresh(server, clientId: client, token: original)
        #expect(try #require(second.refreshToken) != original)
        #expect(try await server.introspect(token: second.accessToken).subject == nil)
        await #expect { _ = try await Self.refresh(server, clientId: client, token: original) }
            throws: { Self.isInvalidGrant($0) }
        #expect(try await server.introspect(token: second.accessToken).active == false)
    }

    @Test("The resource indicator on a refresh still sets the access token's audience",
          arguments: StoreKind.allCases)
    func audienceStillComesFromTheRequest(store kind: StoreKind) async throws {
        let resource = try #require(Self.resource)
        let storage = try kind.makeStore()
        let server = OAuthServer(
            storage: storage, issuer: Self.issuer, scopesSupported: ["read"],
            served: .core, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [resource], allowsUnspecified: true))
        let client = try await Self.registerPublicClient(server)
        let original = try #require(try await Self.issue(server, clientId: client).refreshToken)

        let refreshed = try await Self.refresh(
            server, clientId: client, token: original, resource: [resource])

        #expect(try await server.introspect(token: refreshed.accessToken).audience == [resource.absoluteString])
    }

    @Test("A refresh refused for its resource does not spend the token",
          arguments: StoreKind.allCases)
    func refusedResourceDoesNotBurnTheToken(store kind: StoreKind) async throws {
        let storage = try kind.makeStore()
        let server = OAuthServer(
            storage: storage, issuer: Self.issuer, scopesSupported: ["read"],
            served: .core, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let client = try await Self.registerPublicClient(server)
        let original = try #require(try await Self.issue(server, clientId: client).refreshToken)

        let elsewhere = try #require(URL(string: "https://elsewhere.example.com"))
        await #expect(throws: OAuthError.self) {
            _ = try await Self.refresh(server, clientId: client, token: original, resource: [elsewhere])
        }

        _ = try await Self.refresh(server, clientId: client, token: original)
    }

    @Test("Another client cannot spend, or trigger revocation of, a refresh token",
          arguments: StoreKind.allCases)
    func foreignClientHasNoEffect(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let owner = try await Self.registerPublicClient(server)
        let stranger = try await Self.registerPublicClient(server)
        let original = try #require(try await Self.issue(server, clientId: owner).refreshToken)

        await #expect { _ = try await Self.refresh(server, clientId: stranger, token: original) }
            throws: { Self.isInvalidGrant($0) }
        let second = try await Self.refresh(server, clientId: owner, token: original)
        // And the owner's rotated-out token, replayed by the stranger, is not a replay either.
        await #expect { _ = try await Self.refresh(server, clientId: stranger, token: original) }
            throws: { Self.isInvalidGrant($0) }
        #expect(try await server.introspect(token: second.accessToken).active)
        let replacement = try #require(second.refreshToken)
        _ = try await Self.refresh(server, clientId: owner, token: replacement)
    }

    // MARK: - Reuse detection

    @Test("Presenting a rotated-out token revokes the whole grant, the active token included (§4.14.2)",
          arguments: StoreKind.allCases)
    func replayRevokesTheGrant(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let client = try await Self.registerPublicClient(server)
        let first = try await Self.issue(server, clientId: client)
        let original = try #require(first.refreshToken)
        let second = try await Self.refresh(server, clientId: client, token: original)
        let active = try #require(second.refreshToken)
        #expect(try await server.introspect(token: first.accessToken).active)
        #expect(try await server.introspect(token: second.accessToken).active)

        // The attacker (or the client that lost its response) presents the old token.
        await #expect { _ = try await Self.refresh(server, clientId: client, token: original) }
            throws: { Self.isInvalidGrant($0) }

        #expect(try await server.introspect(token: first.accessToken).active == false)
        #expect(try await server.introspect(token: second.accessToken).active == false)
        await #expect { _ = try await Self.refresh(server, clientId: client, token: active) }
            throws: { Self.isInvalidGrant($0) }
    }

    @Test("A replay after several rotations still ends the line",
          arguments: StoreKind.allCases)
    func replayAfterSeveralRotations(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let client = try await Self.registerPublicClient(server)
        let first = try await Self.issue(server, clientId: client)
        let first1 = try #require(first.refreshToken)
        let second = try await Self.refresh(server, clientId: client, token: first1)
        let second1 = try #require(second.refreshToken)
        let third = try await Self.refresh(server, clientId: client, token: second1)

        await #expect { _ = try await Self.refresh(server, clientId: client, token: first1) }
            throws: { Self.isInvalidGrant($0) }

        for token in [first.accessToken, second.accessToken, third.accessToken] {
            #expect(try await server.introspect(token: token).active == false)
        }
        let latest = try #require(third.refreshToken)
        await #expect { _ = try await Self.refresh(server, clientId: client, token: latest) }
            throws: { Self.isInvalidGrant($0) }
    }

    @Test("Of concurrent refreshes with one token, exactly one wins",
          arguments: StoreKind.allCases)
    func concurrentRefreshHasOneWinner(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let client = try await Self.registerPublicClient(server)
        let original = try #require(try await Self.issue(server, clientId: client).refreshToken)

        let winners = await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<12 {
                group.addTask {
                    (try? await Self.refresh(server, clientId: client, token: original)) != nil
                }
            }
            var count = 0
            for await won in group where won { count += 1 }
            return count
        }

        #expect(winners == 1, "\(winners) of 12 concurrent refreshes with one token succeeded")
    }

    // MARK: - Code replay

    @Test("Redeeming an authorization code twice revokes what the first redemption issued (§4.2.4)",
          arguments: StoreKind.allCases)
    func codeReplayRevokesItsTokens(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let client = try await Self.registerPublicClient(server)
        let issued = try await Self.authorize(server, clientId: client, subject: "alice")
        let tokens = try await Self.redeem(
            server, clientId: client, code: issued.code, verifier: issued.verifier)
        let refreshToken = try #require(tokens.refreshToken)
        #expect(try await server.introspect(token: tokens.accessToken).active)

        await #expect { _ = try await Self.redeem(
            server, clientId: client, code: issued.code, verifier: issued.verifier) }
            throws: { Self.isInvalidGrant($0) }

        #expect(try await server.introspect(token: tokens.accessToken).active == false)
        await #expect { _ = try await Self.refresh(server, clientId: client, token: refreshToken) }
            throws: { Self.isInvalidGrant($0) }
    }

    @Test("A code nobody issued revokes nothing, and another code's tokens are left",
          arguments: StoreKind.allCases)
    func unknownCodeRevokesNothing(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let client = try await Self.registerPublicClient(server)
        let tokens = try await Self.issue(server, clientId: client)

        await #expect { _ = try await Self.redeem(
            server, clientId: client, code: "never-issued", verifier: PKCE.generateCodeVerifier()) }
            throws: { Self.isInvalidGrant($0) }

        #expect(try await server.introspect(token: tokens.accessToken).active)
    }

    // MARK: - The opt-out

    /// Today's behaviour, pinned: the same refresh token comes back, and it keeps working.
    @Test("rotationPolicy .reusable returns the same refresh token, which keeps working",
          arguments: StoreKind.allCases)
    func reusableIsToday(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind, policy: .reusable)
        let client = try await Self.registerPublicClient(server)
        let first = try await Self.issue(server, clientId: client)
        let original = try #require(first.refreshToken)

        let second = try await Self.refresh(server, clientId: client, token: original)
        #expect(second.refreshToken == original)
        let third = try await Self.refresh(server, clientId: client, token: original)
        #expect(third.refreshToken == original)
        // Nothing was revoked by reuse, because reuse is the policy.
        #expect(try await server.introspect(token: first.accessToken).active)
        #expect(try await server.introspect(token: second.accessToken).active)
        #expect(try await server.introspect(token: third.accessToken).active)
    }

    @Test("The default is rotating", arguments: StoreKind.allCases)
    func defaultRotates(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let client = try await Self.registerPublicClient(server)
        let original = try #require(try await Self.issue(server, clientId: client).refreshToken)

        let refreshed = try await Self.refresh(server, clientId: client, token: original)

        let successor = try #require(refreshed.refreshToken)
        #expect(successor != original)
    }
}
