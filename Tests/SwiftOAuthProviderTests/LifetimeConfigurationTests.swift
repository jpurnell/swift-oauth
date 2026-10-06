import CSQLite
import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// A server configured with a lifetime that is not a number of seconds.
///
/// `OAuthServer.init` takes three `TimeInterval`s and does not throw, so nothing stops an
/// operator handing it `.nan`, `.infinity`, a negative, or the result of arithmetic that
/// overflowed. Until `1.0.0-beta.6` every token-issuing path then did `Int(accessTokenLifetime)`
/// — which is not an error for those values but a trap — *after* it had already stored a token
/// whose expiry was `Date() + NaN`. So the first token request ended the process, and left a row
/// behind it.
///
/// What these tests fix in place: such a server refuses, with `server_error`, **before it
/// stores or spends anything**. The second half is the one that needs a test. A refusal that
/// arrives after the authorization code was consumed has cost the client its code; one that
/// arrives after the access token was saved has issued a credential nobody was told about.
///
/// The database is a file rather than `:memory:` so its rows can be counted with raw SQL, for
/// the reason `AudienceBindingTests` gives: the claim is about the state of the database, and a
/// row-counting method on the production type would be permanent API for a test's benefit.
@Suite("A misconfigured lifetime refuses issuance instead of trapping")
struct LifetimeConfigurationTests {

    /// Lifetimes no token can be issued with.
    ///
    /// `0.5` is here because it is positive and still unusable: `expires_in` is an integer on
    /// the wire (RFC 6749 §5.1), and a lifetime that truncates to zero whole seconds describes a
    /// token that has already expired.
    static let unusable: [TimeInterval] = [
        .nan, .infinity, -.infinity, -1, 0, 0.5, 1e300
    ]

    static let accessMessage = "This server's configured access-token lifetime is not a usable "
        + "number of seconds, so it cannot issue a token."
    static let refreshMessage = "This server's configured refresh-token lifetime is not a usable "
        + "number of seconds, so it cannot issue a token."
    static let codeMessage = "This server's configured authorization-code lifetime is not a "
        + "usable number of seconds, so it cannot issue a code."

    static let redirect = "https://app.example.com/callback"

    // MARK: - Fixture

    /// What the database holds, as far as issuance is concerned.
    struct Rows: Equatable {
        var accessTokens: Int
        var refreshTokens: Int
        var authorizationCodes: Int
        var consumedCodes: Int
        var redeemedDeviceCodes: Int
    }

    /// Two servers over one store: one configured sanely, to put the store into a state worth
    /// asking about, and one misconfigured, to be asked.
    struct Fixture {
        let path: String
        let storage: OAuthStorage
        let healthy: OAuthServer

        init() throws {
            path = FileManager.default.temporaryDirectory
                .appendingPathComponent("lifetime-\(UUID().uuidString).sqlite").path
            storage = try OAuthStorage(path: path)
            healthy = OAuthServer(
                storage: storage, issuer: "https://mcp.example.com",
                scopesSupported: ["read"], served: .core, resourceIdentity: .colocated,
                accessTokenLifetime: 3600, refreshTokenLifetime: 7200,
                authorizationCodeLifetime: 600,
                resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        }

        /// A server over the same store with the given lifetimes.
        func server(
            access: TimeInterval = 3600, refresh: TimeInterval = 7200, code: TimeInterval = 600
        ) -> OAuthServer {
            OAuthServer(
                storage: storage, issuer: "https://mcp.example.com",
                scopesSupported: ["read"], served: .core, resourceIdentity: .colocated,
                accessTokenLifetime: access, refreshTokenLifetime: refresh,
                authorizationCodeLifetime: code,
                resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        }

        func remove() {
            try?FileManager.default.removeItem(atPath: path)
        }

        /// Counts the rows issuance writes, on a second connection.
        func rows() throws -> Rows {
            var db: OpaquePointer?
            guard sqlite3_open(path, &db) == SQLITE_OK else {
                throw OAuthStorageError.databaseError("could not open \(path)")
            }
            defer { sqlite3_close(db) }

            func count(_ sql: String) throws -> Int {
                var stmt: OpaquePointer?
                defer { sqlite3_finalize(stmt) }
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK,
                      sqlite3_step(stmt) == SQLITE_ROW else {
                    throw OAuthStorageError.databaseError("count failed: \(sql)")
                }
                return Int(sqlite3_column_int64(stmt, 0))
            }

            return Rows(
                accessTokens: try count("SELECT COUNT(*) FROM access_tokens"),
                refreshTokens: try count("SELECT COUNT(*) FROM refresh_tokens"),
                authorizationCodes: try count("SELECT COUNT(*) FROM authorization_codes"),
                consumedCodes: try count(
                    "SELECT COUNT(*) FROM authorization_codes WHERE consumed = 1"),
                redeemedDeviceCodes: try count(
                    "SELECT COUNT(*) FROM device_codes WHERE redeemed = 1"))
        }

        /// A registered client that may refresh.
        func client() async throws -> ClientRegistrationResponse {
            try await healthy.registerClient(ClientRegistrationRequest(
                clientName: "app", redirectUris: [LifetimeConfigurationTests.redirect],
                grantTypes: ["authorization_code", "refresh_token"]))
        }

        /// An authorization request carrying a challenge for `verifier`.
        func authorizationRequest(
            for client: ClientRegistrationResponse, verifier: String
        ) throws -> AuthorizationRequest {
            AuthorizationRequest(
                responseType: "code", clientId: client.clientId,
                redirectUri: LifetimeConfigurationTests.redirect, scope: "read", state: nil,
                codeChallenge: try PKCE.generateCodeChallenge(verifier: verifier, method: .s256),
                codeChallengeMethod: PKCE.ChallengeMethod.s256.rawValue)
        }

        /// The token request redeeming `code`.
        func codeGrant(
            _ code: String, for client: ClientRegistrationResponse, verifier: String
        ) -> TokenRequest {
            TokenRequest(
                grantType: "authorization_code", code: code,
                redirectUri: LifetimeConfigurationTests.redirect, clientId: client.clientId,
                clientSecret: client.clientSecret, codeVerifier: verifier, refreshToken: nil)
        }
    }

    // MARK: - The access-token lifetime, on each of the four paths that issue one

    @Test("Token exchange refuses, and stores nothing", arguments: unusable)
    func exchangeRefuses(_ lifetime: TimeInterval) async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        try await fixture.storage.saveAccessToken(
            token: "subject", clientId: "gateway", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: nil)
        let before = try fixture.rows()
        #expect(before == Rows(
            accessTokens: 1, refreshTokens: 0, authorizationCodes: 0, consumedCodes: 0,
            redeemedDeviceCodes: 0))

        let broken = fixture.server(access: lifetime)
        await #expect(throws: OAuthError.serverError(Self.accessMessage)) {
            _ = try await broken.exchangeToken(
                TokenExchangeRequest(subjectToken: "subject", subjectTokenType: .accessToken),
                clientId: "gateway")
        }

        #expect(try fixture.rows() == before)
    }

    @Test("The device grant refuses, stores nothing, and leaves the code unspent",
          arguments: unusable)
    func deviceGrantRefuses(_ lifetime: TimeInterval) async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let issued = try await fixture.healthy.authorizeDevice(clientId: "tv-app", scope: "read")
        try await fixture.healthy.approveDeviceCode(userCode: issued.userCode, subject: "user-1")
        let before = try fixture.rows()
        #expect(before == Rows(
            accessTokens: 0, refreshTokens: 0, authorizationCodes: 0, consumedCodes: 0,
            redeemedDeviceCodes: 0))

        let broken = fixture.server(access: lifetime)
        await #expect(throws: OAuthError.serverError(Self.accessMessage)) {
            _ = try await broken.redeemDeviceCode(issued.deviceCode, clientId: "tv-app")
        }

        // Unspent: a device code is single-use, and a refusal that had already marked it
        // redeemed would leave the user to start the whole flow again once the operator fixed
        // the configuration.
        #expect(try fixture.rows() == before)
        #expect(try await fixture.storage.deviceCodeState(
            deviceCode: issued.deviceCode, clientId: "tv-app") == .approved(scope: "read"))
    }

    @Test("The authorization-code grant refuses, stores nothing, and leaves the code unspent",
          arguments: unusable)
    func codeGrantRefuses(_ lifetime: TimeInterval) async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let client = try await fixture.client()
        let verifier = PKCE.generateCodeVerifier()
        let code = try await fixture.healthy.handleAuthorizationRequest(
            fixture.authorizationRequest(for: client, verifier: verifier)).code
        let before = try fixture.rows()
        #expect(before == Rows(
            accessTokens: 0, refreshTokens: 0, authorizationCodes: 1, consumedCodes: 0,
            redeemedDeviceCodes: 0))

        let broken = fixture.server(access: lifetime)
        await #expect(throws: OAuthError.serverError(Self.accessMessage)) {
            _ = try await broken.handleTokenRequest(
                fixture.codeGrant(code, for: client, verifier: verifier))
        }

        #expect(try fixture.rows() == before)
    }

    @Test("The refresh grant refuses, and stores nothing", arguments: unusable)
    func refreshGrantRefuses(_ lifetime: TimeInterval) async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let client = try await fixture.client()
        let verifier = PKCE.generateCodeVerifier()
        let code = try await fixture.healthy.handleAuthorizationRequest(
            fixture.authorizationRequest(for: client, verifier: verifier)).code
        let tokens = try await fixture.healthy.handleTokenRequest(
            fixture.codeGrant(code, for: client, verifier: verifier))
        let before = try fixture.rows()
        #expect(before == Rows(
            accessTokens: 1, refreshTokens: 1, authorizationCodes: 1, consumedCodes: 1,
            redeemedDeviceCodes: 0))

        let broken = fixture.server(access: lifetime)
        await #expect(throws: OAuthError.serverError(Self.accessMessage)) {
            _ = try await broken.handleTokenRequest(TokenRequest(
                grantType: "refresh_token", code: nil, redirectUri: nil,
                clientId: client.clientId, clientSecret: client.clientSecret,
                codeVerifier: nil, refreshToken: tokens.refreshToken))
        }

        #expect(try fixture.rows() == before)
    }

    // MARK: - The refresh-token lifetime, on the two paths that issue one

    @Test("An unusable refresh-token lifetime refuses the device grant", arguments: unusable)
    func deviceGrantRefusesRefreshLifetime(_ lifetime: TimeInterval) async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let issued = try await fixture.healthy.authorizeDevice(clientId: "tv-app", scope: "read")
        try await fixture.healthy.approveDeviceCode(userCode: issued.userCode, subject: "user-1")
        let before = try fixture.rows()

        let broken = fixture.server(refresh: lifetime)
        await #expect(throws: OAuthError.serverError(Self.refreshMessage)) {
            _ = try await broken.redeemDeviceCode(issued.deviceCode, clientId: "tv-app")
        }

        #expect(try fixture.rows() == before)
        #expect(before == Rows(
            accessTokens: 0, refreshTokens: 0, authorizationCodes: 0, consumedCodes: 0,
            redeemedDeviceCodes: 0))
    }

    @Test("An unusable refresh-token lifetime refuses the authorization-code grant",
          arguments: unusable)
    func codeGrantRefusesRefreshLifetime(_ lifetime: TimeInterval) async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let client = try await fixture.client()
        let verifier = PKCE.generateCodeVerifier()
        let code = try await fixture.healthy.handleAuthorizationRequest(
            fixture.authorizationRequest(for: client, verifier: verifier)).code
        let before = try fixture.rows()

        let broken = fixture.server(refresh: lifetime)
        await #expect(throws: OAuthError.serverError(Self.refreshMessage)) {
            _ = try await broken.handleTokenRequest(
                fixture.codeGrant(code, for: client, verifier: verifier))
        }

        #expect(try fixture.rows() == before)
        #expect(before == Rows(
            accessTokens: 0, refreshTokens: 0, authorizationCodes: 1, consumedCodes: 0,
            redeemedDeviceCodes: 0))
    }

    // MARK: - The authorization-code lifetime

    @Test("An unusable authorization-code lifetime refuses to issue a code", arguments: unusable)
    func authorizationRefusesCodeLifetime(_ lifetime: TimeInterval) async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let client = try await fixture.client()
        let verifier = PKCE.generateCodeVerifier()

        let broken = fixture.server(code: lifetime)
        await #expect(throws: OAuthError.serverError(Self.codeMessage)) {
            _ = try await broken.handleAuthorizationRequest(
                fixture.authorizationRequest(for: client, verifier: verifier))
        }

        #expect(try fixture.rows() == Rows(
            accessTokens: 0, refreshTokens: 0, authorizationCodes: 0, consumedCodes: 0,
            redeemedDeviceCodes: 0))
    }

    // MARK: - The configured lifetime is what a client is told

    @Test("Each path reports the configured lifetime, in whole seconds")
    func usableLifetimeIsReportedExactly() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        // Fractional on purpose: `expires_in` truncates, and must not round a client into
        // believing a token outlives its expiry.
        let server = fixture.server(access: 1799.9)
        let client = try await fixture.client()
        let verifier = PKCE.generateCodeVerifier()

        let code = try await server.handleAuthorizationRequest(
            fixture.authorizationRequest(for: client, verifier: verifier)).code
        let issued = try await server.handleTokenRequest(
            fixture.codeGrant(code, for: client, verifier: verifier))
        #expect(issued.expiresIn == 1799)

        let refreshed = try await server.handleTokenRequest(TokenRequest(
            grantType: "refresh_token", code: nil, redirectUri: nil,
            clientId: client.clientId, clientSecret: client.clientSecret,
            codeVerifier: nil, refreshToken: issued.refreshToken))
        #expect(refreshed.expiresIn == 1799)

        let exchanged = try await server.exchangeToken(
            TokenExchangeRequest(subjectToken: issued.accessToken, subjectTokenType: .accessToken),
            clientId: client.clientId)
        #expect(exchanged.expiresIn == 1799)

        let device = try await server.authorizeDevice(clientId: "tv-app", scope: "read")
        try await server.approveDeviceCode(userCode: device.userCode, subject: "user-1")
        let redeemed = try await server.redeemDeviceCode(device.deviceCode, clientId: "tv-app")
        #expect(redeemed.expiresIn == 1799)

        // Four access tokens and two refresh tokens: the code grant and the device grant each
        // issue a refresh token; a refresh and an exchange do not.
        #expect(try fixture.rows() == Rows(
            accessTokens: 4, refreshTokens: 2, authorizationCodes: 1, consumedCodes: 1,
            redeemedDeviceCodes: 1))
    }

    @Test("The defaults are 24 hours of access token")
    func defaultLifetimeIsReported() async throws {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["read"],
            served: .core, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        let device = try await server.authorizeDevice(clientId: "tv-app", scope: "read")
        try await server.approveDeviceCode(userCode: device.userCode, subject: "user-1")

        let tokens = try await server.redeemDeviceCode(device.deviceCode, clientId: "tv-app")

        #expect(tokens.expiresIn == 86400)
    }
}
