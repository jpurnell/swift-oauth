import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// Gap D of the spec-gaps proposal: ending everything one user holds, on every client at once.
///
/// There is no RFC for this; it is the operational half of "disable this user". Expected values
/// are enumerations of what each fixture creates, never what the code returned.
@Suite("Revoke all tokens for a subject")
struct RevokeBySubjectTests {

    static let issuer = "https://auth.example.com"

    private static func makeServer(_ kind: StoreKind) throws -> (OAuthServer, any OAuthProviderStorage) {
        let storage = try kind.makeStore()
        let server = OAuthServer(
            storage: storage, issuer: issuer, scopesSupported: ["read", "write"],
            served: try ServedCapabilities(
                grantTypes: [.authorizationCode, .refreshToken, .clientCredentials, .deviceCode,
                             .tokenExchange],
                clientAuthenticationMethods: [.clientSecretBasic, .clientSecretPost, .none],
                deviceAuthorization: "\(issuer)/device_authorization"),
            resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        return (server, storage)
    }

    private static func registerPublicClient(_ server: OAuthServer) async throws -> String {
        try await server.registerClient(ClientRegistrationRequest(
            clientName: "App", redirectUris: ["https://app.example.com/cb"],
            grantTypes: ["authorization_code", "refresh_token"],
            tokenEndpointAuthMethod: "none")).clientId
    }

    /// Authorizes for `subject` and returns the code and the verifier that redeems it.
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

    @Test("Revoking a subject ends its tokens on every client and leaves everyone else's",
          arguments: StoreKind.allCases)
    func endsOnlyTheSubjectsTokens(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let app1 = try await Self.registerPublicClient(server)
        let app2 = try await Self.registerPublicClient(server)
        let app3 = try await Self.registerPublicClient(server)

        // Two subjects over three clients: alice on all three, bob on one, and one with none.
        var aliceTokens: [TokenResponse] = []
        for client in [app1, app2, app3] {
            let issued = try await Self.authorize(server, clientId: client, subject: "alice")
            aliceTokens.append(try await Self.redeem(
                server, clientId: client, code: issued.code, verifier: issued.verifier))
        }
        let bobIssued = try await Self.authorize(server, clientId: app1, subject: "bob")
        let bobTokens = try await Self.redeem(
            server, clientId: app1, code: bobIssued.code, verifier: bobIssued.verifier)
        let nobodyIssued = try await Self.authorize(server, clientId: app2, subject: nil)
        let nobodyTokens = try await Self.redeem(
            server, clientId: app2, code: nobodyIssued.code, verifier: nobodyIssued.verifier)

        // 3 access tokens + 3 refresh tokens, because each code issued one of each.
        let changed = try await server.revokeAllTokens(forSubject: "alice")
        #expect(changed == 6)

        for tokens in aliceTokens {
            #expect(try await server.introspect(token: tokens.accessToken).active == false)
            let refresh = try #require(tokens.refreshToken)
            await #expect(throws: OAuthError.self) {
                _ = try await server.handleTokenRequest(TokenRequest(
                    grantType: "refresh_token", code: nil, redirectUri: nil, clientId: app1,
                    clientSecret: nil, codeVerifier: nil, refreshToken: refresh))
            }
        }
        #expect(try await server.introspect(token: bobTokens.accessToken).active)
        #expect(try await server.introspect(token: nobodyTokens.accessToken).active,
                "a token with no subject is not reachable by any subject")
    }

    @Test("An unspent authorization code for the subject no longer redeems",
          arguments: StoreKind.allCases)
    func endsUnspentCodes(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let client = try await Self.registerPublicClient(server)
        let alice = try await Self.authorize(server, clientId: client, subject: "alice")
        let bob = try await Self.authorize(server, clientId: client, subject: "bob")

        #expect(try await server.revokeAllTokens(forSubject: "alice") == 1)

        await #expect(throws: OAuthError.self) {
            _ = try await Self.redeem(server, clientId: client, code: alice.code, verifier: alice.verifier)
        }
        let tokens = try await Self.redeem(
            server, clientId: client, code: bob.code, verifier: bob.verifier)
        #expect(try await server.introspect(token: tokens.accessToken).subject == "bob")
    }

    @Test("An approved, unredeemed device code for the subject no longer redeems; a pending one is untouched",
          arguments: StoreKind.allCases)
    func endsApprovedDeviceCodes(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let approved = try await server.authorizeDevice(clientId: "tv-app", scope: "read")
        let pending = try await server.authorizeDevice(clientId: "tv-app", scope: "read")
        try await server.approveDeviceCode(userCode: approved.userCode, subject: "alice")

        #expect(try await server.revokeAllTokens(forSubject: "alice") == 1)

        await #expect(throws: OAuthError.self) {
            _ = try await server.redeemDeviceCode(approved.deviceCode, clientId: "tv-app")
        }
        // Still waiting for a user: it names nobody, so no subject's revocation can reach it.
        do {
            _ = try await server.redeemDeviceCode(pending.deviceCode, clientId: "tv-app")
            Issue.record("a pending code redeemed")
        } catch let error as OAuthError {
            #expect(error.code == "authorization_pending")
        }
    }

    @Test("A token exchanged from the subject's token is revoked with the subject",
          arguments: StoreKind.allCases)
    func coversTokenExchange(store kind: StoreKind) async throws {
        let (server, storage) = try Self.makeServer(kind)
        try await storage.saveAccessToken(
            token: "subject-token", clientId: "gateway", scope: "read write",
            expiresAt: Date().addingTimeInterval(3600), audience: nil,
            keyThumbprint: nil, certificateThumbprint: nil, subject: "alice")
        let exchanged = try await server.exchangeToken(
            TokenExchangeRequest(
                subjectToken: "subject-token", subjectTokenType: .accessToken, scope: "read"),
            clientId: "gateway")
        #expect(try await server.introspect(token: exchanged.accessToken).active)

        // The subject token and the token exchanged from it: two access tokens.
        #expect(try await server.revokeAllTokens(forSubject: "alice") == 2)
        #expect(try await server.introspect(token: exchanged.accessToken).active == false)
    }

    @Test("A client_credentials token has the client_id as subject, so revoking that subject revokes it",
          arguments: StoreKind.allCases)
    func clientCredentialsSubjectIsTheClient(store kind: StoreKind) async throws {
        let (server, _) = try Self.makeServer(kind)
        let service = try await server.createServiceClient(name: "svc", scopes: ["read"])
        let tokens = try await server.handleTokenRequest(TokenRequest(
            grantType: "client_credentials", code: nil, redirectUri: nil,
            clientId: service.clientId, clientSecret: service.clientSecret, codeVerifier: nil,
            refreshToken: nil))

        #expect(try await server.revokeAllTokens(forSubject: service.clientId) == 1)
        #expect(try await server.introspect(token: tokens.accessToken).active == false)
    }

    @Test("An unknown subject returns zero and does not throw; so does a second revocation",
          arguments: StoreKind.allCases)
    func unknownSubjectIsZero(store kind: StoreKind) async throws {
        let (server, storage) = try Self.makeServer(kind)
        try await storage.saveAccessToken(
            token: "t", clientId: "c", scope: nil, expiresAt: Date().addingTimeInterval(3600),
            audience: nil, keyThumbprint: nil, certificateThumbprint: nil, subject: "alice")

        #expect(try await server.revokeAllTokens(forSubject: "no-such-user") == 0)
        #expect(try await server.revokeAllTokens(forSubject: "alice") == 1)
        #expect(try await server.revokeAllTokens(forSubject: "alice") == 0)
    }
}
