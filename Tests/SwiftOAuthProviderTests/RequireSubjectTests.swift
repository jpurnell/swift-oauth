import Foundation
import Testing
import CSQLite
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// A deployment that has user accounts can say so: with `requireSubject`, the server never
/// issues something that names nobody.
///
/// Without it a deployment that forgets to pass `subject` issues tokens whose `sub` is `nil`,
/// which no per-user check can attribute and no revoke-by-user can reach. The package refuses to
/// invent a subject for such a grant (a shared default would make "revoke it" end every
/// unattributed token), so the remedy is to refuse the grant instead, and to make that the
/// deployment's choice: the default leaves every existing consumer exactly as it was.
@Suite("requireSubject: a grant that names nobody is refused when the deployment asks")
struct RequireSubjectTests {

    static let issuer = "https://auth.example.com"
    static let redirect = "https://app.example.com/cb"

    private static func makeServer(requireSubject: Bool?, store kind: StoreKind) throws -> OAuthServer {
        let storage = try kind.makeStore()
        let served = try ServedCapabilities(
            grantTypes: [.authorizationCode, .refreshToken, .clientCredentials, .deviceCode],
            clientAuthenticationMethods: [.clientSecretBasic, .clientSecretPost, .none],
            deviceAuthorization: "\(issuer)/device_authorization")
        let resourcePolicy = ResourceIndicatorPolicy(known: [], allowsUnspecified: true)
        guard let requireSubject else {
            return OAuthServer(
                storage: storage, issuer: issuer, scopesSupported: ["read"], served: served,
                resourceIdentity: .colocated, resourcePolicy: resourcePolicy)
        }
        return OAuthServer(
            storage: storage, issuer: issuer, scopesSupported: ["read"], served: served,
            resourceIdentity: .colocated, resourcePolicy: resourcePolicy,
            requireSubject: requireSubject)
    }

    private static func registerPublicClient(_ server: OAuthServer) async throws -> String {
        try await server.registerClient(ClientRegistrationRequest(
            clientName: "App", redirectUris: [redirect],
            grantTypes: ["authorization_code", "refresh_token"],
            tokenEndpointAuthMethod: "none")).clientId
    }

    private static func authorizationRequest(clientId: String) throws -> AuthorizationRequest {
        let verifier = PKCE.generateCodeVerifier()
        let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)
        return AuthorizationRequest(
            responseType: "code", clientId: clientId, redirectUri: redirect, scope: "read",
            state: nil, codeChallenge: challenge, codeChallengeMethod: "S256")
    }

    /// What a call refused with, or `nil` if it did not throw an `OAuthError`.
    private static func refusal(_ body: () async throws -> Void) async -> OAuthError? {
        do {
            try await body()
            return nil
        } catch let error as OAuthError {
            return error
        } catch {
            return nil
        }
    }

    // MARK: - The authorization code grant

    @Test("With requireSubject, an authorization request naming nobody is refused with server_error", arguments: StoreKind.allCases)
    func codeWithNoSubjectIsRefused(store kind: StoreKind) async throws {
        let server = try Self.makeServer(requireSubject: true, store: kind)
        let clientId = try await Self.registerPublicClient(server)
        let request = try Self.authorizationRequest(clientId: clientId)

        let refused = await Self.refusal { _ = try await server.handleAuthorizationRequest(request, subject: nil) }

        guard case .serverError(_)? = refused else {
            Issue.record("expected server_error, got \(String(describing: refused))")
            return
        }
    }

    @Test("With requireSubject, an empty or blank subject is not a subject", arguments: StoreKind.allCases)
    func blankSubjectIsRefused(store kind: StoreKind) async throws {
        let server = try Self.makeServer(requireSubject: true, store: kind)
        let clientId = try await Self.registerPublicClient(server)

        for blank in ["", "   ", "\n\t"] {
            let request = try Self.authorizationRequest(clientId: clientId)
            let refused = await Self.refusal { _ = try await server.handleAuthorizationRequest(request, subject: blank) }
            guard case .serverError(_)? = refused else {
                Issue.record("subject \(String(reflecting: blank)) was not refused: \(String(describing: refused))")
                return
            }
        }
    }

    @Test("With requireSubject, a named subject is issued a code, and the token carries it", arguments: StoreKind.allCases)
    func namedSubjectStillWorks(store kind: StoreKind) async throws {
        let server = try Self.makeServer(requireSubject: true, store: kind)
        let clientId = try await Self.registerPublicClient(server)
        let verifier = PKCE.generateCodeVerifier()
        let challenge = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)

        let authorization = try await server.handleAuthorizationRequest(
            AuthorizationRequest(
                responseType: "code", clientId: clientId, redirectUri: Self.redirect, scope: "read",
                state: nil, codeChallenge: challenge, codeChallengeMethod: "S256"),
            subject: "ada")
        let tokens = try await server.handleTokenRequest(TokenRequest(
            grantType: "authorization_code", code: authorization.code, redirectUri: Self.redirect,
            clientId: clientId, clientSecret: nil, codeVerifier: verifier, refreshToken: nil))
        let introspected = try await server.introspect(token: tokens.accessToken)

        #expect(introspected.subject == "ada")
    }

    @Test("By default a request naming nobody is still issued a code, as before", arguments: StoreKind.allCases)
    func defaultIsUnchanged(store kind: StoreKind) async throws {
        for server in [try Self.makeServer(requireSubject: nil, store: kind), try Self.makeServer(requireSubject: false, store: kind)] {
            let clientId = try await Self.registerPublicClient(server)
            let request = try Self.authorizationRequest(clientId: clientId)

            let response = try await server.handleAuthorizationRequest(request, subject: nil)

            #expect(!response.code.isEmpty)
        }
    }

    // MARK: - The device grant

    @Test("With requireSubject, approving a device code with no subject is refused, and the device stays pending", arguments: StoreKind.allCases)
    func deviceApprovalWithBlankSubjectIsRefused(store kind: StoreKind) async throws {
        let server = try Self.makeServer(requireSubject: true, store: kind)
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        let refused = await Self.refusal { try await server.approveDeviceCode(userCode: issued.userCode, subject: "  ") }

        guard case .serverError(_)? = refused else {
            Issue.record("expected server_error, got \(String(describing: refused))")
            return
        }
        // Still pending: the refused approval must not have recorded anything, so the right
        // user can still approve the same code.
        try await server.approveDeviceCode(userCode: issued.userCode, subject: "ada")
        let tokens = try await server.redeemDeviceCode(issued.deviceCode, clientId: "tv-app")
        #expect(try await server.introspect(token: tokens.accessToken).subject == "ada")
    }

    @Test("By default a device code can still be approved with a blank subject, as before", arguments: StoreKind.allCases)
    func deviceDefaultIsUnchanged(store kind: StoreKind) async throws {
        let server = try Self.makeServer(requireSubject: nil, store: kind)
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        try await server.approveDeviceCode(userCode: issued.userCode, subject: "")

        let tokens = try await server.redeemDeviceCode(issued.deviceCode, clientId: "tv-app")
        #expect(!tokens.accessToken.isEmpty)
    }

    // MARK: - What it must not touch

    @Test("With requireSubject, client_credentials still works: its subject is the client itself", arguments: StoreKind.allCases)
    func clientCredentialsIsUnaffected(store kind: StoreKind) async throws {
        let server = try Self.makeServer(requireSubject: true, store: kind)
        let service = try await server.createServiceClient(name: "svc", scopes: ["read"])

        let tokens = try await server.handleTokenRequest(TokenRequest(
            grantType: "client_credentials", code: nil, redirectUri: nil,
            clientId: service.clientId, clientSecret: service.clientSecret, codeVerifier: nil,
            refreshToken: nil))

        #expect(try await server.introspect(token: tokens.accessToken).subject == service.clientId)
    }
}
