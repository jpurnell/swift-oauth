import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// The device grant on the provider — RFC 8628, issuing and polling.
@Suite("RFC 8628 — the device endpoint")
struct DeviceAuthorizationEndpointTests {

    private func makeServer() async throws -> (OAuthServer, OAuthStorage) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"], advertisedEndpoints: .none,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        return (server, storage)
    }

    /// A device asking to sign in gets both codes and somewhere to send the user.
    @Test("A device authorization request issues both codes")
    func requestIssuesCodes() async throws {
        let (server, _) = try await makeServer()

        let response = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        #expect(!response.deviceCode.isEmpty)
        #expect(!response.userCode.isEmpty)
        #expect(response.verificationURI.absoluteString.contains("mcp.example.com"))
        #expect(response.interval >= 5)
        #expect(response.expiresIn > 0)
    }

    /// The user code is short enough to read off a screen and type — §6.1 asks for that
    /// explicitly, and a code that is merely random is not usable on a TV remote.
    @Test("The user code is short and readable")
    func userCodeIsReadable() async throws {
        let (server, _) = try await makeServer()

        let response = try await server.authorizeDevice(clientId: "tv-app", scope: nil)
        let bare = response.userCode.replacingOccurrences(of: "-", with: "")

        #expect(bare.count <= 12, "a user code this long will be mistyped")
        // §6.1 recommends excluding characters that are confused when read aloud or typed.
        #expect(!bare.contains("0"))
        #expect(!bare.contains("O"))
        #expect(!bare.contains("1"))
        #expect(!bare.contains("I"))
    }

    /// The device and user codes are different things, and the device code is the credential.
    @Test("The device code is long and distinct from the user code")
    func deviceCodeIsACredential() async throws {
        let (server, _) = try await makeServer()

        let response = try await server.authorizeDevice(clientId: "tv-app", scope: nil)

        #expect(response.deviceCode != response.userCode)
        #expect(response.deviceCode.count >= 32, "a device code is a bearer credential")
    }

    /// Two requests do not collide.
    @Test("Each request issues fresh codes")
    func codesAreUnique() async throws {
        let (server, _) = try await makeServer()

        let first = try await server.authorizeDevice(clientId: "tv-app", scope: nil)
        let second = try await server.authorizeDevice(clientId: "tv-app", scope: nil)

        #expect(first.deviceCode != second.deviceCode)
        #expect(first.userCode != second.userCode)
    }

    /// Polling before the user has finished is `authorization_pending` — the normal state of a
    /// working flow, and the answer a client will receive most of the time.
    @Test("Polling before approval is authorization_pending")
    func pollingBeforeApprovalIsPending() async throws {
        let (server, _) = try await makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        let error = await #expect(throws: OAuthError.self) {
            _ = try await server.redeemDeviceCode(
                issued.deviceCode, clientId: "tv-app")
        }
        #expect(error?.code == "authorization_pending")
    }

    /// After approval, the device code exchanges for tokens.
    @Test("An approved device code exchanges for a token")
    func approvedCodeIssuesToken() async throws {
        let (server, _) = try await makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")

        try await server.approveDeviceCode(userCode: issued.userCode, subject: "user-1")
        let tokens = try await server.redeemDeviceCode(issued.deviceCode, clientId: "tv-app")

        #expect(!tokens.accessToken.isEmpty)
    }

    /// A device code is single-use. Redeeming twice is how one leaked code becomes two
    /// sessions.
    @Test("A device code cannot be redeemed twice")
    func deviceCodeIsSingleUse() async throws {
        let (server, _) = try await makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")
        try await server.approveDeviceCode(userCode: issued.userCode, subject: "user-1")
        _ = try await server.redeemDeviceCode(issued.deviceCode, clientId: "tv-app")

        await #expect(throws: OAuthError.self) {
            _ = try await server.redeemDeviceCode(issued.deviceCode, clientId: "tv-app")
        }
    }

    /// A device code belongs to the client it was issued to.
    ///
    /// Without this check, a device code observed in transit is redeemable by anyone who can
    /// name a client id — and client ids are public by design.
    @Test("Another client cannot redeem a device code")
    func deviceCodeIsBoundToItsClient() async throws {
        let (server, _) = try await makeServer()
        let issued = try await server.authorizeDevice(clientId: "tv-app", scope: "read")
        try await server.approveDeviceCode(userCode: issued.userCode, subject: "user-1")

        await #expect(throws: OAuthError.self) {
            _ = try await server.redeemDeviceCode(issued.deviceCode, clientId: "someone-else")
        }
    }

    /// An unknown user code cannot be approved — otherwise the approval page is an oracle for
    /// guessing short codes, which are short precisely so they can be typed.
    @Test("An unknown user code cannot be approved")
    func unknownUserCodeIsRefused() async throws {
        let (server, _) = try await makeServer()

        await #expect(throws: OAuthError.self) {
            try await server.approveDeviceCode(userCode: "ZZZZ-ZZZZ", subject: "user-1")
        }
    }
}
