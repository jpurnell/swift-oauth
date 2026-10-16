import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// The provider issues `client_credentials` tokens — opt-in, to operator-created clients only.
///
/// The provider used to refuse this grant outright, because it issues access with no user
/// present. The concern was who could obtain such access, and these suites hold the answers
/// that replace the refusal: no one can self-register for it, the deployment must opt in, a
/// service client's scopes are fixed when an operator creates it, and its tokens are short and
/// never refreshed. See `project/plans/proposals/ProviderClientCredentials.md`.
enum ClientCredentialsFixtures {

    static func makeServer(
        served: ServedCapabilities = .core, scopesSupported: [String]? = ["push:send:fleet", "push:read"]
    ) throws -> (OAuthServer, OAuthStorage) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(
            storage: storage, issuer: "https://hub.example.com",
            scopesSupported: scopesSupported, served: served, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        return (server, storage)
    }
}

/// Dynamic registration is open to anyone who can reach `/register`. A machine identity
/// minted there would be exactly the unattended access the original refusal was about.
@Suite("Client credentials — registration is closed to it")
struct ClientCredentialsRegistrationTests {

    @Test("Registering for client_credentials is refused", arguments: [
        ["client_credentials"],
        ["authorization_code", "client_credentials"]
    ])
    func registrationRefused(grantTypes: [String]) async throws {
        let (server, _) = try ClientCredentialsFixtures.makeServer()
        await #expect(throws: OAuthError.invalidClientMetadata(
            "client_credentials clients are created by an operator, not through registration.")
        ) {
            _ = try await server.registerClient(ClientRegistrationRequest(
                clientName: "Would-be service",
                redirectUris: ["https://client.example.com/cb"],
                grantTypes: grantTypes))
        }
    }

    @Test("Over HTTP, the refusal is a 400 invalid_client_metadata")
    func registrationRefusedOverHTTP() async throws {
        let (server, _) = try ClientCredentialsFixtures.makeServer()
        let handler = OAuthHTTPHandler(server: server)
        let response = await handler.handleRegistrationRequest(body: """
            {"client_name":"Would-be service","redirect_uris":["https://client.example.com/cb"],
             "grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_basic"}
            """)

        #expect(response.statusCode == 400)
        #expect(response.body.contains("\"invalid_client_metadata\""))
    }
}
