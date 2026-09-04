import Foundation
import Testing

@testable import SwiftOAuthProvider

/// Authorization changes required by MCP `2026-07-28`.
///
/// Three items: the issuer identifier in authorization responses (RFC 9207), `application_type`
/// in Dynamic Client Registration, and the deprecation of DCR in favour of Client ID Metadata
/// Documents.
@Suite("MCP 2026-07-28 Authorization")
struct MCP2026AuthorizationTests {

    private static func makeServer() async throws -> OAuthServer {
        let storage = try OAuthStorage(path: ":memory:")
        return await OAuthServer(storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"], served: .core,
            // These suites predate RFC 8707 and exercise other things — grants, PKCE, consent, wire
            // shapes. Strict resource indicators would make every one of them carry a `resource`
            // parameter that has nothing to do with what they test. The strict default has its own
            // coverage in ResourceIndicatorTests and AudienceBindingTests.
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
    }

    /// RFC 9207: the authorization response carries the issuer that produced it, and a client
    /// must validate it before redeeming the code. Without it, a code issued by one authorization
    /// server can be replayed against another that the client also trusts.
    @Test("An authorization response carries its issuer")
    func testAuthorizationResponseCarriesIssuer() async throws {
        let server = try await Self.makeServer()
        let client = try await server.registerClient(
            ClientRegistrationRequest(
                clientName: "probe",
                redirectUris: ["https://app.example.com/callback"]
            ))

        let response = try await server.handleAuthorizationRequest(
            AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "https://app.example.com/callback",
                scope: nil,
                state: "xyz",
                codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                codeChallengeMethod: "S256"
            ))

        #expect(response.issuer == "https://mcp.example.com")
        #expect(response.state == "xyz")
    }

    /// The issuer must match the server's own identifier exactly — an approximate match is what
    /// the attack this defends against relies on.
    @Test("The issuer matches the server's identifier exactly")
    func testIssuerIsExact() async throws {
        let server = try await Self.makeServer()
        let client = try await server.registerClient(
            ClientRegistrationRequest(
                clientName: "probe", redirectUris: ["https://app.example.com/callback"]))

        let response = try await server.handleAuthorizationRequest(
            AuthorizationRequest(
                responseType: "code",
                clientId: client.clientId,
                redirectUri: "https://app.example.com/callback",
                scope: nil,
                state: nil,
                codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                codeChallengeMethod: "S256"
            ))

        #expect(response.issuer == "https://mcp.example.com")
        #expect(response.issuer != "https://mcp.example.com/", "a trailing slash is a different issuer")
    }

    /// MCP 2026-07-28 requires clients to declare `application_type` during DCR, to avoid the
    /// OpenID Connect redirect-URI conflicts that arise when a native and a web client register
    /// the same URI.
    @Test("A registration request carries its application type")
    func testRegistrationCarriesApplicationType() async throws {
        let server = try await Self.makeServer()

        let client = try await server.registerClient(
            ClientRegistrationRequest(
                clientName: "probe",
                redirectUris: ["https://app.example.com/callback"],
                applicationType: .web
            ))

        #expect(client.applicationType == .web)
    }

    /// An omitted `application_type` must default to `web`, which is what RFC 7591 specifies —
    /// not to nil, which would leave the conflict this field exists to prevent unresolved.
    @Test("An omitted application type defaults to web")
    func testApplicationTypeDefaults() async throws {
        let server = try await Self.makeServer()

        let client = try await server.registerClient(
            ClientRegistrationRequest(
                clientName: "probe", redirectUris: ["https://app.example.com/callback"]))

        #expect(client.applicationType == .web)
    }

    @Test("Application types round-trip through the wire format")
    func testApplicationTypeWireForm() throws {
        #expect(ApplicationType.web.rawValue == "web")
        #expect(ApplicationType.native.rawValue == "native")

        let decoded = try JSONDecoder().decode(
            ApplicationType.self, from: Data(#""native""#.utf8))
        #expect(decoded == .native)
    }
}
