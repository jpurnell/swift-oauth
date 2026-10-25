import Foundation
import Testing
import SwiftIdentity
import SwiftIdentityConformance
import SwiftOAuthCore
import SwiftOAuthClient
import SwiftOAuthIdentity
import SwiftOAuthProvider

/// The provider as an identity source: a token it issues, introspected by the client half,
/// resolved by `OAuthIdentityStore` to a local SwiftIdentity subject.
///
/// Every hop is the real one. The provider issues through the device grant over its HTTP
/// endpoints; the user approves on its `/device` page; a resource server introspects with the
/// client half's `TokenIntrospector` against the provider's introspection endpoint; and
/// `OAuthIdentityStore` maps the answer's (`iss`, `sub`) through a SwiftIdentity roster. Until
/// the provider carried `sub` and `iss`, the last step had nothing to map.
@Suite("Conformance — the provider as a SwiftIdentity identity source")
struct ProviderIdentitySourceTests {

    static let issuer = DeviceGrantCrossHalfTests.issuer

    /// The introspection endpoint the provider advertises. A literal rather than built from
    /// `issuer`: the transport under test is the provider's own handler, so nothing reaches
    /// the network, and the address is written where a reader can see it is the one expected.
    static func introspectionEndpoint() throws -> URL {
        try #require(URL(string: "https://mcp.example.com/introspect"))
    }

    /// A confidential client for the resource server, which introspection requires (RFC 7662
    /// §2.1).
    static func registerResourceServer(
        _ provider: DeviceGrantCrossHalfTests.Provider
    ) async throws -> TokenIntrospector.Credentials {
        let response = await provider.handler.handleRegistrationRequest(body: """
            {"client_name":"Dashboard","redirect_uris":["https://dash.example.com/cb"],
             "token_endpoint_auth_method":"client_secret_basic"}
            """)
        let registered: SwiftOAuthProvider.ClientRegistrationResponse =
            try ProviderOverHTTP.read(response)
        let secret = try #require(registered.clientSecret)
        return TokenIntrospector.Credentials(clientId: registered.clientId, clientSecret: secret)
    }

    /// Runs a device sign-in for `subject` and returns the access token the device collected.
    static func signIn(
        _ provider: DeviceGrantCrossHalfTests.Provider, as subject: String
    ) async throws -> String {
        let credentials = try await DeviceGrantCrossHalfTests.registerDeviceClient(provider)
        let client = try DeviceAuthorizationClient(
            configuration: DeviceGrantCrossHalfTests.configuration(), credentials: credentials,
            transport: provider.wire)
        let sleeper = ApprovingSleeper(approveOnWait: 1, clock: provider.clock) { userCode in
            try await DeviceGrantCrossHalfTests.approveOnThePage(
                provider, userCode: userCode, subject: subject)
        }
        return try await client.signIn(sleeper: sleeper, elapsed: { 0 }, present: { shown in
            await sleeper.remember(shown.userCode)
        }).accessToken
    }

    static func store(
        _ provider: DeviceGrantCrossHalfTests.Provider,
        resourceServer: TokenIntrospector.Credentials,
        mapping: any CredentialStore,
        issuer: String = issuer,
        refusals: Refusals? = nil
    ) throws -> OAuthIdentityStore {
        var observer: OAuthIdentityStore.RefusalObserver?
        if let refusals {
            observer = { refusal in refusals.record(refusal) }
        }
        return OAuthIdentityStore(
            introspector: TokenIntrospector(
                endpoint: try Self.introspectionEndpoint(),
                credentials: resourceServer,
                transport: provider.wire),
            issuer: issuer,
            // The device grant binds no audience on this provider, so there is none to require.
            audience: .notChecked,
            mapping: mapping,
            onRefusal: observer)
    }

    static func roster(_ entries: [(providerSubject: String, localID: String)]) -> ReferenceCredentialStore {
        ReferenceCredentialStore(
            subjects: entries.map { Subject(id: $0.localID, kind: .person) },
            credentials: entries.map {
                (ExternalAssertion(ExternalIdentity(issuer: issuer, subject: $0.providerSubject)),
                 $0.localID, nil)
            },
            throttle: nil)
    }

    @Test("A device-grant token resolves, through introspection, to the local subject")
    func deviceGrantTokenResolves() async throws {
        let provider = try DeviceGrantCrossHalfTests.provider()
        let resourceServer = try await Self.registerResourceServer(provider)
        let token = try await Self.signIn(provider, as: "provider-user-ada")
        let people = Self.roster([("provider-user-ada", "ada")])
        let store = try Self.store(provider, resourceServer: resourceServer, mapping: people)

        let authenticator = Authenticator(stores: [people, store], audit: nil, now: { Date() })
        let authentication = await authenticator.authentication(for: [OAuthAccessToken(token)])

        #expect(authentication?.subject.id == "ada")
        #expect(authentication?.factors.map(\.kind) == [OAuthAccessToken.kind])
    }

    /// The introspection answer the store relied on, read on the resource server's side of the
    /// wire: `sub` is who approved and `iss` is the provider.
    @Test("The introspection answer the store reads carries sub and iss")
    func introspectionCarriesSubAndIss() async throws {
        let provider = try DeviceGrantCrossHalfTests.provider()
        let resourceServer = try await Self.registerResourceServer(provider)
        let token = try await Self.signIn(provider, as: "provider-user-ada")
        let introspector = TokenIntrospector(
            endpoint: try Self.introspectionEndpoint(),
            credentials: resourceServer, transport: provider.wire)

        let answer = try await introspector.introspect(token: token)

        #expect(answer.active)
        #expect(answer.subject == "provider-user-ada")
        #expect(answer.issuer == Self.issuer)
    }

    /// The roster decides, not the token: a provider subject nobody mapped is nobody here.
    @Test("A provider subject the roster does not know resolves to nobody")
    func unmappedSubjectIsNobody() async throws {
        let provider = try DeviceGrantCrossHalfTests.provider()
        let resourceServer = try await Self.registerResourceServer(provider)
        let token = try await Self.signIn(provider, as: "provider-user-mallory")
        let store = try Self.store(
            provider, resourceServer: resourceServer,
            mapping: Self.roster([("provider-user-ada", "ada")]))

        let resolution = await store.resolve(OAuthAccessToken(token))

        #expect(resolution == .refused(.unknown))
    }

    /// A store that trusts another issuer refuses this provider's answer: the `iss` the
    /// provider now sends is what lets it tell.
    @Test("A store configured for another issuer refuses the provider's token")
    func otherIssuerRefuses() async throws {
        let provider = try DeviceGrantCrossHalfTests.provider()
        let resourceServer = try await Self.registerResourceServer(provider)
        let token = try await Self.signIn(provider, as: "provider-user-ada")
        let refusals = Refusals()
        let store = try Self.store(
            provider, resourceServer: resourceServer,
            mapping: Self.roster([("provider-user-ada", "ada")]),
            issuer: "https://elsewhere.example.com", refusals: refusals)

        let resolution = await store.resolve(OAuthAccessToken(token))

        #expect(resolution == .refused(.unknown))
        // Refused on `iss`, before the mapping was asked — not merely because the roster had
        // no entry under the other issuer.
        #expect(refusals.seen == [.issuerMismatch])
    }
}

/// Keeps every refusal reason the store reports to the operator.
// Justification: `stored` is read and written only under `lock`.
final class Refusals: @unchecked Sendable {
    private var stored: [OAuthIdentityRefusal] = []
    private let lock = NSLock()

    func record(_ refusal: OAuthIdentityRefusal) {
        lock.lock()
        defer { lock.unlock() }
        stored.append(refusal)
    }

    var seen: [OAuthIdentityRefusal] {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }
}
