import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import RedirectWireStub
import Testing
@testable import SwiftOAuthClient
@testable import SwiftOAuthCore

/// A TLS loopback server and transports that will complete a handshake with it.
///
/// How that is arranged differs by platform, because what `URLSession` can be told differs:
///
/// - **Apple platforms:** the certificate is minted here, and the transports are built through
///   the internal `init(trusting:)` seam, which accepts that certificate and no other.
/// - **Linux:** swift-corelibs-foundation verifies against the system bundle and offers a
///   request no say in it, so there is no seam to build. The CI job generates a certificate,
///   installs it in the container's bundle before the tests start, and names the files in
///   two environment variables; the transports are the ordinary public ones. Anywhere those
///   variables are not set these tests are reported as skipped rather than passed.
struct TLSFixture {

    let certificate: LoopbackCertificate
    let token: URLSessionTokenTransport
    let introspection: URLSessionIntrospectionTransport

    /// Whether this environment can run a `URLSession` request against a loopback TLS server.
    static var isAvailable: Bool {
        #if canImport(FoundationNetworking)
        LoopbackCertificate.installed() != nil
        #else
        true
        #endif
    }

    static func make() throws -> TLSFixture {
        #if canImport(FoundationNetworking)
        let certificate = try #require(LoopbackCertificate.installed())
        return TLSFixture(
            certificate: certificate,
            token: URLSessionTokenTransport(),
            introspection: URLSessionIntrospectionTransport())
        #else
        let certificate = try LoopbackCertificate.mint()
        let trust = TestServerTrust(certificatesDER: [Data(certificate.der)])
        return TLSFixture(
            certificate: certificate,
            token: URLSessionTokenTransport(trusting: trust),
            introspection: URLSessionIntrospectionTransport(trusting: trust))
        #endif
    }
}

/// The redirect rule, from `https` to `http`.
///
/// No redirect is followed, so in principle there is nothing scheme-specific to test. In
/// practice this is the case that matters most — the one where following would put a client
/// secret on the network in the clear — and until now it was the one case never run: the
/// tests had no server that spoke TLS.
@Suite("A credential-bearing request is not redirected from https to http")
struct TLSDowngradeWireTests {

    enum Kind: String, Sendable, CaseIterable, CustomTestStringConvertible {
        case codeExchangeBasic
        case codeExchangePost
        case refresh
        case revocation
        case introspection

        var testDescription: String { rawValue }
    }

    static let passphraseFixture = "fixture-client-passphrase"
    static let codeFixture = "fixture-authorization-code"
    static let refreshFixture = "fixture-refresh-value"

    private static func perform(_ kind: Kind, endpoint: URL, with fixture: TLSFixture) async throws {
        let credentials = ClientCredentials(
            environment: "test", clientID: "fixture-client", clientSecret: passphraseFixture)
        switch kind {
        case .codeExchangeBasic, .codeExchangePost:
            _ = try await fixture.token.exchange(
                endpoint: endpoint,
                parameters: [
                    "grant_type": GrantType.authorizationCode.rawValue,
                    "code": codeFixture,
                    "code_verifier": "fixture-pkce-verifier"
                ],
                credentials: credentials,
                method: kind == .codeExchangeBasic ? .clientSecretBasic : .clientSecretPost)
        case .refresh:
            _ = try await fixture.token.exchange(
                endpoint: endpoint,
                parameters: [
                    "grant_type": GrantType.refreshToken.rawValue, "refresh_token": refreshFixture
                ],
                credentials: credentials, method: .clientSecretBasic)
        case .revocation:
            try await fixture.token.revoke(
                endpoint: endpoint,
                parameters: ["token": refreshFixture, "token_type_hint": "refresh_token"],
                credentials: credentials, method: .clientSecretBasic)
        case .introspection:
            let introspector = TokenIntrospector(
                endpoint: endpoint,
                credentials: .init(clientId: "fixture-client", clientSecret: passphraseFixture),
                transport: fixture.introspection)
            _ = try await introspector.introspect(token: refreshFixture)
        }
    }

    @Test(
        "An https endpoint redirecting to http is refused, and nothing is sent in the clear",
        .enabled(if: TLSFixture.isAvailable, "no loopback TLS certificate this platform's URLSession trusts"),
        .timeLimit(.minutes(1)),
        arguments: Kind.allCases, [301, 302, 303, 307, 308])
    func downgradeIsRefused(kind: Kind, status: Int) async throws {
        let fixture = try TLSFixture.make()
        let plaintext = try await RedirectWireServer.start { .answer }
        let location = "\(plaintext.origin)/elsewhere"
        let secure = try await RedirectWireServer.start(tls: fixture.certificate) {
            .redirect(status: status, location: location)
        }
        let endpoint = try #require(secure.url(path: "/oauth/endpoint"))
        #expect(endpoint.scheme == "https")

        let refusal = await #expect(throws: OAuthRedirectRefused.self) {
            try await Self.perform(kind, endpoint: endpoint, with: fixture)
        }

        // The request reached the TLS server — so the handshake completed and the refusal is
        // the redirect's, not a certificate error wearing its name — and went no further.
        #expect(secure.requests.count == 1)
        let arrived = plaintext.requests
        #expect(arrived.isEmpty, "the plaintext origin received \(arrived.map { "\($0.method) \($0.target) body=\($0.body.utf8.count)B authorization=\($0.header("authorization") == nil ? "no" : "yes")" })")
        #expect(refusal?.status == status)
        #expect(refusal?.endpoint == secure.origin)
        #expect(refusal?.destination == plaintext.origin)
        #expect(refusal?.destination.hasPrefix("http://") == true)

        try await secure.stop()
        try await plaintext.stop()
    }

    /// The other half: over TLS and not redirected, the request arrives. Without this the
    /// suite above could pass against a client that cannot speak to the stub at all.
    @Test(
        "An https request that is not redirected is delivered",
        .enabled(if: TLSFixture.isAvailable, "no loopback TLS certificate this platform's URLSession trusts"),
        .timeLimit(.minutes(1)),
        arguments: Kind.allCases)
    func unredirectedRequestIsDelivered(kind: Kind) async throws {
        let fixture = try TLSFixture.make()
        let secure = try await RedirectWireServer.start(tls: fixture.certificate) { .answer }
        let endpoint = try #require(secure.url(path: "/oauth/endpoint"))

        try await Self.perform(kind, endpoint: endpoint, with: fixture)

        #expect(secure.requests.count == 1)
        #expect(secure.requests.first?.method == "POST")
        try await secure.stop()
    }

    #if !canImport(FoundationNetworking)
    /// The seam trusts the certificate it was given and nothing else. A test seam that
    /// accepted any certificate would be a way to switch verification off, which is a
    /// different thing to have lying in a library.
    @Test("The test seam refuses a certificate it was not given", .timeLimit(.minutes(1)))
    func seamRefusesAnotherCertificate() async throws {
        let presented = try LoopbackCertificate.mint()
        let other = try LoopbackCertificate.mint()
        let secure = try await RedirectWireServer.start(tls: presented) { .answer }
        let endpoint = try #require(secure.url(path: "/oauth/endpoint"))
        let transport = URLSessionTokenTransport(
            trusting: TestServerTrust(certificatesDER: [Data(other.der)]))

        await #expect(throws: URLError.self) {
            _ = try await transport.exchange(
                endpoint: endpoint, parameters: ["grant_type": "refresh_token"],
                credentials: .testCredentials, method: .clientSecretBasic)
        }
        #expect(secure.requests.isEmpty)
        try await secure.stop()
    }

    /// And a transport built the public way does not have the seam at all: a certificate
    /// nothing trusts is refused, as it would be for any caller.
    @Test(
        "A transport built through the public API does not trust the test certificate",
        .timeLimit(.minutes(1)))
    func publicTransportDoesNotTrustIt() async throws {
        let presented = try LoopbackCertificate.mint()
        let secure = try await RedirectWireServer.start(tls: presented) { .answer }
        let endpoint = try #require(secure.url(path: "/oauth/endpoint"))

        for transport in [URLSessionTokenTransport(), URLSessionTokenTransport(session: .shared)] {
            await #expect(throws: URLError.self) {
                _ = try await transport.exchange(
                    endpoint: endpoint, parameters: ["grant_type": "refresh_token"],
                    credentials: .testCredentials, method: .clientSecretBasic)
            }
        }
        #expect(secure.requests.isEmpty)
        try await secure.stop()
    }
    #endif
}
