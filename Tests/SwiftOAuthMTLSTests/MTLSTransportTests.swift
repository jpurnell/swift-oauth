import AsyncHTTPClient
import Foundation
import NIOCore
import NIOSSL
import RedirectWireStub
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthMTLS

/// The NIO-backed token transport — RFC 8705's client half.
///
/// The behaviour worth testing here is what the transport *builds*, not what a TLS handshake
/// does. A test that stood up a mutual-TLS server would be testing NIOSSL, which Apple already
/// tests; what this package can get wrong is the configuration it hands over and the request it
/// assembles.
@Suite("RFC 8705 — the mTLS transport")
struct MTLSTransportTests {

    /// A transport built from a certificate reports the identity it will present.
    ///
    /// This is what a token gets bound to, so a client that cannot say which certificate it
    /// holds cannot tell whether a bound token is one it can still use.
    @Test("The transport reports the thumbprint of the certificate it presents")
    func reportsItsCertificateThumbprint() throws {
        let der = Data([0x30, 0x82, 0x01, 0x0a, 0x01, 0x02, 0x03])
        let identity = MTLSIdentity(certificateDER: der, privateKeyPEM: "unused-here")

        #expect(identity.certificateThumbprint == CertificateBinding.thumbprint(ofDER: der))
    }

    /// Two identities are distinguishable, or a bound token cannot be matched to the
    /// certificate that obtained it.
    @Test("Distinct certificates yield distinct thumbprints")
    func distinctIdentitiesDiffer() {
        let first = MTLSIdentity(certificateDER: Data([0xAA]), privateKeyPEM: "k")
        let second = MTLSIdentity(certificateDER: Data([0xBB]), privateKeyPEM: "k")

        #expect(first.certificateThumbprint != second.certificateThumbprint)
    }

    /// A token bound to this identity is recognised; one bound elsewhere is not.
    @Test("An identity confirms only its own bound tokens")
    func identityConfirmsOnlyItsOwn() {
        let mine = MTLSIdentity(certificateDER: Data([0xAA]), privateKeyPEM: "k")
        let theirs = MTLSIdentity(certificateDER: Data([0xBB]), privateKeyPEM: "k")

        #expect(mine.canPresent(tokenBoundTo: mine.certificateThumbprint))
        #expect(!mine.canPresent(tokenBoundTo: theirs.certificateThumbprint))
    }

    /// An unbound token is not claimed by an identity.
    ///
    /// The same trap as the binding comparison: treating "no binding" as "mine" would have a
    /// client believe every bearer token it holds is certificate-bound.
    @Test("An unbound token is not claimed by an identity")
    func unboundTokenIsNotClaimed() {
        let identity = MTLSIdentity(certificateDER: Data([0xAA]), privateKeyPEM: "k")

        #expect(!identity.canPresent(tokenBoundTo: nil))
    }

    /// The transport declares the authentication method it implements, so a caller cannot
    /// configure it for mTLS and then assemble a request that sends a secret.
    @Test("The transport declares an mTLS authentication method")
    func declaresItsMethod() {
        let identity = MTLSIdentity(certificateDER: Data([0xAA]), privateKeyPEM: "k")
        let transport = MTLSTokenTransport(identity: identity)

        #expect(transport.authenticationMethod == .tlsClientAuth)
        #expect(!transport.authenticationMethod.sendsSecret)
    }

    /// A self-signed deployment says so, because the server checks a different thing: a
    /// registered certificate rather than a chain to an authority.
    @Test("A self-signed identity declares the self-signed method")
    func selfSignedDeclaresItsMethod() {
        let identity = MTLSIdentity(
            certificateDER: Data([0xAA]), privateKeyPEM: "k", isSelfSigned: true)
        let transport = MTLSTokenTransport(identity: identity)

        #expect(transport.authenticationMethod == .selfSignedTLSClientAuth)
    }
}

/// What the HTTP client an mTLS token request is made on does with a redirect.
///
/// `clientConfiguration()` is handed to `AsyncHTTPClient`, whose default is to follow up to
/// five redirects wherever they point — re-posting the body on a `307` or `308`. A token
/// request on that client would carry the authorization code, its verifier and the refresh
/// token to whatever origin a `Location` named. The configuration this package builds turns
/// following off, and these tests ask the second of two servers what reached it.
@Suite("RFC 8705 — the mTLS client does not follow redirects")
struct MTLSRedirectWireTests {

    static let codeFixture = "fixture-authorization-code"

    @Test("A redirected token request is handed back, not followed", arguments: [301, 302, 303, 307, 308])
    func redirectIsNotFollowed(status: Int) async throws {
        let second = try await RedirectWireServer.start { .answer }
        let location = "\(second.origin)/elsewhere"
        let first = try await RedirectWireServer.start { .redirect(status: status, location: location) }

        // The configuration `clientConfiguration()` returns, built from the same function —
        // without a certificate, which a plaintext loopback exchange never presents and which
        // this test would otherwise have to mint.
        let client = HTTPClient(
            eventLoopGroupProvider: .singleton,
            configuration: MTLSTokenTransport.clientConfiguration(
                tls: TLSConfiguration.makeClientConfiguration()))

        let endpoint = try #require(first.url(path: "/token"))
        var request = HTTPClientRequest(url: endpoint.absoluteString)
        request.method = .POST
        request.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")
        request.body = .bytes(ByteBuffer(string: "grant_type=authorization_code&code=\(Self.codeFixture)"))

        let response = try await client.execute(request, timeout: .seconds(10))
        try await client.shutdown()

        #expect(response.status.code == UInt(status), "the redirect itself is the answer")
        #expect(second.requests.isEmpty, "the second origin received \(second.requests.map { "\($0.method) \($0.target) body=\($0.body.utf8.count)B" })")
        #expect(first.requests.count == 1)

        try await first.stop()
        try await second.stop()
    }

    /// The case that matters most, and the one a plaintext pair of servers cannot show: the
    /// token endpoint is `https`, and the redirect names an `http` origin. Following it would
    /// post the authorization code in the clear.
    ///
    /// The client is the one `clientConfiguration()` describes, differing only in what its TLS
    /// layer trusts: the certificate the loopback server was just given.
    @Test(
        "A redirect from https to http is handed back, and nothing is sent in the clear",
        arguments: [301, 302, 303, 307, 308])
    func downgradeIsNotFollowed(status: Int) async throws {
        let certificate = try LoopbackCertificate.mint()
        let plaintext = try await RedirectWireServer.start { .answer }
        let location = "\(plaintext.origin)/elsewhere"
        let secure = try await RedirectWireServer.start(tls: certificate) {
            .redirect(status: status, location: location)
        }

        let client = HTTPClient(
            eventLoopGroupProvider: .singleton,
            configuration: MTLSTokenTransport.clientConfiguration(
                tls: try certificate.clientConfiguration()))

        let endpoint = try #require(secure.url(path: "/token"))
        #expect(endpoint.scheme == "https")
        var request = HTTPClientRequest(url: endpoint.absoluteString)
        request.method = .POST
        request.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")
        request.body = .bytes(ByteBuffer(string: "grant_type=authorization_code&code=\(Self.codeFixture)"))

        let response = try await client.execute(request, timeout: .seconds(10))
        try await client.shutdown()

        #expect(response.status.code == UInt(status), "the redirect itself is the answer")
        #expect(secure.requests.count == 1, "the request did not reach the TLS server")
        #expect(plaintext.requests.isEmpty, "the plaintext origin received \(plaintext.requests.map { "\($0.method) \($0.target) body=\($0.body.utf8.count)B" })")

        try await secure.stop()
        try await plaintext.stop()
    }
}
