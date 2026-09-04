import Foundation
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
