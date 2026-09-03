import Foundation
import Crypto
import Testing
@testable import SwiftOAuthCore

/// mTLS client authentication and certificate-bound tokens — RFC 8705.
///
/// The same idea as DPoP with a different key: instead of proving possession per request with a
/// signature, the client proves it by completing a TLS handshake with a certificate. The token
/// is then bound to that certificate, and a holder who cannot present it cannot use the token.
///
/// DPoP binds to a key the client generated; mTLS binds to one a certificate authority — or the
/// client itself — issued. The binding value differs accordingly: DPoP uses the JWK thumbprint,
/// mTLS the SHA-256 of the certificate's DER encoding.
@Suite("RFC 8705 — certificate binding")
struct CertificateBindingTests {

    /// The two authentication methods RFC 8705 defines, on the wire.
    ///
    /// A server matching the wrong string refuses every client using that method, and the
    /// refusal reads as a misconfigured client rather than a typo in a constant.
    @Test("The mTLS authentication methods carry their specified wire values")
    func methodWireValues() {
        #expect(ClientAuthenticationMethod.tlsClientAuth.rawValue == "tls_client_auth")
        #expect(ClientAuthenticationMethod.selfSignedTLSClientAuth.rawValue
            == "self_signed_tls_client_auth")
    }

    /// And parse back, so a server reading a registration and a client writing one agree.
    @Test("The mTLS methods round-trip")
    func methodsRoundTrip() {
        #expect(ClientAuthenticationMethod(rawValue: "tls_client_auth") == .tlsClientAuth)
        #expect(ClientAuthenticationMethod(rawValue: "self_signed_tls_client_auth")
            == .selfSignedTLSClientAuth)
    }

    /// Neither sends a secret. That is the point of them: there is no shared secret to leak,
    /// because possession is proven by the handshake.
    @Test("The mTLS methods carry no client secret")
    func mTLSMethodsSendNoSecret() {
        #expect(!ClientAuthenticationMethod.tlsClientAuth.sendsSecret)
        #expect(!ClientAuthenticationMethod.selfSignedTLSClientAuth.sendsSecret)
        #expect(ClientAuthenticationMethod.clientSecretBasic.sendsSecret)
    }

    /// The binding value is the SHA-256 of the DER certificate — RFC 8705 §3.1, `x5t#S256`.
    @Test("A certificate thumbprint is its DER SHA-256, base64url encoded")
    func thumbprintIsDERHash() {
        let der = Data([0x30, 0x82, 0x01, 0x0a, 0xde, 0xad, 0xbe, 0xef])

        let thumbprint = CertificateBinding.thumbprint(ofDER: der)
        let expected = CompactJWS.base64URL(Data(SHA256.hash(data: der)))

        #expect(thumbprint == expected)
    }

    /// Stable for one certificate, distinct across certificates — or the binding either
    /// rejects the legitimate holder or accepts everyone.
    @Test("The thumbprint is stable per certificate and unique across them")
    func thumbprintIdentifiesTheCertificate() {
        let first = Data([0x01, 0x02, 0x03])
        let second = Data([0x01, 0x02, 0x04])

        #expect(CertificateBinding.thumbprint(ofDER: first)
            == CertificateBinding.thumbprint(ofDER: first))
        #expect(CertificateBinding.thumbprint(ofDER: first)
            != CertificateBinding.thumbprint(ofDER: second))
    }

    /// A certificate-bound token is confirmed by comparing thumbprints, and a mismatch is
    /// refused. This is the check a resource server performs on every request.
    @Test("A token bound to one certificate rejects another")
    func bindingRejectsAnotherCertificate() {
        let issued = CertificateBinding.thumbprint(ofDER: Data([0xAA]))
        let presented = CertificateBinding.thumbprint(ofDER: Data([0xBB]))

        #expect(CertificateBinding.confirms(bound: issued, presented: issued))
        #expect(!CertificateBinding.confirms(bound: issued, presented: presented))
    }

    /// An unbound token is not confirmed by any certificate.
    ///
    /// The subtle case: `nil` binding must not mean "matches anything". A token with no binding
    /// is an ordinary bearer token, and treating an absent binding as satisfied would make
    /// every unbound token appear certificate-confirmed.
    @Test("An absent binding is not confirmed by any certificate")
    func absentBindingIsNotConfirmed() {
        #expect(!CertificateBinding.confirms(
            bound: nil, presented: CertificateBinding.thumbprint(ofDER: Data([0xAA]))))
        #expect(!CertificateBinding.confirms(bound: nil, presented: nil))
    }

    /// A bound token presented with no certificate is refused.
    @Test("A bound token with no certificate presented is refused")
    func boundTokenNeedsACertificate() {
        let issued = CertificateBinding.thumbprint(ofDER: Data([0xAA]))

        #expect(!CertificateBinding.confirms(bound: issued, presented: nil))
    }
}
