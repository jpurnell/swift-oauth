import Foundation
import AsyncHTTPClient
import NIOCore
import NIOSSL
import SwiftOAuthCore
import SwiftOAuthClient

/// The certificate a client presents, and the token binding it produces — RFC 8705.
///
/// Held separately from the transport because two different parties need it: the transport, to
/// configure TLS, and the caller, to decide whether a stored token is one this identity can
/// still present.
public struct MTLSIdentity: Sendable {

    /// The certificate in DER form, as it goes on the wire.
    public let certificateDER: Data

    /// The private key, PEM-encoded.
    ///
    /// Held as text rather than as a parsed key so this type stays `Sendable` and inert:
    /// nothing here can sign, and the key reaches NIOSSL only when a connection is made.
    public let privateKeyPEM: String

    /// Whether the certificate is self-signed and registered rather than chained to an
    /// authority — RFC 8705 §2.2.
    ///
    /// The server checks a different thing in each case, so it has to be told which.
    public let isSelfSigned: Bool

    /// The `x5t#S256` binding value for this certificate.
    ///
    /// What an authorization server records when it issues a bound token, and what this client
    /// compares against to know whether a stored token is still usable.
    public let certificateThumbprint: String

    /// Creates an identity.
    ///
    /// - Parameters:
    ///   - certificateDER: The certificate, DER-encoded.
    ///   - privateKeyPEM: Its private key, PEM-encoded.
    ///   - isSelfSigned: Whether the server should treat it as registered rather than chained.
    public init(certificateDER: Data, privateKeyPEM: String, isSelfSigned: Bool = false) {
        self.certificateDER = certificateDER
        self.privateKeyPEM = privateKeyPEM
        self.isSelfSigned = isSelfSigned
        self.certificateThumbprint = CertificateBinding.thumbprint(ofDER: certificateDER)
    }

    /// Whether a token bound to `thumbprint` is one this identity can present.
    ///
    /// - Parameter thumbprint: The binding recorded on the token, or `nil` if it has none.
    /// - Returns: `true` only for a token bound to *this* certificate.
    ///
    /// An unbound token returns `false`, and that is the answer to the question asked: whether
    /// this identity can present it *as a bound token*. Treating "no binding" as "mine" would
    /// have a client believe every bearer token it holds is certificate-bound.
    public func canPresent(tokenBoundTo thumbprint: String?) -> Bool {
        CertificateBinding.confirms(bound: thumbprint, presented: certificateThumbprint)
    }

    /// The TLS configuration that presents this certificate.
    ///
    /// - Returns: A client configuration carrying the certificate chain and key.
    /// - Throws: If NIOSSL cannot read either.
    public func tlsConfiguration() throws -> TLSConfiguration {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.certificateChain = [
            .certificate(try NIOSSLCertificate(bytes: Array(certificateDER), format: .der))
        ]
        configuration.privateKey = .privateKey(
            try NIOSSLPrivateKey(bytes: Array(privateKeyPEM.utf8), format: .pem))
        return configuration
    }
}

/// A token transport that authenticates with a client certificate — RFC 8705.
///
/// This exists because `URLSessionTokenTransport` cannot do mutual TLS on Linux, and that is a
/// hard limit rather than a configuration gap: corelibs-foundation's `URLCredential` has only
/// `init(user:password:persistence:)`, with no identity-based initialiser, and its source says
/// there is no `SecIdentity` support. `NSURLAuthenticationMethodClientCertificate` *is* declared
/// there — so code referencing it compiles and the challenge can be matched — but no credential
/// can be built to answer it. The name is present and the capability is not.
///
/// NIOSSL's `TLSConfiguration` does expose `certificateChain` and `privateKey`, and
/// AsyncHTTPClient accepts one. So mutual TLS means a NIO-backed transport, which is why this
/// target exists and why it is separate: a consumer that does not need mTLS does not link NIO.
public struct MTLSTokenTransport: Sendable {

    private let identity: MTLSIdentity

    /// Which RFC 8705 method this transport implements.
    ///
    /// Derived from the identity rather than configured separately, so a caller cannot declare
    /// one thing to the server and present another.
    public var authenticationMethod: ClientAuthenticationMethod {
        identity.isSelfSigned ? .selfSignedTLSClientAuth : .tlsClientAuth
    }

    /// Creates a transport that presents `identity`.
    public init(identity: MTLSIdentity) {
        self.identity = identity
    }

    /// The HTTP client configuration this transport requires.
    ///
    /// - Returns: A configuration whose TLS layer presents the client certificate.
    /// - Throws: If the certificate or key could not be read.
    public func clientConfiguration() throws -> HTTPClient.Configuration {
        HTTPClient.Configuration(tlsConfiguration: try identity.tlsConfiguration())
    }
}
