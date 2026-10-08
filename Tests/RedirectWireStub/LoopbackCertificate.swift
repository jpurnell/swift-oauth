import Crypto
import Foundation
import NIOSSL
import SwiftASN1
import X509

/// A TLS server certificate for `127.0.0.1`, with the key that goes with it.
///
/// Minted per run rather than checked in. A fixture would mean a private key in the repository
/// and an expiry date nobody remembers choosing — a suite that goes red on a calendar day.
/// A minted certificate is valid for half an hour either side of the moment it is made.
///
/// Test support only, in a target that is in no product.
public struct LoopbackCertificate: Sendable {

    /// The certificate, DER-encoded.
    public let der: [UInt8]

    /// The certificate, PEM-encoded.
    public let pem: String

    /// The private key, PEM-encoded. Only the stub server reads it.
    public let keyPEM: String

    /// Names the environment variables ``installed()`` reads.
    public enum Environment {
        /// The path of a PEM certificate the platform's trust store already holds.
        public static let certificatePath = "SWIFT_OAUTH_TEST_TLS_CERT"
        /// The path of that certificate's PEM private key.
        public static let keyPath = "SWIFT_OAUTH_TEST_TLS_KEY"
    }

    /// Mints a self-signed certificate naming the loopback address.
    ///
    /// Nothing trusts it until a client is told to: a NIO client through its `trustRoots`,
    /// `URLSession` on Apple platforms through the test seam in `CredentialRequest`.
    ///
    /// - Returns: The certificate and its key.
    /// - Throws: If the certificate cannot be built or serialized.
    public static func mint() throws -> LoopbackCertificate {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName("swift-oauth loopback test server") }
        let now = Date()
        let extensions = try Certificate.Extensions {
            Critical(BasicConstraints.notCertificateAuthority)
            SubjectAlternativeNames([
                .ipAddress(ASN1OctetString(contentBytes: [127, 0, 0, 1])),
                .dnsName("localhost")
            ])
            // Apple's verifier refuses a TLS server certificate without this.
            try ExtendedKeyUsage([.serverAuth])
        }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: now.addingTimeInterval(-1_800),
            notValidAfter: now.addingTimeInterval(1_800),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: Certificate.PrivateKey(key))

        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return LoopbackCertificate(
            der: serializer.serializedBytes,
            pem: try certificate.serializeAsPEM().pemString,
            keyPEM: key.pemRepresentation)
    }

    /// A certificate the platform's own trust store was given before this process started.
    ///
    /// For `URLSession` on Linux, which has no way to be told what to trust: it verifies
    /// against the system bundle and swift-corelibs-foundation offers no delegate, option or
    /// variable that changes that. So the Linux CI job generates a certificate, installs it in
    /// the container's bundle, and names the files here.
    ///
    /// - Returns: The installed certificate, or `nil` when the variables are not set — which
    ///   is every environment but that job.
    public static func installed() -> LoopbackCertificate? {
        let environment = ProcessInfo.processInfo.environment
        guard let certificatePath = environment[Environment.certificatePath],
              let keyPath = environment[Environment.keyPath],
              let pem = FileManager.default.contents(atPath: certificatePath)
                .flatMap({ String(data: $0, encoding: .utf8) }),
              let keyPEM = FileManager.default.contents(atPath: keyPath)
                .flatMap({ String(data: $0, encoding: .utf8) }) else {
            return nil
        }
        // silent: a certificate that will not parse is the same as none installed — the tests that need it are skipped, by name
        guard let der = try? NIOSSLCertificate(bytes: Array(pem.utf8), format: .pem).toDERBytes() else {
            return nil
        }
        return LoopbackCertificate(der: der, pem: pem, keyPEM: keyPEM)
    }

    /// A server-side TLS context presenting this certificate.
    ///
    /// - Returns: The context.
    /// - Throws: If the certificate or key does not load.
    public func serverContext() throws -> NIOSSLContext {
        let certificate = try NIOSSLCertificate(bytes: der, format: .der)
        let key = try NIOSSLPrivateKey(bytes: Array(keyPEM.utf8), format: .pem)
        let configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(certificate)],
            privateKey: .privateKey(key))
        return try NIOSSLContext(configuration: configuration)
    }

    /// A client-side TLS configuration that trusts this certificate and nothing else.
    ///
    /// - Returns: The configuration.
    /// - Throws: If the certificate does not load.
    public func clientConfiguration() throws -> TLSConfiguration {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.trustRoots = .certificates([try NIOSSLCertificate(bytes: der, format: .der)])
        return configuration
    }
}
