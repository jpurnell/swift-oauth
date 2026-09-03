import Foundation
import Crypto

/// Binding a token to an X.509 certificate — RFC 8705 §3.
///
/// The same idea as DPoP with a different key. DPoP proves possession per request with a
/// signature over that request; mTLS proves it by completing a TLS handshake with a
/// certificate. Either way the token stops working for whoever merely holds it.
///
/// The binding value differs because the key does: DPoP binds to a JWK thumbprint of a key the
/// client generated, mTLS to the SHA-256 of the certificate's DER encoding — `x5t#S256` in the
/// token's `cnf` claim.
public enum CertificateBinding {

    /// The `x5t#S256` value for a certificate — RFC 8705 §3.1.
    ///
    /// - Parameter der: The certificate in DER form.
    /// - Returns: The base64url-encoded SHA-256 of those bytes.
    public static func thumbprint(ofDER der: Data) -> String {
        CompactJWS.base64URL(Data(SHA256.hash(data: der)))
    }

    /// Whether a presented certificate confirms a token's binding.
    ///
    /// - Parameters:
    ///   - bound: The thumbprint the token was issued against, or `nil` if it is unbound.
    ///   - presented: The thumbprint of the certificate on this connection, or `nil` if none.
    /// - Returns: `true` only when both are present and equal.
    ///
    /// **An absent binding is not satisfied by anything.** The tempting implementation treats
    /// `nil` as "no requirement" and returns `true`, which makes every ordinary bearer token
    /// appear certificate-confirmed — so a caller checking this before honouring a request
    /// would accept unbound tokens as though they had passed a check they never took. Whether
    /// an unbound token is acceptable is a policy question for the caller, and it is a
    /// different question from whether a certificate confirms a binding.
    public static func confirms(bound: String?, presented: String?) -> Bool {
        guard let bound, let presented else { return false }
        // Constant-time comparison. The values are public, so this is not strictly required;
        // it costs nothing and removes the need for a reader to work out whether it matters.
        return Data(bound.utf8).ct_isEqual(to: Data(presented.utf8))
    }
}

private extension Data {
    /// Compares two byte sequences without an early exit.
    func ct_isEqual(to other: Data) -> Bool {
        guard count == other.count else { return false }
        var difference: UInt8 = 0
        for (a, b) in zip(self, other) { difference |= a ^ b }
        return difference == 0
    }
}
