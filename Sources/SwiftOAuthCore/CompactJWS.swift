import Foundation
import Crypto

/// A minimal JWS in compact serialization — RFC 7515, ES256 only.
///
/// swift-crypto carries every primitive this needs and no JOSE layer: there is no JWS type, so
/// compact serialization, base64url and verification are ours. Written once here for RFC 9101
/// and reused by RFC 9449, rather than taking a JOSE dependency for two features.
///
/// ## One algorithm, deliberately
///
/// ES256 and nothing else. The two most-exploited JWT flaws both come from a verifier deciding
/// what to do based on what the token *says* about itself:
///
/// - **`alg: none`** — the token declares itself unsigned and a credulous verifier agrees.
/// - **Algorithm confusion** — a token declares `HS256`, and a verifier that switches on the
///   header verifies an HMAC using the *public* key as the shared secret. The public key is
///   public, so anyone can forge it.
///
/// Accepting exactly one algorithm makes both unrepresentable rather than guarded against.
/// The header's `alg` is read only to be *rejected* if it is not `ES256`; it never selects
/// what happens next.
public enum CompactJWS {

    /// What can go wrong reading a JWS.
    public enum Failure: Error, Equatable {
        /// Not three dot-separated parts.
        case malformed
        /// The header did not declare `ES256`.
        case unsupportedAlgorithm(String?)
        /// A segment was not valid base64url.
        case invalidEncoding
        /// The signature did not verify against the given key.
        case signatureRejected
    }

    /// Signs a payload with ES256.
    ///
    /// - Parameters:
    ///   - payload: The bytes to sign, usually JSON.
    ///   - key: The signing key.
    /// - Returns: The compact serialization, `header.payload.signature`.
    /// - Throws: If the signature could not be produced.
    public static func sign(payload: Data, using key: P256.Signing.PrivateKey) throws -> String {
        let header = Data(#"{"alg":"ES256","typ":"JWT"}"#.utf8)
        let signingInput = "\(base64URL(header)).\(base64URL(payload))"
        // `rawRepresentation` is the 64-byte r‖s pair JWS specifies. The DER encoding, which
        // is the other property on this type, is not what goes on the wire here.
        let signature = try key.signature(for: Data(signingInput.utf8))
        return "\(signingInput).\(base64URL(signature.rawRepresentation))"
    }

    /// Verifies a compact JWS and returns its payload.
    ///
    /// - Parameters:
    ///   - token: The compact serialization.
    ///   - key: The public key the signature must verify against.
    /// - Returns: The payload bytes, once the signature has verified. **Never** before: a
    ///   caller that could read the payload of an unverified token would eventually act on one.
    /// - Throws: ``Failure`` describing what was wrong.
    public static func verify(_ token: String, using key: P256.Signing.PublicKey) throws -> Data {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw Failure.malformed }

        guard let headerData = decodeBase64URL(String(parts[0])),
              let payloadData = decodeBase64URL(String(parts[1])),
              let signatureData = decodeBase64URL(String(parts[2])) else {
            throw Failure.invalidEncoding
        }

        // Read only to refuse. This value never selects a code path — that is the whole
        // defence against `none` and against algorithm confusion.
        let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any]
        let algorithm = (header ?? [:])["alg"] as? String
        guard algorithm == "ES256" else { throw Failure.unsupportedAlgorithm(algorithm) }

        guard let signature = try? P256.Signing.ECDSASignature(
            rawRepresentation: signatureData) else {
            throw Failure.signatureRejected
        }

        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        guard key.isValidSignature(signature, for: signingInput) else {
            throw Failure.signatureRejected
        }
        return payloadData
    }

    /// base64url without padding — RFC 7515 §2.
    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decodes base64url, restoring the padding it omits.
    static func decodeBase64URL(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }
        return Data(base64Encoded: base64)
    }
}
