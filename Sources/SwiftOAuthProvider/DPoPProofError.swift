import Foundation

/// Why a DPoP proof was refused — RFC 9449 §5 and §7.1.
///
/// Every case carries the same wire code, `invalid_dpop_proof`: §5 gives it as the error a token
/// endpoint returns for an invalid proof, and §7.1 as the `WWW-Authenticate` error a resource
/// returns when "the DPoP proof itself was deemed invalid". A replay is an invalid proof, so it
/// is not given a code of its own.
///
/// A separate type rather than a case of `OAuthError`: that enum is public and switched over
/// by consumers, and a new case would stop their code compiling.
public enum DPoPProofError: Error, Equatable, Sendable {
    /// The proof failed an RFC 9449 §4.3 check (signature, `htm`, `htu`, freshness, shape).
    case invalidProof(String)
    /// The proof's `jti` had already been presented within its acceptance window — §11.1.
    case replayed

    /// The wire error code: always `invalid_dpop_proof`.
    public var errorCode: String { "invalid_dpop_proof" }

    /// A human-readable reason, for `error_description`.
    public var errorDescription: String {
        switch self {
        case .invalidProof(let reason): return reason
        case .replayed: return "The DPoP proof has already been used."
        }
    }

    /// A `WWW-Authenticate` challenge for a protected resource that refuses this proof — §7.1.
    ///
    /// The status to send with it is `401`. At the token endpoint use ``errorCode`` and
    /// ``errorDescription`` in an ordinary RFC 6749 §5.2 error body with status `400`.
    public var challenge: String {
        let description = errorDescription
            .replacingOccurrences(of: "\\", with: "")
            .replacingOccurrences(of: "\"", with: "'")
        return #"DPoP error="invalid_dpop_proof", error_description="\#(description)""#
    }
}
