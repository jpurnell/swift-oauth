import Foundation
import Crypto
import SwiftOAuthCore

/// A client's DPoP key, and the proofs it makes — RFC 9449.
///
/// A bound token is only worth having if the client still holds the key it was bound to, so
/// this owns that key for the life of a connection and signs a fresh proof per request.
///
/// ## One key per session
///
/// The key is generated once and kept. A session that made a new key per request would bind
/// each token to a key it then discarded, and every token would be unusable on the request
/// after the one that obtained it — the failure would look like the server rejecting valid
/// tokens.
///
/// ## The key does not outlive the process
///
/// It is held in memory and not persisted. That is a deliberate limit rather than an oversight:
/// persisting it means writing a private key to disk, which needs the same protection as the
/// tokens it guards, and a token bound to a key that is gone is simply one the client must
/// obtain again. A restart therefore costs a re-authorisation, which is the safe direction to
/// fail in.
public struct DPoPSession: Sendable {

    /// The key's raw bytes, rather than the key.
    ///
    /// `P256.Signing.PrivateKey` is `Sendable` on Apple platforms and is not on
    /// corelibs-crypto, so storing one in a `Sendable` struct compiles on a Mac and fails to
    /// build on Linux. Carrying the bytes and rebuilding the key per signature keeps nothing
    /// non-`Sendable` stored, at the cost of one key construction per proof.
    ///
    /// Exposure is unchanged: these are the same secret bytes the key object holds.
    private let keyBytes: Data

    /// The RFC 7638 thumbprint of this session's public key.
    ///
    /// What an authorization server records as `cnf.jkt` when it issues a bound token, and
    /// what a resource server compares each request's proof against.
    public let keyThumbprint: String

    /// Creates a session with a fresh key.
    public init() {
        // stochastic:exempt a signing key must be unpredictable; there is no seeded path here
        let key = P256.Signing.PrivateKey()
        self.keyBytes = key.rawRepresentation
        self.keyThumbprint = DPoPProof.thumbprint(of: key.publicKey)
    }

    /// Creates a session over an existing key, for a caller that manages key lifetime itself.
    ///
    /// - Parameter key: The key to sign proofs with.
    public init(key: P256.Signing.PrivateKey) {
        self.keyBytes = key.rawRepresentation
        self.keyThumbprint = DPoPProof.thumbprint(of: key.publicKey)
    }

    /// A proof for one request.
    ///
    /// - Parameters:
    ///   - method: The HTTP method.
    ///   - url: The request URI.
    /// - Returns: The value for the `DPoP` header.
    /// - Throws: If the proof could not be signed.
    public func proof(method: String, url: URL) throws -> String {
        let key = try P256.Signing.PrivateKey(rawRepresentation: keyBytes)
        return try DPoPProof.create(method: method, url: url, using: key)
    }

    /// The headers a request carrying a bound token needs.
    ///
    /// The token goes in `Authorization` with the **`DPoP`** scheme, not `Bearer` — RFC 9449
    /// §7.1. That distinction is load-bearing: a bound token sent as `Bearer` is either refused,
    /// or, on a server that accepts both schemes, accepted *without the proof being checked* —
    /// which silently discards the binding and leaves a token that behaves exactly like the
    /// bearer token it was supposed to stop being.
    ///
    /// - Parameters:
    ///   - accessToken: The bound access token.
    ///   - method: The HTTP method.
    ///   - url: The request URI.
    /// - Returns: `Authorization` and `DPoP`, ready to merge into a request.
    /// - Throws: If the proof could not be signed.
    public func authorizationHeaders(
        accessToken: String, method: String, url: URL
    ) throws -> [String: String] {
        [
            "Authorization": "DPoP \(accessToken)",
            "DPoP": try proof(method: method, url: url)
        ]
    }
}
