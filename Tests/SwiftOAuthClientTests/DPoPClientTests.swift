import Foundation
import Crypto
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthClient

/// Presenting DPoP proofs from the client — RFC 9449 §5 and §7.
///
/// A key held by the client is what makes a bound token worth having. This is the half that
/// holds it: one key per connection, a fresh proof per request, and the `DPoP` header on both
/// the token request and every resource request afterwards.
@Suite("RFC 9449 — the client's DPoP session")
struct DPoPClientTests {

    private func url(_ string: String) throws -> URL {
        // SECURITY: parses a literal written in this test; no request is issued from it.
        try #require(URL(string: string))
    }

    /// A session produces a proof a server would accept.
    @Test("A session's proof verifies against the request it was made for")
    func proofVerifies() throws {
        let session = DPoPSession()
        let endpoint = try url("https://api.example.com/resource")

        let header = try session.proof(method: "POST", url: endpoint)
        let verified = try DPoPProof.verify(header, method: "POST", url: endpoint)

        #expect(verified.thumbprint == session.keyThumbprint)
    }

    /// One key per session, so every token a session obtains is bound to the same thumbprint.
    ///
    /// A session that generated a key per request would bind each token to a key it then
    /// discarded, making every token unusable on its next request.
    @Test("A session keeps one key across requests")
    func keyIsStableWithinASession() throws {
        let session = DPoPSession()
        let a = try url("https://api.example.com/one")
        let b = try url("https://api.example.com/two")

        let first = try DPoPProof.verify(
            try session.proof(method: "GET", url: a), method: "GET", url: a)
        let second = try DPoPProof.verify(
            try session.proof(method: "GET", url: b), method: "GET", url: b)

        #expect(first.thumbprint == second.thumbprint)
        #expect(first.thumbprint == session.keyThumbprint)
    }

    /// Separate sessions hold separate keys, so one connection's token cannot be replayed by
    /// another.
    @Test("Separate sessions hold separate keys")
    func sessionsAreIndependent() throws {
        let endpoint = try url("https://api.example.com/resource")
        let first = DPoPSession(), second = DPoPSession()

        #expect(first.keyThumbprint != second.keyThumbprint)
        let proof = try first.proof(method: "GET", url: endpoint)
        let verified = try DPoPProof.verify(proof, method: "GET", url: endpoint)
        #expect(verified.thumbprint != second.keyThumbprint)
    }

    /// Every proof is fresh, so a server refusing a repeated `jti` never sees one.
    @Test("Each request gets a distinct proof")
    func proofsAreNotReused() throws {
        let session = DPoPSession()
        let endpoint = try url("https://api.example.com/resource")

        let a = try DPoPProof.verify(
            try session.proof(method: "GET", url: endpoint), method: "GET", url: endpoint)
        let b = try DPoPProof.verify(
            try session.proof(method: "GET", url: endpoint), method: "GET", url: endpoint)

        #expect(a.identifier != b.identifier,
                "a reused proof is refused by any server enforcing replay protection")
    }

    /// The headers a request carries: the token as `DPoP`, not `Bearer`.
    ///
    /// RFC 9449 §7.1 changes the scheme. A bound token sent as `Bearer` is either refused, or —
    /// worse, on a server that accepts both — accepted without the proof being checked, which
    /// silently discards the binding.
    @Test("A bound token is presented with the DPoP scheme, not Bearer")
    func boundTokenUsesDPoPScheme() throws {
        let session = DPoPSession()
        let endpoint = try url("https://api.example.com/resource")

        let headers = try session.authorizationHeaders(
            accessToken: "bound-token", method: "GET", url: endpoint)

        #expect(headers["Authorization"] == "DPoP bound-token")
        // Verified rather than merely present. A header that exists and does not verify is the
        // failure worth catching, and asserting non-nil would pass for one.
        let proof = try #require(headers["DPoP"])
        let verified = try DPoPProof.verify(proof, method: "GET", url: endpoint)
        #expect(verified.thumbprint == session.keyThumbprint)
    }
}
