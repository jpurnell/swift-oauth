import Foundation
import Crypto
import Testing
@testable import SwiftOAuthCore

/// DPoP — RFC 9449, demonstrating possession of a key.
///
/// A bearer token works for whoever holds it. That is the whole of its security model, and it
/// is why a token leaked in a log, a proxy, or a browser extension is immediately usable by
/// whoever finds it. DPoP binds a token to a key the client holds: presenting the token is no
/// longer enough, because each request must also carry a fresh signature over *that* request.
///
/// The proof is a JWS whose header carries the public key and whose payload names the method,
/// the URI, a timestamp and a unique identifier. Every one of those four exists to stop a
/// specific replay, and each has a test below.
@Suite("RFC 9449 — DPoP proofs")
struct DPoPProofTests {

    private static let resource = "https://api.example.com/resource"
    private let key = P256.Signing.PrivateKey()

    /// Built rather than force-unwrapped, so the fixture needs no `!`.
    private func url(_ string: String) throws -> URL {
        // SECURITY: parses a literal written in this test; no request is issued from it.
        try #require(URL(string: string))
    }

    /// A proof this client made verifies, and reports what it was made for.
    @Test("A proof round-trips and carries its method and URI")
    func proofRoundTrips() throws {
        let proof = try DPoPProof.create(method: "POST", url: try url(Self.resource), using: key)
        let verified = try DPoPProof.verify(proof, method: "POST", url: try url(Self.resource))

        #expect(verified.method == "POST")
        #expect(verified.url.absoluteString == Self.resource)
    }

    /// A proof made for one method is refused for another.
    ///
    /// Without this, a proof captured from a `GET` is replayable as a `DELETE` against the same
    /// URL — the signature is valid, and only `htm` distinguishes them.
    @Test("A proof for one method is refused for another")
    func methodIsBound() throws {
        let proof = try DPoPProof.create(method: "GET", url: try url(Self.resource), using: key)

        #expect(throws: (any Error).self) {
            _ = try DPoPProof.verify(proof, method: "DELETE", url: try url(Self.resource))
        }
    }

    /// A proof made for one URI is refused for another.
    ///
    /// Without this, a proof captured by one resource server is replayable by that server
    /// against a different one — which is the attack DPoP most obviously exists to stop.
    @Test("A proof for one URI is refused for another")
    func uriIsBound() throws {
        let proof = try DPoPProof.create(method: "POST", url: try url(Self.resource), using: key)
        let elsewhere = try #require(URL(string: "https://other.example.com/resource"))

        #expect(throws: (any Error).self) {
            _ = try DPoPProof.verify(proof, method: "POST", url: elsewhere)
        }
    }

    /// The URI is compared without query or fragment — RFC 9449 §4.2 says `htu` is the URI
    /// with those removed, so a client that includes them and a server that does not would
    /// disagree on every request carrying a query string.
    @Test("Query and fragment are excluded from the URI comparison")
    func queryIsExcludedFromComparison() throws {
        let withQuery = try #require(URL(string: "https://api.example.com/resource?page=2"))
        let proof = try DPoPProof.create(method: "GET", url: withQuery, using: key)

        let verified = try DPoPProof.verify(proof, method: "GET", url: withQuery)
        #expect(verified.url.absoluteString == "https://api.example.com/resource")
    }

    /// A signature from a different key is refused — the proof is worthless otherwise.
    @Test("A proof signed by another key is refused")
    func wrongKeyIsRefused() throws {
        let other = P256.Signing.PrivateKey()
        let proof = try DPoPProof.create(method: "POST", url: try url(Self.resource), using: key)

        // Swap in a different public key: the header's JWK must be the one that signed.
        let tampered = try DPoPProof.create(method: "POST", url: try url(Self.resource), using: other)
        let parts = proof.split(separator: ".").map(String.init)
        let otherParts = tampered.split(separator: ".").map(String.init)
        let mixed = "\(otherParts[0]).\(parts[1]).\(parts[2])"

        #expect(throws: (any Error).self) {
            _ = try DPoPProof.verify(mixed, method: "POST", url: try url(Self.resource))
        }
    }

    /// A stale proof is refused — §4.3 requires a freshness check, because a proof with no
    /// time bound is one an attacker can hold and use later.
    @Test("A proof older than the window is refused")
    func staleProofIsRefused() throws {
        let proof = try DPoPProof.create(
            method: "POST", url: try url(Self.resource), using: key,
            issuedAt: Date().addingTimeInterval(-600))

        #expect(throws: (any Error).self) {
            _ = try DPoPProof.verify(proof, method: "POST", url: try url(Self.resource))
        }
    }

    /// A proof from the future is refused too. Clock skew is real, so the window is not zero —
    /// but an unbounded future is a proof that never goes stale.
    @Test("A proof far in the future is refused")
    func futureProofIsRefused() throws {
        let proof = try DPoPProof.create(
            method: "POST", url: try url(Self.resource), using: key,
            issuedAt: Date().addingTimeInterval(600))

        #expect(throws: (any Error).self) {
            _ = try DPoPProof.verify(proof, method: "POST", url: try url(Self.resource))
        }
    }

    /// Every proof carries a unique identifier, which is what a server records to refuse a
    /// replay. Two proofs for the same request must differ.
    @Test("Each proof carries a distinct identifier")
    func identifiersAreUnique() throws {
        let first = try DPoPProof.verify(
            try DPoPProof.create(method: "POST", url: try url(Self.resource), using: key),
            method: "POST", url: try url(Self.resource))
        let second = try DPoPProof.verify(
            try DPoPProof.create(method: "POST", url: try url(Self.resource), using: key),
            method: "POST", url: try url(Self.resource))

        #expect(first.identifier != second.identifier)
        #expect(first.identifier.count >= 16, "a guessable jti is a replay window")
    }

    /// The thumbprint is what an access token is bound to — RFC 9449 §6, `cnf.jkt`.
    ///
    /// It must be stable for one key and different for another, or the binding either rejects
    /// the legitimate holder or accepts everyone.
    @Test("The key thumbprint is stable per key and unique across keys")
    func thumbprintIdentifiesTheKey() throws {
        let a = try DPoPProof.verify(
            try DPoPProof.create(method: "GET", url: try url(Self.resource), using: key),
            method: "GET", url: try url(Self.resource))
        let b = try DPoPProof.verify(
            try DPoPProof.create(method: "GET", url: try url(Self.resource), using: key),
            method: "GET", url: try url(Self.resource))
        let other = try DPoPProof.verify(
            try DPoPProof.create(method: "GET", url: try url(Self.resource), using: P256.Signing.PrivateKey()),
            method: "GET", url: try url(Self.resource))

        #expect(a.thumbprint == b.thumbprint)
        #expect(a.thumbprint != other.thumbprint)
    }
}
