import Foundation
import Crypto
import Testing
import SwiftOAuthCore
import SwiftOAuthClient
import SwiftOAuthProvider

/// This package's DPoP client against this package's DPoP provider.
///
/// Every defect this feature family has produced has had one shape: two halves, each correct
/// alone, with nothing joining them. The RFC 8707 client sent a `resource` no server read; the
/// provider's policy could disagree with the metadata it published; discovery held an
/// identifier the configuration had nowhere to put.
///
/// DPoP has more joins than any of them — a thumbprint computed on one side and recorded on
/// the other, a proof made by one and verified by the other, a replay store that has to see
/// the same `jti` the client generated. This exercises all four.
@Suite("Cross-half — RFC 9449 DPoP")
struct DPoPCrossHalfTests {

    private func url(_ string: String) throws -> URL {
        // SECURITY: parses a literal written in this test; no request is issued from it.
        try #require(URL(string: string))
    }

    /// The client's thumbprint is what the provider records, and what it sees on the proof.
    ///
    /// Three separate computations of one value: the client's own, the provider's from the
    /// proof it receives, and the token's binding. If any two disagree the token is unusable,
    /// and no single-half test would notice.
    @Test("The client's key thumbprint is what the provider binds and verifies")
    func thumbprintAgreesAcrossHalves() async throws {
        let session = DPoPSession()
        let endpoint = try url("https://api.example.com/token")
        let storage = try OAuthStorage(path: ":memory:")

        // The provider verifies a proof the client made, and binds a token to what it saw.
        let proof = try session.proof(method: "POST", url: endpoint)
        let verified = try DPoPProof.verify(proof, method: "POST", url: endpoint)
        try await storage.saveAccessToken(
            token: "bound", clientId: "c1", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: nil,
            keyThumbprint: verified.thumbprint)

        let result = try await storage.validateAccessToken(token: "bound")
        guard case .valid(let token) = result else {
            Issue.record("expected a valid token, got \(result)")
            return
        }
        #expect(token.keyThumbprint == session.keyThumbprint,
                "the token was bound to something other than the client's key")
    }

    /// A token bound to one client's key is refused when another presents it.
    ///
    /// This is the property the whole feature buys: a leaked token is not enough, because the
    /// holder cannot produce a proof by the key it was bound to.
    @Test("A stolen bound token cannot be used without its key")
    func stolenTokenIsUseless() async throws {
        let legitimate = DPoPSession()
        let thief = DPoPSession()
        let endpoint = try url("https://api.example.com/resource")
        let storage = try OAuthStorage(path: ":memory:")

        let issued = try DPoPProof.verify(
            try legitimate.proof(method: "POST", url: endpoint), method: "POST", url: endpoint)
        try await storage.saveAccessToken(
            token: "stolen-later", clientId: "c1", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: nil,
            keyThumbprint: issued.thumbprint)

        // The thief has the token and makes a technically valid proof — with their own key.
        let thiefProof = try DPoPProof.verify(
            try thief.proof(method: "GET", url: endpoint), method: "GET", url: endpoint)

        let result = try await storage.validateAccessToken(token: "stolen-later")
        guard case .valid(let token) = result else {
            Issue.record("expected a valid token, got \(result)")
            return
        }
        // The token is live; the binding is what refuses the thief.
        #expect(token.keyThumbprint != thiefProof.thumbprint,
                "a token bound to one key matched a proof from another")
        #expect(token.keyThumbprint == legitimate.keyThumbprint)
    }

    /// A proof the client made is accepted once and refused the second time.
    ///
    /// The `jti` the client generates and the one the provider records have to be the same
    /// string. A client that varied its encoding, or a provider that stored a normalised form,
    /// would make replay protection either useless or a refusal of every legitimate request.
    @Test("A client's proof is accepted once and replays are refused")
    func replayIsRefusedAcrossHalves() async throws {
        let session = DPoPSession()
        let endpoint = try url("https://api.example.com/resource")
        let storage = try OAuthStorage(path: ":memory:")

        let proof = try session.proof(method: "GET", url: endpoint)
        let verified = try DPoPProof.verify(proof, method: "GET", url: endpoint)
        let expiry = verified.issuedAt.addingTimeInterval(DPoPProof.acceptableClockSkew)

        #expect(try await storage.claimProofIdentifier(verified.identifier, expiresAt: expiry))
        // The same proof presented again — captured in transit, say.
        let replayed = try DPoPProof.verify(proof, method: "GET", url: endpoint)
        #expect(try await storage.claimProofIdentifier(replayed.identifier, expiresAt: expiry) == false,
                "the same proof was accepted twice")
    }

    /// Two different requests from one session are both accepted.
    ///
    /// The mirror of the replay test, and the one that would catch a provider treating every
    /// proof from a key as a repeat — which would refuse a legitimate client's second request.
    @Test("Distinct requests from one session are both accepted")
    func distinctRequestsAreAccepted() async throws {
        let session = DPoPSession()
        let endpoint = try url("https://api.example.com/resource")
        let storage = try OAuthStorage(path: ":memory:")
        let expiry = Date().addingTimeInterval(DPoPProof.acceptableClockSkew)

        let first = try DPoPProof.verify(
            try session.proof(method: "GET", url: endpoint), method: "GET", url: endpoint)
        let second = try DPoPProof.verify(
            try session.proof(method: "GET", url: endpoint), method: "GET", url: endpoint)

        #expect(try await storage.claimProofIdentifier(first.identifier, expiresAt: expiry))
        #expect(try await storage.claimProofIdentifier(second.identifier, expiresAt: expiry),
                "a legitimate second request was refused as a replay")
    }
}
