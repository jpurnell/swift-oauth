import Foundation
import Crypto
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// A generator that always answers the same word, so two proofs carry the same `jti`.
private struct RepeatingGenerator: RandomNumberGenerator {
    mutating func next() -> UInt64 { 0x0123_4567_89AB_CDEF }
}

/// Refusing a replayed DPoP proof — RFC 9449 §11.1, through the storage protocol, on both stores.
///
/// Expected values come from the RFC: "servers can store the `jti` value of each DPoP proof for
/// the time window in which the respective DPoP proof JWT would be accepted to prevent multiple
/// uses of the same DPoP proof", and requests with a `jti` seen before "would be declined".
@Suite("RFC 9449 §11.1 — proof replay")
struct DPoPReplayTests {

    private let url = URL(string: "https://mcp.example.com/resource") ?? URL(fileURLWithPath: "/")

    private func makeServer(_ kind: StoreKind) async throws -> (OAuthServer, any OAuthProviderStorage) {
        let storage = try kind.makeStore()
        let server = OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools"],
            served: .core, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        return (server, storage)
    }

    // MARK: Through the storage protocol

    @Test("A fresh jti is claimed", arguments: StoreKind.allCases)
    func freshIdentifierIsClaimed(store kind: StoreKind) async throws {
        let store = try kind.makeStore()
        #expect(try await store.claimProofIdentifier("jti-1", expiresAt: Date().addingTimeInterval(300)))
    }

    @Test("A replayed jti is refused", arguments: StoreKind.allCases)
    func replayedIdentifierIsRefused(store kind: StoreKind) async throws {
        let store = try kind.makeStore()
        let expiry = Date().addingTimeInterval(300)
        #expect(try await store.claimProofIdentifier("jti-2", expiresAt: expiry))
        #expect(try await store.claimProofIdentifier("jti-2", expiresAt: expiry) == false)
    }

    @Test("The same jti is claimable again once its window has passed and been swept",
          arguments: StoreKind.allCases)
    func identifierIsClaimableAfterTheWindow(store kind: StoreKind) async throws {
        let store = try kind.makeStore()
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        #expect(try await store.claimProofIdentifier("jti-3", expiresAt: start.addingTimeInterval(300)))
        // Inside the window the record is kept.
        #expect(try await store.sweepExpiredProofIdentifiers(now: start.addingTimeInterval(299)) == 0)
        #expect(try await store.claimProofIdentifier("jti-3", expiresAt: start.addingTimeInterval(600)) == false)
        // After it, the record may go, and the identifier is free again.
        #expect(try await store.sweepExpiredProofIdentifiers(now: start.addingTimeInterval(301)) == 1)
        #expect(try await store.claimProofIdentifier("jti-3", expiresAt: start.addingTimeInterval(900)))
    }

    @Test("Of many concurrent presentations of one jti exactly one wins", arguments: StoreKind.allCases)
    func concurrentClaimsHaveOneWinner(store kind: StoreKind) async throws {
        let store = try kind.makeStore()
        let expiry = Date().addingTimeInterval(300)
        let winners = try await withThrowingTaskGroup(of: Bool.self) { group in
            for _ in 0..<25 {
                group.addTask { try await store.claimProofIdentifier("jti-race", expiresAt: expiry) }
            }
            var won = 0
            for try await claimed in group where claimed { won += 1 }
            return won
        }
        #expect(winners == 1)
    }

    // MARK: Through the server

    @Test("A fresh proof is accepted by the server", arguments: StoreKind.allCases)
    func freshProofIsAccepted(store kind: StoreKind) async throws {
        let (server, _) = try await makeServer(kind)
        let key = P256.Signing.PrivateKey()
        let now = Date()
        let proof = try DPoPProof.create(method: "GET", url: url, using: key, issuedAt: now)

        let verified = try await server.verifyDPoPProof(proof, method: "GET", url: url, now: now)

        #expect(verified.thumbprint == DPoPProof.thumbprint(of: key.publicKey))
    }

    @Test("A replayed proof is refused with invalid_dpop_proof", arguments: StoreKind.allCases)
    func replayedProofIsRefused(store kind: StoreKind) async throws {
        let (server, _) = try await makeServer(kind)
        let now = Date()
        let proof = try DPoPProof.create(
            method: "GET", url: url, using: P256.Signing.PrivateKey(), issuedAt: now)
        _ = try await server.verifyDPoPProof(proof, method: "GET", url: url, now: now)

        do {
            _ = try await server.verifyDPoPProof(proof, method: "GET", url: url, now: now)
            Issue.record("a proof was accepted twice")
        } catch let error as DPoPProofError {
            #expect(error.errorCode == "invalid_dpop_proof")
            #expect(error == .replayed)
            #expect(error.challenge.hasPrefix("DPoP "))
            #expect(error.challenge.contains(#"error="invalid_dpop_proof""#))
        }
    }

    @Test("A proof that fails the §4.3 checks is refused with invalid_dpop_proof",
          arguments: StoreKind.allCases)
    func badProofIsRefused(store kind: StoreKind) async throws {
        let (server, _) = try await makeServer(kind)
        let now = Date()
        let proof = try DPoPProof.create(
            method: "GET", url: url, using: P256.Signing.PrivateKey(), issuedAt: now)

        do {
            // Made for GET, presented for POST: §4.3 `htm`.
            _ = try await server.verifyDPoPProof(proof, method: "POST", url: url, now: now)
            Issue.record("a proof for another method was accepted")
        } catch let error as DPoPProofError {
            #expect(error.errorCode == "invalid_dpop_proof")
            #expect(error != .replayed)
        }
    }

    @Test("A refused proof does not spend its jti", arguments: StoreKind.allCases)
    func refusedProofDoesNotSpendItsIdentifier(store kind: StoreKind) async throws {
        let (server, _) = try await makeServer(kind)
        let now = Date()
        let proof = try DPoPProof.create(
            method: "GET", url: url, using: P256.Signing.PrivateKey(), issuedAt: now)
        _ = try? await server.verifyDPoPProof(proof, method: "POST", url: url, now: now)

        // The refusal above was for the method, so the right request must still be honoured.
        let verified = try await server.verifyDPoPProof(proof, method: "GET", url: url, now: now)
        #expect(verified.method == "GET")
    }

    @Test("The same jti is accepted again after its window, with an injected clock",
          arguments: StoreKind.allCases)
    func sameIdentifierAfterTheWindow(store kind: StoreKind) async throws {
        let (server, _) = try await makeServer(kind)
        let key = P256.Signing.PrivateKey()
        let first = Date(timeIntervalSince1970: 1_800_000_000)
        let later = first.addingTimeInterval(2 * DPoPProof.acceptableClockSkew + 1)
        var g1 = RepeatingGenerator()
        var g2 = RepeatingGenerator()
        let p1 = try DPoPProof.create(method: "GET", url: url, using: key, issuedAt: first, generator: &g1)
        let p2 = try DPoPProof.create(method: "GET", url: url, using: key, issuedAt: later, generator: &g2)

        let a = try await server.verifyDPoPProof(p1, method: "GET", url: url, now: first)
        let b = try await server.verifyDPoPProof(p2, method: "GET", url: url, now: later)

        #expect(a.identifier == b.identifier)
    }

    @Test("Of two concurrent presentations of one proof exactly one wins", arguments: StoreKind.allCases)
    func concurrentPresentationsHaveOneWinner(store kind: StoreKind) async throws {
        let (server, _) = try await makeServer(kind)
        let now = Date()
        let proof = try DPoPProof.create(
            method: "GET", url: url, using: P256.Signing.PrivateKey(), issuedAt: now)
        let target = url
        let winners = await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<10 {
                group.addTask {
                    (try? await server.verifyDPoPProof(proof, method: "GET", url: target, now: now)) != nil
                }
            }
            var won = 0
            for await accepted in group where accepted { won += 1 }
            return won
        }
        #expect(winners == 1)
    }
}
