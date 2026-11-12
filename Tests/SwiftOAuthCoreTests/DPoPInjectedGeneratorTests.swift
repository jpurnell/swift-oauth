import Foundation
import Crypto
import Testing
@testable import SwiftOAuthCore

/// `DPoPProof.create(…generator:)` draws the proof's identifier from the generator it is given.
///
/// The overload exists so a proof's shape can be tested against a known sequence. That only
/// works if the generator passed in is the one used.
@Suite("RFC 9449 — a proof's identifier comes from the injected generator")
struct DPoPInjectedGeneratorTests {

    private let key = P256.Signing.PrivateKey()

    private func identifier(seed: UInt64) throws -> String {
        let url = try #require(URL(string: "https://api.example.com/resource"))
        var generator = SeededGenerator(seed: seed)
        let proof = try DPoPProof.create(
            method: "POST", url: url, using: key, generator: &generator)
        return try DPoPProof.verify(proof, method: "POST", url: url).identifier
    }

    @Test("The same seed gives the same identifier")
    func sameSeedSameIdentifier() throws {
        #expect(try identifier(seed: 42) == identifier(seed: 42))
    }

    @Test("Different seeds give different identifiers")
    func differentSeedsDifferentIdentifiers() throws {
        #expect(try identifier(seed: 1) != identifier(seed: 2))
    }
}
