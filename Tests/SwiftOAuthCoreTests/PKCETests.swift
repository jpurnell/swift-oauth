import Foundation
import Testing
@testable import SwiftOAuthCore

/// PKCE is the one part of this package where a subtle error is invisible.
///
/// A wrong challenge derivation still produces a plausible-looking base64
/// string, still round-trips against *our own* verifier, and still passes every
/// test written against our own implementation — while failing against every
/// real authorization server, or worse, accepting a verifier it should reject.
///
/// So correctness is established against RFC 7636's published vectors rather
/// than against ourselves.
@Suite("PKCE — RFC 7636")
struct PKCEVectorTests {

    /// RFC 7636 Appendix B. The specification supplies this verifier and the
    /// challenge that must be derived from it; any implementation that agrees
    /// with a real server agrees with these two strings.
    private let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    private let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    @Test("The published verifier derives the published challenge")
    func appendixBVector() throws {
        let derived = try PKCE.generateCodeChallenge(verifier: verifier, method: .s256)
        #expect(derived == challenge, "derived \(derived)")
    }

    @Test("Verification accepts the published pair")
    func appendixBVerifies() throws {
        #expect(try PKCE.verifyCodeChallenge(
            verifier: verifier, challenge: challenge, method: .s256))
    }

    /// The failure that matters: accepting a verifier that should be rejected
    /// means the interception attack PKCE exists to prevent still works.
    @Test("Verification rejects a verifier that did not produce the challenge")
    func wrongVerifierRejected() throws {
        let other = "aDifferentVerifierEntirelyXXXXXXXXXXXXXXXXXXX"
        #expect(!(try PKCE.verifyCodeChallenge(
            verifier: other, challenge: challenge, method: .s256)))
    }

    /// A single flipped character must not verify. Base64url is dense enough
    /// that a truncated or mis-encoded challenge can still look well-formed.
    @Test("A challenge differing by one character does not verify")
    func nearMissRejected() throws {
        var tampered = Array(challenge)
        tampered[0] = tampered[0] == "E" ? "F" : "E"
        #expect(!(try PKCE.verifyCodeChallenge(
            verifier: verifier, challenge: String(tampered), method: .s256)))
    }
}

@Suite("PKCE — verifier rules")
struct PKCEVerifierTests {

    /// RFC 7636 §4.1 fixes the length at 43–128 characters. Shorter loses the
    /// entropy the scheme depends on; the bound is not stylistic.
    @Test("Verifier length is bounded per §4.1")
    func lengthBounds() {
        #expect(!PKCE.isValidCodeVerifier(String(repeating: "a", count: 42)))
        #expect(PKCE.isValidCodeVerifier(String(repeating: "a", count: 43)))
        #expect(PKCE.isValidCodeVerifier(String(repeating: "a", count: 128)))
        #expect(!PKCE.isValidCodeVerifier(String(repeating: "a", count: 129)))
        #expect(!PKCE.isValidCodeVerifier(""))
    }

    /// The unreserved set is `A-Z a-z 0-9 - . _ ~`. A verifier containing
    /// anything else may be re-encoded in transit and stop matching.
    @Test("Only unreserved characters are accepted")
    func characterSet() {
        let base = String(repeating: "a", count: 42)
        for allowed in ["-", ".", "_", "~", "A", "9"] {
            #expect(PKCE.isValidCodeVerifier(base + allowed), "rejected '\(allowed)'")
        }
        for rejected in ["+", "/", "=", " ", "%", "&", "#"] {
            #expect(!PKCE.isValidCodeVerifier(base + rejected), "accepted '\(rejected)'")
        }
    }

    @Test("A generated verifier is valid and derives a challenge")
    func generatedVerifierRoundTrips() throws {
        var rng = SeededGenerator(seed: 20_260_806)
        let generated = PKCE.generateCodeVerifier(using: &rng)
        #expect(PKCE.isValidCodeVerifier(generated))

        let derived = try PKCE.generateCodeChallenge(verifier: generated, method: .s256)
        #expect(try PKCE.verifyCodeChallenge(
            verifier: generated, challenge: derived, method: .s256))
    }

    /// Two verifiers must not collide. A generator returning a constant would
    /// pass every other test in this file.
    ///
    /// Seeded, so a collision is reproducible rather than a CI curiosity that
    /// never appears again locally.
    @Test("Generated verifiers differ")
    func verifiersAreDistinct() {
        var rng = SeededGenerator(seed: 20_260_806)
        let generated = Set((0..<512).map { _ in PKCE.generateCodeVerifier(using: &rng) })
        #expect(generated.count == 512, "only \(generated.count) of 512 were distinct")
    }

    /// Every generated verifier must satisfy §4.1, not merely the first one.
    /// A generator that occasionally emits a disallowed character would pass a
    /// single-draw test almost always.
    @Test("Every generated verifier satisfies the character and length rules")
    func generatedVerifiersAreAlwaysValid() {
        var rng = SeededGenerator(seed: 99)
        for draw in 0..<512 {
            let verifier = PKCE.generateCodeVerifier(using: &rng)
            #expect(PKCE.isValidCodeVerifier(verifier),
                    "draw \(draw) produced an invalid verifier: \(verifier)")
        }
    }

    /// The same seed must reproduce the same verifier, or the tests above prove
    /// nothing about a failure anyone tries to reproduce.
    @Test("Seeding is reproducible")
    func seedingIsDeterministic() {
        var first = SeededGenerator(seed: 7)
        var second = SeededGenerator(seed: 7)
        #expect(PKCE.generateCodeVerifier(using: &first)
                == PKCE.generateCodeVerifier(using: &second))
    }

    @Test("An invalid verifier is refused rather than hashed anyway")
    func invalidVerifierRefused() {
        #expect(throws: PKCEError.self) {
            try PKCE.generateCodeChallenge(verifier: "too-short", method: .s256)
        }
    }
}

@Suite("PKCE — challenge methods")
struct PKCEMethodTests {

    /// OAuth 2.1 removes `plain`, and it is absent here. Under `plain` the
    /// challenge *is* the verifier, so an attacker who intercepts the
    /// authorization request holds everything needed to redeem the code — the
    /// exact attack PKCE exists to prevent.
    @Test("S256 is the only method offered")
    func onlyS256() {
        #expect(PKCE.ChallengeMethod.allCases == [.s256])
        #expect(PKCE.ChallengeMethod(rawValue: "plain") == nil,
                "the plain method is still constructible")
    }

    @Test("The method round-trips through its wire value")
    func wireValue() {
        #expect(PKCE.ChallengeMethod.s256.rawValue == "S256")
        #expect(PKCE.ChallengeMethod(rawValue: "S256") == .s256)
        // Case matters on the wire: `s256` is not the registered value.
        #expect(PKCE.ChallengeMethod(rawValue: "s256") == nil)
    }
}
