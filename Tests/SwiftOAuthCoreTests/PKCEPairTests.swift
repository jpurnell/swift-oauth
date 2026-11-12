import Foundation
import Testing
@testable import SwiftOAuthCore

/// A verifier generated here is valid by construction, so deriving its challenge cannot fail.
@Suite("RFC 7636 — a generated verifier and its challenge")
struct PKCEPairTests {

    @Test("The pair's challenge is the S256 challenge of its verifier")
    func challengeMatchesVerifier() throws {
        let pair = PKCE.generateVerifierAndChallenge()

        #expect(PKCE.isValidCodeVerifier(pair.verifier))
        #expect(pair.challenge == (try PKCE.generateCodeChallenge(
            verifier: pair.verifier, method: .s256)))
        #expect(try PKCE.verifyCodeChallenge(
            verifier: pair.verifier, challenge: pair.challenge, method: .s256))
    }

    @Test("Each pair is fresh")
    func pairsDiffer() {
        let first = PKCE.generateVerifierAndChallenge()
        let second = PKCE.generateVerifierAndChallenge()
        #expect(first.verifier != second.verifier)
    }
}
