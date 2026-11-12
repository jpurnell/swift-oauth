import Foundation
import Crypto
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// Claims that are signed and still unusable are refused as malformed, not as something else.
@Suite("RFC 9101 — request objects with unreadable claims")
struct RequestObjectMalformedClaimsTests {

    private let key = P256.Signing.PrivateKey()

    @Test("Claims that are not a JSON object are malformed", arguments: ["not json", "[]", "\"text\"", "5"])
    func unreadableClaims(payload: String) throws {
        let token = try CompactJWS.sign(payload: Data(payload.utf8), using: key)
        #expect(throws: RequestObject.Failure.malformedClaims) {
            _ = try RequestObject.verify(
                token, clientId: "client-1", issuer: "https://mcp.example.com",
                using: key.publicKey)
        }
    }
}
