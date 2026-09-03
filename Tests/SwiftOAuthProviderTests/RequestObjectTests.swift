import Foundation
import Crypto
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// JWT-secured authorization requests — RFC 9101.
///
/// The authorization request travels as a signed JWT, so its parameters cannot be altered
/// between the client and the authorization server. PAR hides them from the browser; JAR proves
/// who wrote them. They compose, and neither replaces the other.
///
/// The rule everything here exists to enforce: **a request object that does not verify is
/// refused outright.** It is never fallen back from. A server that verifies a signature and,
/// on failure, uses the query parameters instead has built a signature that means nothing —
/// an attacker simply supplies a broken one, or none.
@Suite("RFC 9101 — request objects")
struct RequestObjectTests {

    private let key = P256.Signing.PrivateKey()

    private func signedRequest(_ claims: [String: Any]) throws -> String {
        let payload = try JSONSerialization.data(withJSONObject: claims)
        return try CompactJWS.sign(payload: payload, using: key)
    }

    /// A valid request object yields its parameters.
    @Test("A verified request object yields its parameters")
    func verifiedObjectYieldsParameters() throws {
        let token = try signedRequest([
            "iss": "client-1", "aud": "https://mcp.example.com",
            "client_id": "client-1", "redirect_uri": "https://app.example.com/callback",
            "scope": "read", "state": "xyz", "response_type": "code"
        ])

        let request = try RequestObject.verify(
            token, clientId: "client-1", issuer: "https://mcp.example.com",
            using: key.publicKey)

        #expect(request.scope == "read")
        #expect(request.state == "xyz")
        #expect(request.redirectUri == "https://app.example.com/callback")
    }

    /// A broken signature is refused, and there is no other path.
    ///
    /// This is the test the whole feature exists for. A server that falls back to query
    /// parameters here has built a signature an attacker can simply omit.
    @Test("A request object with a bad signature is refused, never fallen back from")
    func badSignatureIsRefused() throws {
        let otherKey = P256.Signing.PrivateKey()
        let token = try signedRequest([
            "iss": "client-1", "aud": "https://mcp.example.com",
            "client_id": "client-1", "redirect_uri": "https://app.example.com/callback",
            "scope": "admin"
        ])

        #expect(throws: (any Error).self) {
            _ = try RequestObject.verify(
                token, clientId: "client-1", issuer: "https://mcp.example.com",
                using: otherKey.publicKey)
        }
    }

    /// The issuer claim must be the client — §4. Without the check, a client can present
    /// another client's signed request object and have it honoured.
    @Test("A request object issued by another client is refused")
    func wrongIssuerIsRefused() throws {
        let token = try signedRequest([
            "iss": "someone-else", "aud": "https://mcp.example.com",
            "client_id": "someone-else", "redirect_uri": "https://app.example.com/callback"
        ])

        #expect(throws: (any Error).self) {
            _ = try RequestObject.verify(
                token, clientId: "client-1", issuer: "https://mcp.example.com",
                using: key.publicKey)
        }
    }

    /// The audience must be this server — §4. A request object addressed to a different
    /// authorization server is otherwise replayable against this one.
    @Test("A request object addressed to another server is refused")
    func wrongAudienceIsRefused() throws {
        let token = try signedRequest([
            "iss": "client-1", "aud": "https://other.example.com",
            "client_id": "client-1", "redirect_uri": "https://app.example.com/callback"
        ])

        #expect(throws: (any Error).self) {
            _ = try RequestObject.verify(
                token, clientId: "client-1", issuer: "https://mcp.example.com",
                using: key.publicKey)
        }
    }

    /// `client_id` inside the object must match the one outside it.
    ///
    /// RFC 9101 §4 requires the outer parameter, and a mismatch means the server would
    /// authenticate one client and honour another's parameters.
    @Test("A client_id mismatch between the object and the request is refused")
    func clientIdMismatchIsRefused() throws {
        let token = try signedRequest([
            "iss": "client-1", "aud": "https://mcp.example.com",
            "client_id": "different-client",
            "redirect_uri": "https://app.example.com/callback"
        ])

        #expect(throws: (any Error).self) {
            _ = try RequestObject.verify(
                token, clientId: "client-1", issuer: "https://mcp.example.com",
                using: key.publicKey)
        }
    }

    /// An expired request object is refused.
    @Test("An expired request object is refused")
    func expiredObjectIsRefused() throws {
        let token = try signedRequest([
            "iss": "client-1", "aud": "https://mcp.example.com",
            "client_id": "client-1", "redirect_uri": "https://app.example.com/callback",
            "exp": Date().addingTimeInterval(-60).timeIntervalSince1970
        ])

        #expect(throws: (any Error).self) {
            _ = try RequestObject.verify(
                token, clientId: "client-1", issuer: "https://mcp.example.com",
                using: key.publicKey)
        }
    }

    /// An audience given as an array is accepted when this server is in it — RFC 7519 §4.1.3.
    @Test("An audience array containing this server is accepted")
    func audienceArrayIsAccepted() throws {
        let token = try signedRequest([
            "iss": "client-1",
            "aud": ["https://other.example.com", "https://mcp.example.com"],
            "client_id": "client-1", "redirect_uri": "https://app.example.com/callback"
        ])

        let request = try RequestObject.verify(
            token, clientId: "client-1", issuer: "https://mcp.example.com",
            using: key.publicKey)

        #expect(request.redirectUri == "https://app.example.com/callback")
    }
}
