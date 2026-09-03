import Foundation
import Crypto
import Testing
@testable import SwiftOAuthCore

/// The minimal JWS this package needs — RFC 7515, compact serialization, ES256.
///
/// swift-crypto carries every primitive and no JOSE layer: there is no JWS type, so compact
/// serialization, base64url and signature verification are ours. This is that layer, written
/// once for RFC 9101 and reused by RFC 9449 rather than pulling in a JOSE dependency for two
/// features.
///
/// Only ES256. A verifier that accepts a list of algorithms has to decide what to do about
/// `none` and about HMAC algorithms whose key is the public key of an asymmetric pair — the
/// two most-exploited JWT flaws in existence. Accepting exactly one algorithm makes both
/// unrepresentable rather than guarded against.
@Suite("RFC 7515 — compact JWS")
struct JWSTests {

    /// A signature this package produced verifies against the matching public key.
    @Test("A signed JWS round-trips")
    func roundTrips() throws {
        let key = P256.Signing.PrivateKey()
        let payload = Data(#"{"iss":"client-1"}"#.utf8)

        let token = try CompactJWS.sign(payload: payload, using: key)
        let verified = try CompactJWS.verify(token, using: key.publicKey)

        #expect(verified == payload)
    }

    /// A signature made by a different key is refused.
    ///
    /// The whole point: without this the signature is decoration.
    @Test("A signature from another key is refused")
    func wrongKeyIsRefused() throws {
        let signer = P256.Signing.PrivateKey()
        let other = P256.Signing.PrivateKey()
        let token = try CompactJWS.sign(payload: Data(#"{}"#.utf8), using: signer)

        #expect(throws: (any Error).self) {
            _ = try CompactJWS.verify(token, using: other.publicKey)
        }
    }

    /// A tampered payload is refused, which is the property a signature exists to provide.
    @Test("A modified payload is refused")
    func tamperedPayloadIsRefused() throws {
        let key = P256.Signing.PrivateKey()
        let token = try CompactJWS.sign(payload: Data(#"{"scope":"read"}"#.utf8), using: key)

        var parts = token.split(separator: ".").map(String.init)
        parts[1] = Data(#"{"scope":"admin"}"#.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        #expect(throws: (any Error).self) {
            _ = try CompactJWS.verify(parts.joined(separator: "."), using: key.publicKey)
        }
    }

    /// `alg: none` is refused — the flaw that made JWT notorious.
    ///
    /// A verifier reading the algorithm out of the header and honouring it accepts a token the
    /// attacker declared unsigned. This one does not read the header's algorithm to decide what
    /// to do; it requires ES256 and refuses anything else.
    @Test("alg none is refused")
    func algNoneIsRefused() throws {
        let key = P256.Signing.PrivateKey()
        let header = Data(#"{"alg":"none","typ":"JWT"}"#.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let payload = Data(#"{"scope":"admin"}"#.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        #expect(throws: (any Error).self) {
            _ = try CompactJWS.verify("\(header).\(payload).", using: key.publicKey)
        }
    }

    /// An algorithm that is not ES256 is refused even when the signature is well-formed.
    @Test("An unexpected algorithm is refused")
    func unexpectedAlgorithmIsRefused() throws {
        let key = P256.Signing.PrivateKey()
        let token = try CompactJWS.sign(payload: Data(#"{}"#.utf8), using: key)
        var parts = token.split(separator: ".").map(String.init)
        parts[0] = Data(#"{"alg":"HS256","typ":"JWT"}"#.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        #expect(throws: (any Error).self) {
            _ = try CompactJWS.verify(parts.joined(separator: "."), using: key.publicKey)
        }
    }

    /// A token that is not three parts is refused rather than partially parsed.
    @Test("A malformed token is refused")
    func malformedTokenIsRefused() throws {
        let key = P256.Signing.PrivateKey()

        #expect(throws: (any Error).self) {
            _ = try CompactJWS.verify("not.a.valid.jws", using: key.publicKey)
        }
        #expect(throws: (any Error).self) {
            _ = try CompactJWS.verify("onlyonepart", using: key.publicKey)
        }
    }
}
