import Foundation
import Crypto
import Testing
@testable import SwiftOAuthCore

/// What a verifier says about each kind of malformed input, pinned to the exact refusal.
///
/// The older suites assert "some error". These assert *which*: a token-verification path whose
/// refusal changes shape, or quietly becomes acceptance, is a vulnerability, and a refactor of
/// how unparseable input is handled must not be able to do either unnoticed.
@Suite("Malformed input is refused with the same error, every time")
struct RefusalShapeTests {

    private let key = P256.Signing.PrivateKey()

    private func segment(_ text: String) -> String {
        CompactJWS.base64URL(Data(text.utf8))
    }

    /// A token with a real signature over exactly the header and payload given.
    private func signed(header: String, payload: String) throws -> String {
        let input = "\(segment(header)).\(segment(payload))"
        let signature = try key.signature(for: Data(input.utf8))
        return "\(input).\(CompactJWS.base64URL(signature.rawRepresentation))"
    }

    private func dpopHeader(typ: String = "dpop+jwt", jwk: String? = nil) -> String {
        #"{"alg":"ES256","typ":"\#(typ)","jwk":\#(jwk ?? DPoPProof.jwk(for: key.publicKey))}"#
    }

    private let url = URL(fileURLWithPath: "/resource")

    // MARK: - CompactJWS

    @Test("A header that is not JSON is an unsupported algorithm")
    func headerNotJSON() throws {
        let token = try signed(header: "not json", payload: "{}")
        #expect(throws: CompactJWS.Failure.unsupportedAlgorithm(nil)) {
            _ = try CompactJWS.verify(token, using: key.publicKey)
        }
    }

    @Test("A header that is a JSON array is an unsupported algorithm")
    func headerNotObject() throws {
        let token = try signed(header: #"["ES256"]"#, payload: "{}")
        #expect(throws: CompactJWS.Failure.unsupportedAlgorithm(nil)) {
            _ = try CompactJWS.verify(token, using: key.publicKey)
        }
    }

    @Test("A header with no alg is an unsupported algorithm")
    func headerWithoutAlg() throws {
        let token = try signed(header: #"{"typ":"JWT"}"#, payload: "{}")
        #expect(throws: CompactJWS.Failure.unsupportedAlgorithm(nil)) {
            _ = try CompactJWS.verify(token, using: key.publicKey)
        }
    }

    @Test("A signature of the wrong length is a rejected signature")
    func shortSignature() {
        let input = "\(segment(#"{"alg":"ES256"}"#)).\(segment("{}"))"
        let token = "\(input).\(CompactJWS.base64URL(Data(repeating: 7, count: 10)))"
        #expect(throws: CompactJWS.Failure.signatureRejected) {
            _ = try CompactJWS.verify(token, using: key.publicKey)
        }
    }

    @Test("A signature of the right length that is no signature is a rejected signature")
    func zeroSignature() {
        let input = "\(segment(#"{"alg":"ES256"}"#)).\(segment("{}"))"
        let token = "\(input).\(CompactJWS.base64URL(Data(repeating: 0, count: 64)))"
        #expect(throws: CompactJWS.Failure.signatureRejected) {
            _ = try CompactJWS.verify(token, using: key.publicKey)
        }
    }

    // MARK: - DPoP

    @Test("A proof whose header is not JSON is a malformed header")
    func dpopHeaderNotJSON() throws {
        let proof = try signed(header: "garbage", payload: "{}")
        #expect(throws: DPoPProof.Failure.malformedHeader) {
            _ = try DPoPProof.verify(proof, method: "GET", url: url)
        }
    }

    @Test("A proof whose header is a JSON array is a malformed header")
    func dpopHeaderNotObject() throws {
        let proof = try signed(header: "[1,2]", payload: "{}")
        #expect(throws: DPoPProof.Failure.malformedHeader) {
            _ = try DPoPProof.verify(proof, method: "GET", url: url)
        }
    }

    @Test("A proof that does not declare dpop+jwt is a malformed header")
    func dpopWrongType() throws {
        let proof = try signed(header: dpopHeader(typ: "JWT"), payload: "{}")
        #expect(throws: DPoPProof.Failure.malformedHeader) {
            _ = try DPoPProof.verify(proof, method: "GET", url: url)
        }
    }

    /// Whether a point off the curve is rejected when the key is built (swift-crypto) or when
    /// it is first used (CryptoKit) differs by platform, so which refusal this is does too:
    /// `missingKey` or `signatureRejected`. That it is refused does not.
    @Test("A proof whose key is not a point on the curve is refused")
    func dpopOffCurveKey() throws {
        let x = CompactJWS.base64URL(Data(repeating: 1, count: 32))
        let jwk = #"{"kty":"EC","crv":"P-256","x":"\#(x)","y":"\#(x)"}"#
        let proof = try signed(header: dpopHeader(jwk: jwk), payload: "{}")
        #expect(throws: (any Error).self) {
            _ = try DPoPProof.verify(proof, method: "GET", url: url)
        }
    }

    @Test("A proof whose claims are not JSON is malformed claims")
    func dpopClaimsNotJSON() throws {
        let proof = try signed(header: dpopHeader(), payload: "not json")
        #expect(throws: DPoPProof.Failure.malformedClaims) {
            _ = try DPoPProof.verify(proof, method: "GET", url: url)
        }
    }

    @Test("A proof whose claims are a JSON array is malformed claims")
    func dpopClaimsNotObject() throws {
        let proof = try signed(header: dpopHeader(), payload: "[]")
        #expect(throws: DPoPProof.Failure.malformedClaims) {
            _ = try DPoPProof.verify(proof, method: "GET", url: url)
        }
    }

    @Test("A proof without a jti is malformed claims")
    func dpopClaimsWithoutIdentifier() throws {
        let proof = try signed(header: dpopHeader(), payload: #"{"iat":1,"htm":"GET"}"#)
        #expect(throws: DPoPProof.Failure.malformedClaims) {
            _ = try DPoPProof.verify(proof, method: "GET", url: url)
        }
    }

    @Test("JWK coordinates that are a real point yield that key")
    func jwkCoordinates() throws {
        let valid = key.publicKey.rawRepresentation
        let good: [String: Any] = [
            "kty": "EC", "crv": "P-256",
            "x": CompactJWS.base64URL(valid.prefix(32)),
            "y": CompactJWS.base64URL(valid.suffix(32))
        ]
        #expect((try DPoPProof.publicKey(from: good)).rawRepresentation == valid)
    }

    // MARK: - Introspection `aud`

    private func decode(_ json: String) throws -> IntrospectionResult {
        try JSONDecoder().decode(IntrospectionResult.self, from: Data(json.utf8))
    }

    @Test("aud as a string is a one-element audience")
    func audienceString() throws {
        #expect(try decode(#"{"active":true,"aud":"a"}"#).audience == ["a"])
    }

    @Test("aud as an array is the array")
    func audienceArray() throws {
        #expect(try decode(#"{"active":true,"aud":["a","b"]}"#).audience == ["a", "b"])
    }

    @Test("an absent or null aud is no audience")
    func audienceAbsent() throws {
        #expect(try decode(#"{"active":true}"#).audience == nil)
        #expect(try decode(#"{"active":true,"aud":null}"#).audience == nil)
    }

    @Test("an aud that is neither a string nor an array of strings does not decode")
    func audienceWrongShape() {
        #expect(throws: DecodingError.self) { _ = try decode(#"{"active":true,"aud":5}"#) }
        #expect(throws: DecodingError.self) { _ = try decode(#"{"active":true,"aud":[1,2]}"#) }
    }
}
