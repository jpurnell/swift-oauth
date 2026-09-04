import Foundation
import Crypto

/// A demonstration that the sender holds a key — RFC 9449.
///
/// A bearer token works for whoever holds it. That is its entire security model, and it is why
/// a token leaked into a log, a proxy or a browser extension is immediately usable by whoever
/// finds it. DPoP binds the token to a key: presenting the token stops being enough, because
/// each request must also carry a fresh signature over *that request*.
///
/// The proof is a JWS whose header carries the public key and whose payload names four things,
/// each stopping a specific replay:
///
/// - `htm`, the method — or a proof captured from a `GET` is replayable as a `DELETE`.
/// - `htu`, the URI — or a proof captured by one resource server is replayable by it against
///   another, which is the attack this most obviously exists to stop.
/// - `iat`, when it was made — or a proof has no expiry and can be held for later.
/// - `jti`, a unique identifier — which is what a server records to refuse a second use.
///
/// The first three are checked here. `jti` cannot be: refusing a replay requires memory of what
/// has been seen, which is the server's, so ``Verified/identifier`` is surfaced for a caller to
/// record. A verifier that ignores it has three of the four defences.
public enum DPoPProof {

    /// How long a proof stays acceptable, either side of now.
    ///
    /// Not zero, because clocks differ; not unbounded, because a proof that never goes stale
    /// is one an attacker can hold. RFC 9449 §11.1 leaves the value to the server and expects
    /// it to be short.
    public static let acceptableClockSkew: TimeInterval = 300

    /// A proof that verified.
    public struct Verified: Sendable, Equatable {
        /// The method it was made for.
        public let method: String
        /// The URI it was made for, without query or fragment.
        public let url: URL
        /// `jti` — record this to refuse a replay. Nothing here remembers it.
        public let identifier: String
        /// When it was made.
        public let issuedAt: Date
        /// The RFC 7638 thumbprint of the key that signed it.
        ///
        /// This is what an access token is bound to — `cnf.jkt` in RFC 9449 §6. A resource
        /// server compares the token's binding against this; if they differ, the token is being
        /// presented by someone who does not hold its key.
        public let thumbprint: String
    }

    /// What can be wrong with a proof.
    public enum Failure: Error, Equatable {
        /// The header was absent, malformed, or did not declare `dpop+jwt`.
        case malformedHeader
        /// The header carried no usable public key.
        case missingKey
        /// The claims were not a JSON object, or lacked a required one.
        case malformedClaims
        /// `htm` did not match the request.
        case methodMismatch(expected: String, found: String?)
        /// `htu` did not match the request.
        case uriMismatch(expected: String, found: String?)
        /// `iat` was outside the acceptable window.
        case staleOrFutureDated
    }

    /// Creates a proof for one request.
    ///
    /// - Parameters:
    ///   - method: The HTTP method, upper-case.
    ///   - url: The request URI. Query and fragment are stripped, per §4.2.
    ///   - key: The key this client holds.
    ///   - issuedAt: When the proof is made. Injectable so the freshness rule can be tested
    ///     without waiting.
    /// - Returns: The compact JWS to send in the `DPoP` header.
    /// - Throws: If the proof could not be signed.
    public static func create(
        method: String,
        url: URL,
        using key: P256.Signing.PrivateKey,
        issuedAt: Date = Date()
    ) throws -> String {
        var generator = SystemRandomNumberGenerator() // stochastic:exempt convenience wrapper; injectable overload below
        return try create(
            method: method, url: url, using: key, issuedAt: issuedAt, generator: &generator)
    }

    /// Creates a proof, drawing its identifier from a supplied generator.
    ///
    /// Injectable so the proof's *shape* can be tested against a known sequence without
    /// asserting anything about a value that must be unpredictable in production — a `jti` an
    /// attacker can predict is a replay window, since a server refusing repeats can only refuse
    /// the ones it sees coming.
    ///
    /// - Parameters:
    ///   - method: The HTTP method, upper-case.
    ///   - url: The request URI. Query and fragment are stripped, per §4.2.
    ///   - key: The key this client holds.
    ///   - issuedAt: When the proof is made.
    ///   - generator: The source of the proof identifier.
    /// - Returns: The compact JWS to send in the `DPoP` header.
    /// - Throws: If the proof could not be signed.
    public static func create(
        method: String,
        url: URL,
        using key: P256.Signing.PrivateKey,
        issuedAt: Date = Date(),
        generator: inout some RandomNumberGenerator
    ) throws -> String {
        let jwk = Self.jwk(for: key.publicKey)
        let header = Data(#"{"typ":"dpop+jwt","alg":"ES256","jwk":\#(jwk)}"#.utf8)

        // 16 bytes from the system CSPRNG. A guessable `jti` is a replay window, since a
        // server refusing repeats can only refuse the ones it can predict being reused.
        var generator = SystemRandomNumberGenerator() // stochastic:exempt convenience wrapper; `create(…using:)` takes a generator
        // base64url rather than hex: the encoding is irrelevant to a `jti` — uniqueness and
        // unpredictability are the whole requirement — and it avoids `String(format:)`, which
        // bridges to the C printf ABI and fails at runtime rather than at compile time.
        let identifier = CompactJWS.base64URL(
            Data((0..<16).map { _ in UInt8.random(in: 0...255, using: &generator) }))

        let claims: [String: Any] = [
            "htm": method.uppercased(),
            "htu": Self.canonicalURI(url),
            "iat": Int(issuedAt.timeIntervalSince1970),
            "jti": identifier
        ]
        let payload = try JSONSerialization.data(withJSONObject: claims, options: [.sortedKeys])
        return try CompactJWS.sign(payload: payload, using: key, header: header)
    }

    /// Verifies a proof against the request it should have been made for.
    ///
    /// - Parameters:
    ///   - proof: The `DPoP` header value.
    ///   - method: The method actually being requested.
    ///   - url: The URI actually being requested.
    ///   - now: The current time, injectable for testing the freshness window.
    /// - Returns: What the proof asserts, once it has verified.
    /// - Throws: ``Failure``, or ``CompactJWS/Failure`` if the signature is not good.
    public static func verify(
        _ proof: String,
        method: String,
        url: URL,
        now: Date = Date()
    ) throws -> Verified {
        // The verifying key is inside the header, so it must be read before there is anything
        // to check the signature with. Nothing read here is trusted until `verify` succeeds
        // with the key it yields — a signature that verifies against a key the attacker chose
        // proves only that the attacker can sign, which is why the thumbprint is what a token
        // is bound to rather than the proof alone.
        guard let headerData = CompactJWS.unverifiedHeader(proof),
              // silent: an unparseable header is a malformed proof, thrown as such by this guard
              let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
              header["typ"] as? String == "dpop+jwt" else {
            throw Failure.malformedHeader
        }
        guard let jwk = header["jwk"] as? [String: Any],
              let publicKey = Self.publicKey(from: jwk) else {
            throw Failure.missingKey
        }

        let payload = try CompactJWS.verify(proof, using: publicKey)

        // silent: claims that will not parse are a malformed proof, thrown by this guard
        guard let claims = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let identifier = claims["jti"] as? String,
              let issued = claims["iat"] as? TimeInterval else {
            throw Failure.malformedClaims
        }

        let claimedMethod = claims["htm"] as? String
        guard claimedMethod == method.uppercased() else {
            throw Failure.methodMismatch(expected: method.uppercased(), found: claimedMethod)
        }

        let expectedURI = Self.canonicalURI(url)
        let claimedURI = claims["htu"] as? String
        guard claimedURI == expectedURI else {
            throw Failure.uriMismatch(expected: expectedURI, found: claimedURI)
        }

        let issuedAt = Date(timeIntervalSince1970: issued)
        guard abs(issuedAt.timeIntervalSince(now)) <= acceptableClockSkew else {
            throw Failure.staleOrFutureDated
        }

        // SECURITY: re-parses the caller's own request URI after canonicalisation; never fetched.
        guard let canonical = URL(string: expectedURI) else { throw Failure.malformedClaims }
        return Verified(
            method: method.uppercased(),
            url: canonical,
            identifier: identifier,
            issuedAt: issuedAt,
            thumbprint: Self.thumbprint(of: publicKey))
    }

    /// The URI as `htu` defines it — RFC 9449 §4.2: no query, no fragment.
    ///
    /// A client that includes them and a server that does not would disagree on every request
    /// carrying a query string, and the disagreement would look like a forged proof.
    static func canonicalURI(_ url: URL) -> String {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return url.absoluteString
        }
        components.query = nil
        components.fragment = nil
        return components.url?.absoluteString ?? url.absoluteString
    }

    /// The public key as a JWK, in the member order RFC 7638 requires.
    ///
    /// Built by hand rather than encoded from a dictionary: the thumbprint hashes this exact
    /// string, and the ordering is normative, which a dictionary would not preserve.
    static func jwk(for key: P256.Signing.PublicKey) -> String {
        let raw = key.rawRepresentation
        let x = CompactJWS.base64URL(raw.prefix(32))
        let y = CompactJWS.base64URL(raw.suffix(32))
        return #"{"crv":"P-256","kty":"EC","x":"\#(x)","y":"\#(y)"}"#
    }

    /// The RFC 7638 thumbprint of a public key: SHA-256 over the canonical JWK.
    ///
    /// Public because it is what a caller has to compare. An authorization server records this
    /// as `cnf.jkt` when it binds a token; a resource server checks the value against the proof
    /// on each request; a client needs to know its own in order to recognise what it was issued.
    /// All three are outside this module.
    ///
    /// - Parameter key: The public key to identify.
    /// - Returns: The base64url-encoded thumbprint.
    public static func thumbprint(of key: P256.Signing.PublicKey) -> String {
        CompactJWS.base64URL(Data(SHA256.hash(data: Data(jwk(for: key).utf8))))
    }

    /// Rebuilds a public key from a JWK's coordinates.
    static func publicKey(from jwk: [String: Any]) -> P256.Signing.PublicKey? {
        guard jwk["kty"] as? String == "EC", jwk["crv"] as? String == "P-256",
              let x = (jwk["x"] as? String).flatMap(CompactJWS.decodeBase64URL),
              let y = (jwk["y"] as? String).flatMap(CompactJWS.decodeBase64URL),
              x.count == 32, y.count == 32 else {
            return nil
        }
        // silent: coordinates that are not a valid point yield no key, which the caller reads as absent
        return try? P256.Signing.PublicKey(rawRepresentation: x + y)
    }
}
