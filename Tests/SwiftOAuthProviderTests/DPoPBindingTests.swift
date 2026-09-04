import Foundation
import Crypto
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// Binding a token to a key, and refusing a replayed proof — RFC 9449 §6 and §11.1.
///
/// The proof type in core establishes that a request was signed by whoever holds a key. That is
/// only half of DPoP. The other half is here: the issued token records *which* key, so a
/// resource server can refuse a token presented by anyone else — and the server remembers which
/// proofs it has seen, so one cannot be used twice.
@Suite("RFC 9449 — token binding and replay")
struct DPoPBindingTests {

    private func makeServer() async throws -> (OAuthServer, OAuthStorage) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"],
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        return (server, storage)
    }

    /// A token issued against a proof records that key's thumbprint.
    @Test("An issued token records the key it is bound to")
    func tokenRecordsItsBinding() async throws {
        let (_, storage) = try await makeServer()

        try await storage.saveAccessToken(
            token: "bound-token", clientId: "c1", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: nil,
            keyThumbprint: "thumb-abc")

        let result = try await storage.validateAccessToken(token: "bound-token")
        guard case .valid(let token) = result else {
            Issue.record("expected a valid token, got \(result)")
            return
        }
        #expect(token.keyThumbprint == "thumb-abc")
    }

    /// A token issued without one reports none — a plain bearer token, unchanged.
    @Test("An unbound token reports no thumbprint")
    func unboundTokenReportsNothing() async throws {
        let (_, storage) = try await makeServer()

        try await storage.saveAccessToken(
            token: "plain-token", clientId: "c1", scope: nil,
            expiresAt: Date().addingTimeInterval(3600), audience: nil)

        let result = try await storage.validateAccessToken(token: "plain-token")
        guard case .valid(let token) = result else {
            Issue.record("expected a valid token, got \(result)")
            return
        }
        #expect(token.keyThumbprint == nil)
    }

    /// A proof identifier is accepted once.
    @Test("A jti is accepted the first time")
    func firstUseOfAJTIIsAccepted() async throws {
        let (_, storage) = try await makeServer()

        let accepted = try await storage.claimProofIdentifier(
            "jti-1", expiresAt: Date().addingTimeInterval(300))

        #expect(accepted)
    }

    /// And refused the second time. This is the whole of replay protection: without it a proof
    /// observed in transit is usable again by whoever saw it, for as long as it stays fresh.
    @Test("A replayed jti is refused")
    func replayedJTIIsRefused() async throws {
        let (_, storage) = try await makeServer()
        let expiry = Date().addingTimeInterval(300)

        #expect(try await storage.claimProofIdentifier("jti-2", expiresAt: expiry))
        #expect(try await storage.claimProofIdentifier("jti-2", expiresAt: expiry) == false,
                "a proof was accepted twice")
    }

    /// Two different proofs do not collide.
    @Test("Distinct identifiers are independent")
    func distinctIdentifiersAreIndependent() async throws {
        let (_, storage) = try await makeServer()
        let expiry = Date().addingTimeInterval(300)

        #expect(try await storage.claimProofIdentifier("jti-a", expiresAt: expiry))
        #expect(try await storage.claimProofIdentifier("jti-b", expiresAt: expiry))
    }

    /// The record only has to outlive the proof's freshness window.
    ///
    /// A store that kept every identifier forever would grow without bound; one that forgets
    /// too early re-opens the replay window. Expiry is what makes the table finite, so it is
    /// asserted rather than assumed.
    @Test("Expired identifiers are swept")
    func expiredIdentifiersAreSwept() async throws {
        let (_, storage) = try await makeServer()

        _ = try await storage.claimProofIdentifier(
            "jti-old", expiresAt: Date().addingTimeInterval(-60))
        let removed = try await storage.sweepExpiredProofIdentifiers()

        #expect(removed >= 1)
        // Sweeping does not re-open a live proof to replay: this one was already dead.
        #expect(try await storage.claimProofIdentifier(
            "jti-old", expiresAt: Date().addingTimeInterval(300)))
    }
}

/// The bearer entry point, against a token that is not a bearer token.
///
/// RFC 9449 §7.1 gives a bound token its own scheme. A server that accepts one at the `Bearer`
/// entry point accepts it *without checking any proof* — the token validates, the caller sees
/// success, and the binding is silently gone. The code compiles, nothing logs, and a grep for
/// "DPoP" in the consumer's sources finds nothing, which is exactly why nobody looks there.
///
/// So the refusal lives here rather than in a release note. A token carrying a key thumbprint,
/// presented at the bearer endpoint, is being presented incorrectly by definition — whoever is
/// asking, and whether or not they have read anything about DPoP.
@Suite("RFC 9449 — a bound token is not a bearer token")
struct BoundTokenSchemeTests {

    private func makeHandler() async throws -> (OAuthHTTPHandler, OAuthStorage) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"],
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        return (await OAuthHTTPHandler(server: server), storage)
    }

    /// An ordinary bearer token still works. The refusal must be narrow, or every existing
    /// consumer breaks.
    @Test("An unbound token is still accepted as a bearer token")
    func unboundTokenStillWorks() async throws {
        let (handler, storage) = try await makeHandler()
        try await storage.saveAccessToken(
            token: "plain", clientId: "c1", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: nil)

        let result = await handler.validateBearerToken(authHeader: "Bearer plain")

        #expect(result.isValid)
    }

    /// A bound token presented as a bearer token is refused.
    @Test("A bound token is refused at the bearer entry point")
    func boundTokenIsRefusedAsBearer() async throws {
        let (handler, storage) = try await makeHandler()
        try await storage.saveAccessToken(
            token: "bound", clientId: "c1", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: nil,
            keyThumbprint: "thumb-abc")

        let result = await handler.validateBearerToken(authHeader: "Bearer bound")

        #expect(!result.isValid,
                "a bound token validated as a bearer token; the binding was discarded")
    }

    /// And the refusal says why, because "invalid token" sends an operator looking for an
    /// expiry or a typo rather than at the scheme they used.
    @Test("The refusal names the scheme as the problem")
    func refusalExplainsTheScheme() async throws {
        let (handler, storage) = try await makeHandler()
        try await storage.saveAccessToken(
            token: "bound2", clientId: "c1", scope: nil,
            expiresAt: Date().addingTimeInterval(3600), audience: nil,
            keyThumbprint: "thumb-abc")

        let result = await handler.validateBearerToken(authHeader: "Bearer bound2")

        guard case .invalid(let reason) = result else {
            Issue.record("expected a refusal, got \(result)")
            return
        }
        #expect(reason.contains("DPoP"), "the reason should name the scheme to use")
    }
}

/// Certificate-bound tokens on the provider — RFC 8705 §3.
///
/// The mTLS counterpart to the DPoP binding. Both record which key a token belongs to; they
/// differ only in what identifies the key. A token may carry one or neither — never both, since
/// a client proves possession one way per connection.
@Suite("RFC 8705 — certificate-bound tokens")
struct CertificateBoundTokenTests {

    private func makeHandler() async throws -> (OAuthHTTPHandler, OAuthStorage) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = await OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["mcp:tools", "mcp:resources", "mcp:prompts"],
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        return (await OAuthHTTPHandler(server: server), storage)
    }

    /// A token issued against a certificate records its thumbprint.
    @Test("An issued token records the certificate it is bound to")
    func tokenRecordsItsCertificate() async throws {
        let (_, storage) = try await makeHandler()
        let thumbprint = CertificateBinding.thumbprint(ofDER: Data([0xAA, 0xBB]))

        try await storage.saveAccessToken(
            token: "cert-bound", clientId: "c1", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: nil,
            certificateThumbprint: thumbprint)

        let result = try await storage.validateAccessToken(token: "cert-bound")
        guard case .valid(let token) = result else {
            Issue.record("expected a valid token, got \(result)")
            return
        }
        #expect(token.certificateThumbprint == thumbprint)
    }

    /// A certificate-bound token is refused at the bearer entry point, for the same reason a
    /// DPoP-bound one is: accepting it there accepts it without checking the certificate, and
    /// the binding is silently gone.
    @Test("A certificate-bound token is refused as a bearer token")
    func certificateBoundTokenIsNotABearerToken() async throws {
        let (handler, storage) = try await makeHandler()
        try await storage.saveAccessToken(
            token: "cert-bearer", clientId: "c1", scope: nil,
            expiresAt: Date().addingTimeInterval(3600), audience: nil,
            certificateThumbprint: CertificateBinding.thumbprint(ofDER: Data([0xAA])))

        let result = await handler.validateBearerToken(authHeader: "Bearer cert-bearer")

        #expect(!result.isValid,
                "a certificate-bound token validated as a bearer token; the binding was lost")
    }

    /// An unbound token is unaffected, or every existing consumer breaks.
    @Test("An unbound token is still a valid bearer token")
    func unboundTokenUnaffected() async throws {
        let (handler, storage) = try await makeHandler()
        try await storage.saveAccessToken(
            token: "ordinary", clientId: "c1", scope: nil,
            expiresAt: Date().addingTimeInterval(3600), audience: nil)

        #expect(await handler.validateBearerToken(authHeader: "Bearer ordinary").isValid)
    }
}
