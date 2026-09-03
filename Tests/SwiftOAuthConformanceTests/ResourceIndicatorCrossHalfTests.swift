import Foundation
import Testing
import SwiftOAuthCore
import SwiftOAuthClient
import SwiftOAuthProvider

/// This package's client against this package's provider, for RFC 8707.
///
/// Every other test here checks one half against a fixture written alongside it. That catches
/// a half that disagrees with its own author's intent, and misses the case that has now
/// produced three defects in this feature alone: both halves correct in isolation and wrong
/// together — a client that sent `resource` to a provider that never read it, a provider whose
/// policy could disagree with the metadata it published, and a parser that would have collapsed
/// a repeated parameter before the rule refusing repeats could see it.
///
/// The value here is that the two halves make independent decisions about the same string. The
/// client canonicalises before sending; the provider compares by exact match. Those are
/// separate pieces of code with separate opinions, and nothing but a test spanning both will
/// notice when they stop agreeing.
///
/// It is still not sufficient — both halves share an author and a reading of the specification,
/// so an assumption held consistently across them survives this. That is what an independent
/// consumer is for.
@Suite("Cross-half — RFC 8707 resource indicators")
struct ResourceIndicatorCrossHalfTests {

    private func url(_ string: String) throws -> URL {
        // SECURITY: parses a literal written in this test; no request is issued from it.
        try #require(URL(string: string))
    }

    /// What the client puts on the wire is what the provider accepts.
    ///
    /// The client's canonical form and the provider's `known` set are produced by different
    /// code from the same identifier. If either changes how it normalises — a trailing slash,
    /// a default port, a case difference in the host — this fails, and it is the only test that
    /// would.
    @Test("The client's resource parameter is accepted by the provider")
    func clientParameterIsAcceptedByProvider() async throws {
        let identifier = try url("https://api.example.com")

        let configuration = ProviderConfiguration(
            identifier: "cross-half",
            authorizationEndpoint: try url("https://auth.example.com/authorize"),
            tokenEndpoint: try url("https://auth.example.com/token"),
            scope: "read",
            resource: identifier)

        // The canonical form the client will send. Public API on purpose — a conformance test
        // should see what a consumer sees.
        let sent = try #require(configuration.resource,
                                "the client did not produce a resource indicator")

        let policy = ResourceIndicatorPolicy.protecting(identifier)
        let accepted = try policy.audience(for: [sent])

        #expect(accepted == identifier)
    }

    /// The client strips a fragment; the provider must still recognise what arrives.
    ///
    /// RFC 8707 §2 requires the identifier to have no fragment, and the client enforces that by
    /// removing one. The provider compares by exact match — so if a deployment configures the
    /// same URI with a fragment on both sides, the client sends the stripped form and the
    /// provider is holding the unstripped one. This test says what actually happens rather than
    /// leaving it to be found in a deployment.
    @Test("A fragment is stripped by the client, and the provider sees the stripped form")
    func fragmentIsStrippedBeforeItArrives() async throws {
        let withFragment = try url("https://api.example.com/v1#section")
        let stripped = try url("https://api.example.com/v1")

        let configuration = ProviderConfiguration(
            identifier: "cross-half",
            authorizationEndpoint: try url("https://auth.example.com/authorize"),
            tokenEndpoint: try url("https://auth.example.com/token"),
            scope: "read",
            resource: withFragment)

        let sent = try #require(configuration.resource)
        #expect(sent == stripped, "the client should strip the fragment")

        // A provider configured from the stripped identifier accepts it.
        #expect(try ResourceIndicatorPolicy.protecting(stripped)
            .audience(for: [sent]) == stripped)

        // And one configured with the fragment still on it does not — which is the failure a
        // deployment would hit, recorded here rather than discovered there.
        #expect(throws: OAuthError.self) {
            _ = try ResourceIndicatorPolicy.protecting(withFragment)
                .audience(for: [sent])
        }
    }

    /// A client that names no resource is refused by a strict provider, and the refusal names
    /// the value it wanted.
    ///
    /// This is the whole migration in one test: a 0.6.0-era client, which sent nothing, meeting
    /// a 0.8.0 provider.
    @Test("A client sending no resource is refused, and told what to send")
    func silentClientIsRefusedWithGuidance() async throws {
        let identifier = try url("https://api.example.com")

        let configuration = ProviderConfiguration(
            identifier: "cross-half",
            authorizationEndpoint: try url("https://auth.example.com/authorize"),
            tokenEndpoint: try url("https://auth.example.com/token"),
            scope: "read")

        #expect(configuration.resource == nil, "a 0.6.0-era client sends nothing")

        let error = #expect(throws: OAuthError.self) {
            _ = try ResourceIndicatorPolicy.protecting(identifier).audience(for: [])
        }
        #expect(error?.code == "invalid_target")
        #expect(error?.detail?.contains(identifier.absoluteString) == true,
                "the refusal should hand over the value the client needs")
    }

    /// A token issued through the provider carries the audience, and reports it on validation.
    ///
    /// The end of the round trip: the client's identifier reaches storage and comes back.
    @Test("The audience survives issue and validation")
    func audienceSurvivesRoundTrip() async throws {
        let identifier = try url("https://api.example.com")
        let storage = try OAuthStorage(path: ":memory:")

        try await storage.saveAccessToken(
            token: "cross-half-token", clientId: "client-1", scope: "read",
            expiresAt: Date().addingTimeInterval(3600), audience: identifier)

        let result = try await storage.validateAccessToken(token: "cross-half-token")
        guard case .valid(let token) = result else {
            Issue.record("expected a valid token, got \(result)")
            return
        }
        #expect(token.audience == identifier)
    }
}
