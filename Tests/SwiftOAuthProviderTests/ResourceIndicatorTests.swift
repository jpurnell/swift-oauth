import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// RFC 8707 resource indicators, on the half that decides what a token is *for*.
///
/// The client has sent `resource` since 0.7.0 and no server built on this package has ever
/// read it. That asymmetry is worse than the gap being open in both halves: a client and a
/// server from the same package could talk to each other, one of them naming an audience and
/// the other ignoring it, and nothing would say so — the token would simply be good everywhere.
///
/// The rule this enforces is RFC 8707 §2: a request naming a resource the server does not
/// serve is refused with `invalid_target`, and a token that is issued is bound to the audience
/// that was asked for.
@Suite("RFC 8707 — resource indicator policy")
struct ResourceIndicatorPolicyTests {

    /// Built rather than stored, so the fixtures need no force unwrap.
    private func url(_ string: String) throws -> URL {
        // SECURITY: parses a literal written in this test; no request is ever issued from it.
        try #require(URL(string: string), "not a URL: \(string)")
    }

    /// The ordinary case: a resource the server serves becomes the audience.
    @Test("A known resource is accepted and becomes the audience")
    func knownResourceBecomesAudience() throws {
        let api = try url("https://api.example.com"), reports = try url("https://reports.example.com")
        let policy = ResourceIndicatorPolicy(known: [api, reports])

        #expect(try policy.audience(for: [api]) == api)
    }

    /// The refusal RFC 8707 §2 names, and it must be *that* error rather than a generic one:
    /// `invalid_target` tells a client the resource was the problem, which is the only part it
    /// can do anything about.
    @Test("An unknown resource is refused with invalid_target")
    func unknownResourceIsRefused() throws {
        let api = try url("https://api.example.com")
        let policy = ResourceIndicatorPolicy(known: [api])
        let stranger = try url("https://elsewhere.example.com")

        let error = #expect(throws: OAuthError.self) {
            _ = try policy.audience(for: [stranger])
        }
        #expect(error?.code == "invalid_target")
        // The description is part of the contract, not decoration: `invalid_target` alone does
        // not tell an operator which resource was refused.
        #expect(error?.detail?.contains("elsewhere.example.com") == true)
    }

    /// Strict is the default, deliberately.
    ///
    /// A request naming no resource asks for a token good everywhere. Accepting it by default
    /// would make the safe configuration the one a consumer has to go and find, and the
    /// dangerous one what they get by not thinking about it.
    @Test("By default, naming no resource is refused")
    func unspecifiedRefusedByDefault() throws {
        let policy = ResourceIndicatorPolicy(known: [try url("https://api.example.com")])

        let error = #expect(throws: OAuthError.self) {
            _ = try policy.audience(for: [])
        }
        #expect(error?.code == "invalid_target")
        #expect(error?.detail?.isEmpty == false, "a refusal should say what was expected")
    }

    /// The permissive setting still exists, because a server whose tokens are already
    /// single-audience has nothing to bind and no ambiguity to resolve.
    @Test("A permissive policy allows an unspecified resource")
    func unspecifiedAllowedWhenPermitted() throws {
        let policy = ResourceIndicatorPolicy(
            known: [try url("https://api.example.com")], allowsUnspecified: true)

        #expect(try policy.audience(for: []) == nil)
    }

    /// RFC 8707 §2.2: the parameter may repeat, and a server that cannot issue a single token
    /// covering all of them rejects with `invalid_target`. Silently picking the first would
    /// issue a token for an audience the client did not ask for on its own.
    @Test("Several distinct resources are refused rather than silently narrowed")
    func severalResourcesAreRefused() throws {
        let api = try url("https://api.example.com"), reports = try url("https://reports.example.com")
        let policy = ResourceIndicatorPolicy(known: [api, reports])

        let error = #expect(throws: OAuthError.self) {
            _ = try policy.audience(for: [api, reports])
        }
        #expect(error?.code == "invalid_target")
    }

    /// The same resource named twice is one audience, not an ambiguity — the repetition is a
    /// client quirk, not a second request.
    @Test("The same resource repeated is not an ambiguity")
    func repeatedResourceIsOneAudience() throws {
        let api = try url("https://api.example.com")
        let policy = ResourceIndicatorPolicy(known: [api])

        #expect(try policy.audience(for: [api, api]) == api)
    }
}

/// `invalid_target` on the wire.
///
/// RFC 8707 §2 defines the code, and it has to survive the round trip in both directions: a
/// provider emits it, and a client parses it back. A code that encodes but decodes as
/// `server_error` is one a client cannot branch on.
@Suite("RFC 8707 — invalid_target on the wire")
struct InvalidTargetWireTests {

    @Test("The code parses from the wire")
    func parsesFromWire() {
        #expect(OAuthError(code: "invalid_target") == .invalidTarget(nil))
    }

    @Test("The code round-trips, description included")
    func roundTrips() {
        let error = OAuthError(code: "invalid_target", description: "unknown resource")
        #expect(error == .invalidTarget("unknown resource"))
        #expect(error.code == "invalid_target")
    }
}
