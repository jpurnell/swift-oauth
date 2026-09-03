import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthClient

/// `WWW-Authenticate` — RFC 6750 §3, and RFC 9728 §5.1 for the resource metadata pointer.
///
/// This is how a resource server tells a client what it lacks. A client that cannot read it has
/// only one recovery from a `401`: re-authorise with everything it can think of, and hope. The
/// challenge says precisely what was missing, and the point of parsing it is to ask for exactly
/// that.
@Suite("RFC 6750 — WWW-Authenticate challenges")
struct ChallengeParsingTests {

    /// The ordinary insufficient-scope challenge.
    @Test("An insufficient_scope challenge names the scopes required")
    func insufficientScopeIsParsed() throws {
        let header = #"Bearer realm="api", error="insufficient_scope", scope="read write""#
        let challenge = try #require(BearerChallenge(header: header))

        #expect(challenge.error == "insufficient_scope")
        #expect(challenge.realm == "api")
        #expect(challenge.scopes == ["read", "write"])
    }

    /// Re-authorisation asks for exactly what was named, not the union of everything held.
    ///
    /// The tempting implementation adds the missing scopes to the ones already granted and
    /// re-authorises with the lot. That quietly widens the grant every time a resource asks for
    /// anything, and the widening is invisible — each individual step looks like it is only
    /// asking for what it was told.
    @Test("The scopes to request are exactly those named, not a union")
    func scopesAreNotUnioned() throws {
        let header = #"Bearer error="insufficient_scope", scope="reports:read""#
        let challenge = try #require(BearerChallenge(header: header))

        #expect(challenge.scopes == ["reports:read"])
        #expect(!challenge.scopes.contains("admin"))
    }

    /// RFC 9728 §5.1: the challenge may point at the protected-resource metadata, which is
    /// where a client learns the resource identifier to send as `resource`.
    ///
    /// That closes the loop with RFC 8707 — a client refused for naming no resource can be told
    /// where to find the one to name.
    @Test("A resource_metadata pointer is parsed")
    func resourceMetadataPointerIsParsed() throws {
        let header = #"""
        Bearer error="invalid_token", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"
        """#
        let challenge = try #require(BearerChallenge(header: header))

        #expect(challenge.resourceMetadata?.absoluteString
            == "https://api.example.com/.well-known/oauth-protected-resource")
    }

    /// A bare `Bearer` is a valid challenge that names nothing.
    @Test("A bare Bearer challenge parses with no parameters")
    func bareChallengeParses() throws {
        let challenge = try #require(BearerChallenge(header: "Bearer"))

        #expect(challenge.error == nil)
        #expect(challenge.scopes.isEmpty)
    }

    /// A scheme this client does not speak is not a Bearer challenge.
    ///
    /// Returning a half-parsed value for `Basic` would have a caller act on parameters that
    /// mean something else.
    @Test("A non-Bearer scheme is refused")
    func nonBearerSchemeIsRefused() {
        #expect(BearerChallenge(header: #"Basic realm="api""#) == nil)
    }

    /// Case-insensitive, because RFC 7235 §2.1 says the scheme is.
    @Test("The scheme is matched case-insensitively")
    func schemeIsCaseInsensitive() throws {
        let challenge = try #require(BearerChallenge(header: #"bearer error="invalid_token""#))

        #expect(challenge.error == "invalid_token")
    }

    /// A description containing a comma must not split the parameter list.
    ///
    /// The obvious implementation splits on commas, and this is the header that breaks it —
    /// producing a truncated description and a spurious parameter from its tail.
    @Test("A quoted value containing a comma is not split")
    func quotedCommaIsNotSplit() throws {
        let header = #"Bearer error="invalid_token", error_description="Expired, please retry", scope="read""#
        let challenge = try #require(BearerChallenge(header: header))

        #expect(challenge.errorDescription == "Expired, please retry")
        #expect(challenge.scopes == ["read"])
    }
}
