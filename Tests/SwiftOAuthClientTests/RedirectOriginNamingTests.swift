import Foundation
import Testing
@testable import SwiftOAuthClient

/// What ``OAuthRedirectRefused`` says about a URL.
///
/// A `Location` is whatever a server chose to write, and the error that reports it is logged.
/// So the error names an origin and nothing else — and these are the spellings a server could
/// use to get more than an origin into it.
@Suite("A refused redirect is named by origin only")
struct RedirectOriginNamingTests {

    private static let base = URL(string: "https://auth.example.com/oauth/token?tenant=acme")

    @Test("A Location is reduced to its origin", arguments: [
        // An absolute URL: path and query go.
        ("https://other.example/collect?code=abc#frag", "https://other.example"),
        // A port that is named is kept; it is part of the origin.
        ("https://other.example:8443/x", "https://other.example:8443"),
        // Userinfo is a credential, and `good@evil` is how a URL is made to read as one host.
        ("https://auth.example.com:pw@other.example/x", "https://other.example"),
        // Scheme and host are case-insensitive, and are written one way.
        ("HTTPS://Other.Example/x", "https://other.example"),
        // Scheme-relative: another host on the request's scheme.
        ("//other.example/x", "https://other.example"),
        // Relative references stay on the endpoint's own origin.
        ("/moved?to=elsewhere", "https://auth.example.com"),
        ("moved", "https://auth.example.com"),
        // An IPv6 literal keeps its brackets.
        ("https://[::1]:9443/x", "https://[::1]:9443"),
        // No host at all: nothing to name, and the text itself is not quoted.
        ("mailto:someone@other.example", OAuthRedirectRefused.unnamedOrigin)
    ])
    func locationIsReducedToItsOrigin(location: String, expected: String) {
        #expect(CredentialRequest.destination(of: location, from: Self.base) == expected)
    }

    /// A downgrade is named as what it is: the scheme is part of the origin, so the error
    /// shows `http` where the endpoint was `https`. The plaintext URL is assembled from
    /// components because it exists only to be named, never to be requested.
    @Test("A plaintext Location on the same host is named with its scheme")
    func downgradeIsNamedWithItsScheme() throws {
        var components = URLComponents()
        components.scheme = "http"
        components.host = "auth.example.com"
        components.path = "/oauth/token"
        let location = try #require(components.string)
        components.path = ""
        let expected = try #require(components.string)

        #expect(CredentialRequest.destination(of: location, from: Self.base) == expected)
        #expect(expected != CredentialRequest.origin(of: try #require(Self.base)))
    }

    @Test("The endpoint is named without its path, query or userinfo")
    func endpointIsNamedByOrigin() throws {
        let endpoint = try #require(URL(string: "https://client:pw@auth.example.com:8443/token?tenant=acme"))
        #expect(CredentialRequest.origin(of: endpoint) == "https://auth.example.com:8443")
    }

    @Test("The description names both origins and the status")
    func descriptionNamesBothOrigins() {
        let refusal = OAuthRedirectRefused(
            status: 307, endpoint: "https://auth.example.com", destination: "https://other.example")

        #expect(refusal.description.contains("307"))
        #expect(refusal.description.contains("https://auth.example.com"))
        #expect(refusal.description.contains("https://other.example"))
        #expect(refusal.localizedDescription == refusal.description)
    }
}
