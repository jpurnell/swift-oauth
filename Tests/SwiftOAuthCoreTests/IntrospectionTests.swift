import Foundation
import Testing
@testable import SwiftOAuthCore

/// RFC 7662 token introspection — the wire shape.
///
/// This is how any resource server asks the authorization server whether a token it was handed
/// is still good, and what it is for. It is the ordinary case for a web backend, not an edge
/// case, and its absence is why a consumer validating tokens has had to reach past this package
/// or trust a bearer string it cannot check.
///
/// The distinction the specification draws, and the one implementations most often get wrong:
/// **an expired, revoked or unknown token is `active: false`, not an error.** RFC 7662 §2.2 is
/// explicit. A server that returns 401 for an expired token forces every caller to treat "this
/// token is no good" as a transport failure, which is a different thing entirely and is handled
/// in a different place.
@Suite("RFC 7662 — introspection response")
struct IntrospectionResultTests {

    /// An active token carries what a resource server needs to make a decision.
    @Test("An active response decodes with its claims")
    func activeResponseDecodes() throws {
        let json = """
        {"active":true,"scope":"read write","client_id":"client-1",
         "aud":"https://api.example.com","exp":1788000000,"sub":"user-9"}
        """
        let result = try JSONDecoder().decode(IntrospectionResult.self, from: Data(json.utf8))

        #expect(result.active)
        #expect(result.scope == "read write")
        #expect(result.clientId == "client-1")
        #expect(result.audience == ["https://api.example.com"])
        #expect(result.expiry == Date(timeIntervalSince1970: 1788000000))
        #expect(result.subject == "user-9")
    }

    /// The inactive case is one field. RFC 7662 §2.2: a server must not reveal anything else
    /// about a token that is not active — not its scope, not who it was issued to — because a
    /// caller holding a dead token has proven nothing and an error carrying claims is an
    /// oracle.
    @Test("An inactive response is just active:false")
    func inactiveResponseDecodes() throws {
        let result = try JSONDecoder().decode(
            IntrospectionResult.self, from: Data(#"{"active":false}"#.utf8))

        #expect(!result.active)
        #expect(result.scope == nil)
        #expect(result.clientId == nil)
        #expect(result.expiry == nil)
    }

    /// `aud` is a string or an array of strings — RFC 7519 §4.1.3, which RFC 7662 inherits.
    /// A decoder handling only one of them fails on half the providers in existence.
    @Test("An audience array decodes")
    func audienceArrayDecodes() throws {
        let json = #"{"active":true,"aud":["https://a.example.com","https://b.example.com"]}"#
        let result = try JSONDecoder().decode(IntrospectionResult.self, from: Data(json.utf8))

        #expect(result.audience == ["https://a.example.com", "https://b.example.com"])
    }

    /// A response naming no audience is not an error — most tokens have none.
    @Test("A response with no audience decodes")
    func absentAudienceDecodes() throws {
        let result = try JSONDecoder().decode(
            IntrospectionResult.self, from: Data(#"{"active":true}"#.utf8))

        #expect(result.active)
        #expect(result.audience == nil)
    }

    /// The inactive response is what a server sends, so it must encode to exactly one field.
    @Test("The inactive response encodes to a single field")
    func inactiveResponseEncodes() throws {
        let encoded = try JSONEncoder().encode(IntrospectionResult.inactive)
        let object = try #require(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any])

        #expect(object.count == 1, "an inactive response leaked \(object.keys.sorted())")
        #expect(object["active"] as? Bool == false)
    }

    /// RFC 7662 §2.2's example response, as the RFC prints it. `iss` is how a resource server
    /// that trusts one issuer can see that an answer speaks for another; it was dropped on
    /// decode until this version.
    @Test("The §2.2 example response decodes, issuer included")
    func rfcExampleDecodes() throws {
        let json = """
             {
              "active": true,
              "client_id": "l238j323ds-23ij4",
              "username": "jdoe",
              "scope": "read write dolphin",
              "sub": "Z5O3upPC88QrAjx00dis",
              "aud": "https://protected.example.net/resource",
              "iss": "https://server.example.com/",
              "exp": 1419356238,
              "iat": 1419350238,
              "extension_field": "twenty-seven"
             }
            """
        let result = try JSONDecoder().decode(IntrospectionResult.self, from: Data(json.utf8))

        #expect(result.active)
        #expect(result.clientId == "l238j323ds-23ij4")
        #expect(result.scope == "read write dolphin")
        #expect(result.subject == "Z5O3upPC88QrAjx00dis")
        #expect(result.audience == ["https://protected.example.net/resource"])
        #expect(result.issuer == "https://server.example.com/")
        #expect(result.expiry == Date(timeIntervalSince1970: 1419356238))
        #expect(result.issuedAt == Date(timeIntervalSince1970: 1419350238))
    }

    /// And it is written back out, so a provider that sets it says so on the wire.
    @Test("An issuer encodes as iss")
    func issuerEncodes() throws {
        let encoded = try JSONEncoder().encode(
            IntrospectionResult(active: true, subject: "s", issuer: "https://server.example.com/"))
        let object = try #require(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any])

        #expect(object["iss"] as? String == "https://server.example.com/")
    }
}
