import Foundation
import Testing
@testable import SwiftOAuthCore

/// RFC 8693 token exchange — the wire shapes.
///
/// For a service acting with a token it was given rather than one it obtained: an API gateway
/// calling a backend, a job running on a user's behalf, a service narrowing its own privilege
/// before calling something less trusted.
///
/// The specification distinguishes two things a caller might mean, and conflating them is the
/// mistake it exists to prevent: **impersonation**, where the new token is indistinguishable
/// from one the subject obtained, and **delegation**, where it records that an actor is acting
/// on the subject's behalf. The second is auditable and the first is not.
@Suite("RFC 8693 — token exchange wire types")
struct TokenExchangeWireTests {

    /// The grant type is a URN — §2.1. A server matching a short name refuses every conformant
    /// client.
    @Test("The exchange grant carries its URN")
    func grantTypeIsAURN() {
        #expect(GrantType.tokenExchange.rawValue
            == "urn:ietf:params:oauth:grant-type:token-exchange")
        #expect(GrantType(rawValue: "urn:ietf:params:oauth:grant-type:token-exchange")
            == .tokenExchange)
    }

    /// Token type identifiers are URNs too — §3. A request names what it is handing over and
    /// what it wants back, and both are these.
    @Test("Token type identifiers carry their specified URNs")
    func tokenTypeURNs() {
        #expect(TokenType.accessToken.rawValue == "urn:ietf:params:oauth:token-type:access_token")
        #expect(TokenType.refreshToken.rawValue == "urn:ietf:params:oauth:token-type:refresh_token")
        #expect(TokenType.idToken.rawValue == "urn:ietf:params:oauth:token-type:id_token")
        #expect(TokenType.jwt.rawValue == "urn:ietf:params:oauth:token-type:jwt")
    }

    /// A response decodes, and `issued_token_type` is required — §2.2.1.
    ///
    /// Without it a client holds a token and does not know what kind it is, which decides how
    /// it may be presented. A decoder that made it optional would let that omission through to
    /// a caller who then guesses.
    @Test("An exchange response decodes with its issued token type")
    func responseDecodes() throws {
        let json = """
        {"access_token":"new-token",
         "issued_token_type":"urn:ietf:params:oauth:token-type:access_token",
         "token_type":"Bearer","expires_in":3600,"scope":"read"}
        """
        let response = try JSONDecoder().decode(
            TokenExchangeResponse.self, from: Data(json.utf8))

        #expect(response.accessToken == "new-token")
        #expect(response.issuedTokenType == .accessToken)
        #expect(response.scope == "read")
        #expect(response.expiresIn == 3600)
    }

    /// A response missing `issued_token_type` is refused rather than defaulted.
    @Test("A response without issued_token_type is refused")
    func missingIssuedTypeIsRefused() {
        let json = #"{"access_token":"t","token_type":"Bearer"}"#

        #expect(throws: (any Error).self) {
            _ = try JSONDecoder().decode(TokenExchangeResponse.self, from: Data(json.utf8))
        }
    }

    /// A request encodes to the form parameters §2.1 names.
    @Test("An exchange request encodes its required parameters")
    func requestEncodesRequiredParameters() {
        let request = TokenExchangeRequest(
            subjectToken: "incoming", subjectTokenType: .accessToken, scope: "read")

        let parameters = request.formParameters

        #expect(parameters["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange")
        #expect(parameters["subject_token"] == "incoming")
        #expect(parameters["subject_token_type"]
            == "urn:ietf:params:oauth:token-type:access_token")
        #expect(parameters["scope"] == "read")
    }

    /// An actor token makes it delegation rather than impersonation — §1.1 and §2.1.
    ///
    /// The distinction is the point of the RFC: a delegated token records who is acting, so an
    /// audit log can answer "who did this" rather than only "whose token was used".
    @Test("An actor token is sent, and marks the request as delegation")
    func actorTokenMarksDelegation() {
        let request = TokenExchangeRequest(
            subjectToken: "user-token", subjectTokenType: .accessToken,
            actorToken: "service-token", actorTokenType: .accessToken)

        let parameters = request.formParameters

        #expect(parameters["actor_token"] == "service-token")
        #expect(parameters["actor_token_type"]
            == "urn:ietf:params:oauth:token-type:access_token")
        #expect(request.isDelegation)
    }

    /// Without one it is impersonation, and says so.
    @Test("Without an actor token the request is impersonation")
    func withoutActorIsImpersonation() {
        let request = TokenExchangeRequest(
            subjectToken: "user-token", subjectTokenType: .accessToken)

        #expect(!request.isDelegation)
        #expect(request.formParameters["actor_token"] == nil)
        #expect(request.formParameters["actor_token_type"] == nil)
    }

    /// An actor token type without the token is refused at construction.
    ///
    /// §2.1: `actor_token_type` is required *when* `actor_token` is present, and meaningless
    /// otherwise. Sending the type alone produces a request a server must reject, and the
    /// rejection reads as a malformed request rather than as the mistake it is.
    @Test("An actor token type without a token is not sent")
    func orphanedActorTypeIsNotSent() {
        let request = TokenExchangeRequest(
            subjectToken: "user-token", subjectTokenType: .accessToken,
            actorToken: nil, actorTokenType: .accessToken)

        #expect(request.formParameters["actor_token_type"] == nil,
                "an actor token type without a token is meaningless and would be rejected")
        #expect(!request.isDelegation)
    }
}
