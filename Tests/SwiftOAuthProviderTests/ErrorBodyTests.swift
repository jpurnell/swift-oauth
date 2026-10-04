import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthProvider

/// The JSON error bodies the HTTP layer writes — RFC 6749 §5.2.
///
/// Three sites used to build these by interpolating into a string literal:
/// `"{\"error\": \"\(error)\", \"error_description\": \"\(description)\"}"`. Every value that
/// reached them was a literal in this package, so no response was ever malformed. But the
/// construction was correct only for as long as that stayed true — a description containing a
/// quote, or one taken from a request, becomes a body that either fails to parse or carries
/// fields its author did not write — and nothing in the code said so. They are encoded now,
/// through one function, and these tests pin the bytes.
@Suite("HTTP error bodies are encoded, not interpolated")
struct ErrorBodyTests {

    private func makeHandler() async throws -> (OAuthHTTPHandler, OAuthServer) {
        let storage = try OAuthStorage(path: ":memory:")
        let server = OAuthServer(
            storage: storage, issuer: "https://mcp.example.com", scopesSupported: ["read"],
            served: .core, resourceIdentity: .colocated,
            resourcePolicy: ResourceIndicatorPolicy(known: [], allowsUnspecified: true))
        return (OAuthHTTPHandler(server: server), server)
    }

    /// The property interpolation cannot have: whatever the description holds, the body is
    /// one JSON object with exactly the two fields, and the description comes back unchanged.
    @Test("A description containing JSON syntax is escaped, not spliced")
    func descriptionIsEscaped() throws {
        let hostile = #"said "no", "error": "none"} \ and left"# + "\n"

        let body = OAuthHTTPHandler.errorBody(code: "invalid_request", description: hostile)

        #expect(body
                == #"{"error":"invalid_request","error_description":"said \"no\", \"error\": \"none\"} \\ and left\n"}"#)
        let decoded = try JSONDecoder().decode(OAuthErrorResponse.self, from: Data(body.utf8))
        #expect(decoded == OAuthErrorResponse(
            error: "invalid_request", errorDescription: hostile))
    }

    @Test("A consent form missing its parameters gets an encoded invalid_request")
    func missingConsentParameters() async throws {
        let (handler, _) = try await makeHandler()

        let response = await handler.handleConsentSubmission(formParams: ["action": "approve"])

        #expect(response.statusCode == 400)
        #expect(response.contentType == "application/json")
        #expect(response.body
                == #"{"error":"invalid_request","error_description":"Missing required parameters"}"#)
    }

    @Test("An unregistered redirect URI gets an encoded invalid_request and no redirect")
    func unregisteredRedirect() async throws {
        let (handler, server) = try await makeHandler()
        let client = try await server.registerClient(ClientRegistrationRequest(
            clientName: "app", redirectUris: ["https://app.example.com/callback"]))

        let response = await handler.handleAuthorizationRequest(queryParams: [
            "response_type": "code", "client_id": client.clientId,
            "redirect_uri": "https://attacker.example/callback"])

        #expect(response.statusCode == 400)
        #expect(response.headers == [:])
        #expect(response.body
                == #"{"error":"invalid_request","error_description":"Invalid redirect_uri"}"#)
    }

    /// The token endpoint's errors went through an encoder already, but over a dictionary, so
    /// the two keys came out in whichever order the hash seed chose that run.
    @Test("A token endpoint error has a stable key order")
    func tokenEndpointErrorIsStable() async throws {
        let (handler, _) = try await makeHandler()

        let response = await handler.handleTokenRequest(body: "client_id=test", authHeader: nil)

        #expect(response.statusCode == 400)
        #expect(response.body
                == #"{"error":"invalid_request","error_description":"The request is missing a required parameter or is otherwise malformed."}"#)
    }
}
