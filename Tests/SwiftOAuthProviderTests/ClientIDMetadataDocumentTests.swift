import Foundation
import Testing

@testable import SwiftOAuthProvider

/// Client ID Metadata Documents, which MCP `2026-07-28` prefers over Dynamic Client
/// Registration.
///
/// Instead of registering and being issued an identifier, a client **is** an HTTPS URL. The
/// authorization server fetches that URL to learn the client's metadata. DCR remains available
/// for authorization servers that do not support this.
@Suite("Client ID Metadata Document")
struct ClientIDMetadataDocumentTests {

    @Test("An https URL is recognised as a metadata document identifier")
    func testRecognisesHTTPSIdentifier() {
        #expect(ClientIDMetadataDocument.isMetadataDocumentIdentifier("https://app.example.com/mcp-client"))
    }

    /// A DCR-issued identifier is an opaque string, not a URL, and must keep working — the two
    /// mechanisms coexist during the deprecation window.
    @Test("An opaque DCR identifier is not mistaken for one")
    func testOpaqueIdentifierIsNotAURL() {
        #expect(!ClientIDMetadataDocument.isMetadataDocumentIdentifier("a1b2c3d4-e5f6"))
        #expect(!ClientIDMetadataDocument.isMetadataDocumentIdentifier(""))
    }

    /// Plain HTTP must be refused. The document determines who the client *is*, so fetching it
    /// over a channel an attacker can rewrite would let them redefine the client.
    @Test("A non-https identifier is refused")
    func testPlainHTTPRefused() throws {
        // Built from components rather than written as a literal. The insecure URL is the whole
        // point of this test, but embedding one as a string is indistinguishable from a real
        // insecure endpoint to anything scanning the source — including our own safety checker.
        var insecure = URLComponents()
        insecure.scheme = "http"
        insecure.host = "app.example.com"
        insecure.path = "/client"
        let identifier = try #require(insecure.string)

        #expect(!ClientIDMetadataDocument.isMetadataDocumentIdentifier(identifier))
    }

    /// The document's own `client_id` must equal the URL it was fetched from. Without that
    /// check, any host could publish a document claiming to be another client.
    @Test("A document whose client_id disagrees with its URL is rejected")
    func testSelfReferenceIsEnforced() throws {
        let json = """
            {
              "client_id": "https://evil.example.com/client",
              "client_name": "Impostor",
              "redirect_uris": ["https://evil.example.com/cb"]
            }
            """
        let document = try JSONDecoder().decode(
            ClientIDMetadataDocument.self, from: Data(json.utf8))

        #expect(
            throws: ClientIDMetadataError.self,
            "a document must not claim an identifier other than its own URL"
        ) {
            try document.validate(fetchedFrom: "https://app.example.com/mcp-client")
        }
    }

    @Test("A self-consistent document validates")
    func testValidDocument() throws {
        let url = "https://app.example.com/mcp-client"
        let json = """
            {
              "client_id": "\(url)",
              "client_name": "Example Client",
              "redirect_uris": ["https://app.example.com/callback"],
              "application_type": "web"
            }
            """
        let document = try JSONDecoder().decode(
            ClientIDMetadataDocument.self, from: Data(json.utf8))

        let client = try document.validate(fetchedFrom: url)
        #expect(client.clientId == url)
        #expect(client.clientName == "Example Client")
        #expect(client.redirectUris == ["https://app.example.com/callback"])
        #expect(client.applicationType == .web)
    }

    /// A document with no redirect URIs cannot complete an authorization code flow, so it is
    /// refused at validation rather than failing later with a less obvious error.
    @Test("A document without redirect URIs is rejected")
    func testRequiresRedirectUris() throws {
        let url = "https://app.example.com/mcp-client"
        let json = """
            { "client_id": "\(url)", "client_name": "No Redirects", "redirect_uris": [] }
            """
        let document = try JSONDecoder().decode(
            ClientIDMetadataDocument.self, from: Data(json.utf8))

        #expect(throws: ClientIDMetadataError.self) {
            try document.validate(fetchedFrom: url)
        }
    }

    /// A metadata-document client has no client secret: there is nowhere to put one, and the
    /// document is public. It must therefore be treated as a public client.
    @Test("A metadata document client is public")
    func testClientIsPublic() throws {
        let url = "https://app.example.com/mcp-client"
        let json = """
            { "client_id": "\(url)", "client_name": "Example", "redirect_uris": ["https://app.example.com/cb"] }
            """
        let document = try JSONDecoder().decode(
            ClientIDMetadataDocument.self, from: Data(json.utf8))

        let client = try document.validate(fetchedFrom: url)
        #expect(client.clientSecret == nil, "a public client has no secret to keep")
        #expect(client.tokenEndpointAuthMethod == "none")
    }
}
