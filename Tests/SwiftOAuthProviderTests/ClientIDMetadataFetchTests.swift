import Foundation
import Testing

@testable import SwiftOAuthProvider

/// Fetching a Client ID Metadata Document.
///
/// The document decides **who a client is**, so the fetch policy is an authentication control,
/// not a performance concern. A permissive fetch lets an attacker point the authorization server
/// at a document of their choosing — or at an internal address it can reach and they cannot,
/// which is server-side request forgery.
///
/// Every test here is adversarial by design: the happy path is one case among many.
@Suite("Client ID Metadata Fetch")
struct ClientIDMetadataFetchTests {

    /// A transport that answers from a script rather than the network, so these tests never
    /// make a real request and can pose responses a real server would not.
    private actor ScriptedTransport: ClientIDMetadataTransport {
        private var responses: [String: ClientIDMetadataResponse]
        private(set) var requested: [String] = []

        init(_ responses: [String: ClientIDMetadataResponse]) {
            self.responses = responses
        }

        func get(_ url: URL, maximumBytes: Int) async throws -> ClientIDMetadataResponse {
            requested.append(url.absoluteString)
            guard let response = responses[url.absoluteString] else {
                return ClientIDMetadataResponse(statusCode: 404, body: Data(), location: nil)
            }
            return response
        }
    }

    private func document(clientId: String) -> Data {
        Data("""
            {
              "client_id": "\(clientId)",
              "client_name": "Example",
              "redirect_uris": ["https://app.example.com/cb"]
            }
            """.utf8)
    }

    @Test("A conforming document is fetched and becomes a registered client")
    func testHappyPath() async throws {
        let url = "https://app.example.com/mcp-client"
        let transport = ScriptedTransport([
            url: ClientIDMetadataResponse(statusCode: 200, body: document(clientId: url), location: nil)
        ])
        let fetcher = ClientIDMetadataFetcher(transport: transport)

        let client = try await fetcher.fetch(clientId: url)
        #expect(client.clientId == url)
        #expect(client.clientSecret == nil)
    }

    /// Plain HTTP is refused before any request is made — the check must not be a response
    /// validation, because by then the request has already left.
    @Test("A non-https identifier is refused without making a request")
    func testNonHTTPSRefusedBeforeRequesting() async throws {
        var insecure = URLComponents()
        insecure.scheme = "http"
        insecure.host = "app.example.com"
        insecure.path = "/client"
        let identifier = try #require(insecure.string)

        let transport = ScriptedTransport([:])
        let fetcher = ClientIDMetadataFetcher(transport: transport)

        await #expect(throws: ClientIDMetadataError.self) {
            _ = try await fetcher.fetch(clientId: identifier)
        }
        #expect(await transport.requested.isEmpty, "no request may be made for a refused scheme")
    }

    /// A redirect to another origin is refused. Following it would mean the document that
    /// defines the client came from a host the client never named.
    @Test("A cross-origin redirect is refused")
    func testCrossOriginRedirectRefused() async throws {
        let url = "https://app.example.com/mcp-client"
        let transport = ScriptedTransport([
            url: ClientIDMetadataResponse(
                statusCode: 302, body: Data(), location: "https://evil.example.com/client")
        ])
        let fetcher = ClientIDMetadataFetcher(transport: transport)

        await #expect(throws: ClientIDMetadataError.self) {
            _ = try await fetcher.fetch(clientId: url)
        }
    }

    /// Private, loopback and link-local addresses are refused. Reaching them is server-side
    /// request forgery: the authorization server can see hosts the caller cannot.
    @Test("Private and loopback addresses are refused", arguments: [
        "https://127.0.0.1/client",
        "https://localhost/client",
        "https://10.0.0.1/client",
        "https://192.168.1.1/client",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/client",
    ])
    func testPrivateAddressesRefused(identifier: String) async throws {
        let transport = ScriptedTransport([:])
        let fetcher = ClientIDMetadataFetcher(transport: transport)

        await #expect(throws: ClientIDMetadataError.self) {
            _ = try await fetcher.fetch(clientId: identifier)
        }
        #expect(await transport.requested.isEmpty, "\(identifier) must be refused before any request")
    }

    /// A document larger than the cap is refused rather than read. An unbounded read is a
    /// denial of service that any host publishing a document can trigger.
    @Test("An oversized document is refused")
    func testOversizedDocumentRefused() async throws {
        let url = "https://app.example.com/mcp-client"
        let transport = ScriptedTransport([
            url: ClientIDMetadataResponse(
                statusCode: 200,
                body: Data(repeating: 0x20, count: ClientIDMetadataFetcher.maximumDocumentBytes + 1),
                location: nil)
        ])
        let fetcher = ClientIDMetadataFetcher(transport: transport)

        await #expect(throws: ClientIDMetadataError.self) {
            _ = try await fetcher.fetch(clientId: url)
        }
    }

    /// The self-reference check still applies after fetching: a document served at one URL
    /// must not claim to be a client at another.
    @Test("A document claiming another identifier is refused after fetching")
    func testImpostorDocumentRefused() async throws {
        let url = "https://app.example.com/mcp-client"
        let transport = ScriptedTransport([
            url: ClientIDMetadataResponse(
                statusCode: 200,
                body: document(clientId: "https://evil.example.com/client"),
                location: nil)
        ])
        let fetcher = ClientIDMetadataFetcher(transport: transport)

        await #expect(throws: ClientIDMetadataError.self) {
            _ = try await fetcher.fetch(clientId: url)
        }
    }

    @Test("A non-200 response is refused")
    func testNonSuccessRefused() async throws {
        let url = "https://app.example.com/mcp-client"
        let transport = ScriptedTransport([
            url: ClientIDMetadataResponse(statusCode: 500, body: Data(), location: nil)
        ])
        let fetcher = ClientIDMetadataFetcher(transport: transport)

        await #expect(throws: ClientIDMetadataError.self) {
            _ = try await fetcher.fetch(clientId: url)
        }
    }
}
