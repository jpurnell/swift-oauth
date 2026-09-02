import Foundation

/// One HTTP response to a metadata document request.
public struct ClientIDMetadataResponse: Sendable {
    /// The HTTP status code.
    public let statusCode: Int
    /// The response body, already bounded by the caller's byte cap.
    public let body: Data
    /// The `Location` header, when the response is a redirect.
    public let location: String?

    /// Creates a response.
    ///
    /// - Parameters:
    ///   - statusCode: The HTTP status code.
    ///   - body: The response body.
    ///   - location: The `Location` header, when present.
    public init(statusCode: Int, body: Data, location: String?) {
        self.statusCode = statusCode
        self.body = body
        self.location = location
    }
}

/// Fetches a metadata document over HTTP.
///
/// A transport **must not follow redirects**. ``ClientIDMetadataFetcher`` decides whether a
/// redirect may be followed, because that decision is a security policy: a transport that
/// follows redirects silently would let a document arrive from a host the client never named,
/// and the fetcher would have no way to know.
public protocol ClientIDMetadataTransport: Sendable {
    /// Performs a GET, following no redirects and reading at most `maximumBytes`.
    ///
    /// - Parameters:
    ///   - url: The URL to fetch.
    ///   - maximumBytes: The most the transport should read before giving up.
    /// - Returns: The response.
    func get(_ url: URL, maximumBytes: Int) async throws -> ClientIDMetadataResponse
}

/// Retrieves and validates a Client ID Metadata Document.
///
/// ## This is an authentication control
///
/// The document decides **who a client is**. A permissive fetch lets an attacker point the
/// authorization server at a document of their choosing, or at an internal address the server
/// can reach and they cannot — server-side request forgery. Every rule below exists for that
/// reason rather than for tidiness:
///
/// - **https only**, refused before any request is made. Checking the response would be too
///   late; the request has already left.
/// - **No redirects followed.** A redirect to another origin means the document defining the
///   client came from a host the client never named. Same-origin redirects are refused too,
///   because allowing them buys nothing and widens what has to be reasoned about.
/// - **No private, loopback or link-local addresses.** `169.254.169.254` is the cloud metadata
///   endpoint; reaching it on an attacker's behalf leaks credentials.
/// - **A byte cap.** An unbounded read is a denial of service any publisher can trigger.
/// - **The self-reference check**, applied after fetching: a document served at one URL must
///   not claim to be a client at another.
///
/// ## Known limitation
///
/// Host checks are applied to the URL, so a hostname that *resolves* to a private address is
/// not caught — DNS rebinding. Closing that requires resolving the name, checking the resolved
/// address, and connecting to that pinned address rather than re-resolving. This type does not
/// do that; a deployment that treats untrusted client identifiers as reachable should also
/// restrict egress at the network layer.
public struct ClientIDMetadataFetcher: Sendable {
    /// The most a metadata document may occupy. A conforming document is a few hundred bytes.
    public static let maximumDocumentBytes = 64 * 1024

    private let transport: any ClientIDMetadataTransport

    /// Creates a fetcher.
    ///
    /// - Parameter transport: The transport to fetch through. It must not follow redirects.
    public init(transport: any ClientIDMetadataTransport) {
        self.transport = transport
    }

    /// Fetches the document a client identifier points at and validates it.
    ///
    /// - Parameter clientId: The client's identifier, which is the URL of its document.
    /// - Returns: The client the document describes.
    /// - Throws: ``ClientIDMetadataError`` when the identifier or the document is not usable.
    public func fetch(clientId: String) async throws -> RegisteredClient {
        // Validated as components first, and only then turned into a URL. Constructing the URL
        // before checking it would mean holding a fetchable value for an identifier that has not
        // been cleared yet — the ordering, not just the checks, is what keeps an unvetted
        // identifier from ever becoming something this type could accidentally request.
        guard let components = URLComponents(string: clientId),
            components.scheme?.lowercased() == "https",
            let host = components.host, !host.isEmpty
        else {
            throw ClientIDMetadataError.notHTTPS(clientId)
        }
        guard !Self.isRestrictedHost(host) else {
            throw ClientIDMetadataError.restrictedAddress(host)
        }
        guard let url = components.url else {
            throw ClientIDMetadataError.notHTTPS(clientId)
        }

        let response = try await transport.get(url, maximumBytes: Self.maximumDocumentBytes)

        if let location = response.location {
            throw ClientIDMetadataError.redirected(from: clientId, to: location)
        }
        guard response.statusCode == 200 else {
            throw ClientIDMetadataError.unexpectedStatus(response.statusCode)
        }
        guard response.body.count <= Self.maximumDocumentBytes else {
            throw ClientIDMetadataError.documentTooLarge(response.body.count)
        }

        let document = try JSONDecoder().decode(ClientIDMetadataDocument.self, from: response.body)
        return try document.validate(fetchedFrom: clientId)
    }

    /// Whether a host is one the authorization server must not be pointed at.
    ///
    /// Literal addresses are checked because they are what an attacker supplies directly. A
    /// hostname resolving to one of these ranges is not caught here — see the type's *Known
    /// limitation*.
    static func isRestrictedHost(_ host: String) -> Bool {
        let bare = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()

        if bare == "localhost" || bare.hasSuffix(".localhost") { return true }
        if bare == "::1" || bare.hasPrefix("fe80:") || bare.hasPrefix("fc") || bare.hasPrefix("fd") {
            return true
        }

        let parts = bare.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return false }
        switch (parts[0], parts[1]) {
        case (127, _), (10, _), (0, _):
            return true
        case (169, 254):  // link-local, including the cloud metadata endpoint
            return true
        case (192, 168):
            return true
        case (172, let second) where (16...31).contains(second):
            return true
        default:
            return false
        }
    }
}
