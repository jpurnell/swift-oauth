import Foundation

/// Why a client ID metadata document was refused.
public enum ClientIDMetadataError: Error, Sendable, Equatable {
    /// The document's `client_id` did not equal the URL it was fetched from.
    case identifierMismatch(declared: String, fetchedFrom: String)
    /// The document declared no redirect URIs, so no authorization code flow can complete.
    case noRedirectUris
    /// The identifier was not an https URL.
    case notHTTPS(String)
    /// The host is private, loopback or link-local, and must not be fetched from.
    case restrictedAddress(String)
    /// The response redirected. Redirects are not followed for metadata documents.
    case redirected(from: String, to: String)
    /// The response was not `200 OK`.
    case unexpectedStatus(Int)
    /// The document exceeded the byte cap.
    case documentTooLarge(Int)
}

/// A client's metadata, published by the client at its own https URL.
///
/// MCP `2026-07-28` deprecates OAuth Dynamic Client Registration in favour of this. Rather than
/// registering and being issued an identifier, a client **is** a URL; the authorization server
/// fetches that URL to learn what the client is. DCR remains available for authorization
/// servers that do not support metadata documents.
///
/// ## Why the self-reference check matters
///
/// The document's own `client_id` must equal the URL it was fetched from. Without that check,
/// any host could publish a document claiming to be someone else's client and receive
/// authorizations intended for them. ``validate(fetchedFrom:)`` enforces it, and it is the only
/// thing standing between "I fetched a document" and "I know who this client is".
public struct ClientIDMetadataDocument: Codable, Sendable, Equatable {
    /// The client's identifier, which must equal the URL this document was fetched from.
    public let clientId: String
    /// Human-readable name for the client.
    public let clientName: String
    /// Redirect URIs the client will accept authorization responses at.
    public let redirectUris: [String]
    /// Whether the client is a web or native application.
    public let applicationType: ApplicationType
    /// Scopes the client requests, if it declares any.
    public let scope: String?

    private enum CodingKeys: String, CodingKey {
        case clientId = "client_id"
        case clientName = "client_name"
        case redirectUris = "redirect_uris"
        case applicationType = "application_type"
        case scope
    }

    /// Creates a metadata document.
    ///
    /// - Parameters:
    ///   - clientId: The client's identifier, equal to the URL it publishes this document at.
    ///   - clientName: Human-readable name for the client.
    ///   - redirectUris: Redirect URIs the client will accept responses at.
    ///   - applicationType: Whether the client is a web or native application.
    ///   - scope: Scopes the client requests, if any.
    public init(
        clientId: String,
        clientName: String,
        redirectUris: [String],
        applicationType: ApplicationType = .web,
        scope: String? = nil
    ) {
        self.clientId = clientId
        self.clientName = clientName
        self.redirectUris = redirectUris
        self.applicationType = applicationType
        self.scope = scope
    }

    /// Decodes a document, defaulting `application_type` when the client omits it.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        clientId = try container.decode(String.self, forKey: .clientId)
        clientName = try container.decode(String.self, forKey: .clientName)
        redirectUris = try container.decode([String].self, forKey: .redirectUris)
        applicationType =
            try container.decodeIfPresent(ApplicationType.self, forKey: .applicationType) ?? .web
        scope = try container.decodeIfPresent(String.self, forKey: .scope)
    }

    /// Whether an identifier names a metadata document rather than a DCR-issued client.
    ///
    /// Only https qualifies. The document determines who the client *is*, so fetching it over a
    /// channel an attacker can rewrite would let them redefine the client. A DCR identifier is
    /// an opaque string and is not a URL, so the two never collide.
    ///
    /// - Parameter identifier: The `client_id` presented in an authorization request.
    /// - Returns: `true` when the identifier is an https URL with a host.
    public static func isMetadataDocumentIdentifier(_ identifier: String) -> Bool {
        guard let components = URLComponents(string: identifier),
            components.scheme?.lowercased() == "https",
            let host = components.host, !host.isEmpty
        else { return false }
        return true
    }

    /// Checks the document against the URL it came from and converts it to a registered client.
    ///
    /// - Parameter fetchedFrom: The URL this document was retrieved from.
    /// - Returns: The client this document describes.
    /// - Throws: ``ClientIDMetadataError`` when the document is not usable.
    public func validate(fetchedFrom: String) throws -> RegisteredClient {
        guard Self.isMetadataDocumentIdentifier(fetchedFrom) else {
            throw ClientIDMetadataError.notHTTPS(fetchedFrom)
        }
        guard clientId == fetchedFrom else {
            throw ClientIDMetadataError.identifierMismatch(
                declared: clientId, fetchedFrom: fetchedFrom)
        }
        guard !redirectUris.isEmpty else {
            throw ClientIDMetadataError.noRedirectUris
        }

        // A metadata-document client is public by construction: the document is fetched over
        // the open web, so there is nowhere to put a secret that the client alone would know.
        return RegisteredClient(
            clientId: clientId,
            clientSecret: nil,
            clientName: clientName,
            redirectUris: redirectUris,
            grantTypes: ["authorization_code", "refresh_token"],
            tokenEndpointAuthMethod: "none",
            registrationDate: Date(),
            applicationType: applicationType
        )
    }
}
