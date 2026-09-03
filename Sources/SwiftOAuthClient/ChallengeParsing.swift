import Foundation
import SwiftOAuthCore

/// A `WWW-Authenticate: Bearer` challenge, parsed — RFC 6750 §3.
///
/// This is how a resource server says what a request lacked. Without reading it, a client's
/// only recovery from a `401` is to re-authorise with every scope it can think of and hope one
/// of them was the missing one — which widens the grant on every failure and never learns
/// anything.
///
/// The challenge says precisely what was missing. ``scopes`` is what to ask for: *exactly*
/// those, not those added to what is already held. The tempting implementation unions the two,
/// and each individual step then looks like it is only asking for what it was told while the
/// grant grows without anyone deciding that it should.
public struct BearerChallenge: Sendable, Equatable {

    /// The protection space, when the server named one.
    public let realm: String?

    /// The error code — `invalid_token`, `insufficient_scope`, `invalid_request`.
    public let error: String?

    /// The human-readable detail, when there is one.
    public let errorDescription: String?

    /// The scopes this resource requires, in the order the server listed them.
    ///
    /// Request exactly these. See the type's discussion for why not a union.
    public let scopes: [String]

    /// Where to find the protected-resource metadata — RFC 9728 §5.1.
    ///
    /// This is what closes the loop with RFC 8707: a client refused for naming no resource can
    /// follow this to learn the identifier to send, rather than being told only that one was
    /// required.
    public let resourceMetadata: URL?

    /// Parses a `WWW-Authenticate` header value.
    ///
    /// - Parameter header: The raw header value.
    /// - Returns: `nil` if this is not a `Bearer` challenge. A scheme this client does not
    ///   speak is not half-parsed: `Basic`'s parameters mean different things, and returning
    ///   them under these names would have a caller act on them as though they did not.
    public init?(header: String) {
        let trimmed = header.trimmingCharacters(in: .whitespaces)
        // RFC 7235 §2.1: the scheme is case-insensitive.
        guard trimmed.lowercased() == "bearer" || trimmed.lowercased().hasPrefix("bearer ") else {
            return nil
        }

        let parameters = Self.parameters(in: String(trimmed.dropFirst("bearer".count)))
        realm = parameters["realm"]
        error = parameters["error"]
        errorDescription = parameters["error_description"]
        scopes = parameters["scope"]?
            .split(separator: " ")
            .map(String.init) ?? []
        // The pointer is parsed, not followed. Fetching it here would make reading a header
        // into a network request to an address the header chose.
        // SECURITY: parses a URL from a server header; it is returned to the caller, never fetched.
        resourceMetadata = parameters["resource_metadata"].flatMap { URL(string: $0) }
    }

    /// The `key="value"` pairs in a challenge, respecting quoting.
    ///
    /// Written as a scan rather than a split on commas. A comma inside a quoted value is
    /// ordinary — `error_description="Expired, please retry"` is a legal header — and splitting
    /// on commas truncates that description and invents a parameter from its tail.
    private static func parameters(in text: String) -> [String: String] {
        var parameters: [String: String] = [:]
        var key = "", value = ""
        var inQuotes = false, readingValue = false

        func commit() {
            let trimmedKey = key.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmedKey.isEmpty {
                parameters[trimmedKey.lowercased()] =
                    value.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            key = ""; value = ""; readingValue = false
        }

        for character in text {
            switch character {
            case "\"":
                inQuotes.toggle()
            case "=" where !inQuotes && !readingValue:
                readingValue = true
            case "," where !inQuotes:
                commit()
            default:
                if readingValue { value.append(character) } else { key.append(character) }
            }
        }
        commit()
        return parameters
    }
}
