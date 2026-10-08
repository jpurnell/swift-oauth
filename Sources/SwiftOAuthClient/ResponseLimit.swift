import Foundation

/// A response was larger than this package reads.
///
/// Thrown by ``URLSessionTokenTransport`` and ``URLSessionIntrospectionTransport`` when a
/// token, refresh, revocation or introspection endpoint sends more than ``limit`` bytes of
/// body — counted after any `Content-Encoding` is undone, so a small compressed answer that
/// expands past the limit is refused as well. The transfer is cancelled at the point the limit
/// is passed; the rest of the body is never received, and nothing of what was received is
/// returned.
///
/// These endpoints answer with a short JSON object: a token response is a few hundred bytes,
/// and one carrying a signed JWT a few thousand. A megabyte is several hundred times that, so
/// a conforming server is never refused, and a server that will not stop sending — by fault or
/// by intent — costs the client a megabyte and no more.
public struct OAuthResponseTooLarge: Error, Sendable, Equatable {

    /// The most this package reads of one response body: 1 MiB.
    public static let maximumResponseBytes = 1_048_576

    /// The origin of the endpoint that answered, `scheme://host[:port]`.
    public let endpoint: String

    /// The limit that was passed, in bytes.
    public let limit: Int

    /// Creates the error.
    ///
    /// - Parameters:
    ///   - endpoint: The origin of the endpoint that answered.
    ///   - limit: The limit that was passed, in bytes.
    public init(endpoint: String, limit: Int) {
        self.endpoint = endpoint
        self.limit = limit
    }
}

extension OAuthResponseTooLarge: CustomStringConvertible, LocalizedError {

    /// What happened, naming the endpoint's origin and the limit.
    public var description: String {
        "The endpoint on \(endpoint) sent a response larger than \(limit) bytes. "
            + "The transfer was stopped and the response was not used."
    }

    /// The same text, for callers that read `localizedDescription`.
    public var errorDescription: String? { description }
}
