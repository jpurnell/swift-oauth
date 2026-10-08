import Foundation
#if canImport(FoundationNetworking)
// `URLSession`, `URLRequest` and `HTTPURLResponse` live here on Linux rather than in Foundation.
import FoundationNetworking
#endif
import SwiftOAuthCore

/// A request that carries a credential was answered with a redirect, and was not followed.
///
/// Thrown by ``URLSessionTokenTransport`` and ``URLSessionIntrospectionTransport`` — so by a
/// code exchange, a refresh, a revocation or an introspection — when the endpoint answers with
/// a `3xx` that names a `Location`. Nothing is sent to that location: not the form body, not
/// the `Authorization` header, not a request without them.
///
/// Not transient. The endpoint that was configured, or discovered, is not where the server
/// wants the request, and asking again gets the same answer. If ``destination`` is the server
/// you meant, configure that endpoint; if it is not, something answering for the
/// authorization server tried to have a credential posted elsewhere.
///
/// Both origins are `scheme://host[:port]` and nothing more. A `Location` is whatever the
/// server chose to write, and an endpoint may carry a query, so neither is quoted whole into
/// a value that will be logged.
public struct OAuthRedirectRefused: Error, Sendable, Equatable {

    /// The redirect's status code.
    public let status: Int

    /// The origin of the endpoint the request was sent to.
    public let endpoint: String

    /// The origin the redirect named, or ``unnamedOrigin`` if its `Location` was not a URL
    /// with a host.
    public let destination: String

    /// What ``destination`` and ``endpoint`` say for a URL that has no origin to name.
    public static let unnamedOrigin = "(no origin)"

    /// Creates the error.
    ///
    /// - Parameters:
    ///   - status: The redirect's status code.
    ///   - endpoint: The origin of the endpoint that answered.
    ///   - destination: The origin the redirect named.
    public init(status: Int, endpoint: String, destination: String) {
        self.status = status
        self.endpoint = endpoint
        self.destination = destination
    }
}

extension OAuthRedirectRefused: CustomStringConvertible, LocalizedError {

    /// What happened, naming both origins and nothing else about either URL.
    public var description: String {
        "The endpoint on \(endpoint) answered a request carrying credentials with an "
            + "HTTP \(status) redirect to \(destination). It was not followed, and nothing "
            + "was sent to \(destination)."
    }

    /// The same text, for callers that read `localizedDescription`.
    public var errorDescription: String? { description }
}

/// The one way this package puts a credential on the wire.
///
/// Every request the client half makes itself is a `POST` holding something that must reach
/// one host only: a client secret, an authorization code and its PKCE verifier, a refresh
/// token, a token being revoked or asked about. `URLSession` follows redirects unless told
/// otherwise, and measured between two loopback servers that meant: for a `307` or `308` the
/// whole form body re-posted to wherever `Location` pointed, and for a `301`, `302` or `303` a
/// `GET` sent there — and in every case the *second* server's answer accepted as the
/// endpoint's own.
///
/// No specification this package implements provides for it. RFC 6749 §3.2 (the token
/// endpoint), RFC 7009 §2.1 (revocation) and RFC 7662 §2.1 (introspection) each define the
/// request as a `POST` to an endpoint the client was configured with or discovered, and none
/// describes a redirect as an answer. RFC 9700 §4.12 is about a different hop — the user
/// agent leaving the authorization endpoint — but states the mechanism: a `307` repeats a
/// `POST` with its body, which "discloses the sensitive credentials" to whoever it points at.
///
/// So a redirect is not followed at all — not across origins, and not within one, where a
/// `301`/`302`/`303` would arrive as a body-less `GET` that cannot mean what the `POST` meant.
///
/// The refusal is attached to the *task*, not to a session, so it holds for `URLSession.shared`
/// and equally for a session a caller supplies to ``URLSessionTokenTransport/init(session:)``.
enum CredentialRequest {

    /// Sends a request and returns its answer, refusing any redirect.
    ///
    /// - Parameters:
    ///   - request: The request. Its URL is the only place anything is sent.
    ///   - session: The session to send on.
    /// - Returns: The body and the HTTP response.
    /// - Throws: ``OAuthRedirectRefused`` if the answer is a redirect naming a `Location`,
    ///   `OAuthError.serverError(_:)` if the answer is not HTTP, or whatever the session
    ///   threw.
    static func send(_ request: URLRequest, on session: URLSession) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await load(request, on: session)
        guard let http = response as? HTTPURLResponse else {
            throw OAuthError.serverError("the response was not HTTP")
        }

        // With the redirect declined, the `3xx` itself is what comes back. It is turned into
        // an error here rather than handed on, because every caller would otherwise report
        // it as "HTTP 307" — true, and no help in finding out where the credential was being
        // sent.
        if (300..<400).contains(http.statusCode),
           let location = http.value(forHTTPHeaderField: "Location") {
            throw OAuthRedirectRefused(
                status: http.statusCode,
                endpoint: request.url.map(origin(of:)) ?? OAuthRedirectRefused.unnamedOrigin,
                destination: destination(of: location, from: request.url))
        }
        return (data, http)
    }

    /// Runs one data task with the refusing delegate set on the task itself.
    ///
    /// Not `session.data(for:delegate:)`, which is the obvious spelling and is not portable:
    /// swift-corelibs-foundation accepts the `delegate` argument there and then decides a
    /// redirect by reading `task.delegate`, which that call never sets — so on Linux the
    /// delegate is never asked and the redirect is followed. Measured in this package's CI
    /// (`swift:6.2`, curl 8.5.0), that sent the `Authorization: Basic` header, client secret
    /// included, to the second origin at all five statuses. Assigning `task.delegate` before
    /// the task is resumed is honoured on both platforms.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - session: The session to create the task on.
    /// - Returns: The body and the response — the `3xx` itself when a redirect was declined.
    /// - Throws: Whatever the task failed with. If the calling task is cancelled the data
    ///   task is cancelled with it, and what is thrown is the task's own
    ///   `URLError(.cancelled)`.
    private static func load(_ request: URLRequest, on session: URLSession) async throws -> (Data, URLResponse) {
        // One element at most: the completion handler is called once.
        let (answers, answer) = AsyncThrowingStream<(Data, URLResponse), any Error>.makeStream(
            bufferingPolicy: .bufferingNewest(1))

        let task = session.dataTask(with: request) { data, response, error in
            if let error {
                answer.finish(throwing: error)
            } else if let data, let response {
                answer.yield((data, response))
                answer.finish()
            } else {
                answer.finish(throwing: OAuthError.serverError("the request produced no response"))
            }
        }
        task.delegate = RedirectRefuser()
        task.resume()

        // The answer is awaited by a task of its own, so that cancelling the caller does not
        // end the wait by itself. It ends when the data task does: cancellation is passed to
        // the data task, whose completion handler then reports it. A bridge that stopped
        // waiting without stopping the transfer would leave the request running, credentials
        // and all, for a caller that had gone.
        // lifecycle: completes when the data task's completion handler finishes the stream
        let delivery = Task {
            for try await result in answers {
                return result
            }
            throw OAuthError.serverError("the request produced no response")
        }
        return try await withTaskCancellationHandler {
            try await delivery.value
        } onCancel: {
            task.cancel()
        }
    }

    /// The origin a `Location` resolves to.
    ///
    /// - Parameters:
    ///   - location: The header as the server sent it — absolute, or relative to the request.
    ///   - base: The URL the request was sent to.
    /// - Returns: `scheme://host[:port]`, or ``OAuthRedirectRefused/unnamedOrigin``.
    static func destination(of location: String, from base: URL?) -> String {
        guard let resolved = URL(string: location, relativeTo: base)?.absoluteURL else {
            return OAuthRedirectRefused.unnamedOrigin
        }
        return origin(of: resolved)
    }

    /// `scheme://host[:port]` — the most an error says about a URL.
    ///
    /// Userinfo, path, query and fragment are left out on purpose: the first is a credential,
    /// and the rest is whatever a server wanted written into the caller's logs.
    ///
    /// - Parameter url: The URL to name.
    /// - Returns: Its origin, or ``OAuthRedirectRefused/unnamedOrigin`` if it has no host.
    static func origin(of url: URL) -> String {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
              let scheme = components.scheme?.lowercased(),
              let host = components.host?.lowercased(), !host.isEmpty else {
            return OAuthRedirectRefused.unnamedOrigin
        }
        // `URLComponents` hands an IPv6 literal back with its brackets on Apple platforms and
        // without them elsewhere; one spelling is written either way.
        let bare = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        let authority = bare.contains(":") ? "[\(bare)]" : bare
        guard let port = components.port else { return "\(scheme)://\(authority)" }
        return "\(scheme)://\(authority):\(port)"
    }
}

/// Declines every redirect.
///
/// A task delegate rather than a session delegate, so it applies to one request on whatever
/// session carries it — and takes precedence over a delegate that session has of its own. It holds no state: the `3xx` it declines to follow is returned to the
/// caller as the task's response, and that response says everything there is to report.
private final class RedirectRefuser: NSObject, URLSessionTaskDelegate {

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        // `nil` is "do not follow": the task completes with the redirect response as its
        // answer, and no request is made to `request.url`.
        completionHandler(nil)
    }
}
