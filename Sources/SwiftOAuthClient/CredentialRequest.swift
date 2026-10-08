import Foundation
#if canImport(FoundationNetworking)
// `URLSession`, `URLRequest` and `HTTPURLResponse` live here on Linux rather than in Foundation.
import FoundationNetworking
#endif
#if canImport(Security)
// For the test seam that tells a request which certificate to accept; see `TestServerTrust`.
import Security
#endif
import SwiftOAuthCore

/// A request that carries a credential was answered with a redirect, and was not followed.
///
/// Thrown by ``URLSessionTokenTransport`` and ``URLSessionIntrospectionTransport`` — so by a
/// code exchange, a refresh, a revocation or an introspection — when the endpoint answers with
/// a `3xx`. Nothing is sent anywhere else: not the form body, not the `Authorization` header,
/// not a request without them.
///
/// A `3xx` that carries no `Location` header is reported the same way, with ``destination``
/// set to ``noLocation``: the endpoint said "not here" and named nowhere, which is no more an
/// answer to the request than a redirect that did.
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

    /// The origin the redirect named; ``unnamedOrigin`` if its `Location` was not a URL with a
    /// host; or ``noLocation`` if it had no `Location` header.
    public let destination: String

    /// What ``destination`` and ``endpoint`` say for a URL that has no origin to name.
    public static let unnamedOrigin = "(no origin)"

    /// What ``destination`` says when the redirect carried no `Location` header at all.
    public static let noLocation = "(no Location)"

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
        guard destination != Self.noLocation else {
            return "The endpoint on \(endpoint) answered a request carrying credentials with "
                + "HTTP \(status), a redirect, and no Location header to say where. There was "
                + "nothing to follow, and nothing was sent anywhere else."
        }
        return "The endpoint on \(endpoint) answered a request carrying credentials with an "
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
/// The refusal is attached to the *request*, not to a session a caller owns, so it holds for
/// the default session and equally for one supplied to
/// ``URLSessionTokenTransport/init(session:)``.
///
/// ## The answer is bounded
///
/// The body is received a piece at a time and the transfer is cancelled once it passes
/// ``OAuthResponseTooLarge/maximumResponseBytes``, so a server that never stops sending costs
/// a megabyte rather than the process's memory. The count is of bytes as delivered — after
/// `Content-Encoding` is undone — so a small compressed body that expands past the limit is
/// stopped too.
///
/// ## Why the two platforms send differently
///
/// Both need one object to be told about three things for one request: a redirect, the
/// response head, and each piece of the body.
///
/// On Apple platforms that is a task delegate, which works on any session, including one
/// whose own delegate the caller relies on.
///
/// swift-corelibs-foundation has no arrangement that delivers all three to a task's own
/// delegate. A task made with a completion handler consults `task.delegate` for a redirect
/// but buffers the entire body before calling the handler (`_NativeProtocol`
/// `createTransferBodyDataDrain`: `.dataCompletionHandler` → in-memory drain), and never
/// calls a data delegate. A task made without one delivers the body to the *session's*
/// delegate and to nothing else (`URLSession.behaviour(for:)`: `.callDelegate` reads
/// `self.delegate`). So on Linux the request is made on a short-lived session built from the
/// given session's **configuration**, with the receiver as that session's delegate. The
/// configuration — timeouts, proxy, cookie and credential storage, protocol classes — is the
/// caller's; the caller's session *delegate* is not consulted there.
enum CredentialRequest {

    /// The session used when a caller supplies none.
    ///
    /// Not `URLSession.shared`. That session carries the process's cookie jar, its credential
    /// store and its cache, so a token endpoint that set a cookie had it returned on the next
    /// token request, and one that answered `401` with a Basic challenge was sent whatever
    /// password the process had stored for that host — measured: a second request, carrying
    /// an `Authorization` header this package never wrote. A token request has no use for
    /// any of the three.
    static var isolatedSession: URLSession { isolated.session }

    private static let isolated = SessionBox(session: URLSession(configuration: isolatedConfiguration()))

    /// A configuration that keeps nothing: no cookies in or out, no stored credentials, no
    /// cache.
    ///
    /// - Returns: The configuration ``isolatedSession`` is built from.
    static func isolatedConfiguration() -> URLSessionConfiguration {
        // Ephemeral first, so nothing is written to disk by a default this does not override.
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        return configuration
    }

    /// Sends a request and returns its answer, refusing any redirect and any oversized body.
    ///
    /// - Parameters:
    ///   - request: The request. Its URL is the only place anything is sent.
    ///   - session: The session to send on.
    ///   - limit: The most body bytes to accept.
    ///   - trust: A certificate to accept in place of the platform's trust evaluation. Tests
    ///     only; see ``TestServerTrust``.
    /// - Returns: The body and the HTTP response.
    /// - Throws: ``OAuthRedirectRefused`` if the answer is a `3xx`,
    ///   ``OAuthResponseTooLarge`` if the body passes `limit`, `OAuthError.serverError(_:)`
    ///   if the answer is not HTTP, or whatever the session threw.
    static func send(
        _ request: URLRequest,
        on session: URLSession,
        limit: Int = OAuthResponseTooLarge.maximumResponseBytes,
        trust: TestServerTrust? = nil
    ) async throws -> (Data, HTTPURLResponse) {
        let endpoint = request.url.map(origin(of:)) ?? OAuthRedirectRefused.unnamedOrigin
        let (data, response) = try await load(
            request, on: session, limit: limit, endpoint: endpoint, trust: trust)
        guard let http = response as? HTTPURLResponse else {
            throw OAuthError.serverError("the response was not HTTP")
        }

        // With the redirect declined, the `3xx` itself is what comes back. It is turned into
        // an error here rather than handed on, because every caller would otherwise report
        // it as "HTTP 307" — true, and no help in finding out where the credential was being
        // sent. One with no `Location` is the same answer with less in it, and is reported
        // the same way rather than as a server error nobody could trace to a redirect.
        if (300..<400).contains(http.statusCode) {
            let destination = http.value(forHTTPHeaderField: "Location")
                .map { self.destination(of: $0, from: request.url) }
                ?? OAuthRedirectRefused.noLocation
            throw OAuthRedirectRefused(
                status: http.statusCode, endpoint: endpoint, destination: destination)
        }
        return (data, http)
    }

    /// Runs one data task whose redirect, response head and body all go to one receiver.
    ///
    /// Not `session.data(for:delegate:)`, which is the obvious spelling and is not portable:
    /// swift-corelibs-foundation accepts the `delegate` argument there and then decides a
    /// redirect by reading `task.delegate`, which that call never sets — so on Linux the
    /// delegate is never asked and the redirect is followed. Measured in this package's CI
    /// (`swift:6.2`, curl 8.5.0), that sent the `Authorization: Basic` header, client secret
    /// included, to the second origin at all five statuses.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - session: The session to send on, or — on Linux — to take the configuration of.
    ///   - limit: The most body bytes to accept.
    ///   - endpoint: The request's origin, for an error to name.
    ///   - trust: A certificate to accept, in tests.
    /// - Returns: The body and the response — the `3xx` itself when a redirect was declined.
    /// - Throws: ``OAuthResponseTooLarge``, or whatever the task failed with. If the calling
    ///   task is cancelled the data task is cancelled with it, and what is thrown is the
    ///   task's own `URLError(.cancelled)`.
    private static func load(
        _ request: URLRequest,
        on session: URLSession,
        limit: Int,
        endpoint: String,
        trust: TestServerTrust?
    ) async throws -> (Data, URLResponse) {
        // One element at most: the receiver finishes the stream once.
        let (answers, answer) = AsyncThrowingStream<(Data, URLResponse), any Error>.makeStream(
            bufferingPolicy: .bufferingNewest(1))

        #if canImport(FoundationNetworking)
        // See the type's discussion: the only arrangement corelibs delivers body data to.
        let receiver = ResponseReceiver(limit: limit, endpoint: endpoint, answer: answer)
        let carrier = URLSession(
            configuration: session.configuration, delegate: receiver, delegateQueue: nil)
        // A session holds its delegate until it is invalidated.
        defer { carrier.finishTasksAndInvalidate() }
        let task = carrier.dataTask(with: request)
        #else
        let receiver = trust.map {
            PinnedTrustReceiver(trust: $0, limit: limit, endpoint: endpoint, answer: answer)
        } ?? ResponseReceiver(limit: limit, endpoint: endpoint, answer: answer)
        let task = session.dataTask(with: request)
        // Assigned before the task starts; a task delegate takes precedence over the
        // session's for the callbacks it implements.
        task.delegate = receiver
        #endif
        task.resume()

        // The answer is awaited by a task of its own, so that cancelling the caller does not
        // end the wait by itself. It ends when the data task does: cancellation is passed to
        // the data task, whose completion then reports it. A bridge that stopped waiting
        // without stopping the transfer would leave the request running, credentials and
        // all, for a caller that had gone.
        // lifecycle: completes when the receiver finishes the stream, at the data task's completion or at the size limit
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

/// Holds the default session where a `static let` can keep it.
///
/// `URLSession` is documented as thread-safe on every platform but has not been declared
/// `Sendable` by every toolchain this package builds with.
// Justification: URLSession is thread-safe; the stored session is immutable after init.
private struct SessionBox: @unchecked Sendable {
    let session: URLSession
}

/// A server certificate a request should accept instead of evaluating trust the usual way.
///
/// **For tests.** The redirect rule has to be shown to hold when the first server speaks TLS
/// and sends the request to one that does not, and a loopback TLS server presents a
/// certificate minted a moment ago that nothing trusts. This names that certificate.
///
/// It is internal, it is reachable only through initialisers that are internal too, and no
/// public type stores one a caller could set: a release build of an application has no way to
/// construct it, and nothing in a `URLSessionConfiguration` or an environment variable
/// produces one. It exists on Apple platforms only — swift-corelibs-foundation gives a request
/// no say in what its TLS layer trusts, so there is nothing for it to do on Linux.
struct TestServerTrust: Sendable {

    /// The certificates to accept, DER-encoded. A server presenting anything else is refused.
    let certificatesDER: [Data]
}

/// Receives one request's redirect, response head and body.
///
/// One per request. It declines every redirect — the `3xx` then arrives as the response, and
/// that response says everything there is to report — and it counts the body as it comes,
/// cancelling the transfer the moment the count passes the limit.
// Justification: every mutable field is in `state`, which is read and written only under `lock`.
class ResponseReceiver: NSObject, URLSessionDataDelegate, @unchecked Sendable {

    /// What has arrived so far.
    private struct State {
        var response: URLResponse?
        var body = Data()
        var isFinished = false
        var sawChallenge = false
    }

    private let limit: Int
    private let endpoint: String
    private let answer: AsyncThrowingStream<(Data, URLResponse), any Error>.Continuation
    private let lock = NSLock()
    private var state = State()

    /// Creates a receiver.
    ///
    /// - Parameters:
    ///   - limit: The most body bytes to accept.
    ///   - endpoint: The request's origin, for ``OAuthResponseTooLarge`` to name.
    ///   - answer: Where the outcome is delivered, once.
    init(
        limit: Int,
        endpoint: String,
        answer: AsyncThrowingStream<(Data, URLResponse), any Error>.Continuation
    ) {
        self.limit = limit
        self.endpoint = endpoint
        self.answer = answer
    }

    /// Runs `body` with the state locked.
    private func withState<Value>(_ body: (inout State) -> Value) -> Value {
        lock.lock()
        defer { lock.unlock() }
        return body(&state)
    }

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

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
    ) {
        // A server that says how much is coming is taken at its word before any of it is
        // read. `-1` is "not stated", which is what a chunked body reports.
        guard response.expectedContentLength <= Int64(limit) else {
            refuse(dataTask)
            completionHandler(.cancel)
            return
        }
        withState { $0.response = response }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let isOver = withState { state -> Bool in
            guard !state.isFinished else { return false }
            state.body.append(data)
            return state.body.count > limit
        }
        if isOver {
            refuse(dataTask)
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        let outcome = withState { state -> (response: URLResponse?, body: Data, sawChallenge: Bool)? in
            guard !state.isFinished else { return nil }
            state.isFinished = true
            return (state.response, state.body, state.sawChallenge)
        }
        // Already answered: the transfer was stopped at the limit, and this is its cancellation.
        guard let outcome else { return }

        if let error {
            // A task ended because its authentication challenge was declined has still been
            // answered: the `401` and its body arrived before the challenge was raised, and
            // they are what the caller needs — an `invalid_client`, most likely.
            if outcome.sawChallenge, let response = outcome.response {
                answer.yield((outcome.body, response))
                answer.finish()
                return
            }
            answer.finish(throwing: error)
            return
        }
        // Where swift-corelibs-foundation has not reported a response head to the data
        // delegate, it has still left it on the task.
        guard let response = outcome.response ?? task.response else {
            answer.finish(throwing: OAuthError.serverError("the request produced no response"))
            return
        }
        answer.yield((outcome.body, response))
        answer.finish()
    }

    #if canImport(FoundationNetworking)
    /// Declines an authentication challenge that has no credential to answer it with.
    ///
    /// Linux only, where this receiver is the delegate of a session this package made for
    /// the one request, so it speaks for nobody else.
    ///
    /// RFC 6749 §5.2 has a server refuse a failed `client_secret_basic` authentication with a
    /// `401` and a `WWW-Authenticate: Basic` header — an ordinary wrong-secret answer. In
    /// swift-corelibs-foundation that header raises a challenge, and "perform default
    /// handling" with no credential on offer does nothing at all
    /// (`attemptProceedingWithDefaultCredential` has no `else`): the task is neither retried
    /// nor completed, and its timeout timer was already cancelled when the transfer finished.
    /// Declining the challenge ends the task instead, and
    /// ``urlSession(_:task:didCompleteWithError:)`` then hands on the `401` that had already
    /// arrived.
    ///
    /// A credential the session's own storage proposes is left to the default handling: the
    /// caller configured that storage, and it is theirs to use.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        withState { $0.sawChallenge = true }
        guard challenge.proposedCredential == nil else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
    #endif

    /// Ends the request as too large: answers the caller, drops what was read, stops the rest.
    private func refuse(_ task: URLSessionTask) {
        let isFirst = withState { state -> Bool in
            guard !state.isFinished else { return false }
            state.isFinished = true
            state.body = Data()
            return true
        }
        if isFirst {
            answer.finish(throwing: OAuthResponseTooLarge(endpoint: endpoint, limit: limit))
        }
        task.cancel()
    }
}

#if !canImport(FoundationNetworking)
/// A receiver that also answers the TLS server-trust challenge, for tests.
///
/// A subclass, so that the ordinary receiver does not implement the challenge method at all.
/// A task delegate that implemented it would be asked in place of a caller's session
/// delegate, and "perform default handling" from there would skip certificate pinning the
/// caller had set up. Only a request given a ``TestServerTrust`` gets this class.
// Justification: adds one immutable field to a superclass whose mutable state is lock-guarded.
final class PinnedTrustReceiver: ResponseReceiver, @unchecked Sendable {

    private let trust: TestServerTrust

    /// Creates a receiver that accepts the certificates `trust` names.
    ///
    /// - Parameters:
    ///   - trust: The certificates to accept.
    ///   - limit: The most body bytes to accept.
    ///   - endpoint: The request's origin.
    ///   - answer: Where the outcome is delivered.
    init(
        trust: TestServerTrust,
        limit: Int,
        endpoint: String,
        answer: AsyncThrowingStream<(Data, URLResponse), any Error>.Continuation
    ) {
        self.trust = trust
        super.init(limit: limit, endpoint: endpoint, answer: answer)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        // The named certificates become the only anchors, and the chain is evaluated against
        // them — hostname and validity included. Anything else is refused, not passed on.
        let anchors = trust.certificatesDER.compactMap {
            SecCertificateCreateWithData(nil, $0 as CFData)
        }
        guard SecTrustSetAnchorCertificates(serverTrust, anchors as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(serverTrust, true) == errSecSuccess,
              SecTrustEvaluateWithError(serverTrust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}
#endif
