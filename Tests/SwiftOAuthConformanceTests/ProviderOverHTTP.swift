import Foundation
import SwiftOAuthCore
import SwiftOAuthClient
import SwiftOAuthProvider

/// The client half's transports, answered by the provider's `OAuthHTTPHandler`.
///
/// Everything crosses as it would on a socket: the client's parameters become a URL-encoded
/// form body, the provider's answer is a status and a body, and the client reads that body with
/// its own types — a success as the response type, a refusal as an RFC 6749 §5.2 error. Nothing
/// is handed across as a Swift value.
actor ProviderOverHTTP: DeviceAuthorizationTransport, IntrospectionTransport {

    private let handler: OAuthHTTPHandler
    private(set) var tokenRequests = 0

    init(handler: OAuthHTTPHandler) {
        self.handler = handler
    }

    // MARK: - DeviceAuthorizationTransport

    func requestDeviceAuthorization(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws -> DeviceAuthorizationResponse {
        let (body, authorization) = Self.form(parameters, credentials: credentials, method: method)
        return try Self.read(
            await handler.handleDeviceAuthorizationRequest(body: body, authHeader: authorization))
    }

    func exchange(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws -> TokenResponse {
        tokenRequests += 1
        let (body, authorization) = Self.form(parameters, credentials: credentials, method: method)
        return try Self.read(
            await handler.handleTokenRequest(body: body, authHeader: authorization))
    }

    // MARK: - IntrospectionTransport

    nonisolated func post(url: URL, body: String, authorization: String?) async throws -> (Data, Int) {
        let response = await handler.handleIntrospectionRequest(
            body: body, authHeader: authorization)
        return (Data(response.body.utf8), response.statusCode)
    }

    // MARK: - The wire

    /// The form body and `Authorization` header a client would send, RFC 6749 §2.3.1.
    static func form(
        _ parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) -> (body: String, authorization: String?) {
        var fields = parameters
        var authorization: String?
        switch method {
        case .clientSecretBasic:
            authorization = "Basic " + Data("\(credentials.clientID):\(credentials.clientSecret)".utf8)
                .base64EncodedString()
        case .clientSecretPost:
            fields["client_id"] = credentials.clientID
            fields["client_secret"] = credentials.clientSecret
        default:
            fields["client_id"] = credentials.clientID
        }
        let body = fields.sorted { $0.key < $1.key }
            .map { "\(encoded($0.key))=\(encoded($0.value))" }
            .joined(separator: "&")
        return (body, authorization)
    }

    /// A 2xx body as `Answer`, or anything else as the §5.2 error it carries.
    static func read<Answer: Decodable>(_ response: OAuthHTTPResponse) throws -> Answer {
        let data = Data(response.body.utf8)
        guard (200..<300).contains(response.statusCode) else {
            throw try JSONDecoder().decode(OAuthErrorResponse.self, from: data).oauthError
        }
        return try JSONDecoder().decode(Answer.self, from: data)
    }

    private static func encoded(_ value: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }
}

/// A clock the provider reads and a test moves, shared by the halves under test.
// Justification: mutable `current` is read and written only under `lock`.
final class SharedClock: @unchecked Sendable {
    private var current = Date(timeIntervalSince1970: 1_800_000_000)
    private let lock = NSLock()

    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return current
    }

    func advance(_ seconds: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        current = current.addingTimeInterval(seconds)
    }
}

/// Records each wait, moves the provider's clock by it, and on the given wait approves the code
/// the user was shown — standing in for a person who types it in while the device polls.
actor ApprovingSleeper: DeviceFlowSleeper {

    private let approveOnWait: Int
    private let clock: SharedClock
    private let advancesClock: Bool
    private let approve: @Sendable (String) async throws -> Void
    private var userCode: String?
    private(set) var waits: [TimeInterval] = []

    /// - Parameters:
    ///   - approveOnWait: Which wait, counting from one, the user approves during.
    ///   - clock: The provider's clock.
    ///   - advancesClock: Whether a wait moves that clock. `false` makes a device that, by the
    ///     provider's reckoning, never waits at all.
    ///   - approve: What the user does.
    init(
        approveOnWait: Int, clock: SharedClock, advancesClock: Bool = true,
        approve: @escaping @Sendable (String) async throws -> Void
    ) {
        self.approveOnWait = approveOnWait
        self.clock = clock
        self.advancesClock = advancesClock
        self.approve = approve
    }

    func remember(_ code: String) {
        userCode = code
    }

    func sleep(for interval: TimeInterval) async throws {
        waits.append(interval)
        if advancesClock {
            clock.advance(interval)
        }
        if waits.count == approveOnWait, let userCode {
            try await approve(userCode)
        }
    }
}
