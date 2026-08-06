import Foundation
import SwiftOAuthCore
@testable import SwiftOAuthClient

/// A transport that answers from a script instead of a network.
///
/// The rotation behaviour that makes an OAuth client difficult — a concurrent refresh, a
/// crash mid-write, a token replaced out from under you — cannot be provoked reliably
/// against a live provider. Against this it is a few lines, and deterministic.
actor StubTransport: TokenTransport {

    /// What the next exchange should do.
    enum Reply: Sendable {
        /// Return tokens.
        case tokens(access: String, refresh: String?, expiresIn: Int)
        /// Fail the way a provider does.
        case failure(OAuthError)
    }

    private var replies: [Reply]
    private(set) var requests: [[String: String]] = []

    /// Blocks the next exchange until released, so two callers can be made to overlap.
    private var gate: CheckedContinuation<Void, Never>?
    private var shouldWait = false

    /// Signals a waiter that an exchange has begun, so a test can sequence on the event
    /// rather than on elapsed time. Sleeping for a plausible interval works on an idle
    /// machine and fails on a loaded one — the exact fragility this suite is checking for.
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var hasStarted = false

    init(_ replies: [Reply]) {
        self.replies = replies
    }

    /// Makes the next exchange wait, so a second caller can arrive while it is in flight.
    func holdNextExchange() {
        shouldWait = true
    }

    /// Lets a held exchange proceed.
    func release() {
        gate?.resume()
        gate = nil
    }

    /// Returns once an exchange has actually begun.
    func waitUntilExchangeStarted() async {
        if hasStarted { return }
        await withCheckedContinuation { continuation in
            startWaiters.append(continuation)
        }
    }

    /// How many exchanges have been made. The number that matters for concurrent refresh.
    var exchangeCount: Int { requests.count }

    func exchange(
        endpoint: URL,
        parameters: [String: String],
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod
    ) async throws -> TokenResponse {
        requests.append(parameters)

        hasStarted = true
        for waiter in startWaiters { waiter.resume() }
        startWaiters.removeAll()

        if shouldWait {
            shouldWait = false
            await withCheckedContinuation { continuation in
                gate = continuation
            }
        }

        guard !replies.isEmpty else {
            throw OAuthError.serverError("the stub ran out of scripted replies")
        }
        switch replies.removeFirst() {
        case .failure(let error):
            throw error
        case .tokens(let access, let refresh, let expiresIn):
            return TokenResponse(
                accessToken: access,
                expiresIn: expiresIn,
                refreshToken: refresh,
                scope: "accounting")
        }
    }
}

/// A clock a test advances by hand.
///
/// Waiting for a token to expire in real time would make the suite slow and, worse,
/// timing-dependent: passing on an idle machine and failing on a loaded one.
final class TestClock: @unchecked Sendable {
    // Justification: mutable `instant` is guarded by `lock`; no other state exists.
    private let lock = NSLock()
    private var instant: Date

    init(at instant: Date = Date(timeIntervalSince1970: 1_767_225_600)) {
        self.instant = instant
    }

    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return instant
    }

    func advance(by interval: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        instant = instant.addingTimeInterval(interval)
    }
}

extension ProviderConfiguration {

    /// A provider shaped like Intuit's, for tests.
    static var testProvider: ProviderConfiguration {
        ProviderConfiguration(
            identifier: "test",
            authorizationEndpoint: URL(string: "https://provider.example/authorize") ?? URL(fileURLWithPath: "/"),
            tokenEndpoint: URL(string: "https://provider.example/token") ?? URL(fileURLWithPath: "/"),
            revocationEndpoint: URL(string: "https://provider.example/revoke") ?? URL(fileURLWithPath: "/"),
            scope: "accounting")
    }
}

extension ClientCredentials {

    /// Credentials for tests.
    static var testCredentials: ClientCredentials {
        ClientCredentials(environment: "sandbox", clientID: "test-client", clientSecret: "test-secret")
    }
}

extension ConnectionID {

    /// A connection for tests.
    static var testConnection: ConnectionID {
        ConnectionID(tenant: "acme", provider: "test", account: "123")
    }
}
