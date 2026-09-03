import Foundation
import Testing
@testable import SwiftOAuthCore
@testable import SwiftOAuthClient

/// Driving a device flow from the client — RFC 8628 §3.3–3.5.
///
/// The polling loop is the feature. A device code that nobody polls is a string, and the
/// mistakes all live in the loop: stopping on the wrong states, ignoring the interval the
/// server asked for, or waiting forever on a user who walked away.
///
/// Time is injected throughout. A test that actually slept five seconds per poll would take
/// minutes to assert something that is pure arithmetic.
@Suite("RFC 8628 — the client's polling loop")
struct DeviceFlowTests {

    /// The loop keeps going through `authorization_pending` and stops when tokens arrive.
    @Test("Polling continues through pending and stops on success")
    func pollsUntilIssued() async throws {
        let poller = DeviceFlowPoller(
            outcomes: [.pending, .pending, .issued], sleeper: RecordingSleeper())

        let tokens = try await poller.run(interval: 5, expiresIn: 1800)

        #expect(tokens.accessToken == "issued-token")
        #expect(await poller.pollCount == 3)
    }

    /// `slow_down` widens the wait, and the widening persists.
    ///
    /// The interval the client actually waits is what matters, so the sleeper records it. A
    /// client that applies `slow_down` to one request and reverts keeps making the same
    /// mistake at the same rate, and the server keeps having to say it.
    @Test("slow_down widens the waits, permanently")
    func slowDownWidensSubsequentWaits() async throws {
        let sleeper = RecordingSleeper()
        let poller = DeviceFlowPoller(
            outcomes: [.pending, .slowDown, .pending, .issued], sleeper: sleeper)

        _ = try await poller.run(interval: 5, expiresIn: 1800)

        // Four polls produce three waits, and `slow_down` applies to the wait immediately
        // following it: the stated interval once, then widened, then still widened. The last
        // poll succeeds and is not followed by a wait.
        #expect(await sleeper.waits == [5, 10, 10])
    }

    /// A refusal ends the flow, and says so rather than timing out.
    @Test("access_denied ends the flow as a refusal")
    func denialEndsTheFlow() async throws {
        let poller = DeviceFlowPoller(
            outcomes: [.pending, .denied], sleeper: RecordingSleeper())

        let error = await #expect(throws: OAuthError.self) {
            _ = try await poller.run(interval: 5, expiresIn: 1800)
        }
        #expect(error?.code == "access_denied")
    }

    /// An expired device code ends the flow.
    @Test("expired_token ends the flow")
    func expiryEndsTheFlow() async throws {
        let poller = DeviceFlowPoller(
            outcomes: [.pending, .expired], sleeper: RecordingSleeper())

        let error = await #expect(throws: OAuthError.self) {
            _ = try await poller.run(interval: 5, expiresIn: 1800)
        }
        #expect(error?.code == "expired_token")
    }

    /// The client gives up on its own once the code cannot still be alive.
    ///
    /// A server is not obliged to answer `expired_token` — it may have forgotten the code
    /// entirely. Without a local bound, a client polls a dead code until something else stops
    /// it, which is how a device left on a shelf keeps a server busy indefinitely.
    @Test("The loop stops itself when the code's lifetime has passed")
    func loopStopsAtExpiry() async throws {
        let sleeper = RecordingSleeper()
        // Never anything but pending: only the local bound can end this.
        let poller = DeviceFlowPoller(
            outcomes: Array(repeating: .pending, count: 1000), sleeper: sleeper)

        await #expect(throws: OAuthError.self) {
            _ = try await poller.run(interval: 5, expiresIn: 20)
        }
        // 20 seconds of lifetime at 5 seconds a poll: it must not run away.
        #expect(await poller.pollCount <= 5, "the loop polled past the code's lifetime")
    }
}

/// What a scripted poll returned.
enum ScriptedOutcome: Sendable {
    case pending, slowDown, denied, expired, issued
}

/// Records how long the loop was asked to wait, without waiting.
actor RecordingSleeper: DeviceFlowSleeper {
    private(set) var waits: [TimeInterval] = []

    func sleep(for interval: TimeInterval) async throws {
        waits.append(interval)
    }
}

/// A poller driven by a script rather than a network.
actor DeviceFlowPoller {
    private var outcomes: [ScriptedOutcome]
    private let sleeper: any DeviceFlowSleeper
    private(set) var pollCount = 0

    init(outcomes: [ScriptedOutcome], sleeper: any DeviceFlowSleeper) {
        self.outcomes = outcomes
        self.sleeper = sleeper
    }

    func run(interval: TimeInterval, expiresIn: TimeInterval) async throws -> TokenResponse {
        try await DeviceFlow.poll(
            interval: interval,
            expiresIn: expiresIn,
            sleeper: sleeper,
            elapsed: { [weak self] in
                // One "second" per poll times the interval, so the local bound can be reached
                // without any real time passing.
                TimeInterval((await self?.pollCount ?? 0)) * interval
            },
            redeem: { [weak self] in
                guard let self else { throw OAuthError.serverError(nil) }
                return try await self.next()
            })
    }

    private func next() throws -> TokenResponse {
        pollCount += 1
        guard !outcomes.isEmpty else { throw OAuthError.expiredToken(nil) }
        switch outcomes.removeFirst() {
        case .pending: throw OAuthError.authorizationPending(nil)
        case .slowDown: throw OAuthError.slowDown(nil)
        case .denied: throw OAuthError.accessDenied(nil)
        case .expired: throw OAuthError.expiredToken(nil)
        case .issued:
            return TokenResponse(
                accessToken: "issued-token", tokenType: "Bearer",
                expiresIn: 3600, refreshToken: nil, scope: nil)
        }
    }
}
