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

    // MARK: - What the authorization server said, when it is not a number

    /// Values a device authorization response can carry that are not a wait or a lifetime.
    ///
    /// `interval` and `expires_in` are another server's JSON. A decoder configured to accept
    /// non-conforming floats yields NaN and infinity from it, and any decoder yields `1e300`,
    /// a negative, or zero. Until `1.0.0-beta.6` the loop computed `Int(expiresIn / interval)`
    /// from them, which for the first three is a trap: one malformed response ended the
    /// process that was polling.
    static let malformed: [TimeInterval] = [.nan, .infinity, -.infinity, -1, 0, 1e300]

    @Test("A malformed interval is the server's error, and nothing is polled",
          arguments: malformed)
    func malformedIntervalIsRefused(_ interval: TimeInterval) async throws {
        let sleeper = RecordingSleeper()
        let poller = DeviceFlowPoller(outcomes: [.issued], sleeper: sleeper)

        await #expect(throws: OAuthError.serverError(
            "The authorization server's device authorization response has an interval that "
            + "is not a usable number of seconds.")) {
            _ = try await poller.run(interval: interval, expiresIn: 1800)
        }

        #expect(await poller.pollCount == 0)
        #expect(await sleeper.waits == [])
    }

    @Test("A malformed expires_in is the server's error, and nothing is polled",
          arguments: malformed)
    func malformedExpiryIsRefused(_ expiresIn: TimeInterval) async throws {
        let sleeper = RecordingSleeper()
        let poller = DeviceFlowPoller(outcomes: [.issued], sleeper: sleeper)

        await #expect(throws: OAuthError.serverError(
            "The authorization server's device authorization response has an expires_in that "
            + "is not a usable number of seconds.")) {
            _ = try await poller.run(interval: 5, expiresIn: expiresIn)
        }

        #expect(await poller.pollCount == 0)
        #expect(await sleeper.waits == [])
    }

    /// The largest values that are still numbers of seconds do not overflow the poll bound.
    ///
    /// `2^63 - 1024` is the greatest `Double` an `Int` can hold. At a one-second interval the
    /// bound is that plus one, which is where an unchecked `+ 1` would be closest to trapping.
    @Test("The largest representable lifetime is polled, not trapped on")
    func hugeLifetimeDoesNotTrap() async throws {
        let sleeper = RecordingSleeper()
        let poller = DeviceFlowPoller(outcomes: [.pending, .issued], sleeper: sleeper)

        let tokens = try await poller.run(interval: 1, expiresIn: 9_223_372_036_854_774_784)

        #expect(tokens.accessToken == "issued-token")
        #expect(await poller.pollCount == 2)
        #expect(await sleeper.waits == [1])
    }

    /// A huge interval leaves room for one poll, and the loop then ends by its own bound.
    @Test("The largest representable interval allows exactly one poll")
    func hugeIntervalAllowsOnePoll() async throws {
        let sleeper = RecordingSleeper()
        let poller = DeviceFlowPoller(
            outcomes: Array(repeating: .pending, count: 10), sleeper: sleeper)

        await #expect(throws: OAuthError.expiredToken(
            "The device code's lifetime elapsed before the user finished.")) {
            _ = try await poller.run(
                interval: 9_223_372_036_854_774_784, expiresIn: 9_223_372_036_854_774_784)
        }

        #expect(await poller.pollCount == 1)
    }

    /// A fractional interval below one second is a number, and is honoured as stated.
    @Test("A sub-second interval is accepted and waited as stated")
    func subSecondIntervalIsAccepted() async throws {
        let sleeper = RecordingSleeper()
        let poller = DeviceFlowPoller(outcomes: [.pending, .issued], sleeper: sleeper)

        let tokens = try await poller.run(interval: 0.5, expiresIn: 1800)

        #expect(tokens.accessToken == "issued-token")
        // Bit-identical: the interval is passed through, not computed, so the wait is the very
        // value the server stated.
        let waits = await sleeper.waits
        let stated: [TimeInterval] = [0.5]
        #expect(waits.count == stated.count
                && zip(waits, stated).allSatisfy { $0.bitPattern == $1.bitPattern })
    }

    // MARK: - The real sleeper

    @Test("The task sleeper refuses a wait that is not one", arguments: [
        TimeInterval.nan, TimeInterval.infinity, -TimeInterval.infinity, -1, -0.001, 1e11, 1e300
    ])
    func taskSleeperRefusesUnusableInterval(_ interval: TimeInterval) async throws {
        await #expect(throws: OAuthError.serverError(
            "The polling interval is not a usable number of seconds.")) {
            try await TaskSleeper().sleep(for: interval)
        }
    }

    @Test("The task sleeper waits at least as long as it was asked to")
    func taskSleeperSleeps() async throws {
        let clock = ContinuousClock()

        let waited = try await clock.measure {
            try await TaskSleeper().sleep(for: 0.02)
        }

        #expect(waited >= .milliseconds(20))
    }

    @Test("The task sleeper accepts a zero wait")
    func taskSleeperAcceptsZero() async throws {
        let clock = ContinuousClock()

        let waited = try await clock.measure {
            try await TaskSleeper().sleep(for: 0)
        }

        // Generous: the claim is that zero returns rather than throwing, not how fast.
        #expect(waited < .seconds(5))
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
