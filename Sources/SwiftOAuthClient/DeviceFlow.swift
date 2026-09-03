import Foundation
import SwiftOAuthCore

/// How the polling loop waits.
///
/// Injected rather than calling `Task.sleep` directly, because the loop's arithmetic is the
/// thing worth testing and a test that genuinely waited five seconds a poll would take minutes
/// to assert something that is pure arithmetic. The production implementation sleeps; a test
/// records what it was asked for.
public protocol DeviceFlowSleeper: Sendable {
    /// Waits for the given number of seconds.
    func sleep(for interval: TimeInterval) async throws
}

/// Sleeps for real.
public struct TaskSleeper: DeviceFlowSleeper {
    /// Creates a sleeper.
    public init() {}

    /// Waits, using the cooperative task clock.
    public func sleep(for interval: TimeInterval) async throws {
        try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
    }
}

/// The device grant's polling loop — RFC 8628 §3.5.
///
/// A device code that nobody polls is a string. The loop is the feature, and every mistake in
/// this grant lives in it: stopping on the wrong states, ignoring the interval the server
/// asked for, or waiting forever on a user who walked away.
public enum DeviceFlow {

    /// Polls until the user answers, the code dies, or the caller's own bound is reached.
    ///
    /// - Parameters:
    ///   - interval: Seconds between polls, as the server stated them.
    ///   - expiresIn: How long the device code is good for. The loop stops on its own once
    ///     this has passed — a server is not obliged to answer `expired_token`, and may simply
    ///     have forgotten the code, so without a local bound a device left on a shelf polls
    ///     indefinitely.
    ///   - sleeper: How to wait.
    ///   - elapsed: How long the flow has been running.
    ///   - redeem: One attempt at the token endpoint.
    /// - Returns: The tokens, once the user approves.
    /// - Throws: ``OAuthError/accessDenied(_:)`` if the user refused,
    ///   ``OAuthError/expiredToken(_:)`` if the code died or the local bound was reached, or
    ///   whatever `redeem` threw for a failure that is not a polling state.
    public static func poll(
        interval: TimeInterval,
        expiresIn: TimeInterval,
        sleeper: any DeviceFlowSleeper,
        elapsed: @Sendable () async -> TimeInterval,
        redeem: @Sendable () async throws -> TokenResponse
    ) async throws -> TokenResponse {
        var schedule = DevicePollSchedule(interval: interval)

        // The most polls that can fit in the code's lifetime, plus one. `while true` with
        // exits scattered through the body is a loop whose termination has to be argued;
        // this is one whose bound can be read. The `elapsed` check below still ends it early
        // when real time has passed — this is the backstop, not the mechanism.
        let maximumPolls = max(1, Int(expiresIn / max(interval, 1)) + 1)

        for _ in 0..<maximumPolls {
            do {
                return try await redeem()
            } catch let error as OAuthError {
                // Anything that is not one of the flow's own states is a real failure and is
                // raised. Treating an unrecognised error as "keep waiting" turns a
                // misconfigured client into one that polls forever.
                guard let outcome = DevicePollOutcome(error: error) else { throw error }

                schedule.apply(outcome)
                guard schedule.shouldContinue else { throw error }
            }

            guard await elapsed() < expiresIn else {
                throw OAuthError.expiredToken(
                    "The device code's lifetime elapsed before the user finished.")
            }
            try await sleeper.sleep(for: schedule.interval)
        }

        throw OAuthError.expiredToken(
            "The device code's lifetime elapsed before the user finished.")
    }
}
