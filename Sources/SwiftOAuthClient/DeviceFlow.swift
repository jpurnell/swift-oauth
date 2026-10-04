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
    ///
    /// - Parameter interval: Seconds to wait. Zero returns at once.
    /// - Throws: `OAuthError.serverError(_:)` when `interval` is NaN, infinite, negative, or
    ///   too long to express in nanoseconds. The interval a device flow waits is the one the
    ///   authorization server stated, so a value that is not a wait is that server's fault,
    ///   and is reported rather than converted — the conversion is a trap, not an error.
    ///   Also throws `CancellationError` if the task is cancelled while waiting.
    public func sleep(for interval: TimeInterval) async throws {
        guard let nanoseconds = WholeSeconds.nanoseconds(in: interval) else {
            throw OAuthError.serverError("The polling interval is not a usable number of seconds.")
        }
        try await Task.sleep(nanoseconds: nanoseconds)
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
    /// - Throws: `OAuthError.accessDenied(_:)` if the user refused,
    ///   `OAuthError.expiredToken(_:)` if the code died or the local bound was reached,
    ///   `OAuthError.serverError(_:)` if `interval` or `expiresIn` is not a positive, finite
    ///   number of seconds — in which case `redeem` is never called — or whatever `redeem`
    ///   threw for a failure that is not a polling state.
    public static func poll(
        interval: TimeInterval,
        expiresIn: TimeInterval,
        sleeper: any DeviceFlowSleeper,
        elapsed: @Sendable () async -> TimeInterval,
        redeem: @Sendable () async throws -> TokenResponse
    ) async throws -> TokenResponse {
        // Both values are another server's JSON, and are checked before anything is done
        // with them. Unchecked, a NaN or an out-of-range value reaches an integer conversion
        // below, which does not fail but stops the process.
        try requireUsable(interval, field: "interval")
        try requireUsable(expiresIn, field: "expires_in")

        var schedule = DevicePollSchedule(interval: interval)

        // The most polls that can fit in the code's lifetime, plus one. `while true` with
        // exits scattered through the body is a loop whose termination has to be argued;
        // this is one whose bound can be read. The `elapsed` check below still ends it early
        // when real time has passed — this is the backstop, not the mechanism.
        //
        // A sub-second interval is counted as one second here, so the bound never exceeds the
        // lifetime in seconds. That makes the quotient no larger than `expiresIn`, which was
        // just shown to be representable; the conversion and the addition are checked anyway,
        // because "cannot happen" is an argument and a trap is not an error.
        let (maximumPolls, overflowed) = try wholeSeconds(
            expiresIn / max(interval, 1), field: "expires_in"
        ).addingReportingOverflow(1)
        guard !overflowed else { throw malformed("expires_in") }

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

    // MARK: - What the authorization server stated

    /// Refuses a value from the device authorization response that is not a positive number
    /// of seconds.
    ///
    /// Zero is refused along with the rest. RFC 8628 §3.2 makes `expires_in` REQUIRED and
    /// defines it as a lifetime, and a zero `interval` asks a client to poll without waiting —
    /// the specification's own default when the field is absent is five seconds, and the
    /// decoder applies that default, so a zero here was stated rather than omitted.
    private static func requireUsable(_ value: TimeInterval, field: String) throws {
        // NaN fails this comparison, as every comparison with NaN does.
        guard value > 0 else { throw malformed(field) }
        // Infinity and anything past `Int.max` pass it, and are refused here.
        _ = try wholeSeconds(value, field: field)
    }

    /// The whole seconds in a value the authorization server stated.
    private static func wholeSeconds(_ value: TimeInterval, field: String) throws -> Int {
        guard let seconds = WholeSeconds.count(in: value) else { throw malformed(field) }
        return seconds
    }

    /// The error for a device authorization response this client cannot act on.
    ///
    /// `server_error`, not `invalid_request`. RFC 6749 §5.2 defines `invalid_request` as a
    /// fault in what the *client* sent, and a caller reading it would go looking for one; the
    /// request here was fine and the server's answer was not. `server_error` is the code for
    /// a server that "encountered an unexpected condition", it is what
    /// `OAuthError.init(code:description:)` already uses for a response this package cannot
    /// interpret, and it is transient — which is right, since asking again is the one thing
    /// that might yield a sane response.
    private static func malformed(_ field: String) -> OAuthError {
        .serverError(
            "The authorization server's device authorization response has an \(field) that "
            + "is not a usable number of seconds.")
    }
}
