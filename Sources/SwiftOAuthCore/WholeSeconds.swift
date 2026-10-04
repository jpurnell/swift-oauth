import Foundation

/// Checked conversions from a `TimeInterval` to an integer.
///
/// `Int(.nan)`, `Int(.infinity)` and `Int(1e300)` are not errors: they stop the process. A
/// lifetime reaches this package as a `Double` from two places nothing here controls — an
/// operator's configuration, and another server's JSON — and either can hold any of those.
/// The conversion is one line, and every site that wrote it out by hand wrote the trapping
/// form, so it is written once here and the sites ask.
///
/// Both functions answer `nil` rather than substituting a value. What to do about an interval
/// that is not a number depends on whose it was: a provider refuses to issue, a client reports
/// the server's response as malformed. A default chosen here would make that decision for both
/// and hide that it had been made.
public enum WholeSeconds {

    /// The whole seconds in an interval, truncated toward zero.
    ///
    /// Truncated rather than rounded, because the result is reported as `expires_in`: a client
    /// told a 59.9-second token lasts 60 will present it once after it has expired.
    ///
    /// A negative interval converts to a negative count. Whether a negative lifetime is
    /// acceptable is the caller's question; this answers only whether the value is an integer.
    ///
    /// - Parameter interval: Seconds, as a floating-point value.
    /// - Returns: The count, or `nil` when `interval` is NaN, infinite, or outside what `Int`
    ///   can hold.
    public static func count(in interval: TimeInterval) -> Int? {
        guard interval.isFinite else { return nil }
        return Int(exactly: interval.rounded(.towardZero))
    }

    /// The whole nanoseconds in a non-negative interval, for a wait.
    ///
    /// - Parameter interval: Seconds to wait.
    /// - Returns: The count, or `nil` when `interval` is NaN, infinite, negative, or longer
    ///   than `UInt64` nanoseconds can express — a little over 584 years.
    public static func nanoseconds(in interval: TimeInterval) -> UInt64? {
        guard interval.isFinite, interval >= 0 else { return nil }
        // The product of two finite values can itself be infinite; `exactly:` answers nil for
        // that, as it does for any other value out of range.
        let nanoseconds = (interval * nanosecondsPerSecond).rounded(.towardZero)
        return UInt64(exactly: nanoseconds)
    }

    /// Nanoseconds in a second.
    private static let nanosecondsPerSecond: TimeInterval = 1_000_000_000
}
