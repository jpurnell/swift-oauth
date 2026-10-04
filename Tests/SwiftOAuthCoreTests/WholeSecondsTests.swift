import Foundation
import Testing
@testable import SwiftOAuthCore

/// Turning a `TimeInterval` into an integer without stopping the process.
///
/// `Int(.nan)`, `Int(.infinity)` and `Int(1e300)` are not errors in Swift, they are traps: the
/// process ends. A lifetime arrives as a `Double` from an operator's configuration or from
/// another server's JSON, and both can hold any of those. The conversion is one line and every
/// site that wrote it out by hand got it wrong the same way, so it lives here once.
@Suite("Whole seconds — a checked conversion from TimeInterval")
struct WholeSecondsTests {

    /// A representable interval and the whole seconds it holds.
    struct Representable: Sendable, CustomTestStringConvertible {
        let interval: TimeInterval
        let seconds: Int
        var testDescription: String { "\(interval) -> \(seconds)" }
    }

    @Test("A representable interval converts, truncating toward zero", arguments: [
        Representable(interval: 0, seconds: 0),
        Representable(interval: -0.0, seconds: 0),
        Representable(interval: 1, seconds: 1),
        Representable(interval: 86400, seconds: 86400),
        Representable(interval: 7_776_000, seconds: 7_776_000),
        // Truncation, not rounding: a 59.9-second lifetime has not lasted a minute.
        Representable(interval: 59.9, seconds: 59),
        Representable(interval: 0.5, seconds: 0),
        Representable(interval: -0.5, seconds: 0),
        Representable(interval: -1, seconds: -1),
        Representable(interval: -59.9, seconds: -59),
        Representable(interval: 1e15, seconds: 1_000_000_000_000_000),
        // The largest Double below 2^63, which is exactly representable as an Int.
        Representable(interval: 9_223_372_036_854_774_784, seconds: 9_223_372_036_854_774_784),
        // -2^63 is Int.min exactly.
        Representable(interval: -9_223_372_036_854_775_808, seconds: Int.min)
    ])
    func representableIntervalsConvert(_ row: Representable) {
        #expect(WholeSeconds.count(in: row.interval) == row.seconds)
    }

    @Test("An interval with no integer value has no whole seconds", arguments: [
        TimeInterval.nan,
        TimeInterval.signalingNaN,
        TimeInterval.infinity,
        -TimeInterval.infinity,
        1e300,
        -1e300,
        TimeInterval.greatestFiniteMagnitude,
        // 2^63 exactly: one past Int.max, and the value `Int(Double(Int.max))` traps on.
        9_223_372_036_854_775_808,
        // The first Double below -2^63.
        -9_223_372_036_854_777_856
    ])
    func unrepresentableIntervalsAreNil(_ interval: TimeInterval) {
        #expect(WholeSeconds.count(in: interval) == nil)
    }

    /// A representable interval and the nanoseconds it holds.
    struct Nanoseconds: Sendable, CustomTestStringConvertible {
        let interval: TimeInterval
        let nanoseconds: UInt64
        var testDescription: String { "\(interval)s -> \(nanoseconds)ns" }
    }

    @Test("A non-negative interval converts to nanoseconds", arguments: [
        Nanoseconds(interval: 0, nanoseconds: 0),
        Nanoseconds(interval: -0.0, nanoseconds: 0),
        Nanoseconds(interval: 1, nanoseconds: 1_000_000_000),
        Nanoseconds(interval: 5, nanoseconds: 5_000_000_000),
        Nanoseconds(interval: 0.25, nanoseconds: 250_000_000),
        Nanoseconds(interval: 1800, nanoseconds: 1_800_000_000_000),
        // Below one nanosecond there is nothing to wait for.
        Nanoseconds(interval: 1e-12, nanoseconds: 0)
    ])
    func nonNegativeIntervalsConvertToNanoseconds(_ row: Nanoseconds) {
        #expect(WholeSeconds.nanoseconds(in: row.interval) == row.nanoseconds)
    }

    @Test("An interval that is not a wait has no nanoseconds", arguments: [
        TimeInterval.nan,
        TimeInterval.infinity,
        -TimeInterval.infinity,
        // Negative: a wait cannot be owed backwards.
        -1,
        -0.001,
        // Finite, and its nanosecond count overflows UInt64 (about 584 years).
        1e11,
        1e300,
        TimeInterval.greatestFiniteMagnitude
    ])
    func unusableIntervalsHaveNoNanoseconds(_ interval: TimeInterval) {
        #expect(WholeSeconds.nanoseconds(in: interval) == nil)
    }
}
