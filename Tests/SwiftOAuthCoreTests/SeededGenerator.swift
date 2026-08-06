import Foundation

/// A deterministic random number generator, for tests.
///
/// The generation APIs take an `inout some RandomNumberGenerator` precisely so a
/// test can supply this. Using the system generator would make a failure
/// unreproducible: a collision or a malformed verifier that appears once in
/// tens of thousands of draws would show up in CI and never again locally.
///
/// SplitMix64 — small, well-distributed, and specified, so the sequence is the
/// same on every platform.
struct SeededGenerator: RandomNumberGenerator {

    private var state: UInt64

    /// Creates a generator from a seed.
    init(seed: UInt64) {
        self.state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
