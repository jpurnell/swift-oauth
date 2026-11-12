#if canImport(os)
import os
#else
import Synchronization
#endif

/// A value that can be read and changed from any thread, one at a time.
///
/// The state lives inside a lock the type system knows is a lock — `OSAllocatedUnfairLock`
/// on Apple platforms, `Mutex` elsewhere — and the only way to reach it is ``withLock(_:)``.
/// The class holds nothing but that lock, so its `Sendable` conformance is checked by the
/// compiler rather than asserted.
///
/// `package` access, not `public`: the package's own targets and tests share it, and a caller
/// of the library has no use for it.
package final class Guarded<State: Sendable>: Sendable {

    #if canImport(os)
    private let storage: OSAllocatedUnfairLock<State>
    #else
    private let storage: Mutex<State>
    #endif

    /// Creates a guarded value.
    ///
    /// - Parameter initial: The state before anyone has changed it.
    package init(_ initial: State) {
        #if canImport(os)
        storage = OSAllocatedUnfairLock(initialState: initial)
        #else
        storage = Mutex(initial)
        #endif
    }

    /// Runs `body` with exclusive access to the state.
    ///
    /// - Parameter body: Runs while the lock is held. Keep it short, and do not wait inside it.
    /// - Returns: Whatever `body` returns.
    package func withLock<Result: Sendable>(_ body: @Sendable (inout State) -> Result) -> Result {
        storage.withLock { state in
            body(&state)
        }
    }
}
