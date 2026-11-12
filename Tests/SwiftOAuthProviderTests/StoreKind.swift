import Testing
import Foundation
import SwiftOAuthProvider

/// The two provider stores this package ships, for a suite that must hold against both.
///
/// A server-level suite parameterised over this proves `OAuthServer` depends on the
/// ``OAuthProviderStorage`` contract and not on SQLite.
enum StoreKind: String, CaseIterable, Sendable, CustomTestStringConvertible {
    case sqlite = "SQLite"
    case inMemory = "in-memory"

    var testDescription: String { rawValue }

    /// A fresh, empty store of this kind.
    func makeStore() throws -> any OAuthProviderStorage {
        switch self {
        case .sqlite: return try OAuthStorage(path: ":memory:")
        case .inMemory: return InMemoryOAuthStorage()
        }
    }
}
