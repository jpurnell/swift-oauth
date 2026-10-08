import Foundation
import SwiftOAuthCore

/// A disconnect removed the local credential and could not confirm the provider revoked it.
///
/// Thrown by ``OAuthConnection/disconnect()`` **after** the stored credential is gone. The
/// connection is disconnected as far as this device is concerned: nothing is left to present,
/// and ``OAuthConnection/validAccessToken()`` now throws ``ConnectionError/notConnected``.
/// What is not known is whether the provider has forgotten the token too. Until it expires,
/// or is revoked some other way, a copy of it held anywhere else still works.
///
/// What to do depends on ``step`` and ``underlying``:
///
/// - A provider that was unreachable, or answered `503`, may be asked again — but not through
///   `disconnect()`, which no longer has the token. RFC 7009 §2.2.1: on a `503` "the client
///   must assume the token still exists and may retry after a reasonable delay." A caller that
///   needs that retry should read ``OAuthConnection/currentCredential()`` *before*
///   disconnecting and keep the refresh token until revocation is confirmed.
/// - A refusal (`invalid_client`, `unsupported_token_type`) or an ``OAuthRedirectRefused``
///   will be the same next time; the remedy is in the provider's configuration or its
///   console.
/// - Either way, tell the user the truth: disconnected here, not confirmed there.
///
/// A separate type rather than a ``ConnectionError`` case, because a case added to a public
/// enum breaks every exhaustive `switch` over it.
public struct OAuthRevocationFailed: Error, Sendable {

    /// Where the disconnect stopped being able to promise a revocation.
    public enum Step: Sendable, Equatable {
        /// The stored credential could not be read, so there was no token to send. No
        /// revocation request was made.
        case readingStoredCredential
        /// The revocation request was made and did not succeed: it could not be sent, or the
        /// provider refused it, redirected it, or answered with something other than success.
        case revocationRequest
    }

    /// Which step failed.
    public let step: Step

    /// What that step threw: the storage's own error, an `OAuthError` the provider answered
    /// with, an ``OAuthRedirectRefused``, an ``OAuthResponseTooLarge``, or the transport's.
    public let underlying: any Error

    /// Creates the error.
    ///
    /// - Parameters:
    ///   - step: Which step failed.
    ///   - underlying: What it threw.
    public init(step: Step, underlying: any Error) {
        self.step = step
        self.underlying = underlying
    }
}

extension OAuthRevocationFailed: CustomStringConvertible, LocalizedError {

    /// What happened. Names the kind of failure and never the token: the underlying error is
    /// described only when it is one of this package's own, whose text is known to hold no
    /// credential, and by its type otherwise.
    public var description: String {
        let cause: String
        switch underlying {
        case let error as OAuthError:
            cause = "the provider answered \(error.code)"
        case let error as OAuthRedirectRefused:
            cause = String(describing: error)
        case let error as OAuthResponseTooLarge:
            cause = String(describing: error)
        default:
            cause = "\(type(of: underlying))"
        }
        switch step {
        case .readingStoredCredential:
            return "The local credential was removed, but it could not be read first, so no "
                + "revocation request was made and the token may still be valid at the "
                + "provider (\(cause))."
        case .revocationRequest:
            return "The local credential was removed, but the provider did not confirm the "
                + "revocation, so the token may still be valid there (\(cause))."
        }
    }

    /// The same text, for callers that read `localizedDescription`.
    public var errorDescription: String? { description }
}
