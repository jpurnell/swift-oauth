import Foundation
import SwiftOAuthCore

/// Which connection a credential belongs to.
///
/// Three parts, because all three vary independently: one application serves many tenants,
/// a tenant may connect several providers, and one provider may expose several accounts —
/// QuickBooks calls those realms, and an accountant with four client companies has four.
///
/// Multi-tenant from the start deliberately. Retrofitting tenancy means migrating stored
/// credentials, and a single-tenant shape leaks into every storage implementation written
/// against the protocol in the meantime.
public struct ConnectionID: Sendable, Hashable, Codable, CustomStringConvertible {

    /// Who, in the consuming application's terms.
    public let tenant: String

    /// Which provider — `"quickbooks"`, `"xero"`.
    public let provider: String

    /// Which account at that provider. QuickBooks' realm id; empty where a provider has no
    /// such concept.
    public let account: String

    /// Creates a connection identifier.
    public init(tenant: String, provider: String, account: String = "") {
        self.tenant = tenant
        self.provider = provider
        self.account = account
    }

    /// A stable string form, suitable as a storage key.
    public var description: String {
        account.isEmpty ? "\(tenant)/\(provider)" : "\(tenant)/\(provider)/\(account)"
    }
}

/// A credential obtained from another system, and what is needed to keep it alive.
///
/// The fields beyond the obvious two exist because of **rotation**: presenting a refresh
/// token returns a new pair and expires the one presented. Everything here that looks like
/// bookkeeping is there to survive that.
public struct StoredCredential: Sendable, Equatable, Codable {

    /// The token presented on API calls.
    public let accessToken: String

    /// The token exchanged for a new pair when the access token expires.
    public let refreshToken: String

    /// When the access token stops working.
    public let accessExpiry: Date

    /// When the refresh token stops working, if the provider said.
    ///
    /// Providers differ: Intuit sends `x_refresh_token_expires_in`, many send nothing. A
    /// `nil` here means unknown, not unlimited.
    public let refreshExpiry: Date?

    /// The refresh token this one replaced.
    ///
    /// Kept because a failed refresh is otherwise ambiguous. `invalid_grant` means either
    /// "the user revoked you" — go and ask them again — or "you lost a rotation and are
    /// presenting a token that was already replaced" — recoverable. Those need opposite
    /// responses, and without the previous token there is no way to tell them apart after
    /// the fact.
    public let previousRefreshToken: String?

    /// When this credential replaced its predecessor.
    public let rotatedAt: Date

    /// The scope actually granted, which may be less than was requested.
    public let scope: String?

    /// Creates a stored credential.
    public init(
        accessToken: String,
        refreshToken: String,
        accessExpiry: Date,
        refreshExpiry: Date? = nil,
        previousRefreshToken: String? = nil,
        rotatedAt: Date,
        scope: String? = nil
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.accessExpiry = accessExpiry
        self.refreshExpiry = refreshExpiry
        self.previousRefreshToken = previousRefreshToken
        self.rotatedAt = rotatedAt
        self.scope = scope
    }

    /// Builds a credential from a provider's response.
    ///
    /// - Parameters:
    ///   - response: What the token endpoint returned.
    ///   - received: When it arrived — expiries are durations on the wire, so only the
    ///     caller knows what they are relative to.
    ///   - replacing: The refresh token this response replaced, if any.
    /// - Returns: The credential, or `nil` if the response carried no refresh token.
    ///   A response without one cannot be kept alive, and storing it would promise a
    ///   connection that will silently stop working within the hour.
    public init?(
        from response: TokenResponse,
        received: Date,
        replacing previous: String? = nil
    ) {
        guard let refreshToken = response.refreshToken else { return nil }
        self.init(
            accessToken: response.accessToken,
            refreshToken: refreshToken,
            accessExpiry: response.expiry(from: received),
            refreshExpiry: response.refreshExpiry(from: received),
            previousRefreshToken: previous,
            rotatedAt: received,
            scope: response.scope)
    }

    /// Whether the access token has expired, allowing for a safety margin.
    ///
    /// The margin matters: a token valid for another two seconds will have expired by the
    /// time a request reaches the provider, and the resulting failure looks like a bug
    /// rather than a race.
    ///
    /// - Parameters:
    ///   - now: The current moment.
    ///   - margin: How long before true expiry to treat it as expired. Sixty seconds by
    ///     default, comfortably longer than any request.
    /// - Returns: `true` if it should be refreshed before use.
    public func needsRefresh(at now: Date, margin: TimeInterval = 60) -> Bool {
        now.addingTimeInterval(margin) >= accessExpiry
    }

    /// Whether the refresh token is known to have expired.
    ///
    /// `false` when the provider never said, which is not the same as knowing it is valid.
    public func refreshHasExpired(at now: Date) -> Bool {
        guard let refreshExpiry else { return false }
        return now >= refreshExpiry
    }
}

extension StoredCredential: CustomStringConvertible, CustomDebugStringConvertible {

    /// Redacts both tokens.
    ///
    /// This type exists to be persisted and passed around, so it is exactly the sort of
    /// value that ends up interpolated into a log line during debugging.
    public var description: String {
        """
        StoredCredential(accessToken: <redacted>, refreshToken: <redacted>, \
        accessExpiry: \(accessExpiry), rotatedAt: \(rotatedAt), scope: \(scope ?? "none"))
        """
    }

    /// The same redacted rendering.
    public var debugDescription: String { description }
}
