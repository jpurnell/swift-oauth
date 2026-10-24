import SwiftIdentity

/// An OAuth access token, presented as a SwiftIdentity credential.
///
/// ## Why this is a kind of its own
///
/// SwiftIdentity made `Credential` a protocol so a kind it had never heard of could be declared
/// elsewhere; this is that kind for SwiftOAuth, as `PasskeyAssertion` is for SwiftWebAuthn. It is
/// not a `BearerKey`, though both travel in an `Authorization: Bearer` header. A bearer key is a
/// secret this deployment minted and holds a digest of; an access token is one an authorization
/// server minted and only that server can vouch for. Giving them one kind would let a store
/// answer for a value it never issued, and the conformance suite's kinds-do-not-cross
/// requirement is the check that they stay apart.
///
/// ## It is a bearer credential
///
/// Whoever holds it is, to a resource server, whoever it was issued to. Its `description` and
/// `debugDescription` therefore never contain the value, so interpolating one into a log line
/// does not put the token there.
public struct OAuthAccessToken: Credential, Equatable {

    /// This kind's stable name, as it appears in audit records.
    public static let kind = "oauth-access-token"

    /// The token as presented.
    public let value: String

    /// Wraps a presented access token.
    ///
    /// - Parameter value: The token, exactly as it arrived — without the `Bearer ` prefix.
    public init(_ value: String) {
        self.value = value
    }
}

extension OAuthAccessToken: CustomStringConvertible, CustomDebugStringConvertible {

    /// Names the kind and never the value.
    public var description: String { "OAuthAccessToken(<redacted>)" }

    /// The same redacted rendering, so `String(reflecting:)` cannot expose what
    /// ``description`` hides.
    public var debugDescription: String { description }
}
