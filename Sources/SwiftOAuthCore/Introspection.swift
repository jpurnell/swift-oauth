import Foundation

/// What an authorization server says about a token — RFC 7662.
///
/// Introspection is how a resource server answers the only question it actually has: *is this
/// bearer string still good, and what is it for?* A bearer token is opaque to whoever receives
/// it, so without this a resource server either trusts what it was handed or reaches past this
/// package to find out.
///
/// ## Inactive is an answer, not a failure
///
/// The central distinction, and the one implementations most often get wrong: an expired,
/// revoked or unknown token is `active: false` with HTTP 200 — **not** an error. RFC 7662 §2.2
/// is explicit about it. A server that answers 401 for an expired token forces every caller to
/// treat "this token is no good" as a transport failure, which is a different condition,
/// handled in a different place, usually with a retry that cannot help.
///
/// ## An inactive response says nothing else
///
/// Also §2.2: a server must not reveal the scope, the client, or the subject of a token that is
/// not active. A caller holding a dead token has proven nothing, and a response that carries
/// claims anyway is an oracle for probing tokens that are not yours.
public struct IntrospectionResult: Codable, Sendable, Equatable {

    /// Whether the token is currently active.
    ///
    /// The only field guaranteed present, and the only one an inactive response carries.
    public let active: Bool

    /// The scopes the token was granted, space-delimited as RFC 6749 §3.3 defines them.
    public let scope: String?

    /// The client the token was issued to.
    public let clientId: String?

    /// Who authorised it, when a user did.
    public let subject: String?

    /// The audiences the token is for — RFC 8707's resource indicators, seen from the other end.
    ///
    /// A resource server checks its own identifier against this. That check is what stops a
    /// token minted for somewhere else from being accepted here, and it is the reason the
    /// audience is worth binding at issue time.
    public let audience: [String]?

    /// When the token expires.
    public let expiry: Date?

    /// When it was issued.
    public let issuedAt: Date?

    /// The response for a token that is expired, revoked, or was never issued.
    ///
    /// A constant rather than a constructed value, because every inactive response is identical
    /// by requirement: any variation between them is information about tokens the caller does
    /// not hold.
    public static let inactive = IntrospectionResult(active: false)

    /// Creates an introspection response.
    ///
    /// The parameter list mirrors the fields RFC 7662 §2.2 defines, all optional but `active`.
    // legibility:reserved the parameter list mirrors the specification's response fields
    public init(
        active: Bool,
        scope: String? = nil,
        clientId: String? = nil,
        subject: String? = nil,
        audience: [String]? = nil,
        expiry: Date? = nil,
        issuedAt: Date? = nil
    ) {
        self.active = active
        self.scope = scope
        self.clientId = clientId
        self.subject = subject
        self.audience = audience
        self.expiry = expiry
        self.issuedAt = issuedAt
    }

    private enum CodingKeys: String, CodingKey {
        case active, scope, aud, exp, iat, sub
        case clientId = "client_id"
    }

    /// Decodes a response, tolerating the two shapes `aud` is allowed to take.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        active = try container.decode(Bool.self, forKey: .active)
        scope = try container.decodeIfPresent(String.self, forKey: .scope)
        clientId = try container.decodeIfPresent(String.self, forKey: .clientId)
        subject = try container.decodeIfPresent(String.self, forKey: .sub)

        // RFC 7519 §4.1.3, which RFC 7662 inherits: `aud` is a string or an array of strings.
        // A decoder handling only one shape fails against half the providers in existence, and
        // fails at the point a token is being checked rather than at configuration time.
        // Typed explicitly: `.map` on a bare `String?` resolves to `Sequence.map` and yields
        // an array of characters, which compiles nowhere useful and reads as a decoder bug.
        let singleAudience: String? = try? container.decodeIfPresent(String.self, forKey: .aud)
        if let singleAudience {
            audience = [singleAudience]
        } else {
            audience = try container.decodeIfPresent([String].self, forKey: .aud)
        }

        expiry = try container.decodeIfPresent(TimeInterval.self, forKey: .exp)
            .map { Date(timeIntervalSince1970: $0) }
        issuedAt = try container.decodeIfPresent(TimeInterval.self, forKey: .iat)
            .map { Date(timeIntervalSince1970: $0) }
    }

    /// Encodes a response, omitting every field it does not carry.
    ///
    /// An inactive response therefore encodes to `{"active":false}` exactly, which is what
    /// §2.2 requires rather than merely permits.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(active, forKey: .active)
        try container.encodeIfPresent(scope, forKey: .scope)
        try container.encodeIfPresent(clientId, forKey: .clientId)
        try container.encodeIfPresent(subject, forKey: .sub)
        // Encoded as an array only when there is more than one, matching how servers write it.
        if let audience {
            if audience.count == 1 {
                try container.encode(audience[0], forKey: .aud)
            } else {
                try container.encode(audience, forKey: .aud)
            }
        }
        try container.encodeIfPresent(expiry?.timeIntervalSince1970, forKey: .exp)
        try container.encodeIfPresent(issuedAt?.timeIntervalSince1970, forKey: .iat)
    }
}
