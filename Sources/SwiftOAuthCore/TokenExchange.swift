import Foundation

/// What kind of token is being handed over or asked for — RFC 8693 §3.
///
/// A request names both, because "exchange this for that" is meaningless without them: the
/// server has to know how to validate what it was given, and the client has to know what it may
/// do with what it gets back.
public enum TokenType: String, Codable, Sendable, Equatable, CaseIterable {
    /// An OAuth access token.
    case accessToken = "urn:ietf:params:oauth:token-type:access_token"
    /// An OAuth refresh token.
    case refreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
    /// An OpenID Connect ID token.
    ///
    /// Recognised so a request naming one can be *refused* intelligibly. This package does not
    /// issue or validate ID tokens — that is OIDC, which is out of scope by decision, because
    /// an access token is not an authentication statement and treating one as proof of identity
    /// is the misuse OIDC exists to prevent.
    case idToken = "urn:ietf:params:oauth:token-type:id_token"
    /// A JWT that is not one of the above.
    case jwt = "urn:ietf:params:oauth:token-type:jwt"
}

/// A request to exchange one token for another — RFC 8693 §2.1.
///
/// ## Impersonation and delegation
///
/// The distinction this type makes explicit, and the one the specification exists to prevent
/// being conflated:
///
/// - **Impersonation** — no actor token. The issued token is indistinguishable from one the
///   subject obtained themselves. An audit log can say whose token was used and nothing about
///   who used it.
/// - **Delegation** — an actor token is supplied. The issued token records that this actor is
///   acting on the subject's behalf, so the log can answer *who did this*.
///
/// A caller that wants delegation and omits the actor token gets impersonation silently, which
/// is why ``isDelegation`` is a property rather than something to infer at a call site.
public struct TokenExchangeRequest: Sendable, Equatable {

    /// The token being exchanged.
    public let subjectToken: String
    /// What kind of token that is.
    public let subjectTokenType: TokenType
    /// The token identifying the party acting on the subject's behalf, if any.
    public let actorToken: String?
    /// What kind of token that is. Meaningful only alongside ``actorToken``.
    public let actorTokenType: TokenType?
    /// The kind of token requested back. Absent means the server chooses.
    public let requestedTokenType: TokenType?
    /// The scope being asked for. A server must not grant more than the subject token carries.
    public let scope: String?
    /// The resource the issued token is for — RFC 8707.
    public let resource: URL?
    /// The intended audience of the issued token.
    public let audience: String?

    /// Whether this is a delegation rather than an impersonation.
    ///
    /// True exactly when an actor token is present. A type without a token does not count:
    /// there is no actor, so nothing can be recorded as acting.
    public var isDelegation: Bool { actorToken != nil }

    /// Creates an exchange request.
    ///
    /// The parameter list mirrors §2.1's request parameters.
    // legibility:reserved the parameter list mirrors the specification's request parameters
    public init(
        subjectToken: String,
        subjectTokenType: TokenType,
        actorToken: String? = nil,
        actorTokenType: TokenType? = nil,
        requestedTokenType: TokenType? = nil,
        scope: String? = nil,
        resource: URL? = nil,
        audience: String? = nil
    ) {
        self.subjectToken = subjectToken
        self.subjectTokenType = subjectTokenType
        self.actorToken = actorToken
        self.actorTokenType = actorTokenType
        self.requestedTokenType = requestedTokenType
        self.scope = scope
        self.resource = resource
        self.audience = audience
    }

    /// The form parameters this request sends.
    ///
    /// `actor_token_type` is omitted when there is no actor token, even if one was supplied.
    /// §2.1 requires the type *when* the token is present and gives it no meaning otherwise, so
    /// sending it alone produces a request the server must reject — and the rejection reads as
    /// a malformed request rather than as the mistake it is.
    public var formParameters: [String: String] {
        var parameters: [String: String] = [
            "grant_type": GrantType.tokenExchange.rawValue,
            "subject_token": subjectToken,
            "subject_token_type": subjectTokenType.rawValue
        ]
        if let actorToken {
            parameters["actor_token"] = actorToken
            if let actorTokenType {
                parameters["actor_token_type"] = actorTokenType.rawValue
            }
        }
        parameters["requested_token_type"] = requestedTokenType?.rawValue
        parameters["scope"] = scope
        parameters["resource"] = resource?.absoluteString
        parameters["audience"] = audience
        return parameters.compactMapValues { $0 }
    }
}

/// What an authorization server returns from an exchange — RFC 8693 §2.2.1.
public struct TokenExchangeResponse: Codable, Sendable, Equatable {

    /// The issued token.
    public let accessToken: String

    /// What kind of token it is.
    ///
    /// Required by §2.2.1, and required here: a client holding a token that does not know its
    /// kind cannot know how it may be presented. Decoding this as optional would let that
    /// omission through to a caller who then guesses.
    public let issuedTokenType: TokenType

    /// How it is presented — `Bearer`, or `N_A` when the issued type is not a bearer token.
    public let tokenType: String

    /// Its lifetime in seconds, when the server states one.
    public let expiresIn: Int?

    /// The scope granted, which may be narrower than the scope requested.
    public let scope: String?

    /// A refresh token, when one is issued.
    public let refreshToken: String?

    private enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case issuedTokenType = "issued_token_type"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case scope
        case refreshToken = "refresh_token"
    }

    /// Creates a response.
    public init(
        accessToken: String,
        issuedTokenType: TokenType,
        tokenType: String = "Bearer",
        expiresIn: Int? = nil,
        scope: String? = nil,
        refreshToken: String? = nil
    ) {
        self.accessToken = accessToken
        self.issuedTokenType = issuedTokenType
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.scope = scope
        self.refreshToken = refreshToken
    }
}
