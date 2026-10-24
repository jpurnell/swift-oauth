import Foundation
#if canImport(os)
import os
#endif
import SwiftIdentity
import SwiftOAuthClient
import SwiftOAuthCore

/// Which audience a token must carry to be accepted here — RFC 8707, seen from the resource.
public enum AudienceRequirement: Sendable, Equatable {

    /// The token's `aud` must include this identifier: this resource server's own.
    ///
    /// A token with no audience at all is refused too. An authorization server that binds no
    /// audience issues tokens every resource it protects will accept, so a token obtained for
    /// one service can be replayed against another; refusing the unbound token is what makes
    /// that replay fail here.
    case mustInclude(String)

    /// Any audience, or none, is accepted.
    ///
    /// For an authorization server that binds no audience and protects nothing but this. Named
    /// rather than defaulted, so a deployment that does not check says so where it is built.
    case notChecked
}

/// Why an access token was refused before its subject was looked up — for the operator.
///
/// Every one of these reaches the caller as the same refusal, and the service's audit as
/// `IdentityEvent.Outcome.unknown` (or `.expired`). Neither says *which* check
/// failed: an attacker probing with tokens learns nothing from the difference. The operator does
/// need the difference — an unreachable authorization server and a token minted for another
/// service call for different responses — so it is handed to
/// ``OAuthIdentityStore/RefusalObserver`` and nowhere else.
public enum OAuthIdentityRefusal: Sendable, Equatable {
    /// The introspection request failed or its answer could not be read. The token may be
    /// perfectly good; nothing could be learned about it.
    case introspectionFailed
    /// The authorization server says the token is not active: expired, revoked, or never
    /// issued. RFC 7662 §2.2 does not say which, and neither can this.
    case inactive
    /// The server says the token is active and its `exp` has passed — a server clock behind
    /// this one, or a cache. Refused on this side's clock.
    case expired
    /// The answer named no subject, so there is nobody to map. A `client_credentials` token is
    /// the usual cause: it was issued to a client, not a person.
    case noSubject
    /// The answer's `iss` named an issuer other than the one this store trusts.
    case issuerMismatch
    /// The token was not issued for this resource, under the store's ``AudienceRequirement``.
    case audienceMismatch
}

/// Resolves an OAuth access token to a SwiftIdentity subject, by asking the authorization server.
///
/// The bridge SwiftIdentity's design anticipated (`SubjectsAndCredentials`, §4b): an identity
/// provider's store "answers it by introspecting a token instead of comparing a hash". The token
/// is introspected (RFC 7662); an active answer's `sub` becomes an
/// `ExternalAssertion` of (issuer, `sub`); and that assertion is resolved by `mapping` — the
/// deployment's own store, holding which provider subject is which local `Subject.id`. The local
/// id is what durable records carry, so adopting a provider is a roster change rather than a
/// migration.
///
/// ## The order of the checks
///
/// 1. **The kind.** Anything but an ``OAuthAccessToken`` is refused as unknown, without asking
///    anyone, so an `Authenticator` moves on to the store that does know it.
/// 2. **Introspection.** A request that fails is a refusal. It fails closed: a resource server
///    that admits whoever presents a token while the authorization server is down has no
///    authorization server.
/// 3. **Active.** RFC 7662 §2.2's inactive answer is a refusal.
/// 4. **Issuer.** When the answer carries `iss`, it must be the issuer this store was given.
///    When it does not, the answer is taken as the configured issuer's — it came from that
///    issuer's endpoint, and §2.2 makes the field optional.
/// 5. **Audience**, under the store's ``AudienceRequirement``.
/// 6. **Expiry**, on this side's clock, when the answer carries `exp`.
/// 7. **Subject.** An answer naming nobody maps to nobody.
/// 8. **The mapping.** Asked with the *configured* issuer and the introspected `sub`, never
///    with anything taken from the token, and its answer — verified, revoked, honeypot,
///    whatever it is — is returned unaltered. Revocation and tripwires are therefore the
///    mapping's to hold, and a honeypot reached through a token still reports as one.
///
/// ## Who is told what
///
/// The caller learns nothing: SwiftIdentity's `subject(for:)` returns `nil` for every refusal
/// alike. The service's `audit` is told the outcome of every resolution of an access token, with
/// the subject when there is one. The operator's ``RefusalObserver`` is told which of steps 2–7
/// refused. The token itself goes to the introspection endpoint and nowhere else.
///
/// The mapping audits its own lookup, if it was given an audit. A deployment that hands the same
/// audit to both sees two events for one sign-in — the token's, and the external identity's —
/// which is two layers each saying what they did, not one event counted twice.
///
/// ## The mapping is consulted only with assertions this store built
///
/// An `ExternalAssertion` presented directly to the mapping, by some other code path, is the
/// mapping's business: this store refuses one presented to it (step 1), and has no say over what
/// another store does with one.
public struct OAuthIdentityStore: CredentialStore {

    /// Handed the reason a token was refused before the mapping was asked.
    ///
    /// Synchronous and called on the resolving task: wire it to something that does not block.
    /// The reason is a case name and nothing else — no token, no claim.
    public typealias RefusalObserver = @Sendable (OAuthIdentityRefusal) -> Void

    #if canImport(os)
    private static let logger = Logger(
        subsystem: "com.swiftoauth.identity", category: "OAuthIdentityStore")
    #endif

    private let introspector: TokenIntrospector
    private let issuer: String
    private let audience: AudienceRequirement
    private let mapping: any CredentialStore
    private let audit: (any IdentityAudit)?
    private let now: @Sendable () -> Date
    private let onRefusal: RefusalObserver?

    /// Creates a store over one authorization server.
    ///
    /// - Parameters:
    ///   - introspector: How to ask the authorization server about a token. Its endpoint is the
    ///     issuer's introspection endpoint, and its credentials this resource server's.
    ///   - issuer: The issuer that introspector speaks for, exactly as the mapping records it —
    ///     `https://server.example.com/`, trailing slash and all, if that is how the roster
    ///     writes it. It is the issuer half of every external identity this store looks up.
    ///   - audience: What a token's audience must include. No default: whether to check is the
    ///     deployment's security decision.
    ///   - mapping: The store that resolves an `ExternalAssertion` to a local subject — a
    ///     `FileCredentialStore` whose verifiers hold the provider subjects, for instance.
    ///   - audit: Told the outcome of every resolution of an access token.
    ///   - now: The clock, injected so expiry is testable without waiting.
    ///   - onRefusal: Told why a token was refused before the mapping was asked.
    public init(
        introspector: TokenIntrospector,
        issuer: String,
        audience: AudienceRequirement,
        mapping: any CredentialStore,
        audit: (any IdentityAudit)? = nil,
        now: @escaping @Sendable () -> Date = { Date() },
        onRefusal: RefusalObserver? = nil
    ) {
        self.introspector = introspector
        self.issuer = issuer
        self.audience = audience
        self.mapping = mapping
        self.audit = audit
        self.now = now
        self.onRefusal = onRefusal
    }

    /// Resolves an access token, reporting the reason to the service and nothing to the caller.
    ///
    /// - Parameter credential: The proof presented. Anything but an ``OAuthAccessToken`` is
    ///   refused as unknown, unaudited and without a request.
    /// - Returns: The mapping's answer for the token's subject, or the reason it never got
    ///   that far.
    public func resolve(_ credential: any Credential) async -> Resolution {
        guard let token = credential as? OAuthAccessToken else { return .refused(.unknown) }

        let at = now()
        let resolution = await resolve(token, at: at)
        let subjectID: String?
        let outcome: IdentityEvent.Outcome
        switch resolution {
        case .verified(let subject):
            subjectID = subject.id
            outcome = .verified
        case .refused(let reason):
            subjectID = nil
            outcome = reason
        }
        await audit?.record(IdentityEvent(
            outcome: outcome, subjectID: subjectID, credentialKind: OAuthAccessToken.kind, at: at))
        return resolution
    }

    /// Steps 2 to 8 of the type's discussion.
    private func resolve(_ token: OAuthAccessToken, at time: Date) async -> Resolution {
        let answer: IntrospectionResult
        do {
            answer = try await introspector.introspect(token: token.value)
        } catch {
            // Logged, because the observer is optional and an authorization server that cannot
            // be reached should leave a trace in a deployment that supplied none. By type only,
            // publicly: the token went out in the request and nothing of the request is written
            // here. The description is kept private, so it is readable on the machine and
            // redacted from anything collected off it.
            #if canImport(os)
            Self.logger.warning(
                "access token refused: introspection failed (\(String(describing: type(of: error)), privacy: .public)): \(String(describing: error), privacy: .private)")
            #endif
            return refused(.introspectionFailed)
        }

        guard answer.active else { return refused(.inactive) }
        if let asserted = answer.issuer, asserted != issuer {
            return refused(.issuerMismatch)
        }
        if case .mustInclude(let resource) = audience {
            guard answer.audience?.contains(resource) == true else {
                return refused(.audienceMismatch)
            }
        }
        if let expiry = answer.expiry, expiry <= time {
            return refused(.expired, as: .expired)
        }
        guard let subject = answer.subject, !subject.isEmpty else {
            return refused(.noSubject)
        }

        return await mapping.resolve(
            ExternalAssertion(ExternalIdentity(issuer: issuer, subject: subject)))
    }

    /// Tells the operator why, and the service only that it was refused.
    private func refused(
        _ reason: OAuthIdentityRefusal, as outcome: IdentityEvent.Outcome = .unknown
    ) -> Resolution {
        onRefusal?(reason)
        return .refused(outcome)
    }
}
