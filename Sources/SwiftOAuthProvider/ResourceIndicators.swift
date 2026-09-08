import Foundation
import SwiftOAuthCore

/// Which resources this server issues tokens for, and what to do about a request naming one.
///
/// RFC 8707 exists because a bearer token is accepted by whoever receives it. Without an
/// audience, a token minted for one API is a token that works at every API trusting the same
/// authorization server — so a compromised or merely careless resource server can replay what
/// it was handed somewhere it was never meant to reach.
///
/// The client half of this package has sent `resource` since 0.7.0. This is the half that
/// reads it. Until now a server built here accepted the parameter and ignored it, which is the
/// worst of the three possible states: a client and a server from the same package could talk
/// to each other, one naming an audience and the other discarding it, and nothing anywhere
/// would say so.
///
/// ## Strict by default
///
/// A request naming no resource asks for a token good everywhere, and ``init(known:allowsUnspecified:)``
/// refuses it unless told otherwise. The permissive setting is correct for a server whose
/// tokens are already single-audience — but it is the dangerous one to get by accident, so it
/// is the one you have to ask for.
///
/// ## Turning it on for an existing deployment
///
/// "Strict" reads as one decision and is enforced at **three** places, because RFC 8707 §2.2
/// puts the resource on each of them. A client must send it on:
///
/// 1. the authorization request,
/// 2. the token request that exchanges the code, and
/// 3. **every refresh**.
///
/// The third is the one that costs a day. Migrate the first two and the flow works end to end:
/// authorization succeeds, the exchange succeeds, a happy-path suite goes green, and the
/// migration reads as finished. The refresh fails later — correctly, with `invalid_target`, in
/// whatever runs long enough to reach one. A correct error arriving after you believed you were
/// done is worse than an incorrect one arriving immediately, because the first thing it
/// contradicts is a conclusion you have already acted on.
///
/// So flip it against a test that refreshes, not one that only obtains. If a refresh path
/// exists anywhere in the deployment, it is the leg to migrate first and verify last.
///
/// Reported by the SwiftMCPServer consumer, which hit exactly this: four failures became two
/// after the authorization leg was fixed, and the last was a refresh sending no resource.
public struct ResourceIndicatorPolicy: Sendable, Hashable {

    /// The resources this server will issue tokens for. Anything else is `invalid_target`.
    public let known: Set<URL>

    /// Whether a request naming no resource is acceptable.
    ///
    /// `false` — the default — for a server protecting more than one API, where a token
    /// without an audience is a token good at all of them. `true` for one whose tokens are
    /// already single-audience and have nothing to disambiguate.
    public let allowsUnspecified: Bool

    /// The canonical form of every entry in `known`, for comparison.
    private let knownCanonical: Set<String>

    /// Creates a policy.
    ///
    /// - Parameters:
    ///   - known: The resources this server issues tokens for.
    ///   - allowsUnspecified: Whether to accept a request naming no resource. Defaults to
    ///     `false`, so the permissive behaviour is chosen rather than inherited.
    public init(known: Set<URL>, allowsUnspecified: Bool = false) {
        self.known = known
        self.allowsUnspecified = allowsUnspecified
        self.knownCanonical = Set(known.map(Self.canonical))
    }

    /// The RFC 3986 canonical form of a resource identifier, for comparison only.
    ///
    /// Two identifiers that differ only by the normalisations §6.2.2–§6.2.3 declare
    /// insignificant are the same resource, and a server that treats them as different
    /// refuses the client that behaved best. The empty path is the one that bites:
    /// §6.2.3 makes `https://host:8081` and `https://host:8081/` the same URI, and most
    /// URL libraries — `new URL()` in JavaScript, `URL` in Swift, `urllib` in Python —
    /// hand back the second when given the first. A client reads
    /// `"resource": "https://host:8081"` from protected-resource metadata, passes it
    /// through a parser on the way to building the request, and sends a trailing slash
    /// it never typed.
    ///
    /// Applied to both sides, so the comparison does not depend on which one was written
    /// by hand.
    ///
    /// What is **not** normalised: a non-empty path. `https://host/mcp` and
    /// `https://host/mcp/` are different URIs under §6.2.3 and are left that way — the
    /// slash there may genuinely select a different resource, and collapsing it would
    /// widen an audience rather than repair one.
    ///
    /// - Parameter url: The identifier to normalise.
    /// - Returns: A string safe to compare against another canonicalised identifier.
    static func canonical(_ url: URL) -> String {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return url.absoluteString
        }
        // §6.2.2.1: scheme and host are case-insensitive.
        components.scheme = components.scheme?.lowercased()
        components.host = components.host?.lowercased()
        // §6.2.3: a port equal to the scheme's default is insignificant.
        if let port = components.port, port == Self.defaultPort(for: components.scheme) {
            components.port = nil
        }
        // §6.2.3: an empty path is equivalent to "/" for a hierarchical scheme.
        if components.path.isEmpty {
            components.path = "/"
        }
        // RFC 8707 §2: the resource MUST NOT carry a fragment, so it cannot distinguish two.
        components.fragment = nil
        return components.string ?? url.absoluteString
    }

    /// The default port for a scheme, or `nil` when it has none worth eliding.
    private static func defaultPort(for scheme: String?) -> Int? {
        switch scheme {
        case "http": return 80
        case "https": return 443
        default: return nil
        }
    }

    /// A policy for a server that protects the resource it identifies itself as.
    ///
    /// This is the ordinary case and the one to prefer, because the alternative invites a
    /// specific and badly-behaved failure. A provider publishes its canonical resource
    /// identifier in RFC 9728 metadata at `/.well-known/oauth-protected-resource`, and that is
    /// exactly what a conformant client reads in order to learn what to put in `resource`. If
    /// a hand-written policy then disagrees with that metadata — a trailing slash, a port,
    /// `http` against `https`, or someone changing one and not the other — the server
    /// advertises a resource and refuses it at the token endpoint.
    ///
    /// The client that breaks first is the most correct one: it read the metadata, sent what
    /// it was told, and got `invalid_target`. Both halves look right in isolation, and the
    /// operator's first instinct is that the client is wrong.
    ///
    /// - Parameter identifier: The server's canonical resource identifier — the same value it
    ///   publishes as `resource` in its protected-resource metadata.
    public static func protecting(_ identifier: URL) -> ResourceIndicatorPolicy {
        ResourceIndicatorPolicy(known: [identifier])
    }

    /// What this server accepts, phrased for an error message.
    ///
    /// Included in every refusal. A client that has just been told "no" needs the value, and
    /// the alternative is an operator reading a specification to discover something the server
    /// already knew and could have said.
    private var acceptedDescription: String {
        let sorted = known.map(\.absoluteString).sorted()
        switch sorted.count {
        case 0:
            return "This server lists no resources it issues tokens for."
        case 1:
            // Quoted so the value is unambiguous. The comparison is on the RFC 3986
            // canonical form, so a difference that only §6.2.2–§6.2.3 normalisation would
            // remove — a trailing slash on an empty path, letter case, a default port —
            // is not what this refusal is about.
            return "This server issues tokens for exactly \"\(sorted[0])\"."
        default:
            return "This server issues tokens for exactly one of: "
                + sorted.map { "\"\($0)\"" }.joined(separator: ", ") + "."
        }
    }

    /// The audience to bind into a token, for the resources a request named.
    ///
    /// - Parameter requested: Every `resource` parameter on the request, in order. RFC 8707 §2
    ///   permits the parameter to repeat.
    /// - Returns: The audience to bind, or `nil` when the request named none and the policy
    ///   permits that.
    /// - Throws: `OAuthError.invalidTarget` when a resource is unknown, when several
    ///   distinct resources were named, or when none was named and the policy is strict.
    public func audience(for requested: [URL]) throws -> URL? {
        // Repetition of one resource is a client quirk, not a second request — RFC 8707 does
        // not forbid it, and reading it as ambiguity would refuse a request that named exactly
        // one thing.
        let distinct = Set(requested)

        guard let resource = distinct.first else {
            guard allowsUnspecified else {
                // Distinct wording from the mismatch case on purpose. Under a strict default
                // the commonest failure is a client that sent nothing at all, and telling it
                // its resource was refused — when it named none — sends the reader looking for
                // a value that was never there.
                // The refusal hands over the value rather than describing the rule.
                //
                // "this server requires one" is accurate and reads as server policy, which
                // points at the wrong remedy: an operator whose client worked yesterday
                // concludes the server is configured too strictly, and the nearest apparent
                // fix is `allowsUnspecified: true` — turning the check off — rather than
                // setting `resource`. A strict default that is easy to switch off under
                // pressure gets switched off.
                throw OAuthError.invalidTarget(
                    "No resource indicator was supplied. Send the identifier of the API this "
                    + "token is for as the `resource` parameter (RFC 8707), on the "
                    + "authorization request and the token request. \(acceptedDescription)")
            }
            return nil
        }

        // RFC 8707 §2.2: a server that cannot issue one token covering every resource named
        // rejects the request. Narrowing to the first silently would issue a token for an
        // audience the client never asked for on its own, and the client would not be told.
        guard distinct.count == 1 else {
            throw OAuthError.invalidTarget(
                "A token can be issued for one resource; the request named \(distinct.count).")
        }

        guard knownCanonical.contains(Self.canonical(resource)) else {
            throw OAuthError.invalidTarget(
                "This server does not issue tokens for \(resource.absoluteString). "
                + acceptedDescription)
        }

        return resource
    }
}
