import Foundation
import SwiftOAuthCore
import SwiftOAuthProvider

/// The bar every ``OAuthProviderStorage`` must clear, shipped as a library rather than as tests.
///
/// A store written elsewhere runs *this* suite rather than its own, which is what makes the
/// protocol a substitution guarantee instead of a hope: if a store cannot pass it unchanged,
/// either the store or the protocol is wrong, and that is found here rather than on the
/// afternoon a deployment swaps SQLite for something else.
///
/// Every expected value comes from a specification (RFC 6749, 7009, 7662, 7591, 8628, 9126) or
/// from a contract the protocol's documentation states. None was copied from what a store
/// returned.
///
/// A negative requirement ("an expired token does not validate") is satisfied by a store that
/// refuses everything, so each one is preceded by a positive control: the same store is first
/// shown to accept the thing it is about to be shown to refuse. A store that fails the control
/// is reported ``Verdict/inconclusive``, not ``Verdict/passed``.
///
/// ```swift
/// let suite = ProviderStorageConformanceSuite { try InMemoryOAuthStorage() }
/// let report = await suite.run()
/// precondition(report.isConformant, report.summary)
/// ```
public struct ProviderStorageConformanceSuite: Sendable {

    /// Makes a fresh, empty store. Called once per requirement so no requirement sees another's
    /// data.
    public typealias Factory = @Sendable () async throws -> any OAuthProviderStorage

    /// A behaviour a store must exhibit.
    public enum Requirement: String, Sendable, CaseIterable {
        // Clients
        case clientRoundTrips = "a saved client is returned with every field it was saved with"
        case unknownClientIsNil = "an unknown client reads as nil"
        case clientSecretIsNeverReturned = "a client read back carries no secret"
        case clientSecretMatching = "only the registered secret matches, and a public client has none"
        case clientResaveKeepsSecret = "re-saving without a secret keeps it; a new one replaces it; none drops it"
        case deletingAClientDeletesItsCredentials = "deleting a client deletes its tokens and codes"
        // Authorization codes
        case codeRoundTripsSubjectAndAudience = "a code returns its subject, audience and challenge, nil included"
        case codeIsSingleUse = "a code is consumed once and an unknown one is nil"
        case codeConsumptionIsAtomic = "concurrent redemptions of one code succeed exactly once"
        // CSRF
        case csrfTokenIsSingleUse = "a CSRF token validates once"
        case csrfTokenIsBound = "a CSRF token is refused for another client, redirect, or after expiry"
        // Access tokens
        case accessTokenRoundTripsItsClaims = "an access token validates with the claims it was saved with"
        case accessTokenExpires = "an expired or unknown access token does not validate"
        case accessTokenRevocation = "a revoked access token does not validate and others are unaffected"
        case revokeAllTokensForClient = "revoking a client's tokens ends its access and refresh tokens only"
        // Refresh tokens
        case refreshTokenLookup = "a live refresh token is found with its subject; expired and unknown are nil"
        // Introspection
        case introspectionOfActiveToken = "an active token introspects with its claims (RFC 7662 §2.2)"
        case introspectionOfDeadTokenIsInactive = "revoked, expired and unknown tokens introspect alike as inactive"
        // Device codes
        case deviceUserCodeLookup = "a pending user code is found in any case and punctuation, with its client and scope"
        case deviceApprovalIsOnce = "a device code is approved once, recording who approved it"
        case deviceDenial = "a denied device code reports denied and cannot then be approved"
        case deviceCodeOwnership = "another client, or an unknown code, sees the device code as unknown"
        case deviceExpiry = "an expired device code is expired and cannot be approved"
        case deviceRedemptionIsOnce = "a device code is redeemed exactly once, even concurrently"
        case devicePollPacing = "polling too soon is slow_down and widens the interval by five seconds"
        // Pushed authorization requests
        case pushedRequestIsSingleUse = "a pushed request is consumed once, by its own client, before it expires"
    }

    /// How a requirement came out.
    public enum Verdict: String, Sendable {
        /// Every expectation held.
        case passed
        /// An expectation did not hold, or the store threw.
        case failed
        /// The store refused something it had not first been shown to accept, so its refusal
        /// proves nothing.
        case inconclusive
    }

    /// One requirement's outcome.
    public struct Result: Sendable {
        /// The behaviour that was checked.
        public let requirement: Requirement
        /// How it came out.
        public let verdict: Verdict
        /// What was observed when it did not pass; empty on a pass.
        public let detail: String
    }

    /// What the suite found.
    public struct Report: Sendable {
        /// Every requirement's outcome, in declaration order.
        public let results: [Result]
        /// Requirements the store did not meet.
        public var failures: [Result] { results.filter { $0.verdict == .failed } }
        /// Requirements whose result proves nothing, because the store refused its own control.
        public var inconclusive: [Result] { results.filter { $0.verdict == .inconclusive } }
        /// Whether the store cleared every requirement. Inconclusive counts against it.
        public var isConformant: Bool { failures.isEmpty && inconclusive.isEmpty }

        /// A table for a test to print when something is wrong.
        public var summary: String {
            let lines = results.map { result -> String in
                let mark: String
                switch result.verdict {
                case .passed: mark = "PASS"
                case .failed: mark = "FAIL"
                case .inconclusive: mark = "????"
                }
                let tail = result.detail.isEmpty ? "" : " [\(result.detail)]"
                return "  \(mark)  \(result.requirement.rawValue)\(tail)"
            }
            let passed = results.filter { $0.verdict == .passed }.count
            return (["\(results.count) requirements: \(passed) passed, \(failures.count) failed, "
                     + "\(inconclusive.count) inconclusive"] + lines).joined(separator: "\n")
        }
    }

    private let makeStore: Factory

    /// Creates a suite that judges the stores `makeStore` returns.
    ///
    /// - Parameter makeStore: Returns a fresh, empty store each time it is called.
    public init(makeStore: @escaping Factory) {
        self.makeStore = makeStore
    }

    /// Runs every requirement, each against a store of its own.
    public func run() async -> Report {
        var results: [Result] = []
        for requirement in Requirement.allCases {
            results.append(await run(requirement))
        }
        return Report(results: results)
    }

    /// Runs one requirement against a fresh store.
    public func run(_ requirement: Requirement) async -> Result {
        var observation = Observation()
        do {
            let store = try await makeStore()
            try await Self.check(requirement, store, &observation)
        } catch {
            observation.fail("threw \(error)")
        }
        let verdict: Verdict
        if !observation.controlFailures.isEmpty {
            verdict = .inconclusive
        } else if !observation.failures.isEmpty {
            verdict = .failed
        } else {
            verdict = .passed
        }
        return Result(
            requirement: requirement, verdict: verdict,
            detail: (observation.controlFailures + observation.failures).joined(separator: "; "))
    }

    // MARK: - Observation

    /// What one requirement saw.
    private struct Observation {
        var failures: [String] = []
        var controlFailures: [String] = []

        mutating func expect(_ condition: Bool, _ message: String) {
            if !condition { failures.append(message) }
        }

        /// A check that must hold for the requirement's other results to mean anything.
        mutating func control(_ condition: Bool, _ message: String) {
            if !condition { controlFailures.append("control: \(message)") }
        }

        mutating func fail(_ message: String) {
            failures.append(message)
        }
    }

    // MARK: - Fixtures

    private static var future: Date { Date().addingTimeInterval(3600) }
    private static var past: Date { Date().addingTimeInterval(-3600) }
    private static let resource = URL(string: "https://api.example.com/mcp")

    private static func client(
        _ id: String,
        secret: String? = "s3cret",
        method: String = "client_secret_basic",
        name: String = "Test",
        application: ApplicationType = .web,
        ceiling: Set<String>? = nil
    ) -> RegisteredClient {
        RegisteredClient(
            clientId: id, clientSecret: secret, clientName: name,
            redirectUris: ["https://app.example.com/cb", "https://app.example.com/cb2"],
            grantTypes: ["authorization_code", "refresh_token"],
            tokenEndpointAuthMethod: method,
            registrationDate: Date(timeIntervalSince1970: 1_700_000_000),
            applicationType: application, scopeCeiling: ceiling)
    }

    private static func code(
        _ value: String, client: String = "c1", expiresAt: Date = future,
        subject: String? = nil, audience: URL? = nil,
        challenge: String? = "ch", method: String? = "S256"
    ) -> AuthorizationCode {
        AuthorizationCode(
            code: value, clientId: client, redirectUri: "https://app.example.com/cb",
            scope: "read write", codeChallenge: challenge, codeChallengeMethod: method,
            expiresAt: expiresAt, createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            audience: audience, subject: subject)
    }

    private static func isValid(_ result: TokenValidationResult) -> Bool {
        if case .valid = result { return true }
        return false
    }

    private static let userCode = "BCDF-GHJK"

    private static func saveDevice(
        _ store: any OAuthProviderStorage, device: String = "dev-1", user: String = userCode,
        client: String = "c1", scope: String? = "read", expiresAt: Date, interval: TimeInterval = 5,
        now: Date
    ) async throws {
        try await store.saveDeviceCode(
            deviceCode: device, userCode: user, clientId: client, scope: scope,
            expiresAt: expiresAt, interval: interval, now: now)
    }

    // MARK: - Requirements

    private static func check(
        _ requirement: Requirement, _ store: any OAuthProviderStorage, _ o: inout Observation
    ) async throws {
        switch requirement {
        case .clientRoundTrips: try await clientRoundTrips(store, &o)
        case .unknownClientIsNil:
            o.expect(try await store.getClient(clientId: "nobody") == nil, "unknown client was not nil")
        case .clientSecretIsNeverReturned: try await clientSecretIsNeverReturned(store, &o)
        case .clientSecretMatching: try await clientSecretMatching(store, &o)
        case .clientResaveKeepsSecret: try await clientResaveKeepsSecret(store, &o)
        case .deletingAClientDeletesItsCredentials: try await deletingAClient(store, &o)
        case .codeRoundTripsSubjectAndAudience: try await codeRoundTrips(store, &o)
        case .codeIsSingleUse: try await codeIsSingleUse(store, &o)
        case .codeConsumptionIsAtomic: try await codeConsumptionIsAtomic(store, &o)
        case .csrfTokenIsSingleUse: try await csrfSingleUse(store, &o)
        case .csrfTokenIsBound: try await csrfBound(store, &o)
        case .accessTokenRoundTripsItsClaims: try await accessTokenClaims(store, &o)
        case .accessTokenExpires: try await accessTokenExpires(store, &o)
        case .accessTokenRevocation: try await accessTokenRevocation(store, &o)
        case .revokeAllTokensForClient: try await revokeAllForClient(store, &o)
        case .refreshTokenLookup: try await refreshLookup(store, &o)
        case .introspectionOfActiveToken: try await introspectActive(store, &o)
        case .introspectionOfDeadTokenIsInactive: try await introspectDead(store, &o)
        case .deviceUserCodeLookup: try await deviceUserCodeLookup(store, &o)
        case .deviceApprovalIsOnce: try await deviceApprovalIsOnce(store, &o)
        case .deviceDenial: try await deviceDenial(store, &o)
        case .deviceCodeOwnership: try await deviceOwnership(store, &o)
        case .deviceExpiry: try await deviceExpiry(store, &o)
        case .deviceRedemptionIsOnce: try await deviceRedemptionIsOnce(store, &o)
        case .devicePollPacing: try await devicePollPacing(store, &o)
        case .pushedRequestIsSingleUse: try await pushedRequest(store, &o)
        }
    }

    // MARK: Clients

    private static func clientRoundTrips(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        let saved = client("c1", application: .native, ceiling: ["read", "write"])
        try await store.saveClient(saved)
        guard let got = try await store.getClient(clientId: "c1") else {
            o.fail("saved client was not found")
            return
        }
        o.expect(got.clientId == "c1", "clientId differs")
        o.expect(got.clientName == "Test", "clientName differs")
        o.expect(got.redirectUris == saved.redirectUris, "redirectUris differ or lost their order")
        o.expect(got.grantTypes == saved.grantTypes, "grantTypes differ")
        o.expect(got.tokenEndpointAuthMethod == "client_secret_basic", "auth method differs")
        o.expect(abs(got.registrationDate.timeIntervalSince(saved.registrationDate)) < 0.001,
                 "registrationDate differs")
        o.expect(got.applicationType == .native, "applicationType differs (RFC 7591 application_type)")
        o.expect(got.scopeCeiling == ["read", "write"], "scopeCeiling differs")

        try await store.saveClient(client("c2", secret: nil, method: "none"))
        let plain = try await store.getClient(clientId: "c2")
        o.expect(plain?.scopeCeiling == nil, "a client saved with no ceiling gained one")
        o.expect(plain?.applicationType == .web, "default application type is web (RFC 7591 §2)")
    }

    private static func clientSecretIsNeverReturned(
        _ store: any OAuthProviderStorage, _ o: inout Observation
    ) async throws {
        try await store.saveClient(client("c1", secret: "s3cret"))
        let got = try await store.getClient(clientId: "c1")
        o.control(got != nil, "the client was not stored")
        o.expect(got?.clientSecret == nil, "a client read back carried its secret")
    }

    private static func clientSecretMatching(
        _ store: any OAuthProviderStorage, _ o: inout Observation
    ) async throws {
        try await store.saveClient(client("conf", secret: "s3cret"))
        try await store.saveClient(client("pub", secret: nil, method: "none"))
        o.control(try await store.clientSecretMatches(clientId: "conf", presented: "s3cret"),
                  "the registered secret did not match")
        o.expect(try await store.clientSecretMatches(clientId: "conf", presented: "wrong") == false,
                 "a wrong secret matched")
        o.expect(try await store.clientSecretMatches(clientId: "conf", presented: "") == false,
                 "an empty secret matched")
        o.expect(try await store.clientSecretMatches(clientId: "ghost", presented: "s3cret") == false,
                 "an unknown client matched")
        o.expect(try await store.clientSecretMatches(clientId: "pub", presented: "") == false,
                 "a public client authenticated with an empty secret")
        o.expect(try await store.clientSecretMatches(clientId: "pub", presented: "s3cret") == false,
                 "a public client authenticated with a secret")
    }

    private static func clientResaveKeepsSecret(
        _ store: any OAuthProviderStorage, _ o: inout Observation
    ) async throws {
        try await store.saveClient(client("c1", secret: "first", name: "One"))
        o.control(try await store.clientSecretMatches(clientId: "c1", presented: "first"),
                  "the first secret did not match")
        // A client read back has no secret; saving it again must not erase the credential.
        guard let readBack = try await store.getClient(clientId: "c1") else {
            o.fail("client missing")
            return
        }
        let renamed = RegisteredClient(
            clientId: readBack.clientId, clientSecret: nil, clientName: "Two",
            redirectUris: readBack.redirectUris, grantTypes: readBack.grantTypes,
            tokenEndpointAuthMethod: readBack.tokenEndpointAuthMethod,
            registrationDate: readBack.registrationDate, applicationType: readBack.applicationType,
            scopeCeiling: readBack.scopeCeiling)
        try await store.saveClient(renamed)
        o.expect(try await store.clientSecretMatches(clientId: "c1", presented: "first"),
                 "re-saving a client without a secret erased its secret")
        o.expect(try await store.getClient(clientId: "c1")?.clientName == "Two", "the update was not applied")

        try await store.saveClient(client("c1", secret: "second"))
        o.expect(try await store.clientSecretMatches(clientId: "c1", presented: "second"),
                 "a new secret did not replace the old")
        o.expect(try await store.clientSecretMatches(clientId: "c1", presented: "first") == false,
                 "the replaced secret still matched")

        try await store.saveClient(client("c1", secret: nil, method: "none"))
        o.expect(try await store.clientSecretMatches(clientId: "c1", presented: "second") == false,
                 "a client re-saved as public kept its secret")
    }

    private static func deletingAClient(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        try await store.saveClient(client("c1"))
        try await store.saveClient(client("c2"))
        for id in ["c1", "c2"] {
            try await store.saveAccessToken(
                token: "at-\(id)", clientId: id, scope: "read", expiresAt: future,
                audience: nil, keyThumbprint: nil, certificateThumbprint: nil, subject: nil)
            try await store.saveRefreshToken(
                token: "rt-\(id)", clientId: id, scope: "read", expiresAt: future, subject: nil)
            try await store.saveAuthorizationCode(code("code-\(id)", client: id))
        }
        let storedClient = try await store.getClient(clientId: "c1")
        let storedAccess = try await store.validateAccessToken(token: "at-c1")
        let storedRefresh = try await store.getRefreshTokenInfo(token: "rt-c1")
        o.control(storedClient != nil && isValid(storedAccess) && storedRefresh != nil,
                  "the client's credentials were not stored")

        try await store.deleteClient(clientId: "c1")
        o.expect(try await store.getClient(clientId: "c1") == nil, "the client survived deletion")
        o.expect(isValid(try await store.validateAccessToken(token: "at-c1")) == false,
                 "an access token survived its client's deletion")
        o.expect(try await store.getRefreshTokenInfo(token: "rt-c1") == nil,
                 "a refresh token survived its client's deletion")
        o.expect(try await store.consumeAuthorizationCode(code: "code-c1") == nil,
                 "an authorization code survived its client's deletion")
        o.expect(try await store.getClient(clientId: "c2") != nil, "another client was deleted")
        o.expect(isValid(try await store.validateAccessToken(token: "at-c2")), "another client's token was deleted")
    }

    // MARK: Authorization codes

    private static func codeRoundTrips(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        try await store.saveAuthorizationCode(code("with", subject: "alice", audience: resource))
        try await store.saveAuthorizationCode(code("without", challenge: nil, method: nil))
        guard let with = try await store.consumeAuthorizationCode(code: "with") else {
            o.fail("a saved code was not found")
            return
        }
        o.expect(with.subject == "alice", "the subject was lost")
        o.expect(with.audience == resource, "the audience was lost (RFC 8707)")
        o.expect(with.codeChallenge == "ch" && with.codeChallengeMethod == "S256", "the PKCE challenge was lost")
        o.expect(with.clientId == "c1" && with.redirectUri == "https://app.example.com/cb"
                 && with.scope == "read write", "client, redirect or scope differs")
        guard let without = try await store.consumeAuthorizationCode(code: "without") else {
            o.fail("a second saved code was not found")
            return
        }
        o.expect(without.subject == nil, "a code granted with no subject gained one")
        o.expect(without.audience == nil, "a code granted for no resource gained one")
        o.expect(without.codeChallenge == nil && without.codeChallengeMethod == nil, "a challenge appeared")
    }

    private static func codeIsSingleUse(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        try await store.saveAuthorizationCode(code("once"))
        o.control(try await store.consumeAuthorizationCode(code: "once") != nil, "the first redemption failed")
        // RFC 6749 §4.1.2: the code MUST NOT be used more than once.
        o.expect(try await store.consumeAuthorizationCode(code: "once") == nil, "a code was redeemed twice")
        o.expect(try await store.consumeAuthorizationCode(code: "never-issued") == nil, "an unknown code was found")
    }

    private static func codeConsumptionIsAtomic(
        _ store: any OAuthProviderStorage, _ o: inout Observation
    ) async throws {
        try await store.saveAuthorizationCode(code("race"))
        let winners = await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<24 {
                group.addTask { (try? await store.consumeAuthorizationCode(code: "race")) != nil }
            }
            var count = 0
            for await won in group where won { count += 1 }
            return count
        }
        o.expect(winners == 1, "\(winners) of 24 concurrent redemptions succeeded; exactly 1 should")
    }

    // MARK: CSRF

    private static func csrfSingleUse(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        let token = try await store.generateCSRFToken(clientId: "c1", redirectUri: "https://a/cb", expiresIn: 600)
        let other = try await store.generateCSRFToken(clientId: "c1", redirectUri: "https://a/cb", expiresIn: 600)
        o.expect(!token.isEmpty && token != other, "tokens were empty or repeated")
        let first = try await store.validateCSRFToken(token: token, clientId: "c1", redirectUri: "https://a/cb")
        o.control(first.isValid, "a fresh token did not validate")
        let second = try await store.validateCSRFToken(token: token, clientId: "c1", redirectUri: "https://a/cb")
        o.expect(second.isValid == false, "a CSRF token validated twice")
        o.expect(second.error != nil, "a refusal carried no reason")
        let unknown = try await store.validateCSRFToken(token: "nope", clientId: "c1", redirectUri: "https://a/cb")
        o.expect(unknown.isValid == false, "an unknown CSRF token validated")
    }

    private static func csrfBound(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        let probe = try await store.generateCSRFToken(clientId: "c1", redirectUri: "https://a/cb", expiresIn: 600)
        o.control(try await store.validateCSRFToken(token: probe, clientId: "c1", redirectUri: "https://a/cb").isValid,
                  "a fresh token did not validate")
        let bound = try await store.generateCSRFToken(clientId: "c1", redirectUri: "https://a/cb", expiresIn: 600)
        o.expect(try await store.validateCSRFToken(token: bound, clientId: "c2", redirectUri: "https://a/cb")
            .isValid == false, "a token validated for another client")
        o.expect(try await store.validateCSRFToken(token: bound, clientId: "c1", redirectUri: "https://evil/cb")
            .isValid == false, "a token validated for another redirect URI")
        let stale = try await store.generateCSRFToken(clientId: "c1", redirectUri: "https://a/cb", expiresIn: -1)
        o.expect(try await store.validateCSRFToken(token: stale, clientId: "c1", redirectUri: "https://a/cb")
            .isValid == false, "an expired token validated")
    }

    // MARK: Access tokens

    private static func accessTokenClaims(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        try await store.saveAccessToken(
            token: "full", clientId: "c1", scope: "read write", expiresAt: future, audience: resource,
            keyThumbprint: "jkt", certificateThumbprint: nil, subject: "alice")
        try await store.saveAccessToken(
            token: "cert", clientId: "c1", scope: nil, expiresAt: future, audience: nil,
            keyThumbprint: nil, certificateThumbprint: "x5t", subject: nil)
        let expected = TokenValidationResult.valid(.init(
            clientId: "c1", scope: "read write", audience: resource, keyThumbprint: "jkt",
            certificateThumbprint: nil, subject: "alice"))
        o.expect(try await store.validateAccessToken(token: "full") == expected,
                 "the validated claims differ from what was saved")
        let bare = TokenValidationResult.valid(.init(
            clientId: "c1", scope: nil, audience: nil, keyThumbprint: nil,
            certificateThumbprint: "x5t", subject: nil))
        o.expect(try await store.validateAccessToken(token: "cert") == bare,
                 "a token saved with no scope, audience or subject gained one, or lost its certificate binding")
    }

    private static func accessTokenExpires(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        try await store.saveAccessToken(
            token: "live", clientId: "c1", scope: "read", expiresAt: future,
            audience: nil, keyThumbprint: nil, certificateThumbprint: nil, subject: nil)
        try await store.saveAccessToken(
            token: "dead", clientId: "c1", scope: "read", expiresAt: past,
            audience: nil, keyThumbprint: nil, certificateThumbprint: nil, subject: nil)
        o.control(isValid(try await store.validateAccessToken(token: "live")), "a live token did not validate")
        o.expect(isValid(try await store.validateAccessToken(token: "dead")) == false, "an expired token validated")
        o.expect(isValid(try await store.validateAccessToken(token: "never-issued")) == false,
                 "an unknown token validated")
    }

    private static func accessTokenRevocation(
        _ store: any OAuthProviderStorage, _ o: inout Observation
    ) async throws {
        for name in ["a", "b"] {
            try await store.saveAccessToken(
                token: name, clientId: "c1", scope: nil, expiresAt: future,
                audience: nil, keyThumbprint: nil, certificateThumbprint: nil, subject: nil)
        }
        o.control(isValid(try await store.validateAccessToken(token: "a")), "a live token did not validate")
        try await store.revokeAccessToken(token: "a")
        o.expect(isValid(try await store.validateAccessToken(token: "a")) == false, "a revoked token validated")
        o.expect(isValid(try await store.validateAccessToken(token: "b")), "revoking one token revoked another")
        // RFC 7009 §2.2: revoking a token that does not exist is not an error.
        try await store.revokeAccessToken(token: "never-issued")
    }

    private static func revokeAllForClient(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        for (client, subject) in [("c1", Optional("alice")), ("c1", nil), ("c2", Optional("alice"))] {
            let suffix = "\(client)-\(subject ?? "nil")"
            try await store.saveAccessToken(
                token: "at-\(suffix)", clientId: client, scope: nil, expiresAt: future,
                audience: nil, keyThumbprint: nil, certificateThumbprint: nil, subject: subject)
            try await store.saveRefreshToken(
                token: "rt-\(suffix)", clientId: client, scope: nil, expiresAt: future, subject: subject)
        }
        let storedAccess = try await store.validateAccessToken(token: "at-c1-alice")
        let storedRefresh = try await store.getRefreshTokenInfo(token: "rt-c1-nil")
        o.control(isValid(storedAccess) && storedRefresh != nil, "the tokens were not stored")
        try await store.revokeAllTokensForClient(clientId: "c1")
        for suffix in ["c1-alice", "c1-nil"] {
            o.expect(isValid(try await store.validateAccessToken(token: "at-\(suffix)")) == false,
                     "access token at-\(suffix) survived revocation of its client")
            o.expect(try await store.getRefreshTokenInfo(token: "rt-\(suffix)") == nil,
                     "refresh token rt-\(suffix) survived revocation of its client")
        }
        o.expect(isValid(try await store.validateAccessToken(token: "at-c2-alice")),
                 "revoking one client's tokens revoked another client's access token")
        o.expect(try await store.getRefreshTokenInfo(token: "rt-c2-alice") != nil,
                 "revoking one client's tokens revoked another client's refresh token")
    }

    // MARK: Refresh tokens

    private static func refreshLookup(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        let expiry = future
        try await store.saveRefreshToken(token: "rt", clientId: "c1", scope: "read", expiresAt: expiry, subject: "alice")
        try await store.saveRefreshToken(token: "anon", clientId: "c1", scope: nil, expiresAt: expiry, subject: nil)
        try await store.saveRefreshToken(token: "old", clientId: "c1", scope: "read", expiresAt: past, subject: "alice")
        guard let info = try await store.getRefreshTokenInfo(token: "rt") else {
            o.fail("a live refresh token was not found")
            return
        }
        o.expect(info.clientId == "c1" && info.scope == "read", "client or scope differs")
        o.expect(info.subject == "alice", "the subject was lost")
        o.expect(abs(info.expiresAt.timeIntervalSince(expiry)) < 0.001, "expiry differs")
        let anon = try await store.getRefreshTokenInfo(token: "anon")
        o.expect(anon != nil && anon?.subject == nil && anon?.scope == nil,
                 "a refresh token saved with no subject or scope gained one, or was not found")
        o.expect(try await store.getRefreshTokenInfo(token: "old") == nil, "an expired refresh token was found")
        o.expect(try await store.getRefreshTokenInfo(token: "never-issued") == nil, "an unknown refresh token was found")
    }

    // MARK: Introspection

    private static func introspectActive(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        let before = Date()
        let expiry = future
        try await store.saveAccessToken(
            token: "live", clientId: "c1", scope: "read write", expiresAt: expiry, audience: resource,
            keyThumbprint: nil, certificateThumbprint: nil, subject: "alice")
        try await store.saveAccessToken(
            token: "anon", clientId: "c1", scope: nil, expiresAt: expiry, audience: nil,
            keyThumbprint: nil, certificateThumbprint: nil, subject: nil)
        let after = Date()
        let result = try await store.introspectAccessToken(token: "live")
        o.expect(result.active, "a live token introspected as inactive")
        o.expect(result.scope == "read write", "scope differs (RFC 7662 §2.2 scope)")
        o.expect(result.clientId == "c1", "client_id differs")
        o.expect(result.subject == "alice", "sub differs")
        o.expect(result.audience == [resource?.absoluteString ?? ""], "aud differs (RFC 8707)")
        o.expect(result.expiry.map { abs($0.timeIntervalSince(expiry)) < 0.001 } == true, "exp differs")
        o.expect(result.issuedAt.map { $0 >= before.addingTimeInterval(-1) && $0 <= after.addingTimeInterval(1) } == true,
                 "iat is not the time the token was saved")
        let anon = try await store.introspectAccessToken(token: "anon")
        o.expect(anon.active && anon.subject == nil && anon.audience == nil && anon.scope == nil,
                 "a token saved with no subject, audience or scope reported one")
    }

    private static func introspectDead(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        for (name, expiry) in [("live", future), ("revoked", future), ("expired", past)] {
            try await store.saveAccessToken(
                token: name, clientId: "c1", scope: "read", expiresAt: expiry,
                audience: resource, keyThumbprint: nil, certificateThumbprint: nil, subject: "alice")
        }
        try await store.revokeAccessToken(token: "revoked")
        o.control(try await store.introspectAccessToken(token: "live").active, "a live token was not active")
        // RFC 7662 §2.2: an inactive response carries `active: false` and nothing else, so the
        // three cases are indistinguishable.
        for name in ["revoked", "expired", "never-issued"] {
            o.expect(try await store.introspectAccessToken(token: name) == IntrospectionResult.inactive,
                     "the \(name) token did not introspect as exactly {active: false}")
        }
    }

    // MARK: Device codes (RFC 8628)

    private static func deviceUserCodeLookup(
        _ store: any OAuthProviderStorage, _ o: inout Observation
    ) async throws {
        let now = Date()
        try await saveDevice(store, expiresAt: now.addingTimeInterval(600), now: now)
        for typed in ["BCDF-GHJK", "bcdf-ghjk", "bcdfghjk", "BCDF GHJK"] {
            let found = try await store.pendingDeviceCode(userCode: typed, now: now)
            o.expect(found?.clientId == "c1" && found?.scope == "read",
                     "the user code typed as \"\(typed)\" was not found with its client and scope (§6.1)")
        }
        o.expect(try await store.pendingDeviceCode(userCode: "BCDF-GHJL", now: now) == nil, "a wrong code was found")
        o.expect(try await store.pendingDeviceCode(userCode: userCode, now: now.addingTimeInterval(601)) == nil,
                 "an expired code was found")
        o.expect(try await store.approveDeviceCode(userCode: userCode, subject: "alice", now: now),
                 "the code could not be approved")
        o.expect(try await store.pendingDeviceCode(userCode: userCode, now: now) == nil,
                 "an answered code was still pending")
    }

    private static func deviceApprovalIsOnce(
        _ store: any OAuthProviderStorage, _ o: inout Observation
    ) async throws {
        let now = Date()
        try await saveDevice(store, expiresAt: now.addingTimeInterval(600), now: now)
        o.control(try await store.deviceCodeState(deviceCode: "dev-1", clientId: "c1", now: now) == .pending,
                  "a new device code was not pending")
        o.expect(try await store.approveDeviceCode(userCode: "bcdf ghjk", subject: "alice", now: now),
                 "a pending code was not approved")
        o.expect(try await store.deviceCodeState(deviceCode: "dev-1", clientId: "c1", now: now)
                 == .approved(scope: "read", subject: "alice"),
                 "approval did not record the approver and scope")
        o.expect(try await store.approveDeviceCode(userCode: userCode, subject: "mallory", now: now) == false,
                 "an approved code was approved again")
        o.expect(try await store.deviceCodeState(deviceCode: "dev-1", clientId: "c1", now: now)
                 == .approved(scope: "read", subject: "alice"),
                 "a second approval rewrote whose session the device collects")
        o.expect(try await store.approveDeviceCode(userCode: "ZZZZ-ZZZZ", subject: "alice", now: now) == false,
                 "an unknown user code was approved")
    }

    private static func deviceDenial(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        let now = Date()
        try await saveDevice(store, expiresAt: now.addingTimeInterval(600), now: now)
        o.control(try await store.deviceCodeState(deviceCode: "dev-1", clientId: "c1", now: now) == .pending,
                  "a new device code was not pending")
        o.expect(try await store.denyDeviceCode(userCode: userCode, subject: "alice", now: now), "denial failed")
        o.expect(try await store.deviceCodeState(deviceCode: "dev-1", clientId: "c1", now: now) == .denied,
                 "a denied code did not report denied (§3.5 access_denied)")
        o.expect(try await store.approveDeviceCode(userCode: userCode, subject: "alice", now: now) == false,
                 "a denied code was approved")
        o.expect(try await store.denyDeviceCode(userCode: userCode, subject: "alice", now: now) == false,
                 "a denied code was denied again")
    }

    private static func deviceOwnership(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        let now = Date()
        try await saveDevice(store, expiresAt: now.addingTimeInterval(600), now: now)
        _ = try await store.approveDeviceCode(userCode: userCode, subject: "alice", now: now)
        o.control(try await store.deviceCodeState(deviceCode: "dev-1", clientId: "c1", now: now)
                  == .approved(scope: "read", subject: "alice"), "the owner could not see its approved code")
        o.expect(try await store.deviceCodeState(deviceCode: "dev-1", clientId: "c2", now: now) == .unknown,
                 "another client saw someone else's device code")
        o.expect(try await store.deviceCodeState(deviceCode: "never-issued", clientId: "c1", now: now) == .unknown,
                 "an unknown device code was not unknown")
        o.expect(try await store.markDeviceCodeRedeemed(deviceCode: "never-issued") == false,
                 "an unknown device code was redeemed")
    }

    private static func deviceExpiry(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        let now = Date()
        let expiry = now.addingTimeInterval(600)
        try await saveDevice(store, expiresAt: expiry, now: now)
        o.control(try await store.deviceCodeState(deviceCode: "dev-1", clientId: "c1", now: now) == .pending,
                  "a new device code was not pending")
        let late = expiry.addingTimeInterval(1)
        o.expect(try await store.deviceCodeState(deviceCode: "dev-1", clientId: "c1", now: late) == .expired,
                 "a device code past its expiry was not expired (§3.5 expired_token)")
        o.expect(try await store.approveDeviceCode(userCode: userCode, subject: "alice", now: late) == false,
                 "an expired code was approved")
        o.expect(try await store.denyDeviceCode(userCode: userCode, subject: "alice", now: late) == false,
                 "an expired code was denied")
    }

    private static func deviceRedemptionIsOnce(
        _ store: any OAuthProviderStorage, _ o: inout Observation
    ) async throws {
        let now = Date()
        try await saveDevice(store, expiresAt: now.addingTimeInterval(600), now: now)
        _ = try await store.approveDeviceCode(userCode: userCode, subject: "alice", now: now)
        let winners = await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<24 {
                group.addTask { (try? await store.markDeviceCodeRedeemed(deviceCode: "dev-1")) == true }
            }
            var count = 0
            for await won in group where won { count += 1 }
            return count
        }
        o.expect(winners == 1, "\(winners) of 24 concurrent redemptions spent the code; exactly 1 should")
        o.expect(try await store.deviceCodeState(deviceCode: "dev-1", clientId: "c1", now: now) == .alreadyRedeemed,
                 "a redeemed code did not report alreadyRedeemed")
    }

    private static func devicePollPacing(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        let start = Date()
        try await saveDevice(store, expiresAt: start.addingTimeInterval(3600), interval: 5, now: start)
        // §3.5: a poll sooner than the interval is slow_down, and the interval grows by 5 seconds
        // "for this and all subsequent requests". Offsets are from `start`, in seconds.
        let polls: [(offset: TimeInterval, tooSoon: Bool)] = [
            (0, false),    // the first poll is never too soon
            (6, false),    // 6 >= 5
            (7, true),     // 1 < 5: slow_down; interval becomes 10
            (16, true),    // 9 < 10: slow_down; interval becomes 15
            (32, false)    // 16 >= 15
        ]
        for poll in polls {
            let got = try await store.pacePendingPoll(
                deviceCode: "dev-1", now: start.addingTimeInterval(poll.offset))
            o.expect(got == poll.tooSoon, "the poll at +\(poll.offset)s answered tooSoon=\(got), expected \(poll.tooSoon)")
        }
        o.expect(try await store.pacePendingPoll(deviceCode: "never-issued", now: start) == false,
                 "polling an unknown device code was reported too soon")
    }

    // MARK: Pushed requests (RFC 9126)

    private static func pushedRequest(_ store: any OAuthProviderStorage, _ o: inout Observation) async throws {
        func push(_ uri: String, client: String = "c1", expiresAt: Date = future) async throws {
            try await store.savePushedRequest(
                requestURI: uri, clientId: client, redirectUri: "https://app.example.com/cb",
                scope: "read", state: "xyz", codeChallenge: "ch", codeChallengeMethod: "S256",
                expiresAt: expiresAt)
        }
        try await push("urn:ietf:params:oauth:request_uri:live")
        try await push("urn:ietf:params:oauth:request_uri:dead", expiresAt: past)
        try await push("urn:ietf:params:oauth:request_uri:theirs")

        // §2.2 and RFC 9126 §4: the reference is one-time use and bound to the pushing client.
        let stranger = try await store.consumePushedRequest(
            requestURI: "urn:ietf:params:oauth:request_uri:theirs", clientId: "c2")
        o.expect(stranger == nil, "another client consumed a pushed request")
        let mine = try await store.consumePushedRequest(
            requestURI: "urn:ietf:params:oauth:request_uri:live", clientId: "c1")
        let expected = PushedAuthorizationRequest(
            redirectUri: "https://app.example.com/cb", scope: "read", state: "xyz",
            codeChallenge: "ch", codeChallengeMethod: "S256")
        o.control(mine == expected, "a live pushed request was not consumed intact")
        o.expect(try await store.consumePushedRequest(
            requestURI: "urn:ietf:params:oauth:request_uri:live", clientId: "c1") == nil,
                 "a pushed request was consumed twice")
        o.expect(try await store.consumePushedRequest(
            requestURI: "urn:ietf:params:oauth:request_uri:dead", clientId: "c1") == nil,
                 "an expired pushed request was consumed")
        o.expect(try await store.consumePushedRequest(
            requestURI: "urn:ietf:params:oauth:request_uri:theirs", clientId: "c1") != nil,
                 "a refused attempt by another client spent the pushed request")
        o.expect(try await store.consumePushedRequest(requestURI: "never-issued", clientId: "c1") == nil,
                 "an unknown reference was consumed")
    }
}
