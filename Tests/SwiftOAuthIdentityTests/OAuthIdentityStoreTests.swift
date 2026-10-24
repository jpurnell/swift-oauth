import Foundation
import Testing
import SwiftIdentity
import SwiftIdentityConformance
import SwiftOAuthCore
import SwiftOAuthClient
import SwiftOAuthIdentity

/// An introspected OAuth access token, resolved to a SwiftIdentity subject.
///
/// The bar is SwiftIdentity's own `ConformanceSuite`, run unchanged — the same one its
/// file-backed store and SwiftWebAuthn's passkey store pass. Everything else here is about the
/// checks the suite cannot know to make: whose token it is, who it is for, and what happens
/// when the authorization server cannot be asked.
///
/// The token and claims in the end-to-end tests are RFC 7662 §2.2's example response, copied
/// from the RFC.
@Suite("SwiftOAuthIdentity — an access token as a SwiftIdentity credential")
struct OAuthIdentityStoreTests {

    static let issuer = "https://server.example.com/"
    static let resource = "https://protected.example.net/resource"
    /// Between the RFC example's `iat` (1419350238) and its `exp` (1419356238).
    static let now = Date(timeIntervalSince1970: 1_419_353_000)

    // MARK: - The suite

    @Test("It passes SwiftIdentity's conformance suite")
    func passesTheConformanceSuite() async throws {
        let mapping = ReferenceCredentialStore(
            subjects: [
                Subject(id: "ada", kind: .person, attributes: ["team": "ops"]),
                Subject(id: "retired", kind: .person, status: .revoked),
                Subject(id: "leaked", kind: .person, status: .honeypot)
            ],
            credentials: [
                (Self.assertion("sub-ada"), "ada", nil),
                (Self.assertion("sub-retired"), "retired", nil),
                (Self.assertion("sub-leaked"), "leaked", nil)
            ],
            throttle: nil,
            now: { Self.now })
        let introspection = ScriptedIntrospection([
            "tok-ada": .active(sub: "sub-ada"),
            "tok-ada-again": .active(sub: "sub-ada"),
            "tok-retired": .active(sub: "sub-retired"),
            "tok-leaked": .active(sub: "sub-leaked"),
            "tok-expired": .active(sub: "sub-ada", expiry: Self.now.addingTimeInterval(-1)),
            "tok-unknown": .inactive
        ])
        let store = try Self.store(introspection: introspection, mapping: mapping)

        let report = await ConformanceSuite(
            store: store,
            fixtures: .init(
                // Revocation and honeypots are the mapping's: this store hands its answer back
                // unaltered, so a revoked or tripwired subject is reported as such. Expiry is
                // this store's own, from the token's `exp`. The external identity is the whole
                // mechanism. Throttling defends a guessable secret, and an access token is not
                // one; passphrases and algorithm records do not apply.
                capabilities: [.revocation, .honeypot, .expiry, .externalIdentity],
                active: .init(
                    id: "ada", credential: OAuthAccessToken("tok-ada"), attributes: ["team": "ops"]),
                refusals: .init(
                    revoked: OAuthAccessToken("tok-retired"),
                    honeypot: OAuthAccessToken("tok-leaked"),
                    expired: OAuthAccessToken("tok-expired"),
                    unknown: OAuthAccessToken("tok-unknown")),
                // A second token for the same provider subject: the local id must not depend
                // on which token proved it.
                externalForActiveSubject: OAuthAccessToken("tok-ada-again"),
                // The active token's value presented as a bearer key. A store matching values
                // regardless of kind would let a token introspected elsewhere stand in for a
                // key this deployment minted.
                activeAsAnotherKind: BearerKey("tok-ada"))
        ).run()

        #expect(report.isConformant, "\(report.summary)")
        #expect(report.gaps.isEmpty, "\(report.summary)")
    }

    // MARK: - Experience B: introspection to the deployment's own roster

    /// RFC 7662 §2.2's example token, introspected, mapped through a `FileCredentialStore`
    /// roster to the local subject, and authenticated by SwiftIdentity's `Authenticator` — the
    /// arrangement SwiftCLIKit's sign-in design calls Experience B.
    @Test("The RFC 7662 example resolves through a FileCredentialStore roster")
    func rfcExampleResolvesThroughTheRoster() async throws {
        let people = try Roster.make(
            subjects: ["ada person active team=ops"],
            verifiers: [("ada", ExternalAssertion(ExternalIdentity(
                issuer: Self.issuer, subject: "Z5O3upPC88QrAjx00dis")))])
        let store = try Self.store(
            introspection: ScriptedIntrospection(["2YotnFZFEjr1zCsicMWpAA": .rfcExample]),
            mapping: people.store)
        let authenticator = Authenticator(stores: [people.store, store], audit: nil, now: { Self.now })

        let authentication = await authenticator.authentication(
            for: [OAuthAccessToken("2YotnFZFEjr1zCsicMWpAA")])

        #expect(authentication?.subject.id == "ada")
        #expect(authentication?.subject.attributes == ["team": "ops"])
        #expect(authentication?.factors.map(\.kind) == [OAuthAccessToken.kind])
    }

    /// The mapping is asked with the issuer this store was configured with and the `sub` the
    /// server returned, and with nothing taken from the token itself.
    @Test("The mapping is asked about (configured issuer, introspected sub)")
    func mappingIsAskedTheRightQuestion() async throws {
        let mapping = RecordingMapping()
        let store = try Self.store(
            introspection: ScriptedIntrospection(["2YotnFZFEjr1zCsicMWpAA": .rfcExample]),
            mapping: mapping)

        _ = await store.resolve(OAuthAccessToken("2YotnFZFEjr1zCsicMWpAA"))

        #expect(await mapping.asked == [
            ExternalIdentity(issuer: "https://server.example.com/", subject: "Z5O3upPC88QrAjx00dis")
        ])
    }

    // MARK: - What the store checks before the mapping is asked

    /// Each answer an authorization server can give that must not produce a subject, the
    /// outcome the service is told, and the reason the operator is told. The caller is told
    /// none of it — `subject(for:)` is nil for every one.
    static let refusals: [(String, ScriptedIntrospection.Answer, IdentityEvent.Outcome, OAuthIdentityRefusal)] = [
        ("inactive", .inactive, .unknown, .inactive),
        ("expired", .active(sub: "sub-ada", expiry: now.addingTimeInterval(-1)), .expired, .expired),
        ("expiring this instant", .active(sub: "sub-ada", expiry: now), .expired, .expired),
        ("no subject", .active(sub: nil), .unknown, .noSubject),
        ("an empty subject", .active(sub: ""), .unknown, .noSubject),
        ("for another resource", .active(sub: "sub-ada", audience: ["https://elsewhere.example"]),
         .unknown, .audienceMismatch),
        ("for no resource", .active(sub: "sub-ada", audience: nil), .unknown, .audienceMismatch),
        ("from another issuer", .active(sub: "sub-ada", issuer: "https://other.example.com/"),
         .unknown, .issuerMismatch),
        ("an unreachable server", .status(503), .unknown, .introspectionFailed),
        ("an unreadable answer", .body("not json"), .unknown, .introspectionFailed),
        ("a transport that throws", .throwing, .unknown, .introspectionFailed)
    ]

    @Test("A token that must not resolve is refused, and only the service learns why",
          arguments: refusals)
    func tokenIsRefused(
        _ label: String, answer: ScriptedIntrospection.Answer,
        outcome: IdentityEvent.Outcome, reason: OAuthIdentityRefusal
    ) async throws {
        let mapping = RecordingMapping()
        let audit = RecordingAudit()
        let observed = Observed()
        let store = try Self.store(
            introspection: ScriptedIntrospection(["presented": answer]), mapping: mapping,
            audit: audit, onRefusal: observed.record)

        let resolution = await store.resolve(OAuthAccessToken("presented"))

        #expect(resolution == .refused(outcome), "\(label)")
        #expect(await store.subject(for: OAuthAccessToken("presented")) == nil, "\(label)")
        #expect(observed.reasons.first == reason, "\(label)")
        #expect(await mapping.asked.isEmpty, "\(label): the mapping was asked about a token that was refused")
        #expect(await audit.events.first?.outcome == outcome, "\(label)")
        #expect(await audit.events.first?.credentialKind == OAuthAccessToken.kind, "\(label)")
    }

    /// RFC 7662 §2.2 makes `iss` optional. Absent, the answer speaks for the issuer whose
    /// endpoint gave it — the one this store was configured with.
    @Test("An answer that names no issuer is taken to be the configured issuer's")
    func absentIssuerIsTheConfiguredOne() async throws {
        let mapping = RecordingMapping()
        let store = try Self.store(
            introspection: ScriptedIntrospection(["presented": .active(sub: "sub-ada", issuer: nil)]),
            mapping: mapping)

        _ = await store.resolve(OAuthAccessToken("presented"))

        #expect(await mapping.asked == [ExternalIdentity(issuer: Self.issuer, subject: "sub-ada")])
    }

    /// A deployment that does not check audiences says so by name, at the call site.
    @Test("An audience that is not checked is not checked")
    func uncheckedAudience() async throws {
        let mapping = RecordingMapping()
        let store = try Self.store(
            introspection: ScriptedIntrospection(["presented": .active(sub: "sub-ada", audience: nil)]),
            mapping: mapping, audience: .notChecked)

        #expect(await store.resolve(OAuthAccessToken("presented")) == .verified(RecordingMapping.subject))
    }

    /// A token with several audiences is for each of them.
    @Test("One audience among several is enough")
    func audienceAmongSeveral() async throws {
        let mapping = RecordingMapping()
        let store = try Self.store(
            introspection: ScriptedIntrospection([
                "presented": .active(sub: "sub-ada", audience: ["https://a.example", Self.resource])
            ]),
            mapping: mapping)

        #expect(await store.resolve(OAuthAccessToken("presented")) == .verified(RecordingMapping.subject))
    }

    // MARK: - What the mapping says is final

    /// A refusal from the mapping is handed back as the mapping gave it — a honeypot is still a
    /// honeypot when it was reached through a token — and audited with that outcome.
    @Test("The mapping's refusal is passed through, and audited", arguments: [
        IdentityEvent.Outcome.revoked, .honeypot, .unknown, .expired
    ])
    func mappingRefusalPassesThrough(_ outcome: IdentityEvent.Outcome) async throws {
        let audit = RecordingAudit()
        let store = try Self.store(
            introspection: ScriptedIntrospection(["presented": .active(sub: "sub-ada")]),
            mapping: RecordingMapping(answer: .refused(outcome)), audit: audit)

        #expect(await store.resolve(OAuthAccessToken("presented")) == .refused(outcome))
        #expect(await audit.events.map(\.outcome) == [outcome])
    }

    @Test("A verified resolution is audited with the subject")
    func verifiedIsAudited() async throws {
        let audit = RecordingAudit()
        let store = try Self.store(
            introspection: ScriptedIntrospection(["presented": .active(sub: "sub-ada")]),
            mapping: RecordingMapping(), audit: audit)

        _ = await store.resolve(OAuthAccessToken("presented"))

        let event = try #require(await audit.events.first)
        #expect(event.outcome == .verified)
        #expect(event.subjectID == RecordingMapping.subject.id)
        #expect(event.credentialKind == "oauth-access-token")
        #expect(event.at == Self.now)
    }

    // MARK: - Other kinds

    /// Another kind is not this store's to judge. It is refused as unknown — which is how an
    /// `Authenticator` moves on to the next store — without asking the authorization server
    /// and without an audit entry for every request some other store answers.
    @Test("Another kind of credential is refused without asking anyone")
    func otherKindsAreNotIntrospected() async throws {
        let introspection = ScriptedIntrospection(["tok": .active(sub: "sub-ada")])
        let audit = RecordingAudit()
        let store = try Self.store(introspection: introspection, mapping: RecordingMapping(), audit: audit)

        for credential in [BearerKey("tok"), SessionToken("tok"), CapabilityToken("tok")] as [any Credential] {
            #expect(await store.resolve(credential) == .refused(.unknown))
        }
        #expect(await store.resolve(ExternalAssertion(
            ExternalIdentity(issuer: Self.issuer, subject: "sub-ada"))) == .refused(.unknown))
        #expect(await introspection.asked.isEmpty)
        #expect(await audit.events.isEmpty)
    }

    /// The token is a bearer credential. It reaches the authorization server and nothing
    /// else: not a log line built by interpolation, not the audit, not the observer.
    @Test("The token is not written anywhere it could be read back")
    func tokenIsRedacted() async throws {
        let presented = "fixture-access-value-0123456789"
        let audit = RecordingAudit()
        let observed = Observed()
        let store = try Self.store(
            introspection: ScriptedIntrospection([presented: .inactive]), mapping: RecordingMapping(),
            audit: audit, onRefusal: observed.record)

        _ = await store.resolve(OAuthAccessToken(presented))

        let token = OAuthAccessToken(presented)
        let rendered = [
            "\(token)", String(reflecting: token),
            "\(await audit.events)", "\(observed.reasons)"
        ]
        for text in rendered {
            #expect(!text.contains(presented), "the token appeared in: \(text)")
        }
    }

    // MARK: - Fixtures

    static func assertion(_ subject: String) -> ExternalAssertion {
        ExternalAssertion(ExternalIdentity(issuer: issuer, subject: subject))
    }

    static func store(
        introspection: ScriptedIntrospection,
        mapping: any CredentialStore,
        audience: AudienceRequirement = .mustInclude(resource),
        audit: (any IdentityAudit)? = nil,
        onRefusal: OAuthIdentityStore.RefusalObserver? = nil
    ) throws -> OAuthIdentityStore {
        let introspector = TokenIntrospector(
            endpoint: try #require(URL(string: "https://server.example.com/introspect")),
            credentials: .init(clientId: "resource-server", clientSecret: "fixture-passphrase"),
            transport: introspection)
        return OAuthIdentityStore(
            introspector: introspector,
            issuer: issuer,
            audience: audience,
            mapping: mapping,
            audit: audit,
            now: { now },
            onRefusal: onRefusal)
    }
}

/// An introspection endpoint that answers from a table, by token.
actor ScriptedIntrospection: IntrospectionTransport {

    /// One scripted answer.
    enum Answer: Sendable {
        /// RFC 7662 §2.2's example response, verbatim.
        case rfcExample
        /// `{"active":false}`.
        case inactive
        /// An active token, with the claims given. The audience defaults to the resource the
        /// tests protect; the expiry to an hour after the test clock.
        case active(sub: String?, audience: [String]? = [OAuthIdentityStoreTests.resource],
                    issuer: String? = OAuthIdentityStoreTests.issuer,
                    expiry: Date = OAuthIdentityStoreTests.now.addingTimeInterval(3600))
        /// A status with no body.
        case status(Int)
        /// A `200` with this body.
        case body(String)
        /// The request fails.
        case throwing
    }

    static let rfcExampleBody = """
         {
          "active": true,
          "client_id": "l238j323ds-23ij4",
          "username": "jdoe",
          "scope": "read write dolphin",
          "sub": "Z5O3upPC88QrAjx00dis",
          "aud": "https://protected.example.net/resource",
          "iss": "https://server.example.com/",
          "exp": 1419356238,
          "iat": 1419350238,
          "extension_field": "twenty-seven"
         }
        """

    private let answers: [String: Answer]
    private(set) var asked: [String] = []

    init(_ answers: [String: Answer]) {
        self.answers = answers
    }

    func post(url: URL, body: String, authorization: String?) async throws -> (Data, Int) {
        let token = body.hasPrefix("token=")
            ? String(body.dropFirst("token=".count)).removingPercentEncoding ?? ""
            : ""
        asked.append(token)
        switch answers[token] ?? .inactive {
        case .rfcExample:
            return (Data(Self.rfcExampleBody.utf8), 200)
        case .inactive:
            return (Data(#"{"active":false}"#.utf8), 200)
        case .active(let sub, let audience, let issuer, let expiry):
            let result = IntrospectionResult(
                active: true, scope: "read", clientId: "cli", subject: sub, audience: audience,
                expiry: expiry, issuer: issuer)
            return (try JSONEncoder().encode(result), 200)
        case .status(let code):
            return (Data(), code)
        case .body(let text):
            return (Data(text.utf8), 200)
        case .throwing:
            throw URLError(.cannotConnectToHost)
        }
    }
}

/// A mapping that records what it was asked and answers as told.
actor RecordingMapping: CredentialStore {
    static let subject = Subject(id: "local-ada", kind: .person, attributes: ["team": "ops"])

    private let answer: Resolution
    private(set) var asked: [ExternalIdentity] = []

    init(answer: Resolution = .verified(RecordingMapping.subject)) {
        self.answer = answer
    }

    func resolve(_ credential: any Credential) async -> Resolution {
        guard let assertion = credential as? ExternalAssertion else { return .refused(.unknown) }
        asked.append(assertion.identity)
        return answer
    }
}

/// Keeps every audit event.
actor RecordingAudit: IdentityAudit {
    private(set) var events: [IdentityEvent] = []

    func record(_ event: IdentityEvent) async {
        events.append(event)
    }
}

/// Keeps every refusal reason the store reports to the operator.
// Justification: `stored` is read and written only under `lock`.
final class Observed: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [OAuthIdentityRefusal] = []

    var reasons: [OAuthIdentityRefusal] {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    var record: OAuthIdentityStore.RefusalObserver {
        { [self] reason in
            lock.lock()
            defer { lock.unlock() }
            stored.append(reason)
        }
    }
}

/// A `FileCredentialStore` written to a fresh directory, owner-only as it requires.
struct Roster {
    let store: FileCredentialStore

    static func make(subjects: [String], verifiers: [(String, any Credential)]) throws -> Roster {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("swift-oauth-identity-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let lines = try verifiers.map { subject, credential in
            let digest = try #require(FileCredentialStore.storedDigest(for: credential))
            return "\(subject) \(credential.kindName) \(digest)"
        }
        for (name, text) in [
            (FileCredentialStore.subjectsFile, subjects.joined(separator: "\n")),
            (FileCredentialStore.verifiersFile, lines.joined(separator: "\n"))
        ] {
            let path = directory.appendingPathComponent(name).path
            try Data((text + "\n").utf8).write(to: URL(fileURLWithPath: path))
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
        }
        return Roster(store: try FileCredentialStore(directory: directory.path))
    }
}
