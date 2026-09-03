# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] — 2026-09-03

RFC 7662 token introspection, both halves, and `WWW-Authenticate` parsing.

### Additive — but read this if you are on 0.7.x

**Coming from 0.8.0:** everything here is additive. New types, new methods, no changed
signatures, no tightened defaults, no schema change. A bound raise and nothing else.

**Coming from 0.7.x:** everything in 0.8.0's notes applies to you as well. This release adds
nothing on top of it, but there is no route to 0.9.0 except through 0.8.0, so you still take its
client refusals on the way through. Read that entry first; this one adds no migration of its
own.

The distinction matters because of who is likely to be reading. Anyone who followed 0.8.0's
advice and bounded their dependency is sitting at 0.7.1 — a population that release's own
warning created. **An additive release is only additive relative to a baseline, and the baseline
worth stating is the one consumers are actually on, which after a breaking release is the
version before it rather than the version after.** Bounded consumers accumulate at the last safe
version, which is exactly where a "nothing to plan around" note is least true.

### Added
- **`IntrospectionResult`** (Core) — RFC 7662's response. An expired, revoked or unknown token
  is `active: false`, **not** an error. That is §2.2 and it is the distinction implementations
  most often get wrong: a server answering `401` for an expired token makes every caller treat
  "this token is no good" as a transport failure, handled elsewhere, usually with a retry that
  cannot help.

  An inactive response carries nothing else — not scope, not client, not subject. A caller
  holding a dead token has proven nothing, and a response with claims in it is an oracle for
  probing tokens that are not theirs.

  `aud` decodes as a string or an array, per RFC 7519 §4.1.3. Handling one shape fails against
  half the providers in existence, at the moment a token is being checked.

- **`OAuthServer.introspect(token:)`** and **`OAuthHTTPHandler.handleIntrospectionRequest`**
  (Provider). The endpoint is authenticated, as §2.1 requires: left open it tells anyone whether
  any string is a live token, which turns a stolen token into a verified one and gives guessing
  a feedback signal. Authentication is checked before the token is looked at.

- **`TokenIntrospector`** (Client) — for a resource server validating a token it was handed. An
  inactive answer is returned, not thrown, so a caller can tell a revoked token from an
  unreachable server. The token travels in a form body, never a URL, because a token in a query
  string is a token in every log that records a path.

- **`BearerChallenge`** (Client) — `WWW-Authenticate` parsing, RFC 6750 §3. Asks for **exactly**
  the scopes the challenge names, not those added to what is already held: unioning them widens
  the grant on every `401` while each individual step looks like it is only asking for what it
  was told.

  Its parser scans rather than splitting on commas, because `error_description="Expired, please
  retry"` is a legal header that the obvious implementation truncates while inventing a
  parameter from the tail.

  It also reads RFC 9728's `resource_metadata` pointer, which closes the loop with RFC 8707: a
  client refused for naming no resource can follow it to find the identifier to send. The
  pointer is parsed, never fetched — following it would turn reading a header into a request to
  an address the header chose.

## [0.8.0] — 2026-09-03

### Read this first: taking 0.8.0 refuses every existing client

Not a configuration change — a deployment-ordering one. **A server that upgrades starts
refusing every client that does not send `resource`, which is every client written before this
release.** Verified from outside this package: SwiftMCPServer's Sources compiled completely
unchanged and its OAuth suite then failed six ways, all standard authorization-code exchanges
that send no resource indicator.

The server needs no configuration. Its clients all need a code change. For a server package
that is the harder half, because the operator taking the bump is usually not the person who
controls the clients.

If you cannot migrate clients at the same time, stage it deliberately:

```swift
OAuthServer(storage: storage, issuer: issuer,
            resourcePolicy: ResourceIndicatorPolicy(known: [...], allowsUnspecified: true))
```

That accepts requests naming no resource while you migrate, and tightens later by removing the
flag. It is the supported staging path, not a workaround — but it is opt-in on purpose, so that
a server issuing tokens good at every resource is a decision someone made rather than one they
inherited.

### Breaking, and it affects you even if you never touch resource indicators

**`TokenValidationResult.valid` gains a third associated value, `audience: URL?`.** Every
exhaustive pattern match on it must add a binding:

```swift
if case .valid(let clientId, let scope) = result        // before
if case .valid(let clientId, let scope, _) = result     // after
```

Seven sites across two packages so far — four here, three in SwiftMCPServer — none in
production sources, all in tests. Mechanical, but not nothing, and it hits consumers who have
no interest in RFC 8707 at all, which is why it leads.

Taken before 1.0 deliberately: after 1.0 it costs a major version.

### Also breaking: your database is migrated on first open
There was no migration mechanism before this release, so this is the first one. It is additive
and idempotent, and reopening an already-migrated database is tested — but it changes data you
own, on disk, and you should know before taking the bump. `:memory:` users are unaffected.

---

The RFC 8707 provider half. The client has sent `resource` since 0.7.0 and no server built on
this package read it — the asymmetry this release exists to close.

### Added
- **`ResourceIndicatorPolicy`** decides what a token is *for*. A known resource becomes the
  audience; an unknown one is refused with RFC 8707 §2's own `invalid_target`. Several distinct
  resources are refused rather than narrowed to the first, which would issue a token for an
  audience the client never asked for on its own. The same resource repeated is one audience,
  not an ambiguity.

  Prefer `.protecting(_:)`. The value it wants is the one the server already publishes as
  `resource` in its RFC 9728 metadata, and a hand-written policy that disagrees produces a
  server advertising a resource and refusing it — breaking the most conformant clients first,
  since they read the metadata and obeyed it.

- **`OAuthError.invalidTarget`**, mapping to 400. Distinct from `invalidScope` deliberately: a
  scope names what may be done, a resource names where. A client told its scope was wrong
  retries with different scopes and fails again, never learning the audience was the problem.

- **Issued tokens carry their audience**, and `TokenValidationResult.valid` reports it. Checked
  on refresh as well as on issue — a token that could shed its audience by being refreshed
  would be bound only until its first renewal.

- **A schema migration mechanism.** There was none: the schema is built with
  `CREATE TABLE IF NOT EXISTS`, so a column added to an existing table never appeared, and the
  failure would be a query naming a missing column at runtime, on deployed installations only,
  never in a test starting from `:memory:`. `PRAGMA user_version` now carries a version.

  The `CREATE` deliberately omits the new column, so every database — new or existing — arrives
  through the migration path rather than only upgrades taking it.

### Changed
- **The default is strict.** A request naming no resource is refused. Accepting it would make
  the safe configuration the one an operator has to go and find. `allowsUnspecified: true` is
  the opt-out.

- **`TokenValidationResult.valid` gains `audience`** — a source break for anyone matching it
  exhaustively. Taken now because after 1.0 it costs a major version.

- **`TokenRequest` gains `resource`**, defaulted, and the token endpoint reads repeats.
  `parseFormBody` keeps one value per key, which is right for OAuth's singular parameters and
  wrong for `resource`: a request naming two would have become a request naming the last, making
  the refusal of several unreachable from a real request.

### Known limitation
**Validation happens at the token endpoint, not the authorization endpoint.** RFC 8707 §2 has
the client send `resource` on both, and the refusal text says so because that is what a client
should do and it is forward-compatible. But `/authorize` currently accepts the parameter
without validating it or binding it to the authorization code, so the audience is decided when
the token is issued rather than when the code is granted.

The practical difference: a client can be granted a code and only then discover its resource is
unknown. Nothing is issued wrongly — the token endpoint still refuses — but the error arrives a
round trip later than it needs to. Closing it means carrying an audience on the authorization
code, which is a second schema change and its own release.

### Migration
On the server: raise the bound, update any `case .valid(_, _)` patterns to
`case .valid(_, _, _)`, and let the database migrate on first open. No configuration is needed
if you already serve correct protected-resource metadata — the policy defaults to your issuer.

On every client: send `resource`. This is the part that is not mechanical, and the part to plan
the rollout around. On this package's client it is `ProviderConfiguration.resource`, shipped in
0.7.0. Until a client sends it, that client is refused. Clients must send `resource`; on this package's client that
is `ProviderConfiguration.resource`, shipped in 0.7.0. A client that sends nothing is refused
with a description naming the value to send.

Note that `from: "0.7.1"` on a 0.x package is up-to-next-major, so 0.8.0 satisfies it. A
deployment relying on the permissive behaviour should bound its dependency before upgrading.

## [0.7.1] — 2026-09-02

Authorization changes required by MCP `2026-07-28`.

### Added
- **RFC 9207 issuer identification.** `AuthorizationResponse` carries the issuer that produced
  the code. A client validates it against the issuer it recorded before redeeming: without it, a
  code issued by one authorization server can be replayed against another the client also trusts.
- **`application_type` in Dynamic Client Registration**, `web` or `native`, defaulting to `web`
  per RFC 7591. Recorded on the client and echoed in the registration response, so a client can
  confirm the server stored what it declared — a silent disagreement is the redirect-URI conflict
  the field exists to prevent.
- **`ClientIDMetadataDocument`**, which MCP `2026-07-28` prefers over DCR. A client *is* an https
  URL and publishes its metadata there. The self-reference check — the document's `client_id`
  must equal the URL it was fetched from — is load-bearing: without it any host could publish a
  document claiming to be someone else's client. A metadata-document client is public by
  construction and registers with `token_endpoint_auth_method` `none`.

- **Fetching a metadata document, with an SSRF-safe policy.** The fetch is an authentication
  control, not plumbing: the document decides *who a client is*, so a permissive fetch lets an
  attacker point the authorization server at a document of their choosing, or at an internal
  address it can reach and they cannot.

  https only, refused **before any request is made** — a test asserts the transport was never
  called for a rejected scheme. The identifier is validated as `URLComponents` and only then
  turned into a `URL`, so an uncleared identifier never becomes fetchable. Redirects are not
  followed and the transport is documented as forbidden from following them, because that
  decision must live in one place. Private, loopback and link-local addresses are refused,
  `169.254.169.254` among them. A 64KB cap bounds the read. The self-reference check still
  applies after fetching.

  Twelve adversarial cases, written before the implementation existed; the happy path is one of
  them. **Known limitation, documented on the type:** host checks apply to the URL, so a
  hostname that *resolves* to a private address is not caught. Closing DNS rebinding needs
  resolve-check-pin-and-connect, so a deployment treating untrusted identifiers as reachable
  should also restrict egress at the network layer.

### Fixed
- **`RegisteredClient` decodes records written before `application_type` existed.** The
  synthesized decoder made the new field required, which would have made every client already
  persisted in SQLite undecodable — the store would have lost every registration it held. An
  existing `OAuthModelsTests` decode caught it.

## [0.7.0] — 2026-09-01

### Fixed
- **This package did not compile on Linux at all.** Two files, and neither failure could show
  up on a Mac: `TokenTransport` uses `URLSession` and `URLRequest`, which live in
  `FoundationNetworking` rather than `Foundation` there; and `EncryptedFileClientStorage` logs
  through `os.Logger`, which is Apple-only, with the import guarded and every call site not.

  `URLSessionTokenTransport` is now `@unchecked Sendable`: `URLSession` is thread-safe and
  documented as such, but corelibs-foundation does not mark it `Sendable`, so the stored
  property passed on Apple platforms and failed on Linux alone.

  Found by SwiftMCPClient's CI, which had been **disabled at the repository level since
  2026-07-04** and was re-enabled 2026-09-01. Eighty-six errors, all of them here and none in
  the client.

  Logging on Linux is absent rather than replaced. What a caller acts on is the thrown error,
  which is identical everywhere; only the operator's breadcrumb is missing, and four lines did
  not justify a logging dependency.

### Added
- **RFC 8707 resource indicators.** `ProviderConfiguration.resource` names the API a token is
  *for*, and it is sent on the authorization request, the code exchange, and every refresh —
  §2 requires all three, and a token refreshed without it can come back audienced to something
  else, surfacing as `invalid_audience` at the resource long after the sign-in that would
  explain it.

  Without this a token is audience-less: an authorization server protecting several resources
  issues something all of them accept, so a token obtained for one service can be replayed
  against another.

  **MCP's 2025-06-18 revision requires clients to send it**, naming the canonical URI of the
  MCP server — so until now every MCP client built on this package was non-conformant with the
  revision it was otherwise implementing. `master_plan.md` had recorded the gap since the
  package was extracted.

  The value is normalised on the way in: RFC 8707 §2 requires an absolute URI with no fragment,
  and a fragment is a client-side concept the server never sees. A query string is kept, being
  part of what identifies the resource. One resource rather than several — the RFC permits the
  parameter to repeat, and token requests here carry form parameters as a dictionary, which
  cannot express a repeated key.

  Additive: a defaulted initialiser parameter, `nil` reproducing today's behaviour exactly.
  Six tests, written first.

## [0.6.0] — 2026-09-01

### Added
- **`OAuthConnection.refreshedAccessToken()` — refresh now, whatever the clock says.**
  `validAccessToken()` refreshes on expiry, which handles every case it can see. It cannot
  see the provider deciding a still-valid-looking token is no longer honoured: a revoked
  grant, a drifted clock, a dynamic client registration that expired underneath the
  credential it issued (RFC 7591 `client_secret_expires_at`). In all of those the only
  evidence is a `401` from an API call, and the only recovery is an exchange the local clock
  says is unnecessary.

  Requested by SwiftMCPClient, which cannot recover from a rejected token without it — a
  transport that refreshes only on predicted expiry has no answer to a server that refuses
  a token the clock says is fine.

  It joins a refresh already in flight rather than starting a second, including an ordinary
  one, because racing an exchange invalidates the token that exchange is about to return.
  A refusal arrives as `ConnectionError.reauthorizationRequired(hadPreviousToken:)`, which
  is the distinction a caller acts on: a revoked grant and a lost rotation need opposite
  responses. Deliberately **not** a routine call — against a rotating provider, forcing a
  refresh on a healthy connection spends a rotation for a token no better than the one held.

  Seven tests, written first.

## [0.5.0] — 2026-08-28

### Added
- **A DocC catalogue for each library.** The package has depended on
  `swift-docc-plugin` since before any of this and `master_plan.md` commits to "DocC on
  public types", but no target owned a catalogue, so `doc-lint` had nothing to examine
  and said so rather than passing vacuously.

  Each landing page says what the module is *for* and groups its symbols under headings
  that name the job rather than the kind — "Authorizing", "Persisting what comes back",
  "What the server refuses" — because a topic list sorted by `struct`/`enum`/`protocol`
  tells a reader what the compiler already told them.

  The catalogues are declared as `resources: [.copy(...)]`, not `exclude:`.
  `swift-docc-plugin` locates a catalogue through the target's `sourceFiles`, which
  `exclude:` removes it from — so excluding would have silenced SwiftPM's unhandled-file
  warning by handing DocC nothing, and `doc-lint` would then have gone green over an
  article it never opened.

### Fixed
- **Fourteen broken documentation links**, invisible until `doc-lint` had a catalogue to
  run against. Five were `` ``OAuthError`` `` and one `` ``ClientAuthenticationMethod`` ``
  written as symbol links from `SwiftOAuthClient` to types that live in
  `SwiftOAuthCore` — DocC resolves per module, so a link across one silently resolves to
  nothing. Those are now plain code spans, which say the same thing and claim less. The
  rest were stale: `exchange(authorizationCode:verifier:)` and
  `fromEnvironment(provider:environment:reading:)` had both grown a parameter since the
  sentences pointing at them were written, and a `- Parameters:` entry documented
  `replacing`, the argument label, where DocC wants `previous`, the name.

- **Storage tests generate their tokens instead of imitating them.** Eight fixtures were
  hand-written strings shaped like the real thing — `"mcp_at_test_token_12345"` against
  `TokenGenerator.generateAccessToken()`'s `mcp_at_` + 32 bytes. They now call the
  generator, so the storage layer is exercised against the token shape it will actually
  be given, and the fixture cannot drift from the format if it changes.

- **`createsFileBasedDatabase` uses the URL-native `FileManager` API.** `atPath:` takes a
  path string that has already lost what the `URL` knew about itself; `removeItem(at:)`
  and `checkResourceIsReachable()` do not.

- **Every `## Usage` example compiles.** Nine `doc-comment-code` errors, surfaced
  when that checker briefly entered the default set upstream. They had been wrong
  for as long as they existed.

  `PKCE` and `TokenGenerator` referred to values a server receives —
  `receivedVerifier`, `storedChallenge`, `provided` — without saying where they
  come from. Each is now bound to the value generated earlier in the same fence,
  which also makes the round trip visible: the verifier the client kept is the one
  the server checks against the challenge it stored.

  `OAuthServer` and `OAuthStorage` now take their request objects and client as
  function parameters rather than conjuring them. Constructing a
  `ClientRegistrationRequest`, an `AuthorizationRequest` and a `TokenRequest`
  inline would have buried what the examples are about — what the server *does*
  with a request, not how one is parsed off the wire.

- **Every force unwrap in the test suite is now `try #require`.** Twenty-five
  `safety` errors, all in `Tests/`. The note that recorded them argued that a force
  unwrap in a test is often deliberate — a nil there should fail loudly — and under
  XCTest that would be right. Under swift-testing with `--parallel` it is not: a trap
  takes down the entire runner, so one nil fails all four targets and reports a stack
  frame instead of an assertion. `rules/test_driven_development.md` says exactly this,
  and the suite had already decided — 23 `try #require` calls across six files.
  `OAuthHTTPHandlerTests.swift` was simply the file that never got converted. So this
  was not a style decision left open; it was a conversion left unfinished.

  Ten of the twenty-five were `String.data(using: .utf8)!`, which cannot return nil for
  any Swift string. Those became `Data(_:utf8)` — non-optional, and one less line that
  reads like a risk is being taken where none is.

- **`TestClock`'s `@unchecked Sendable` justification now sits where the auditor looks
  for it**, directly above the declaration rather than as the first line of the type
  body. The reasoning was recorded from the start; only its placement was wrong.

### Fixed (gate)
- **`--check all` passes: 45 of 45 checkers, 0 errors, 0 warnings.** It had never run to
  the end before — `[safety]` stopped it, and the 39 checkers behind the stop had never
  reported at all. Getting there took 25 force unwraps, 2 errors that only became visible
  once the run reached them, 14 stale doc links, three missing DocC catalogues, and
  18 `[safety]` warnings.

  Of those 18: ten were real and were fixed. Four went to changes worth making anyway —
  two redirect-mismatch tests now use `https://attacker.example`, since the point of
  those tests is a URI that does not match the one registered, the scheme was never
  the point, and `attacker.example` is reserved by RFC 2606 where `evil.com` is a domain
  somebody owns.

  The last four carry a `// SECURITY:` justification, which is what that mechanism is
  for. All four are on **negative tests** — where the bad practice is the *input*,
  because the code under test exists to refuse it, and no scanner reading `Tests/` can
  tell "does X" from "proves X is rejected":

  - Two insecure `http://` URLs in `DiscoveryTests` that
    `#expect(throws: DiscoveryError.insecureEndpoint(...))` proves are refused. Rewriting
    either to `https://` would assert that a *valid* endpoint is rejected.
  - A four-line test helper that parses a callback literal into a `URL` and issues no
    request, flagged as SSRF.
  - `let credentials = "\(client.clientId):\(clientSecret)"`, flagged as a hardcoded
    secret on the strength of the variable's name; the value is interpolated from a
    secret `registerClient` generated three lines earlier.

  Each justification says which of those it is. That is the difference between a
  justification and a suppression: the comment has to be true, and a reader can check it.

  One thing worth keeping from the attempt to avoid needing them: binding a discovery URL
  to a constant named `tokenEndpoint` cleared an `insecure-transport` warning and raised a
  `hardcoded-secret` one, because the new name contained "token". Renaming code to satisfy
  a matcher moves findings around; it does not remove them.

## [0.4.0] — 2026-08-06

### Added
- **`GrantType.clientCredentials`** — RFC 6749 §4.4, the standard grant for
  machine-to-machine access. Previously excluded alongside the two grants OAuth 2.1
  removes, which conflated two different things: implicit and password are unsafe,
  while client credentials is simply user-less by design. Excluding it made the client
  half unable to consume a large class of third-party APIs that offer no alternative.
  **Client-side only** — `OAuthServer` dispatches on the raw wire string and still
  returns `unsupported_grant_type`, now pinned by `ProviderRejectsClientCredentials`.
- **iOS support** — the package declares `.iOS(.v17)` alongside macOS. The client half
  depends only on Foundation and Crypto, so it runs wherever Swift does; the provider
  half is simply never built for iOS because nothing there depends on it.

### Added (previously unreleased)
- **`EncryptedFileClientStorage`** — the persistent counterpart to the in-memory store, so an
  application need not make its user authorise again after a restart. AES-GCM over the whole
  file, so which providers a user has connected is not readable either
- A wrong key or a tampered file **throws** rather than reading as empty: an empty read looks
  like a first run, and a first run invites a caller to overwrite a file it could not read

## [0.3.0] — 2026-08-06

### Added
- **The authorization half of the client.** `beginAuthorization(redirectURI:)` generates the
  state and PKCE pair; `completeAuthorization(callback:pending:)` validates the callback and
  exchanges the code. The `state` is compared first, in constant time, and a duplicated one
  resolves first-occurrence-wins so an appended value cannot override the real one
- **Discovery (RFC 8414) and dynamic client registration (RFC 7591).** A client pointed at an
  arbitrary server has no pre-registered credentials, so both are unavoidable rather than
  conveniences
- Discovered endpoints are **bound to the issuer's origin**, host and port. Without it a
  fetched metadata document is an instruction to post an authorization code, a client secret
  and a refresh token to whatever host it names
- **A conformance test target.** The two halves do not depend on each other, so nothing
  checked they agreed on the wire; each had passed its own suite against its own idea of the
  format

### Fixed
- `OAuthError` declared `Codable` but used the synthesized conformance, which for an enum with
  associated values emits `{"invalidRequest":{"_0":…}}` — valid JSON that no OAuth peer can
  read

## [0.2.0] — 2026-08-06

`SwiftOAuthProvider`, extracted from SwiftMCPServer.

### Added
- **`SwiftOAuthProvider`** — extracted from SwiftMCPServer: authorization server, HTTP
  handler, consent page, SQLite storage. 114 tests moved with it
- `OAuthError.standardDescription` — the RFC 6749 §5.2 meaning of a code, emitted when no
  specific detail was supplied

### Fixed
- `OAuthError` declared `Codable` but used the *synthesized* conformance, which for an enum
  with associated values emits `{"invalidRequest":{"_0":…}}` — valid JSON that no OAuth peer
  can read. Now encodes `{"error":…,"error_description":…}` as RFC 6749 §5.2 requires

### Changed
- The authorization endpoint **refuses `code_challenge_method=plain`**, and metadata no
  longer advertises it. Anything unrecognised is refused too, rather than falling through
  to S256
- The provider's duplicate `OAuthError` and `TokenResponse` are gone; both halves now share
  Core's. They were ambiguous for any consumer linking both

### Added
- **`SwiftOAuthCore`** — PKCE, token generation, `TokenResponse`, `OAuthError`, grant types.
  28 tests
- PKCE verified against **RFC 7636 Appendix B's published vectors** rather than against
  itself: a wrong derivation still round-trips internally while failing every real server
- `plain` removed as a challenge method. Under it the challenge *is* the verifier, so an
  attacker who intercepts the authorization request holds everything needed to redeem the
  code — the attack PKCE exists to prevent
- Implicit and password grants are **absent** rather than rejected, so a provider built on
  this cannot accidentally support them and a client cannot request them
- `TokenResponse` carries `x_refresh_token_expires_in`, which RFC 6749 does not define but
  Intuit and others send; a client that ignores it cannot tell a lapsing connection from a
  healthy one

### Decided
- **SwiftMCPClient is the harness for the client half**, as SwiftMCPServer is the control for
  the provider half. They implement opposite roles of the same protocol, so once both adopt
  this package the client can authorise against the provider in-process — a full
  authorization-code exchange with PKCE, a refresh, and a rotation, offline and
  deterministic. Better than a mock, because neither side is a stub written to agree with the
  other
- The weakness is recorded rather than assumed: a closed loop can be mutually conformant and
  both wrong. Two external anchors already exist — the client half faces Intuit through
  LedgeOS, the provider half faces Claude connecting to the user's MCP servers

## [0.1.0] — 2026-08-06

First tagged release: `SwiftOAuthCore` and the client half.

### Added
- **`SwiftOAuthClient`** — `OAuthConnection`, a rotation-safe token lifecycle behind one
  method, `validAccessToken()`. Concurrent refreshes join one exchange rather than racing;
  credentials persist before the new access token is returned; a failed write hands the
  credential back inside the error rather than losing it
- `OAuthClientStorage` as a protocol, with in-memory and deliberately-failing implementations
- Credential variables namespaced by application as well as provider and environment

## [0.0.1] — 2026-08-06

Scaffold and design. Nothing is implemented.

### Added
- Project scaffold: three targets — `SwiftOAuthCore`, `SwiftOAuthProvider`,
  `SwiftOAuthClient` — with neither half depending on the other
- `project/plans/proposals/SwiftOAuthDesign.md`, the full design: two storage protocols
  rather than one, `consume` rather than get-then-delete for single-use artifacts, and the
  three refresh-rotation hazards the client half exists to handle
- `project/master_plan.md`

### Decided
- **OAuth 2.0 on the wire, OAuth 2.1 semantics by policy.** The inherited implementation
  already meets four of 2.1's six changes; this package closes the other two by requiring
  PKCE and advertising `S256` only. Both are breaking for a client relying on the loose
  behaviour. MCP's authorization spec mandates 2.1, so optional PKCE would leave an MCP
  server non-conformant with the protocol it serves
- **Multi-tenancy from the start** — `ConnectionID` is (tenant, provider, realm). Retrofitting
  it would mean migrating stored credentials
- **Expiry is swept automatically**, on a timer the provider owns and reports. Exposing the
  call and leaving it to a consumer's cron means it does not happen — which is what the
  inherited implementation does today

### Noted
- **RFC 8707 resource indicators are not implemented.** Required by MCP's 2025-06-18 revision
  to bind each access token to a specific server; a follow-on, not a blocker

Nothing is implemented yet. The extraction from SwiftMCPServer is sequenced so that
SwiftMCPServer's own quality gate acts as the control: if it cannot be made green against the
extracted package, the extraction was wrong and is reverted rather than patched.

[Unreleased]: https://github.com/jpurnell/SwiftOAuth/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/jpurnell/SwiftOAuth/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jpurnell/SwiftOAuth/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jpurnell/SwiftOAuth/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jpurnell/SwiftOAuth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jpurnell/SwiftOAuth/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/jpurnell/SwiftOAuth/releases/tag/v0.0.1

