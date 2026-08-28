# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [0.4.0]

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

[Unreleased]: https://github.com/jpurnell/SwiftOAuth/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/jpurnell/SwiftOAuth/releases/tag/v0.0.1

