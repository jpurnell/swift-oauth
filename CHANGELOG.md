# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-06

First tagged release: `SwiftOAuthCore` and the client half.

### Added
- **`SwiftOAuthClient`** — `OAuthConnection`, a rotation-safe token lifecycle behind one
  method, `validAccessToken()`. Concurrent refreshes join one exchange rather than racing;
  credentials persist before the new access token is returned; a failed write hands the
  credential back inside the error rather than losing it
- `OAuthClientStorage` as a protocol, with in-memory and deliberately-failing implementations
- Credential variables namespaced by application as well as provider and environment

## [Unreleased]

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
