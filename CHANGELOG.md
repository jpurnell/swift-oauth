# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
