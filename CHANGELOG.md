# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **A resource server honoured tokens minted for other resources — RFC 8707's second half.**
  Issuing bound an audience correctly; consuming ignored it. `validateBearerToken` returned
  `.valid(ValidatedToken)` with `audience` populated and nothing obliged the caller to look at
  it, so `isValid` meant "this token exists and has not expired" rather than "honour this".
  Demonstrated on deployed servers: a token minted at one origin, planted in a second origin's
  store so absence could not explain a refusal, accepted with `200 OK`.

  The comparison is against the identifier the deployment **advertises**, not the issuer. Those
  are one string only for a colocated deployment; assuming otherwise would refuse correct tokens
  at any resource server whose authorization server is elsewhere — the `beta.2` defect
  reappearing in enforcement rather than metadata.

  An unbound token is still honoured. That is the permissive contract `ValidatedToken.audience`
  documents, not a mismatch, and refusing it would break every deployment that has not adopted
  resource indicators. Honouring a *foreign* audience now requires `acceptingAudiences: .any`.

- **The token endpoint required `client_id` in the body under `client_secret_basic`** — RFC 6749
  §2.3.1 puts the id in the header. `clientId(fromBasic:)` existed and documented exactly this;
  the introspection endpoint called it and the token endpoint did not, so the conformant request
  was the one refused with `invalid_request`.

### Noted
- **Why neither side caught it.** Issuing is testable with one server and is well tested here and
  in consumers. Consuming needs two servers and a token deliberately carried between them, which
  no single-server suite constructs. This package's conformance tests passed; so did the
  consumer's 255.
- **Fifth instance in one day of one shape: a value recorded and never read.** The others were a
  custom header, the consent form dropping `resource`, a configured path wired to nothing, and
  now the audience. One side writes, the other is assumed to read, and nothing on either side
  fails when it does not.

## [1.0.0-beta.3] — 2026-09-04

Cut to unblock the strict resource-indicator flip, which beta.2 made impossible: a consumer
attempting it had to back it out, because a client could not name a resource over HTTP at all.
No API change from beta.2.

### Fixed
- **The authorization endpoint discarded the `resource` parameter a client sent — RFC 8707.**
  `AuthorizationRequest.resource` existed and the server validated it correctly, but neither
  HTTP entry point populated it, so it was unconditionally `nil` for any client that speaks
  HTTP. Under a permissive policy this is invisible; under a strict one it refuses every
  authorization-code flow with `invalid_target`, including one whose error text tells the client
  to send the parameter it is already sending. Fixed in four places: GET `/authorize`, the
  consent page's construction, the hidden field it renders, and the approve action. The token
  endpoint was never affected.

  The hidden field is the substance of it. Forwarding only the POST parameter works for a client
  that re-sends and silently drops for a browser, which posts what the page rendered — the same
  defect through a narrower door, reachable from a real browser and not from a test that
  supplies form fields itself.

### Testing
- **A browser round trip covers the consent form**: render the page, parse every `<input>` out
  of the `<form>`, submit only those fields. It asserts what a browser does rather than what the
  page contains — the string assertions it joins would pass if the field were rendered with the
  wrong name, twice, or outside the form.

  Contributed by the SwiftMCPServer session with three weaknesses stated on handover. All three
  are addressed rather than inherited: the scan is bounded to the form element (fixed here
  rather than documented, since this package owns the page), a duplicated field name now fails
  instead of silently keeping the last, and entity decoding is real rather than theoretical —
  ``ConsentPage`` escapes `&`, and a resource identifier carrying a query string is ordinary.

  The suite has been seen to fail: reverting all four forwarding sites builds with **0 errors**
  and fails three of five tests. That count is recorded in the suite, because a suite that fails
  to compile and a suite that detects the bug look identical in a terminal.

### Documentation
- **``ResourceIndicatorPolicy`` now says that strict is enforced at three places, not one.**
  RFC 8707 §2.2 puts the resource on the authorization request, the code exchange, and every
  refresh. Migrating the first two makes the flow work end to end and a happy-path suite go
  green, so the migration reads as finished; the refresh then fails later with a correct
  `invalid_target`. A correct error arriving after you believed you were done is worse than a
  wrong one arriving immediately, because the first thing it contradicts is a conclusion you
  have already acted on. Flip it against a test that refreshes, not one that only obtains.

  Reported by the SwiftMCPServer consumer, which hit exactly this while running the flip.

### Noted
- **This blocked the strict resource-indicator flip**, which is the remaining policy step before
  1.0.0. It was found by a consumer attempting that flip and backing it out, not by this
  package's tests — the sixth such finding, and the second that a reader of the code could have
  caught and no test could, because every consent test runs under `allowsUnspecified: true`.
  That setting is well-reasoned and its comment is honest; the consequence was that no test of
  the HTTP consent path had ever run under a strict policy.

## [1.0.0-beta.2] — 2026-09-04

One fix, and it changes a signature — which is why it is a tag rather than a note on `main`.

### Compatibility

**`OAuthServer.init` requires a third argument with no default**, alongside `scopesSupported`
and `served`:

```swift
OAuthServer(storage: storage, issuer: issuer,
            scopesSupported: ["your:scopes"],
            served: .core,
            resourceIdentity: .colocated)   // this origin issues *and* protects
```

A deployment whose authorization server is somewhere else names it instead:

```swift
resourceIdentity: try ResourceIdentity(
    resource: "https://api.example.com",
    authorizationServers: ["https://auth.example.com"])
```

### Fixed
- **Protected-resource metadata described a deployment shape it assumed rather than knew.**
  `getProtectedResourceMetadata()` published `resource: issuer` and
  `authorizationServers: [issuer]`, which is correct exactly when one origin both issues tokens
  and protects the resource. RFC 9728 keeps the two fields separate because deployments
  routinely split them, and this package supports the split role already — `introspect` and
  `TokenIntrospector` exist so a resource server can validate a token it did not issue. Such a
  server published metadata naming *itself* as its authorization server, sending clients to
  authorize against something that issues nothing. A supported role with unreachable
  configuration is not really supported.

### Noted
- **No shipped deployment was affected**, so beta.1's "no known issues" was true when claimed
  and is not being retracted. This is tagged because the *signature* changed: anyone pinned to
  beta.1 should meet a compile error on the way to 1.0.0, not a silent change in what their
  server advertises.
- **The default was written and then removed.** `resourceIdentity` initially defaulted to
  `.colocated` while the doc comment above it said a default "would be right for most
  deployments and silently wrong for the rest" — documentation and code disagreeing, in the
  type family that exists to stop exactly that. Recorded because it was the fourth such
  mismatch found in this package in a day, and because the gate caught the stale doc example
  afterwards while the contradiction itself went unnoticed until re-reading.
- **beta.1's "no known issues" overstated one thing.** It claimed zero warnings; the gate was
  emitting two doc-lint warnings at that tag, and the check that reported it clean grepped for
  the PASSED line without ever reading the warning count. Both are fixed here — an undocumented
  `audience` parameter dating to 0.8.0, and the `resourceIdentity` parameter added above. The
  *code* claims in beta.1 hold; the claim about the gate did not, and grepping for a verdict
  while ignoring the findings underneath it is the same shape of error as the metadata defect
  this release fixes.
- This is the **fifth** instance of one defect: a metadata field the library computed from what
  it could see when only the operator knew the answer. The other four were endpoints, grant
  types, authentication methods, and DPoP algorithms. Each was found by a consumer running the
  change; none by this package's own tests.

## [1.0.0-beta.1] — 2026-09-04

The complete OAuth 2.1 surface the design proposal approved, exercised before the number is
claimed. **No known issues**: 45 of 45 quality-gate checkers with zero warnings, 454 tests, and
Linux CI green.

### Compatibility

**`OAuthServer.init` requires two new arguments, neither with a default:**

```swift
OAuthServer(storage: storage, issuer: issuer,
            scopesSupported: ["your:scopes"],   // or nil, meaning "advertise none"
            served: .core)                      // what this deployment actually routes
```

Both are required deliberately. A default for either produces a metadata document that promises
something the deployment may not honour, and that failure surfaces at a *client* rather than at
the server that made the claim. Forgetting should be a compile error.

**`TokenValidationResult.valid` carries a `ValidatedToken` struct** rather than associated values
(since 0.12.0). Update `case .valid(let a, let b)` to `case .valid(let token)`.

**Your database migrates to schema version 6 on first open** — audience columns for RFC 8707, a
key thumbprint and proof store for RFC 9449, a certificate thumbprint for RFC 8705, a device code
table for RFC 8628, and pushed requests for RFC 9126. Additive and idempotent throughout.

**PKCE is required.** A client sending no `code_challenge` is refused at the authorization
endpoint. Every release before 0.12.1 / 0.14.1 accepted one without.

**Coming from 0.7.x?** Read every entry between. Nothing here routes around 0.8.0's strict
resource indicators.

### What the beta is for

Everything below has tests and a clean gate. What it does not have is use. The proposal's own
criterion was that 1.0.0 is promoted only after the beta has been used, and the specific things
worth learning from use are: whether the strict resource-indicator default is the right default
in practice, whether `ServedCapabilities` covers what deployments actually vary, and whether the
DPoP and mTLS paths hold up against a real authorization server rather than this package's own.

### The complete surface

| RFC | What |
| :--- | :--- |
| 6749 / 7636 | Authorization code with PKCE — **required**, both endpoints |
| 6749 §6 | Refresh, with rotation |
| 7009 | Revocation |
| 7591 | Dynamic client registration |
| 7662 | Token introspection, both halves |
| 8414 / 9728 | Server and protected-resource metadata |
| 8628 | Device authorization grant |
| 8693 | Token exchange, narrowing only |
| 8705 | mTLS client authentication and certificate-bound tokens |
| 8707 | Resource indicators, both endpoints, strict by default |
| 9101 | JWT-secured authorization requests |
| 9126 | Pushed authorization requests |
| 9207 | Issuer identification |
| 9449 | DPoP, with replay protection |

Deliberately absent: **OpenID Connect**. An access token is not an authentication statement, and
treating one as proof of identity is the misuse OIDC exists to prevent. It returns after 1.0 as
its own module — authorization is not identity.

Also absent, because OAuth 2.1 removes them: the implicit grant and resource owner password
credentials. They are omitted rather than unimplemented.

## [0.14.1] — 2026-09-04

### Security

**PKCE was not required, and now is.** `code_challenge` was optional at the authorization
endpoint, and the token endpoint verified one only *if* the authorization code carried it — so a
client that omitted it received a code with no challenge and redeemed it with no verifier. An
intercepted authorization code was redeemable by whoever intercepted it, which is precisely what
PKCE exists to prevent.

`GrantType`'s documentation has stated "PKCE is required with it" since this package was
written. The documentation was correct and the implementation did not match it — the worse of
the two arrangements, because a reader checking the docs would conclude it was handled.

**Every release from 0.0.1 through 0.14.0 carries this defect.** The same fix is backported to
the 0.12 line as **0.12.1**, so a deployment bounded below 0.13 can take it without also taking
mTLS or token exchange.

**This is a behaviour change, not only a fix.** A client sending no `code_challenge` is now
refused at the authorization endpoint, where the error still reaches whoever can fix it rather
than arriving mid-flow after a code has been issued. Any client not already using PKCE must
start; on this package's client half it is already in use. The consent path routes through the
same request construction and is covered — consent is not a way around it.

Found by auditing this package against a list of eight properties a consumer said it relies on
and never re-checks. Seven held. This one did not, and nothing in either package would have
failed.

## [0.14.0] — 2026-09-03

RFC 8693 token exchange — the last feature before the 1.0.0 beta.

### Compatibility

**`GrantType` gains `tokenExchange`** — a source break only for an exhaustive `switch` with no
`default`. The compiler points at any site that needs an arm. This is the last grant type this
package adds before 1.0.

No schema change. No other break.

**Coming from 0.7.x–0.13.x?** Read those entries too. There is no route here except through
0.8.0's client refusals and the breaks in 0.10.0, 0.12.0 and 0.13.0.

### Added
- **Token exchange**, for a service acting with a token it was given rather than one it
  obtained: an API gateway calling a backend, a job running on a user's behalf, a service
  narrowing its own privilege before calling something less trusted.

  **An exchange may narrow privilege and never widens it.** That is the whole purpose, and the
  thing a naive implementation gets wrong: granting the scope a client asked for, without
  checking what the subject token carried, lets any holder of a read-only token mint an
  administrative one through a documented grant type — and the result looks entirely legitimate
  to everything downstream. Absent a requested scope, the subject's is inherited rather than the
  server's full set.

  Three further refusals, each closing a way the endpoint could launder a credential: an expired
  or unknown subject token, or expiry means nothing; a **bound** subject token, because
  exchanging one strips the binding and this endpoint would otherwise be a documented route
  around everything 0.12.0 and 0.13.0 added; and an ID token, which this package does not
  validate.

- **`TokenExchangeRequest` distinguishes impersonation from delegation.** Without an actor token
  the issued token is indistinguishable from one the subject obtained — an audit log can say
  whose token was used and nothing about who used it. With one, the log can answer *who did
  this*. A caller wanting delegation who forgets the actor token gets impersonation silently,
  so `isDelegation` is a property rather than something inferred at a call site.

  `actor_token_type` is dropped when there is no actor token, even if supplied: §2.1 gives it no
  meaning alone, so sending it produces a request the server must reject — and that rejection
  reads as malformed rather than as the mistake it is.

- **`issued_token_type` is required on decode.** A client holding a token that does not know its
  kind cannot know how it may be presented.

## [0.13.0] — 2026-09-03

RFC 8705 — mutual TLS client authentication and certificate-bound tokens.

### Compatibility

**No source break.** New types, new methods, one new property on `ValidatedToken` — and that
property is the first test of 0.12.0's decision to carry a struct rather than a widening list of
associated values. It arrived without a single `case .valid(let token)` needing to change. Under
the old shape this would have been the third arity break in five releases.

**Two enums gained cases**, which is a source break only for an exhaustive `switch` over them
with no `default`: `ClientAuthenticationMethod` gains `tlsClientAuth` and
`selfSignedTLSClientAuth`. The compiler will point at any site that needs an arm.

**Your database migrates to schema version 5 on first open** — one nullable column,
`access_tokens.certificate_thumbprint`. A server issuing no certificate-bound tokens gets a
column of nulls.

**Coming from 0.7.x–0.12.x?** Read those entries too. There is no route here except through
0.8.0's client refusals and the breaks in 0.10.0 and 0.12.0.

### Added
- **`SwiftOAuthMTLS`**, a new product and target. `MTLSTokenTransport` presents a client
  certificate through NIOSSL, because `URLSessionTokenTransport` cannot: corelibs-foundation's
  `URLCredential` has no identity-based initialiser and its source states there is no
  `SecIdentity` support. `NSURLAuthenticationMethodClientCertificate` *is* declared there, so
  code referencing it compiles and the challenge can be matched — but no credential can be
  constructed to answer it. The name is present and the capability is not.

  **What the separate target buys, stated precisely:** SwiftPM resolves every package-level
  dependency regardless, so the AsyncHTTPClient download is taken by everyone. What it avoids is
  *linking* NIO into a binary that never uses it, and compiling it on every build of the other
  targets. Worth having, and not the same as isolation.

- **`ClientAuthenticationMethod.tlsClientAuth` / `.selfSignedTLSClientAuth`**, plus a
  `sendsSecret` property. Neither mTLS method transmits a secret — that is the point, since
  nothing is sent that could be captured. `sendsSecret` is asked rather than inferred from the
  case, because code written before a method existed cannot guess the answer for it.

- **`CertificateBinding`** — `x5t#S256` computation and comparison. **An absent binding is not
  satisfied by anything.** Treating `nil` as "no requirement" would make every ordinary bearer
  token appear certificate-confirmed, so a caller checking this before honouring a request would
  accept unbound tokens as though they had passed a check they never took.

- **Certificate-bound tokens on the provider**, and `validateBearerToken` refuses them for the
  same reason it refuses DPoP-bound ones: accepting one there accepts it without the certificate
  being checked.

## [0.12.0] — 2026-09-03

RFC 9449 — DPoP. A token that only works for the client holding its key.

### Breaking

**`TokenValidationResult.valid` now carries a single `ValidatedToken` struct** instead of a list
of associated values:

```swift
case .valid(let clientId, let scope, _)   // before
case .valid(let token)                    // after — token.clientId, token.scope, …
```

This case has been widened twice in four releases: 0.8.0 added the audience, and this needed to
add the key binding. Each widening broke every exhaustive `case .valid(a, b)` in every consumer,
including ones with no interest in the feature that caused it — seven sites across two packages
paid for the first. Adding a property to a struct breaks nobody, so **this is one more break to
end a recurring one**, taken now because pre-1.0 is the only cheap moment.

**Your database migrates to schema version 4 on first open** — `access_tokens.key_thumbprint`
and a `dpop_proofs` table. Additive and idempotent; a server that never issues bound tokens gets
one nullable column and an empty table.

**Coming from 0.7.x–0.11.x?** Read those entries too. There is no route here except through
0.8.0's client refusals and 0.10.0's `GrantType` and `OAuthError` breaks.

### Added
- **`DPoPProof`** (Core) — create and verify proofs. Three of the four claims are checked here:
  `htm`, or a proof captured from a `GET` replays as a `DELETE`; `htu`, or a proof captured by
  one resource server replays against another; `iat`, or a proof never goes stale.

  `jti` is surfaced, not checked — refusing a replay needs memory of what has been seen, and
  that memory belongs to the server.

- **`DPoPSession`** (Client) — one key per session, a fresh proof per request, and the token
  presented with the `DPoP` scheme rather than `Bearer`. That distinction is load-bearing: a
  bound token sent as `Bearer` is either refused, or — on a server accepting both — accepted
  *without the proof being checked*, which silently discards the binding.

  The key is held in memory and not persisted. A restart costs a re-authorisation, which is the
  safe direction to fail in; persisting it would mean writing a private key to disk with the
  same protection needs as the tokens it guards.

- **Token binding and replay protection** (Provider). `claimProofIdentifier` decides by the
  *insert*, not by a preceding read: `INSERT OR IGNORE` on a primary key either succeeds or does
  not, atomically, where a check-then-insert would let two concurrent requests both find the
  identifier absent and both proceed — precisely the replay it exists to stop.

- **A cross-half conformance suite** for the four places the two halves must agree on one value.

### Fixed
- **`validateBearerToken` now refuses a bound token.** A server accepting one at the `Bearer`
  entry point accepts it *without checking any proof* — the token validates, the caller sees
  success, and the binding is silently gone. Nothing logs, and a search for "DPoP" in that
  consumer's sources finds nothing, so there is no thread to pull.

  The refusal is here rather than in these notes because documenting it puts the burden on every
  consumer with a Bearer path: know bound tokens exist, know they must be refused at that entry
  point, and write the check. The consumer who has not read this section is exactly the one it
  protects.

  Found by a consumer that checked its own code after the warning and found the shape in its own
  request handler — not exploitable there yet, since it issues no bound tokens, but live the
  moment it does.

## [0.11.1] — 2026-09-03

### Fixed
- **`AuthorizationServerMetadata.configuration(identifier:scope:)` could not carry a resource
  indicator**, so every consumer building a configuration from discovery got `resource: nil` no
  matter what the protected-resource metadata said. A client would discover the identifier it
  was supposed to send and then send nothing — and against a server with the strict policy 0.8.0
  introduced, be refused for it.

  The parameter is new and defaulted, so this is additive: existing call sites compile unchanged
  and keep their current behaviour. Callers that want the indicator now have somewhere to put it.

  Found while wiring SwiftMCPClient to send `resource`, which is the client-side half of
  adopting 0.8.0's strict default. The gap was invisible from inside this package: the client
  half shipped in 0.7.0, the provider half in 0.8.0, and nothing here connected the value
  discovery already had to the configuration that needed it.

## [0.11.0] — 2026-09-03

PAR (RFC 9126) and JAR (RFC 9101) — two ways of protecting an authorization request that
compose rather than compete. PAR hides the parameters from the browser; JAR proves who wrote
them. A pushed request is opaque but unsigned; a signed request in a URL is authentic but
visible.

### Compatibility

**Coming from 0.10.0:** no source break. New types and new methods only — no changed
signatures, no tightened defaults.

**One thing is not source-level:** your database migrates to schema version 3 on first open,
adding a `pushed_requests` table. Additive and idempotent, and a server that never accepts
pushed requests gets an empty table. It still changes data you own, which is why it is here
rather than under "Added".

**Coming from 0.7.x, 0.8.x or 0.9.x:** read those entries too. There is no route here except
through 0.8.0's client refusals and 0.10.0's `GrantType` and `OAuthError` breaks.

### Added
- **`OAuthServer.pushAuthorizationRequest(...)`** and **`consumePushedRequest(...)`** — RFC 9126.
  The reference is hashed at rest, 32 bytes, single-use, bound to the client that pushed it, and
  marked spent in the same step that reads it so two concurrent authorization requests cannot
  both succeed on one. Unknown, expired, spent and belonging-to-another-client are one answer,
  because distinguishing them lets a caller probe which references exist.

- **`RequestObject.verify(...)`** — RFC 9101. **A request object that does not verify is refused,
  and the query parameters are not used instead.** That is the whole feature: a server that falls
  back has built a signature an attacker can simply omit. There is deliberately no API returning
  parameters without verification, so the fallback cannot be written by accident.

  `iss` must be the client, `aud` must contain this server, and the inner `client_id` must match
  the outer one — closing, respectively: one client presenting another's signed object; an object
  addressed to a different authorization server being replayed here; and the server
  authenticating one client while honouring another's parameters.

- **`CompactJWS`** — a minimal JWS in compact serialization, **ES256 only**. swift-crypto carries
  every primitive and no JOSE layer, so this is written once here and reused by RFC 9449 rather
  than taking a JOSE dependency for two features.

  One algorithm, deliberately. The two most-exploited JWT flaws both come from a verifier acting
  on what the token says about itself: `alg: none`, and algorithm confusion where a token
  declares HS256 and a verifier uses the public key as an HMAC secret — the public key being
  public, anyone can forge it. Accepting exactly one algorithm makes both unrepresentable rather
  than guarded against. The header's `alg` is read only to refuse anything that is not ES256.

## [0.10.0] — 2026-09-03

RFC 8628, the device authorization grant — signing in on anything without a browser.

### Breaking

**`GrantType` gains `deviceCode`.** A source break for anyone switching exhaustively over it.
This is the change the design proposal argued must land before 1.0, on the grounds that
afterwards it costs a major version.

Its wire value is the URN `urn:ietf:params:oauth:grant-type:device_code`, not a short name. A
server matching on `"device_code"` refuses every conformant client, and the refusal reads as an
unsupported grant rather than as a typo.

**`OAuthError` gains three cases** — `authorizationPending`, `slowDown`, `expiredToken` — which
is a source break for the same reason. Without them a client sees a generic server error for
`authorization_pending`, the expected answer during most of a device flow, and cannot tell
"still waiting" from "something broke".

**Your database is migrated on first open**, to schema version 2, adding a `device_codes` table.
Additive and idempotent. Servers that never issue device codes still take the migration; it
creates an empty table and nothing else.

**Coming from 0.7.x or 0.8.x?** Read those entries too. There is no route here except through
0.8.0's client refusals.

### Added
- **`OAuthServer.authorizeDevice(clientId:scope:)`**, **`approveDeviceCode(userCode:subject:)`**
  and **`redeemDeviceCode(_:clientId:)`** — the provider half.

- **`DeviceFlow.poll`** — the client half. `slow_down` widens the wait that follows it and the
  widening persists; a client that applies it once and reverts keeps making the same mistake at
  the same rate. The loop also stops itself once the code's lifetime has passed: a server is not
  obliged to answer `expired_token` — it may simply have forgotten the code — so without a local
  bound a device left on a shelf polls indefinitely.

- **`TokenGenerator.generateUserCode()`** — eight characters from a twenty-letter alphabet with
  `0`/`O` and `1`/`I` excluded, those being the pairs people confuse when reading a code off one
  screen and typing it on another, which is the entire interaction this grant exists for. Vowels
  are excluded too, so a random code cannot spell something unfortunate on a television.

  A little over 34 bits, which is weak by credential standards and correct here: short-lived,
  rate-limited by the polling interval, and useless without the device code.

### Security notes for anyone implementing against this
- The device code is hashed at rest; the user code is not, deliberately — it is looked up by
  exactly what a person typed, and approving one authorises a session the approver cannot
  collect.
- A device code is bound to the client it was issued to. Without that check, a code seen in
  transit is redeemable by anyone who can name a client id, and client ids are public by design.
- It is single-use, and marked spent before the token is issued — the other order leaves a
  window in which two concurrent polls both collect a token.
- Unknown, not-yours and already-redeemed are indistinguishable to a caller, and unknown and
  expired are indistinguishable at the approval page. Otherwise it confirms which short codes
  exist, and they are short by design.

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

[Unreleased]: https://github.com/jpurnell/swift-oauth/compare/v1.0.0-beta.3...HEAD
[1.0.0-beta.3]: https://github.com/jpurnell/swift-oauth/compare/v1.0.0-beta.2...v1.0.0-beta.3
[1.0.0-beta.2]: https://github.com/jpurnell/swift-oauth/compare/v1.0.0-beta.1...v1.0.0-beta.2
[1.0.0-beta.1]: https://github.com/jpurnell/swift-oauth/compare/v0.14.1...v1.0.0-beta.1
[0.14.1]: https://github.com/jpurnell/swift-oauth/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/jpurnell/swift-oauth/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/jpurnell/swift-oauth/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/jpurnell/swift-oauth/compare/v0.11.1...v0.12.0
[0.11.1]: https://github.com/jpurnell/swift-oauth/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/jpurnell/swift-oauth/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/jpurnell/swift-oauth/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/jpurnell/swift-oauth/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/jpurnell/swift-oauth/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/jpurnell/swift-oauth/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/jpurnell/swift-oauth/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/jpurnell/swift-oauth/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jpurnell/swift-oauth/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jpurnell/swift-oauth/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jpurnell/swift-oauth/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jpurnell/swift-oauth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jpurnell/swift-oauth/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/jpurnell/swift-oauth/releases/tag/v0.0.1
