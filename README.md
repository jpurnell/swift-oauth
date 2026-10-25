# SwiftOAuth

**Both halves of OAuth 2.0, with storage as a protocol.**

OAuth's two roles share a name and almost no behaviour. An authorization **server** issues
tokens and validates its own. A **client** obtains another system's tokens and refreshes them.
Most libraries do one; this does both, because they share the wire even when they share no
logic — grant types, token responses, error codes, and PKCE, where the client generates the
verifier the server validates.

```
SwiftOAuthCore        models · errors · grant types · PKCE · token generation
  ├── SwiftOAuthProvider    issuing and validating
  └── SwiftOAuthClient      obtaining, storing, refreshing
        └── SwiftOAuthIdentity   an introspected token as a SwiftIdentity subject
```

Neither half depends on the other. A service that only issues tokens never links client code.

## Storage is yours

The protocols say *what* must be persisted, not where. A service behind Postgres should not
run SQLite for its tokens, and a test should not touch disk.

| Protocol | Persists |
|---|---|
| `OAuthProviderStorage` | registered clients, authorization codes, issued tokens, CSRF tokens |
| `OAuthClientStorage` | credentials obtained from other systems, per connection |

Ships with SQLite and in-memory provider storage, and in-memory and encrypted-file client
storage. A conformance suite ships too, so your own implementation can be held to the same
expectations.

## Why the client half is a library

Presenting a refresh token expires it. Three failures follow, and each locks a user out of
their own data rather than producing an error anyone can read:

- **Concurrent refresh** — two requests both refresh, the second kills the first's token.
  Refresh is serialised per connection.
- **A crash mid-rotation** — the old token is already dead at the provider and the new one
  exists only in memory. The credential is persisted before the new access token is used.
- **Revocation looks like a lost rotation** — opposite remedies, indistinguishable. The
  previous token and rotation timestamp are retained so they can be told apart.

Callers see one method: `validAccessToken()`. Expiry, rotation and persistence are not their
problem, which is what stops each caller reinventing them slightly differently.

## Installation

```swift
.package(url: "https://github.com/jpurnell/swift-oauth.git", exact: "1.0.0-beta.7")
```

Pinned exactly, because SwiftPM's version ranges do not select prereleases: a `from:` range
resolves to the newest *stable* release, which for this package does not exist yet.

Then depend on the half you need — `SwiftOAuthProvider` to issue tokens, `SwiftOAuthClient` to
consume someone else's, `SwiftOAuthMTLS` only for RFC 8705, `SwiftOAuthIdentity` only to resolve
access tokens to [SwiftIdentity](https://github.com/jpurnell/swift-identity) subjects.

**SwiftPM resolves every dependency of this package for every consumer**, whichever product you
link: AsyncHTTPClient (for `SwiftOAuthMTLS`) and `swift-identity` (for `SwiftOAuthIdentity`)
are downloaded and pinned either way, and compiled and linked only if you use the product that
needs them. Swift 6.2, macOS 14+ / iOS 17+, and
Linux (CI runs `swift:6.2`).

## Status

**1.0.0-beta.7.** The full OAuth 2.1 surface: authorization code with mandatory PKCE, refresh
with rotation, client credentials, the device grant (RFC 8628), token exchange (RFC 8693),
introspection (RFC 7662), revocation (RFC 7009), dynamic registration (RFC 7591), PAR (RFC
9126), JAR (RFC 9101), DPoP (RFC 9449), mTLS-bound tokens (RFC 8705), resource indicators (RFC
8707), and both metadata documents (RFC 8414, RFC 9728).

Client credentials is on both halves, and on the provider it is **opt-in**. A deployment
issues the grant only if it lists `.clientCredentials` in its `ServedCapabilities`; `.core`
does not, and still answers `unsupported_grant_type`. Even then it goes only to service
clients an operator creates with `createServiceClient`. `/register` refuses the grant. Each
service client has a scope ceiling, and gets no refresh token. Client secrets are stored as
hashes.

On the client half, a request that carries a credential follows no redirect, and the answer
it reads is capped at 1 MiB.

The client half can run the device grant end to end — for a command-line tool or a terminal
session that cannot open a browser. `DeviceAuthorizationClient.signIn(present:)` asks for the
codes, hands them to you to show the user, and polls until they approve:

```swift
let client = try DeviceAuthorizationClient(configuration: configuration, credentials: credentials)
let tokens = try await client.signIn { authorization in
    print("Visit \(authorization.verificationURI) and enter \(authorization.userCode)")
}
```

What the server sends is checked before it is shown: `https` verification URIs only, and a user
code with no control or bidirectional-override characters to rewrite the terminal.

`SwiftOAuthIdentity` is the other end: a resource server or sign-in gate that holds an access
token asks the authorization server about it, and SwiftIdentity's own roster says which local
subject that provider's `sub` is.

```swift
let corp = OAuthIdentityStore(
    introspector: introspector,                       // the issuer's RFC 7662 endpoint
    issuer: "https://auth.example.com/",
    audience: .mustInclude("https://dash.example.com"),
    mapping: people)                                  // a SwiftIdentity store of external identities
let authenticator = Authenticator(stores: [people, corp], audit: audit, now: { Date() })
let who = await authenticator.authentication(for: [OAuthAccessToken(tokens.accessToken)])
```

It fails closed, tells the caller nothing about why, and passes SwiftIdentity's conformance
suite unchanged.

625 tests; the quality gate runs its 43 selected checkers with no errors and no warnings. Linux CI was green at 1.0.0-beta.7 and has not yet run the unreleased changes — `SwiftOAuthIdentity` and its `swift-identity` dependency have been built on macOS only.

Three adoptions exercised it rather than a test suite alone: LedgeOS on the client half,
SwiftMCPServer and SwiftMCPClient on the provider half. Eight defects in this package were found by a
consumer *running* a change rather than by its own tests. Five were metadata fields the library
computed when only the deployment could know the answer; two were values recorded and never read
back, including the token audience it bound and then ignored. That is the failure mode this package has been worst at, and
it is why the constructor asks for things it could have defaulted.

OpenID Connect is out of scope: authorization is not identity. It returns after 1.0 as its own
module, if at all.

## License

Proprietary. Copyright (c) 2026 Justin Purnell. All rights reserved; no licence is granted
without written permission. See `LICENSE`.

Tags `0.7.1` through `v1.0.0-beta.7` were published with the MIT licence text in `LICENSE`;
see the changelog.
