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
.package(url: "https://github.com/jpurnell/swift-oauth.git", exact: "1.0.0-beta.2")
```

Pinned exactly, because SwiftPM's version ranges do not select prereleases: a `from:` range
resolves to the newest *stable* release, which for this package does not exist yet.

Then depend on the half you need — `SwiftOAuthProvider` to issue tokens, `SwiftOAuthClient` to
consume someone else's, `SwiftOAuthMTLS` only for RFC 8705. Swift 6.2, macOS 14+ / iOS 17+, and
Linux (CI runs `swift:6.2`).

## Status

**1.0.0-beta.2.** The full OAuth 2.1 surface: authorization code with mandatory PKCE, refresh
with rotation, client credentials, the device grant (RFC 8628), token exchange (RFC 8693),
introspection (RFC 7662), revocation (RFC 7009), dynamic registration (RFC 7591), PAR (RFC
9126), JAR (RFC 9101), DPoP (RFC 9449), mTLS-bound tokens (RFC 8705), resource indicators (RFC
8707), and both metadata documents (RFC 8414, RFC 9728).

458 tests; the quality gate runs 45 checkers with no errors and no warnings; Linux CI green.

Three adoptions exercised it rather than a test suite alone: LedgeOS on the client half,
SwiftMCPServer and SwiftMCPClient on the provider half. Five defects in this package were found
by a consumer *running* a change rather than by its own tests — each one a metadata field the
library computed when only the deployment could know it. That is the failure mode this package
has been worst at, and it is why the constructor asks for things it could have defaulted.

OpenID Connect is out of scope: authorization is not identity. It returns after 1.0 as its own
module, if at all.

## License

Proprietary.
