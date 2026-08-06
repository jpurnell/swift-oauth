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

## Status

Scaffolded. See [`project/master_plan.md`](project/master_plan.md) for what is built and
[`project/plans/proposals/SwiftOAuthDesign.md`](project/plans/proposals/SwiftOAuthDesign.md)
for the design.

## License

Proprietary.
