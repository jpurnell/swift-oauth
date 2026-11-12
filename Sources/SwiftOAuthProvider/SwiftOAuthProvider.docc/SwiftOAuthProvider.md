# ``SwiftOAuthProvider``

Issuing tokens and validating your own, with storage as a protocol.

## Overview

``OAuthServer`` is the protocol logic: registration, the authorization request, consent,
the token exchange, and validation. It is an actor, it holds no sockets, and it decides
policy rather than parsing wire formats. ``OAuthHTTPHandler`` is the layer that takes
query parameters and form bodies and gives back ``OAuthHTTPResponse`` — which is what
makes ``OAuthServer`` testable without a running web server, and what lets this package
sit behind whichever HTTP stack a service already uses.

### What the server refuses

Most of the work of an authorization server is declining things precisely.

- **A redirect URI that was not registered.** Checked before anything is issued and
  before any redirect happens, because redirecting to an unregistered URI to report the
  error is the vulnerability itself.
- **An authorization code presented twice.** ``OAuthStorage`` consumes codes rather than
  reading them, so replay finds nothing.
- **A PKCE verifier that does not derive the stored challenge.** Compared in constant
  time, via `PKCE`.
- **A consent submission without a matching CSRF token.** ``CSRFValidationResult``
  distinguishes a token that is absent from one that is wrong, so a caller can tell a
  malformed client from an attack.
- **`grant_type=client_credentials`, unless the deployment opted in.** A deployment that
  lists `.clientCredentials` in its ``ServedCapabilities`` issues it, and only to clients
  an operator created with ``OAuthServer/createServiceClient(name:scopes:authentication:)``:
  `/register` refuses the grant. A service client's scopes are fixed when it is created
  (``RegisteredClient/scopeCeiling``), its tokens last 15 minutes by default, and it is
  never given a refresh token. Every other deployment answers `unsupported_grant_type`.

### Storage is yours

``OAuthProviderStorage`` is the expectation: exactly the operations ``OAuthServer`` performs.
``OAuthStorage`` is the SQLite implementation, and ``InMemoryOAuthStorage`` is the one for tests
and single-process use, which does not survive a restart. A service already behind Postgres
should not run SQLite for its tokens. The `SwiftOAuthProviderConformance` product holds any
substitute to the same behaviour — including the parts that are easy to get subtly wrong,
such as consuming a code exactly once under concurrent presentation — and both shipped stores
pass it unchanged.

### Revoking tokens

RFC 7009 is served by ``OAuthHTTPHandler/handleRevocationRequest(body:authHeader:)``, which a
deployment routes at the path it declares in ``ServedCapabilities/revocation``; the metadata
names `revocation_endpoint` exactly when that is declared. The client authenticates first. A
valid, unknown, expired, already revoked or another client's token all answer `200` with an
empty body (§2.2), so the status says nothing about whether the token existed; a store failure
answers `503` (§2.2.1). Both kinds of token are revoked, the `token_type_hint` is only a hint,
and revoking a refresh token also revokes the access tokens of the same grant (§2.1).

A *grant* is the authorization a user gave once. Every token issued from one code, or one
approved device code, carries the same grant identifier, as does every token refreshed from
them. It is what lets one revocation reach the access tokens made from a refresh token. Tokens
stored before schema 11, and `client_credentials` and exchanged tokens, have none and revoke one
at a time.

``OAuthServer/revokeAllTokens(forSubject:)`` ends everything one user holds, on every client,
including authorization codes not yet spent and device codes they approved and the device has
not collected. Rows with no subject are not reachable by it; revoke those by client.

### Metadata

``ServerMetadata`` is RFC 8414 and ``ProtectedResourceMetadata`` is RFC 9728. Both are
generated from the server's own configuration rather than written out separately, so a
change to what the server accepts cannot drift from what it advertises.

## Topics

### The server

- ``OAuthServer``
- ``OAuthHTTPHandler``
- ``OAuthHTTPResponse``

### Registering clients

- ``ClientRegistrationRequest``
- ``ClientRegistrationResponse``
- ``RegisteredClient``

### Authorizing

- ``AuthorizationRequest``
- ``AuthorizationResponse``
- ``AuthorizationCode``
- ``ConsentPage``
- ``CSRFValidationResult``

### Issuing and validating tokens

- ``TokenRequest``
- ``TokenValidationResult``
- ``RefreshTokenInfo``

### Advertising the server

- ``ServerMetadata``
- ``ProtectedResourceMetadata``

### Persistence

- ``OAuthProviderStorage``
- ``OAuthStorage``
- ``InMemoryOAuthStorage``
- ``OAuthStorageError``
