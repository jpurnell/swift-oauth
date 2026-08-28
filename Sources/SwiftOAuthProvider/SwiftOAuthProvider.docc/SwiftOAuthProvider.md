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
- **`grant_type=client_credentials`.** `GrantType` can spell it, because
  the client half needs to consume APIs that offer nothing else. This provider still
  answers `unsupported_grant_type`.

### Storage is yours

``OAuthStorage`` ships as the SQLite implementation, and it is one implementation of an
expectation, not the expectation itself. A service already behind Postgres should not run
SQLite for its tokens. The conformance suite that ships with the package holds any
substitute to the same behaviour — including the parts that are easy to get subtly wrong,
such as consuming a code exactly once under concurrent presentation.

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

- ``OAuthStorage``
- ``OAuthStorageError``
