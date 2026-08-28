# ``SwiftOAuthClient``

Obtaining another system's tokens, storing them, and refreshing them without losing them.

## Overview

Callers see one method: ``OAuthConnection/validAccessToken()``. Expiry, rotation, and
persistence are not their problem — which is what stops each caller reinventing them
slightly differently, and slightly wrong.

That method is the whole argument for this being a library rather than a page of
instructions. Presenting a refresh token expires it. Three failures follow from that one
fact, and each locks a user out of their own data rather than producing an error anyone
can read.

### Concurrent refresh

Two requests notice the same expired token and both refresh. The provider honours the
first and, seeing a token it has already retired, rejects the second — or worse, honours
both and retires the first's replacement. Either way a caller holds a token that no
longer works and has no way to know why.

``OAuthConnection`` is an actor and serialises refresh per connection, so concurrent
callers await one exchange and all receive its result.

### A crash mid-rotation

The old token is already dead at the provider; the new one exists only in memory. A
process that stops here comes back with nothing that works and no record of why.

The credential is written through ``OAuthClientStorage`` *before* the new access token is
returned to the caller. A crash after the write costs nothing; a crash before it leaves
the old token still valid at the provider.

### Revocation that looks like a lost rotation

A user revoking access and a rotation whose result was never persisted both present as
"the refresh token was rejected". The remedies are opposite: one requires sending the
user through authorization again, the other must not.

``StoredCredential`` retains the previous token and the rotation timestamp so
``ConnectionError`` can tell them apart, and a transient failure is not reported as
revocation.

### Storage is yours

``OAuthClientStorage`` says *what* must be persisted, not where. Two implementations
ship: ``InMemoryClientStorage`` for tests, and ``EncryptedFileClientStorage`` for
applications that should not make a user authorize again after a restart. The latter
encrypts the whole file under AES-GCM, so *which* providers a user has connected is not
readable either, and a wrong key or a tampered file throws rather than reading as empty —
an empty read looks like a first run, and a first run invites a caller to overwrite a
file it could not read.

### Transport is yours too

``TokenTransport`` exists so a test suite need not open a socket.
``URLSessionTokenTransport`` is the implementation an application wants; a test supplies
its own and gets deterministic responses.

## Topics

### Holding a connection

- ``OAuthConnection``
- ``ConnectionID``
- ``ConnectionError``

### Authorizing

- ``BegunAuthorization``
- ``PendingAuthorization``
- ``AuthorizationCallback``
- ``CallbackError``

### Describing a provider

- ``ProviderConfiguration``
- ``ClientCredentials``
- ``ClientCredentialError``

### Finding one automatically

- ``AuthorizationServerMetadata``
- ``DiscoveryError``

### Registering with one

- ``ClientRegistrationRequest``
- ``ClientRegistrationResponse``

### Persisting what comes back

- ``OAuthClientStorage``
- ``StoredCredential``
- ``InMemoryClientStorage``
- ``EncryptedFileClientStorage``
- ``StorageError``

### Sending the request

- ``TokenTransport``
- ``URLSessionTokenTransport``

### Test doubles

- ``FailingClientStorage``
