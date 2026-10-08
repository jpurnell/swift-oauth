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

### A redirect is not followed

Every request this module makes itself — a code exchange, a refresh, a revocation, an
introspection — is a `POST` carrying something that must reach one host only: a client
secret, an authorization code and its PKCE verifier, a refresh token, a token being asked
about. If the endpoint answers `301`, `302`, `303`, `307` or `308`, the request is not
repeated anywhere, on another origin or on the same one. The call throws
``OAuthRedirectRefused``, which names the origin the redirect pointed at and the status, and
nothing is sent there.

That is true of ``URLSessionTokenTransport`` with the default session and with one you
supply, and of ``URLSessionIntrospectionTransport``. It is not something a transport of your
own inherits: a ``TokenTransport`` you write decides for itself, and should decide the same
way.

A `3xx` with no `Location` is the same answer with less in it, and is reported the same way,
with ``OAuthRedirectRefused/destination`` set to ``OAuthRedirectRefused/noLocation``.

RFC 6749 §3.2, RFC 7009 §2.1 and RFC 7662 §2.1 define these requests as a `POST` to the
endpoint and describe no redirect as an answer to one.

### The answer is bounded, and nothing is remembered

No more than ``OAuthResponseTooLarge/maximumResponseBytes`` — 1 MiB — of a response is read.
The body is received a piece at a time and the transfer is cancelled when it passes the limit,
so a server that does not stop sending costs a megabyte; the call throws
``OAuthResponseTooLarge``.

``URLSessionTokenTransport/init()`` and ``URLSessionIntrospectionTransport/init()`` send on a
session that keeps no cookies, no stored credentials and no cache. `URLSession.shared` keeps
all three for the whole process: a token endpoint's cookie came back on the next token
request, and a `401` challenge was answered from the credential store. Pass a session of your
own to ``URLSessionTokenTransport/init(session:)`` if you want one that remembers — on Linux
its configuration is used and its delegate is not.

### Disconnecting tells you what the provider did

``OAuthConnection/disconnect()`` always removes the local credential. If the provider has a
revocation endpoint and did not confirm the revocation — unreachable, refused, redirected, a
`503` — it then throws ``OAuthRevocationFailed``: disconnected here, not confirmed there, and
the token may be valid at the provider until it expires. RFC 7009 §2.2 makes a `200` the
whole answer and has the client ignore the body, so a transport of your own should implement
``TokenTransport/revoke(endpoint:parameters:credentials:method:)`` rather than leave
revocation to an exchange that expects a token response.

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
- ``OAuthRedirectRefused``
- ``OAuthResponseTooLarge``
- ``OAuthRevocationFailed``

### Test doubles

- ``FailingClientStorage``
