# ``SwiftOAuthCore``

The wire OAuth's two roles share: grant types, token responses, error codes, and PKCE.

## Overview

A provider and a client share almost no logic. What they do share is the *format* of
what passes between them — and both halves of a protocol getting that format
independently right is how interoperability bugs are made.

So this module holds value types and cryptographic primitives, and no behaviour beyond
them. Nothing here opens a socket, reads a database, or decides policy. That is the
point: both `SwiftOAuthProvider` and `SwiftOAuthClient` depend on this module, so a
change here moves two working systems at once, and the smaller the surface, the less
often that has to happen.

### PKCE is the reason this module exists

``PKCE`` is where the shared vocabulary stops being an analogy. The client generates a
verifier and derives a challenge from it; the provider stores the challenge and, at
token exchange, checks the verifier against it. One side generates, the other
validates, and the two must agree bit for bit on the base64url encoding and the SHA-256
input.

Splitting that across two packages means two implementations of one derivation, which
either agree or produce an authorization failure nobody can debug from either side
alone. ``PKCE/generateCodeChallenge(verifier:method:)`` and
``PKCE/verifyCodeChallenge(verifier:challenge:method:)`` are the same code, called
from both ends.

### Errors are values, not strings

``OAuthError`` is the RFC 6749 §5.2 error set as a Swift enum, and
``OAuthErrorResponse`` is its wire form. Encoding an error to `invalid_grant` and
decoding `invalid_grant` back are inverse operations on the same type — a client that
receives one gets the same case the provider raised, rather than a string it has to
match on.

### Grants this package will not name

``GrantType`` omits `implicit` and `password`. OAuth 2.1 removes both, and having no
spelling for them is a stronger position than having one that is discouraged in a doc
comment.

`client_credentials` is present, which is a different judgement: it is not unsafe, only
user-less, and a client that cannot spell it cannot consume a large class of
machine-to-machine APIs. A provider built on this package still rejects it —
`OAuthServer` dispatches on the wire string and answers
`unsupported_grant_type` — so the client can ask and this provider can decline.

## Topics

### Proof Key for Code Exchange

- ``PKCE``
- ``PKCEError``

### Naming the exchange

- ``GrantType``
- ``ResponseType``
- ``ClientAuthenticationMethod``

### What comes back

- ``TokenResponse``

### When it does not

- ``OAuthError``
- ``OAuthErrorResponse``

### Generating tokens

- ``TokenGenerator``
