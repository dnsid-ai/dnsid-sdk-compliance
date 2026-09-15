# JOSE Profile: JWT and JWS

## Draft 01 Key Role Note

For the draft 01 behavior selected by `dnsid-draft-01` or pre-RFC `DNSid1`, application/runtime signatures use the verified agent `ku` key set; `ek` is only for TXT `sg` and accountable-entity lifecycle signatures.

This document defines the SDK's JOSE helpers. These helpers are application-layer
conveniences built on top of DNSid identity verification; they are not part of
the DNSid protocol core.

## Standards

- RFC 7515: JSON Web Signature
- RFC 7517: JSON Web Key
- RFC 7518: JSON Web Algorithms
- RFC 7519: JSON Web Token
- RFC 7638: JSON Web Key Thumbprint
- RFC 7800: Proof-of-Possession Key Semantics for JWTs
- RFC 8037: CFRG elliptic curve algorithms for JOSE, including OKP/EdDSA

## Dependencies

This profile depends on the shared `IdentityResolver` contract defined in
[README.md](README.md#shared-profile-contracts),
[`KeyProvider`](01-core-identity-manager.md#keyprovider-interface),
[`VerifiedDomain`](07-protocol-data-types.md#verifieddomain), and verified
[`JWKS`](07-protocol-data-types.md#jwks) / `JWK` values from the core identity
module. It should not depend on registry publication, DNS TXT construction, or
HTTP Message Signatures.

## Profile Configuration

JOSE freshness settings are profile configuration, not core DNSid protocol
configuration:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `jose.maxLifetime` | number (seconds) | 900 | Maximum accepted JWT lifetime, computed as `exp - iat`, before `VerifyJWT` rejects the token. |
| `jose.clockSkew` | number (seconds) | 60 | Allowed clock skew when checking that JWT `iat` and `nbf` are not in the future. |

In pseudocode, `config.identity` refers to the manager's local `IdentityConfig`
and `joseConfig` refers to these separately owned JOSE profile settings. JOSE
settings are not members of `DnsidConfig`; verification uses the supplied
`IdentityResolver` and its configured counterparty acceptance policy.

`maxLifetime` MUST be finite and positive; `clockSkew` MUST be finite and
non-negative. Reject invalid configuration with `ArgumentError`, including
non-numeric values. Defaults apply only when omitted: an explicit zero skew
means zero tolerance. Clock skew does not extend JWT expiration in this profile.
`DefaultIfMissing` below tests presence, not truthiness. `UnixSeconds` retains
the current instant's fractional seconds; do not round the verification clock
down when comparing fractional NumericDates.

## Parsing and validation boundaries

These rules apply to compact JWT/JWS parsing before domain or key discovery:

- Require exactly three compact components, strict base64url decoding, and a
  UTF-8 JSON object protected header. JWT claims must also be a JSON object.
  Reject duplicate JSON member names rather than selecting a first/last value;
  JWS payload bytes remain opaque, not JSON-parsed.
- Require non-empty string `alg` and `kid`, an allowed algorithm, and correctly
  typed supported header parameters (`typ`, when present, is a string). This profile implements no critical header
  extensions: reject any `crit` parameter. Reject `b64=false` and non-Boolean
  `b64` values; unencoded or detached payload semantics are not supported.
- JWT `iss`/`sub` must be non-empty FQDN strings; `aud` must be a non-empty
  string or a non-empty array of non-empty strings, without coercion. Normalize
  these FQDNs for comparison. A mixed-type audience array is invalid even when
  one member matches.
- Required `iat`/`exp` and present `nbf` must be finite JSON numbers, not strings,
  Booleans, nulls, NaN, or infinities. NumericDate permits fractions and zero;
  presence checks must not mistake zero for a missing claim.
- Require `exp > iat`, `exp - iat <= maxLifetime`, and `now < exp`.
  Enforce `iat <= now + clockSkew` and, when present, `nbf <= now + clockSkew`.
  Recheck expiration before returning after network/signature verification.

Decode failures are verification failures, not successful partial parses.
`JWT.Decode` and `JSON.Decode` below enforce the structural/type rules.
`ValidateJoseProtectedHeader` denotes the header rules above, including the
algorithm allowlist, and runs before following untrusted signer identifiers.
JOSE helpers or their documented hosting boundary MUST also enforce finite token,
header, and decoded-payload size limits before parsing/allocation; see the
[shared resource budget](README.md#verification-resource-budgets).

OIDC JWT Bearer assertions are specified separately in
[09-oidc-federation.md](09-oidc-federation.md). They use JOSE primitives, but
their issuer URL audience and OAuth token-exchange semantics are OIDC-specific.

## Public Surface

#### `CreateJWT(opts: JWTOptions) -> string`

Creates a self-signed JWT for authenticating to a counterparty identity. The issuer and subject are set to the local identity's domain; the audience is the counterparty domain.

`JWTOptions` fields:

| Field              | Type               | Required | Description |
|--------------------|--------------------|----------|-------------|
| `audience`         | string             | yes      | FQDN of the counterparty identity this token is intended for |
| `expiry`           | duration           | no       | Token lifetime. Defaults to `DefaultExpiry` (15 minutes) if omitted |
| `additionalClaims` | map[string]any     | no       | Extra claims merged into the payload. Must not override reserved claims (`iss`, `sub`, `aud`, `iat`, `exp`, `jti`) |

```
FUNCTION CreateJWT(opts: JWTOptions) -> string
  IF opts.audience == "" THEN
    RAISE ArgumentError("audience is required")
  END
  expiry = DefaultIfMissing(opts.expiry, DefaultExpiry)
  maxLifetime = DefaultIfMissing(joseConfig.maxLifetime, 900)
  IF NOT IsFinite(expiry) OR expiry <= ZeroDuration OR expiry > Duration(maxLifetime) THEN
    RAISE ArgumentError("JWT expiry must be positive, finite, and within maximum lifetime")
  END

  now = Now()
  claims = {
    iss: config.identity.domain,
    sub: config.identity.domain,
    aud: NormalizeFQDN(opts.audience),
    iat: now.Unix(),
    exp: (now + expiry).Unix(),
    jti: GenerateUUID(),
  }
  IF claims.exp <= claims.iat THEN
    RAISE ArgumentError("JWT expiry is below timestamp resolution")
  END
  FOR key, value in opts.additionalClaims
    IF key IN ["iss", "sub", "aud", "iat", "exp", "jti"] THEN
      RAISE ArgumentError("additionalClaims must not override reserved claim: " + key)
    END
    claims[key] = value
  END
  signingKey = keyProvider.SigningKey()
  signingAlg = signingKey.SignatureAlg()
  header = {
    alg: signingAlg,
    kid: signingKey.kid,
    typ: "JWT",
  }
  RETURN JWT.Sign(header, claims, keyProvider)
END
```

---

#### `VerifyJWT(jwt: string) -> VerifiedDomain`

Verifies a JWT received from a counterparty. Validates the DNSid identity of the
issuer with
[`VerifyDomain`](01-core-identity-manager.md#core-methods),
then verifies the JWT signature against the issuer's verified signing key.

`expectedAudience` is trusted verifier configuration or a per-call argument,
exposed idiomatically by the binding. A local-identity profile may default it
to `config.identity.domain`; a verification-only JWT caller must supply it
without manufacturing local identity configuration. Never derive it from the
received token or an untrusted request header. Both JOSE verify helpers also
accept current-peer evidence through the invocation context described in the
[shared contracts](README.md#shared-profile-contracts); `peerCert` below denotes
that optional current application peer, not a cached or JWKS endpoint certificate.

```
FUNCTION VerifyJWT(jwt: string) -> VerifiedDomain
  IF expectedAudience IS missing OR expectedAudience == "" THEN
    RAISE ArgumentError("expected audience is required")
  END
  expectedAudience = NormalizeFQDN(expectedAudience)
  header, claims = JWT.Decode(jwt)       // does NOT verify signature yet; just parses
  ValidateJoseProtectedHeader(header)

  IF claims.iss == "" THEN
    RAISE VerificationError("JWT missing iss claim")
  END
  IF NormalizeFQDN(claims.sub) != NormalizeFQDN(claims.iss) THEN
    RAISE VerificationError("JWT sub must equal iss")
  END
  // aud may be a JSON string or array per RFC 7519 §4.1.3; normalize to list and check membership
  audList = ToStringList(claims.aud)
  IF expectedAudience NOT IN Map(audList, NormalizeFQDN) THEN
    RAISE VerificationError("JWT audience mismatch: " + expectedAudience + " not in aud")
  END
  maxLifetime = DefaultIfMissing(joseConfig.maxLifetime, 900)
  clockSkew = DefaultIfMissing(joseConfig.clockSkew, 60)
  now = Now().UnixSeconds()
  IF claims.iat IS missing THEN
    RAISE VerificationError("JWT missing iat claim")
  END
  IF claims.iat > (now + clockSkew) THEN
    RAISE VerificationError("JWT issued-at time is in the future")
  END
  IF claims.exp IS missing THEN
    RAISE VerificationError("JWT missing exp claim")
  END
  IF claims.exp <= claims.iat THEN
    RAISE VerificationError("JWT exp must be after iat")
  END
  IF (claims.exp - claims.iat) > maxLifetime THEN
    RAISE VerificationError("JWT lifetime exceeds maximum")
  END
  IF claims.exp <= now THEN
    RAISE VerificationError("JWT is expired")
  END
  IF claims.nbf IS present AND now + clockSkew < claims.nbf THEN
    RAISE VerificationError("JWT not yet valid (nbf)")
  END

  verifiedDomain = VerifyDomain(claims.iss, peerCert)  // full protocol and current-peer verification

  signingKey = verifiedDomain.jwks.KeyById(header.kid)
  IF signingKey == nil THEN
    RAISE VerificationError("JWT kid not found in issuer JWKS")
  END

  keyAlg = signingKey.SignatureAlg()  // key-compatible alg; header.alg remains authoritative
  IF header.alg != keyAlg THEN
    RAISE VerificationError("JWT alg mismatch: header declares " + header.alg + " but key is " + keyAlg)
  END

  IF NOT JWT.VerifySignature(jwt, signingKey) THEN
    RAISE VerificationError("JWT signature invalid")
  END

  IF claims.exp <= Now().UnixSeconds() THEN
    RAISE VerificationError("JWT expired during verification")
  END

  // jti replay prevention is out of scope for the SDK. Callers that require replay protection
  // must maintain a seen-jti store and check claims.jti before trusting this result.
  RETURN verifiedDomain
END
```

---

#### `CreateJWS(payload: bytes) -> string`

Produces a JWS compact serialization over arbitrary input bytes, signed with the local identity's current signing key. The `kid` header parameter encodes the identity domain as `{domain}#{kid}`, enabling recipients to call `VerifyJWS` to establish the signer's identity.

```
FUNCTION CreateJWS(payload: bytes) -> string
  signingKey = keyProvider.SigningKey()
  IF StringContains(signingKey.kid, "#") THEN
    RAISE ArgumentError("signing key kid must not contain '#'")
  END
  signingAlg = signingKey.SignatureAlg()
  header = {
    alg: signingAlg,
    kid: config.identity.domain + "#" + signingKey.kid,
    typ: "jose",
  }
  sigInput = Base64url(JSON(header)) + "." + Base64url(payload)
  sig = keyProvider.Sign(sigInput)
  RETURN sigInput + "." + Base64url(sig)
END
```

---

#### `VerifyJWS(jws: string) -> (bytes, VerifiedDomain)`

Verifies a JWS compact serialization received from a counterparty. Extracts the
signer domain from the `kid` header parameter, performs full DNSid verification
of the signer with
[`VerifyDomain`](01-core-identity-manager.md#core-methods),
then verifies the signature. Returns the raw payload bytes alongside the
verified domain.

```
FUNCTION VerifyJWS(jws: string) -> (bytes, VerifiedDomain)
  parts = Split(jws, ".")
  IF len(parts) != 3 THEN
    RAISE VerificationError("malformed JWS: expected 3 dot-separated components")
  END
  headerB64, payloadB64, sigB64 = parts[0], parts[1], parts[2]

  header = JSON.Decode(Base64urlDecode(headerB64))
  ValidateJoseProtectedHeader(header)
  payload = Base64urlDecode(payloadB64)

  IF header.kid == "" THEN
    RAISE VerificationError("JWS missing kid header parameter")
  END
  domain, kid = ParseKeyId(header.kid)   // keyId format: "{domain}#{kid}"

  verifiedDomain = VerifyDomain(domain, peerCert)  // full protocol and current-peer verification

  signingKey = verifiedDomain.jwks.KeyById(kid)
  IF signingKey == nil THEN
    RAISE VerificationError("JWS kid not found in signer JWKS")
  END

  keyAlg = signingKey.SignatureAlg()  // key-compatible alg; header.alg remains authoritative
  IF header.alg != keyAlg THEN
    RAISE VerificationError("JWS alg mismatch: header declares " + header.alg + " but key is " + keyAlg)
  END

  sigInput = headerB64 + "." + payloadB64
  sig = Base64urlDecode(sigB64)
  IF NOT signingKey.Verify(sigInput, sig) THEN
    RAISE VerificationError("JWS signature invalid")
  END

  RETURN payload, verifiedDomain
END
```

---

### DNSid SDK Application Authentication Profile

The JWT, JWS, and HTTP Message Signature helpers implement an SDK-defined
application authentication profile layered on top of DNSid verification. This
profile is not part of the DNSid protocol and is not required for DNSid
conformance. Shared profile contracts and key ID conventions are defined in
[README.md](README.md#shared-profile-contracts).

### JWT Authentication Token

[Reference RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)

A token signed by the identity's `sig` key, used to authenticate to a counterparty. JWT signing uses the SDK's application-layer JOSE algorithm policy, not the DNSid protocol signing-algorithm requirements. The JOSE header `kid` is the local JWKS key ID; the signer domain is taken from the `iss` claim, not encoded into `kid`.

| Claim | Description |
|-------|-------------|
| `iss` | Issuer. FQDN of the signing identity. Required. |
| `sub` | Subject. FQDN of the signing identity. Required and MUST equal `iss`. |
| `aud` | Audience. Required; MUST include the trusted expected audience (defaulting to the local domain only for a local-identity verifier). |
| `iat` | Issued-at timestamp. Required. |
| `exp` | Expiry timestamp. Required. |
| `jti` | Unique token ID. Generated by `CreateJWT`; replay prevention is the caller's responsibility. |
| `nbf` | Not-before timestamp. Optional; enforced by `VerifyJWT` when present. |

`VerifyJWT` enforces `iat` as a required claim. Tokens with `iat` in the future
beyond the configured JOSE clock skew, `exp <= iat`, or `exp - iat` greater than
the configured JOSE maximum lifetime are rejected. This prevents a token with an
unbounded or far-future `exp` from being accepted outside the SDK's
application-layer freshness profile.

### Application-Layer Key IDs

JWS `kid` values use the shared application-layer compound key ID convention
defined in [README.md](README.md#shared-profile-contracts). JWT headers do not
use this compound form because the signer domain is carried in the `iss` claim.

### Application-Layer Algorithm Policy

DNSid protocol signature verification is governed by the protocol JWKS requirements: ES256 support is mandatory and Ed25519 support is recommended. For draft 01 live `ku` keys, JWK `alg` is required and must match the key binding; older profiles may derive it from unambiguous `kty`/`crv` bindings. JWT/JWS headers still carry the authoritative algorithm and drive verification; the key-compatible algorithm is only a consistency check. The JWT, JWS, and HTTP Message Signature helpers are application-layer conveniences and use their own explicit allowlists.

`APPLICATION_JOSE_ALGS = ["EdDSA", "ES256"]` for JWT and JWS helpers. HTTP Message Signatures define their RFC 9421 mapping in [02-rfc9421-http-message-signatures.md](02-rfc9421-http-message-signatures.md#algorithm-mapping).

### JWS Compact Signature

[Reference RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)

The JWS helper produces and verifies compact serialization only. The protected header `kid` MUST use the application-layer compound form `{domain}#{kid}` and `typ` is `jose`. Payload semantics are opaque to the SDK. The SDK provides no replay protection for JWS payloads; applications that need freshness must include and enforce their own timestamp, nonce, audience, or challenge fields in the payload.

## Required boundary checks

SDK validation must cover these cases with otherwise-valid signatures and
identity evidence. These requirements are not assertions of current SDK coverage.

| Input / condition | Required result |
|---|---|
| Unsupported `crit`, `b64=false`, duplicate protected-header or claim member | Reject before discovery. |
| NumericDate is a string, Boolean, null, NaN, or infinity; audience has a non-string member | Reject, without coercion. |
| `now == exp`, or token expires during identity discovery | Reject as expired, including with nonzero skew. |
| Explicit `clockSkew=0`, `iat` or `nbf` is just in the future | Reject; do not substitute the default skew. |
| Valid finite fractional NumericDates, or `iat=0` with an otherwise-valid lifetime at the test clock | Apply ordinary time checks; do not classify as missing/wrong-type. |
| Omitted expiry versus explicit zero/negative/non-finite expiry | Default only when omitted; reject the explicit invalid values. |
| Verification-only JWT with no expected audience, or a mismatching one | Argument error for missing trusted context; verification failure for mismatch. |
| Cached `fl=mtls` identity but missing/wrong current peer | Reject even when the JWT/JWS signature is valid. |

## Local Identity Client and Server Flows

These flows cover JOSE use by services that rely on DNSid identity
verification.

### Local Identity as JWT Client

1. Identify the counterparty domain.
2. Create a JWT with `CreateJWT({ audience: counterpartyDomain })`.
3. Attach the JWT according to the application protocol, commonly as a bearer token.

### Local Identity as JWT/JWS Server

1. Receive inbound request or payload.
2. If the caller presented a JWT bearer token, call `VerifyJWT(jwt)`.
3. If the caller presented a JWS compact serialization, call `VerifyJWS(jws)`.
4. Use the returned `VerifiedDomain` as authenticated identity input to local authorization policy.
