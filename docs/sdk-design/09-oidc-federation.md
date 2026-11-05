# OIDC Federation Profile

This document defines SDK helpers for using DNSid identities with OpenID Connect
and OAuth 2.0 JWT Bearer token exchange. These helpers are application-layer
conveniences built on top of DNSid identity verification; they are not part of
the DNSid protocol core.

DNSid remains owner-authoritative: a domain owner controls its DNSid record and
runtime signing keys. An OIDC issuer is a federation/token-vending service, not a
protocol authority for the domain.

## Standards

- OpenID Connect Discovery 1.0
- RFC 6749: OAuth 2.0 Authorization Framework
- RFC 7523: OAuth 2.0 JWT Bearer Token Profiles
- RFC 7515: JSON Web Signature
- RFC 7517: JSON Web Key
- RFC 7519: JSON Web Token

## Dependencies

This profile depends on the shared `IdentityResolver` contract defined in
[README.md](README.md#shared-profile-contracts),
[`KeyProvider`](01-core-identity-manager.md#keyprovider-interface), the JOSE
primitives in [03-jose-jwt-jws.md](03-jose-jwt-jws.md), and SDK-managed HTTPS
transport controls in [05-transport-and-registry.md](05-transport-and-registry.md).
It should not depend on registry publication or DNS TXT construction.

## Profile Configuration

OIDC settings remain profile-owned, not members of `DnsidConfig`. In pseudocode,
`config.identity` is the local `IdentityConfig`; `oidc` holds this profile's
settings. OIDC issuer approval and DNSid accountable-entity acceptance are
independent policies; neither allowlist populates or replaces the other.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `oidc.defaultScope` | string | `openid` | Scope sent when the caller omits `scope`. |
| `oidc.assertionLifetime` | number (seconds) | 300 | Lifetime for agent-signed JWT Bearer assertions. MUST NOT exceed `oidc.maxAssertionLifetime`. |
| `oidc.maxAssertionLifetime` | number (seconds) | 900 | Maximum assertion lifetime accepted by SDK helpers. |
| `oidc.clockSkew` | number (seconds) | 30 | Allowed clock skew when validating OIDC assertions or issued tokens. |
| `oidc.allowedIssuers` | list<string> | empty | Issuer allowlist for verifying issued OIDC tokens. Bindings MUST require an explicit allowlist before trusting tokens. |
| `oidc.allowedTokenAlgorithms` | list<string> | `["RS256"]` | Policy allowlist for provider-issued OIDC token algorithms. SDKs MUST support `RS256`, MAY support additional algorithms, and MUST first reject algorithms outside this allowlist, then fail closed when an allowed algorithm is not implemented by the binding. This is separate from the DNSid assertion signing policy. |
| `oidc.allowHttpLoopbackIssuer` | boolean | `false` | Test/local-development escape hatch allowing `http://localhost` and loopback issuers. MUST NOT allow non-loopback HTTP issuers. |

Assertion lifetimes and their maximum MUST be finite and positive; clock skew
MUST be finite and non-negative. Invalid configuration/explicit expiry is an
argument error. Use the JOSE `DefaultIfMissing` presence rule: zero skew remains
zero, while explicit zero expiry is invalid. OIDC uses the same strict compact
JSON/NumericDate parsing rules as JOSE, but retains its own issuer, audience,
header allowlist, and algorithm policy.

Issuer URLs are exact issuer identifiers: scheme plus host and optional path, no
query, fragment, or trailing slash. For path-based issuers, discovery appends
`/.well-known/openid-configuration` to the issuer URL. Explicit issuer discovery
MUST reject redirects. Production issuers MUST use HTTPS. Bindings MAY allow HTTP
only for `localhost` or loopback addresses through an explicit
test/local-development opt-in such as `oidc.allowHttpLoopbackIssuer`; when set,
the SDK-managed transport MUST permit only those loopback issuer requests and
MUST keep the normal public-network SSRF protections for all other requests.
Discovery, JWKS, and token endpoint responses MUST be read with an
implementation-defined maximum size. Responses exceeding that size MUST fail
closed, not be truncated and parsed.

`jti` values MUST be cryptographically random, unique, opaque strings. Bindings
MAY use UUIDs, random URL-safe bytes, or another equivalent representation.

Errors named in pseudocode are semantic categories. Bindings SHOULD expose
language-appropriate equivalents; for example, a failed OAuth token endpoint
response should be distinguishable from local argument validation and token
verification failures.

## Public Surface

#### `CreateOIDCAssertion(opts: OIDCAssertionOptions) -> string`

Creates an agent-signed JWT Bearer assertion for RFC 7523 token exchange. The
issuer and subject are the local DNSid identity domain. The audience is the exact
OIDC issuer URL.

`OIDCAssertionOptions` fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `issuer` | string | yes | Exact OIDC issuer URL. Used as the assertion `aud`. |
| `expiry` | duration | no | Assertion lifetime. Defaults to `oidc.assertionLifetime`; MUST NOT exceed `oidc.maxAssertionLifetime`. |
| `additionalClaims` | map<string, any> | no | Extra claims. Must not override reserved claims (`iss`, `sub`, `aud`, `iat`, `exp`, `jti`, `fqdn`). |

```
FUNCTION CreateOIDCAssertion(opts: OIDCAssertionOptions) -> string
  issuer = ValidateExactOIDCIssuer(opts.issuer)
  expiry = DefaultIfMissing(opts.expiry, Duration(DefaultIfMissing(oidc.assertionLifetime, 300)))
  maxLifetime = DefaultIfMissing(oidc.maxAssertionLifetime, 900)
  IF NOT IsFinite(expiry) OR expiry <= ZeroDuration OR expiry > Duration(maxLifetime) THEN
    RAISE ArgumentError("OIDC assertion expiry must be positive, finite, and within maximum lifetime")
  END

  now = Now()
  claims = {
    iss: config.identity.domain,
    sub: config.identity.domain,
    aud: [issuer],
    iat: now.Unix(),
    exp: (now + expiry).Unix(),
    jti: GenerateRandomOpaqueId(),
    fqdn: config.identity.domain,
  }
  IF claims.exp <= claims.iat THEN
    RAISE ArgumentError("OIDC assertion expiry is below timestamp resolution")
  END
  FOR key, value in opts.additionalClaims
    IF key IN ["iss", "sub", "aud", "iat", "exp", "jti", "fqdn"] THEN
      RAISE ArgumentError("additionalClaims must not override reserved claim: " + key)
    END
    claims[key] = value
  END

  signingKey = keyProvider.SigningKey()
  header = { alg: signingKey.SignatureAlg(), kid: signingKey.kid, typ: "JWT" }
  RETURN JWT.Sign(header, claims, keyProvider)
END
```

---

#### `DiscoverOIDCIssuer(issuer: string) -> OIDCDiscoveryDocument`

Fetches `{issuer}/.well-known/openid-configuration` and validates the discovery
document.

```
FUNCTION DiscoverOIDCIssuer(issuer: string) -> OIDCDiscoveryDocument
  issuer = ValidateExactOIDCIssuer(issuer)
  response = HTTPS.GET(issuer + "/.well-known/openid-configuration", followRedirects=false)
  IF response.status != 200 THEN
    RAISE NetworkError("OIDC discovery failed")
  END
  doc = JSON.Decode(response.body)
  IF doc.issuer != issuer THEN
    RAISE VerificationError("OIDC discovery issuer mismatch")
  END
  ValidateOIDCTokenEndpoint(doc.token_endpoint, issuer)
  ValidateOIDCJWKSURI(doc.jwks_uri, issuer)
  RETURN doc
END

FUNCTION ValidateOIDCTokenEndpoint(endpoint: string, issuer: string)
  endpointURL = ParseAbsoluteURL(endpoint)
  issuerURL = ParseExactRootURL(issuer)
  IF endpointURL.scheme != issuerURL.scheme OR endpointURL.host != issuerURL.host THEN
    RAISE VerificationError("OIDC token_endpoint must use the issuer origin")
  END
  IF endpointURL.path == "" OR endpointURL.query != "" OR endpointURL.fragment != "" THEN
    RAISE VerificationError("invalid OIDC token_endpoint")
  END
END

FUNCTION ValidateOIDCJWKSURI(jwksURI: string, issuer: string)
  jwksURL = ParseAbsoluteURL(jwksURI)
  issuerURL = ParseExactRootURL(issuer)
  IF jwksURL.scheme != issuerURL.scheme OR jwksURL.host != issuerURL.host THEN
    RAISE VerificationError("OIDC jwks_uri must use the issuer origin")
  END
  IF jwksURL.path == "" OR jwksURL.query != "" OR jwksURL.fragment != "" THEN
    RAISE VerificationError("invalid OIDC jwks_uri")
  END
END
```

---

#### `ExchangeOIDCToken(opts: OIDCTokenExchangeOptions) -> OIDCTokenResponse`

Exchanges an agent-signed assertion for an OIDC bearer token.

`OIDCTokenExchangeOptions` fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `issuer` | string | yes | Exact issuer URL used for discovery and assertion audience. |
| `audience` | string | yes | Relying-party audience for the issued token. |
| `scope` | string | no | Space-separated OAuth scopes. Defaults to `openid`. |
| `assertion` | string | no | Prebuilt assertion. If omitted, call `CreateOIDCAssertion({issuer})`. |

The `audience` form field is a DNSid OIDC provider extension, not an RFC 7523
core parameter. Generic issuers MAY reject or ignore it.

```
FUNCTION ExchangeOIDCToken(opts: OIDCTokenExchangeOptions) -> OIDCTokenResponse
  IF opts.audience == "" THEN
    RAISE ArgumentError("audience is required")
  END
  doc = DiscoverOIDCIssuer(opts.issuer)
  assertion = opts.assertion OR CreateOIDCAssertion({ issuer: doc.issuer })
  IF opts.assertion != "" THEN
    assertionClaims = JWT.DecodeClaims(opts.assertion)  // parse only, no trust needed
    IF ToStringList(assertionClaims.aud) != [doc.issuer] THEN
      RAISE ArgumentError("OIDC assertion audience must exactly match issuer")
    END
  END
  scope = opts.scope OR (oidc.defaultScope OR "openid")

  form = {
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: assertion,
    audience: opts.audience,
    scope: scope,
  }
  response = HTTPS.POST_FORM(doc.token_endpoint, form, followRedirects=false)
  IF response.status IN [301, 302, 303, 307, 308] THEN
    RAISE NetworkError("OIDC token endpoint redirects are not allowed")
  END
  IF response.status != 200 THEN
    RAISE OAuthError(response.error, response.error_description)
  END
  tokenResponse = JSON.Decode(response.body)
  IF tokenResponse.access_token == "" THEN
    RAISE VerificationError("OIDC token response missing access_token")
  END
  IF Lowercase(tokenResponse.token_type) != "bearer" THEN
    RAISE VerificationError("OIDC token response token_type must be Bearer")
  END
  RETURN OIDCTokenResponse{
    accessToken: tokenResponse.access_token,
    idToken: tokenResponse.id_token,
    tokenType: tokenResponse.token_type,
    expiresIn: tokenResponse.expires_in,
    scope: tokenResponse.scope,
    raw: tokenResponse,
  }
END
```

`OIDCTokenResponse` fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `accessToken` | string | yes | Issued bearer JWT. |
| `idToken` | string | no | ID Token returned as `id_token` when the issuer provides one. SDKs MUST preserve it but do not require it for this access-token exchange. |
| `tokenType` | string | yes | Usually `Bearer`. |
| `expiresIn` | number | no | Lifetime in seconds when returned by the issuer. |
| `scope` | string | no | Granted scope string. |
| `raw` | any | no | Original token response for diagnostics. Treat as sensitive bearer material if retained. |

---

#### `GetOIDCToken(opts: OIDCTokenExchangeOptions) -> OIDCTokenResponse`

Convenience alias for `ExchangeOIDCToken` that always creates a fresh assertion.
Bindings that reuse `OIDCTokenExchangeOptions` here MUST ignore `assertion`.

---

#### `VerifyOIDCToken(token: string, opts: VerifyOIDCTokenOptions) -> VerifiedOIDCSubject`

Verifies an issued OIDC token and, by default, verifies the DNSid identity named
by the token `sub` claim.

`VerifyOIDCTokenOptions` fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `issuer` | string | yes | Expected issuer. MUST be present in `oidc.allowedIssuers`. |
| `audience` | string | yes | Expected relying-party audience. |
| `verifyDnsidSubject` | boolean | no | Defaults to true. When true, call `VerifyDomain(sub, peerCert)` before returning. |
| `peerCert` | TLSCertificate | no | Trusted current application-peer evidence for DNSid subject verification; required when that identity signals `fl=mtls`. May be supplied through the binding's equivalent invocation context. |

```
FUNCTION VerifyOIDCToken(token: string, opts: VerifyOIDCTokenOptions) -> VerifiedOIDCSubject
  IF opts.issuer NOT IN oidc.allowedIssuers THEN
    RAISE VerificationError("OIDC issuer is not allowed")
  END
  IF opts.audience == "" THEN
    RAISE ArgumentError("audience is required")
  END

  header, claims = JWT.Decode(token)  // untrusted; only used for early rejection and key lookup
  IF claims.iss != opts.issuer THEN
    RAISE VerificationError("OIDC issuer mismatch")
  END
  IF ToStringList(claims.aud) != [opts.audience] THEN
    RAISE VerificationError("OIDC audience mismatch")
  END
  IF header contains any parameter outside ["alg", "kid", "typ"] THEN
    RAISE VerificationError("unsupported OIDC token header")
  END

  doc = DiscoverOIDCIssuer(opts.issuer)
  jwks = HTTPS.GET_JSON(doc.jwks_uri, followRedirects=false)
  signingKey = jwks.KeyById(header.kid)
  allowedAlgs = oidc.allowedTokenAlgorithms OR ["RS256"]
  IF header.alg NOT IN allowedAlgs THEN
    RAISE VerificationError("OIDC token signing algorithm is not allowed")
  END
  IF header.alg is not implemented by this binding THEN
    RAISE VerificationError("OIDC token signing algorithm is not implemented")
  END
  IF signingKey == nil OR NOT OIDCKeySupportsAlg(signingKey, header.alg) THEN
    RAISE VerificationError("OIDC signing key mismatch")
  END
  IF NOT JWT.VerifySignature(token, signingKey) THEN
    RAISE VerificationError("OIDC token signature invalid")
  END
  IF claims.exp is missing OR not a NumericDate THEN
    RAISE VerificationError("OIDC token missing or invalid exp")
  END
  IF claims.iat is missing OR not a NumericDate THEN
    RAISE VerificationError("OIDC token missing or invalid iat")
  END
  IF claims.exp <= claims.iat THEN
    RAISE VerificationError("OIDC token exp must be after iat")
  END
  IF claims.nbf is present AND not a NumericDate THEN
    RAISE VerificationError("OIDC token invalid nbf")
  END
  ValidateJWTTimes(claims, DefaultIfMissing(oidc.clockSkew, 30))

  IF claims.sub == "" THEN
    RAISE VerificationError("OIDC token missing sub")
  END
  dnsidSubject = nil
  IF opts.verifyDnsidSubject != false THEN
    dnsidSubject = identityResolver.VerifyDomain(claims.sub, opts.peerCert)
  END
  ValidateJWTTimes(claims, DefaultIfMissing(oidc.clockSkew, 30))  // recheck after DNSid verification
  RETURN VerifiedOIDCSubject{ issuer: claims.iss, subject: claims.sub, audience: opts.audience, verifiedDomain: dnsidSubject, claims: claims }
END
```

`NumericDate` here means a finite JSON number (including zero/fractions), not a
Boolean or coerced string. `ValidateJWTTimes` uses the current instant without
rounding down, rejects `now >= exp`, and permits `iat`/present `nbf` only through
`now + clockSkew`. Skew does not extend expiration. The JOSE date/default/peer
boundary checks also apply here with OIDC's own issuer/audience policy.

`verifyDnsidSubject=false` is an advanced issuer-attestation-only mode. It MUST
be explicit because it trusts the issuer without independently verifying the
subject's DNSid identity. It also skips DNSid accountable-entity acceptance and
MUST NOT be represented as satisfying that policy. Applications requiring DNSid
acceptance MUST use subject verification; issuer-only mode is not an automatic
fallback after DNSid verification or acceptance fails.

## Optional Provider Surface

Bindings that expose server-side OIDC helpers MAY provide an `OIDCProvider`.
This is optional; SDKs can fully support client and relying-party use without it.

```
OIDCProvider(
  issuer: string,
  signer: TokenSigner,
  subjectEligibility: SubjectEligibility,
  identityResolver: IdentityResolver,
  jtiStore: JTIStore,
  rateLimiter?: RateLimiter
)
```

Provider behavior:

1. Accept only `POST /token` with `application/x-www-form-urlencoded` bodies.
2. Reject requests exceeding implementation-defined form or assertion size limits
   before parsing.
3. Apply `rateLimiter`, or equivalent external enforcement, before token exchange
   work.
4. Require `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`.
5. Parse the untrusted assertion only enough to read `iss` for eligibility and
   key discovery.
6. Before any outbound DNSid/JWKS fetch, require the subject to be eligible by
   local policy to avoid SSRF amplification.
7. Resolve and verify the subject's DNSid runtime signing key.
8. Verify the assertion signature before trusting any claims other than the
   prechecked `iss` used for lookup.
9. Require `iss == sub`, assertion `aud` exactly equal to the provider issuer,
   non-empty `jti`, `iat`, and `exp`.
10. Reject assertions outside the configured time window or longer than
    `oidc.maxAssertionLifetime`.
11. Atomically reserve `jti` if absent before issuing a token; duplicate `jti` or
    replay-store failure MUST fail closed.
12. Validate requested scopes only after the assertion is authenticated.
13. Issue short-lived JWTs with `iss = provider issuer`, `sub = DNSid domain`,
    `aud = requested audience`, `iat`, `exp`, `jti`, and optional profile claims
    such as `scope` or `environment`.

Provider-issued tokens SHOULD be signed with an issuer-controlled key advertised
from the issuer's JWKS. That key is not the DNSid subject's key.
