# Web Bot Auth Profile

## Status and scope

Web Bot Auth (WBA) is an application profile over RFC 9421 and the HTTP Message
Signatures Directory drafts. It is not part of DNSid protocol core.

This design targets:

- draft-meunier-webbotauth-httpsig-protocol-00
- draft-meunier-webbotauth-httpsig-directory-00
- RFC 9421, RFC 8941, RFC 9530, RFC 7638, and RFC 8037

The Internet-Drafts are revision `00`. References to `dnsid-draft-01` describe
the DNSid key-role profile, not a WBA draft revision.

This cut provides request signing and directory serving. Request and directory
verification below are mandatory behavior for a future verifier API, not an
existing API claim. Shared RFC 9421 behavior comes from
[02-rfc9421-http-message-signatures.md](02-rfc9421-http-message-signatures.md).

For `dnsid-draft-01` and verification-only `DNSid1`, WBA uses the verified
agent `ku` key. `ek` is not an application-signing key.

## WBA requirements and DNSid constraints

The WBA drafts permit broader behavior than this SDK. The first public DNSid
SDKs intentionally use this narrower **DNSid WBA profile**:

| Area | WBA draft | DNSid WBA profile |
|---|---|---|
| Target coverage | At least one of `@authority` or `@target-uri` | Exact unparameterized `@authority` required |
| Signing algorithms | Registered asymmetric algorithms | Ed25519 only |
| Discovery schemes | Draft-defined schemes | HTTPS only |
| Signature label | Any valid label | Signers default to `sig1`; verifiers accept any valid label |
| `alg` parameter | Not one of WBA's four mandatory parameters | Signers emit and DNSid verifiers require `ed25519` |
| Content | No universal digest requirement | Supplied content requires covered SHA-256 `Content-Digest` |
| Directory response coverage | Draft baseline | DNSid server additionally covers `content-type` and `cache-control` |
| DNS authority | Outside WBA | Directory key must bind to verified DNSid `ku` key material |

A generic WBA implementation can conform to the drafts without satisfying
these additional DNSid policy constraints. SDK documentation and marketing
must not claim complete general WBA interoperability.

WBA itself requires request signature parameters `created`, `expires`, `keyid`,
and `tag="web-bot-auth"`. `keyid` is the unpadded base64url SHA-256 RFC 7638 JWK
thumbprint, not the DNSid `{domain}#{kid}` identifier.

## Configuration

WBA settings are profile-owned, not members of `DnsidConfig`. The DNSid WBA
profile MUST verify the signer's DNSid identity and enforce the supplied identity
resolver's configured accountable-entity acceptance on every invocation. Directory
self-signatures alone do not satisfy either requirement.

A binding offering generic, non-DNSid WBA verification must expose it as a
separately and explicitly selected mode, including when DNSid acceptance is
configured. Its result MUST NOT claim DNSid verification or entity acceptance.
It MUST NOT be an automatic fallback after DNSid verification or acceptance
fails. This design does not require a generic WBA verifier or a new mode toggle.

| Field | Type | Default | Requirement |
|---|---|---|---|
| `webBotAuth.signatureAgent.uri` | HTTPS URI | `https://{domain}` | Origin for `directory`; direct endpoint for `jwks_uri`. |
| `webBotAuth.signatureAgent.type` | `directory` or `jwks_uri` | `directory` | Discovery interpretation placed in `Signature-Agent`. |
| `webBotAuth.signatureTTL` | seconds | 60 | Positive and no greater than 300. |
| `webBotAuth.includeSignatureAgent` | boolean | true | Cloudflare interoperability currently requires true. |
| `webBotAuth.directorySignatureTTL` | seconds | 300 | Positive and no greater than 300. |
| `webBotAuth.clockSkew` | seconds | 5 | Non-negative verification tolerance. |

The draft recommends expiry no later than 24 hours. DNSid deliberately limits
accepted request and directory lifetimes to five minutes.

## Signature-Agent discovery

`Signature-Agent` is an RFC 8941 Dictionary. The selected member key SHOULD
match the HTTP signature label. DNSid signers use `sig1`, for example:

```http
Signature-Agent: sig1="https://agent.example";type=directory
```

The discovery types supported by this profile are:

- `directory`: the HTTPS URI identifies an origin. The verifier discards any
  path, query, and fragment and fetches
  `/.well-known/http-message-signatures-directory` at that origin. DNSid
  signers emit an origin URI without path, query, or fragment.
- `jwks_uri`: the HTTPS URI is the direct directory/JWKS endpoint and is emitted
  with `;type=jwks_uri`. The `type` parameter is an RFC 8941 Token, not a String.

An absent `type` has the draft's `directory` meaning and MUST NOT be interpreted
as a direct custom URL. The SDK emits `type` explicitly to avoid ambiguity.
Unsupported discovery types are rejected by the DNSid profile.

When sent, the selected member is covered using the exact component identifier
matching its member key:

```text
"signature-agent";key="sig1"
```

Inbound verifiers do not hard-code `sig1`: they select the WBA signature by
`tag`, read its label and covered `signature-agent;key` identifier, and resolve
that selected dictionary member.

## Request signing

`CreateWebBotAuthSignedRequest(req, opts)`:

1. Requires an Ed25519 `ku` signing key.
2. Starts with exact unparameterized `@authority`.
3. If content is supplied, buffers/replays the exact bytes, sets RFC 9530
   `Content-Digest` with SHA-256, and covers `content-digest`. Empty supplied
   content is hashed as an empty byte sequence.
4. Unless disabled, emits the configured `Signature-Agent` member and covers
   that exact `key` component.
5. Validates additional components against the constrained matrix in the RFC
   9421 design.
6. Rejects a non-positive TTL or one greater than 300 seconds.
7. Emits:
   - `keyid` as the active public JWK thumbprint;
   - `alg="ed25519"`;
   - integer `created` and `expires`, with `expires = created + ttl`;
   - 64 cryptographically random bytes encoded as unpadded base64url in
     `nonce`;
   - `tag="web-bot-auth"`.
8. Signs under label `sig1` by default.

A request signature therefore has at least:

```text
Signature-Input: sig1=("@authority" ...);keyid="...";alg="ed25519";created=...;expires=...;nonce="...";tag="web-bot-auth"
```

The shared RFC 9421 content rules define stream handling and digest
verification. Body presence is not inferred solely from `Content-Length` or
HTTP transfer framing.

## Directory serving

`ServeHttpMessageSignaturesDirectory(req)` serves:

```text
/.well-known/http-message-signatures-directory
Content-Type: application/http-message-signatures-directory+json
```

The response body is a JWKS object. Each directory JWK:

- contains public key material only;
- has `kid` equal to its unpadded RFC 7638 thumbprint;
- uses the HTTP Message Signatures algorithm name `ed25519` in `alg`, not JOSE
  `EdDSA`;
- has `use="sig"`;
- is rejected if recomputing the thumbprint does not reproduce `kid`.

The thumbprint input contains only the RFC 7638 required public members (`crv`,
`kty`, and `x` for Ed25519). It excludes `kid`, `alg`, `use`, `d`, and extension
members.

The DNSid directory helper sets:

- `Cache-Control: max-age=300` or the lower configured TTL;
- a SHA-256 `Content-Digest` over the exact JSON bytes;
- one complete signature per usable directory key when the binding can sign
  with each key.

Each directory signature covers:

- `"@authority";req`
- `content-type`
- `cache-control`
- `content-digest`

and includes:

- the key thumbprint as `keyid`;
- `alg="ed25519"`;
- integer `created` and `expires` with a lifetime no greater than 300 seconds;
- a random nonce;
- `tag="http-message-signatures-directory"`.

The minimal DNSid implementation has exactly one current operational key and
therefore emits one directory key and one signature. Multi-key implementations
use distinct labels and signatures and must define deterministic key/signature
selection.

## Request verification requirements

A future DNSid WBA verifier performs these checks:

1. Parse the complete `Signature-Input` and `Signature` fields and select
   exactly one complete signature tagged `web-bot-auth`.
2. Require integer `created` and `expires`, `created <= expires`, a lifetime no
   greater than 300 seconds, and current-time validity with the configured
   clock skew.
3. Require a syntactically valid unpadded base64url SHA-256 JWK thumbprint in
   `keyid`, `alg="ed25519"`, and exact unparameterized `@authority` coverage.
4. If content is supplied, require and recompute covered `content-digest` under
   the shared RFC 9530 rules.
5. If `Signature-Agent` is present, require that one selected dictionary member
   is covered with `signature-agent;key="member"`. Resolve its explicit or
   default discovery type as defined above.
6. Establish `signerDomain` from caller policy. Discovery from
   `Signature-Agent` is allowed only when policy permits its HTTPS origin host
   to identify the signer. Cross-host delegation is unsupported without a
   separate authenticated delegation proof.
7. Treat discovery as SSRF input: require HTTPS and valid Web PKI; resolve and
   connect only to public addresses for the approved host; re-check every
   redirect and connection; reject localhost, loopback, private, link-local,
   reserved, multicast, and IPv6 ULA targets; and enforce redirect, timeout,
   response-size, key-count, and JSON-depth limits.
8. Select an OKP/Ed25519 directory key whose recomputed thumbprint equals
   `keyid` and whose `alg`, if present, is `ed25519`; then verify the canonical
   request signature base.
9. Call `VerifyDomain(signerDomain)`, including configured counterparty
   acceptance, and accept the WBA key only when the same public-key thumbprint
   is present in verified current `ku` key material. Missing DNSid identity or
   acceptance denial rejects; directory-only verification is not a fallback.
10. Apply local nonce replay policy when one-time request semantics are needed.

`Signature-Agent` is recommended by WBA but remains optional. Without it, the
caller must provide a trusted signer domain and key-discovery policy.

## Directory verification requirements

For each candidate directory key, a future verifier:

1. Requires status 200, the directory media type, bounded JSON, and a valid
   public JWK.
2. Recomputes the candidate JWK thumbprint and requires it to equal `kid`.
3. Selects a complete signature tagged
   `http-message-signatures-directory` whose `keyid` equals that thumbprint.
4. Applies the same timestamp and algorithm limits as above.
5. Requires exact `@authority;req`, `content-type`, `cache-control`, and
   `content-digest` coverage.
6. Verifies the recomputed SHA-256 content digest and then the canonical HTTP
   signature with the candidate key.
7. Rejects cache use beyond the earliest of HTTP cache freshness, signature
   `expires`, or DNSid key-state freshness.
8. Calls `VerifyDomain(signerDomain)`, including configured counterparty
   acceptance, and binds the key to verified current `ku` material, including
   on directory cache hits.

A directory self-signature proves possession and protects the response bytes.
It does not establish domain authority by itself.

SDK verifier validation MUST cover a directory-only signer with configured
acceptance (reject in the DNSid profile), a valid DNSid signer denied by policy
(reject without fallback), and cached directory evidence (reevaluate DNSid
acceptance and current key binding). A separately offered generic verifier must
test explicit selection and results that make no DNSid acceptance claim. These
requirements apply only to bindings that ship a WBA verifier; a signing-only
binding records them as `Not applicable` in its implementation tracker until a
verifier exists.

## Key reuse decision

The WBA draft advises against reusing signing keys across purposes and
protocols. DNSid intentionally defines `ku` as the current application/runtime
identity key, so the first profile permits the same Ed25519 key for WBA and
other DNSid runtime signatures. This is a deliberate profile deviation.

Cross-protocol separation is mandatory:

- WBA requests use a JWK-thumbprint `keyid`, required
  `tag="web-bot-auth"`, and WBA component policy.
- Directory responses use a different required tag and response component
  policy.
- DNSid generic HTTP signatures use a domain-qualified `keyid` and their own
  minimum component policy.

Verifiers never accept a signature under one profile's selection and policy as
another profile. A future dedicated WBA key can be introduced only with an
owner-authoritative DNSid binding; no unbound directory key is accepted.
