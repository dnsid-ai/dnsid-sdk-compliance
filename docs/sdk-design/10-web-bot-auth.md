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

This design requires request signing, directory serving, and DNSid WBA request
verification, including verification of discovered directory responses. Bindings
MUST expose the request verifier defined below. Request and directory verification
are required implementation work, not an existing API claim.

Until verification is implemented, describe a binding as **DNSid WBA request
signing and directory serving; verification not yet available** and record its
verification coverage as `Missing`. A signing-only binding MUST NOT advertise
end-to-end WBA support or imply that its DNSid HTTP signature verifier accepts
WBA requests. Shared RFC 9421 behavior comes from
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
| DNS authority | Outside WBA | Directory key must bind to the profile-selected current operational signing key |

A generic WBA implementation can conform to the drafts without satisfying
these additional DNSid policy constraints. SDK documentation and marketing
must not claim complete general WBA interoperability. RFC 9421 is a published
standard; the targeted WBA protocol and directory documents are Internet-Drafts,
not a finalized WBA standard. Any partner interoperability claim MUST name the
external implementation/version and WBA draft revisions actually tested, and
state which signing, discovery, directory, or verification paths were tested.
Local signer tests alone do not establish partner interoperability.

A JWT in `Authorization: Bearer` is not this profile. Reserve WBA names for this
RFC 9421 surface; [JWT bearer transport](03-jose-jwt-jws.md#http-bearer-transport)
remains a separately selected application authentication mechanism. WBA signing
MUST preserve an existing `Authorization` field.

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
| `webBotAuth.includeSignatureAgent` | boolean | true | Enables Signature-Agent-based discovery. Keep enabled unless the verifier has trusted out-of-band discovery; partner compatibility requires testing the named implementation and draft revision. |
| `webBotAuth.directorySignatureTTL` | seconds | 300 | Positive and no greater than 300. |
| `webBotAuth.clockSkew` | seconds | 5 | Non-negative verification tolerance. |

The draft recommends expiry no later than 24 hours. DNSid deliberately limits
accepted request and directory lifetimes to five minutes. TTLs and clock skew
MUST be finite numeric values, not Booleans. TTLs must produce a positive integer
signature lifetime within the stated bound. Defaults apply only when omitted;
explicit zero skew means zero tolerance. Invalid settings raise `ArgumentError`
before network work. Apply shared
[profile configuration ownership](README.md#profile-configuration-ownership),
including nested discovery settings.

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

The response body is an uncoded JWKS object. The helper MUST NOT apply a content
coding or emit `Content-Encoding`. This constrained profile does not support
compressed directories; see [Directory transport](#directory-transport).
Each directory JWK:

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

## Public verifier contract

`VerifyWebBotAuthSignedRequest(req, opts) -> VerifiedDomain` authenticates one
DNSid WBA request. It returns the verified signer identity only after all request,
directory, and DNSid identity checks succeed. It does not grant application
permissions. Verification-only construction requires an `IdentityResolver` and
SSRF-safe HTTPS discovery transport, not a local identity or signing key.

Bindings MUST reuse the shared RFC 9421 parsing, component extraction,
signature-base construction, and content-digest primitives. WBA keeps its own
signature selection, thumbprint key ID, discovery, and acceptance rules; the
DNSid generic HTTP signature verifier is not a substitute.

`opts` supplies trusted signer-domain/discovery policy as defined below and a
per-invocation route for the current application peer certificate. Pass that
certificate to `VerifyDomain`; a directory endpoint's certificate is not the
application peer. Native cancellation/deadline support or equivalent options
MUST cover the complete operation, including directory reads and DNSid
verification, under the [shared resource budget](README.md#verification-resource-budgets).

The verifier MUST authenticate directory evidence under the directory requirements
below before accepting its key. Directory verification may be an internal helper;
no separate public directory-verifier API is required. A single invocation may
reuse its verified DNSid evidence for directory and request binding without
omitting current-peer, acceptance, or final freshness checks.

This change does not add mandatory `@method` or `@target-uri` coverage. The
existing WBA minimum component policy remains unchanged; applications decide
whether that coverage is sufficient for their operations. Bindings MUST expose
an optional `requiredComponents` policy in verifier options, defaulting to no
additional requirements. Every required component MUST be covered by the
selected request signature, using the exact component equality rules in section
02, including parameter values. Policy entries MUST be valid for request
messages; response-only `@status` and components with `req` are malformed policy.
Validate this policy and check coverage before discovery; malformed policy raises
`ArgumentError`, and missing coverage rejects verification. Signing extra components does not make a recipient require them.

## Signature selection

WBA overrides section 02's exactly-one-successfully-verified-candidate rule.
A complete candidate has the same label in both parsed `Signature-Input` and
`Signature` dictionaries. Request selection requires exactly one complete
candidate tagged `web-bot-auth`, before cryptographic verification. One valid
candidate plus another complete verification-invalid candidate with that tag
MUST be rejected, not resolved by trying both signatures.

Directory selection applies the same rule per candidate key thumbprint: exactly
one complete candidate tagged `http-message-signatures-directory` with that
`keyid` is required. Signatures for other keys do not create ambiguity; this
preserves multi-key directory support. Well-formed unrelated or incomplete
members do not count as complete candidates. Malformed Structured Fields still
reject the complete field under the shared parsing rules.

## Directory transport

Verifiers MUST request uncoded directory content and reject responses containing
`Content-Encoding`. Discovery transports MUST disable transparent decompression
and preserve the original response fields and content bytes so this rejection
and the shared Content-Digest checks operate on the received representation.
Injected transports have the same obligations. This is a DNSid WBA profile
restriction, not a change to section 02's general digest byte-layer contract.

Directory availability failures, including network timeouts and temporary HTTP
503 responses, MUST be classified as transient verification failures, not invalid
signatures. Invalid TLS, unsafe destinations, malformed or cryptographically
invalid evidence, and acceptance denial remain permanent failures. Neither
classification permits success, stale-evidence fallback, or directory-only
fallback.

## Request verification requirements

The DNSid WBA verifier performs these checks:

1. Parse the complete `Signature-Input` and `Signature` fields and select
   exactly one complete signature tagged `web-bot-auth`.
2. Require integer `created` and `expires`, `created <= expires`, a lifetime no
   greater than 300 seconds, and current-time validity with the configured
   clock skew.
3. Require a syntactically valid unpadded base64url SHA-256 JWK thumbprint in
   `keyid`, `alg="ed25519"`, and exact unparameterized `@authority` coverage.
4. If content is supplied, require exact unparameterized `content-digest`
   coverage. Validate every covered Content-Digest component under the shared
   RFC 9530 rules, including parameterized coverage; reject a covered digest
   when content was not supplied.
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
8. Verify the discovered response under the directory verification requirements
   below. Select an authenticated OKP/Ed25519 directory key whose recomputed
   thumbprint equals `keyid` and whose `alg`, if present, is `ed25519`; then
   verify the canonical request signature base.
9. Call `VerifyDomain(signerDomain, peerCert)`, including configured counterparty
   acceptance, and accept the WBA key only when the same public-key thumbprint
   equals that of the profile-selected current operational signing key in the
   verified runtime JWKS. Membership in that JWKS alone is insufficient; auxiliary
   or historical keys do not gain operational signing authority. Missing DNSid
   identity or acceptance denial rejects; directory-only verification is not a
   fallback.
10. Recheck request and directory time validity and DNSid evidence freshness
    before returning, including when network work consumed the validity window.
    Apply core's [acquisition-operation freshness rules](01-core-identity-manager.md#verifydomaindomain-string-peercert-tlscertificate---verifieddomain):
    fresh zero-TTL DNS evidence may be used within this acquiring WBA invocation,
    but never by a later invocation. Positive DNS TTL, runtime and record-signing
    certificate validity, and key-age bounds remain enforced. `Expiry()` alone
    is not a sufficient acquisition-operation validity check.
11. Apply caller-selected nonce replay policy when one-time request semantics
    are needed. The binding MUST provide an integration point for that policy.
    When enabled, require a non-empty nonce, atomically reject repeated
    `(signerDomain, keyid, nonce)` values, retain them through `expires + clockSkew`,
    and fail closed on replay-store errors. Without replay policy, document
    that time validity limits reuse but does not detect it.

`Signature-Agent` is recommended by WBA but remains optional. Without it, the
caller must provide a trusted signer domain and key-discovery policy.

## Directory verification requirements

For each candidate directory key, the verifier:

1. Requires status 200, the directory media type, bounded JSON, and a valid
   public OKP/Ed25519 JWK with no private material. Preserve and validate standard
   JWK metadata: `use`, if present, MUST be `sig`; `alg`, if present, MUST be
   `ed25519`. `key_ops`, if present, MUST be an array of distinct strings containing
   `verify` and no operations other than `sign` or `verify`. Malformed, empty, or
   verification-excluding arrays reject. Algorithm translation MUST NOT discard
   these restrictions.
2. Recomputes the candidate JWK thumbprint and requires it to equal `kid`.
3. Requires exactly one complete signature tagged
   `http-message-signatures-directory` whose `keyid` equals that thumbprint,
   under the signature-selection rule above.
4. Applies the same timestamp and algorithm limits as above.
5. Requires exact `@authority;req`, `content-type`, `cache-control`, and
   `content-digest` coverage.
6. Verifies the recomputed SHA-256 content digest and then the canonical HTTP
   signature with the candidate key.
7. Rejects cache use beyond the earliest of HTTP cache freshness, signature
   `expires`, or DNSid key-state freshness.
8. Calls `VerifyDomain(signerDomain, peerCert)`, including configured counterparty
   acceptance, and binds the key to the profile-selected current operational
   signing key, including on directory cache hits. A single invocation may reuse
   the same verified DNSid result for request and directory binding; two separate
   `VerifyDomain` calls are not required.

A directory self-signature proves possession and protects the response bytes.
It does not establish domain authority by itself.

### Directory caching

Directory caching is optional. A freshly acquired response with `no-store`,
`no-cache`, or a zero freshness lifetime MAY authenticate the acquiring
invocation; those directives restrict storage or reuse, not fresh acquisition.
Request and directory signature validity, DNSid evidence bounds, and final checks
still apply. Missing HTTP age metadata on a fresh response is not a reason to
substitute signature `created` for acquisition time or reject that invocation.

Cache obligations apply whenever directory evidence
is reused, including through an injected discovery transport. Reuse MUST preserve
HTTP freshness under RFC 9111 age calculations, with applicable `Date`/`Age` fields
and original acquisition timing. The discovery boundary MUST retain or expose
sufficient age metadata to establish the original freshness deadline. Returning
the same response MUST NOT restart its freshness window. Missing `Date` and `Age`
do not prove that reused evidence has age zero; evidence without sufficient age
metadata MUST NOT be reused as fresh. No new public metadata field is required
when a binding can enforce this internally.

Each invocation still requires current-peer handling, DNSid acceptance, current
operational-key binding, and final freshness checks. Directory caching does not
replace core's DNSid evidence freshness policy.

SDK verifier validation MUST cover a directory-only signer with configured
acceptance (reject in the DNSid profile), a valid DNSid signer denied by policy
(reject without fallback), and, when caching is supported, cached directory
evidence (reevaluate DNSid acceptance and current key binding). Uncached bindings
MUST instead test repeated fresh discovery, with acceptance denial and changed
current operational keys on later invocations. A separately offered generic
verifier must test explicit selection and results that make no DNSid acceptance claim. These
requirements are mandatory for the DNSid WBA verifier. A signing-only binding
records verification as `Missing`, not `Not applicable`.

Required verifier tests include successful signed request/directory verification,
non-default signature labels, bad request or directory signatures, wrong tags or
thumbprints, missing required coverage, modified content, expired evidence,
private-address discovery and redirect rejection, missing current-peer evidence
for `fl=mtls`, cache-hit acceptance denial or key rotation when caching is
supported, and configured nonce replay/store failure. Tests MUST confirm that neither DNSid verification failures
nor acceptance denial fall back to directory-only success.

Additional required validation covers:

| Scenario | Required result |
|---|---|
| Auxiliary non-signing key signs request and directory alongside a valid current operational key | Reject. |
| Fresh zero-TTL DNS evidence, otherwise valid | Acquiring invocation may succeed; next invocation needs fresh DNS. |
| Certificate or key-age bound expires, including with zero DNS TTL | Reject. |
| Repeated cache use, including without `Date`/`Age` | Preserve original freshness deadline; reject reuse without sufficient age metadata. |
| One valid plus one invalid complete same-tag request candidate | Reject before cryptographic selection. |
| One valid plus one invalid complete directory candidate for the same key | Reject that key; signatures for distinct keys are not ambiguous. |
| Authority-only signature with omitted versus configured operation coverage policy | Default may accept; configured missing coverage rejects. |
| Malformed, empty, or encryption-only directory `key_ops` | Reject. |
| Coded directory response | Reject without transparent decompression. |
| Valid directory signature also covering actual `@status` | Accept if all other checks pass. |
| Non-finite, Boolean, or out-of-range duration settings | `ArgumentError` before network work. |
| Caller mutates validated configuration, including nested discovery settings | Existing profile policy is unchanged. |
| Parameterized Content-Digest coverage without supplied content | Reject; digest validation is not limited to exact minimum coverage. |
| Fresh signed directory with `no-store`, `no-cache`, or `max-age=0` | Acquiring invocation may succeed; cache reuse remains restricted. |
| Repeated signing or verification of the same streamed message | Preserve cleanup without retaining earlier replay buffers. |
| Directory timeout or HTTP 503 | Transient failure; no successful fallback. |

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
