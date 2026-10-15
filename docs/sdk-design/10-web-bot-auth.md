# Web Bot Auth Profile

## Status and scope

Web Bot Auth (WBA) is an application profile over RFC 9421, not DNSid core.
This design targets
[draft-ietf-webbotauth-httpsig-protocol-00](https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol-00)
(September 1, 2026), including directory discovery, plus RFCs 8941, 9530, 7638,
and 8037. `dnsid-draft-01` names the DNSid key-role profile, not a WBA revision.

The [editor's copy](https://webbotauth.github.io/draft-ietf-webbotauth-httpsig-protocol/)
at [commit `be12662`](https://github.com/webbotauth/draft-ietf-webbotauth-httpsig-protocol/tree/be12662f3c5cc97e10e65a37355bdb33ba0d2fc4)
requires direct JWKS URLs without member parameters and separates JWK and HTTP
signature algorithm registries. Those unpublished changes are not adopted:
typed discovery and directory JWK `alg="ed25519"` follow WG revision `00`.

Bindings MUST provide request signing, signed-directory serving, and request
verification including directory verification. These requirements, identity
refresh, and directory backdating do not imply existing SDK support. Until a
binding implements verification, describe it as **DNSid WBA request signing and
directory serving; verification not yet available**, record verification as
`Missing`, and do not claim end-to-end WBA support or substitute the DNSid HTTP
signature verifier. Reuse the primitives in
[02-rfc9421-http-message-signatures.md](02-rfc9421-http-message-signatures.md).

For `dnsid-draft-01` and verification-only `DNSid1`, WBA uses the verified
current `ku` key. Onboarding MUST state that it must be Ed25519; ES256 operational
keys are unsupported. `ek` is not an application-signing key and may use ES256.

## WBA requirements and DNSid constraints

This **DNSid WBA profile** intentionally narrows the draft:

| Area | WBA draft | DNSid WBA profile |
|---|---|---|
| Target coverage | `@authority` or `@target-uri` | Exact unparameterized `@authority` |
| Algorithms | Registered asymmetric algorithms | Ed25519; `alg="ed25519"` required |
| HTTPS discovery | `directory`, `jwks_uri`, `cimd` | `directory`, `jwks_uri`; covered header required |
| Labels and count | Any label; multiple signatures | Signers default to `sig1`; verifier accepts any label but exactly one complete WBA candidate |
| Content | No universal digest requirement | Supplied content requires covered SHA-256 `Content-Digest` |
| Lifetime | Request expiry within 24 hours recommended | Request and directory signatures at most 300 seconds |
| Directory proof | Optional for directly resolved keys; required for redistributed-key URL attribution | Required for every accepted key; also covers `content-type` and `cache-control` |
| Directory JWK `kid` | Optional; equals thumbprint when present at well-known endpoint | Required thumbprint |
| Rotation and authority | Overlap recommended; DNS authority out of scope | Only the verified current DNSid operational key |

Do not claim complete general WBA interoperability or a finalized WBA standard.
Partner claims MUST name the tested external implementation/version, WBA draft
revision, and signing, discovery, directory, or verification paths. Local signer
tests do not establish partner interoperability.

[JWT bearer transport](03-jose-jwt-jws.md#http-bearer-transport) is separate and
MUST NOT be called WBA. WBA signing MUST preserve existing `Authorization` fields.

## Configuration

WBA settings belong to the profile, not `DnsidConfig`. Every DNSid WBA invocation
MUST verify DNSid identity and enforce the resolver's configured accountable-entity
acceptance. A directory self-signature satisfies neither requirement.

Generic non-DNSid verification is optional, must be explicitly selected, and MUST
NOT claim DNSid verification or entity acceptance. It is never an automatic
fallback after DNSid verification or acceptance failure; no generic-mode API is
required here.

| Field | Type | Default | Requirement |
|---|---|---|---|
| `webBotAuth.signatureAgent.uri` | HTTPS URI | `https://{domain}` | Origin for `directory`; endpoint for `jwks_uri`. |
| `webBotAuth.signatureAgent.type` | `directory` or `jwks_uri` | `directory` | Discovery interpretation. |
| `webBotAuth.signatureTTL` | seconds | 60 | Positive, at most 300. |
| `webBotAuth.directorySignatureTTL` | seconds | 300 | Positive, at most 300. |
| `webBotAuth.clockSkew` | seconds | 5 | Non-negative; never allows future directory `created`. |

Durations MUST be finite numbers, not Booleans; TTLs must produce positive integer
signature lifetimes within the bound. Defaults apply only to omitted values;
zero skew means zero tolerance. Invalid configuration raises `ArgumentError`
before network work. Apply shared
[configuration ownership](README.md#profile-configuration-ownership), including
snapshotting nested discovery settings against caller mutation.

`{domain}` is the agent identity FQDN, not `gi` or the request destination.
The WBA directory is separate from the live `ku` JWKS. Signing configuration
MUST reject `jwks_uri` identifying local `ku`; verifiers MUST reject discovery
identifying authenticated signer `ku`. Compare normalized WBA identifiers without
query or fragment, not URL path-name conventions.

## Signature-Agent discovery

`Signature-Agent` MUST be an RFC 8941 Dictionary. Signers emit and cover the
member keyed to their signature label:

```http
Signature-Agent: sig1="https://agent.example";type=directory
```

- `directory`: require an ASCII HTTPS origin without userinfo, path, query,
  fragment, or trailing `/`. Fetch
  `/.well-known/http-message-signatures-directory` at that origin. Signers reject
  invalid configuration before network work; verifiers MUST NOT strip components
  to repair invalid origins.
- `jwks_uri`: fetch the HTTPS directory/JWKS endpoint as supplied. `type` is an
  RFC 8941 Token, not a String.

Signers emit `type` explicitly; absent `type` means `directory`, never a custom
endpoint. Ignore unsupported types and invalid origins during member selection;
an invalid, unsupported, missing, or uncovered selected member rejects before
network work, even with trusted caller discovery. Do not infer type from path,
media type, or body. Legacy bare String discovery is unsupported.

Verifiers select by WBA tag, not a hard-coded label, and resolve the exact covered
`"signature-agent";key="member"`. An intermediary may relabel `Signature` and
`Signature-Input`; the covered discovery member may therefore retain a different
key. Verifiers MUST NOT relabel that member or attribute a signature to an
uncovered one.

The WBA identifier is the resolved well-known URL for `directory`, or the supplied
`jwks_uri` without query and fragment. Normalize per WBA section 5.5 (RFC 3986
sections 6.2.2 and 6.2.3). Key lookup and cached attribution MUST use the normalized
URL and thumbprint together within the verification policy context, not either
alone or just the hostname.

## Request signing

`CreateWebBotAuthSignedRequest(req, opts)` MUST:

1. Use the current Ed25519 `ku` key and default label `sig1`.
2. Start coverage with exact unparameterized `@authority` and include the configured
   discovery member keyed to the signature label. No setting or per-request
   option may omit it.
3. For supplied content, buffer/replay exact bytes, set SHA-256 `Content-Digest`,
   and cover exact `content-digest`. Empty supplied content hashes empty bytes;
   body presence is not inferred only from length or transfer framing.
4. Validate extra components against section 02's constrained matrix and reject
   TTLs outside `(0, 300]` seconds.
5. Emit the unpadded base64url SHA-256 RFC 7638 JWK thumbprint as `keyid` (not
   `{domain}#{kid}`), `alg="ed25519"`, integer `created` and
   `expires = created + ttl`, `tag="web-bot-auth"`, and 64 cryptographically random
   bytes encoded as unpadded base64url in `nonce`.

Shared RFC 9421 content rules govern stream replay, cleanup, and digest handling.

## Directory serving

`ServeHttpMessageSignaturesDirectory(req)` serves an uncoded JWKS object at
`/.well-known/http-message-signatures-directory` with
`Content-Type: application/http-message-signatures-directory+json`. The helper
MUST NOT emit `Content-Encoding` or apply content coding.

Each JWK contains public material only, `use="sig"`, `alg="ed25519"` (the HTTP
signature name, not JOSE `EdDSA`), and `kid` equal to its recomputed unpadded RFC
7638 thumbprint. Hash only the required public members: `crv`, `kty`, and `x` for
Ed25519; exclude metadata, private material, and extensions.

Set SHA-256 `Content-Digest` over exact JSON bytes and `Cache-Control: max-age=N`,
with `N` no greater than remaining signature validity at response generation.
Emit one complete signature per usable key when able to sign with each. Each
signature covers exact `"@authority";req`, `content-type`, `cache-control`, and
`content-digest`, and includes the thumbprint `keyid`, `alg="ed25519"`, integer
`created`/`expires` with lifetime at most 300 seconds, a random nonce, and
`tag="http-message-signatures-directory"`.

Signers MUST backdate directory signatures, without extending the configured
lifetime. For integer `ttl` and `now = floor(unixTime)`:

```text
backdate = min(5, ttl - 1)
created = now - backdate
expires = created + ttl
```

The default leaves at most 295 seconds of cache freshness. TTLs below six seconds
provide less clock tolerance; TTL 1 has none. Do not serve already expired
signatures. Verifiers still reject future directory `created` without skew.

The minimal implementation emits one current operational key and one signature.
Multi-key implementations need distinct labels and deterministic key/signature
selection.

## Rotation compatibility

WBA sections 4.2 and 5.5.2 recommend overlapping directory keys (a SHOULD).
DNSid [operational rotation](01-core-identity-manager.md#operational-key-rotation)
requires one current live `ku` key, with no superseded keys. Historical logs or
overlap in a generic WBA directory do not authorize old keys in this profile.
Once a verifier learns the new key, it rejects outstanding old-key requests even
if their signatures remain time-valid. No overlap grace or dedicated-key binding
is defined here.

Request TTL does not bound rotation disruption or revoke a stolen key. DNS/HTTP
caches, publication/log convergence, refresh limits, and availability can delay
new-key acceptance. A cached directory missing the new key also delays verification
until fresh discovery; mismatch refresh requires checkable signatures.

### Key-mismatch refresh

After directory and request signatures, coverage, and time checks pass, a mismatch
with the verified current `ku` thumbprint MUST trigger one
`RefreshDomain(signerDomain, peerCert)` attempt, subject to these limits:

- Allow at most one attempt per normalized domain per five seconds in the
  verifier's immutable context. Concurrent invocations share admission state;
  changing keys, labels, or discovery URLs does not obtain another allowance.
- Callers MAY join an admitted in-flight refresh; otherwise suppress retries
  during cooldown. Bound state and network work under the shared resource budget;
  refuse new refreshes when state is full rather than evict active cooldowns.
- Failed attempts consume the allowance. Do not refresh for malformed input,
  failed signatures, invalid discovery, DNSid verification failure, or acceptance
  denial. Never loop until keys match.
- Recheck both signatures' current-key binding, discovery/`ku` separation, all
  evidence validity, and per-invocation policy after refresh.

Suppressed, failed, or still-mismatched refresh MUST NOT authenticate a request.
Preserve normal evidence-error classification; never accept auxiliary, historical,
or stale keys, bypass revocation, or fall back to directory-only verification.

### Operational guidance

WBA tooling MUST reuse the shared
[managed rotation/recovery contract](01-core-identity-manager.md#operational-key-rotation),
including durable state and pausing request/directory signing. No separate WBA
rotation transaction or overlapping live `ku` keys. Test new-key acceptance through
a verifier caching the old key, bounded refresh, and restart recovery without
old-key signing.

For an unavailable or suspected compromised operational key, disable signing and
use [revocation/reissuance](01-core-identity-manager.md#registry-status-change-eg-revocation),
not routine rotation. The lifecycle coordinator promptly publishes non-active
status; invalidate verifier caches where possible. Short TTLs and mismatch
refresh do not stop an attacker signing under a still-cached current key.

## Public verifier contract

Bindings MUST expose
`VerifyWebBotAuthSignedRequest(req, opts) -> VerifiedDomain`. It authenticates the
request, directory, and DNSid identity before returning, without granting
application permissions. Construction needs a
[`RefreshingIdentityResolver`](README.md#identity-resolution) and SSRF-safe HTTPS
transport, not a local identity/key. Missing refresh capability is a construction
error; profiles MUST NOT work around it with cache eviction.

Reuse shared RFC 9421 parsing, component extraction, signature-base, and digest
primitives, but apply WBA selection, discovery, key-ID, and acceptance rules.
Directory verification may be internal; no separate public API is required.

`opts` supplies trusted signer-domain/discovery policy and the current application
peer certificate for `VerifyDomain`. Endpoint certificates are not peer evidence.
Cancellation/deadlines MUST cover directory reads and DNSid verification under
the [shared resource budget](README.md#verification-resource-budgets).

Without `fl=mtls`, fetching `ku` over validated HTTPS at the agent FQDN supplies
DNSid section 9.1 step 4's TLS connection. Only public identity resources, not the
crawler process, need inbound reachability. WBA does not replace that TLS check;
with `fl=mtls`, hosting cannot replace current application-peer evidence.

Expose optional `requiredComponents`, defaulting to no extra coverage. Entries
must be valid request components; `@status` and components with `req` are invalid.
Before discovery, raise `ArgumentError` for malformed policy and reject missing
coverage using section 02's exact component/parameter equality. `@method` and
`@target-uri` remain optional unless required by the recipient; signer-selected
extra coverage does not set recipient policy.

## Signature selection

A complete candidate has matching labels in parsed `Signature-Input` and
`Signature`. Before cryptographic verification, require exactly one complete
request candidate tagged `web-bot-auth`, or, for each directory key, exactly one
tagged `http-message-signatures-directory` with that thumbprint `keyid`. Distinct
keys' directory signatures do not create ambiguity. Ignore well-formed unrelated
or incomplete members; malformed Structured Fields reject the complete field.

This overrides section 02's exactly-one-successfully-verified-candidate rule:
one valid plus one invalid complete same-tag request candidate rejects. WBA
section 5.2.2 permits broader multi-signature behavior.

Nested signing is optional. If offered, covering `"signature";key="X"` MUST also
cover `"signature-input";key="X"` and all inner covered component identifiers;
reject signing if their values cannot be preserved. Verify signatures independently:
an outer signature neither validates the inner nor establishes authorization,
delegation, or consent.

## Directory transport

Require HTTP 200; all other statuses fail discovery. MUST NOT follow any redirect,
including same-host HTTPS. These rules also bind injected transports, regardless
of core DNSid fetcher redirect allowances.

Request uncoded content; reject `Content-Encoding`. Transports MUST disable
transparent decompression and preserve original fields and bytes for digest
verification. This restriction does not change section 02's general byte-layer
contract.

Timeouts and temporary failures such as HTTP 503 are transient, not invalid
signatures. Invalid TLS, unsafe destinations, malformed/cryptographically invalid
evidence, and acceptance denial are permanent failures. Neither permits stale
success or directory-only fallback.

## Request verification requirements

1. Parse complete signature fields and apply [selection](#signature-selection).
2. Require integer `created`/`expires`, `created <= expires`, lifetime at most
   300 seconds, and current-time validity with configured skew.
3. Require a valid unpadded base64url SHA-256 JWK thumbprint `keyid`,
   `alg="ed25519"`, exact unparameterized `@authority`, and recipient-required
   coverage.
4. Supplied content requires exact unparameterized `content-digest` coverage.
   Validate every covered digest, including parameterized components, under
   shared RFC 9530 rules; reject covered digests without supplied content.
5. Validate the selected covered `Signature-Agent` member before network work
   under [discovery](#signature-agent-discovery), even with trusted caller discovery.
6. Establish `signerDomain` from caller policy. Use the discovery origin host only
   if policy allows it to identify the signer. Cross-host delegation requires a
   separate authenticated proof and is otherwise unsupported.
7. Treat discovery as SSRF input: require HTTPS/Web PKI and public addresses for
   the approved host. Validate every connection; reject redirects, localhost,
   loopback, private, link-local, reserved, multicast, and IPv6 ULA destinations.
   Bound timeout, response size, key count, and JSON depth.
8. Validate directory transport, structure, digest, signature, and time as below.
   Select the candidate key matching request `keyid` and verify the canonical
   request signature. Defer DNSid binding until both signatures pass; a
   self-signed directory is not domain authority.
9. Call `VerifyDomain(signerDomain, peerCert)` with configured acceptance. Bind
   both request and directory to the profile-selected current operational key's
   thumbprint, not mere JWKS membership. Reject discovery identifying authenticated
   `ku`. Only a key mismatch permits [bounded refresh](#key-mismatch-refresh).
10. Before returning, recheck request/directory time validity and core
    [acquisition-operation freshness](01-core-identity-manager.md#verifydomaindomain-string-peercert-tlscertificate---verifieddomain).
    Fresh zero-TTL DNS evidence is usable only by its acquiring invocation;
    positive DNS TTL, runtime/record-signing certificate validity, and key-age
    bounds still apply. `Expiry()` alone is insufficient.
11. Provide an integration point for caller-selected nonce replay policy. When
    enabled, require a non-empty nonce, atomically reject repeated
    `(signerDomain, keyid, nonce)`, retain entries through `expires + clockSkew`,
    and fail closed on store errors. Otherwise document that time limits reuse
    but does not detect replay.

Missing DNSid identity, failed verification, or acceptance denial rejects without
directory-only fallback. Trusted discovery never makes `Signature-Agent` optional.

## Directory verification requirements

For each candidate key:

1. Require directory transport/media type, bounded JSON, and a valid public
   OKP/Ed25519 JWK without private members. If present, `use` MUST be `sig`, `alg`
   MUST be `ed25519`, and `key_ops` MUST be an array of distinct strings including
   `verify`, with no operations outside `sign`/`verify`. Reject malformed or empty
   arrays; algorithm translation MUST preserve metadata restrictions.
2. Recompute the RFC 7638 thumbprint and require matching `kid` and signature
   `keyid`, with [directory signature selection](#signature-selection).
3. Apply request lifetime, expiry, and algorithm limits, but reject any future
   `created` without skew, per WBA Appendix B.1.
4. Require exact `@authority;req`, `content-type`, `cache-control`, and
   `content-digest` coverage; verify SHA-256 digest and canonical signature.
5. Bind to the verified current DNSid operational key with current-peer and
   acceptance checks, including cache hits. One invocation may reuse its DNSid
   result for both bindings; a mismatch refresh waits until the request signature
   also verifies.
6. Limit reuse to the earliest HTTP freshness, signature expiry, or DNSid
   key-state freshness deadline.

### Directory caching

Caching is optional. Fresh `no-store`, `no-cache`, or zero-freshness responses MAY
serve their acquiring invocation subject to signature/DNSid validity and final
checks. Missing HTTP age metadata does not invalidate fresh acquisition or justify
using signature `created` as acquisition time.

All reuse, including injected transport caches, MUST preserve RFC 9111 age using
applicable `Date`/`Age` and original acquisition timing. Retain or expose enough
metadata to establish the original deadline; do not restart freshness on access.
Without sufficient age metadata, do not reuse evidence as fresh. No new public
metadata field is required if enforced internally.

Newer successful evidence replaces older keys for that URL, including removed
keys. Order direct resolutions by fetch time and signed proofs by `created`, not
receipt time. Failed resolution MUST NOT evict retained evidence or extend its
freshness; an invocation needing fresh evidence fails if discovery is unavailable.
Every invocation still checks current peer, acceptance, current-key binding, and
core freshness.

Native validation MUST cover:

- Successful verification and non-default/intermediary-relabeled labels; bad
  signatures, tags, thumbprints, coverage, modified content, and expired evidence.
- Directory-only signers with configured acceptance, DNSid failures, and policy
  denial without fallback; explicit generic-mode selection/results if offered.
  Cached bindings recheck acceptance and changed keys; uncached bindings test
  repeated fresh discovery with later denial and changed current keys.
- Missing/uncovered/unsupported discovery and non-origin `directory` URLs before
  network work, even with trusted discovery; URL/key-pair isolation; `ku` discovery
  including query/fragment variants; SSRF, invalid TLS, and same-host redirects.
- Future directory `created` by one second despite five-second skew; serving TTLs
  300/5/1 backdated 5/4/0 with bounded `max-age`; default-TTL verification with a
  clock five seconds behind generation.
- Mismatch refresh success, unchanged/revoked/denied/unavailable outcomes,
  concurrent cooldowns across changed keys/URLs, failed-attempt accounting,
  invalid-signature/failure suppression, and evidence expiring during refresh.
- Cache deadline/age retention, including missing `Date`/`Age`, newer-key removal
  despite older time-valid proofs, failed refresh without stale success, and fresh
  `no-store`/`no-cache`/`max-age=0` responses.
- Auxiliary-key rejection; zero-TTL acquisition versus later invocation and
  certificate/key-age expiry; missing current-peer evidence for `fl=mtls`.
- Valid-plus-invalid request candidates and same-key directory candidates;
  distinct-key directory signatures; nested signing's inner-coverage requirements.
- Default authority-only versus required operation coverage; malformed/empty/
  encryption-only `key_ops`; coded responses; valid extra `@status` coverage;
  parameterized digest coverage without content; nonce replay/store failure.
- Invalid numeric settings; configuration mutation including nested discovery;
  repeated streamed-message cleanup; transient directory timeout/HTTP 503.

## Key reuse decision

WBA advises against cross-purpose key reuse. This profile deliberately uses the
current Ed25519 `ku` for WBA and other DNSid runtime signatures. It also authorizes
`KEY_ROTATION`: compromise of a signing node with unrestricted key access can
authorize operational identity rotation. Tags do not stop fresh rotation
signatures; this does not grant `ek` authority or prevent entity revocation.
Deployment guidance MUST state this exposure.

Cross-protocol separation is mandatory: WBA requests use thumbprint `keyid`,
`tag="web-bot-auth"`, and request policy; directories use their distinct tag and
response policy; DNSid generic HTTP signatures use domain-qualified IDs and their
own coverage. Never accept one profile's signature under another profile's rules.

Dedicated WBA delegation needs a separate security design before broad multi-node
fleet deployment: owner-authoritative binding, signer identity, purpose, discovery
attribution, lifetime/withdrawal, current-issuer checks, and `ku` rotation behavior.
Delegated WBA-key overlap alone cannot bridge authorizing `ku` rotation. No unbound
directory key is accepted.
