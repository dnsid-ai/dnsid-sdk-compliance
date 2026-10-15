# SDK Conformance Vectors

These language-neutral fixtures test behavior defined by the SDK design docs.
Every SDK may adapt the JSON into its native test harness, but it must preserve
the case inputs and expected results.

The compliance harness also consumes the auto-discovered YAML suites under
`fixtures/`. In addition to the core data-model vectors, those suites verify
release conformance metadata, deterministic TXT-record generation and entity-key
signing, and the separate six-state protocol status document.

## HTTP Message Signatures

[`http-message-signatures.json`](http-message-signatures.json) exercises the
constrained RFC 9421 component model and exact signature-base construction from
one parsed `Signature-Input` member. The expected base is authoritative UTF-8
text. Rejection text is not normative; `expectedError` documents the expected
failure reason but the initial adapters compare only success versus rejection.

These vectors intentionally stop before cryptographic signing. A correct
signature over an incorrect base is still non-interoperable, so all SDKs must
first produce the same base or fail closed on the same unsupported component
semantics.

## Web Bot Auth

[`web-bot-auth.json`](web-bot-auth.json) targets the DNSid WBA profile in
[10](../10-web-bot-auth.md), targeting published
`draft-ietf-webbotauth-httpsig-protocol-00`, including its directory requirements.
It contains fixed Ed25519 test keys, exact request/directory bytes, signature bases,
signatures, and SHA-256 content digests. All private material is disposable test
data; the private-directory-key case intentionally tests prohibited disclosure.

The corpus separates three kinds of expectation:

- Exact RFC 9421 request-base construction, without WBA acceptance policy.
- Request signing and directory serving: coverage, thumbprint IDs, algorithm,
  tags, nonce encoding, TTL limits, body bytes/digests, discovery, and preservation
  of existing Basic or Bearer credentials.
- Request/directory verification: positive paths, non-default labels, incomplete
  or ambiguous signatures, missing coverage/timestamps, wrong tags/keys/algorithms,
  modified content, expired/future evidence, DNSid failure without fallback,
  cache-hit acceptance/key/freshness checks, SSRF/Web PKI, current-peer evidence,
  and nonce replay/store failure. Additional cases cover parameterized digest
  coverage without supplied content, configuration mutation, fresh non-cacheable
  directories, zero-TTL acquisition, valid-plus-invalid candidate ambiguity,
  distinct-key directory candidates, exact recipient coverage policy, directory
  JWK metadata, coded responses, response `@status`, HTTP 503, and timeouts.
  Regressions include query form encoding (`~`, `*`, spaces, and empty values),
  network `Age`/`Date` staleness even without local caching, and local `ku`
  empty-path aliases.
  WG revision `00` cases require a covered `Signature-Agent` even with trusted
  caller discovery, reject non-origin `directory` values before discovery,
  reject same-host public redirects without following them, and reject future
  directory `created` values even within configured request clock skew. A
  relabeled signature retains its original covered discovery member.

Message bodies are standard-base64 strings so empty supplied content remains
distinct from absent content. `signatureBase` is authoritative UTF-8 text;
`signatureValid` and `digestValid` describe cryptographic fixture integrity,
not DNSid acceptance. Authority-only signatures remain valid after changing an
uncovered operation; optional method/target-URI coverage protects the query.
These vectors do not strengthen the required WBA coverage policy.

Verification cases reference named signed messages and a fixed clock. Their
`verification` values describe injected resolver, discovery, cache, current-peer,
and replay-store behavior; they are not authenticated DNSid evidence or a
production trust catalog. Native test adapters must implement those dependencies
and run the real profile verifier. Scenario flags must drive injected dependencies
or real operation sequences, not directly supply expected verdicts. Transport
failure cases must exercise the actual discovery transport boundary. Adapter
errors and unsupported capabilities MUST NOT count as successful negative tests.
Native verification rejections use normalized `ConformanceError`; malformed
caller policy uses `ArgumentError`. Unknown adapter/runtime exceptions are not
verification rejections. Exact error text is not normative. Where an expectation
includes `transient` or `discoveryRequests`, adapters must report the native error
classification or observed discovery count, not infer it from the expectation.
`configMutation` changes the caller's configuration after constructing the
profile; an expired request must remain rejected under the original policy.
Signing cases also mutate nested discovery URI settings; output must still
match the original configuration. Signing always includes and covers
`Signature-Agent`; no signing case permits its omission. Directory serving checks
require backdating by `min(5, ttl - 1)` seconds without extending the total signed
lifetime, cap `max-age` at remaining validity, and require `must-revalidate`
without stale-serving directives. Checker unit tests cover TTLs of 300, 60, 5,
and 1 seconds and cache directives. Fixed verification fixtures remain valid
inputs; external signers need not use the SDK helper's backdate or cache directives.
`signingKeyChange` activates a second disposable key at the provider's first
current-key sign call. A request or directory must either verify under its
advertised original/new key or explicitly reject through the SDK signing API.
Only recognized native rejection types pass this safety check; adapter/runtime
errors and unsupported methods still fail. `localKu` supplies a known local
operational endpoint through the native signing construction path.

Directory caching is optional. Cache cases apply only when a binding reuses
directory evidence; uncached bindings must instead test repeated fresh discovery
with renewed DNSid checks, including later acceptance denial and current-key
changes. Cache adapters must preserve original acquisition/age metadata through
the native discovery boundary, not assume fixture-only `cachedAt` is a verifier
input. Repeated invocations must prove that the freshness window does not restart.
`uncachedExpect` supplies the alternative expectation for bindings that do not
cache directories: successful repeated operations must perform two fresh
network discoveries. A newly fetched non-cacheable response remains usable in
its acquiring invocation. Explicit HTTP age/deadline cases have no uncached
alternative: fetching over the network does not authorize known HTTP-stale evidence.
TypeScript receives real raw streams in isolated processes; process crashes fail
that case rather than being hidden by buffering or aborting the complete matrix.

The native Go cache regression uses an overlay of the SDK's core test fixtures:

```sh
DNSID_GO_DIR="$HOME/dnsid-go" .venv/bin/python -m unittest discover -s harness -p 'test_*.py'
```

Without `DNSID_GO_DIR` that one SDK-dependent test is skipped. It confirms that a
full refresh learning revocation cannot leave an older cached `ACTIVE` result
usable with a positive status-check interval. It is not part of wire-vector counts.

Remaining required native coverage includes certificate and key-age expiry with
zero DNS TTL, all numeric configuration boundaries (including non-finite and
Boolean inputs where representable), configuration accessor ownership, and repeated
stream replay without retained buffers or lost cleanup. Native tests must also
cover URL/key-pair cache isolation, newer-directory key removal, and retention
without stale success after a failed refresh. Native coverage must also test
rejection of `ku` as WBA discovery, bounded key-mismatch refresh through
`RefreshingIdentityResolver`, successful replacement of cached current-key state,
unchanged/revoked/unavailable refresh outcomes, concurrent retry admission and
cooldowns, invalid-signature refresh suppression, and expiry during refresh.
Cached-directory key misses also require bounded re-fetch tests: upstream
revalidation, URL/domain cooldowns, fresh-miss suppression, and no failed-fetch fallback.
These scenarios are not yet encoded in the shared corpus; existing corpus results
do not establish support for the new refresh contract. Bindings supporting
caching must also test original age/deadline retention, including missing
`Date`/`Age`; uncached discovery does not prove cache-reuse correctness. The full
matrix remains in [10: Directory verification requirements](../10-web-bot-auth.md#directory-verification-requirements).
Passing this corpus does not establish complete SDK coverage or a full SDK
review. Native adapters and measured runs are required before advancing
implementation coverage claims.

Regenerate deterministically or check the artifact without importing an SDK:

```sh
.venv/bin/python harness/generate_wba_fixtures.py
.venv/bin/python harness/generate_wba_fixtures.py --check
.venv/bin/python harness/wba_vectors.py
```

The independent cryptographic checker supports only this fixture subset of
structured fields and component extraction. It is not a production WBA verifier,
does not perform DNSid acceptance, and cannot establish partner interoperability.
SDKs may consume this corpus directly in their own native tests. Generation also
maintains deterministic local TLS credentials under `shims/testdata/`; these
public test credentials must never be used in a deployment.

## Shared lifecycle reducer and snapshots

[`lifecycle-transitions.json`](lifecycle-transitions.json) exercises the shared
lifecycle interpretation in
[`06-log-bindings.md`](../06-log-bindings.md#implemented-lifecycle-interpretation).
Each case starts with a new reducer in `UNISSUED`; a separate case is therefore
a separate identity verification history even when it uses the same FQDN.

The fixtures contain only reducer-relevant fields. They are not wire events and
deliberately omit signatures, full JWK bodies, canonical encodings, and
log-method proof metadata. A production harness either substitutes valid
cryptographic fixtures or calls the reducer after method verification.

`reduce` cases apply every event in verified lifecycle order. `snapshot` cases
apply only a verified prefix through `at`; they reject a boundary that would
skip a future-timestamped event and then include a later log event. Exact error
text is not normative; `errorCategory` is.

## C2SP candidate selection

The active selection evidence is
[`c2sp-lifecycle-selection-logical-v1.json`](../../../fixtures/c2sp-lifecycle-selection-logical-v1.json),
regenerated for method revision `d5a65d06f76eff4db81e50f8767a600d2ca7fc2a`.
The original signed evidence and its
[semantic snapshot](../../../fixtures/historical/c2sp-lifecycle-selection.json)
remain untouched as historical baselines, not current chain conformance.
The generator changes canonical signing bytes, re-signs affected events, rebuilds
Merkle paths, and re-signs checkpoints/witness statements; it does not merely
change expected outcomes or a source digest.

[`c2sp-lifecycle-selection.json`](c2sp-lifecycle-selection.json) tests the
binding-owned boundary before the shared reducer. It distinguishes candidates
that cannot be authenticated and bound to the lifecycle, and are therefore
ignored, from authenticated chain or transition contradictions, trusted
evidence failures, migration-history failures, or incompleteness that must abort
fresh complete logged-state verification.

`authenticated` means all required role signatures verify under predecessor
authority. The old misleading `issuance-resigned` case is now named
`issuance-signed-extension`: its signed `dnsid_test_variant` changes the payload,
so the fatal second-genesis expectation is unchanged. Separate ES256 cases use
actual high-S/low-S signature-only copies, including high-S first and replay
after revocation. Other cases cover invalid/missing countersignatures,
historical-predecessor forks, and rejection of prohibited index/leaf chains.

The corrected contract deduplicates exact canonical signed payloads, excluding
signatures. New payloads require all role signatures under verified predecessor
authority; genuinely different authenticated post-terminal events still cause
`TERMINAL_STATE`. The same invariants are also exercised by the focused check below.

The semantic JSON is paired with exact JCS entries, real signatures, hashes,
proofs, and checkpoints in the active wire evidence. The migration selection
case still uses an injected trusted prior-history snapshot; it is not a recursive
source-log proof or exact-cutoff migration integration test. Candidate effect IDs
are harness labels, not event IDs or occurrence-proof evidence.

Regenerate/check the selection and portable bundle artifacts without SDK imports:

```sh
.venv/bin/python harness/generate_c2sp_fixtures.py
.venv/bin/python harness/generate_c2sp_fixtures.py --check
```

This requires `cryptography >= 43` for deterministic ES256 signing. All keys are
public disposable fixture keys. The generator only accepts the ASCII/integer JCS
subset used by these fixtures. CI checks reproducibility before running SDKs.
Run `harness/run.py` for SDK selection checks and `make c2sp-matrix` for the
corrected three-writer/three-verifier portable-bundle matrix. No old-format
fallback is permitted.

## C2SP event identity

[`c2sp-event-identity.json`](c2sp-event-identity.json) fixes exact canonical
bytes, the event-ID zero-byte separator, the unchanged separator-free state
hash, and hash outputs for the corrected
[`c2sp-tlog` binding](../11-c2sp-tlog-binding.md). Placeholder predecessor
hashes and state thumbprints make these hash-primitive vectors, not a verified
lifecycle or C2SP proof bundle. The unknown signed extension must affect the ID.

Run the focused check from the compliance repository root:

```sh
.venv/bin/python harness/c2sp_event_identity_check.py
```

It uses the already-required `cryptography` dependency and no SDK imports. The
check verifies these golden hashes and generates real ES256 issuance, rotation,
and revocation signatures with disposable test keys. It checks high-S/low-S
copies before and after the original, independently re-signed identical payloads,
stripped/invalid countersignatures, different complete-entry leaf hashes, stable
logical history, historical-predecessor forks, signed chain errors, genuinely
different genesis, and post-terminal contradictions.

Its small reducer assumes complete, included, context-bound fixture entries and
supports only the event types exercised. Its JSON encoder deliberately supports
only the printable-ASCII/safe-integer fixture subset of JCS. This is not a general
parser or production reference verifier. It does **not** verify C2SP inclusion or
consistency proofs, bundles, migration, networking, or SDK method dispatch.
Those integration requirements remain in the method and SDK design. The focused check
is separate from SDK selection and matrix results and does not increase recorded
SDK conformance counts or imply released support for the corrected contract.
The method, envelope, and bundle version labels are unchanged; older results
cannot establish conformance to the changed semantics.

## C2SP managed trust selection

[`c2sp-managed-trust-selection.json`](c2sp-managed-trust-selection.json) tests
the exact catalog-dispatch boundary of the named DNSid-managed trust
factory. Each case parses the complete `lr` before comparing its exact `(scope,
canonical log_prefix)` selector. Exact development and production selectors
select their respective profile-backed entries; wrong scopes, unknown or
deceptive hostnames, and malformed or noncanonical references fail closed.

The fixture contains selector and trust-mode metadata only. It deliberately
contains no policy, checkpoint, witness, or bundle-signer keys and MUST NOT be
loaded as an SDK trust catalog. Operational trust material remains the reviewed
snapshot vendored by each SDK release. `reason` text documents the expected
selection outcome but is not a normative error string.

## Stable error categories

| Category | Meaning |
|---|---|
| `GENESIS_REQUIRED` | A shared history begins with an event other than `ISSUANCE`. |
| `DUPLICATE_ISSUANCE` | A second `ISSUANCE` appears in one shared identity history. |
| `INVALID_ISSUANCE` | Issuance key material is missing, inconsistent with its thumbprints, or does not separate entity and operational roles. |
| `TERMINAL_STATE` | The shared reducer receives an event after `REVOCATION` or `RETIREMENT`. |
| `DOMAIN_MISMATCH` | An applied event names a different identity. |
| `KEY_CONTINUITY` | Rotation does not continue from the active operational key or introduces invalid key material. |
| `INVALID_REVOCATION_REASON` | A revocation reason is missing or outside the base vocabulary. |
| `INVALID_MIGRATION` | Migration references are equal or verified history stitching is unavailable. |
| `SNAPSHOT_EMPTY` | No verified event exists at or before the requested time. |
| `SNAPSHOT_NON_PREFIX` | The requested timestamp would select a non-prefix subsequence. |
| `UNSUPPORTED_EVENT` | No supported base or companion profile defines reducer semantics for the event type. |
| `CHAIN_CONTINUITY` | An authenticated C2SP event does not continue the signed stream chain, or accepted completeness evidence contradicts the applied chain. |
| `INVALID_EVIDENCE` | An accepted checkpoint, policy, witness quorum, trusted bundle, or other completeness evidence fails. |
| `INCOMPLETE_STREAM` | The binding cannot establish complete logged-state history. |
