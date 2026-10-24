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

`ENTITY_KEY_ROTATION` reducer cases cover continuity from the active entity key
(including after a previous entity rotation), rejection of a new key equal to
the active entity key or the active operational key (including after a
`KEY_ROTATION`), mismatched or missing new thumbprints, interleaving with
`KEY_ROTATION`, pre-genesis and post-terminal rejection, and a snapshot showing
that entity rotation leaves the operational key and `keyBoundAt` unchanged.
Signatures are binding-owned and are covered by the selection vectors below.

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
authority, with each signature's `kid` naming the key that verifies it; for
`ENTITY_KEY_ROTATION`, `new_ae` must name a non-empty `kid` of a `new_ek`
without private members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`, `oth`).
`failureScope: "genesis-anchor"` marks a self-authenticated genesis that is
not eligible for anchored selection, and that genesis's own successors; `authenticated-payload`
marks a fully signed rotation or genesis that fails structural validation.

A case may name `recordEk`, the disposable entity key the identity's TXT record
currently carries; the evidence supplies it as `recordEntityJwk`. Without
`recordEk`, the record carries the ISSUANCE entity key (`entityJwk`). Readers
that anchor genesis selection on the record `ek` use this key as described in
[Genesis Selection Anchored on the Record `ek`](../11-c2sp-tlog-binding.md#genesis-selection-anchored-on-the-record-ek).
For a case with `recordEk`, `valid` covers history selection and the bilateral
binding against that key. `bilateralBinding` gives the expected
`initialEntityThumbprint` and `currentEntityThumbprint`. When the record key is
not reachable from any valid history, the case asserts only `valid: false`:
anchored readers report no valid lifecycle events where other readers report a
key-continuity or record-key mismatch. When the record key is the active entity
key at the failing event, the case asserts the category.

The `ENTITY_KEY_ROTATION` cases cover binding a rotated record key and
rejecting the ISSUANCE key afterwards; chained rotations; wrong-key `prev_ae`
and invalid or missing `new_ae` (ignored); a previous thumbprint that is not the
active key and a new key equal to the operational key (`KEY_CONTINUITY`);
`REVOCATION` by the rotated key (applied) and by the superseded key (ignored);
interleaved `KEY_ROTATION`; a rotation before or without genesis; a rotation
after `RETIREMENT` (`TERMINAL_STATE`); rotations fully signed under a matching
non-empty `new_ek` kid but malformed (thumbprint mismatch, missing `alg`,
unchanged thumbprint), which are fatal `INVALID_EVIDENCE`; and a `new_ek`
with any private member (`d` or a stray one such as `p`), a `new_ek` with a
missing or empty `kid`, or a `new_ae` kid that differs from `new_ek`, which
cannot authenticate and are ignored. Spam-genesis cases put a
self-authenticated ISSUANCE with another entity key ahead of the real one, with
and without a later rotation, with its own authenticated contradicting
successors, and with a spam rotation to the record key whose `new_ae` is not
made by that key; none of them is selected. Further cases check
that the first eligible genesis decides: a fresh ISSUANCE under a superseded
entity key after the real history was rotated and revoked is not selected as a
fallback (rejected), with the record carrying either the superseded or the
original key. A malformed ISSUANCE is fatal rather than skipped when a chain
key authenticates it ahead of the real genesis (the record key, the root key, or
an intermediate rotated key), or when the current entity key or a MIGRATION
genesis signer that is still current authenticates it after the stream has
started; after the stream has started, one signed only by a superseded root or
intermediate key is ignored. A malformed ISSUANCE authenticated only by an unrelated key is not
asserted. A well-formed later ISSUANCE is a fatal
`DUPLICATE_ISSUANCE` when the current entity key signs it and is ignored when a
superseded chain key (the ISSUANCE key or an intermediate key) signs it. Cases marked `anchoredReader: true`
encode the optional anchored genesis selection. A reader that does not anchor
on the record `ek` may diverge on them only when the stream has competing
authenticated genesis candidates; its markers in
`harness/semantic_known_bugs.json` say so and persist while that remains its
design, unlike markers for missing support, which are removed once the SDK
passes.

Rotation key errors fall into two layers. In the C2SP binding, structural
checks on a fully signed rotation run first, and their failures (thumbprint
mismatch, unchanged thumbprint, missing `alg`) are `INVALID_EVIDENCE`. The
reducer vectors receive already parsed events, so the same defects reaching the
shared reducer are `KEY_CONTINUITY` "invalid key material". Further cases cover a `prev_ae`
whose kid does not name the active key, a rotation signed by a superseded key
(ignored), a superseded-key fork from before the rotation (`CHAIN_CONTINUITY`),
a `KEY_ROTATION` to the rotated entity key (`KEY_CONTINUITY`), a rotation to an
ES256 key, and `RETIREMENT` by the rotated key.

These vectors are committed before SDK support. Their signed evidence is
complete, but each adapter must still be extended to send `ENTITY_KEY_ROTATION`
fields, to use `recordEntityJwk` as the record key, and to report
`bilateralBinding`. Until then the failing cases carry per-SDK markers in
`harness/semantic_known_bugs.json` and report XFAIL; a marker is removed when its
SDK passes. The old misleading `issuance-resigned` case is now named
`issuance-signed-extension`: its signed `dnsid_test_variant` changes the payload,
so the fatal second-genesis expectation is unchanged. Separate ES256 cases use
actual high-S/low-S signature-only copies, including high-S first and replay
after revocation. Other cases cover invalid/missing countersignatures,
historical-predecessor forks, and rejection of prohibited index/leaf chains.

Three cases put a fractional, small-exponent, or large-exponent JCS number in
an unknown signed extension of a valid REVOCATION. Only `ts` and `seq` are
integer-restricted, so the revocation must apply. An inbound MIGRATION with an
invalid entity signature before a valid ISSUANCE must be ignored, not abort the
stream. A genesis whose distinct `ek` and `ku` share one non-thumbprint `kid`
is valid: method section 9 makes `kid` a label, and roles select keys.

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
public disposable fixture keys. The generator only accepts printable-ASCII
strings; numbers use RFC 8785 serialization. CI checks reproducibility before running SDKs.
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
printable-ASCII strings, safe integers, and finite JCS numbers. This is not a general
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

## C2SP checkpoint continuity and storage

The normative behavior is defined by the binding's
[store contract](../11-c2sp-tlog-binding.md#trusted-checkpoint-store-contract),
[durable-storage requirements](../11-c2sp-tlog-binding.md#durable-checkpoint-storage),
[re-baseline procedure](../11-c2sp-tlog-binding.md#authorized-checkpoint-re-baselining),
and [diagnostic rules](../11-c2sp-tlog-binding.md#checkpoint-failure-diagnostics).
SDK-native tests MUST cover applicable SDK behavior below, using valid signed
checkpoints and evidence for verification-boundary cases. Store-level tests may
use injected checkpoints and deterministic I/O/locking failures. For
deployment-owned recovery steps, document the required operational checks;
SDK tests do not establish operator authorization or audit-archive integrity.

| Scenario | Required result |
|---|---|
| Smaller policy-accepted candidate | `LOG_ROLLBACK`; trusted state unchanged. |
| Equal-size candidate with another root | `LOG_FORK`; trusted state unchanged. |
| Larger candidate with invalid supplied consistency proof | `LOG_INCONSISTENT`; no scan fallback or trust change. |
| Complete scan reproduces candidate root but not trusted prefix | `LOG_INCONSISTENT`; trusted state unchanged. |
| Scan lacks the required candidate prefix, has invalid indexes, or cannot reproduce candidate root | `INVALID_EVIDENCE`, not `LOG_INCONSISTENT`; no trust change. |
| No consistency source for an otherwise valid growing bundle | Distinct machine-readable missing-evidence condition; only permitted fallback may proceed, after verifying both roots. Required-bundle mode fails. |
| Proof/scan fetch fails or is canceled | Preserve cause and retry classification; do not classify as inconsistent evidence or reset trust. |
| Store load or pre-publication write fails | Non-transient `CHECKPOINT_STORE_ERROR`; no empty/in-memory substitution or trust change. |
| Continuity error crosses a public verification boundary | Category mapping, origin, both sizes/roots, and available cause remain inspectable without message matching; roots cannot mutate trust. |
| Two conflicting extensions race against the same old checkpoint | At most one succeeds; loser checks against the winner before accepting anything. A stale witnessed time also fails an exact-state comparison. |
| Cancellation while queued, waiting for a lock, or flushing staged data before publication | No later publication; lock waits respect the shared budget. |
| Paused live lock holder, or two simultaneous stale-lock reclaimers | No simultaneous owners and no deletion of a successor's lock. Unexpected lock inspection/removal errors fail closed. |
| Administrative replacement uses stale expected state | No replacement; no automatic reload/retry authorizing a different old state. |
| Authorized replacement succeeds | Exact reviewed state replaced, audit evidence retained, affected caches discarded, and fresh verification completed before workflows resume. |

A built-in durable adapter is optional. Tests for each provided durable adapter
MUST additionally cover restart persistence, competing threads/processes, crash
before commit, invalid persisted roots/sizes/timestamps, missing or corrupt
existing storage, explicit initialization, and read-back after authorized
replacement. A crash leaves an old or new complete record. A post-publication
sync failure reports failure with an indeterminate outcome requiring
reconciliation; it must not claim that the old state necessarily remains.

The [shared signed checkpoint vectors](../../../fixtures/c2sp-checkpoint-continuity.yaml)
exercise first contact, repeated checkpoints, valid proof/scan growth, rollback,
equal-size conflicts, invalid consistency proofs, contradictory trusted prefixes,
candidate-invalid scans, missing consistency evidence, injected fetch/store
failures, and invalid checkpoint signatures. They verify native error mappings,
diagnostics, retry classification, and actual stored state through real
verification entrypoints, rather than using supplied acceptance flags.

Those vectors use native memory stores and injected dependencies. They do not
establish durable-storage, concurrency, cancellation, lock-recovery,
administrative-recovery, network-fallback, or full identity-manager coverage.
The selection/event-identity fixtures do not establish those guarantees either.
Native test results and shared harness results MUST identify which cases
actually ran; known classification gaps do not count as compliant passes.

## Stable error categories

Bindings expose the checkpoint categories through idiomatic errors or typed
kinds with a documented mapping. The observation does not establish its cause,
and no category authorizes resetting trust. Continuity contradictions and
checkpoint-store failures are non-transient; retrieval failures retain their
underlying classification. Detailed precedence and fallback rules are owned by
[Checkpoint Failure Diagnostics](../11-c2sp-tlog-binding.md#checkpoint-failure-diagnostics).

| Category | Meaning |
|---|---|
| `GENESIS_REQUIRED` | A shared history begins with an event other than `ISSUANCE`. |
| `DUPLICATE_ISSUANCE` | A second `ISSUANCE` appears in one shared identity history. |
| `INVALID_ISSUANCE` | Issuance key material is missing, inconsistent with its thumbprints, or does not separate entity and operational roles. |
| `TERMINAL_STATE` | The shared reducer receives an event after `REVOCATION` or `RETIREMENT`. |
| `DOMAIN_MISMATCH` | An applied event names a different identity. |
| `KEY_CONTINUITY` | `KEY_ROTATION` does not continue from the active operational key, `ENTITY_KEY_ROTATION` does not continue from the active entity key, or either introduces invalid key material. |
| `INVALID_REVOCATION_REASON` | A revocation reason is missing or outside the base vocabulary. |
| `INVALID_MIGRATION` | Migration references are equal or verified history stitching is unavailable. |
| `SNAPSHOT_EMPTY` | No verified event exists at or before the requested time. |
| `SNAPSHOT_NON_PREFIX` | The requested timestamp would select a non-prefix subsequence. |
| `UNSUPPORTED_EVENT` | No supported base or companion profile defines reducer semantics for the event type. |
| `CHAIN_CONTINUITY` | An authenticated C2SP event does not continue the signed stream chain, or accepted completeness evidence contradicts the applied chain. |
| `INVALID_EVIDENCE` | A checkpoint, policy, witness quorum, trusted bundle, candidate scan prefix, or other completeness evidence fails, or a fully authenticated lifecycle event fails structural validation, except for the more specific continuity/storage conditions below. |
| `INCOMPLETE_STREAM` | The binding cannot establish complete logged-state history. |
| `LOG_ROLLBACK` | A policy-accepted candidate checkpoint has a smaller tree than trusted state; retain trust and investigate with operations and security. |
| `LOG_FORK` | A policy-accepted candidate has the trusted size but a different root; an equal-size conflict is an equivocation signal, not proof of malice. |
| `LOG_INCONSISTENT` | A larger policy-accepted candidate has an invalid supplied consistency proof, or a scan reproduces the candidate root but contradicts the trusted prefix root. |
| `CHECKPOINT_STORE_ERROR` | Trusted checkpoint storage is unavailable, malformed, lost, or refuses the operation; fail closed and never substitute empty trust. |
