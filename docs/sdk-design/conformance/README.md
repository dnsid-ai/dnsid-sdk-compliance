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
the exact catalog-dispatch boundary of the named Identity Digital-managed trust
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
