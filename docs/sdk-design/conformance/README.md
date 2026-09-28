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

## C2SP trust profile epochs

[`c2sp-trust-profile-epochs-v1.json`](../../../fixtures/c2sp-trust-profile-epochs-v1.json)
(format `dnsid-c2sp-trust-profile-epochs@v1`) is the shared vector for
[trust profile version 2](../11-c2sp-tlog-binding.md#version-2-trust-epochs)
and for version 1 compatibility under it. It holds 79 cases: 37 profile, 20
checkpoint, 15 bundle, and 7 continuity. Its
[format document](../../../fixtures/c2sp-trust-profile-epochs.md) defines the
encodings, verifier configuration, and case types. Both files are byte-for-byte
copies of the dnsid-go originals at commit
`70da783a6c7504aa0c9968aca13de5dfef558ffc`
(`log/c2sptlog/testdata/`, from
[dnsid-go#40](https://github.com/dnsid-ai/dnsid-go/pull/40)).

| File | SHA-256 |
|---|---|
| `fixtures/c2sp-trust-profile-epochs-v1.json` | `9ee8e63a394aaa3abc55c6c0900783a444ac8ab259032a08db828ebf1abb5fdf` |
| `fixtures/c2sp-trust-profile-epochs.md` | `2acff5877872d395f9d49dbe6fb1805fdbcb1672b937f494cb9cb17a9d5dcd35` |

The dnsid-go generator `log/c2sptlog/trust_epoch_vectors_gen_test.go`
produces the vector deterministically from fixed, published Ed25519 test
seeds. The `generator` and `documentation` fields inside the file name those
dnsid-go paths. Every key in it is a disposable test key and none protects a
deployment. The vector carries signed checkpoints and bundles as text, and
profiles as raw JSON text so that lexical bound cases survive. Never parse and
re-serialize a profile before handing it to an SDK.

This harness does not execute the vector yet. Each SDK runs every case in its
own test suite against a byte-identical copy and pins it by SHA-256.
dnsid-go also fails its test if the checked-in file differs from a fresh
generation.

To change the vector:

1. Change the generator in dnsid-go and regenerate:
   `DNSID_UPDATE_TRUST_EPOCH_VECTORS=1 go test -run TestTrustEpochVectors ./log/c2sptlog`.
   Never hand-edit the JSON. If the change alters an expectation, first change
   the [normative rules](../11-c2sp-tlog-binding.md#version-2-trust-epochs)
   here. A new rule or reason code is a spec change, not a vector refresh.
2. Copy the regenerated JSON and its format document byte-for-byte into
   `fixtures/` here, update the commit and SHA-256 values above, and merge that
   change before any SDK adopts it.
3. In each SDK (dnsid-go `log/c2sptlog/testdata/`, dnsid-ts `test/fixtures/`,
   dnsid-py `tests/vectors/`), replace the copy and bump the pinned SHA-256
   and, when it changed, the expected case count.

A change that breaks the format of existing cases gets a new format label
(`@v2`) and file name rather than rewriting `@v1` in place.

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
