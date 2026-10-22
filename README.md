# DNSid Cross-SDK Compliance Test Kit

Runs one shared set of IETF-draft-derived test vectors against all three DNSid
SDKs (dnsid-go, dnsid-ts, dnsid-py) and emits a side-by-side compliance matrix.
Where the SDKs disagree, the kit says so — with the spec clause each case is
derived from.


## Quick start

The kit runs against SDK checkouts on your disk, not published packages, so clone the
SDKs first:

```bash
git clone https://github.com/dnsid-ai/dnsid-go ~/dnsid-go
git clone https://github.com/dnsid-ai/dnsid-ts ~/dnsid-ts
git clone https://github.com/dnsid-ai/dnsid-py ~/dnsid-py
```

```bash
make run                       # builds shims + venv, runs everything, writes report.md
make run DNSID_TS_DIR=/elsewhere/dnsid-ts   # override an SDK checkout
.venv/bin/python harness/run.py --filter canonical --sdks go,ts   # subset
```

Requirements: Go 1.26+, Node 22+, Python 3.11+, [uv](https://docs.astral.sh/uv/).
SDK checkouts default to `~/dnsid-go`, `~/dnsid-ts`, `~/dnsid-py`
(`DNSID_GO_DIR` / `DNSID_TS_DIR` / `DNSID_PY_DIR` to override).

Exit code is nonzero only on **unexpected** failures — documented known bugs
(XFAIL) do not break the build.

## Entity naming

The shared [entity-naming rule](policy/ENTITY_NAMING.md) defines first-party legal
attribution and permitted brand usage. Run `make entity-naming` to check this
repository, the three SDKs, and cookbook without installing SDK dependencies.
Override `DNSID_COOKBOOK_DIR` as needed, like the SDK directory variables above.
CI checks all five main branches and gates SDK PR heads strictly on this rule.

## Layout

```
dnsid-sdk-compliance/
├── fixtures/          # YAML test vectors, one file per suite
├── harness/           # loads YAML plus the shared lifecycle JSON vectors
├── shims/
│   ├── go/            # CLI shim around dnsid-go (built by make; uses go.work
│   │                  #   to test the local checkout, not the published module)
│   └── ts/shim.mjs    # Node shim that imports the built dnsid-ts dist
└── docs/
    ├── sdk-design/    # SDK design docs, incl. conformance/ JSON vectors
    └── security/      # SDK threat model + data/network inventory
```

`harness/py_adapter.py` imports dnsid-py in-process (installed editable into `.venv`).
Setup rebuilds Go and reinstalls the selected Python checkout on every run.
The Python adapter rejects imports from a different checkout.
The harness also directly loads, without copying or translating them into
another checked-in fixture format:

- `docs/sdk-design/conformance/http-message-signatures.json`
- `docs/sdk-design/conformance/web-bot-auth.json`
- `docs/sdk-design/conformance/lifecycle-transitions.json`
- `docs/sdk-design/conformance/c2sp-lifecycle-selection.json`
- `docs/sdk-design/conformance/c2sp-managed-trust-selection.json`

Its adapters construct the SDK-native lifecycle events and C2SP evidence needed
to execute those shared semantic expectations.

## How it works

The harness sends every case to each SDK in **one batch** as a JSON array on
stdin; shims reply with a JSON array of normalized results:

```jsonc
// request                                   // response
{"op": "parse",           "raw": "..."}      {"ok": true, "record": {...}}
{"op": "canonical",       "raw": "..."}      {"ok": true, "value": "..."}
{"op": "roundtrip",       "raw": "..."}      {"ok": true, "record": {...}, "value": "..."}
{"op": "validate",        "raw": "...",
                          "identity_fqdn": "..."}  {"ok": true, "record": {...}}
{"op": "normalize_fqdn",  "name": "..."}     {"ok": true, "value": "..."}
{"op": "jwk_thumbprint",   "jwk": {...}}       {"ok": true, "value": "..."}
{"op": "jwk_signature_alg","jwk": {...}}       {"ok": true, "value": "EdDSA"}
{"op": "jwks_validate",    "jwks": {"keys": [...]}}  {"ok": true}
{"op": "jwks_signing_keys","jwks": {"keys": [...]}}  {"ok": true, "value": ["kid-1"]}
{"op": "jwks_key_by_id",   "jwks": {"keys": [...]},
                             "kid": "kid-1"}     {"ok": true, "value": "kid-1"}
{"op": "http_signature_base", "request": {...},
 "signature_input": "sig1=(...)", "label": "sig1"}
                                                {"ok": true, "value": "signature base"}
{"op": "sdk_conformance"}                      {"ok": true, "publishProfile": "dnsid-draft-01", ...}
{"op": "create_txt_record", "config": {...}, "entityKey": {...}, "operationalKey": {...}}
                                                {"ok": true, "record": {...}, "signatureVerified": true}
{"op": "c2sp_checkpoint_vector", "checkpointCase": {...}}
                                                {"ok": false, "error": "CheckpointError", "errorCategory": "LOG_ROLLBACK", "stored": {...}, ...}
// any error:                                {"ok": false, "error": "ParseError", "message": "..."}
```

Normalized record shape: wire tag names (`v gi oi ek ku lr su sg fl ka cu`),
absent/empty optionals as `null`, extension tags under `unknown`. `error` is the
normalized error-class label (`ParseError`, `ValidationError`, ...), which is
what cases assert on. Checkpoint cases use `CheckpointError` for recognized
native verification or injected dependency failures; unexpected exceptions stay
`AdapterError`. Messages are only matched via the optional, substring-based
`error_contains`.

## Web Bot Auth adapters

WBA verification runs the native SDK verifier, not an independent verdict engine.
The shared cases inject clocks, identity evidence, DNS answers, replay stores,
and real operation sequences. Discovery uses local TLS with a test trust root;
public-address filtering and certificate verification still run in the SDK.

- Python and TypeScript inject identity results at the public resolver boundary.
  These cases test profile handling of acceptance and key evidence, not the core
  identity manager's complete DNSid evidence chain.
- Go uses a batched `go test -overlay` bridge in
  `shims/go/testdata/wba_adapter_test.go`, reusing the SDK's native WBA fixture
  helpers and core identity manager. The CLI's `NativeAdapterRequired` marker is
  internal; `harness/run.py` replaces it with bridge results. The bridge requires
  the corresponding native fixture helpers in the SDK checkout. Compile or
  setup failures remain `AdapterError`, never successful negative tests. No SDK
  source files are changed.
- TypeScript verification cases run in separate processes because clock/dial
  overrides are process-wide and stream rejection can crash the runtime. The
  real raw response stream reaches the verifier without adapter buffering.
  A child crash remains a per-case `AdapterError`, not a successful rejection;
  other cases and SDKs still produce a report.

`CAPABILITIES` in `harness/run.py` records optional directory-cache support. All
current adapters use uncached discovery; `uncachedExpect` requires observed
rediscovery instead of claiming cache-hit coverage. Do not enable caching there
without a native cache adapter that preserves original age metadata.

The deterministic TLS certificate and private key in `shims/testdata/` are
public, disposable test credentials. They are not deployment credentials.

## Fixture schema

```yaml
suite: parse-valid
cases:
  - id: parse-valid-minimal          # unique, kebab-case
    description: ...
    spec_ref: "draft-ihsanullah-dnsid-01 §Record Format"
    tags: [required, happy-path]     # required|edge-case|security|deviation|version-specific|forward-compat|idn|happy-path
    version: dnsid-draft-01          # optional: the draft profile this record targets
    op: parse                        # record, FQDN, JWK, or JWKS operation listed above
    input:
      raw: "v=dnsid-draft-01;..."    # for record ops
      identity_fqdn: agent.test          # for validate
      name: example.test             # for normalize_fqdn
      jwk: {kty: OKP, crv: Ed25519, x: ..., kid: key-1}  # for JWK ops
      jwks: {keys: [...]}             # for JWKS ops
      kid: key-1                      # for jwks_key_by_id
    expect:
      ok: true
      record: {gi: example.test, unknown: {}}   # subset match — only listed keys compared
      value: "..."                   # exact match (canonical/serialized/normalized output)
      # or, for rejections:
      # ok: false
      # error: ParseError            # error class
      # error_contains: duplicate    # case-insensitive substring of the message
    sdk:                             # optional per-SDK adjustments
      go:
        note: "why go legitimately differs"
        expect: {error: ValidationError}   # deep-merged over the base expect
      ts:
        known_bug: "spec-correct behavior the SDK doesn't meet yet"
```

Two distinct per-SDK mechanisms, deliberately separate:

- **`expect` override + `note`** — a *documented, accepted divergence* (e.g.
  error-class taxonomy differences). The case passes and the note is listed in
  the report's divergence appendix.
- **`known_bug`** — the base expectation stays **spec-correct**; the SDK is
  known to fail it. Reported as XFAIL, doesn't fail CI. If the SDK starts
  passing, the report flags the marker for removal (XPASS).

## Version capability gating

The SDK-supported `v=` strings are declared in `CAPABILITIES` in
`harness/run.py`. The authority for what each selector means is
[draft-ihsanullah-dnsid](https://datatracker.ietf.org/doc/draft-ihsanullah-dnsid/)
and the per-draft profile sections in
[`docs/sdk-design/07-protocol-data-types.md`](docs/sdk-design/07-protocol-data-types.md):

| SDK | Supported versions |
|-----|--------------------|
| go  | dnsid-draft-01, DNSid1 (moving verification selector) |
| ts  | dnsid-draft-01, DNSid1 (moving verification selector) |
| py  | dnsid-draft-01, DNSid1 (moving verification selector) |

When a case's `version` is outside an SDK's set, the case is **not skipped**:
the harness asserts the SDK rejects the record as an unsupported version
(fail-closed). These show as `REJ` in the matrix. Core cases use the immutable
submitted selector `v=dnsid-draft-01`, including its required `ek` tag and bare
unpadded-base64url `sg`. Dated and legacy selectors remain as explicit
fail-closed version-dispatch cases.

## Adding cases

1. Pick the suite file (or add one — any `fixtures/*.yaml` with `suite:` and
   `cases:` is auto-discovered).
2. Derive the expectation from the spec —
   [draft-ihsanullah-dnsid](https://datatracker.ietf.org/doc/draft-ihsanullah-dnsid/),
   the referenced RFCs, and the profile sections under
   [`docs/sdk-design/`](docs/sdk-design/) — not from what an SDK happens to do.
   Cite the clause in `spec_ref`.
3. Run `make run`. If an SDK disagrees with the spec, decide: accepted
   divergence (`expect` override + `note`) or bug (`known_bug`) — never silently
   change the base expectation to match a single implementation.

## PR check for SDK repos

Each SDK repo gates its own PRs on this suite via the reusable workflow
`.github/workflows/sdk-compliance.yaml` in this repo. The caller stub in
`dnsid-<sdk>/.github/workflows/compliance.yaml`:

```yaml
name: Compliance
on: pull_request
jobs:
  compliance:
    uses: dnsid-ai/dnsid-sdk-compliance/.github/workflows/sdk-compliance.yaml@main
    with:
      sdk: py                 # go | ts | py
      ref: ${{ github.event.pull_request.head.sha }}
      base-ref: ${{ github.event.pull_request.base.sha }}
```


It runs the suite against the PR head and the base branch and reports
`N/total compliant (%)` in the job summary. The check goes **red only if the PR
introduces a newly failing case** — even if another failure is fixed — so an SDK with pre-existing failures
(the fixtures encode the spec, not what the SDK does today) can keep merging
while it digs out, without a new break slipping through. Omit `base-ref` to gate
on zero failures instead.

## Continuous cross-SDK validation

The [`Cross-SDK Compliance`](.github/workflows/cross-sdk-compliance.yml) workflow
runs the complete harness and deterministic C2SP matrix against all three SDK
main branches on every pull request, after changes land on `main`, on manual
dispatch, and daily. This repository owns that workflow because it owns the
canonical fixtures and harness being validated.

## What a compliant result means

A `PASS`/`REJ` cell asserts that the SDK checkout produced the behavior required
by the cited clause for that case, on the protocol and WBA signing surfaces
listed under Scope below. It does **not** assert that the SDK is secure, that
`VerifyDomain` end-to-end is correct, or anything about live network, TLS, caching,
or key handling. Those remain covered by each SDK's own tests. A shim crash or
missing result aborts the run; it is never reported as passed.

Verifier cases without an integrated SDK verifier are reported as `MISSING`,
never as successful rejection. They remain in the denominator, do not count as
compliant, and do not fail the regression gate. A green check does not mean that
required WBA verification exists. Where SDKs disagree, the matrix shows each
result and the divergence appendix explains why.

The per-SDK PR gate is **regression-only**: it goes red when a previously passing case fails,
not when unchanged failures exist. A green check therefore means "no new failing cases", not
"conformant". Any conformance claim about a release must cite the full report
(`make run` → `report.md`) for that exact commit, not the CI status.

## Scope

The main harness covers the pure-data protocol surface: SDK conformance metadata,
TXT record generation and entity-key signing, TXT record grammar, version dispatch,
canonical (signing) form, serialization round-trip, semantic validation, FQDN
normalization, RFC 7638 JWK thumbprints, effective JWK signature algorithms,
generic JWKS validation and selection helpers, RFC 9421 signature-base
construction, protocol `AgentStatus` validation and ACTIVE acceptance,
lifecycle state reduction, C2SP lifecycle candidate selection, managed
trust-catalog selection, and stateful checkpoint continuity with injected
storage and consistency-source failures.

The WBA suite additionally calls each SDK's real request signer and directory
server. An independent, constrained fixture checker verifies emitted signatures,
covered components, public directory keys, body digests, freshness parameters,
discovery serialization, and preservation of existing `Authorization`.
It does not replace an SDK verifier. Shared signed positive/negative verifier
vectors are present, but signing-only bindings report those cases as `MISSING`.
When an SDK exposes the verifier entry point, the current shim fails with
`AdapterError` until its native verification adapter is integrated; it must not
silently keep claiming missing support.

Run the focused suite and fixture checks:

```sh
.venv/bin/python harness/generate_wba_fixtures.py --check
.venv/bin/python -m unittest discover -s harness -p 'test_*.py'
.venv/bin/python harness/run.py --filter wba --out report-wba.md
```

See the [WBA vector contract](docs/sdk-design/conformance/README.md#web-bot-auth)
and [recorded baseline checks](docs/wba-conformance-checks.md).
Live network fetching, TLS, cache behavior, nonce-store concurrency, and the
complete `VerifyDomain` orchestration remain out of scope until native verifier
adapters run those scenarios. Live partner interoperability is not tested.

**C2SP contract correction:** the design now requires signature-independent
event IDs and predecessor chaining under the existing `c2sp-tlog` name. The
original signed fixtures are historical baselines. The active selection suite
and writer/verifier matrix now use newly signed `*-logical-v1.json` artifacts
for method revision `d5a65d06f76eff4db81e50f8767a600d2ca7fc2a`, while preserving
all original signed bytes. Do not rewrite old log data or add old-format fallback.
The separate focused check is:

```sh
.venv/bin/python harness/c2sp_event_identity_check.py
```

It exercises real ES256 signatures and logical-chain invariants, not full
SDK, proof, bundle, or migration integration.

`fixtures/c2sp-lifecycle-selection-logical-v1.json` freezes the corrected signed
entries, checkpoints, and proofs used by candidate-selection cases. The old
`c2sp-lifecycle-selection-evidence.json` and its semantic snapshot under
`fixtures/historical/` remain unchanged. The common
harness only loads those bytes; it does not import one SDK to manufacture input
for the others. The fixture records the SHA-256 digest of its authoritative
semantic source, so changing those semantics without refreshing the evidence
fails before any SDK runs. Regeneration follows the current candidate order and
scenario flags; unsupported candidates or mismatched wire definitions fail rather
than certifying old evidence with a new source hash. Every SDK verifies the
checkpoint policy and inclusion proofs rather than trusting a harness-supplied
validity flag. The invalid-checkpoint case contains a corrupted log signature;
Python and TypeScript send incomplete evidence through their native readers.

`fixtures/c2sp-checkpoint-continuity.yaml` adds 15 signed, stateful sequences:
first contact, repeated checkpoints, valid growth by proof/scan, rollback,
equal-size conflict, invalid proof, contradictory trusted prefix, incomplete or
candidate-invalid scans, missing consistency evidence, dependency failures, and
invalid checkpoint signatures. The generator below uses no SDK to create these
inputs. Each adapter first authenticates any seed through its native public
reader, then verifies the candidate using the same native memory store.

Go uses the public reader with optional proof/full-log sources. Python and
TypeScript use their public readers for scans and portable-bundle verifiers for
proof/missing-evidence cases. These are verifier-boundary tests, not full
`IdentityManager`/`VerifyDomain` or network fallback orchestration tests.

Results report the actual store tuple (`origin`, `treeSize`, base64url `rootHash`,
and Unix-second `witnessTime`), native retry classification, typed diagnostics,
observed proof requests, and injected-cause identity. Adapters map native error
types/kinds, not message text. They do not receive expected verdicts. Mutable
native diagnostic roots are also changed before reading stored state back.
Known taxonomy gaps can be XFAIL, but acceptance, stored-state, dependency-cause,
required proof-source invocation, and adapter failures always fail the run,
even with a marker.
SDK-native durable storage, concurrency, cancellation, lock recovery, and
administrative recovery tests remain separate requirements.

```sh
.venv/bin/python harness/run.py --filter checkpoint- --out report-checkpoints.md
```

See [recorded checkpoint checks](docs/checkpoint-conformance-checks.md) for the
tested SDK revisions and known gaps.

`fixtures/c2sp-stream-bundle-logical-v1.json` is the corrected deterministic
portable bundle used by the writer/verifier matrix. Its historical predecessor
`c2sp-stream-bundle-v1.json` remains untouched. Generate and verify reproducibility
without importing an SDK (requires `cryptography >= 43`):

```sh
.venv/bin/python harness/generate_c2sp_fixtures.py
.venv/bin/python harness/generate_c2sp_fixtures.py --check
```

All embedded keys are public disposable test keys, never deployment trust roots.
The normal selection suite does not replace the portable bundle matrix.

Run the deterministic writer/verifier matrix with integrated SDK checkouts:

```sh
make c2sp-matrix \
  DNSID_GO_DIR=/path/to/dnsid-go \
  DNSID_TS_DIR=/path/to/dnsid-ts \
  DNSID_PY_DIR=/path/to/dnsid-py
```

`fixtures/c2sp-generation-logical-v1.json` contains only language-neutral semantic
inputs: fixed Ed25519 seeds, identity fields, timestamps, and event order.
Each SDK independently prepares and signs the complete checked-in ISSUANCE to
KEY_ROTATION stream through its production writer API. The harness requires all
three streams to match the golden entries byte-for-byte, then runs the signed
golden bundle once through each production verifier. It also exercises a
Python-to-TypeScript split ISSUANCE handoff and
requires every verifier to reject each checked-in negative mutation for the
declared reason.

SDK PR workflows and manual smoke tests use the shared default-branch harness
and fixtures. Merge coordinated compliance changes before SDK updates; there
is no per-SDK fixture-ref override. Manual smoke tests require zero failures.
The metadata fixture includes the `dnsid-method` pin; SDKs missing that pin must
update their metadata, not weaken the shared expectation.
