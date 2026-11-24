# SDK Implementation Coverage

This directory tracks the [SDK Design](../README.md) across Go, TypeScript, and
Python. Each tracker's `Analysis Details` table is the authoritative baseline.
Historical findings and review changes remain in Git.

## Latest Review — 2026-11-24

| SDK | Coverage File | Reviewed Branch | Reviewed Commit | Package Version | Open Findings |
| --- | --- | --- | --- | --- | --- |
| Go | [go.md](./go.md) | `main` | `4c08b87` | `v0.48.0` | Active-only key inventory, response no-content verification, registry transport, profile ownership, publication snapshots, cross-provider/algorithm rotation, shared-kid preparation, construction ordering, unavailable TTL, KMS recovery coverage, Foundry acceptance, conformance metadata |
| TypeScript | [typescript.md](./typescript.md) | `main` | `2606e02` | `0.37.0` | Active-only key inventory, registry defaults, obsolete loader fields, profile ownership, cross-provider/empty-target rotation, Google saved-state recovery, Foundry successor reconciliation/acceptance, conformance metadata; prior dependency audit findings not rechecked |
| Python | [python.md](./python.md) | `main` | `2248785` | `0.36.0` | Active-only key inventory, response header bounds/no-content signing, profile ownership, JWT bearer naming, OIDC decoded allocation, Google saved-state recovery, Foundry successor reconciliation/acceptance, conformance metadata |

Design baseline: `a9940979e6df63315b6eb49b2b487b485d0133cd` (`main`, before
this tracker update). All three SDKs are main checkouts after their release tags.
Full commits and actual validation commands are recorded per SDK. Published
artifacts and packed consumers were not checked in this review.

## Review Scope

This incremental review starts at each tracker's recorded SDK commit and design
commit `8a5139751b08371cd608ea7ab263540a0ed86394`. All baseline commits resolve
and are ancestors of the reviewed heads. Review covered all SDK commit subjects,
name/status changes and aggregate diffs, plus normative design, conformance and
root-fixture changes. Affected callers were reviewed; unaffected coverage retains
baseline evidence. Citations in changed files were refreshed. Reviewed SDK,
normative-design and fixture checkouts were clean.

The design delta replaces WBA draft 00 with draft 01: parameterless direct
directory URLs, no emitted JWK `alg`, and optional received JOSE `Ed25519`.
All three SDKs now implement the updated WBA behavior. Conformance vectors
changed; root fixtures did not. No DNSid identity-record profile or wire selector
changed. WBA draft 01 is not wire-compatible with draft 00; deployed peers need
a coordinated upgrade.

SDK changes add staging/Known managed trust, overflow bundle keys, registry
`policy_violation`, regional KMS evidence and NAT64 destination guards.
TypeScript/Python validate returned AWS key references. Go also fixes canonical
host boundaries and separates identity-name and general DNS limits across
record, publication, acceptance, issuance and Foundry callers.
Unrelated findings remain open despite passing suites.

Native validation passed for all three SDKs, including Go vet, race, optional
AWS/GCP and tagged Foundry suites; TypeScript typecheck/build and 1,979 tests
(1 skipped); and Python's 3,271 tests, lint and type checks.
Existing dependency environments were used. No fresh installation, dependency
audit, packed-artifact validation, SDK code change or dependency fix was made.
The previous TypeScript audit reported three moderate development-dependency
findings; current vulnerability status is not established.

Foundry availability is separate from source coverage: Go requires the
`dnsid_foundry` build tag, TypeScript's package is private, and Python excludes
the module from wheel/sdist. Native fake-registry tests do not establish a
supported released server or hosted acceptance.

## Shared Compliance Harness

All **1,791 expectations per SDK** matched: 1,780 passes and 11 fail-closed
retired-selector rejections, with zero FAIL, XFAIL or MISSING results.
This includes all 153 updated WBA cases, all eight shared migration-chain cases
and the negotiated-response preparation, signature-base and server-signing
vectors. Typed Python JWKS errors and optional no-directory-cache behavior use
declared expectations.

All 63 harness unit tests, both fixture reproducibility checks and 33 focused
event-identity checks passed. Three writers matched both canonical golden
ISSUANCE/KEY_ROTATION entries; three verifiers accepted the golden stream and
each rejected all six mutations. The Python-to-TypeScript split-signing handoff
matched. Shared vectors do not establish every native response-verifier,
provider or Foundry boundary.

Commands ran from the compliance root:

```sh
export DNSID_GO_DIR="$HOME/dnsid-go"
export DNSID_TS_DIR="$HOME/dnsid-ts"
export DNSID_PY_DIR="$HOME/dnsid-py"
(cd shims/go && go build -o dnsid-shim .)
.venv/bin/python harness/generate_c2sp_fixtures.py --check
.venv/bin/python harness/generate_wba_fixtures.py --check
.venv/bin/python -m unittest discover -s harness -p 'test_*.py'
.venv/bin/python harness/c2sp_event_identity_check.py
.venv/bin/python harness/run.py --out /tmp/dnsid-review-2026-11-24/harness.md
.venv/bin/python harness/c2sp_matrix.py
```

The shared Python import resolved to `~/dnsid-py` without rebinding the
environment. The first unit/matrix invocation omitted SDK environment variables:
four unit cases skipped and the matrix stopped. Both were rerun with the
variables; all 63 unit tests and the matrix passed. Logs/reports are under
`/tmp/dnsid-review-2026-11-24/`. Earlier focused probes cited in trackers are
historical unless listed in the current validation commands.

Passing suites do not close the findings. No live cloud/IAM or hosted server,
shared Foundry daily scenario matrix, external CLI, cross-binding recovery
document transfer, destructive storage crash, external WBA partner or load
benchmark was validated. Checkpoint durability remains caller-owned; optional
WBA directory caching is not claimed.

## Agent Update Instructions

Follow [AGENTS.md](../AGENTS.md#updating-sdk-implementation-coverage) for the review
procedure, including baseline checks, delta enumeration, impact mapping, evidence
refresh, validation, and full-review triggers.

- Read the target tracker first; record exact reviewed heads and actual commands.
- Use the statuses below and concrete implementation paths/line numbers. Verify
  behavior, validation, errors, and defaults, not exported names alone.
- Keep current findings distinct from evidence; preserve unaffected coverage only
  after checking both SDK and design deltas.
- Update only the requested trackers. Keep shared run details here and native
  commands/results in each SDK's metadata; update this summary when in scope.
- Keep rows organized by subject, with short requirement names and design links.
  Merge duplicate requirements; put release/test distinctions in metadata, not
  dated appendices. Optional API limitations are not missing design requirements.

## Status Legend

| Status | Meaning |
| --- | --- |
| TBD | Not reviewed yet |
| Implemented | Reviewed and matches the design item |
| Partial | Reviewed and present, but incomplete or divergent |
| Missing | Reviewed and no implementation found |
| Not applicable | Reviewed and intentionally does not apply |

## Coverage Scope

The per-SDK files cover the full SDK design set:

| Design Area | Source |
| --- | --- |
| Document set and shared contracts | [README.md](../README.md) |
| Core Identity Manager | [01-core-identity-manager.md](../01-core-identity-manager.md) |
| RFC 9421 HTTP Message Signatures | [02-rfc9421-http-message-signatures.md](../02-rfc9421-http-message-signatures.md) |
| JOSE JWT and JWS | [03-jose-jwt-jws.md](../03-jose-jwt-jws.md) |
| Transport and Registry | [05-transport-and-registry.md](../05-transport-and-registry.md) |
| Log Bindings | [06-log-bindings.md](../06-log-bindings.md) |
| Protocol Data Types | [07-protocol-data-types.md](../07-protocol-data-types.md) |
| Open Questions | [08-open-questions.md](../08-open-questions.md) |
| OIDC Federation | [09-oidc-federation.md](../09-oidc-federation.md) |
| Web Bot Auth | [10-web-bot-auth.md](../10-web-bot-auth.md) |
| C2SP Transparency Log Binding | [11-c2sp-tlog-binding.md](../11-c2sp-tlog-binding.md) |
| Configuration Loading | [12-configuration-loading.md](../12-configuration-loading.md) |
| Known Foundry Create (product profile) | [13-known-foundry.md](../13-known-foundry.md) |
