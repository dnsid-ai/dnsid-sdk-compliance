# SDK Implementation Coverage

This directory tracks the [SDK Design](../README.md) across Go, TypeScript, and
Python. Each tracker's `Analysis Details` table is the authoritative baseline.
Historical findings and review changes remain in Git.

## Latest Review — 2026-10-20

| SDK | Coverage File | Reviewed Branch | Reviewed Commit | Package Version | Open Findings |
| --- | --- | --- | --- | --- | --- |
| Go | [go.md](./go.md) | `main` | `8797e22` | `v0.42.0` | Profile configuration, publication snapshot validation, signer binding, rotation algorithm/recovery, onboarding, construction ordering, missing TTL, conformance metadata |
| TypeScript | [typescript.md](./typescript.md) | `main` | `41f0df0` | `0.30.0` | Profile ownership, built-in cross-provider retirement, empty rotation targets, managed log transport, conformance metadata |
| Python | [python.md](./python.md) | `main` | `26a5e80` | `0.29.0` | Profile ownership, JWT bearer naming, managed log transport, OIDC decoded allocation, conformance metadata, initial-issuance recovery evidence |

Design baseline: `8c3731d1ed068399dc2ab4190b2b88e4ce37aeda` (`main`).
Full reviewed/tested commits, release tags, native commands/results, and review
scope are recorded per SDK. Python `v0.29.0` and TypeScript `v0.30.0` contain
only release metadata changes after their tested commits; suites/package smoke
were not rerun and published artifacts were not inspected.

## Review Scope

All recorded full SDK/design baselines resolved and were ancestors of the
reviewed commits. All four worktrees were initially clean; no uncommitted
normative or fixture changes were included.

The design range
`8d04d58c7e8d920b1f62100ce4f7436324e06c40`..`8c3731d1ed068399dc2ab4190b2b88e4ce37aeda`
clarifies rotation algorithm selection/generated-key agreement and exact
saved-provider recovery (`19cee11`, `32f1fa3`). Root fixture changes
(`302c227`) correct rejection categories and invalid-checkpoint evidence.
No numbered identity-record profile changed. Harness/adapter refactoring and
fresh-source checks were also reviewed. Resolved [design questions](../08-open-questions.md)
are covered in the relevant subject rows, not a separate implementation status.

## Shared Compliance Harness

This run used the **tested SDK commits** in each tracker's metadata, before the
Python/TypeScript release-only commits. Existing environments/locks were not
refreshed. The Python editable install was rebound to the reviewed checkout
before the successful run; TypeScript packages and the Go shim were rebuilt.

All **358 expectations per SDK** matched: 347 passes and 11 fail-closed
retired-selector rejections, including 150 WBA and 15 signed-checkpoint cases.
No unexpected failures or known-bug allowances occurred. Typed Python JWKS
errors and optional no-directory-cache behavior use declared expectations.
All 60 harness unit tests, both fixture reproducibility checks, and 33 focused
event-identity checks passed. Three writers produced identical canonical
ISSUANCE/KEY_ROTATION entries; three verifiers accepted the signed golden stream
and each rejected all six mutations. The Python-to-TypeScript split-signing
handoff matched; the matrix no longer executes nine redundant paths.

Commands ran from the compliance root:

```sh
uv pip install -p .venv -e "$HOME/dnsid-py"
(cd shims/go && go build -o dnsid-shim .)
.venv/bin/python harness/generate_c2sp_fixtures.py --check
.venv/bin/python harness/generate_wba_fixtures.py --check
DNSID_GO_DIR="$HOME/dnsid-go" DNSID_TS_DIR="$HOME/dnsid-ts" DNSID_PY_DIR="$HOME/dnsid-py" .venv/bin/python -m unittest discover -s harness -p 'test_*.py'
.venv/bin/python harness/c2sp_event_identity_check.py
DNSID_GO_DIR="$HOME/dnsid-go" DNSID_TS_DIR="$HOME/dnsid-ts" DNSID_PY_DIR="$HOME/dnsid-py" .venv/bin/python harness/run.py --out /tmp/dnsid-review-2026-10-20/harness.md
DNSID_GO_DIR="$HOME/dnsid-go" DNSID_TS_DIR="$HOME/dnsid-ts" DNSID_PY_DIR="$HOME/dnsid-py" .venv/bin/python harness/c2sp_matrix.py
```

Logs/reports and focused probes are under `/tmp/dnsid-review-2026-10-20/`.
Passing suites do not close the findings. Checkpoint cases use memory stores,
not built-in durable adapters. WBA directories are fetched on every invocation;
optional directory caching is not claimed. No live registry/cloud authorization,
external WBA partner, durable checkpoint crash/multiprocess behavior,
deployment-owned recovery, throughput/load benchmark, or complete recursive
migration interoperability was tested.

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
