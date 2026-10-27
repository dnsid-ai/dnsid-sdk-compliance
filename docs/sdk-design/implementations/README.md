# SDK Implementation Coverage

This directory tracks the [SDK Design](../README.md) across Go, TypeScript, and
Python. Each tracker's `Analysis Details` table is the authoritative baseline.
Historical findings and review changes remain in Git.

## Latest Review — 2026-10-27

| SDK | Coverage File | Reviewed Branch | Reviewed Commit | Package Version | Open Findings |
| --- | --- | --- | --- | --- | --- |
| Go | [go.md](./go.md) | `main` | `ec12961` | `v0.45.0` | Profile configuration, publication snapshot validation, configured signer binding, cross-provider/algorithm rotation, shared-kid prepared signing, onboarding, construction ordering, missing TTL, conformance metadata |
| TypeScript | [typescript.md](./typescript.md) | `main` | `f5e0c8a` | `0.32.0` | Profile ownership, built-in cross-provider retirement, empty rotation targets, managed log transport, conformance metadata; moderate development-dependency audit findings |
| Python | [python.md](./python.md) | `main` (release tag) | `2f98756` | `0.31.0` | Profile ownership, JWT bearer naming, managed log transport, OIDC decoded allocation, conformance metadata, initial-issuance recovery evidence |

Design baseline: `ed80183256383ee299bf57f8ff098a15a955acde` (`main`, before
this tracker update). All three exact release commits were reviewed and tested.
Full commits, release tags, native commands/results, and evidence are recorded
per SDK. Published artifacts were not inspected; TypeScript's locally packed
packages passed smoke validation.

## Review Scope

The authoritative SDK/design baselines from each tracker resolved and were
ancestors of the reviewed releases/design head. Commit subjects, name/status
changes, aggregate diffs and affected callers were reviewed across each SDK's
entire repository. No uncommitted normative or fixture changes were included;
unaffected coverage was retained after impact review.

The design range
`8c3731d1ed068399dc2ab4190b2b88e4ce37aeda`..`ed80183256383ee299bf57f8ff098a15a955acde`
adds application `KeyNotFound`, fresh local-publication checks, terminal/offline
rotation resume, role-owned C2SP key selection, signature/host/empty-tag
clarifications, hash-tile checkpoint consistency, and prepared-event reference
derivation without a response header. Shared selection, canonicalization, FQDN,
parse and validation vectors changed too. No numbered identity-record selector
or generation profile changed.

SDK impact review covered those requirements plus Go cache fencing/history
preloading, Python per-event-loop HTTP pooling and owned-resource shutdown,
configuration-selected signer callers, dependency/runtime floors, release
metadata, exports, examples and generated API references. Go's same-provider
recovery validation/publication gaps are resolved; cross-provider and algorithm
selection gaps remain. A focused Go probe found shared-kid rejection in prepared
signing despite passing reader selection coverage.

Go and TypeScript used their clean release checkouts. Python's existing checkout
was left on its development branch; a detached `v0.31.0` worktree at
`/tmp/dnsid-review-2026-10-27/python` supplied native and shared validation.
The temporary Python worktree was removed after validation, and the shared
Python environment was rebound to the original checkout. TypeScript used
`npm ci`; Python native validation used the complete locked extras environment.
Go used toolchain `1.27.3`, TypeScript Node `22.23.4`.
The TypeScript dependency audit reported two moderate development-dependency
findings; see its tracker. No SDK code or dependency fixes were made.

## Shared Compliance Harness

All **377 expectations per SDK** matched: 366 passes and 11 fail-closed
retired-selector rejections, including 150 WBA, 27 C2SP selection and 15 signed
checkpoint cases. No unexpected failures or known-bug allowances occurred.
Typed Python JWKS errors and optional no-directory-cache behavior use declared
expectations.

All 60 harness unit tests, both fixture reproducibility checks, and 33 focused
event-identity checks passed. Three writers produced identical canonical
ISSUANCE/KEY_ROTATION entries; three verifiers accepted the signed golden stream
and each rejected all six mutations. The Python-to-TypeScript split-signing
handoff matched. Shared compliance and the interoperability matrix were rerun
successfully after TypeScript's clean dependency installation.
Hash-tile evidence selection, failure isolation, request bounds, authentication,
contention and cancellation are covered by native suites, not new shared wire
vectors.

Commands ran from the compliance root:

```sh
export DNSID_GO_DIR="$HOME/dnsid-go"
export DNSID_TS_DIR="$HOME/dnsid-ts"
export DNSID_PY_DIR=/tmp/dnsid-review-2026-10-27/python
uv pip install -p .venv -e "$DNSID_PY_DIR"
(cd shims/go && go build -o dnsid-shim .)
.venv/bin/python harness/generate_c2sp_fixtures.py --check
.venv/bin/python harness/generate_wba_fixtures.py --check
.venv/bin/python -m unittest discover -s harness -p 'test_*.py'
.venv/bin/python harness/c2sp_event_identity_check.py
.venv/bin/python harness/run.py --out /tmp/dnsid-review-2026-10-27/harness.md
.venv/bin/python harness/c2sp_matrix.py
```

Logs/reports and the shared-kid probe are under
`/tmp/dnsid-review-2026-10-27/`. Passing suites do not close the findings.
Checkpoint cases use memory stores, not built-in durable adapters. WBA
directories are fetched on every invocation; optional directory caching is not
claimed. No live registry/cloud authorization, external WBA partner, durable
checkpoint crash/multiprocess behavior, deployment-owned recovery, load
benchmark, or complete recursive migration interoperability was tested.
Prior-review focused probes are identified as historical in the trackers.

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
