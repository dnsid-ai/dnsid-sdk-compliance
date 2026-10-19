# SDK Implementation Coverage

This directory tracks coverage of the [SDK Design](../README.md) across the Go,
TypeScript, and Python SDKs. Each tracker's `Analysis Details` table is the
**authoritative review baseline**; use its full commits, not this summary.
Historical review scopes and resolved findings remain available in Git history.

## Latest Review — 2026-10-19

| SDK | Coverage File | Reviewed Branch | Reviewed Commit | Package Version | Open Findings |
| --- | --- | --- | --- | --- | --- |
| Go | [go.md](./go.md) | `main` | `1f6e49a` | `v0.41.0` | Partial missing-record taxonomy, profile configuration ownership/validation, publication snapshot validation, signer binding, cross-provider recovery, onboarding validation, construction ordering, unavailable TTL, and conformance metadata |
| TypeScript | [typescript.md](./typescript.md) | `main` | `1bf3901` | `0.28.0` | Partial missing-record taxonomy, profile configuration ownership, cross-provider recovery, onboarding validation, construction/provider validation ordering, and conformance metadata |
| Python | [python.md](./python.md) | `main` | `40181a3` | `0.27.0` | Partial missing-record taxonomy, profile configuration ownership, JWT bearer naming, signer binding, onboarding validation, provider validation ordering, managed log transport, missing DoH TTL, prepared-event metadata, OIDC response bounds, conformance metadata, and issuance-recovery evidence |

Design baseline: `main` at
`e2f43a053e4d8e1acf4079b16cf2da2897692fa0`. Full SDK commits and review scope
are recorded in each tracker. These versions identify source, not a claim about
published release contents.

The review compares each recorded SDK baseline with the heads above and design
`e2e76f9`..`e2f43a0`. All recorded baselines resolve and are ancestors of their
reviewed heads. Changes cover WBA verification and rotation refresh, shared HTTP
signature/content handling, profile configuration ownership, core identity
refresh/cache/freshness, missing-record errors, checkpoint continuity/storage,
and code-only checkpoint-store injection. Shared WBA and signed-checkpoint
fixtures were added; no numbered identity-record profile changed.

All three SDKs now implement DNSid WBA request and signed-directory verification,
targeting published `draft-ietf-webbotauth-httpsig-protocol-00`. They bind both
signatures to the current verified operational key, enforce configured entity
acceptance and current-peer policy, and support bounded key-mismatch refresh.
They fetch directories on every invocation; optional directory-cache reuse is
not claimed. This is the constrained DNSid profile, not a claim of general WBA
or external partner interoperability.

All three expose checkpoint continuity/storage diagnostics and atomic memory-store
verification/advancement. Durable stores remain code-injected; no built-in durable
adapter ships at these heads. Python removed its SQLite adapter. Recovery requires
explicit deployment authorization; verification never resets trust automatically.
The managed SDK catalogs now include the partner log alongside development and
production. These vendored trust choices are not protocol authority.

All three still lack the required distinct permanent missing-record code and
have profile configuration ownership gaps outside WBA. Python retains a JWT bearer
class named `WebBotAuthProfile`, contrary to the revised naming contract.
Existing registration/provider gaps remain: Go and Python do not bind
configuration-selected signers to verified publication; Go and TypeScript lack
complete cross-provider recovery; all three lack onboarding-binding validation.
See the trackers for evidence and the remaining findings.

Python's checked-in `uv.lock` labels the editable package `0.26.0`, while
`pyproject.toml` reports `0.27.0`; its dnspython minimum is now 2.8. Validation
used existing installed environments without refreshing locks.

## Native Validation

Commands were run in each SDK checkout at the heads above.

| SDK | Commands | Result |
| --- | --- | --- |
| Go | `go vet ./...`, `go test -count=1 ./...`, `go test -race ./...`, `(cd key/aws && go test ./...)`, `(cd examples/deployment-identity && go test ./...)`, `(cd examples/trust-policy && go test ./...)` | All passed on the first run; the prior OIDC boundary-test flake did not recur, but is not proven fixed |
| TypeScript | `npm run typecheck`, `npm run build`, `npm test -- --run`, `npm run smoke:pack` | All passed; 1218 tests passed, 1 skipped |
| Python | `.venv/bin/pytest -q`, `.venv/bin/ruff check dnsid tests`, `.venv/bin/mypy dnsid` | 1847 tests passed with 8 local-key warnings; lint/types clean, 47 source files checked |

## Shared Compliance Harness

The 2026-10-19 run matched all 358 expectations per SDK: 347 passes and 11
fail-closed rejections of retired selectors, including 150 WBA and 15 signed
checkpoint cases. There were no unexpected failures, known-bug allowances, or
missing WBA capabilities. The rebuilt Go shim, rebuilt TypeScript packages and
installed local Python package were used.

The C2SP matrix passed: all three writers produced identical canonical
ISSUANCE → KEY_ROTATION entries; all nine writer/verifier paths succeeded;
the Python-to-TypeScript split-signing handoff matched; every verifier rejected
all six mutated bundles. All 40 harness tests passed without skips, including
the native Go revocation/cache regression.

Commands ran from the compliance repository root:

```sh
(cd shims/go && go build -o dnsid-shim .)
.venv/bin/python harness/run.py --out /tmp/dnsid-review-2026-10-19/harness.md
DNSID_GO_DIR="$HOME/dnsid-go" DNSID_TS_DIR="$HOME/dnsid-ts" DNSID_PY_DIR="$HOME/dnsid-py" .venv/bin/python harness/c2sp_matrix.py
DNSID_GO_DIR="$HOME/dnsid-go" DNSID_TS_DIR="$HOME/dnsid-ts" DNSID_PY_DIR="$HOME/dnsid-py" .venv/bin/python -m unittest discover -s harness -p 'test_*.py'
```

Passing fixtures do not close the documented gaps. The signed-checkpoint cases
use memory stores; they do not establish durable-storage, crash, multiprocess
locking, or administrative-recovery guarantees. WBA directory-cache reuse was
not established. No live registry integration, cloud authorization, persistent
server replay/organization isolation, external WBA partner interoperability,
deployment-owned recovery, or complete recursive-migration interoperability was
tested. Registration/provider and recovery checks use local/mocked dependencies.

## Agent Update Instructions

Follow [AGENTS.md](../AGENTS.md#updating-sdk-implementation-coverage) for the review
procedure, including baseline checks, delta enumeration, impact mapping, evidence
refresh, validation, and full-review triggers.

- Read the target tracker first; record exact reviewed heads and actual commands.
- Use the statuses below and concrete implementation paths/line numbers. Verify
  behavior, validation, errors, and defaults, not exported names alone.
- Keep current findings distinct from evidence; preserve unaffected coverage only
  after checking both SDK and design deltas.
- Update only the requested trackers. Update this summary when requested or when
  the review scope includes shared run metadata; keep it consistent with them.

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
