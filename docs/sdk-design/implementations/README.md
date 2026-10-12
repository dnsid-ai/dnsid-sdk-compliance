# SDK Implementation Coverage

This directory tracks coverage of the [SDK Design](../README.md) across the Go,
TypeScript, and Python SDKs. Each tracker's `Analysis Details` table is the
**authoritative review baseline**; use its full commits, not this summary.
Historical review scopes and resolved findings remain available in Git history.

## Latest Review — 2026-10-12

| SDK | Coverage File | Reviewed Branch | Reviewed Commit | Package Version | Open Findings |
| --- | --- | --- | --- | --- | --- |
| Go | [go.md](./go.md) | `main` | `3369ad9` | `v0.39.0` | Partial publication snapshot validation, signer binding, cross-provider recovery, onboarding validation, construction ordering, unavailable TTL, and conformance metadata; intermittent OIDC test failure |
| TypeScript | [typescript.md](./typescript.md) | `main` | `18c797b` | `0.26.0` | Partial cross-provider recovery, onboarding validation, construction/provider validation ordering, and conformance metadata |
| Python | [python.md](./python.md) | `main` | `d82ad82` | `0.25.0` | Partial signer binding, onboarding validation, provider validation ordering, managed log transport, missing DoH TTL, prepared-event metadata, OIDC response bounds, conformance metadata, and issuance-recovery evidence |

Design baseline: `main` at
`e2e76f963e260b899c02d0d4b8d995f24182d0fd`. Full SDK commits and review scope
are recorded in each tracker. These versions identify source, not a claim about
published release contents.

Design changes since `4de3e45` revise unified registration, authoritative
publication snapshots, authenticated account discovery, deployment key sources,
and cross-provider rotation/restart recovery. No identity-record profiles or
fixtures changed. All SDKs implement unified registration and retain creation
facts after follow-up failures. Go now implements deployment-file loading.
All three preserve parsed empty optional TXT tags in signed canonical content.
Go's setup snapshot validation still accepts profile-invalid ku/ek host bindings;
published-record verification remains separate and fail-closed.

TypeScript binds configuration-selected keys to verified publication; Go and
Python leave that check to callers. Python adds explicit cross-provider rotation,
verified-publication gating and crash-safe signer restoration; Go and TypeScript
still have single-provider recovery. All three expose onboarding reads but do
not validate/compare the new account/GI/proof bindings. Other open gaps remain
in the per-SDK findings.

Python's prior branch baseline is not an ancestor of `main`; its recovered
squash commit `531b547` is an ancestor with the exact same tree as `b218b81`.
Its checked-in `uv.lock` still labels the editable package `0.23.2`, not
`0.25.0`. Existing installed environments were used without refreshing locks.

## Native Validation

Commands were run in each SDK checkout at the heads above.

| SDK | Commands | Result |
| --- | --- | --- |
| Go | `go vet ./...`, `go test -count=1 ./...`, `go test -race ./...`, `(cd key/aws && go test ./...)`, `(cd examples/deployment-identity && go test ./...)`, `(cd examples/trust-policy && go test ./...)` | First full test run failed the OIDC exp=now boundary test; full rerun, race, vet, AWS and examples passed |
| TypeScript | `npm run typecheck`, `npm run build`, `npm test -- --run`, `npm run smoke:pack` | Typecheck/build/packed-package smoke passed; 945 tests passed, 1 skipped |
| Python | `.venv/bin/pytest -q`, `.venv/bin/ruff check dnsid tests`, `.venv/bin/mypy dnsid` | 1488 tests passed; lint/types clean |

## Shared Compliance Harness

The 2026-10-12 run matched all 193 expectations per SDK: 182 passes and 11
fail-closed rejections of retired selectors, with no unexpected failures or
known-bug allowances. The rebuilt Go shim, rebuilt TypeScript packages and
installed local Python package were used.

The C2SP matrix passed: all three writers produced identical canonical
ISSUANCE → KEY_ROTATION entries; all nine writer/verifier paths succeeded;
the Python-to-TypeScript split-signing handoff matched; every verifier rejected
all six mutated bundles.

Commands ran from the compliance repository root:

```sh
(cd shims/go && go build -o dnsid-shim .)
.venv/bin/python harness/run.py --out /tmp/dnsid-2026-10-12-harness.md
DNSID_GO_DIR="$HOME/dnsid-go" DNSID_TS_DIR="$HOME/dnsid-ts" DNSID_PY_DIR="$HOME/dnsid-py" .venv/bin/python harness/c2sp_matrix.py
```

Passing fixtures do not close the documented gaps. No live registry integration,
cloud authorization, persistent server replay/organization isolation, or full
recursive-migration interoperability was tested. SDK registration/provider and
recovery checks use local/mocked dependencies; the shared harness does not cover
those new requirements. Earlier focused event-identity checks were not rerun.

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
