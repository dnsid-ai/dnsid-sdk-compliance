# SDK Implementation Coverage

This directory tracks coverage of the [SDK Design](../README.md) across the Go,
TypeScript, and Python SDKs. Each tracker's `Analysis Details` table is the
**authoritative review baseline**; use its full commits, not this summary.
Historical review scopes and resolved findings remain available in Git history.

## Latest Review — 2026-10-01

| SDK | Coverage File | Reviewed Branch | Reviewed Commit | Package Version | Open Findings |
| --- | --- | --- | --- | --- | --- |
| Go | [go.md](./go.md) | `main` | `9850ba2` | `v0.37.1` | Missing deployment-file loader; partial construction ordering, unavailable-TTL handling, and conformance metadata |
| TypeScript | [typescript.md](./typescript.md) | `main` | `50d5573` | `0.24.1` | Partial construction validation ordering |
| Python | [python.md](./python.md) | `fix/leftover-sandbox` | `b218b81` | `0.23.1` | Partial missing-DoH-TTL handling, prepared-event metadata, OIDC response bounds, conformance metadata, and issuance-recovery evidence |

Design baseline: `main` at
`4de3e4545bf665dbe8b74d1693b4823604f798d1`. Package versions identify the reviewed
source; these post-release heads are not claims about published release contents.

Design changes since `9326f7a`:

- `def611a` changes the managed development selector and conformance vectors to
  `https://log.dev.dnsid.ai`.
- `a858525` requires zero TTL when a fresh DNS answer's TTL is unavailable.
- `ac7ffda` updates identity examples; `c832a7e` moves root wire/generation vectors
  to second-level `.test` identities and regenerates signatures.

No identity-record profile or C2SP method revision changed. All three SDKs replace
managed development/production trust pins without legacy overlap. Go now captures
wire TTLs but errors when capture is unavailable; TypeScript captures wire TTLs
and uses zero on native fallback. Python still invents a 300-second TTL when DoH
omits it. Go and TypeScript still permit a policy fetch before rejecting injected
transport conflicts; Go still lacks the design 12 deployment-file loader.

Python's checked-in `uv.lock` labels the editable package `0.21.0`, not `0.23.1`.
Its untracked `tests/test_validate_domain_example.py` was inspected but excluded
from the committed-head test count. See the tracker for remaining implementation
and evidence gaps; its standalone migration-verifier limitation does not imply
missing recursive migration support in configured readers.

## Native Validation

Commands were run in each SDK checkout at the heads above.

| SDK | Commands | Result |
| --- | --- | --- |
| Go | `go vet ./...`, `go test -count=1 ./...`, `go test -race ./...`, `(cd key/aws && go test ./...)` | All passed |
| TypeScript | `npm run typecheck`, `npm run build`, `npm test -- --run` | Typecheck/build passed; 877 tests passed, 1 skipped |
| Python | `.venv/bin/pytest -q --ignore=tests/test_validate_domain_example.py`, `.venv/bin/ruff check dnsid tests`, `.venv/bin/mypy dnsid` | 1378 tests passed; lint/types clean; existing virtualenv used without refreshing `uv.lock` |

## Shared Compliance Harness

The 2026-10-01 run matched all 193 expectations per SDK: 182 passes and 11
fail-closed rejections of retired selectors, with no unexpected failures or
known-bug allowances. Coverage includes release conformance metadata, signed TXT
generation, seven managed trust-selection vectors, and 12 RFC 9421 vectors.

The C2SP matrix also passed at those heads: all three writers produced the same
canonical ISSUANCE → KEY_ROTATION stream; all nine writer/verifier paths succeeded;
the Python-to-TypeScript split-signing handoff matched; and every verifier
rejected all six mutated bundles.

Validation used a rebuilt Go shim, rebuilt TypeScript packages, and the installed
local Python package. Shared commands ran from the compliance repository root:

```sh
.venv/bin/python harness/run.py --out /tmp/dnsid-2026-10-01-harness.md
DNSID_GO_DIR="$HOME/dnsid-go" DNSID_TS_DIR="$HOME/dnsid-ts" DNSID_PY_DIR="$HOME/dnsid-py" .venv/bin/python harness/c2sp_matrix.py
```

Passing tests do **not** establish complete SDK conformance or close the documented
gaps. The harness does not cover the registry Live workflow or the newly recorded
unavailable-TTL paths; the matrix does not establish full recursive migration
interoperability. Earlier focused event-identity checks are not included in the
193 expectations and were not rerun in this review.

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
