# SDK Implementation Coverage

This directory tracks implementation coverage for the [SDK Design](../README.md) across the Go, TypeScript, and Python SDKs.

Use the per-SDK files for implementation evidence:

| SDK | Coverage File | Last Reviewed Branch | Last Reviewed Commit | Package Version | Last Analysis Date | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Go | [go.md](./go.md) | `feat/private-address-hosts` | `9c75835` | `v0.34.0`+unreleased | 2026-09-22 | `PrivateAddressHosts` and `ConfigFromEnv` implemented per design 05; no open findings |
| TypeScript | [typescript.md](./typescript.md) | `private-address-hosts` | `c24c86d` | `0.21.0`+unreleased | 2026-09-22 | `privateAddressHosts` (suffix entries, no implicit `.test`) implemented per design 05. Partial: `verifyPublicationEvidence` remains a published acceptance-free method |
| Python | [python.md](./python.md) | `private-address-hosts` | `686d7bf` | `0.20.0`+unreleased | 2026-09-22 | `private_address_hosts` (no implicit `.test`, C2SP passthrough, choke-point validation) and constructor-time config type validation implemented. Partial: prepared-event, OIDC response-bound, conformance-metadata, and issuance-evidence gaps remain |

The 2026-09-22 second pass reviews the three `private-address-hosts` SDK branches
against design branch `design/private-address-hosts` (`5cc35bc`), which replaced
the unspecified hostname-scoped allowlist with `TransportConfig.privateAddressHosts`
(no built-in `.test` exemption) and rewrote the `AgentRegistrationInput` defaults.
All three SDKs implement the new field; the earlier `.test` and
registration-default findings are resolved. Native suites, the 193-expectation
harness, and the C2SP matrix were rerun at the branch heads and passed.

The earlier 2026-09-22 review followed the move from the `Identity-Digital` organization
to `dnsid-ai`, which rewrote history in every repository. The old baselines were
recovered from pre-migration clones and shown to be content-identical (modulo
org/module renames) to each repository's new "Initial public release" root, so
the trackers proceed incrementally from those roots. Design changes since
`1d3fbb5` are wording and RFC 2606 fixture domains only. SDK changes common to
all three bindings: an implicit `.test`-TLD exemption in the SSRF guard (design
01 requires an explicit hostname-scoped allowlist), registration defaults that
invert design 05's documented product default (`production`, `managed` requires a
zone), a loopback `dnsid local` default registry URL, explicit registry
environment loaders, and a transport option on the C2SP verification factory.
Because the transport guard and (TS/Python) `verifyDomain` fan-out are
cross-cutting, native suites, the 193-expectation shared harness, and the C2SP
matrix were rerun at the heads recorded below and passed.

The 2026-09-15 review covered design commits `dd5ef3b..1d3fbb5` (the consolidated
`DnsidConfig` and `trustedEntities` contract); each tracker's
`SDK Configuration and Counterparty Acceptance` section carries that evidence.

The 2026-09-09 review reconciled the earlier tracker edits and superseded the
historical correction notices. Per-SDK files retain authoritative review scope,
source citations, findings, and hosting preconditions. Passing shared tests does
not establish complete SDK conformance or eliminate the documented Python gaps.
Python's standalone migration-verifier limitation does not imply missing
migration support in configured readers.

## Last Run Details

| Repository | Branch | Version / Commit | Package Version | Analysis Date | Notes |
| --- | --- | --- | --- | --- | --- |
| dnsid design docs baseline | `design/private-address-hosts` | `5cc35bcb35c75800ff6ed726b85db4ae34f36382` | N/A | 2026-09-22 | Adds 05 `Private Address Hosts`, `privateAddressHosts` in 01/05/11, and the rewritten `AgentRegistrationInput`; `fixtures/` unchanged since `c20013d`. 33 focused event-identity checks pass. |
| dnsid-go | `feat/private-address-hosts` | `9c75835` | `v0.34.0`+unreleased | 2026-09-22 | `go vet ./...`, `go test -count=1 ./...`, `go test -race ./...`, `key/aws` module tests, all 193 shared expectations, and the C2SP matrix passed. |
| dnsid-ts | `private-address-hosts` | `c24c86d` | `0.21.0`+unreleased | 2026-09-22 | 836 tests passed, 1 skipped; typecheck, build, all 193 shared expectations, and the C2SP matrix passed. |
| dnsid-py | `private-address-hosts` | `686d7bf` | `0.20.0`+unreleased | 2026-09-22 | 1390 tests, `ruff`, `mypy`, all 193 shared expectations, and the C2SP matrix passed. |

## Shared Compliance Harness

The latest recorded three-SDK run (2026-09-22, second pass) used Go commit `9c75835`,
TypeScript commit `c24c86d`, and Python commit `686d7bf`. Each SDK matched all 193 expectations:
182 passes plus 11 fail-closed rejections of retired selectors, with no
unexpected failures or known-bug allowances. This includes release conformance
metadata, signed TXT generation, all seven managed trust-selection vectors, and
all 12 RFC 9421 vectors.

The C2SP interoperability gate passed at those same SDK heads. Go,
TypeScript, and Python independently produced the same canonical ISSUANCE to
KEY_ROTATION stream, all three verifiers accepted every writer for nine
interoperable paths, the Python-to-TypeScript split ISSUANCE handoff matched,
and all three verifiers rejected all six negative bundle mutations. These results
use the corrected logical-event-chain contract. The matrix does not establish
full recursive migration interoperability. The shared harness does not cover the
registry Live workflow; that area is tracked in the per-SDK files.

Validation used the direct harness commands (`harness/c2sp_event_identity_check.py`,
`harness/run.py`, `harness/c2sp_matrix.py`) with a rebuilt Go shim, a rebuilt
TypeScript package, and the Python package reinstalled into `.venv`.
The separate 33 focused event-identity checks are not included in the 193 SDK
expectations and do not themselves verify SDKs, proofs, bundles, or migration.

## Agent Update Instructions

Follow [AGENTS.md](../AGENTS.md) for the authoritative review procedure. Use an incremental review when the recorded history is available and the impact can be bounded confidently.

1. Read the target SDK file first. Its `Analysis Details` table—not this summary—is the authoritative baseline for that SDK.
2. Record the current design commit, SDK branch and commit, package version, and analysis date. Verify that the recorded commits resolve and are ancestors of the current heads.
3. Review both deltas:
   - Every design-repo commit after the recorded design baseline that touched `docs/sdk-design/` or root `fixtures/`, excluding `docs/sdk-design/implementations/` and `docs/sdk-design/AGENTS.md` but including `conformance/`, wire/generation fixtures, and conformance metadata. Inspect current uncommitted changes separately.
   - Every SDK-repo commit after the recorded SDK baseline across the entire repository.
4. Inspect commit subjects and name/status changes, then aggregate diffs. Map changed requirements and implementation paths to coverage rows before loading files. Follow callers for cross-cutting changes and refresh line references in every cited file that changed.
5. Re-review every impacted row and add rows for new requirements. Preserve a row only after confirming neither delta affects it. Perform a full review when baselines are unavailable, history was rewritten, impact cannot be bounded, or broad security-critical/API changes occurred.
6. For each reviewed item, use:
   - `Implemented: path/to/file.ext:line` when behavior matches the design.
   - `Partial: path/to/file.ext:line` with the missing or divergent behavior stated.
   - `Missing` when no implementation is found.
   - `Not applicable` only when the item genuinely does not apply.
7. Prefer direct implementation references over tests. Verify behavior, validation, errors, and defaults rather than exported names alone. Keep findings separate from evidence and record validation commands actually run.
8. Update the target file's exact-head metadata even if statuses do not change. Update this summary only when the user requests it or the review scope includes shared run metadata.

## Status Legend

| Status | Meaning |
| --- | --- |
| TBD | Not reviewed yet. |
| Implemented | Reviewed and matches the design item. |
| Partial | Reviewed and present, but incomplete or divergent. |
| Missing | Reviewed and no implementation found. |
| Not applicable | Reviewed and intentionally does not apply. |

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
