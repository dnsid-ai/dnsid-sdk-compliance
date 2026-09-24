# SDK Implementation Coverage

This directory tracks implementation coverage for the [SDK Design](../README.md) across the Go, TypeScript, and Python SDKs.

Use the per-SDK files for implementation evidence:

| SDK | Coverage File | Last Reviewed Branch | Last Reviewed Commit | Package Version | Last Analysis Date | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Go | [go.md](./go.md) | `main` | `089fe48` | `v0.36.0` | 2026-09-24 | Missing design 12 deployment-file loader; partial construction validation ordering |
| TypeScript | [typescript.md](./typescript.md) | `main` | `86b708a` | `0.23.0` | 2026-09-24 | Partial design 12 construction validation ordering |
| Python | [python.md](./python.md) | `main` | `a07070a` | `0.22.0` | 2026-09-24 | Partial prepared-event metadata, OIDC response bounds, conformance metadata, and issuance-recovery evidence |

The 2026-09-24 review covers design 12 configuration loading on design `main`
(`615f182`) and SDK implementation commits through `a255586` (Go), `bb70f74`
(TypeScript), and `68ba790` (Python). The next commit in each SDK is a release:
`v0.36.0`, `v0.23.0`, and `v0.22.0`, respectively. The design repo's
`9326f7a` tracker commit changes no requirements or fixtures; release commits
change no implementation source or tests. All three native suites, the shared
193-expectation harness and the C2SP matrix passed at the release heads. Go still
lacks the design 12 deployment-file loader; Go and TypeScript still defer an
injected-transport conflict check until after a policy fetch can occur. The
Python partials listed above remain open. Python's released `uv.lock` still
records the editable package as `0.21.0` rather than `0.22.0`.

The 2026-09-23 review records the releases cut from the `private-address-hosts`
branches (Go `v0.35.0`, TypeScript `0.22.0`, Python `0.21.0`). Each branch was
squash-merged to `main`, so the prior baselines are not literal ancestors; the Go
and Python squash commits are tree-identical to the reviewed tips, and the
TypeScript squash additionally enables `stripInternal` and un-exports
`RegistryPublicationVerifier`, resolving the acceptance-free-method finding. The
design repo changed only under `implementations/`. Native suites, the
193-expectation harness, and the C2SP matrix were rerun at the release heads and
passed.

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
| dnsid design docs baseline | `chore/impl-tracker-updates` | `9326f7a7407d68376f8484e1122a696f01b01ee0` | N/A | 2026-09-24 | Tracker-only change since design `main` `615f182`; no fixture or design requirement changes. |
| dnsid-go | `main` | `089fe482a1ec757b0d27fb4168e5af1a9bb4e0d8` | `v0.36.0` | 2026-09-24 | `go vet ./...`, `go test -count=1 ./...`, `go test -race ./...`, `key/aws` module tests, 193/193 shared expectations, and C2SP matrix passed. |
| dnsid-ts | `main` | `86b708a977ffa43414719d7ebf10fa7d74cfdc2b` | `0.23.0` | 2026-09-24 | 866 tests passed, 1 skipped; typecheck, build, 193/193 shared expectations, and C2SP matrix passed. |
| dnsid-py | `main` | `a07070a53a9191ce158b43dd17be7e0619a945e7` | `0.22.0` | 2026-09-24 | 1376 tests, `ruff`, `mypy`, 193/193 shared expectations, and C2SP matrix passed. |

## Shared Compliance Harness

The latest recorded three-SDK run (2026-09-24) used Go commit `089fe48`,
TypeScript commit `86b708a`, and Python commit `a07070a`. Each SDK matched all 193 expectations:
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

Validation used `harness/run.py` and `harness/c2sp_matrix.py` with a rebuilt
Go shim, rebuilt TypeScript packages, and the installed local Python package.
The earlier 33 focused event-identity checks are not included in the 193 SDK
expectations and were not rerun at these release heads.

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
| Configuration Loading | [12-configuration-loading.md](../12-configuration-loading.md) |
