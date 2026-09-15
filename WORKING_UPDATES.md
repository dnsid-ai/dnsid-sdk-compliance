# Working Updates: Remaining DNSid Work

Updated 2026-09-08. Completed documentation corrections and superseded proposals
have been removed from this list. The architecture remains unchanged. This pass
changed design/tracker documentation, not SDK/server implementations, status
contracts, submitted numbered profiles, live logs, or historical signed fixtures.

## 1. Implement and validate the clarified SDK contracts

The design now specifies the following; runtime support still needs a scoped
review and any necessary implementation/regression tests across Go, TypeScript,
and Python. Historical `Implemented` rows are not proof of these corrections.

| Remaining work | Contract / acceptance boundary |
|---|---|
| Cache isolation | `01-core-identity-manager.md`: manager-private or explicitly identical immutable verification contexts; no cross-policy hits/coalescing or old-context in-flight results. Retain per-invocation peer checks. |
| Cache timing | `01` and `07`: absolute DNS expiry from acquisition, no TTL restart at verification completion/status refresh/cache insertion, final freshness checks, zero-TTL use only by the acquiring operation, and TLS/key-age checks even for zero TTL. Exercise slow verification, expiry during refresh/cache writes, and concurrent callers. |
| JOSE/OIDC parsing and time boundaries | `03` and `09`: duplicate-member/critical-header rejection, supported payload semantics, correctly typed finite NumericDates, expiration at equality and after network work, positive finite lifetimes, and omission-only defaults preserving zero skew. Add real SDK negative tests; the documented cases are not executable conformance evidence. |
| Verification-only and current-peer context | Shared README, `02`, `03`, and `09`: explicit trusted JWT audience without local identity configuration; forward the current application peer through HTTP, JWT/JWS, and DNSid-subject OIDC verification. Missing/wrong peer evidence must fail for `fl=mtls`, including cache hits. |
| Resource bounds | Shared README, `02`, `03`, and `11`: finite whole-invocation deadlines shared by candidates, retries, log resources, and migration hops; finite input/body/candidate limits before expensive work. Document the SDK-versus-host enforcing boundary and safe standalone defaults. Test cancellation, over-limit inputs, and no partial-success fallback. |
| Go `logchk` policy | Align profile helpers with the existing caller-owned operation policy. `jose/jose.go:221`, `:455`, `httpsig/http_signatures.go:378`, and `oidc/oidc.go:457` currently require evidence automatically. The tracker now records this as a divergence, not an approved exception. Update exported deviation metadata with actual behavior until corrected. |
| Small public-surface consistency | During the affected SDK reviews, confirm empty unknown-tag round trips, CLI `kuUrl`/`ekUrl` mappings and instance references, and `NewReader` parse errors versus `Register` argument errors. The documentation contradictions are fixed; no fresh claim about every SDK surface is made. |

**Question before implementation:** May the next pass edit all three SDK
repositories, or should it remain review-only? No further design decision is
needed for the requirements above. Prefer existing helpers and native
cancellation/storage primitives; do not introduce replacement frameworks.

## 2. Establish Python initial-issuance recovery coverage

The Python tracker now separates demonstrated publication/signing primitives
from unsubstantiated durable issuance recovery. Current citations
(`dnsid/manager.py:386`, `:400`, `:418`, `:1733` and
`dnsid/c2sp_tlog/prepared.py:119`) do not demonstrate one durable issuance intent,
restart recovery, exact-byte retries, accepted-result binding, or idempotent
completion. Managed rotation evidence is not initial-issuance evidence.

**Question:** Is a supported Python application/service already responsible for
this coordination? If so, identify that integration so it can be tested. If not,
confirm whether the desired SDK surface is managed-issuance parity with Go/TS
rather than requiring each caller to compose the recovery flow. Do not invent a
new coordinator merely to make the tracker green.

Python's standalone migration-bundle verifier is separately classified as a
limited API: it fails closed without predecessor resolution, while configured
readers perform recursive verification. No new standalone API is required.
Its general corrected-C2SP validation remains covered by the next section.

## 3. Corrected C2SP SDK/server implementation and release proof

The current wire contract is pinned from the SDK design to method commit
`d5a65d06f76eff4db81e50f8767a600d2ca7fc2a`. It retains `c2sp-tlog`, envelope
`v:1`, bundle `@v1`, the original separator-free state hash, and exact-byte log
proofs. Event identity excludes top-level signatures; successors bind logical
IDs. There is no second method, legacy fallback, or authorized history rewrite.

### Remaining implementation

- Update all SDK codecs, prepared events/chain types, full-role authentication,
  logical replay handling, and historical-predecessor fork detection. Keep Go's
  required high-S acceptance change local to C2SP, not shared JWT/TXT crypto.
- Make scanner and bundle selection agree. Direct reads and migration cutoffs
  must verify the exact requested occurrence, including valid later copies.
  Do not mistake an ignored invalid duplicate for valid standalone evidence.
- Remove bare-FQDN historical reader acceptance under the corrected method.
  TypeScript/Python trackers now identify it as an unapproved deviation; check
  every binding's reader path rather than fixing only its writer.
- Update the product's actual Go SDK dependency (research baseline: v0.31.0).
  Reuse the corrected SDK `Client.ChainForWrite` instead of duplicated server
  `Service.nextPublicChain` derivation/raw-entry counting.
- Preserve potentially authenticated malformed candidates in
  `internal/tlog/source.go` and `internal/tlog/monitor.go` until signature-aware
  classification. Reuse the SDK selector in `internal/tlog/bundle.go`.
- Establish one durable stream-predecessor admission guard across API submission,
  reconciliation, Temporal activities, and custody/signing handoffs. Existing
  JSON/revision-CAS submission records and immutable bytes/receipts are reusable;
  separate per-event slots are not a cross-event guard. Prove crash and
  indeterminate-append recovery rather than assuming an HTTP-only lock suffices.
- Regenerate shared signed evidence from corrected SDK implementations. Cover
  actual ES256 variants and stripped countersignatures, genuine forks, ordering,
  counts, invalid proofs, migration, scanner/bundle parity, and exact-byte retry.
  Old `issuance-resigned` evidence changes a signed extension and is not a
  signature-only replay test; do not change its expectation to manufacture a pass.

Research at Go `7ee0fee`, TS `b9c7395`, Python `0fb1dff`, and product `fc4d097b`
confirmed that all three SDK reducers reject valid history after an included
copy with an invalid/missing operational countersignature. Go already rejects
high-S but remains vulnerable to operational-copy poisoning and valid independent
re-signing. The 12-case real-signature probes in
`/tmp/dnsid-c2sp-research.Tzn7dC` isolate lifecycle selection and assume inclusion;
they are not network exploits, production exposure evidence, or maintained SDK
tests. The focused checked-in 33-case model is not SDK/proof/bundle conformance.

### Release and deployment decisions

- Independent review/acceptance of the corrected contract and integration remains
  required; provisional `specs/tlog/` artifacts are not approval.
- Inventory actual histories, client versions, and pending/indeterminate
  submissions before selecting cutovers. Preserve any complete history that
  verifies unchanged under the corrected rules (including a conforming public
  ISSUANCE-only stream); terminal histories remain terminal. Retain incompatible
  evidence and use fresh streams only where needed for new conforming histories.
- Reconcile outstanding submissions before replacing anything. Never replace
  bytes that may already have been appended. Coordinate readers, writers,
  workers, monitors, and bundle producers; no concurrent incompatible writers
  on one stream, log wipe, or silent old-chain upgrade.

**Questions:** Who will provide independent contract/integration acceptance?
Which deployment environments may be inventoried, and may the implementation
pass include the product repository as well as the SDKs? No production access or
destructive action is authorized by the documentation cleanup.

## 4. Status work — owned by the other session

Replacement-instance binding, HTTP freshness/revalidation, and the distinction
between response freshness and `lastTransitionAt` remain outside this session.
Reconcile the other session's result with publisher/verifier tests, including
cache hits and replacement at the same FQDN. The old Go future-transition
rejection also needs classification against that final contract.

**Question here:** None; await the other session rather than edit competing
status fields, URLs, or semantics.

## 5. Deployment measurements

The documentation now explains raw-scan amplification, existing bounded/required
bundle controls, and the single-live-key rotation cache window. Actual fallback
frequency/cost and rotation availability have not been measured in a deployment.
Use existing telemetry and configuration first; do not add an indexing service,
overlapping live keys, or automatic trust-update machinery.

**Question:** Which test/deployment workload and latency/resource budget should
be used for these measurements? Existing SDK defaults remain the starting point.

## Validation boundary for this cleanup

- The existing shared harness passed all 185 expectations per SDK (174 passes
  plus 11 retired-selector rejections), including the existing empty-unknown-tag
  and 12 HTTP signature-base vectors. These retained fixtures predate the new
  security requirements; this is baseline regression evidence, not corrected
  conformance. No new shared counts or full-review baselines were advertised.
- Three existing Python migration checks passed: recursive raw history,
  recursive bundles, and standalone fail-closed behavior. Run from `~/dnsid-py`:
  `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_c2sp_migration.py -k 'factory_recursively_verifies_single_and_nested_migrations or stream_bundles_use_the_same_recursive_cutoff_verification or standalone_bundle_verifier_rejects_migration_without_predecessor_resolution'`.
- The first attempted pytest invocation used the compliance environment, which
  has no pytest; the successful run used the existing Python SDK environment.
- The 33 focused C2SP checks pass. All eight C2SP dependency pins match the
  immutable method source; the CLI sample's instance ID, local link paths,
  Markdown fences, and whitespace were checked. The frozen numbered record
  profile, status schema/validation, and prior cache-isolation text were preserved.
  `git diff --check` passes in the compliance, method, and product repositories.
- Temporary baseline output is in `/tmp/dnsid-small-fixes.Wy8CMR/`. Broad renewed
  SDK review, executable new-boundary tests, integration/race/recovery tests,
  and deployment evidence remain required before claiming release conformance.
