# Checkpoint continuity conformance checks

## Tested SDK revisions

| SDK | Commit |
|---|---|
| Go | `501eff1271020603d5df44761ca64f10befa61b8` |
| TypeScript | `7be8f79aa7d044fc5e21e5e18c240025336cf418` |
| Python | `f7827000e720b665417e718276ebe21e75a63dbc` |

Checks ran on 2026-10-16 against clean SDK checkouts on their checkpoint-fix branches.

The expectations come from design 11's store contract and checkpoint diagnostic
rules, including the clarified distinction between candidate-invalid evidence
and a verified candidate that contradicts trusted history. They were not changed
to match the SDKs.

## Executed coverage

`fixtures/c2sp-checkpoint-continuity.yaml` contains 15 signed sequences. Adapters
authenticate the seed, share a native memory store across verifications, run the
public reader or bundle verifier, and inspect actual stored state afterward.
The wrong-root scan contradicts both roots, so candidate validity must take
precedence over a continuity classification. Go and TypeScript diagnostic byte
arrays are mutated before reading state back when those diagnostics are exposed.

| Checkpoint suite | Pass | Known failures | Unexpected failures |
|---|---|---|---|
| Go | 15/15 | 0 | 0 |
| TypeScript | 15/15 | 0 | 0 |
| Python | 15/15 | 0 | 0 |

All 13 prior known-failure entries were removed from the generator and regenerated
fixture: six for Go, six for TypeScript, and one for Python. The base expectations
and signed evidence are unchanged. TypeScript's missing-evidence condition now
uses the exported native exception type rather than its constructor name.

Every SDK rejected the negative candidates, preserved the trusted checkpoint,
and retained injected dependency causes. Known-failure markers cannot hide a
change to those invariants, missing required proof-source calls, or adapter
failures. A fixed classification produces XPASS and requires removal of its marker.

## Validation

The Go shim and TypeScript packages were rebuilt from the recorded checkouts.
The following commands passed, using the default sibling SDK directories:

```sh
make -W shims/go/checkpoint.go run c2sp-matrix
(cd shims/go && go test ./... && go vet ./...)
node --check shims/ts/checkpoint-verify.mjs
```

The `-W` argument forces the Go shim to rebuild even if only its SDK dependency
changed. `make run` checks both fixture generators, runs the harness unit suite
and event-identity checks, and writes the full compliance report to `report.md`.

The per-SDK CI entrypoint, `ci/run-one.sh`, was also run for Go, TypeScript,
and Python. Each produced a report with zero unexpected failures. Its unit
phase skips the three all-SDK adapter self-checks, since other SDKs are not
installed and the target shim is not built yet. The selected SDK still executes
all 15 shared checkpoint vectors after setup. All-SDK runs enable those
self-checks through the existing three SDK directory variables.

The all-SDK unit suite ran 40 tests without skips. Single-SDK unit runs had six
skips for Go, seven for TypeScript, and four for Python; all selected SDK vectors
still executed. The event-identity check ran 33 checks.

The all-SDK and per-SDK reports each recorded 347 PASS and 11 correct unsupported
version rejections per SDK: 358/358 compliant, with no FAIL, XFAIL, XPASS, or
MISSING results. The inactive Go taxonomy override for a retired version selector
was also removed; capability gating still requires that selector to be rejected.

The C2SP matrix produced identical entries from all three writers, passed all nine
writer/verifier paths and the Python-to-TypeScript split-signing handoff, and
confirmed that all three verifiers reject all six bundle mutations.

Cross-SDK CI checks SDK main branches, not these fix branches. Merge the SDK fixes
before merging this exception cleanup; older SDK heads still fail these cases.

## Not covered

These cases do not test direct store-input validation, a durable adapter, real
concurrent writers, cancellation at publication, stale-lock recovery, crashes,
administrative authorization/audit
retention, network fallback orchestration, or full identity-manager verification.
Those still require SDK-native and deployment tests. No SDK source was changed
and no full SDK test suite was run by this change.
