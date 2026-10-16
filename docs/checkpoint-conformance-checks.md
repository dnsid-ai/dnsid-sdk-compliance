# Checkpoint continuity conformance checks

## Tested SDK revisions

| SDK | Commit |
|---|---|
| Go | `3529b743767feeda5f07c39addee93b23d40894c` |
| TypeScript | `156d0e945b256e3d4750f2d1d18f5d478069029e` |
| Python | `dc7f81b3855bd96c8cc050b4a0b456b7e9ed4f64` |

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
| Go | 9/15 | 6 | 0 |
| TypeScript | 9/15 | 6 | 0 |
| Python | 14/15 | 1 | 0 |

Known failures remain XFAIL, not compliant passes:

- Go misclassifies candidate-invalid scans and store errors, loses the transient
  classification of consistency retrieval failures at the public reader
  boundary, and reports a generic error for the invalid-checkpoint-signature case.
- TypeScript lacks the new continuity categories/diagnostics and store-error
  classification at this revision. Its missing-evidence condition is identifiable
  by the native exception type, without matching message text.
- Python reports `INCOMPLETE_STREAM` rather than `INVALID_EVIDENCE` for a complete
  scan missing a required candidate leaf.

Every SDK rejected the negative candidates, preserved the trusted checkpoint,
and retained injected dependency causes. Known-failure markers cannot hide a
change to those invariants, missing required proof-source calls, or adapter
failures. A fixed classification produces XPASS and requires removal of its marker.

## Validation

With the three SDK directory variables set and shims built:

```sh
.venv/bin/python harness/generate_c2sp_fixtures.py --check
.venv/bin/python harness/generate_wba_fixtures.py --check
.venv/bin/python -m unittest discover -s harness -p 'test_*.py'
.venv/bin/python harness/c2sp_event_identity_check.py
.venv/bin/python harness/run.py --out /tmp/compliance-checkpoints.md
(cd shims/go && go test ./... && go vet ./...)
```

The per-SDK CI entrypoint, `ci/run-one.sh`, was also run for Go, TypeScript,
and Python. Each produced a report with zero unexpected failures. Its unit
phase skips the three all-SDK adapter self-checks, since other SDKs are not
installed and the target shim is not built yet. The selected SDK still executes
all 15 shared checkpoint vectors after setup. All-SDK runs enable those
self-checks through the existing three SDK directory variables.

The all-SDK unit suite ran 40 tests without skips. The event-identity check ran 33 checks.
The full compliance run executed 358 cases per SDK with zero unexpected failures:
Go 341 PASS / 11 REJ / 6 XFAIL; TypeScript 341 PASS / 11 REJ / 6 XFAIL;
Python 346 PASS / 11 REJ / 1 XFAIL. TypeScript was rebuilt from the recorded checkout.

## Not covered

These cases do not test direct store-input validation, a durable adapter, real
concurrent writers, cancellation at publication, stale-lock recovery, crashes,
administrative authorization/audit
retention, network fallback orchestration, or full identity-manager verification.
Those still require SDK-native and deployment tests. No SDK source was changed
and no full SDK test suite was run by this change.
