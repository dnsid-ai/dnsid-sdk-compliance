# WBA Conformance Harness Checks — 2026-10-12

This is focused harness validation, not a new full SDK implementation review.
The shared [WBA corpus](sdk-design/conformance/web-bot-auth.json) targets both
WBA drafts at revision `00` and preserves the current authority-only coverage
policy.

## Source snapshots

Tests used isolated, detached worktrees of these committed SDK heads:

| SDK | Commit |
|---|---|
| Go | `3369ad9930041ab46eb52ccdee0e6e24bf303a4e` |
| TypeScript | `18c797bdf899f2e2a495f881047c3db7452f708a` |
| Python | `d82ad8260ede279a9b7e3c5b3039e4b391963565` |

The sibling checkouts had uncommitted verifier work. That work was not changed
or certified by this run. The isolated TypeScript packages and Go shim were
rebuilt; Python was installed editable into an isolated virtual environment.

## Results

Each SDK matched all 234 executable expectations: 223 passes and 11 fail-closed
rejections of retired selectors. There were no unexpected failures, known-bug
allowances, or stale known-bug markers.

The WBA suite adds 25 exact request-base cases and 16 signing/directory cases.
The signing checks use each SDK's production API and independently verify the
emitted Ed25519 signature, digest, component coverage, parameters, and directory
key representation. Existing Basic and Bearer credentials are preserved.

The remaining 45 positive/negative WBA verifier cases are `MISSING` for all
three committed baselines. They were not executed or counted as compliant.
The report therefore shows 234/279 (83.9%), not complete WBA conformance.
The shims require native verification-adapter integration when SDK verifiers
become available; unsupported-operation errors must never pass negative cases.

Fixture reproducibility, independent golden cryptographic checks, 12 harness
unit tests (including CI missing-capability counts and regression gating), Python
error/unused-import checks, Node syntax, shell syntax, and Go shim vet/build/tests
passed. The Go shim packages have no native unit-test files; signing behavior was
exercised through the shared harness.

Existing C2SP checks also passed: fixture reproducibility, 33 focused checks,
three identical writers, all nine writer/verifier paths, the Python-to-TypeScript
split-signing handoff, and rejection of all six mutations by every verifier.

## Commands

With `BASELINES` set to the temporary snapshot directory:

```sh
export DNSID_GO_DIR="$BASELINES/dnsid-go"
export DNSID_GO_SHIM="$BASELINES/dnsid-shim"
export DNSID_TS_DIR="$BASELINES/dnsid-ts"
export DNSID_PY_DIR="$BASELINES/dnsid-py"
export GOWORK="$BASELINES/go.work"
PY="$BASELINES/venv/bin/python"

(cd shims/go && go build -o "$DNSID_GO_SHIM" . && go vet ./... && go test ./...)
(cd "$DNSID_TS_DIR" && npm ci --silent && npm run build --silent)
"$PY" harness/generate_wba_fixtures.py --check
"$PY" -m unittest discover -s harness -p 'test_*.py'
"$PY" harness/run.py --out /tmp/dnsid-wba-full-report.md
"$PY" harness/generate_c2sp_fixtures.py --check
"$PY" harness/c2sp_event_identity_check.py
"$PY" harness/c2sp_matrix.py
node --check shims/ts/shim.mjs
bash -n ci/run-one.sh
```

The fixture checker is not a production verifier. DNSid verification, live
discovery/TLS, cache behavior, replay-store concurrency, published package
contents, and partner interoperability were not certified.
