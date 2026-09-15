#!/usr/bin/env bash
# Run the compliance suite for a single SDK against a single checkout, writing a
# markdown report. Used twice by the PR check (head vs base) with its own venv
# each time — dnsid-py is imported in-process, so two refs can't share one venv.
#
# Usage: run-one.sh <go|ts|py> <sdk_dir> <out.md>
# Exits 0 when the harness produced a report; the caller ratchets case failures.
# Harness crashes and missing reports fail this suite step.
set -euo pipefail

sdk=$1; dir=$2; out=$3
cd "$(dirname "$0")/.."   # repo root

venv=$(mktemp -d)/venv
uv venv "$venv"
if [ "$sdk" = py ]; then
  uv pip install -q -p "$venv" pyyaml cryptography -e "$dir"
else
  uv pip install -q -p "$venv" pyyaml cryptography
fi

"$venv/bin/python" harness/generate_c2sp_fixtures.py --check
"$venv/bin/python" harness/c2sp_event_identity_check.py

case "$sdk" in
  go) (cd shims/go && rm -f go.work go.work.sum && go work init . "$dir" && go build -o dnsid-shim .) ;;
  ts) (cd "$dir" && npm ci --silent && npm run build --silent) ;;
esac

rm -f "$out"
set +e
DNSID_GO_DIR="$dir" DNSID_TS_DIR="$dir" DNSID_PY_DIR="$dir" \
  "$venv/bin/python" harness/run.py --sdks "$sdk" --out "$out"
status=$?
set -e

if [ ! -s "$out" ]; then
  echo "compliance harness exited $status without creating $out" >&2
  [ "$status" -ne 0 ] || status=1
  exit "$status"
fi

# A nonzero status with a complete report is an ordinary compliance mismatch;
# sdk-compliance.yaml compares it with the base report at the ratchet gate.
exit 0
