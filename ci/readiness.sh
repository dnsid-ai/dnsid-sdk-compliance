#!/usr/bin/env bash
# Release-readiness checks for one SDK checkout: the mechanically verifiable rows
# of the InfoSec checklist and the OSS legal review form. Human decisions (CRA,
# CLA, owners, export record) are not here on purpose.
#
# Usage: readiness.sh <go|ts|py|cookbook> <repo_dir> <out.md>
#        cookbook = docs/recipes repo: no published package, so release/vuln-scan/license rows are N/A.
# Env:   GH_TOKEN (optional) enables the GitHub-settings section.
# Exit:  1 if any check is FAIL. WARN never fails the build.
set -uo pipefail

# fail closed: every grep-based check reads "no output" as a pass, so a missing rg would false-pass them
command -v rg >/dev/null || { echo "readiness.sh: ripgrep (rg) is required" >&2; exit 2; }

sdk=$1; dir=$2; out=$3
case $out in /*) ;; *) out=$PWD/$out ;; esac  # resolve before cd so the report lands where the caller expects
root=$(cd "$(dirname "$0")/.." && pwd)
repo="dnsid-ai/dnsid-$sdk"
rows=(); fails=0

ok()   { rows+=("| ✅ | $1 | $2 |"); }
warn() { rows+=("| 🟡 | $1 | $2 |"); }
fail() { rows+=("| ❌ | $1 | $2 |"); fails=$((fails+1)); }
# has PATTERN GLOBS... : rg with library-only scope (no tests/docs/deps)
lib_rg() { rg -n -i --no-heading "$@" \
  -g '!*_test.go' -g '!*.test.ts' -g '!test/**' -g '!tests/**' -g '!docs/**' -g '!examples/**' \
  -g '!node_modules/**' -g '!*.md' -g '!NOTICE.txt' -g '!LICENSE*' -g '!*lock*' -g '!*.sum' -g '!typedoc*.json' -g '!cliff.toml' . ; }

cd "$dir"

# --- files --------------------------------------------------------------------
for f in LICENSE* NOTICE.txt CONTRIBUTING.md .github/CODEOWNERS .github/dependabot.yml; do
  if compgen -G "$f" >/dev/null; then ok "file: $f" "present"; else fail "file: $f" "missing (Legal §1/§12, OSS-018)"; fi
done
# canonical policy files: byte-identical to policy/ in this repo
if [ -f SECURITY.md ]; then
  if cmp -s SECURITY.md "$root/policy/SECURITY.md"; then ok "SECURITY.md" "matches policy/SECURITY.md"
  else fail "SECURITY.md" "differs from dnsid-sdk-compliance/policy/SECURITY.md (VIR-009, OSS-021)"; fi
else fail "SECURITY.md" "missing (VIR-001)"; fi
if [ -f CODE_OF_CONDUCT.md ]; then
  if cmp -s CODE_OF_CONDUCT.md "$root/policy/CODE_OF_CONDUCT.md"; then ok "CODE_OF_CONDUCT.md" "matches policy/CODE_OF_CONDUCT.md"
  else fail "CODE_OF_CONDUCT.md" "differs from dnsid-sdk-compliance/policy/CODE_OF_CONDUCT.md (Legal §12)"; fi
else fail "CODE_OF_CONDUCT.md" "missing (Legal §12, OSS-018)"; fi

# --- dependency licenses (Legal §1, OSS-002) -------------------------------------------
# Permissive allowlist; anything else (GPL/AGPL/unknown) fails. Own workspace packages excluded.
lic_ok=""
case $sdk in
  go) if command -v go >/dev/null; then
        err=$(go run github.com/google/go-licenses@v1.6.0 check ./... \
          --allowed_licenses=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0 2>&1 >/dev/null); rc=$?
        lic_ok="$(grep -v '^W' <<<"$err") rc=$rc"; fi ;;
  ts) if [ -d node_modules ] || npm ci --ignore-scripts >/dev/null 2>&1; then
        bad=$(npm ls --all --omit=dev --parseable -ws --include-workspace-root 2>/dev/null | grep node_modules | sort -u | while read -r d; do
          [ -f "$d/package.json" ] && jq -r 'select((.name|startswith("@dnsid-ai/"))|not) | "\(.name) \(.license // "UNKNOWN")"' "$d/package.json"; done \
          | grep -vE ' (Apache-2\.0|MIT|BSD-[23]-Clause|ISC|0BSD|MPL-2\.0|BlueOak-1\.0\.0|CC0-1\.0|Python-2\.0|\(MIT OR [A-Za-z0-9.-]+\))$' || true)
        lic_ok="$bad rc=$([ -z "$bad" ] && echo 0 || echo 1)"; fi ;;
  py) if command -v uv >/dev/null; then
        uv venv -q --clear /tmp/lic && uv pip install -q -p /tmp/lic . pip-licenses 2>/dev/null &&
        lic_ok=$(/tmp/lic/bin/pip-licenses --ignore-packages dnsid pip-licenses --partial-match \
          --allow-only 'Apache;MIT;BSD;ISC;MPL;Mozilla;PSF;Python Software Foundation' 2>&1 >/dev/null; echo "rc=$?"); fi ;;
esac
if [ "$sdk" = cookbook ]; then ok "dependency licenses" "N/A — recipes fetch deps at run time, nothing redistributed (NOTICE.txt)"
elif [ -z "$lic_ok" ]; then warn "dependency licenses" "tool unavailable; skipped"
elif [[ $lic_ok == *rc=0 ]]; then ok "dependency licenses" "all runtime deps permissive (Apache/MIT/BSD/ISC/MPL)"
else fail "dependency licenses" "$(echo "$lic_ok" | sed 's/ *rc=[0-9]*$//' | head -3 | tr '\n' ';') (Legal §1, OSS-002)"; fi

# --- release pipeline -----------------------------------------------------------
rel=.github/workflows/release.yml
if [ "$sdk" = cookbook ]; then ok "release: pipeline" "N/A — no published artifact"
elif [ -f "$rel" ]; then
  rg -qi 'sbom-action|syft|cyclonedx' "$rel" && ok "release: SBOM step" "found in $rel" || fail "release: SBOM step" "none in $rel (OSS-003, Legal §1 CRA driver)"
  rg -qi 'attest-build-provenance|--provenance|cosign|sigstore' "$rel" && ok "release: signing/provenance" "found in $rel" || fail "release: signing/provenance" "none in $rel (OSS-010/011/012)"
else fail "release: workflow" "$rel missing"; fi
# pinned = 40-hex SHA; our own reusable workflows (dnsid-ai/*) and local ./ paths are exempt
unpinned=$(rg -n '^\s*-?\s*uses:\s*[^./]\S*@' .github/workflows 2>/dev/null | grep -vE '@[0-9a-f]{40}\b|uses:\s*dnsid-ai/' || true)
[ -z "$unpinned" ] && ok "actions SHA-pinned" "all \`uses:\` pinned" || fail "actions SHA-pinned" "unpinned: $(echo "$unpinned" | wc -l | tr -d ' ') (SSD-014)"
[ "$sdk" = cookbook ] && ok "CI: dependency vuln scan" "N/A — Dependabot alerts cover recipe manifests" || rg -qi 'govulncheck|npm audit|pip-audit|osv-scanner|trivy' .github/workflows && ok "CI: dependency vuln scan" "found" || fail "CI: dependency vuln scan" "no govulncheck/npm audit/pip-audit in CI (SSD-006)"
rg -qi 'codeql-action|semgrep|gosec|bandit' .github/workflows && ok "CI: SAST" "found" || fail "CI: SAST" "no CodeQL/semgrep/gosec/bandit in CI (SSD-005)"

# --- secrets --------------------------------------------------------------------
if command -v gitleaks >/dev/null; then
  if gitleaks git --no-banner --redact --exit-code 1 . >/tmp/gitleaks.log 2>&1; then ok "gitleaks (full history)" "no leaks"
  else fail "gitleaks (full history)" "$(grep -c 'Fingerprint' /tmp/gitleaks.log) finding(s) (IDT-006, OSS-014, Legal §6)"; fi
else warn "gitleaks" "not installed; skipped"; fi

# --- library source hygiene ---------------------------------------------------------
hits=$(lib_rg 'InsecureSkipVerify\s*:\s*true|rejectUnauthorized:\s*false|verify\s*=\s*False|CERT_NONE' || true)
[ -z "$hits" ] && ok "TLS verification never disabled" "" || fail "TLS verification never disabled" "$(echo "$hits" | head -3 | tr '\n' ';') (DAT-007, API-001)"
hits=$(lib_rg 'telemetry|analytics|sentry|posthog|segment\.io|mixpanel' || true)
if [ -z "$hits" ]; then ok "no telemetry" "no telemetry/analytics libraries or strings"
elif [ "$sdk" = cookbook ]; then warn "no telemetry" "recipe-level instrumentation (must be disclosed in that recipe's README, data goes to the user's own account): $(echo "$hits" | head -3 | tr '\n' ';')"
else fail "no telemetry" "$(echo "$hits" | head -3 | tr '\n' ';') (DAT-003, Legal §5)"; fi
hits=$(lib_rg '\baes\b|\bjwe\b|ecdh|hpke|chacha|xchacha' || true)
[ -z "$hits" ] && ok "signature-only cryptography" "no confidentiality primitives; export classification unchanged" || fail "signature-only cryptography" "encryption primitive introduced — re-run export review (Legal §4): $(echo "$hits" | head -2 | tr '\n' ';')"
hits=$(lib_rg -o 'https?://[a-zA-Z0-9._-]+' | sed -E 's#.*https?://##' | sort -u | grep -vE '^(docs\.dnsid\.ai|app\.dnsid\.ai|api\.dnsid\.(ai|dev)|oidc\.dnsid\.(ai|dev)|log\.dnsid\.(ai|dev)|witness\.dnsid\.(ai|dev)|c2sp\.org|github\.com|pkg\.go\.dev|datatracker\.ietf\.org|www\.rfc-editor\.org|.*\.example(\.[a-z]+)?\.?|.*\.test|.*\.invalid|localhost|\.\.\.)$' || true)
[ -z "$hits" ] && ok "network destinations" "only first-party/spec/RFC 2606 hosts in library source" || warn "network destinations" "unlisted hosts, add to COM-003 inventory or allowlist: $(echo "$hits" | tr '\n' ' ')"

# --- test fixtures ----------------------------------------------------------------
# Match a full hostname so `registry.dev.dnsid.test` is not misread as `registry.dev`.
hits=$(rg -oIN --no-heading '\b[a-z0-9.-]+\.(com|net|org|io|ai|dev|co)\b(?![a-z0-9.-])' --pcre2 -g '*_test.go' -g '*.test.ts' -g 'tests/**' -g 'test/**' -g '!node_modules/**' . 2>/dev/null \
  | grep -vE '(^|\.)example\.|(^|\.)(github\.com|dnsid\.(ai|dev)|c2sp\.org|ietf\.org|w3\.org|golang\.org|npmjs\.com|pypi\.org|rfc-editor\.org)$' | sort -u || true)
[ -z "$hits" ] && ok "test fixtures: RFC 2606 domains only" "" || warn "test fixtures: RFC 2606 domains only" "registrable placeholders: $(echo "$hits" | tr '\n' ' ') (Legal §6)"

# --- GitHub settings (needs token) -----------------------------------------------------
if [ -n "${GH_TOKEN:-}" ] && command -v gh >/dev/null; then
  meta=$(gh api "repos/$repo" 2>/dev/null || true)
  if [ -n "$meta" ]; then
    private=$(jq -r .private <<<"$meta")
    [ "$(jq -r '.description // ""' <<<"$meta")" != "" ] && ok "repo description" "set" || fail "repo description" "blank (OSS-001)"
    for k in secret_scanning secret_scanning_push_protection dependabot_security_updates; do
      st=$(jq -r ".security_and_analysis.$k.status // \"unknown\"" <<<"$meta")
      if [ "$st" = enabled ]; then ok "github: $k" "enabled"
      elif [ "$private" = true ]; then warn "github: $k" "$st — must be enabled before/when repo goes public (SSD-006/007)"
      else fail "github: $k" "$st (SSD-006/007)"; fi
    done
    pvr=$(gh api "repos/$repo/private-vulnerability-reporting" --jq .enabled 2>/dev/null || echo unavailable)
    if [ "$pvr" = true ]; then ok "github: private vulnerability reporting" "enabled"
    elif [ "$private" = true ]; then warn "github: private vulnerability reporting" "public-repo feature; enable at publication (VIR-001)"
    else fail "github: private vulnerability reporting" "$pvr (VIR-001)"; fi
    rs=$(gh api "repos/$repo/rulesets" --jq '.[] | select(.enforcement=="active") | .id' 2>/dev/null | head -1)
    if [ -n "$rs" ]; then
      r=$(gh api "repos/$repo/rulesets/$rs")
      types=$(jq -r '[.rules[].type] | join(",")' <<<"$r")
      bypass=$(jq -r '.bypass_actors | length' <<<"$r")
      for need in pull_request required_signatures non_fast_forward deletion; do
        grep -q "$need" <<<"$types" && ok "ruleset: $need" "" || fail "ruleset: $need" "missing (SSD-002, OSS-006)"
      done
      [ "$(jq -r '.rules[]|select(.type=="pull_request")|.parameters.require_code_owner_review' <<<"$r")" = true ] && ok "ruleset: CODEOWNER review" "" || fail "ruleset: CODEOWNER review" "not required (SSD-004, OSS-008)"
      [ "$bypass" = 0 ] && ok "ruleset: no bypass actors" "" || warn "ruleset: bypass actors" "$bypass actor(s) can bypass (OSS-024)"
    else fail "ruleset on default branch" "none active (SSD-002)"; fi
  else warn "github settings" "API call failed; token lacks access"; fi
else warn "github settings" "GH_TOKEN not set; skipped"; fi

# --- report -------------------------------------------------------------------------
{
  echo "## Release readiness: dnsid-$sdk"
  echo
  echo "$(( ${#rows[@]} - fails )) / ${#rows[@]} checks passing or advisory · **$fails failing**"
  echo
  echo "| | Check | Evidence / gap |"
  echo "|---|---|---|"
  printf '%s\n' "${rows[@]}"
  echo
  echo "_Mechanical checks only. Human-decision items (CRA category, CLA/DCO, owners, export record, pentest) live in the release review document._"
} > "$out"
cat "$out"
[ "$fails" -eq 0 ]
