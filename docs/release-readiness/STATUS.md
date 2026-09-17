# DNSid SDK Release Readiness — Status & Handoff

Working log for getting the DNSid SDKs through the two review checklists required for
public open-source release. Lives in the compliance repo so it travels with the checker.

## Goal

Answer every item on both checklists for `dnsid-go`, `dnsid-ts`, `dnsid-py`; automate the
mechanically-checkable rows so they stay answered; leave a short list of decisions for humans.

## Source documents

| Doc | Location | Content |
|---|---|---|
| DNSid Agent InfoSec Checklist (Identity Digital) | `~/Downloads/DNSid_Agent_InfoSec_Checklist.docx.pdf` | ~125 controls: COM, DAT, IDT, IAM, AGN, API, SSD, LOG, VIR (common); FRE (free agent); OSS (open source). Must/Should, P1/P2. |
| OSS Release Legal & Privacy Review Form (Known Services) | `~/Downloads/OSS Release Legal Review Form.docx.pdf` | 13 sections, ~95 items: publish approval, ownership, IP, crypto/export, runtime behavior, dev data, claims, warranties, security, EU CRA, sanctions, governance, sign-off. |

A per-row filled-in review (`SDK_Release_Review.md`) was produced in session 1 and then lost;
its findings are summarized below and can be regenerated from `ci/readiness.sh` output plus
the "Human decisions" list. Regenerate only if an auditor wants the row-by-row form.

## Scoping conclusion (important)

The three repos are **SDK libraries** — verify `_dnsid` DNS records, JWKS/JWT/RFC 9421
signatures, status endpoints; sign on an agent's behalf. No LLM, no autonomous actions,
no hosted service, no telemetry, no credentials shipped. Therefore:

- **N/A for the SDKs**: AGN-001–012, FRE-001–012, IAM-001–004/006–010, most LOG-*, API server-side
  controls. These belong to the hosted registry/status service review.
- **Strong by design**: forks cannot inherit trust (OSS-015/016/017) because identity = DNS control
  + agent private key + registry status, none of which the software contains.
- **Crypto is signature-only** (Ed25519, ECDSA P-256/384/521, RSA, secp256k1 indirect, ML-DSA
  indirect via `filippo.io/mldsa` in go). No AES/JWE/ECDH/HPKE → outside encryption export controls;
  legal to record the determination.

## Repos

All under `github.com/dnsid-ai`, cloned at `~/`. All **private** today.

| Repo | Role | Branch | PR | Status |
|---|---|---|---|---|
| `dnsid-sdk-compliance` | Conformance harness + **readiness checker** | `release-readiness` | #2 | pushed, awaiting merge — **merge first** |
| `dnsid-go` | Go SDK v0.33.1 (`github.com/dnsid-ai/dnsid-go`, `…/key/aws`) | `release-readiness` | #11 | pushed |
| `dnsid-ts` | TS SDK v0.19.1, 11 pkgs `@dnsid-ai/*` (GitHub Packages today) | `release-readiness` | #9 | pushed |
| `dnsid-py` | Python SDK v0.19.1, PyPI `dnsid` | `release-readiness` | #4 | pushed |
| `dnsid-cookbook` | Recipes | — | — | **not yet reviewed** |

Merge order matters: SDK callers reference `sdk-release-readiness.yaml@main` in this repo.

Ignore `release/next` PRs (release automation). `dnsid-ts` local branch `pr6` holds 4 unmerged
`allowedUnsafeHosts` commits — not ours, untouched. `dnsid-go` local `unpin-compliance-workflow`
is squash-merge residue, safe to delete.

## What the PRs contain

**dnsid-sdk-compliance #2**
- `ci/readiness.sh <go|ts|py> <sdk_dir> <out.md>` — 28 mechanical checks, each tagged with the
  checklist IDs it satisfies. ❌ fails the build, 🟡 advisory. Sections: required files; SECURITY.md
  byte-match; SBOM + provenance steps in `release.yml`; all actions SHA-pinned; dep vuln scan in CI;
  gitleaks full history; TLS-disable / telemetry / encryption-primitive greps on library source;
  network-destination allowlist; RFC 2606 fixture domains; GitHub settings + ruleset via API.
- `policy/SECURITY.md` — canonical; every SDK must match byte-for-byte.
- `.github/workflows/sdk-release-readiness.yaml` — reusable; full-history checkout, pinned gitleaks
  8.30.1, PR comment (upserted), artifact `readiness-<sdk>.md`.

**Each SDK** (`release-readiness`)
- `.github/workflows/readiness.yaml` — 5-line caller (PR + Monday cron + manual)
- `SECURITY.md` synced to canonical (ts/py had stale "0.12.x / 0.13.x" tables)
- `release.yml` — CycloneDX SBOM via `anchore/sbom-action@v0.24.2` (SHA-pinned), attached to the release
- CI vuln scan — ts `npm audit --omit=dev --audit-level=high`; py `pip-audit`; go already had `govulncheck`
- Tests — registrable placeholder domains → `.example` / `.test`. **Do not rename**
  `registry.dev.dnsid.test` in py: it is a real signed testnet checkpoint origin.

Expected readiness after merge: ❌ only for `CODE_OF_CONDUCT.md` (all 3) and signing/provenance
(go, ts — skipped by decision). GitHub security features show 🟡 while repos are private.

## Findings snapshot (pre-PR baseline → after PRs)

| Area | Before | After PRs |
|---|---|---|
| License / NOTICE / SECURITY.md / CONTRIBUTING / CODEOWNERS / dependabot.yml | present | present |
| Branch ruleset: PR + CODEOWNER review + signed commits + no force-push/delete, no bypass actors | ✅ | ✅ |
| Actions SHA-pinned | ✅ | ✅ |
| Gitleaks full history | clean | clean |
| Telemetry / analytics | none | none |
| TLS verification disabled anywhere | none | none |
| SBOM on release | ❌ | ✅ |
| Dep vuln scan in CI | go only | all 3 (0 vulns today) |
| SECURITY.md consistency | ts/py stale | byte-checked |
| Fixture domains | registrable placeholders | RFC 2606 |
| Signing / provenance | py only | py only (go/ts skipped) |
| CODE_OF_CONDUCT | ❌ | ❌ (legal question out) |
| GitHub: secret scanning, push protection, PVR | disabled | disabled — needs GHAS or public |
| Repo descriptions | blank | set |
| Dependabot security updates | disabled | enabled |

Runtime network behavior (for Legal §5 / COM-003): DNS TXT `_dnsid.<domain>`; HTTPS to the record's
JWKS + status URLs; **opt-in only**: `https://api.dnsid.ai` (registry client, ts/py), `https://log.dnsid.ai`
/ `log.dnsid.dev` (C2SP tlog, bundled public trust roots); KMS/GCP only if configured. Go core has no
`api.dnsid.ai` default. No hardcoded public resolver. py uses stdlib `logging` (thumbprints/states, never keys).

## Fix list

| # | Item | Status |
|---|---|---|
| 1 | Repo descriptions + homepage | ✅ "`<Lang> SDK — Cryptographically verifiable identity for agents, anchored in DNS.`", homepage `https://docs.dnsid.ai` |
| 2 | Dependabot alerts + security updates | ✅ all 3 |
| 3 | Secret scanning / push protection / private vuln reporting | ⏸ GHAS or public repo required; readiness flips 🟡→❌ automatically when public |
| 4 | Org 2FA requirement | ⏸ **enterprise team enabling**. All 16 members have 2FA. `members_can_create_public_repositories=false` ✅ done |
| 5 | Registry account ownership | 🟡 npm org `@dnsid-ai` exists, owner unverified (no npm login on this machine); PyPI `dnsid`, `dnsid-sdk`, `dnsid-ai`, `dnsid_ai`, `dnsidai` all unclaimed — **Ben setting up PyPI** |
| 6 | CODE_OF_CONDUCT.md | ⏸ **question sent to legal** (Contributor Covenant 2.1 unmodified; enforcement ladder as written?). Not answered directly, but the thread it triggered settled the contact: use **`report@dnsid.ai`** (misconduct-report alias, being created — see #18), not `idil-bugreport@identity.digital`. Enforcement-ladder question still open. Plan: `policy/CODE_OF_CONDUCT.md` byte-checked like SECURITY.md |
| 7 | SBOM in release.yml | ✅ in PRs |
| 8 | Signing / provenance for go + ts | ⏭ **skipped by decision**. ts blocked on npmjs-vs-GitHub-Packages cutover (`--provenance` needs npmjs) |
| 9 | Dep vuln scan in CI | ✅ in PRs |
| 10 | RFC 2606 fixture domains | ✅ in PRs; go/ts (815)/py (1285) suites green |
| 11 | README "Security & trust" section | ⏭ **next** — official channels + verify-a-release; "software ≠ identity"; runtime network / no telemetry; downstream privacy-notice line |
| 12 | — | (merged into 11) |
| 13 | Reserve PyPI confusable names | ⏸ Ben |
| 14 | `security.txt` on dnsid.ai / docs.dnsid.ai | ⏸ need the site repo location |
| 15 | CONTRIBUTING: "adding any encryption primitive → export re-review" | ⏭ next |
| 16 | `THREAT_MODEL.md` (shared, this repo) | ⏭ next — impersonation, DNS spoofing, key theft, malicious fork, dep confusion, compromised maintainer/CI |
| 17 | Data + network-destination inventory tables (this repo) | ⏭ next |
| 18 | Public contact aliases | ⏸ **IT setting up, needed by 9/22.** Legal position: public-facing contacts must not expose the `identity.digital` domain; split by product URL. Aliases: `security@dnsid.ai` (requested; `security@knownsystems.ai` exists), `report@dnsid.ai` + `report@knownsystems.ai` (misconduct/AUP reports), `legal@dnsid.ai` + `legal@knownsystems.ai`. All route to the ID legal alias plus the security group; 4 SDK maintainers named as owners. **Our follow-ups once live:** (a) `policy/SECURITY.md` contact → `security@dnsid.ai` (one edit, byte-check propagates to all 3 SDKs); (b) CoC contact → `report@dnsid.ai`; (c) same two addresses go in `security.txt` (#14) and the README section (#11); (d) `security@dnsid.ai` is the natural CRA reporting contact (decision #4) |

## Human decisions (nobody can grep these)

1. **Publishing entity** — names in use: "Identity Digital Inc." (NOTICE), "Identity Digital
   Innovation Labs" (SECURITY.md), "Known Services" (legal form), `knownsystems.ai` (email aliases);
   GitHub org `dnsid-ai`. Pick one, align. **New constraint from legal**: public-facing surfaces
   (contacts, and by extension probably README/SECURITY.md prose) should not present as "Identity
   Digital". Current SECURITY.md and NOTICE both do — needs an explicit answer on the copyright line.
2. **History** — old tags (through v0.24.0 in go) carry the former evaluation-agreement license.
   Keep history or publish clean snapshot. Local clones show 5–11 commits; confirm against origin.
3. **CLA / DCO / neither** (Apache §5 default).
4. **CRA category** — SDK drives adoption of `api.dnsid.ai`; form itself says that's a poor fit for
   "steward" → likely **manufacturer**. Reporting obligations live since 11 Sep 2026; needs a named
   ENISA reporting contact and a published security-update support period.
5. **Export classification record** — facts support decontrolled (signature-only, standard algorithms).
6. **Contributor IP** — Ben Guidarelli and Gabriel Kuettel both committed under personal emails;
   confirm employment/assignment. Repos contain `AGENTS.md`/`CLAUDE.md` → confirm AI-assisted-code policy.
7. **Named security owner + engineering owner** (COM-004). Team today: `@dnsid-ai/sdk-maintainers` =
   winder, jmelloy, barnjamin, wolfgangmeyers, JasonWeathersby, starlightromero, gabrielkuettel.
8. **Pentest** — required for a library, or does conformance harness + review suffice? (SSD-012)
9. **API ToS** for `api.dnsid.ai` / `log.dnsid.ai` (license doesn't cover hosted endpoints).
10. **Trademark guidance** for "DNSid" + brand approval.
11. **Docs license** for `docs.dnsid.ai` (CC-BY-4.0 customary); docs-site cookies/privacy notice.

## Working agreement (user ↔ agent)

- Agent **proposes** each item — what, where, why, side effects — user answers yes / no / modify.
- Agent does it, runs the affected test suite and `ci/readiness.sh`, commits locally on
  `release-readiness`. **User pushes** (agent pushes only on explicit request).
- One branch per repo; new work cherry-picked on top, never force-pushed.
- Anything needing org-admin scope, registry credentials, or a legal/business decision → agent
  drafts the ask, user carries it.
- Ponytail: smallest change that closes the checklist row; skip and say so rather than over-build.

## Next session, in order

1. Confirm PRs merged (compliance #2 first). Check the first readiness CI run: if the GitHub-settings
   section says "token lacks access", `github.token` can't read `security_and_analysis` on private
   repos — `secrets: inherit` already passes `GH_PAT`, which the workflow prefers when present.
2. **#11** README section — agent proposes text first.
3. **#15, #16, #17** → one PR to this repo (+ CONTRIBUTING line per SDK).
4. When aliases go live (**#18**, by 9/22): update `policy/SECURITY.md` contact, then CoC (**#6**) with
   `report@dnsid.ai` once the enforcement-ladder question is answered. Draft README/security.txt
   with the new addresses now; don't publish until the aliases resolve.
5. Then review `dnsid-sdk-compliance` itself and `dnsid-cookbook` (Legal §7 "what a conformance
   pass asserts" lives in the harness).

## Commands

```sh
# local readiness run (GH_TOKEN enables the settings section)
GH_TOKEN=$(gh auth token) ~/dnsid-sdk-compliance/ci/readiness.sh go ~/dnsid-go /tmp/r.md

# open PRs
for r in dnsid-go dnsid-ts dnsid-py dnsid-sdk-compliance; do gh pr list -R dnsid-ai/$r; done

# org / repo settings we touched
gh api orgs/dnsid-ai --jq '{two_factor_requirement_enabled,members_can_create_public_repositories}'
gh api repos/dnsid-ai/dnsid-go --jq '{description,homepage,sec:.security_and_analysis}'
```
