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

Row-by-row filled forms: **`REVIEW.md`**, generated from `gen_review.py` (edit the answer tables there,
rerun `python3 gen_review.py infosec_rows.txt > REVIEW.md`). 225 rows; every one has a status and a
pointer to `readiness.sh`, `INVENTORY.md`, `THREAT_MODEL.md`, or a `DECISIONS.md` id. This is the §13
sign-off attachment. Tally today: 64 ⏳ pending decisions, 56 ➖ N/A, rest answered/enforced/documented.

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
| `dnsid-sdk-compliance` | Conformance harness + **readiness checker** | `release-readiness` | #2 | workflow/policy only — **merge first** |
| `dnsid-sdk-compliance` | Tracking docs (this directory) | `release-readiness-docs` | — | split from #2 so the workflow can merge independently; open PR after push |
| `dnsid-go` | Go SDK v0.33.1 (`github.com/dnsid-ai/dnsid-go`, `…/key/aws`) | `release-readiness` | #11 | pushed |
| `dnsid-ts` | TS SDK v0.19.1, 11 pkgs `@dnsid-ai/*` (GitHub Packages today) | `release-readiness` | #9 | pushed |
| `dnsid-py` | Python SDK v0.19.1, PyPI `dnsid` | `release-readiness` | #4 | pushed |
| `dnsid-cookbook` | Recipes (prose + sample code) | `release-readiness` | — | `d82288b` local, **not pushed**. See "dnsid-cookbook review" |
| `Identity-Digital/c2sp-ledger-witness` (`~/c2sp-ledger-witness`) | **Service**: C2SP tlog witness partners operate | `release-readiness` | — | committed locally, **not pushed** — see section below |
| `Identity-Digital/dnsid` (`~/dnsid`) | Platform monorepo: server, console, deploy, **CLI (`cmd/cli`)** | — | — | **out of scope** for the SDK review — hosted-service repo, separate org. See decision #13 |

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

Expected readiness after merge: ❌ only for signing/provenance (go, ts — skipped by decision).
`readiness.sh` now also byte-checks `CODE_OF_CONDUCT.md` and runs a **dependency-license allowlist**
(go-licenses / `npm ls`+jq / pip-licenses; Apache/MIT/BSD/ISC/MPL pass, anything else ❌) — Legal §1 row 9,
OSS-002. All 3 SDKs pass today. GitHub security features show 🟡 while repos are private.

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
| CODE_OF_CONDUCT | ❌ | ✅ Contributor Covenant 2.1, byte-checked (fix #6) |
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
| 4 | Org 2FA requirement | ✅ `two_factor_requirement_enabled=true` (verified in sanity pass). 18 members, 0 without 2FA. `members_can_create_public_repositories=false` ✅ |
| 5 | Registry account ownership | 🟡 **npm verified 9/21**, second owner added 9/21 ✅.: org `@dnsid-ai` owner = Ben Guidarelli, user `dnsid-barnjamin`, company email, 2FA on. ⚠️ single owner → add a second org owner (Jason, #7) for continuity (Legal §12 row 3). **PyPI**: org-name approval pending; will be same email + 2FA. `dnsid` + confusables (`dnsid-sdk`, `dnsid-ai`≡`dnsid_ai`, `dnsidai`) need a stub upload each — PyPI has no reservation |
| 6 | CODE_OF_CONDUCT.md | ✅ **Legal answered** (contact `report@dnsid.ai` re-confirmed L12): Contributor Covenant 2.1 as written, ladder as written, contact `report@dnsid.ai` (legal may later prefer a dedicated conduct alias — one edit in `policy/`). `policy/CODE_OF_CONDUCT.md` byte-checked in `readiness.sh`; copied to go `9bbecc0`, ts `070bea8`, py `9b6cbad`, this repo `00b058b`. Alias itself not live until #18 |
| 7 | SBOM in release.yml | ✅ in PRs |
| 8 | Signing / provenance for go + ts | ⏭ **skipped by decision**. ts blocked on npmjs-vs-GitHub-Packages cutover (`--provenance` needs npmjs) |
| 9 | Dep vuln scan in CI | ✅ in PRs |
| 10 | RFC 2606 fixture domains | ✅ in PRs; go/ts (815)/py (1285) suites green |
| 11 | README "Security & trust" section | ✅ committed on all 3 `release-readiness` branches (go `141ed87`, ts `5699e6a`, py `e291c95`), **not pushed**. Identical section before `## License`; per-SDK fills for package registry, opt-in endpoints, logging. Finding: none of the 3 SDKs emit logs (py declares a `dnsid` logger, never calls it). Says "DNSid-operated" not "Identity Digital" pending decision #1. Contact deferred to SECURITY.md so the #18 alias swap is one edit |
| 12 | — | (merged into 11) |
| 13 | Reserve PyPI confusable names | ⏸ Ben |
| 14 | `security.txt` on dnsid.ai / docs.dnsid.ai | ⏸ need the site repo location |
| 15 | CONTRIBUTING: "adding any encryption primitive → export re-review" | ⏭ **deferred by decision** — not in source docs; `readiness.sh` primitive grep already trips on it |
| 16 | `THREAT_MODEL.md` (shared, this repo) | ✅ `docs/release-readiness/THREAT_MODEL.md` — trust boundaries (COM-001), can/cannot (COM-002), 9 protocol + 3 key-handling + 7 supply-chain threats with cited mitigations and residuals (COM-005, OSS-023, VIR-007), false-pass row (Legal §9), fork-cannot-inherit-trust argument (OSS-015/016/017). Surfaced: single-approver merges on trust-path files → added to decision #7 |
| 17 | Data + network-destination inventory | ✅ `docs/release-readiness/INVENTORY.md` — network table (8 destinations, default vs opt-in; sanity pass removed a wrongly-listed witness row — witnesses are never contacted), data table, `~/.dnsid` file properties, in-memory caches. Surfaced **decision #12** (plaintext local keys) |
| 19 | SAST in SDK CI (SSD-005) | ⚠️ **CodeQL cannot run while repos are private**: `Analyze` fails with "Code Security must be enabled for this repository" (no GHAS on `dnsid-ai`, same root as fix #3). Red on go/ts/py PRs until public or GHAS. Options: accept red until publish, or gate the job `if: !github.event.repository.private` (readiness only checks the step exists — a skipped scan still "passes"). Earlier: ✅ **sanity-pass finding**: was recorded as done but only the compliance repo had CodeQL; SDK CI had golangci (no gosec) / ruff (no `S`) / nothing (ts). Added pinned `codeql.yml` to go `5034562`, ts `5f6edc3`, py `30135a9`; `readiness.sh` now fails without a SAST step |
| 18 | Public contact aliases | ✅ **`security@dnsid.ai` live 9/21**; (a) done — canonical + this repo's SECURITY.md → `security@dnsid.ai`, propagated to go `9071dac`, ts `b32ef6a`, py `89a86e3`, cookbook `302b9ed`, witness `97c963d` (same commit also carried the L8 sections, which had **not** reached go/ts/py despite the L8 note). (b) already `report@dnsid.ai`. (c)/(d) still open. Original ask: Legal position: public-facing contacts must not expose the `identity.digital` domain; split by product URL. Aliases: `security@dnsid.ai` (requested; `security@knownsystems.ai` exists), `report@dnsid.ai` + `report@knownsystems.ai` (misconduct/AUP reports), `legal@dnsid.ai` + `legal@knownsystems.ai`. All route to the ID legal alias plus the security group; 4 SDK maintainers named as owners. **Our follow-ups once live:** (a) `policy/SECURITY.md` contact → `security@dnsid.ai` (one edit, byte-check propagates to all 3 SDKs); (b) CoC contact → `report@dnsid.ai`; (c) same two addresses go in `security.txt` (#14) and the README section (#11); (d) `security@dnsid.ai` is the natural CRA reporting contact (decision #4) |

## Human decisions (nobody can grep these)

> Presentation copy for decision-makers: **`DECISIONS.md`** (grouped by owner, proposed defaults, blocks; no
> names). Cross-walk STATUS# → DECISIONS: 1→L1, 2→M2, 3→L5, 4→L7, 5→L6, 6→L2, 7→M4+M9, 8→M5, 9→L10, 10→L11,
> 11→L14, 12→M6, 13→M3, 14→M7, 15→E6, 16→L8, 17→L13, 18→L3, 19→L4, 20→L9, 21→L6, 22→M8, 23→L15, 24→E6;
> fix-list 3/4→E4, 5/13→E2, 8→E5, 14→E7, 18→E1, CoC alias→L12. Update both when an answer lands.

1. ✅ **Publishing entity** — "Known Systems AI, Inc." **confirmed 9/21**. Wording follow-up done: "Identity Digital-managed" → "DNSid-managed" in go `0f0cb5a`, ts `e19eb0f`, py `223b288`, compliance `docs/sdk-design` (anchors updated). **Pass applied** on
   `release-readiness` everywhere: canonical SECURITY.md lines 3/37 → propagated to go `f111017`, ts `746d6ce`,
   py `dea89f8` (+ NOTICE, py `pyproject.toml` authors), compliance `b8163a1`, witness `2cbbb23` (+ `$DNSID_TEAM` →
   "Known Systems"). If the name changes Friday: one sed over the same files. **Not touched**: ~25 occurrences of
   "Identity Digital-managed DNSid logs" in code comments / API docs / design docs describing the `log.dnsid.ai`
   operator — wording decision, see DECISIONS L1 follow-up. — names in use: "Identity Digital Inc." (NOTICE), "Identity Digital
   Innovation Labs" (SECURITY.md), "Known Services" (legal form), `knownsystems.ai` (email aliases);
   GitHub org `dnsid-ai`. Pick one, align. **New constraint from legal**: public-facing surfaces
   (contacts, and by extension probably README/SECURITY.md prose) should not present as "Identity
   Digital". **Legal: yes, extends to prose — repos must present as "Known".** Exact entity name
   pending confirmation, expected **"Known Systems AI, Inc."** Once confirmed: NOTICE copyright line,
   `policy/SECURITY.md` lines 3/37, witness `$DNSID_TEAM` placeholders, W3 NOTICE — one pass.
2. ✅ **History** — **decided 9/21: SDKs + cookbook keep history; witness squashes to a fresh root before publish.** Verified against origin: go/ts/py/cookbook each have a single root dated 2026-09-15 and every tag is Apache-2.0 — they are already clean snapshots (the evaluation-license history is in the private predecessor, not published). Personal author emails covered by L2. Witness: `build-image.yml` infra IDs in 3 commits of `release-readiness` → squash (W1); no consumers, no cost.
3. ✅ **CLA / DCO / neither** — **neither**; CONTRIBUTING.md "Licensing of contributions" section in every repo (L5). (Apache §5 default).
4. ⏳ **CRA** — legal round 2: applies, deferred by decision, discuss later. E3 still recommended. — SDK drives adoption of `api.dnsid.ai`; form itself says that's a poor fit for
   "steward" → likely **manufacturer**. Reporting obligations live since 11 Sep 2026; needs a named
   ENISA reporting contact and a published security-update support period.
5. ⏳ **Export classification record** — legal: pending work, not a blocker. — facts support decontrolled (signature-only, standard algorithms).
6. ✅ **Contributor IP** — employment covers all; AI-assisted code confirmed covered (L2 round 2). — Ben Guidarelli and Gabriel Kuettel both committed under personal emails;
   confirm employment/assignment. Repos contain `AGENTS.md`/`CLAUDE.md` → confirm AI-assisted-code policy.
7. ✅ **Named 9/21: Jason Weathersby (`@JasonWeathersby`) is both security owner and engineering owner**, and on point post-release. Inbound path `security@dnsid.ai`; he is therefore also the CRA/ENISA reporting contact (E3). Unblocks M10. **Named security owner + engineering owner** (COM-004). Team today: `@dnsid-ai/sdk-maintainers` =
   winder, jmelloy, barnjamin, wolfgangmeyers, JasonWeathersby, starlightromero, gabrielkuettel.
   Also: ruleset requires **1** approving review today. Threat model C5 suggests 2 for trust-path files
   (crypto, DNS, verification, release workflows) — accept 1, or raise?
8. **Pentest** — required for a library, or does conformance harness + review suffice? (SSD-012)
9. ✅ **API ToS** — drafted and sent by legal; link from READMEs when published. for `api.dnsid.ai` / `log.dnsid.ai` (license doesn't cover hosted endpoints).
10. ✅ **Trademark guidance** — legal: N/A (no mark claimed). for "DNSid" + brand approval.
11. ✅ **Docs license** — CC-BY-4.0 confirmed; site owner to apply. for `docs.dnsid.ai` (CC-BY-4.0 customary); docs-site cookies/privacy notice.
12. ✅ **accepted 9/21, option (a)** — **Local private keys unencrypted at rest** (DAT-006 Must/P1, IDT-005). `~/.dnsid/<domain>/keys.json`
    is plaintext JWK, `0600`, no passphrase option, all 3 SDKs + CLI. Options: (a) accept and document
    "local provider = dev/single-host; KMS for production" — same as ssh/aws/gcloud; (b) add optional
    passphrase encryption (new crypto primitive → re-opens export review #5). Proposed: (a).
13. ✅ **9/21: CLI is a public download at launch; binary signing/provenance deferred to post-release** (OSS-010/011/012 accepted deviation). **Consequence — new open item #27**: the CLI binaries + install path need their own Legal §4 row 4 / §5 row 6 assessment; the CLI repo (`Identity-Digital/dnsid`) is outside this review. goreleaser emits `checksums.txt` by default (OSS-011) — confirm. **CLI release status.** The CLI lives in the private platform monorepo and ships as goreleaser
    binaries. If those are a public download at launch, OSS-010/011/012 (signing, hashes, provenance),
    Legal §4 (binaries assessed separately) and §5 (installer script) apply to it even with source private.
    It also writes the `~/.dnsid` files the SDKs read, so decision #12 must hold for both. `dnsid-ts/README.md`
    references the CLI. Question for mgmt: public download, or internal-only at launch?
14. **Publish `dnsid-sdk-compliance`?** See "This repo's own review". Needed only if conformance claims
    are made publicly and should be independently reproducible.
15. ✅ **DeepSource** — leftover: app not installed on `dnsid-ai` (0 installations, no webhooks). `.deepsource.toml` removed from compliance `ee6eea7`, go `c495f7d`, ts `5f686c8`, py `e4d6418`, cookbook `58adbfb`. Legal §12 row 3.
16. ✅ **Security-process numbers** — legal: deferred with CRA; **deliberately no commitments**. SECURITY.md finalized with process + explicit no-timeline statement (L8). Draft file removed. — needed to finish `SECURITY-fixes-section.draft.md` (then it goes into
    canonical SECURITY.md and propagates). Legal §8 row 5, §9 rows 2–4, §12 row 4; VIR-003/004/009, OSS-019/021, SSD-009.
    - **16a** fix-time targets by severity (proposed Critical 7d / High 30d / Medium 90d)
    - **16b** security-update support period (CRA: ≥5 years or a stated shorter lifetime; proposed 5y from 1.0 or 2y from last release)
    - **16c** pre-1.0 support stance (proposed: latest minor only)
    - **16d** end-of-life notice period (proposed 6 months)
    - **16e** is there, or will there be, paid support? (changes the support sentence and confirms CRA manufacturer in #4)
    - Also record as deliberate: existing "acknowledge in 3 business days / assess in 14 days" commitment (Legal §9 row 2).
17. ✅ **IETF participation obligations** — confirmed. (Legal §3 rows 3, 6). The protocol is `draft-ihsanullah-dnsid`. IETF BCP 79
    puts IPR-disclosure duties on participants personally; the Note Well covers competition-law conduct. Confirm the
    draft authors/contributors have done the IPR disclosure (or that there is nothing to disclose) and know the rules.
18. ✅ **Trade secret / patent position** — we hold a patent, no trade secrets (L3). ⚠️ Apache §3 outward patent grant — confirm understood. (Legal §1 row 5, §3 row 5). Is anything in the SDKs relied on as confidential
    know-how? Any filed or intended patent that reads on the published implementation? Publication creates prior art.
19. ✅ **Funding and restrictive agreements** — none. (Legal §2 rows 3, 5). Was any of this customer- or grant-funded? Does
    any customer/partner/exclusivity agreement restrict publication? Adjacent to #2 (the old evaluation-agreement license).
20. ✅ **Sanctions position** — service geo-blocked; repo + contributions rely on GitHub/npm/PyPI platform enforcement (L9). (Legal §11, all four rows). Legal to record: (a) publication of OSS vs. provision of the
    hosted service are different acts; (b) gated components = `api.dnsid.ai` accounts, handled under service terms;
    (c) GitHub/npm/PyPI/Go proxy enforce their own sanctions posture; (d) contributions from restricted jurisdictions —
    accept / refuse / case-by-case.
21. **Destination-market crypto import restrictions** (Legal §4 row 6). One line from legal: any market where we
    distribute or operate that restricts import/use of signature cryptography?
22. ⏸ **deferred 9/21, not blocking** — **Governance statement** (Legal §12 row 1). Mechanism exists (CODEOWNERS + ruleset = who merges). Missing: who may
    speak for the project publicly, and a sentence that issue-thread statements by maintainers are not company
    commitments. Half a page in CONTRIBUTING or a `GOVERNANCE.md`; needs the owner from #7.
23. ✅ **Open source policy** — confirmed. (Legal §1 row 16). Does the company have one? If not, the form says this review *is* the
    policy for this release — record that.
25. **Warranty adequacy** for a security library (Legal §8 row 1) → DECISIONS L16.
26. ✅ **Post-publication legal/privacy problem plan** (Legal §13 row 6) — section added to canonical `policy/SECURITY.md` + this repo's variant; go `01f2654`, ts `cbd56e2`, py `3e924e9`, cookbook `0bc74b0`, witness `5103b52`. Legal decides, security owner (#7) executes; inbound `security@dnsid.ai`.
27. ⏳ **CLI binary assessment** (from #13). Public goreleaser download at launch, unsigned. Needs: checksums published (OSS-011), install instructions reviewed (Legal §5 row 6), export note (same signature-only determination, confirm no extra crypto in CLI), README download link in SDKs. Owner: #7.
24. **Third-party service accounts** (Legal §12 row 3). GitHub org `dnsid-ai`, npm `@dnsid-ai`, PyPI, DeepSource (#15),
    any CI/SaaS — who accepted the terms, is each held by a company account, and what happens when that person leaves.

## Readiness checker defects found in CI (fixed on `release-readiness-docs`)

- **`rg` not on `ubuntu-latest`** → 4 checks false-failed (SBOM, vuln scan, SAST, release) and, worse, 5
  grep-based checks **false-passed** (SHA-pinned, TLS, telemetry, crypto primitives, network destinations) because
  "no output" reads as clean. Fixed: script exits 2 if `rg` is missing (fail closed); reusable workflow installs
  ripgrep. First real CI run only happened after the PRs went up — local runs always had `rg`. Legal §9 false-pass row.
- SECURITY.md byte-check on the SDK PRs stays ❌ until this branch (canonical contact) merges to `main`.

## Recorded as satisfied (no action, just so the form has an answer)

| Row | Answer |
|---|---|
| Legal §1 row 7 — patent grant | Apache-2.0 §3: express patent grant, with defensive termination. Intended. |
| Legal §3 row 2 — no trademark rights in license | Apache-2.0 §6 withholds trademark rights. Usage guidance still needed (#10). |
| Legal §4 row 3 — export notification | N/A: standard published algorithms only, no notification owed (post-2021 rule). |
| Legal §4 row 4 — binaries assessed separately | SDKs ship no binaries or images. CLI (#13, **public download — assessment owed, #27**) and witness image are separate assessments. |
| Legal §5 row 6 — installer scripts | None. Install is `go get` / `npm install` / `pip install`. |
| Legal §2 row 6 — non-code assets | SDK repos contain no fonts, logos, images, or datasets. Test keys are disposable, generated. Docs site is #11. |
| Legal §6 row 3 — personal data via public repos | Standard GitHub: commit metadata, issue authors. Permanent and public; deletion requests route to GitHub's process. |
| Legal §7 row 6 — naming consistency | Packages `dnsid-go`, `@dnsid-ai/*`, `dnsid`; ts renamed `core→protocol` before publish. Standard name "DNSid" reserved for the protocol. |
| InfoSec COM-007 — acceptance criteria | `ci/readiness.sh` is the release acceptance gate; ❌ blocks. |
| InfoSec OSS-022 — reproducible builds | Go module builds are reproducible by default (`-trimpath`, module proxy). ts/py: not evaluated; Should/P2. |
| InfoSec IDT-009 — fail-secure | Unknown version, expired evidence, revoked/suspended status, unverifiable signature all reject. Harness `REJ` cases exercise version dispatch fail-closed. |
| InfoSec IDT-012 — replay | JWT `exp`/`iat`/`jti`, RFC 9421 `created`/`expires`/`nonce`; documented in per-SDK ops docs. |
| InfoSec DAT-005 — retention | Nothing retained beyond process lifetime except integrator-created `~/.dnsid` (INVENTORY.md). |

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
3. ~~#16 threat model~~ done; **#17** done, **#15** dropped.
4. When aliases go live (**#18**, by 9/22): update `policy/SECURITY.md` contact. When entity name is
   confirmed (**#1**): NOTICE + SECURITY.md prose pass across all repos. CoC done (#6).
5. ~~Review `dnsid-sdk-compliance` itself~~ done. ~~`dnsid-cookbook`~~ done (see below).

## c2sp-ledger-witness review

A deployable service, not a library: API-*/DAT-*/LOG-* rows apply to it as shipped; the operator is a
partner. `PARTNER_HOSTING_REQUIREMENTS.md` already covers COM-001/002/003, DAT-001, IDT-005, VIR-005.

**Passing**: gitleaks clean; **secret scanning + push protection enabled** (the `Identity-Digital` org
has GHAS — `dnsid-ai` does not, relevant to fix #3); Dependabot gomod/docker/actions + security updates;
signature-only crypto (Ed25519, ML-DSA-44) — same export determination; **no outbound network calls, no
telemetry** (OTel is an unused indirect dep of Tessera); RFC 2606 hosts only; keygen `O_EXCL` `0600`.

**Fixed on `release-readiness` (`caf588f`)**: `LICENSE.txt` (Apache-2.0, same file as SDKs); `SECURITY.md`
(canonical copy); `CONTRIBUTING.md`; `ci.yml` — build/vet/race/tidy/`govulncheck`, pinned; `build-image.yml`
actions SHA-pinned. Via API: description replaced ("welcome to the TLOG party").

**Blocked on decisions**

| # | Item | Needs |
|---|---|---|
| W1 | **Decision 9/21: squash `release-readiness` to a fresh root before publish** (decision #2). Still owed: scrub the workflow itself — see brief. `build-image.yml` publishes infra detail: AWS account ID, IAM role ARN, ECR repo, region; runs `on: push` for every branch with OIDC. Legal §1 row 2 names this exactly. Already in all 11 commits of history | **Handed off** — see `witness-image-pipeline-brief.md`. Decision #2 (history vs clean snapshot) for this repo |
| W2 | **Org + Go module path** `github.com/Identity-Digital/c2sp-ledger-witness`. Import path is effectively permanent once public; SDKs live in `dnsid-ai` | Decision #1 **before** publish |
| W3 | No `NOTICE` — deps Tessera/transparency-dev (Apache-2.0), klog (Apache-2.0), yaml.v3 (MIT+Apache), `filippo.io/mldsa` | Copyright entity (#1); then a NOTICE like the SDKs' |
| W4 | No CODEOWNERS; branch protection is classic: 1 review, no code-owner review, no signed commits, **admins bypass** (SSD-002, OSS-006/008) | Which team owns it? Then convert to a ruleset matching the SDKs |
| W5 | No public distribution: image → private ECR only, no tags/releases. Partner doc says `docker run` — from where? (OSS-003/010/011/012, OSS-021, VIR-009) | Public image (GHCR) or build-from-source; cosign + SBOM + provenance; version/support statement |
| W6 | Provenance: authors under `cadena.ai` and gmail addresses, **2 commits by `copilot-swe-agent[bot]`** (Legal §2 rows 1, 4) | Extend decision #6 to this repo |
| W7 | `$DNSID_TEAM` placeholders in partner doc; "C2SP" (third-party spec body) in the repo name (Legal §3 row 1) | #1; one-line trademark note |
| W8 | CODE_OF_CONDUCT | #6 |

## dnsid-cookbook review

**Was**: `LICENSE.txt` = the old proprietary *DNSid Evaluation Agreement* (Identity Digital Inc.) — publishing
as-is would have been a non-open release. SECURITY.md stale (0.11.x, identity.digital contact). No NOTICE /
CONTRIBUTING / CoC / CODEOWNERS. Blank description. Ruleset already good (PR + code-owner + signatures, 0 bypass).
Gitleaks clean (5 commits, two author emails — both the same person). Fixture domains fine: all `*.dev.dnsid.test`.

**Now** (`d82288b` on `release-readiness`): **dual license by decision** — `LICENSE.txt` Apache-2.0 for sample
code, `LICENSE-docs.txt` CC BY 4.0 for Markdown; README §License states the split (code blocks in Markdown =
Apache). Canonical SECURITY.md + CODE_OF_CONDUCT.md, NOTICE (Known Systems; nothing redistributed),
CONTRIBUTING (recipe lifecycle, CI matrix rule, licensing-of-contributions), CODEOWNERS `@dnsid-ai/sdk-maintainers`,
pinned CodeQL (3 languages), readiness caller (`sdk: cookbook`), README "Security & trust" pointer.
Deleted `licenses/README.md` (tracked copying of the old evaluation license — obsolete). Via API: description,
homepage, Dependabot alerts + security updates.

**Finding**: recipe 28 depends on `aws-opentelemetry-distro` (AgentCore observability → user's own CloudWatch)
and didn't say so. Disclosure note added to the recipe README (Legal §5 row 4). `readiness.sh` reports telemetry
hits as 🟡 for the cookbook target (recipe-level instrumentation, must be disclosed) instead of ❌.

**Done**: `plans/` deleted `5530cc9` (M11). `CLAUDE.md` kept (contributor instructions).
`FIXUPS.md` deleted by decision. CODEOWNERS team assumed same as SDKs — confirm.
`.deepsource.toml` removed (#15). Readiness: exit 0, advisories only (vendor hosts in recipes).

## This repo's own review (dnsid-sdk-compliance)

Fixed on `release-readiness`: CODEOWNERS pointed at `@Identity-Digital/…` (wrong org — code-owner
review gate had no owner to require); `codeql.yml` actions SHA-pinned; fixtures `other.com`/`ample.com`
→ `.example` (harness 193/193 all SDKs); README "What a compliant result means" — the Legal §7 row 1
representation, plus a note that the SDK PR gate is regression-only so green ≠ conformant. Via API:
description/homepage set, Dependabot alerts + security updates enabled.

Passing by design: shim crash or result-count mismatch aborts the run (never a false PASS); `REJ`,
`XFAIL`, `XPASS` distinct; divergence appendix (Legal §7 rows 2–3). Ruleset has no bypass actors.
Reusable workflows are `on: pull_request`, so fork PRs never receive `GH_PAT`. N/A: SBOM, signing,
registry — no released artifact (NOTICE records this).

Open — decision **#14 publish this repo?** Reusable workflows work from a private repo (org access
setting). If public: `docs/release-readiness/` (internal tracker, agent notes) must move out first
(`WORKING_UPDATES.md` already removed in #5). ~~Decision #15~~ done. Advisory: harness deps installed unpinned by `make`.

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
