#!/usr/bin/env python3
"""Render REVIEW.md (row-by-row answers to both checklists) from the answer tables below.

Usage: python3 gen_review.py /tmp/infosec_rows.txt > REVIEW.md
infosec_rows.txt: one control per line, "ID|Req Pri| text" (extracted from the InfoSec PDF).
Edit the ANSWERS dicts, re-run. Keeps the form honest: every row has a status and a pointer.
"""
import sys

# status glyphs: ✅ done · 🔧 mechanical (readiness.sh) · 📄 documented · ⏳ pending decision · ➖ N/A
R = "`ci/readiness.sh`"
INV = "`INVENTORY.md`"
TM = "`THREAT_MODEL.md`"
D = "`DECISIONS.md`"
NA_SVC = ("➖", "N/A for SDK libraries — hosted-service control. Belongs to the registry/console review. See `STATUS.md` scoping.")
NA_AGN = ("➖", "N/A — no LLM, no autonomous action, no tool execution in the SDKs (`THREAT_MODEL.md` §can/cannot).")
NA_FRE = ("➖", "N/A — free-tier controls belong to the hosted service.")

INFOSEC = {
 "COM-001": ("📄", f"{TM} §trust boundaries: zones, what each is trusted for, no privileged components."),
 "COM-002": ("📄", f"{TM} §can/cannot; README 'Security & trust' in each SDK."),
 "COM-003": ("📄", f"{INV} network table (8 destinations, default vs opt-in). Enforced: {R} 'network destinations' allowlist."),
 "COM-004": ("✅", "Security + engineering owner named 9/21 (`STATUS.md` #7); inbound `security@dnsid.ai`."),
 "COM-005": ("📄", f"{TM} §A (impersonation, DNS, key theft, replay, DoS) — 'API abuse' and 'malicious tool use' N/A for a library."),
 "COM-006": ("⏳", "Should/P2. Not mapped. Controls in place cover SSDF PO/PS/PW/RV in substance; formal mapping deferred post-launch."),
 "COM-007": ("🔧", f"{R} is the acceptance gate: ❌ blocks; runs on every PR and weekly."),
 "DAT-001": ("📄", f"{INV} data table + README: no PII/PHI/PCI, no telemetry. Only domain names and public keys handled."),
 "DAT-002": ("📄", f"{INV} data table: collected / transmitted / stored / logged per class."),
 "DAT-003": ("📄", f"{INV}: nothing collected beyond what verification requires; no telemetry ({R} grep)."),
 "DAT-004": ("📄", f"SDKs emit no logs; errors carry thumbprints/domains only ({INV} §logging, {TM} B2)."),
 "DAT-005": ("📄", f"{INV} §caches: nothing retained beyond process lifetime except integrator-created `~/.dnsid`."),
 "DAT-006": ("⏳", f"Local private keys plaintext at rest, `0600`. {D} M6 (proposed: accept + document; KMS for production). {TM} B1."),
 "DAT-007": ("🔧", f"{R} 'TLS verification never disabled'; HTTPS-only fetches, redirects HTTPS-only (ops docs)."),
 "DAT-008": ("➖", "No telemetry exists to disable."),
 "DAT-009": ("📄", f"{INV}: no IP/device/user identifiers handled; IPs visible only to remote hosts as for any client."),
 "DAT-010": ("🔧", f"{R} 'fixture domains RFC 2606'; test keys disposable and generated."),
 "IDT-001": ("📄", "Protocol: identity = domain + operational key + entity key; each agent has its own `_dnsid` record and JWKS."),
 "IDT-002": ("📄", f"Record signed by `ek`, JWKS host-pinned to the record's domain ({TM} A1)."),
 "IDT-003": ("➖", "Enrolment is registry/CLI-side. SDK generates keys and TXT records on request only."),
 "IDT-004": ("➖", "Domain-control verification is registry-side (hosted-service review)."),
 "IDT-005": ("⏳", f"KMS providers keep keys in HSM; local provider `0600`/`O_EXCL`/atomic but plaintext → {D} M6."),
 "IDT-006": ("🔧", f"{R} gitleaks full history (clean, all repos); {INV}: no credentials shipped."),
 "IDT-007": ("📄", "Rotation supported: JWKS overlap, `ka=` max key age, JOSE evict-and-retry (ops docs §rotation)."),
 "IDT-008": ("📄", "Status endpoint (`su`) rechecked per `StatusCheckInterval`; 0 = every call. Revocation observed on next check."),
 "IDT-009": ("📄", f"Fail-closed: unknown version, expired evidence, revoked/suspended, unverifiable signature all reject. Harness `REJ` cases. ({TM} A8)"),
 "IDT-010": ("📄", f"`sg` signature over canonical record; DNSSEC modes `auto`/`validated`/`required`; no TTL restart ({TM} A2)."),
 "IDT-011": ("📄", "Evaluated: built-in resolvers can't see AD bit → `UNKNOWN`; validating resolver injectable. Documented in ops docs."),
 "IDT-012": ("📄", f"JWT `exp`/`iat`/`nbf`, 5-min default assertion; RFC 9421 `created`/`expires`/`nonce`; `fl=mtls` peer binding ({TM} A4)."),
 "IDT-013": ("📄", "Record `gi` (governance) + `ek` signature + `ku` agent key; `TrustedEntities` exact-match allowlist with `ek` thumbprint pin."),
 "IDT-014": ("➖", "Should/P2. SDK emits no logs by design; lifecycle events are recorded in the transparency log by the registry."),
 "IAM-005": ("✅", "Org-level 2FA required (`two_factor_requirement_enabled=true`), 18/18 members."),
 "API-001": ("🔧", f"Client side: HTTPS-only, default cert validation never relaxed ({R}). Server side: hosted-service review."),
 "API-003": ("📄", f"Input caps and strict parsing before verification ({TM} A7; ops docs §resource bounds)."),
 "API-005": ("📄", f"SSRF guard: non-public IPs rejected, redirects denied/host-pinned, HTTPS-only ({TM} A6)."),
 "API-007": ("📄", "30 s invocation budget, 10 s dial, response caps 1 MiB/64 KiB, no retry storms (ops docs §transport)."),
 "API-008": ("📄", "Errors expose thumbprints and domains only; denial messages never echo allowlist/pins."),
 "API-009": ("📄", "RFC 9421 HTTP message signatures and JWT signing are the SDK's purpose."),
 "SSD-001": ("⏳", "Practices in place (review, CI gates, scanning, threat model); formal SDL document deferred with COM-006."),
 "SSD-002": ("🔧", f"{R} GitHub ruleset check: PR + code-owner review + signed commits + no force-push/delete, no bypass."),
 "SSD-003": ("✅", "Org-level 2FA required; verified via API."),
 "SSD-004": ("🔧", f"CODEOWNERS on `*` + ruleset `require_code_owner_review`. Second reviewer for trust-path files → {D} M9."),
 "SSD-005": ("🔧", f"CodeQL workflow (SHA-pinned) in every repo — added to SDKs in sanity pass; {R} 'CI: SAST' fails without it."),
 "SSD-006": ("🔧", f"{R} 'CI: dependency vuln scan' — govulncheck / npm audit / pip-audit. 0 findings today."),
 "SSD-007": ("🔧", f"gitleaks full history in {R}; GitHub secret scanning + push protection flip on when repos go public (fix #3)."),
 "SSD-008": ("➖", "No containers/installers for SDKs. Release packages covered by dep scan + SBOM. Witness image: separate review."),
 "SSD-009": ("📄", "SECURITY.md: false-pass = highest priority; no fixed deadlines by recorded decision (L8/L7)."),
 "SSD-010": ("📄", "GitHub Security Advisories + Dependabot alerts track findings to fixed version."),
 "SSD-011": ("➖", "Should/P2. No exposed service in the SDKs."),
 "SSD-012": ("⏳", f"{D} M5 — pentest vs. harness + review."),
 "SSD-013": ("➖", "Should/P2. No agent behaviour to red-team; verification path covered by conformance harness."),
 "SSD-014": ("🔧", f"{R} 'actions SHA-pinned'; fork PRs get no secrets (`on: pull_request`); release via automation PRs ({TM} C6)."),
 "LOG-006": ("📄", "SDK emits no logs; nothing to redact. Documented so integrators know their logs contain nothing from us."),
 "VIR-001": ("🔧", f"SECURITY.md byte-checked against canonical ({R}). GitHub Security Advisories + email."),
 "VIR-002": ("⏳", f"`security.txt` → {D} E7 (needs site repo; aliases live)."),
 "VIR-003": ("📄", "SECURITY.md §How Fixes Are Released + §Remediation Timelines: severity via CVSS, escalation = false-pass rule; remediation targets deliberately not committed (L8)."),
 "VIR-004": ("📄", "SECURITY.md §How Fixes Are Released: new version + advisory, patch on latest minor."),
 "VIR-005": ("📄", f"Compromised keys: rotation + status revocation + `ka=` (ops docs). Signing keys: none held by SDK repos ({TM} C6). Procedures for hosted side: service review."),
 "VIR-006": ("➖", "Operational suspend/revoke is registry-side; SDK observes status on next check."),
 "VIR-007": ("📄", f"{TM} §C and §D cover fork abuse, impersonation, trust-assertion compromise as scenarios."),
 "VIR-008": ("📄", "SECURITY.md: CVE via GitHub for Medium+."),
 "VIR-009": ("📄", "SECURITY.md: latest minor, best-effort, no defined period (recorded decision L8)."),
 "OSS-001": ("📄", "README 'Security & trust' §official sources in each SDK; repo description/homepage set."),
 "OSS-002": ("🔧", f"Apache-2.0 LICENSE + NOTICE in each repo; {R} 'dependency licenses' allowlist (all pass)."),
 "OSS-003": ("🔧", f"{R} 'release: SBOM step' — CycloneDX via anchore/sbom-action attached to each release."),
 "OSS-004": ("🔧", "Dependabot alerts + security updates enabled; CI vuln scan on every PR; weekly readiness cron."),
 "OSS-005": ("🔧", "Lockfiles committed (go.sum, package-lock, uv.lock); actions SHA-pinned; CODEOWNERS covers lockfiles."),
 "OSS-006": ("🔧", f"{R} ruleset check."),
 "OSS-007": ("✅", "Org-level 2FA required; registry-account 2FA → E2."),
 "OSS-008": ("🔧", f"Ruleset + CODEOWNERS. Trust-path double review → {D} M9."),
 "OSS-009": ("📄", f"Release via automation PRs merged under ruleset; registry accounts → {D} E2."),
 "OSS-010": ("⏳", f"py: provenance ✅. ts: npmjs trusted publishing + provenance in dnsid-ts #16. go: deferred post-launch by decision (E5). {R} shows ❌ until done."),
 "OSS-011": ("⏳", "Registry checksums (Go sumdb, npm/PyPI hashes) + SBOM today; README names official sources. Signatures → E5."),
 "OSS-012": ("⏳", "py: `attest-build-provenance`. go/ts → E5."),
 "OSS-013": ("📄", "README 'Security & trust': official sources named; forks/mirrors/similar names disclaimed."),
 "OSS-014": ("🔧", f"{R} gitleaks + telemetry/TLS greps; {INV}: no credentials or internal config in repos."),
 "OSS-015": ("📄", f"{TM} §D — fork cannot inherit trust."),
 "OSS-016": ("📄", f"{TM} §D — cannot mint/export another agent's identity (needs DNS zone + private key + status)."),
 "OSS-017": ("📄", f"{TM} §D — software authenticity (C1) and agent identity (A1) are independent properties."),
 "OSS-018": ("🔧", f"CONTRIBUTING.md + CODEOWNERS + CODE_OF_CONDUCT.md present ({R}); ruleset enforces review. CLA/DCO → {D} L5."),
 "OSS-019": ("📄", "Dependabot for updates; SECURITY.md §End of Life for deprecation/archive."),
 "OSS-020": ("🔧", f"SECURITY.md byte-checked ({R})."),
 "OSS-021": ("📄", "Should/P2. SECURITY.md supported-versions table + §Remediation Timelines and Support Period."),
 "OSS-022": ("📄", "Should/P2. Go module builds reproducible by default; ts/py not evaluated."),
 "OSS-023": ("📄", f"{TM} §C1–C7."),
 "OSS-024": ("⏳", f"Signing keys not in repos; py provenance via OIDC. go/ts → E5. Ruleset has no bypass ({TM} C6)."),
}
for i in range(1, 11):
    INFOSEC.setdefault(f"IAM-{i:03d}", NA_SVC)
for i in range(1, 13):
    INFOSEC.setdefault(f"AGN-{i:03d}", NA_AGN)
    INFOSEC.setdefault(f"FRE-{i:03d}", NA_FRE)
for k in ["API-002", "API-004", "API-006", "API-010", "LOG-001", "LOG-002", "LOG-003", "LOG-004", "LOG-005", "LOG-007", "LOG-008", "LOG-009"]:
    INFOSEC.setdefault(k, NA_SVC)

# Legal form: (section title, [(item, status, answer)])
LEGAL = [
 ("1. Approval to Publish, Licensing, and Distribution", [
  ("Decision to publish recorded by someone with authority", "⏳", f"{D} M1."),
  ("Full contents incl. history reviewed for material that should not be published", "⏳", f"gitleaks clean; `WORKING_UPDATES.md` removed (#5); `docs/release-readiness/` flagged for compliance repo (M7). History vs snapshot → {D} M2."),
  ("Third-party/partner/customer material cleared", "✅", "None present (L4: no customer/partner material)."),
  ("What is published vs held back is recorded", "📄", "`STATUS.md` repo table: 3 SDKs + witness public; platform monorepo (server, console, CLI) private → M3, M7."),
  ("Publication does not forfeit intended protection (trade secret / patent)", "✅", "L3: one patent, held by us; no trade secrets. Apache §3 outward grant flagged for confirmation."),
  ("Outbound license chosen, approved, applied; LICENSE present", "🔧", f"Apache-2.0 in every repo ({R} file check)."),
  ("License grants or withholds a patent license", "✅", "Apache-2.0 §3 express patent grant. Intended."),
  ("Contribution intake decided (CLA / DCO / neither)", "✅", "Neither (L5). CONTRIBUTING.md §Licensing of contributions in every repo: Apache-2.0 §5 inbound = outbound."),
  ("Every third-party dependency reviewed for license compatibility", "🔧", f"{R} 'dependency licenses' allowlist; all three SDKs pass."),
  ("SBOM produced for each published package (CRA driver)", "🔧", f"{R} 'release: SBOM step'."),
  ("Third-party attribution retained; NOTICE where required", "🔧", "NOTICE.txt in every repo, third-party license texts reproduced in SDK NOTICEs."),
  ("Documentation/spec text carries a stated license", "✅", "L14: CC-BY-4.0 for docs.dnsid.ai. Site owner to apply."),
  ("Registry accounts/namespaces held by the company", "⏳", f"{D} E2."),
  ("Confusable package names reserved or monitored", "⏳", f"{D} E2 (PyPI confusables listed)."),
  ("Release artifacts signed; publishing restricted to named people", "⏳", f"py signed/attested; go/ts → E5. Publishing via automation PRs under ruleset."),
  ("Conforms to company open source policy, or absence recorded", "✅", "L15 confirmed."),
  ("Publishing entity settled and matches repos/packages/license", "✅", "L1: Known Systems AI, Inc. (final confirmation pending); applied to NOTICE/SECURITY.md/pyproject."),
 ]),
 ("2. Ownership and Provenance", [
  ("All contributors assigned/licensed work to publishing entity", "✅", "L2 confirmed (employment)."),
  ("No former-employer or other-project material introduced", "✅", "L2 confirmed."),
  ("Customer-/grant-funded material identified; terms permit publication", "✅", "L4: none."),
  ("Provenance of incorporated code incl. coding assistants understood", "✅", "L2 round 2: AI-assisted code covered by policy."),
  ("No agreement in force restricts publication", "✅", "L4: none."),
  ("Non-code assets licensed for publication", "✅", "No fonts/logos/images/datasets in SDK repos; test keys generated. Docs site → L14."),
 ]),
 ("3. Intellectual Property and Standards", [
  ("Every trademark identified; right to use confirmed", "✅", "L11: N/A — no mark claimed on 'DNSid'."),
  ("License grants no trademark rights; implementer guidance exists", "✅", "Apache-2.0 §6. Guidance N/A per L11."),
  ("Standards-process IP disclosure obligations met", "✅", "L13 confirmed (IETF BCP 79 for draft-ihsanullah-dnsid)."),
  ("Foundation contribution terms reviewed", "➖", "No foundation involved."),
  ("Patent filings reading on the implementation identified", "✅", "L3: one patent, held by us."),
  ("Competition-law guardrails understood (standards participation)", "✅", "L13 confirmed."),
 ]),
 ("4. Cryptography and Export Control", [
  ("Every cryptographic operation listed incl. dependencies", "📄", "`STATUS.md` §scoping: Ed25519, ECDSA P-256/384/521, RSA, secp256k1 (indirect), ML-DSA (go, `filippo.io/mldsa`). Signature/verify only. No AES/JWE/ECDH/HPKE."),
  ("Classification determination recorded with reasoning", "⏳", "L6: legal to write the record; facts support decontrolled (signature-only, standard algorithms)."),
  ("Notification owed for controlled public code?", "✅", "No — standard published algorithms, no non-standard cryptography."),
  ("Binaries/containers/installers assessed separately", "⏳", "SDKs ship none. CLI is a public download at launch (M3, 9/21) → assessment owed, `STATUS.md` #27; witness image → witness review."),
  ("Determination tied to change in crypto functionality", "🔧", f"{R} 'signature-only cryptography' grep fails the build if an encryption primitive appears."),
  ("Destination-market import restrictions considered", "⏳", "L6 (pending legal record); L9 geo-blocking applies to the service."),
 ]),
 ("5. What the Software Does at Runtime", [
  ("Every default network call listed with destination and reason", "📄", f"{INV} network table; README 'Security & trust' per SDK."),
  ("Default third-party endpoints disclosed in docs", "📄", "README: no hardcoded resolver; JWKS/status hosts chosen by the verified domain; `*.dnsid.ai` opt-in only."),
  ("Every default that sends data can be changed/disabled, docs say how", "📄", f"{INV}: resolver, transport, proxy, TLS, timeouts, registry/log URLs all injectable (ops docs)."),
  ("No telemetry/usage/update checks/error reports by default", "🔧", f"{R} 'no telemetry' grep; README states it."),
  ("What the software writes to logs is documented", "📄", f"README + {INV}: SDKs emit no logs."),
  ("Installer scripts reviewed", "➖", "None. `go get` / `npm install` / `pip install`."),
  ("Guidance for installers' own privacy notices", "📄", "README 'For your privacy notice' paragraph in each SDK."),
 ]),
 ("6. Developer Data and the Documentation Site", [
  ("Account/API key/registration requirement settled; personal data inventoried", "➖", "No account needed to use the SDKs. Registry accounts → hosted-service review (L10 ToS)."),
  ("Docs-site analytics/cookies/consent reviewed; privacy notice", "⏳", "L14 (site owner)."),
  ("Personal data via public repos identified", "✅", "Standard GitHub commit/issue metadata; permanent; deletion via GitHub process. Recorded in `STATUS.md`."),
  ("No personal data / real personal domains in samples, fixtures, tests", "🔧", f"{R} 'fixture domains RFC 2606'."),
  ("No credentials/keys/tokens in repos or history", "🔧", f"{R} gitleaks full history — clean."),
 ]),
 ("7. Claims, Conformance, and Naming", [
  ("What a conformance pass asserts is defined in writing", "📄", "Compliance repo README 'What a compliant result means'."),
  ("A check that did not run is never reported as passed", "📄", "Harness aborts on shim crash / result-count mismatch; `REJ`/`XFAIL`/`XPASS` distinct from `PASS`."),
  ("Two implementations that can disagree are stated as such", "📄", "Per-SDK matrix cells + divergence appendix; never averaged."),
  ("No documentation claim that cannot be cited", "⏳", "SDK READMEs reviewed. docs.dnsid.ai content not yet reviewed (needs site repo)."),
  ("Statements about identity match ToS/AUP", "⏳", "L10: ToS drafted and sent; cross-check on publication."),
  ("Product naming consistent; standard names reserved", "✅", "`dnsid-go`, `@dnsid-ai/*`, `dnsid`; ts `core→protocol` rename done pre-publish."),
  ("Availability/uptime/support statements about hosted endpoints removed or qualified", "📄", "README 'Hosted endpoints' paragraph: no availability commitment."),
  ("Launch announcement / comparative claims reviewed", "⏳", "No announcement drafted yet. Review when it exists."),
 ]),
 ("8. Warranties, Liability, and API Terms", [
  ("Warranty disclaimer/liability limitation adequate", "⏳", "Apache-2.0 §7–8. → `DECISIONS.md` L16."),
  ("Product liability exposure considered (EU PLD)", "⏳", "Turns on the same commercial-activity question as CRA (L7, deferred by legal)."),
  ("Decision on separate terms beyond the license", "⏳", "L10: API ToS drafted."),
  ("Public API terms cover rate limits, AUP, no availability commitment", "⏳", "L10."),
  ("Support expectations set or disclaimed in writing", "📄", "SECURITY.md §Support: best-effort, no commercial support."),
  ("Nothing creates a hosted-service commitment the service doesn't make", "📄", "README 'Hosted endpoints' paragraph."),
 ]),
 ("9. Security and Vulnerability Handling", [
  ("Security policy published with working disclosure contact (CRA driver)", "✅", f"SECURITY.md in every repo ({R}), contact `security@dnsid.ai` (live 9/21)."),
  ("Decision recorded on response/remediation timelines", "✅", "Acknowledge 3 business days / assess 14 days; remediation deadlines deliberately not committed (L8, recorded in SECURITY.md)."),
  ("Process for issuing and announcing a fix", "📄", "SECURITY.md §How Fixes Are Released."),
  ("Security updates free for a defined, published period (CRA driver)", "⏳", "Deliberately undefined for now (L8); revisit with CRA (L7). Published as such in SECURITY.md."),
  ("No known exploitable vulnerabilities; secure defaults (CRA driver)", "🔧", f"{R} vuln scan 0 findings; fail-closed defaults ({TM})."),
  ("Dependency/vuln scanning with an owner for findings", "✅", f"Scanning ✅; owner = security owner (`STATUS.md` #7)."),
  ("Publishing requires more than one person / controlled against single compromise", "📄", f"Release PRs under ruleset (review required, no bypass); registry accounts → E2. {TM} C5."),
  ("Consequences of a correctness bug (false pass) thought through", "📄", f"{TM} A8; false pass = Critical regardless of CVSS (draft SECURITY.md)."),
 ]),
 ("10. EU Cyber Resilience Act", [
  ("Policy decision on pursuing CRA compliance, by whom, reasoning", "✅", "L7 round 2: legal — CRA applies; deferred post-launch; reasoning: in practice a constraint on EU users rather than our launch. Recorded."),
  ("Category determination per package (out of scope / steward / manufacturer)", "⏳", "L7 deferred. Facts point to manufacturer (`STATUS.md` decision 4)."),
  ("Manufacturer likelihood assessed rather than defaulted to steward", "⏳", "L7."),
  ("Made available on the EU market confirmed (registries/mirrors)", "✅", "Yes — npm/PyPI/Go proxy are global."),
  ("Essential requirements and vulnerability handling met (if manufacturer)", "⏳", "Evidence exists (SBOM, SECURITY.md, scanning, threat model); formal claim → L7."),
  ("Technical documentation, conformity assessment, DoC, CE marking", "⏳", "L7."),
  ("Reporting path for actively exploited vulns with named person", "✅", "Security owner (`STATUS.md` #7) via `security@dnsid.ai`. ENISA platform access still to be set up by the owner."),
  ("Authorized EU representative decision; importer/distributor obligations", "⏳", "L7."),
  ("CRA obligations of third-party components identified", "⏳", "SBOM lists them; assessment → L7."),
 ]),
 ("11. Sanctions and Distribution", [
  ("Position on sanctions applying to publishing OSS", "✅", "L9: rely on GitHub platform trade-control enforcement; service geo-blocked separately."),
  ("Gated components treated separately", "✅", "L9: `api.dnsid.ai` geo-blocked for embargoed regions; SDK itself is ungated."),
  ("Sanctions posture of each distribution channel understood", "✅", "GitHub, npm, PyPI, Go proxy each enforce their own; recorded."),
  ("Position on contributions from restricted jurisdictions", "✅", "L9: GitHub restricts accounts from sanctioned regions at platform level; no project-level screening."),
 ]),
 ("12. Governance and Ongoing Operation", [
  ("Governance model recorded: who merges, who speaks", "⏳", f"Merging: CODEOWNERS + ruleset. Speaking: → {D} M8 — deferred 9/21, not blocking."),
  ("Code of conduct published with enforcement position", "✅", "Contributor Covenant 2.1, ladder as written, `report@dnsid.ai` (L12); byte-checked."),
  ("Third-party service accounts company-held, terms knowingly accepted", "⏳", f"{D} E6."),
  ("End-of-life position recorded", "📄", "SECURITY.md §End of Life: README + release note, registry deprecation, archive read-only."),
  ("Whether the project can be relicensed later is understood", "✅", "L5 = neither → relicensing needs every contributor's consent. Accepted."),
 ]),
 ("13. Release Sign-off", [
  ("Approval covers final contents as released", "⏳", "M1, after all 🔴 items close."),
  ("Security review completed and recorded", "⏳", "This document + `THREAT_MODEL.md` + readiness output; pentest question M5."),
  ("Legal and privacy review completed with link to approval", "⏳", "Pending legal round 2 and M/E answers."),
  ("Brand and trademark approval for names", "✅", "L11 N/A."),
  ("Named person responsible for first weeks incl. security reports", "✅", "`STATUS.md` #7 (named 9/21)."),
  ("Plan for a legal/privacy problem found after publication", "✅", "SECURITY.md §\"Non-Security Problems Found After Publication\" in every repo: new version + notice/advisory + registry deprecation; archive last resort; legal decides, security owner executes."),
  ("Every item answered or recorded N/A with reason", "⏳", "This document. Regenerate with `gen_review.py` as answers land."),
 ]),
]


def main():
    rows = [l.rstrip("\n").split("|", 2) for l in open(sys.argv[1]) if l.strip()]
    out = []
    out.append("# DNSid SDK Release Review — Row-by-Row\n")
    out.append("Generated by `gen_review.py`; edit that file, not this one. Covers `dnsid-go`, `dnsid-ts`, `dnsid-py`.\n")
    out.append("Status: ✅ answered · 🔧 enforced mechanically by `ci/readiness.sh` on every PR · 📄 documented · ⏳ pending a decision (see `DECISIONS.md`) · ➖ not applicable, reason given.\n")
    counts = {}
    out.append("\n## Part A — DNSid Agent InfoSec Checklist\n")
    cur = None
    for cid, req, text in rows:
        pre = cid[:3]
        if pre != cur:
            cur = pre
            out.append(f"\n### {pre}\n\n| ID | Req | Control | Status | Response / evidence |\n|---|---|---|---|---|")
        st, ans = INFOSEC.get(cid, ("❓", "**no answer recorded**"))
        counts[st] = counts.get(st, 0) + 1
        out.append(f"| {cid} | {req} | {text.strip()} | {st} | {ans} |")
    out.append("\n## Part B — OSS Release Legal & Privacy Review Form\n")
    for title, items in LEGAL:
        out.append(f"\n### {title}\n\n| Item | Status | Finding and evidence |\n|---|---|---|")
        for item, st, ans in items:
            counts[st] = counts.get(st, 0) + 1
            out.append(f"| {item} | {st} | {ans} |")
    out.append("\n## Tally\n\n| Status | Rows |\n|---|---|")
    for st in ["✅", "🔧", "📄", "⏳", "➖", "❓"]:
        if counts.get(st):
            out.append(f"| {st} | {counts[st]} |")
    print("\n".join(out))


if __name__ == "__main__":
    main()
