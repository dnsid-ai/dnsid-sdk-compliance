# DNSid SDK Public Release — Decisions Required

**What this is.** The DNSid SDKs (Go, TypeScript, Python) have been taken through the *DNSid Agent
InfoSec Checklist* and the *OSS Release Legal & Privacy Review Form*. Everything that can be checked
mechanically now is, on every pull request (`ci/readiness.sh`), and the written artifacts the checklists
ask for exist (threat model, data/network inventory, security policy, code of conduct). What remains
are the questions below, which need a person with authority to answer.

**How to read it.** Each item: the question, why it's asked (checklist row), the default we will apply
if nobody objects, and what it blocks. Answer with the default, an alternative, or "need more info."
Items are grouped by who answers and ordered so publish-blockers come first.

**Scope reminder.** The SDKs are verification/signing libraries. They ship no keys or credentials, run
no service, send no telemetry, and contain no encryption (signatures only). A fork cannot inherit a
DNSid identity. The hosted service (`api.dnsid.ai`, registry, console) is a separate review.

Legend: 🔴 blocks publish · 🟡 blocks a specific file or sign-off row · ⚪ record the answer, nothing blocked

---

## Legal

| # | Question | Why | Proposed default | Blocks |
|---|---|---|---|---|
| L1 🔴 | **Publishing entity.** Confirm the exact legal name for the copyright line and all public prose. Expected "Known Systems AI, Inc." | Legal §1 row 17; also legal's instruction that public surfaces must not present as Identity Digital. Today NOTICE says "Identity Digital Inc.", SECURITY.md says "Identity Digital Innovation Labs". | Use the confirmed name in NOTICE, SECURITY.md, and package metadata in one pass across all repos. | NOTICE, SECURITY.md, package metadata, witness placeholders |
| L2 🔴 | **Contributor IP.** Two contributors committed under personal email addresses; two commits in the witness repo are from a coding-assistant bot. Confirm employment/assignment covers all contributors, and that company policy permits AI-assisted code under Apache-2.0. | Legal §2 rows 1, 2, 4 | Confirm in writing; no code change. | Publish |
| L3 🔴 | **Trade secret / patent.** Is anything in the SDKs relied on as confidential know-how? Any filed or intended patent that reads on the implementation? | Legal §1 row 5, §3 row 5. Publication creates prior art and ends trade-secret status. | "Nothing relied on; no filings." | Publish |
| L4 🔴 | **Funding and restrictive agreements.** Any customer-, partner-, or grant-funded work in these repos? Any agreement (exclusivity, confidentiality, the former evaluation agreement) restricting publication? | Legal §2 rows 3, 5 | "None." | Publish |
| L5 🟡 | **Contribution intake: CLA, DCO, or neither.** Cannot be retrofitted after external contributions arrive; also determines whether relicensing is ever possible. | Legal §1 row 8, §12 row 5 | **DCO** (sign-off line, enforced by a bot; no paperwork for contributors). | CONTRIBUTING.md; relicensing question |
| L6 🟡 | **Export classification record.** Facts: Ed25519, ECDSA, RSA, ML-DSA signatures only; no encryption of content; standard published algorithms. | Legal §4 rows 2, 3, 6 | Record as **decontrolled** (authentication/signature only); no notification owed; no destination-market restriction identified. Re-review triggers automatically if an encryption primitive is ever added (CI grep). | Sign-off row |
| L7 🟡 | **EU CRA position.** The SDKs drive adoption of a paid service, which the form says is a poor fit for "open source steward." Reporting obligations began 11 Sep 2026. | Legal §10, all rows | Record **manufacturer**; sequence remaining obligations to 11 Dec 2027; name an ENISA reporting contact (see E3) and publish a support period (see L8). | Sign-off; SECURITY.md support period |
| L8 🟡 | **Security-update commitments** — five numbers for SECURITY.md: (a) fix targets Critical/High/Medium; (b) support period; (c) pre-1.0 stance; (d) end-of-life notice; (e) is paid support planned? | Legal §8 row 5, §9 rows 2–4, §12 row 4; VIR-003/004/009; CRA expects ≥5-year support. Existing "acknowledge in 3 business days / assess in 14 days" also needs to be a deliberate decision. | (a) 7 / 30 / 90 days; (b) 5 years from 1.0 or 2 years from last release, whichever later; (c) latest minor only while pre-1.0; (d) 6 months; (e) no. Keep the 3-day/14-day commitment. | SECURITY.md final section |
| L9 🟡 | **Sanctions position.** Record whether sanctions restrictions apply to publishing the code, and the position on contributions from restricted jurisdictions. | Legal §11, all rows | Publication of open source is not a service and is not restricted; the hosted API is gated under its own terms; registries enforce their own posture; contributions from restricted jurisdictions declined case-by-case. | Sign-off row |
| L10 🟡 | **API terms of service** for `api.dnsid.ai` and `log.dnsid.ai`. The Apache license governs the code, not the hosted endpoints the code can call. Must cover rate limits, acceptable use, and absence of availability commitment. | Legal §8 rows 3, 4, 6; §7 row 5 | Legal drafts; SDK READMEs already state the endpoints are governed separately with no availability commitment. | Sign-off row |
| L11 🟡 | **Trademark.** Right to use "DNSid" confirmed; written guidance for implementers on how they may/may not describe their implementations using the mark. | Legal §3 rows 1, 2; §13 row 4 | Short `TRADEMARKS.md` in each repo. Apache-2.0 §6 already withholds trademark rights. | Sign-off row 4 |
| L12 🟡 | **Code of conduct contact.** `report@dnsid.ai` is shared with hosted-service misconduct reports. Keep shared, or create a dedicated `conduct@dnsid.ai`? | Legal §12 row 2 | Keep `report@dnsid.ai` (already published in the CoC). | Nothing — one-line change if a new alias is chosen |
| L13 ⚪ | **IETF participation obligations.** The protocol is an IETF Internet-Draft. BCP 79 puts IPR-disclosure duties on participants personally; the Note Well covers competition-law conduct. Confirm the draft's authors have made any required disclosure and are briefed. | Legal §3 rows 3, 6 | Confirm; no code change. | — |
| L14 ⚪ | **Docs site license and privacy notice.** License for prose at `docs.dnsid.ai`; cookie/analytics review and privacy notice for the site. | Legal §1 row 12, §6 row 2 | CC-BY-4.0 for docs; site review by whoever owns the site. | Docs site, not the SDKs |
| L15 ⚪ | **Open source policy.** Does one exist? If not, the form itself says this review is the policy for this release. | Legal §1 row 16 | Record "no standing policy; this review serves." | — |

## Management / product

| # | Question | Why | Proposed default | Blocks |
|---|---|---|---|---|
| M1 🔴 | **Approval to publish**, per repository, by someone with authority, covering the final contents. Publication is irreversible. | Legal §1 row 1, §13 row 1 | Named approver signs the filled review form for each of the three SDK repos. | Publish |
| M2 🔴 | **History or clean snapshot.** Early tags carry the former evaluation-agreement license; commit history includes personal emails. Publish the full history, or a squashed snapshot with a fresh initial commit? | Legal §1 row 2, §6 row 5 | **Clean snapshot** for the witness repo (11 commits, no external consumers). For the SDKs, keep history if L2/L4 come back clean; otherwise snapshot. | Publish |
| M3 🔴 | **CLI release status.** The CLI lives in the private platform monorepo and ships as compiled binaries. Is it a public download at launch? If yes, binaries need signing, hashes, provenance, and their own export/installer review; if no, SDK docs that reference it need adjusting. | OSS-010/011/012, Legal §4 row 4, §5 row 6 | Internal-only at launch; SDK READMEs reference it as "the DNSid CLI" without a download link. | Publish (doc changes) |
| M4 🟡 | **Named owners.** A security owner and an engineering owner for the SDKs, by name, and who is on point for the first weeks after release. | COM-004, Legal §13 row 5 | The SDK maintainer team lead for both, recorded in CODEOWNERS/README. | Sign-off row 5; governance statement |
| M5 🟡 | **Independent penetration test** of the verification path before release, or accept that the cross-SDK conformance harness plus code review suffices for a library? | SSD-012 (Must), THREAT_MODEL A8 | Commission a scoped review of the verification path (false-pass focus) before 1.0; release pre-1.0 without it, stated in README. | Sign-off row 2 |
| M6 🟡 | **Local private keys are stored unencrypted** (`~/.dnsid`, file mode 0600, no passphrase option) by the SDKs and CLI. Accept and document as development/single-host use with KMS for production, or add optional encryption? | DAT-006 (Must), IDT-005; THREAT_MODEL B1 | **Accept and document.** Same posture as SSH, AWS and gcloud CLIs. Adding encryption re-opens L6. | INVENTORY / README wording |
| M7 🟡 | **Publish the compliance repo?** Contains the conformance harness and readiness checker. Only needed if conformance claims are made publicly and should be independently reproducible. Internal working docs would need to move out first. | Legal §7 row 1 | Keep private for launch; revisit when a public conformance claim is made. | — |
| M8 ⚪ | **Governance statement.** Who merges is enforced by CODEOWNERS and branch rules. Missing: who may speak for the project publicly, and that maintainer statements in issue threads are not company commitments. | Legal §12 row 1 | Half a page in CONTRIBUTING, authored once M4 names the owner. | Sign-off row |
| M9 ⚪ | **Trust-path review depth.** Branch rules require one approving review. Raise to two for cryptography, DNS, verification, and release-workflow files? | OSS-008, THREAT_MODEL C5 | Keep one for now; revisit at 1.0. | — |

## Engineering / IT

| # | Question | Why | Proposed default | Blocks |
|---|---|---|---|---|
| E1 🔴 | **Public contact aliases** (`security@`, `report@`, `legal@` on `dnsid.ai`) — confirm live before publish. SECURITY.md and the code of conduct point at them. | VIR-001/002, Legal §9 row 1 | Aliases route to legal and the security group; SECURITY.md contact switched from the identity.digital inbox on go-live. | Publish (dead contact otherwise) |
| E2 🔴 | **Package registry ownership.** npm org `@dnsid-ai` owner unverified; PyPI `dnsid` and confusable names (`dnsid-sdk`, `dnsid-ai`, `dnsid_ai`, `dnsidai`) unclaimed. Must be company-held accounts. | Legal §1 rows 13, 14; OSS-001; THREAT_MODEL C2 | Claim all under a company account with 2FA; record who holds it. | Publish |
| E3 🟡 | **CRA reporting contact.** A named person with access to the ENISA single reporting platform for actively exploited vulnerabilities. Obligation already live. | Legal §10 row 7 | The security owner from M4, with `security@dnsid.ai` as the inbound path. | Sign-off row |
| E4 🟡 | **Org-level 2FA enforcement** on the GitHub org. All members have 2FA; the org setting is pending enterprise. | SSD-003, OSS-007 | Enterprise team enables. | Sign-off row |
| E5 🟡 | **Release signing for Go and TypeScript** was skipped (Python has provenance). TypeScript is blocked on the npmjs-vs-GitHub-Packages decision (`--provenance` requires npmjs). Confirm skip is accepted for launch, and decide the npm registry. | OSS-010/011/012, OSS-024 | Publish `@dnsid-ai/*` to **npmjs** with provenance; add Go release signing before 1.0. | Readiness shows ❌ until done |
| E6 ⚪ | **Third-party service accounts.** GitHub org, npm, PyPI, DeepSource, any CI/SaaS — held by company accounts, terms accepted knowingly, continuity when a person leaves. DeepSource in particular: in use, or leftover config to delete? | Legal §12 row 3 | Inventory the accounts; delete DeepSource config if unused. | — |
| E7 ⚪ | **`security.txt`** at `dnsid.ai` and `docs.dnsid.ai`. Needs the site repository. | VIR-002 | Publish once E1 aliases exist. | — |

---

## What is already done (for context, no decision needed)

- Every repo: Apache-2.0 LICENSE, NOTICE, CONTRIBUTING, canonical SECURITY.md and CODE_OF_CONDUCT.md (byte-checked), CODEOWNERS, Dependabot.
- Branch rules: PR required, code-owner review, signed commits, no force-push or deletion, no bypass.
- CI on every PR: all GitHub Actions SHA-pinned, secret scan over full history (clean), dependency vulnerability scan, dependency license allowlist, TLS-disable and telemetry greps (none), encryption-primitive grep (none — export re-review tripwire), fixture domains RFC 2606.
- Releases: CycloneDX SBOM attached; Python has build provenance.
- Written: data & network inventory (every destination, default vs opt-in, what is stored), threat model (19 threats with mitigations and residuals), README "Security & trust" section in each SDK (official sources, software ≠ identity, network behavior, no telemetry, downstream privacy-notice guidance).
- Cross-SDK conformance harness: 193 spec-derived cases, all three SDKs 100%, with a written statement of what a pass does and does not assert.

## After the decisions

Once the 🔴 items are answered, remaining work is mechanical and small: one pass to apply the entity
name, fill the SECURITY.md numbers, merge the readiness PRs, flip repos public, and complete the two
review forms row-by-row for §13 sign-off with pointers to the evidence above.
