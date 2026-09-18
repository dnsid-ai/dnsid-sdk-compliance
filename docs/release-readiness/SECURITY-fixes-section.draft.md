# DRAFT — section to append to `policy/SECURITY.md`

Not yet in `policy/` (byte-check would push placeholders to every SDK). Every value in
`⟦NEEDS DECISION #n⟧` maps to a row in STATUS.md "Human decisions". Once all are filled, append
below "Our Commitment", drop this file, and let the byte-check propagate.

Closes: Legal §8 row 5, §9 rows 2–4, §12 row 4; InfoSec VIR-003/004/008/009, OSS-019/021, SSD-009.
Proposed defaults in brackets are what I'd write if nobody objects — they still need a yes.

---

## **Severity and Response Targets**

We classify confirmed vulnerabilities using CVSS v3.1 and aim to release a fix within:

| Severity | CVSS | Fix target |
| :---- | :---- | :---- |
| Critical | 9.0–10.0 | ⟦NEEDS DECISION #16a — proposed 7 days⟧ |
| High | 7.0–8.9 | ⟦NEEDS DECISION #16a — proposed 30 days⟧ |
| Medium | 4.0–6.9 | ⟦NEEDS DECISION #16a — proposed 90 days⟧ |
| Low | 0.1–3.9 | Next scheduled release |

These are targets, not guarantees. A report that shows an invalid record, signature, or status
being **accepted as valid** is always treated as Critical regardless of CVSS score.

## **How Fixes Are Released**

A published package cannot be recalled, so the remedy is always a new version plus an advisory:

1. The fix ships as a new tagged release of the affected SDK(s), with the SBOM attached.
2. A GitHub Security Advisory is published on the affected repository at the same time, with a
   CVE requested through GitHub's CNA for Medium and above.
3. The advisory names the first fixed version and the affected range. Dependabot and the package
   registries pick it up automatically; we do not operate a separate mailing list.
4. Reporters are credited in the advisory unless they ask otherwise.

Critical and High fixes are released as patch versions on the latest minor so that upgrading never
requires taking unrelated changes.

## **Security Update Period**

Security fixes for the latest tagged minor release are provided free of charge for at least
⟦NEEDS DECISION #16b — CRA expects ≥5 years or a stated shorter product lifetime; proposed: 5 years
from 1.0.0, or 2 years from the last release, whichever is later⟧.

⟦NEEDS DECISION #16c — pre-1.0 stance. Proposed: "While the SDKs are pre-1.0, only the latest
minor receives fixes; upgrade paths between minors are documented in each release."⟧

## **End of Life**

If maintenance of an SDK is ending, we will:

- Announce it in the repository README and a final release note at least
  ⟦NEEDS DECISION #16d — proposed 6 months⟧ in advance,
- Mark the package deprecated on its registry with a pointer to any successor,
- Archive the repository (read-only) rather than delete it, so existing installs keep resolving.

Forks remain free to continue under the Apache-2.0 license; see the README on why a fork cannot
inherit DNSid trust.

## **Support Expectations**

This is open-source software provided under the Apache-2.0 license without warranty. Issues and
pull requests are triaged on a best-effort basis by the maintainers named in `CODEOWNERS`. There is
no commercial support attached to these repositories ⟦NEEDS DECISION #16e — or is there? If a paid
support tier exists or is planned, this sentence changes and the CRA "manufacturer" analysis in
decision #4 is confirmed⟧.
