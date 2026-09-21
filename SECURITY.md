# **Security Policy**

Known Systems AI, Inc. takes the security of this project seriously. This document explains how to report vulnerabilities and what you can expect from us in return.

## **Scope**

This repository holds the cross-SDK compliance test kit: test vectors, the harness that runs them, and the reusable CI workflow that gates the DNSid SDK repositories. It is not a released package and has no versioned releases.

| Area | Supported |
| :---- | :---- |
| `main` (harness, fixtures, reusable workflow) | ✅ |
| Historical commits and forks | ❌ |

A vulnerability in a DNSid SDK itself belongs in that SDK's repository
([dnsid-go](https://github.com/dnsid-ai/dnsid-go),
[dnsid-ts](https://github.com/dnsid-ai/dnsid-ts),
[dnsid-py](https://github.com/dnsid-ai/dnsid-py)), each of which has its own
`SECURITY.md`. Report it there, or here if you are unsure which applies — we will route it.

Findings that are in scope for **this** repository include a test vector whose
expectation is unsound and would let a real protocol flaw pass as compliant, and any
weakness in the reusable workflow that could let untrusted input reach a privileged
CI context.

## **Reporting a Vulnerability**

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.**

Report privately through one of the following:

- **GitHub Security Advisories**: if the **"Report a vulnerability"** button is available under
  this repository's **Security** tab, use it to open a private advisory.
- **Email**: `security@dnsid.ai`

## **Our Commitment**

When you report a vulnerability responsibly, we will:

- **Acknowledge** receipt within **3 business days**.
- Provide an **initial assessment** (validity, severity, next steps) within **14 days**.

## **How Fixes Are Released**

This repository publishes no package. A confirmed issue is fixed by a commit to `main`:

1. Test-vector fixes land on `main`; SDK repositories pin the reusable workflow at `@main`, so their
   next CI run picks the correction up automatically.
2. If an unsound vector could have let a real protocol flaw pass as compliant, a GitHub Security
   Advisory is published here naming the affected vectors and the fixing commit, and the affected
   SDK repositories are notified so they can re-run conformance.
3. Reporters are credited in the advisory unless they ask otherwise.

A report showing an invalid record, signature, or status being **accepted as valid** is treated as the
highest priority regardless of its CVSS score.

## **Non-Security Problems Found After Publication**

If a published release is found to contain a licensing defect, third-party material we may not
distribute, personal data, or anything else that should not have been published, we follow the same
path as a security fix: a new release with the material removed, a notice in the README and (where a
registry supports it) an advisory, and deprecation of the affected versions on the package registry.
Because published packages and git history cannot be truly recalled, we will also remove the
material from the repository where that is possible and contact the registry if removal of a published
version is warranted. Archiving the repository is the last resort. The decision is made by the
company's legal team; the security owner executes it. Report such problems to `security@dnsid.ai`; they
are routed to legal.

## **Remediation Timelines and Support Period**

Beyond the acknowledgement and assessment commitments above, we do not currently commit to fixed
remediation deadlines or to a defined security-support period. Fixes are provided on `main` on a
best-effort basis. This position will be revisited; any change will be made in this file first.

## **End of Life**

If maintenance of this repository ends, we will say so in its README and archive the repository
read-only rather than delete it, so that workflows referencing it keep resolving. Forks remain free to
continue under the Apache-2.0 license.

## **Support**

This is open-source software provided under the Apache License 2.0 without warranty. Issues and pull
requests are triaged on a best-effort basis by the maintainers listed in `CODEOWNERS`. No commercial
support is attached to this repository.

## **Safe Harbor**

We will not pursue or support legal action against researchers who:

- Act in good faith and in accordance with this policy,
- Avoid privacy violations, service disruption, and destruction/exfiltration of data beyond what is needed to demonstrate the issue, and
- Give us a reasonable time to respond before disclosing.

*This policy applies to this open-source project only. It does not create any obligation with respect to Known Systems' commercial products or services.*
