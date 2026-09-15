# **Security Policy**

Identity Digital Innovation Labs takes the security of this project seriously. This document explains how to report vulnerabilities and what you can expect from us in return.

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
- **Email**: `idil-bugreport@identity.digital`

## **Our Commitment**

When you report a vulnerability responsibly, we will:

- **Acknowledge** receipt within **3 business days**.
- Provide an **initial assessment** (validity, severity, next steps) within **14 days**.

## **Safe Harbor**

We will not pursue or support legal action against researchers who:

- Act in good faith and in accordance with this policy,
- Avoid privacy violations, service disruption, and destruction/exfiltration of data beyond what is needed to demonstrate the issue, and
- Give us a reasonable time to respond before disclosing.

*This policy applies to this open-source project only. It does not create any obligation with respect to Identity Digital's commercial products or services.*
