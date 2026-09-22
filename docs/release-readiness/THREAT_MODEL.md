# DNSid SDK Threat Model

Covers `dnsid-go`, `dnsid-ts`, `dnsid-py` as shipped. Answers InfoSec **COM-001/002/005**, **OSS-023**,
**VIR-007** (scenarios) and Legal **§9 row 8** (false-pass consequences). Mitigations are cited to the
per-SDK operations docs (`dnsid-go/OPERATIONS.md`, `dnsid-ts/docs/security.md`, `dnsid-py/docs/security.md`)
and to `INVENTORY.md`; nothing here is asserted that is not in those documents or in source.

## System and trust boundaries (COM-001)

```
 integrator process ──┬── SDK ── system DNS resolver ──────── authoritative DNS for <domain>
   (calls verify/sign) │         ── HTTPS ──────────────────── JWKS host, status host (chosen by domain owner)
                       │         ── HTTPS (opt-in) ────────── api.dnsid.ai, log.dnsid.ai
                       │         ── local files (opt-in) ──── ~/.dnsid (keys, config)
                       │         ── cloud KMS (opt-in) ────── AWS / GCP
                       └── integrator's own peer connection (TLS chain, for fl=mtls binding)
```

Trust boundaries, from most to least trusted by the SDK:

| Zone | Trusted for | Not trusted for |
|---|---|---|
| Integrator code and configuration | Policy: DNSSEC mode, trusted-entity allowlist, timeouts, injected resolver/transport/KMS | — (it is the principal) |
| Bundled trust roots (tlog public keys, witness keys) | Authenticity of `log.dnsid.*` checkpoints | Anything else |
| DNS answer for `_dnsid.<domain>` | Location of keys/status; record signature `sg` is verified against `ek` | Freshness beyond TTL; integrity unless DNSSEC-validated resolver injected |
| JWKS / status hosts | Content, after TLS + host pinning + size caps | Availability; being non-malicious (they are the counterparty's) |
| Registry / log | Signed evidence (incl. witness cosignatures inside checkpoints), checked against bundled roots | Anything unsigned |
| Counterparty input (JWT, HTTP signature, record text) | Nothing until fully parsed, bounded, and verified | Everything |

**Privileged components:** none in the SDK. Private keys live in the integrator's file system (`~/.dnsid`,
`0600`) or in a KMS the SDK cannot extract from. The SDK holds no credentials of its own.

## What the SDK can and cannot do (COM-002)

Can: resolve and verify a domain's DNSid record, keys, status, and (optionally) log evidence; verify JWTs,
RFC 9421 HTTP signatures, and OIDC assertions bound to a verified domain; sign the same on the integrator's
behalf with a key the integrator supplies; generate keys and TXT records; publish to a registry when told to.

Cannot: act autonomously (every operation is a synchronous call); reach any host not derived from
integrator config or the verified record; send telemetry; persist anything except keys/config the
integrator explicitly asks for; disable TLS verification; mint or export another party's identity.

## Threats and mitigations (COM-005, OSS-023)

Severity is what the integrator suffers if the threat succeeds against the SDK as shipped.
"Residual" is what remains after the listed mitigations; items marked **integrator** are decisions the
SDK exposes but cannot make for them.

### A. Protocol / verification path

| # | Threat | Impact if realized | SDK mitigation | Residual |
|---|---|---|---|---|
| A1 | **Agent impersonation** — attacker presents a domain they don't control | Verifier trusts the wrong party | Identity = DNS control + `ek`-signed record + `ku` key + status; all four checked. `sg` over canonical record verified against `ek`; JWKS host pinned to record's domain (`ku`) / governance domain (`ek`); `TrustedEntities` allowlist with exact `gi` match, optional `ek` thumbprint pin | Attacker who controls the DNS zone *is* the domain owner by definition — see A2 |
| A2 | **DNS spoofing / cache poisoning / downgrade** of `_dnsid` TXT | Redirect verifier to attacker's JWKS/status | `sg` signature ties record to `ek`; forged record fails unless attacker also controls `ek`. DNSSEC: `auto` rejects explicit FAILED; `validated`/`required` modes with injected validating resolver. No hardcoded public resolver. TTL bound from lookup start, no TTL restart on refresh | Built-in resolvers cannot see DNSSEC AD bit → `UNKNOWN` accepted in `auto`. **Integrator**: inject validating resolver for high-value gates |
| A3 | **Key theft** — counterparty's operational key compromised | Attacker signs as that agent until rotation/revocation | Status endpoint (`su`) rechecked on cache hit per `StatusCheckInterval` (0 = every call); `ka=` max key age enforced from log evidence; log-binding continuity for draft-01; JOSE evicts+retries once on signature failure during rotation | Detection is the counterparty's job. **Integrator**: `StatusCheckInterval=0` and per-call deadline for revocation-sensitive gates |
| A4 | **Replay** of a captured JWT / signed request | Stale authorization reused | JWT `exp`/`iat`/`nbf`, default assertion lifetime 5 min (max 15); RFC 9421 `created`/`expires`/`nonce`; `fl=mtls` binds to the *current* peer TLS chain, checked on cache hits too | Nonce uniqueness storage is **integrator**-side |
| A5 | **Stale evidence** — revoked/rotated identity still cached | Trusting a revoked agent | Cache expiry = min(DNS TTL, `ka`, TLS validity); zero TTL = single use; no negative caching; expiry during refresh fails rather than reinserting; `EvictDomain()` | Up to `StatusCheckInterval` of lag by **integrator** choice |
| A6 | **Malicious JWKS / status host** (SSRF, redirect, resource exhaustion) | Verifier coerced into internal-network requests or OOM | Non-public IP ranges rejected at fetch; redirects denied by default, JWKS redirects host-pinned, HTTPS-only, no userinfo; response caps (JWKS 1 MiB, status 64 KiB); 30 s overall budget shared by all child requests; 10 s dial timeout | Public-IP SSRF targets are indistinguishable from legitimate hosts — inherent to the protocol |
| A7 | **Hostile input parsing** (JOSE, HTTP signature, TXT record, C2SP entries) | Crash, DoS, parser confusion | Size caps before parsing (compact JOSE 1 MiB, headers 16 KiB, payload 768 KiB, HTTP fields 1 MiB, body 8 MiB, C2SP entry 64 KiB); duplicate JSON members, invalid UTF-8, depth >64, noncanonical base64url, `crit` headers rejected; structured-field parser limits (128 labels/components, 64 params); oversized input rejects the invocation, never truncates | Custom injected fetchers/readers that ignore limits or cancellation are **integrator** responsibility (documented) |
| A8 | **False pass — correctness bug accepts invalid input as valid** (Legal §9) | Silent trust in a forged identity; worst case for a security library because nobody notices | Fail-closed design: unknown version → reject; missing log reader for draft-01 → reject, not skip; `TrustedEntities` empty-non-nil → deny all. Cross-SDK conformance harness (193 spec-derived cases, three independent implementations must agree; disagreement is reported, never averaged). Any report of a false pass is Critical regardless of CVSS (SECURITY.md draft) | Harness covers the pure-data surface, not `VerifyDomain` end-to-end (stated in harness README). Independent pentest is decision #8 |
| A9 | **Denial of service** against the verifier via slow/large upstreams | Integrator's process stalls | Per-invocation deadline (default 30 s) shared by DNS, HTTPS, redirects, retries, log scans; coalesced verification has a finite ceiling; bounded cache (1024) | Key-provider calls (KMS) are synchronous and cannot be interrupted by the SDK — **integrator** sets provider timeouts |

### B. Local key handling

| # | Threat | Impact | Mitigation | Residual |
|---|---|---|---|---|
| B1 | **Local key file read** by another local user or leaked backup | Attacker signs as the integrator's agent | `0600`, `O_EXCL`, atomic write; `DNSID_CONFIG_DIR` relocatable; KMS providers keep keys in HSM | **Plaintext at rest — decision #12.** Same-user malware or root reads it |
| B2 | **Key material in logs / errors** | Leak via integrator's log pipeline | SDKs emit no logs; errors carry thumbprints and domains only; denial messages never echo allowlist or pins | — |
| B3 | **Cloud credential misuse** via KMS providers | Attacker with the integrator's cloud creds signs | Not SDK-mitigable; SDK never handles the creds, cloud SDK reads env | **Integrator** IAM scoping |

### C. Supply chain and project (OSS-023, VIR-007)

| # | Threat | Impact | Mitigation | Residual |
|---|---|---|---|---|
| C1 | **Malicious fork / modified build** presented as official | Users install a backdoored SDK | Official sources named in README; SBOM per release; py + ts provenance attestations; forks cannot inherit identity (see D) | go release signing skipped (decision, fix #8). OSS-011 hashes rely on registry checksums (Go sumdb, npm/PyPI hashes) |
| C2 | **Dependency confusion / typosquat** | Wrong package installed | Scoped npm names `@dnsid-ai/*`; Go module path is the repo URL; PyPI `dnsid` claimed (#5); confusable names to reserve (#13); README names the exact package | Reservation incomplete — #13 |
| C3 | **Compromised dependency** | Malicious code in the trust path | Lockfiles committed; Dependabot alerts + security updates on; `govulncheck` / `npm audit` / `pip-audit` in CI; license allowlist in readiness | Zero-day in a dep until advisory. Small dep surface: go ≈15, py 12, ts 109 (mostly AWS SDK, opt-in package) |
| C4 | **Malicious contributor** | Backdoor merged | Ruleset: PR required, CODEOWNER review, extra approval for unattributed changes, signed commits, no bypass actors; CodeQL (all repos, added in sanity pass); gitleaks; readiness gate on PR; conformance regression gate | CLA/DCO undecided (#3). Review quality is human |
| C5 | **Compromised maintainer account** | Push/release as maintainer | Org-level 2FA enforced, 18/18 members; signed commits required; no ruleset bypass; publish restricted to release automation (`release/next` PRs) | Single maintainer approval suffices today (`required_approving_review_count: 1`) |
| C6 | **Compromised CI / release pipeline** | Poisoned artifact with a valid-looking release | All actions SHA-pinned (readiness ❌ otherwise); reusable workflows `on: pull_request` so forks get no secrets; GitHub-hosted runners; SBOM generated in-pipeline; **ts: npm trusted publisher allows `stage publish` only — CI stages, a maintainer approves with 2FA (`npm stage approve`), so repo + CI compromise alone cannot make a package live** | go/py: repo + CI compromise together could still publish — OSS-024 wants signing keys outside the repo; go signing skipped (#8) |
| C7 | **Secrets in history** | Credential leak on publish | gitleaks full history in readiness, clean on all repos; `IDT-006` grep | History-vs-snapshot decision #2 |

### D. Why a fork cannot inherit trust (OSS-015/016/017)

A DNSid identity is established by three things the software does not contain: control of the DNS zone
(publishing `_dnsid.<domain>`), possession of the operational and entity private keys, and the status the
registry/log publishes for that identity. The SDK is a verifier and a signer *for keys you give it*.
Cloning, forking, or modifying it yields a program that can verify others and sign with the operator's
own keys — exactly what the official build does. It cannot produce a valid `sg` for someone else's record,
serve their JWKS from their domain, or alter their status. Software authenticity (C1) and agent identity
(A1) are therefore independent properties; compromising the first does not grant the second.

## Out of scope for the SDK (belongs to the hosted-service review)

Registry API abuse, rate limiting, tenant isolation, account takeover, status-endpoint availability,
transparency-log operation, witness operation, enrolment/domain-control verification (IDT-003/004),
server-side logging (LOG-*), autonomous-agent controls (AGN-*), free-tier abuse (FRE-*). The SDK's exposure
to these is as a client: it treats every response as untrusted until verified against bundled roots or
the record's own keys.

## Open items surfaced by this model

| Item | Where tracked |
|---|---|
| Plaintext local keys (B1) | Decision #12 |
| go release signing and provenance (C1, C6) | Fix #8 (skipped by decision; ts done 9/22) |
| Independent pentest of verification path (A8) | Decision #8 |
| Confusable package names (C2) | Fix #13 |
| Single-approver merges (C5) | Consider `required_approving_review_count: 2` for trust-path files — not raised before; add to decision #7 |
| Named security owner for advisory response (all) | Decision #7 |
