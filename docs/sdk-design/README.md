# DNSid SDK Design Documents

This directory contains the DNSid SDK design documents.

The SDK lifecycle profile keeps deployment workflow, current protocol status,
and verified lifecycle-history state separate. The shared reducer is defined in
[`06-log-bindings.md`](06-log-bindings.md), managed cross-system coordination in
[`05-transport-and-registry.md`](05-transport-and-registry.md), and C2SP-specific
stream rules in [`11-c2sp-tlog-binding.md`](11-c2sp-tlog-binding.md).

This is a conservative managed-service and SDK profile over the current base
protocol draft. It does not claim that every conforming DNSid implementation
must make the same choices, and no base-protocol edit is required before
implementing it. Concrete C2SP semantics remain requirements of the mutable
C2SP log-method specification and its SDK binding.

Implementation coverage and the 2026-10-27 release review are tracked in
[implementations/README.md](implementations/README.md), including tested release
commits, validation results, and remaining gaps.

The documents are organized by SDK responsibility:

- DNSid core remains centered on `IdentityManager`.
- RFC and external-spec helpers are separate profiles built on top of DNSid
  identity verification.

## Document Set

| Document | Scope |
|---|---|
| [01-core-identity-manager.md](01-core-identity-manager.md) | DNSid protocol implementation: TXT records, JWKS, domain verification, status checks, DNSSEC, lifecycle logs, cache, key provider. |
| [02-rfc9421-http-message-signatures.md](02-rfc9421-http-message-signatures.md) | RFC 9421 request signing and opt-in `Accept-Signature` response authentication using DNSid identity and JWKS discovery. |
| [03-jose-jwt-jws.md](03-jose-jwt-jws.md) | JOSE profile for JWT and JWS helpers using DNSid identity and key discovery. |
| [05-transport-and-registry.md](05-transport-and-registry.md) | SDK-managed HTTPS transport and registry control-plane workflows. |
| [06-log-bindings.md](06-log-bindings.md) | Shared `Log`, `LogReader`, `LogRegistry`, `DomainLog`, and lifecycle-event contracts. |
| [07-protocol-data-types.md](07-protocol-data-types.md) | Shared DNSid data structures and wire profiles. |
| [08-open-questions.md](08-open-questions.md) | Open design questions. |
| [09-oidc-federation.md](09-oidc-federation.md) | OIDC federation profile for JWT Bearer assertions, token exchange, and token verification using DNSid identities. |
| [10-web-bot-auth.md](10-web-bot-auth.md) | Web Bot Auth request signing and verification, with signed-directory serving and verification, using RFC 9421 primitives and DNSid identity binding. |
| [11-c2sp-tlog-binding.md](11-c2sp-tlog-binding.md) | C2SP transparency-log binding: references, envelopes, split signing, prepared submission, tiled-log verification, policy, witnesses, and completeness. |
| [12-configuration-loading.md](12-configuration-loading.md) | Configuration sources: environment variable schema, deployment file, merge rule, and convenience constructors. Loaders parse; constructors default. |
| [conformance/](conformance/) | Language-neutral RFC 9421 signature-base, lifecycle reducer, snapshot, and binding-selection vectors shared by SDK implementations. |

## Configuration

[`DnsidConfig`](01-core-identity-manager.md#initialization) is the single core
configuration entry point: optional `identity` publication settings, shared
`verification` settings (including `trustedEntities`), and `transport`
deployment settings. Omitting `identity` yields a verification-only manager
with the same sections and defaults. Key providers may be injected or selected
through [key-source configuration](12-configuration-loading.md#operational-key-source-selection);
log registries remain injectable.
The initial acceptance surface is a static entity allowlist with optional current
entity-key pins; custom evaluators and remote policy services are deferred.
Registry clients, log-trust factories, and application profiles retain ownership
of their own configuration. Environment variables, the deployment file, and
DNSid CLI directories are configuration sources defined in
[12](12-configuration-loading.md): loaders return only what the source
contains, constructors apply every default and validation, and convenience
constructors are `Load → Merge → Construct` with no logic of their own. All
constructors share one initialization path, and obsolete configuration is
replaced directly, without compatibility adapters.

These SDK configuration and acceptance contracts do not change protocol wire
behavior. Implementation trackers record reviewed release baselines and remaining
gaps, not claims of complete coverage. Replacing the public constructors and
configuration types is a breaking SDK API change, with no compatibility shims.
Such changes require a full review against the settled contract; subsequent
release reviews follow
[the implementation review procedure](AGENTS.md#updating-sdk-implementation-coverage).

## Shared Profile Contracts

### Profile configuration ownership

Profile constructors MUST validate and independently snapshot configuration
values, including nested settings, before network work. Later mutation of the
caller-supplied configuration or a configuration accessor's result MUST NOT
change an existing profile's signing or verification policy. Changing policy
requires a new profile. Injected resolvers, key providers, and transports remain
dependencies; this rule does not require copying them.

### Identity resolution

Profiles that only verify counterparties depend on this narrow core contract:

```
INTERFACE IdentityResolver
  VerifyDomain(domain: string, peerCert?: TLSCertificate) -> VerifiedDomain
END
```

`IdentityManager` satisfies `IdentityResolver`. Bindings may expose it as an
interface, protocol, trait, or function.

Profiles requiring an explicit evidence refresh use this additional capability:

```
INTERFACE RefreshingIdentityResolver EXTENDS IdentityResolver
  RefreshDomain(domain: string, peerCert?: TLSCertificate) -> VerifiedDomain
END
```

`IdentityManager` MUST implement `RefreshingIdentityResolver`.
[`RefreshDomain`](01-core-identity-manager.md#refreshdomaindomain-string-peercert-tlscertificate---verifieddomain)
performs full identity verification without reusing the manager's cached identity
result. It preserves all trust, current-peer, acceptance, and freshness checks.
Other profiles continue to depend only on `IdentityResolver`; WBA uses the
refresh capability for its bounded key-mismatch retry. Profiles MUST NOT access
an injected resolver's cache or compose eviction and verification themselves.

JWS `kid` values and the DNSid HTTP Message Signature profile's `keyId`
parameters use `{domain}#{kid}`. JWT headers do not; JWT signer domain comes
from `iss`. `ParseKeyId` splits on the first `#`, requires both sides,
normalizes the domain with `NormalizeFQDN()`, and rejects a `kid` side containing
`#`. `KeyProvider` key IDs therefore MUST NOT contain `#`.

Application-layer verify helpers that authenticate DNSid counterparties call
`VerifyDomain(signerDomain, peerCert)` before accepting signatures. Every binding
MUST expose a per-invocation route for trusted application-peer evidence (an
option, native request/context, or equivalent). Pass it through HTTP, JWT/JWS,
and DNSid-subject OIDC verification, including cache hits. Missing evidence fails
when `fl=mtls`; endpoint certificates, token claims, or a previous invocation's
peer are not substitutes. Profile signatures shown without this context are
abbreviations, not permission to omit the check. JWT verification also needs a
trusted expected audience independent of local-identity construction; OIDC
already takes its explicit audience in verification options. For the draft 01
behavior selected by `dnsid-draft-01` or pre-RFC `DNSid1`, application
signatures use the verified agent/runtime JWKS selected from `ku`; the TXT
record `sg` is verified separately with the accountable-entity JWKS selected
from `ek`. Profiles such as Web Bot Auth may define different
`keyid` semantics while still binding discovered keys to a verified DNSid
domain. Status freshness follows `config.verification.statusCheckInterval`.
Bilateral ISSUANCE binding is part of draft 01 identity verification;
operation-level `logchk` enforcement is caller policy, not automatic.

A successful `VerifyDomain` return means all profile-mandatory baseline checks
succeeded and status is `ACTIVE` under the configured freshness policy. Any
configured [counterparty acceptance](01-core-identity-manager.md#counterparty-acceptance)
must also succeed for that invocation, including cache hits. Without a configured
policy, no entity acceptance decision is made. This does not grant application
permissions or prove a request signature; profiles and applications still enforce
signature, audience, replay, and authorization requirements. Paths that do not
verify a DNSid subject (such as explicitly selected issuer-only OIDC or a
separately offered generic WBA verifier) cannot claim to satisfy DNSid entity
acceptance. The DNSid WBA profile requires subject verification and configured
acceptance; it never falls back to directory-only verification.
Permanent verification errors are rejected; transient errors are indeterminate.
SDK verification helpers MUST NOT automatically fail open. An application may
choose an explicit fallback path, but that path MUST NOT return, construct, or
represent a successful `VerifiedDomain`. Assurance tiers may tighten status
freshness, DNSSEC, or complete-log requirements, but MUST NOT omit mandatory
identity binding or continuity checks while describing the result as verified.

## Verification Dependencies

A verifier can authenticate a signer without prior bilateral enrollment, using
public DNS and authenticated HTTPS verification resources, subject to configured
trust and freshness policy. This is not offline or DNS-only verification.
`VerifyDomain` uses profile-required key, status, and lifecycle-log evidence;
see [01: VerifyDomain](01-core-identity-manager.md#verifydomaindomain-string-peercert-tlscertificate---verifieddomain).
The default `statusCheckInterval=0` requires a status fetch on every invocation.
Cached evidence does not remove freshness, current-peer, or acceptance checks,
and unavailable mandatory evidence must not produce successful verification.

## Presentation Naming and Transport

Reserve **Web Bot Auth** and **WBA** for the RFC 9421 profile in
[10](10-web-bot-auth.md). JWT bearer authentication, including an Agent Identity
Assertion (AIA) helper, is a separate application profile. Its public names,
examples, and reference documentation MUST identify it as JWT bearer
authentication, not Web Bot Auth. A name change does not make its claims or
audience rules interchangeable with the [JOSE profile](03-jose-jwt-jws.md).

HTTP message signatures can coexist with bearer authentication. Their signing
helpers MUST preserve an existing `Authorization` field. JWT bearer transport
uses that field only when explicitly selected by the caller and MUST reject an
existing field instead of replacing it; see
[03: HTTP Bearer Transport](03-jose-jwt-jws.md#http-bearer-transport).
SDK documentation MUST NOT claim that every DNSid application profile avoids
`Authorization` or that bearer tokens authenticate HTTP method, URI, or content.

Request signing alone does not provide mutual DNSid authentication. The opt-in
[negotiated response profile](02-rfc9421-http-message-signatures.md#dnsid-negotiated-response-profile)
adds client `Accept-Signature` preparation, server response signing, and mandatory
client verification against a locally expected DNSid domain and a fresh request
challenge. An enabled client rejects missing or invalid signatures, including on
HTTP error responses. HTTPS remains required; response authentication happens
after request data is sent. These are design requirements, not claims that the
SDK implementation baselines already provide negotiation or response verification.

## Verification Resource Budgets

A verification invocation MUST have a finite overall time budget, exposed through
the binding's native cancellation/deadline mechanism or equivalent options.
Document a finite default when the caller supplies none. DNS, HTTPS redirects,
retries, signature candidates, log resources, and recursive migration verification
share the remaining budget; no child operation restarts the full timeout.
Per-request timeouts alone are insufficient. Shared/coalesced work must preserve
each caller's deadline and must not continue unbounded after all callers cancel.

Bindings must document and enforce finite input/response/allocation limits, or
state the hosting-layer preconditions that enforce them before the SDK does
expensive work. Standalone use needs safe bounds if no host supplies them.
Exceeding a bound or deadline never permits a successful partial verification,
skipped mandatory evidence, or stale-cache fallback. These are local resource
policies, not new wire fields or universal byte/time constants.

## Draft Version Contract

While version 1 remains an Internet-Draft, released SDKs verify the immutable
submitted numbered selectors they support and also verify `DNSid1` using the
latest submitted draft fully supported by that release. The exact parsed `v=`
value is always preserved in signed canonical bytes. SDKs and registries publish
only the current numbered selector, initially `dnsid-draft-01`; they do not
publish `DNSid1`, dated selectors, or work-in-progress draft selectors. When
version 1 becomes an RFC, `DNSid1` freezes to the RFC behavior and becomes the
version 1 publish selector.

## Conformance Metadata

Each released binding MUST expose one immutable, machine-readable conformance
value through an idiomatic public constant or read-only accessor:

```
TYPE SDKConformance
  publishProfile: string
  verificationProfiles: map[string]string
  specificationStatus: "internet-draft" | "rfc"
  logBindings: map[string]string
  knownDeviations: []string
END
```

`publishProfile` is the exact numbered selector emitted by the release.
`verificationProfiles` maps every accepted wire selector to the exact immutable
numbered behavior profile it selects; during the Internet-Draft period this
includes the current `DNSid1` mapping. `logBindings` maps each concrete method
to its exact profile and dependency revisions. `knownDeviations` is empty when
none are known and otherwise contains stable, human-readable descriptions.
Bindings MAY expose additional package or build version fields, but MUST NOT
replace these exact protocol-facing values with a package version.

## Dependency Direction

The important boundary is that standards profiles depend on DNSid core, while
DNSid core does not depend on any application authentication profile.

```text
01 core IdentityManager
  -> 07 protocol data types
  -> 06 log bindings
  -> shared key, DNS, HTTPS, cache interfaces

02 RFC 9421 HTTP Message Signatures
  -> core IdentityResolver
  -> KeyProvider

03 JOSE JWT/JWS
  -> core IdentityResolver
  -> KeyProvider

05 transport and registry
  -> IdentityConfig, TransportConfig, and protocol data types

09 OIDC federation
  -> core IdentityResolver
  -> KeyProvider
  -> JOSE JWT/JWS primitives
  -> transport helpers

10 Web Bot Auth
  -> core IdentityResolver
  -> RFC 9421 primitives
  -> KeyProvider (signing only)
  -> JWKS/JWK data types
  -> SSRF-safe HTTPS discovery transport

11 C2SP transparency log binding
  -> 06 shared log bindings
  -> 07 protocol data types
  -> KeyProvider
  -> transport helpers

12 configuration loading
  -> 01 core IdentityManager constructor
  -> 05 RegistryClient and TransportConfig
  -> 11 log-trust factories
```

Configuration loading sits above core: it constructs an `IdentityManager` and
its log registry, so core never imports it. Bindings place it in a separate
package when their module system requires acyclic imports.

## Naming

Use `IdentityManager` for the main DNSid facade. When a smaller dependency is
needed by a profile, use names such as:

```text
IdentityResolver
IdentityVerifier
VerifiedDomainProvider
```
