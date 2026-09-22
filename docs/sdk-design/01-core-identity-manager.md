# DNSid SDK Core: IdentityManager

This document defines the DNSid protocol implementation exposed by `IdentityManager`.
`IdentityManager` is the primary SDK facade for managing the local DNSid identity
and verifying external DNSid identities.

The core module answers one question:

> Given a domain, can DNSid establish a verified identity and a verified signing
> key set for that domain?

Configured counterparty acceptance is a separate SDK-local gate after that
verification, not an additional protocol claim or application authorization.

Application authentication standards such as JWT, JWS, and HTTP Message
Signatures call into this module but are specified in their own profile
documents. Connection-specific policy is never satisfied by cached identity
evidence: when `fl=mtls`, the current invocation's peer certificate is checked
even when `VerifyDomain` otherwise returns a cached result.

## IdentityManager

The `IdentityManager` is the primary way runtimes and services incorporate the DNSid Protocol. All protocol operations flow through it.

### Initialization

```
IdentityManager(config?: DnsidConfig, deps?: IdentityManagerDependencies) -> IdentityManager
```

`DnsidConfig` is the single core configuration entry point. Its sections have
separate responsibilities; configuration contains data, while runtime objects
are supplied through `IdentityManagerDependencies`. This is a logical dependency
bundle; bindings MAY use idiomatic dependency injection such as functional
options rather than requiring a new container type. All initialization paths
MUST use the same configuration validation, defaults, and dependency setup.
Replace obsolete configuration directly; no compatibility adapters or parallel
legacy configuration model are required.

| Section | Type | Default | Responsibility |
|---|---|---|---|
| `identity` | IdentityConfig | absent | The local identity's publication settings. |
| `verification` | VerificationConfig | default settings | Protocol verification and counterparty acceptance. |
| `transport` | TransportConfig | platform defaults | SDK-managed DNS and HTTPS deployment settings. |

A manager without `config.identity` is verification-only and rejects a
supplied `deps.keyProvider` or `deps.entityKeyProvider` with `ArgumentError`;
neither has a consumer without a local identity. A local-identity manager
requires `deps.keyProvider`. No dummy domain, status URL, log reference, or key is
needed for verification; application audiences belong in profile configuration,
not a manufactured local identity. Bindings MAY add an idiomatic alias such as
`NewVerifier` or `for_verification` that delegates to this constructor with
`identity` omitted. There is no separate `VerificationOptions` or mixed
`ProtocolConfig` surface.

A verification-only manager supports `VerifyDomain`, `LoadDomainLog`, cache
eviction, and verifier/profile construction. Operations that act as a local
identity or require private-key access, local record construction, event
signing, registry publication, or lifecycle mutation MUST fail with
`ArgumentError` before performing work. Verification still fails closed when
the selected record profile requires a read-side dependency, such as a
supported lifecycle-log reader, that was not supplied.

#### IdentityConfig

`config.identity` contains only local publication settings:

| Field               | Type     | Required | Description |
|---------------------|----------|----------|-------------|
| `domain`            | string   | yes      | FQDN of the DNSid identity (e.g. `billing-agent.acme.example`). Normalized with `NormalizeFQDN()` on construction. |
| `governanceId`      | string   | yes      | Registrant/accountable-entity domain (`gi` tag). For the draft 01 behavior, lowercase ASCII DNS domain only, normalized with `NormalizeFQDN()`. If not equal to or a parent of `domain`, the bilateral ISSUANCE event must prove the relationship. |
| `logRef`         | string   | yes      | Log reference for the `lr` tag. Format: `{method}:{entry-ref}` where method matches `[a-z][a-z0-9-]*` (e.g. `algorand:ADDR`). See [LogRegistry](06-log-bindings.md#logregistry) for parse rules. |
| `statusUrl`         | string   | yes      | HTTPS URL for the identity's status endpoint (`su` tag). |
| `policyFlags`         | string   | no       | Comma-separated policy flags for the `fl` tag (e.g. `mtls,logchk`). |
| `maxKeyAge`         | string   | no       | Maximum signing key age for the `ka` tag. Permitted values: `24h`, `7d`, `30d`, `90d`. |
| `ekUrl`             | string   | draft 01 publishing: yes | HTTPS URL for the accountable-entity record-signing JWKS endpoint (`ek` tag). For the draft 01 behavior, the host must equal `governanceId` or be beneath it with DNS-label boundary matching. The protocol defines no default path. |
| `kuUrl`             | string   | draft 01 publishing: yes | HTTPS URL for the agent/runtime JWKS endpoint (`ku` tag). For the draft 01 behavior, host must equal `domain`. The protocol defines no default path. |
| `publishProfile`    | string   | no       | `_dnsid` behavior profile to emit when creating or registry-publishing new records. Defaults to `dnsid-draft-01` while version 1 remains an Internet-Draft. Must be in `SupportedPublishProfiles`; verification ignores this setting and dispatches from the exact DNS `v=` selector. |
| `capabilitiesUrl`   | string   | no       | HTTPS URL for the capabilities document (`cu` tag). AGENTS.md or Agent Card. |

While version 1 remains an Internet-Draft, released SDKs create records only
with the latest fully supported submitted numbered selector. Support for an
unpublished next draft remains off the release branch. Verification accepts the
supported numbered selectors and pre-RFC `DNSid1` according to
[Version String Convention](07-protocol-data-types.md#version-string-convention).

#### VerificationConfig

| Field | Type | Default | Description |
|---|---|---|---|
| `statusCheckInterval` | number (seconds) | 0 | Maximum age of cached status before re-fetching `su`. Zero re-fetches on every invocation (spec-strict interactive verification). A positive value explicitly accepts that revocation may remain unseen for this interval; `EvictDomain` can shorten that window. Must be finite and non-negative, not a Boolean. |
| `dnssecMode` | DNSSECMode | `auto` | `auto`, `validated`, or `required`; `FAILED` always aborts. See [DNSSECMode](#dnssecmode). |
| `trustedEntities` | []TrustedEntity | absent | Optional counterparty allowlist; absence makes no entity acceptance decision, `[]` denies all. See [Counterparty Acceptance](#counterparty-acceptance). |

#### Configuration Ownership and Loading

`config.transport` uses [TransportConfig](05-transport-and-registry.md#transport-responsibilities).
It configures default SDK networking, not TXT contents or entity approval.
Registry endpoint/credentials remain registry-client configuration. JOSE, OIDC,
and HTTP signature settings remain profile-owned. Log and witness trust remain
explicit inputs to log-verification factories, whose resulting `LogRegistry`
is injected. Neither a local `logRef` nor registry URL implicitly selects trust.

Constructors MUST validate and snapshot static configuration, including nested
lists, before network work. Reject invalid values with `ArgumentError`. Where
the binding's configuration representation can carry them (JSON documents,
dictionaries, dynamically typed objects), also reject unknown fields and
mistyped values; statically typed configuration satisfies this by construction.
Explicit JSON config loaders SHOULD reject duplicate members where the platform
parser makes that available.
Defaults apply only to omitted fields; explicit empty allowlists and zero
intervals retain their meaning. Each setting has one home: verification settings
MUST NOT also appear under `identity`, and transport settings MUST NOT also
appear in dependencies.

Constructors MUST NOT implicitly read files or environment variables. Explicit
loaders MAY, and then follow one precedence rule: explicit caller settings win
over loaded values, omission is distinct from explicit zero/empty, and policy
arrays replace rather than merge. Loading local identity data MUST NOT infer
accepted counterparties from its `governanceId`, registry, TLS CA, or log.
Replacing security policy means constructing a new manager; see
[IdentityCache](#identitycache).

##### Deployment File

Bindings that offer a file loader for verifiers MUST use this shape. It is an
umbrella-package convenience, not a core type: each section maps 1:1 onto an
existing type or factory with no cross-section logic or inference.

```json
{
  "dnsid": { "verification": { "dnssecMode": "required", "trustedEntities": [{ "governanceId": "acme.example" }] } },
  "logTrust": { "managed": "identity-digital" }
}
```

| Section | Maps to |
|---|---|
| `dnsid` | `DnsidConfig`, validated as above. |
| `logTrust` | Exactly one of `managed` ([managed catalog](11-c2sp-tlog-binding.md#dnsid-managed-trust)), `profile` (inline [trust profile](11-c2sp-tlog-binding.md#trust-profiles) document), or `policyUrl` ([generic factory](11-c2sp-tlog-binding.md#verification-convenience-factory)). Zero or more than one fails with `ArgumentError`. |

The loader returns `(DnsidConfig, IdentityManagerDependencies)` with
`logRegistry` populated; the caller passes both to the ordinary constructor.
Runtime objects such as checkpoint stores and injected fetchers stay code-only.
Profile settings (`jose`, `oidc`, `webBotAuth`, `httpMessageSignatures`) are not
sections today; add them as siblings when a consumer needs them.

Injected resolvers/fetchers are caller-owned runtime infrastructure. A
caller-supplied HTTP client, session, or transport that the SDK wraps for its
HTTPS fetches counts as an injected HTTPS fetcher for these rules, even when
the SDK adds its own safety layer around it. Transport settings configure
default implementations, not mutations of injected objects.
Reject an explicit transport setting only when it has no SDK-managed consumer
in the component being constructed. `dnsServer` configures both the default TXT
resolver and default HTTPS fetcher: with only one injected, it still configures
the other; reject it when both are injected. `caBundlePath` and
`privateAddressHosts` configure the default HTTPS fetcher only, so reject them
when that fetcher is injected. Do not inspect or
negotiate injected dependencies' configuration. Callers take responsibility for
injected components; settings for remaining SDK-managed components still apply.

Verification-only example (the caller separately supplies an explicitly trusted
read-side `logRegistry`):

```json
{
  "verification": {
    "dnssecMode": "required",
    "statusCheckInterval": 0,
    "trustedEntities": [{ "governanceId": "acme.example" }]
  }
}
```

#### Counterparty Acceptance

Acceptance is verifier-local SDK policy, not a DNSid wire field or application
authorization. Protocol verification establishes identity and accountability;
acceptance selects counterparties; applications separately authorize actions.
Trusting log infrastructure or observing `ACTIVE` status does not approve an
entity. Setting local `identity.policyFlags` does not configure local acceptance.

```
TYPE TrustedEntity
  governanceId: string
  entityKeyThumbprints?: []string
END
```

`trustedEntities` accepts only an exact match of
`record.Profile().GovernanceID(record)` against one configured entry. Configured
identifier validation and normalization follow the selected
[identity record profile](07-protocol-data-types.md#identity-record-behavior-profiles);
reject invalid identifiers and duplicate normalized entries at construction.
The currently supported draft 01 profile defines domain-only policy identifiers.
Never rewrite signed record fields for acceptance comparison.
There are no wildcard, suffix, or transitive entity matches. A trusted entity's
agents may be outside its DNS namespace: the verified bilateral binding, not
agent naming, establishes accountability. An empty list denies all. Future
modes (denylists, evaluators) are not reserved; add a sibling field when needed.

Agent-FQDN filtering remains application or gateway authorization policy. An
application may additionally restrict authenticated signer domains with its own
exact or wildcard rules; such rules neither replace entity acceptance nor follow
implicitly from an allowed `gi`. Authorize the domain bound to the authenticated
request, not an unverified caller-supplied name.

If `entityKeyThumbprints` is present, it must be a non-empty list of distinct
canonical unpadded base64url SHA-256 RFC 7638 JWK thumbprints (32 decoded bytes).
The verified current entity record-signing key (`VerifiedDomain.signingKey`)
MUST match one pin as well as the exact `gi`. A `kid`, `ek` URL, operational key,
or log key is not a pin. Pins constrain current keys, not historical anchors;
no rotation automatically expands them, even if a supported profile proves
continuity. Multiple pins permit an explicit transition. A `governanceId`-only entry accepts
keys established by current protocol verification; it is not proof of unchanged
real-world ownership.

Pins are suitable when the relying party can coordinate entity-key changes,
especially with self-managed key custody. A pin identifies key material, not
who holds the private key. Registry-custodied entity keys may rotate independently
of relying-party configuration, causing acceptance to fail until pins are
explicitly updated; the SDK MUST NOT learn replacement pins automatically. See
[registry custody considerations](05-transport-and-registry.md#registry-custody-and-pins).

To enroll a pin, compute the RFC 7638 thumbprint of `signingKey` from a successful
protocol verification and confirm it through an authenticated operator channel
before adding it to policy. Discovery alone is not independent approval. Existing
acceptance remains enforced during normal verification; enrollment is a separate,
explicit operator workflow, never an automatic retry without policy after denial.

The initial acceptance surface is static allowlist/key-pin configuration only.
Custom evaluators, remote policy services, and policy composition are deferred
until a concrete consumer requires them; no evaluator interface or decision
object is required. Applications may enforce additional restrictions separately,
but those checks cannot replace configured SDK acceptance or protocol verification.

`VerifyDomain` MUST run configured acceptance after mandatory protocol and
current-peer checks, before every successful return, including cache hits and
status refreshes. Checks are per invocation, not shared/coalesced with identity
lookup work. A nonmatching governance ID or key raises permanent
`CounterpartyNotAccepted`; never fall back to unrestricted verification. Reuse
existing domain normalization and JWK thumbprint primitives; bindings SHOULD
compute the entity-key thumbprint once at verification time and retain it as
evidence rather than recomputing it on every cache hit. The check does not
perform network work or mutate verified evidence. It is not proof that a request
signature has passed: profiles still perform signature and replay checks.

Without `trustedEntities`, protocol verification proceeds without making a
counterparty acceptance decision. `VerifiedDomain` remains identity evidence,
not a durable `trusted=true` assertion; policy decisions MUST NOT be cached in
it. Its lifetime does not promise continued acceptance. Applications requiring a
new decision invoke verification again. This also applies when a workflow calls
`VerifyDomain` on the local identity: there is no self-acceptance exception in
that public API. Control-plane publication confirmation instead uses the internal
protocol-only path described in
[registry-managed publication](05-transport-and-registry.md#awaitregistrymanagedpublicationregistryclient-registryclient---publishedrecord).
It does not approve a counterparty or modify the configured policy.

SDK validation MUST cover:

| Scenario | Required result |
|---|---|
| Same verification settings with or without local identity configuration | Identical verification behavior and defaults. |
| Mutate caller config/lists after construction | Manager retains its validated snapshot. |
| Unknown setting, invalid pin, or duplicate normalized entity | Construction fails before network work. |
| `dnsServer` with only the TXT resolver injected | Default HTTPS fetcher uses the setting; injected resolver is unchanged. |
| `dnsServer` with only the HTTPS fetcher injected | Default TXT resolver uses the setting; injected fetcher is unchanged. |
| `dnsServer` with both consumers injected, or `caBundlePath`/`privateAddressHosts` with HTTPS fetcher injected | Construction fails before network work. |
| `privateAddressHosts` entry that is not a hostname or leading-dot suffix (IP literal, port, scheme, path, credentials) | Construction fails before network work. |
| Deployment file with zero or multiple `logTrust` variants | Loader rejects with `ArgumentError`. |
| Local publisher absent from allowlist | Publication confirmation can succeed on valid protocol evidence; public `VerifyDomain(localDomain)` still rejects. |
| Acceptance denial | Error's structured fields and message carry only observed values (verified ID, key thumbprint); no configured allowlist entry or pin is echoed. Validate structurally: assert the observed fields, and assert that a configured value which is not a substring of any observed value does not appear. Configured values may legitimately be substrings of observed ones (a parent domain), so a bare substring check is not a valid test. |
| Policy omitted versus explicit empty allowlist | No acceptance decision versus reject all. |
| Exact allowed `gi`, valid bilateral binding for an unrelated agent domain | Accept after all mandatory checks. |
| Child/suffix/lookalike `gi`, or missing/invalid binding despite an allowed name | Reject. |
| Correct `gi` but different current entity key; pin matches only `ku` or historical key | Reject. |
| Current entity key matches one configured pin | Accept only if all remaining checks succeed. |
| Fresh protocol verification succeeds with positive TTL, then acceptance denies | Invocation fails; eligible identity evidence remains cached. Next invocation reuses it subject to expiry/status rules and reevaluates acceptance. |
| Cached identity status refresh succeeds, then acceptance denies | Invocation fails; refreshed status and its acquisition time remain cached without extending identity expiry. Acceptance is reevaluated next time; zero status interval still requires another refresh. |
| Denied identity is cached and no status refresh is due | Invocation still rejects; the cache hit does not bypass acceptance. |
| Concurrent invocations share protocol verification work for a denied identity | Every invocation rejects; coalescing does not bypass acceptance. |
| Identity evidence expires before return | Reject; recheck freshness after acceptance. |
| Different acceptance policies share a cache backend or in-flight work | No cross-context reuse; no shared acceptance decision. |

### Initialization from DNSid CLI Configuration

Language bindings MAY provide a convenience initializer that constructs an
`IdentityManager` from local identity files written by the DNSid CLI. This is a
binding convenience only; it does not change protocol semantics or the
`IdentityManager` constructor contract.

The loader reads a DNSid identity directory, defaulting to the user's DNSid
config directory (`~/.dnsid` on Unix-like systems). The DNSid CLI writes a root
`config.json` pointer and a per-identity `<domain>/config.json`; testnet commands
such as `dnsid testnet agent ensure` and `dnsid testnet run` may also write an
identity directory under `~/.dnsid-testnet/agents/<domain>` and expose it to child
processes as `DNSID_CONFIG_DIR`. Both config files use the same snake_case shape:

```json
{
  "server_url": "https://api.example",
  "agent_id": "ag_...",
  "domain": "agent.example.com",
  "governance_id": "example.com",
  "status_url": "https://api.example/api/v1/agent/agent.example.com/status",
  "ku_url": "https://agent.example.com/.well-known/jwks.json",
  "ek_url": "https://example.com/.well-known/dnsid/entity.jwks",
  "entity_key_path": "/secure/keys/example.com.jwk",
  "log_ref": "c2sp-tlog:public:https://log.dnsid.ai#Q2hWbW5Ta0x5R0JtM3B0dw",
  "publish_profile": "dnsid-draft-01",
  "max_key_age": "90d",
  "environment": "production"
}
```

Relevant files:

| Path | Purpose |
|---|---|
| `config.json` | Current local identity pointer/configuration when reading the root DNSid directory. |
| `<domain>/config.json` | Per-identity configuration when reading an identity directory directly. |
| `<domain>/private.pem` or `private.pem` | Optional binding-supported PKCS#8 PEM Ed25519 private key. |
| `<domain>/private.jwk` or `private.jwk` | Local signing key material for the selected identity. Bindings MAY require this format. |
| `<domain>/public.jwk` or `public.jwk` | Optional public key material; implementations may derive it from `private.jwk` when absent. |

The loader maps DNSid CLI configuration into the existing SDK configuration
groups:

| CLI value | SDK value |
|---|---|
| `domain` | `DnsidConfig.identity.domain` |
| `governance_id` | `DnsidConfig.identity.governanceId` |
| `status_url` | `DnsidConfig.identity.statusUrl` |
| `ku_url` | `DnsidConfig.identity.kuUrl` |
| `ek_url` | `DnsidConfig.identity.ekUrl` |
| `entity_key_path` | Local accountable-entity `KeyProvider` |
| `log_ref` | `DnsidConfig.identity.logRef` |
| `publish_profile` | `DnsidConfig.identity.publishProfile` |
| `max_key_age` | `DnsidConfig.identity.maxKeyAge` |
| `server_url` | Registry base URL used only to derive `status_url` when `status_url` is absent. |

For self-managed identities, the DNSid CLI persists these publication fields
from the registry's registration response rather than deriving deployment
defaults locally. Bindings that support client-controlled publication should
consume the persisted values without replacing them with local defaults.

If `status_url` is omitted and `server_url` is present, the loader MAY derive
the local status URL from the registry's documented status endpoint format. This
derived value is local initialization behavior only; verification of external
identities still uses the signed `su` value from DNS.

The conceptual loader signature is:

```
IdentityManagerFromDnsid(directory: string, config: DnsidConfig, deps: IdentityManagerDependencies) -> IdentityManager
```

Bindings expose these inputs idiomatically. Loaded publication fields supply
defaults; supplied `config` and key providers win per the
[loader precedence rule](#configuration-ownership-and-loading). Apply the
overlay before normalizing, validating, or deriving any field, so a caller can
supply values the persisted configuration lacks. Where the CLI's on-disk key
layout is keyed by domain, key files are located using the effective
`config.identity.domain` after overlay, not the persisted value; a caller
supplying a different domain therefore also supplies, or points at, that
domain's key files.

The loader returns the same result as explicitly constructing
`IdentityManager(config, deps)`, mapping the CLI publication fields into
`config.identity` and supplying a file-backed `deps.keyProvider` from the
selected identity's key files. The CLI's flat snake_case format is an explicit
adapter input, not an alternative core config schema. Verification settings are
never inferred from local publication data.

`IdentityManagerDependencies` fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `logRegistry` | LogRegistry | draft 01 verification: yes | Registry of lifecycle-log method readers/writers. |
| `dnsResolver` | DNSResolver | no | Resolver used for `_dnsid` TXT lookups. |
| `httpsFetcher` | HTTPSFetcher | no | HTTPS JSON fetcher used for JWKS and status endpoint retrieval. Language bindings may provide a default fetcher or require injection. |
| `cache` | IdentityCache | no | Cache for verified domain results, isolated to the manager's verification context; see [IdentityCache](#identitycache). |
| `keyProvider` | KeyProvider | local identity: yes | Local operational signer; absent for verification-only use. |
| `entityKeyProvider` | KeyProvider | setup/log writes only | Accountable-entity key provider for `_dnsid` signing and entity lifecycle events. Keep separate from the agent key provider. |

JWT freshness settings are specified in [03-jose-jwt-jws.md](03-jose-jwt-jws.md).
HTTP Message Signature freshness settings are specified in
[02-rfc9421-http-message-signatures.md](02-rfc9421-http-message-signatures.md).

`KeyProvider` — see [KeyProvider Interface](#keyprovider-interface). For the draft 01 behavior selected by `dnsid-draft-01` or pre-RFC `DNSid1`, the accountable-entity record-signing key (`ek`) is separate from the agent key (`ku`). `CreateTxtRecord` and entity lifecycle events require `entityKeyProvider`; application/profile signatures use the ordinary `keyProvider`. The current entity and agent public keys MUST be distinct by RFC 7638 JWK thumbprint.


`LogRegistry` — see [LogRegistry](06-log-bindings.md#logregistry). Required for full draft 01 verification because `VerifyDomain` checks bilateral binding and operational continuity through `lr`. Concrete bindings may provide a safe convenience factory that returns a ready-to-inject registry from explicit caller trust; the generic C2SP factory is defined in [Verification Convenience Factory](11-c2sp-tlog-binding.md#verification-convenience-factory). A separately named managed-service factory may instead make an explicit product trust decision by selecting reviewed embedded roots as defined in [DNSid-Managed Trust](11-c2sp-tlog-binding.md#dnsid-managed-trust); omitted generic trust MUST NOT select those roots implicitly. When provided for local identity management, the constructor may derive the local write log by calling `logRegistry.NewReader(config.identity.logRef)` and asserting `Log`; if the binding performs this eager derivation and the returned implementation does not satisfy `Log`, construction raises `ArgumentError`. Language bindings may alternatively defer the write-capability check until a log-writing method is called. When omitted, log-dependent read operations use `NoopLogReader` and fail if the selected profile, requested operation, record field such as `ka`, or local policy requires log evidence. Log-writing methods require a write-capable local `Log`; missing or read-only local log configuration raises `ArgumentError`.

`DNSResolver` — see [DNSResolver Interface](#dnsresolver-interface). When supplied, `VerifyDomain` uses it for `_dnsid` TXT lookups. When omitted, a language binding may use a default implementation configured by `TransportConfig.dnsServer` when set, otherwise the host language/runtime resolver. `RegistryConfig.registryUrl` is control-plane configuration only and MUST NOT be used as an implicit DNS resolver for protocol verification.

`HTTPSFetcher` — language-agnostic abstraction for SDK-managed HTTPS JSON fetches used by `VerifyDomain` for the profile-selected TXT signature verification JWKS URI and `su`. It MUST enforce the TLS and redirect rules in [Protocol Data Types](07-protocol-data-types.md#tls-certificate). Language bindings may expose this as a fetch function, HTTP client, transport/session object, or another idiomatic dependency.

Internal fields (initialized on construction, not caller-supplied):

| Field           | Type            | Description |
|-----------------|-----------------|-------------|
| `config` | DnsidConfig | Validated immutable snapshot; `identity` absent for verification-only use, with the same `verification` and `transport` sections in either mode |
| `keyProvider` | KeyProvider | Supplied agent/runtime key provider; nil/absent for verification-only managers |
| `entityKeyProvider` | KeyProvider | Optional accountable-entity key provider from `deps`; required only for `_dnsid` signing and entity lifecycle events |
| `localLog`      | Log             | Local write log, derived from `logRegistry.NewReader(config.identity.logRef)` asserted as `Log` when available; nil for verification-only managers without local log writes |
| `logRegistry`   | LogRegistry     | Optional log registry; used during `VerifyDomain` to construct counterparty `LogReader` instances. Nil means log-dependent operations receive `NoopLogReader`. |
| `dnsResolver`   | DNSResolver     | Supplied or default DNS resolver. See [DNSResolver Interface](#dnsresolver-interface). |
| `httpsFetcher`  | HTTPSFetcher    | Supplied or default HTTPS JSON fetcher. Enforces protocol TLS and redirect rules. |
| `cache`         | IdentityCache   | In-memory cache initialized on construction; see [IdentityCache Interface](#identitycache). Holds verified domain results keyed by FQDN, evicting entries automatically at `VerifiedDomain.Expiry()`. |

---

### Core Methods

Log-writing methods, including `WriteSignedEvent`, setup flows, key rotation,
and revocation flows, require `localLog` to be a write-capable `Log`. If an
`IdentityManager` was constructed for verification-only use, no local log is
configured, or the configured `LogRegistry` produces only a read-capable
`LogReader`, these methods raise `ArgumentError` before writing.

Event signing is split from log submission so required signatures can be produced
by different SDK instances or machines. Canonicalization MUST exclude signature
fields (`sig`, `operationalCountersig`, and any profile-defined countersignature
fields), so adding one signature does not change the bytes signed by another.

#### `CanonicalizeLogEvent(event: LogEvent) -> bytes`

Returns the log-method-specific canonical bytes that all event signatures cover.
Requires a local log binding for `config.identity.logRef` (`Log` or `LogReader`),
but not write access.

```
FUNCTION CanonicalizeLogEvent(event: LogEvent) -> bytes
  logBinding = LocalLogBinding(config.identity.logRef) // Log or LogReader
  IF logBinding IS nil THEN
    RAISE ArgumentError("local log binding is required")
  END
  RETURN logBinding.Canonical(event)
END
```

#### `RequiredLogSignatures(event: LogEvent) -> []LogSignerRole`

Returns the profile-owned signer roles required before the event can be written.
It does not return log-method-owned additions. A concrete binding MUST add and
enforce any signatures required by that method without weakening or replacing
these profile-owned roles. For draft 01 core lifecycle events:

| Event | Required roles |
|---|---|
| `ISSUANCE` | `Entity`, `OperationalCountersignature` |
| `KEY_ROTATION` | `PreviousOperational` |
| other core lifecycle events | `Entity` |

In particular, `RequiredLogSignatures(KEY_ROTATION)` returns only
`PreviousOperational`. A concrete binding may separately require additional
proofs as part of its preparation, parsing, and verification rules; those roles
do not become base-profile requirements.

#### `SignEvent(event: LogEvent, role: LogSignerRole) -> LogEvent`

Adds the signature for one requested role using whatever matching local provider
this SDK instance has. This is the generic step used by local and remote signers;
it does not write to the log.

```
ENUM LogSignerRole
  Entity
  Operational
  OperationalCountersignature
  PreviousOperational
END

FUNCTION SignEvent(event: LogEvent, role: LogSignerRole) -> LogEvent
  canonical = CanonicalizeLogEvent(event)
  SWITCH role
    CASE Entity:
      event.sig = Base64url(entityKeyProvider.Sign(canonical))
    CASE Operational:
      event.sig = Base64url(keyProvider.Sign(canonical))
    CASE OperationalCountersignature:
      event.operationalCountersig = Base64url(keyProvider.Sign(canonical))
    CASE PreviousOperational:
      event.sig = Base64url(keyProvider.SignKey(event.previousOperationalKid, canonical))
  END
  RETURN event
END
```

`IdentityManager.SignEvent` is a convenience facade over a provider-explicit
signing primitive. SDKs MUST expose an equivalent lower-level operation for a
process that intentionally holds only one signer role:

```
FUNCTION SignEventWithProvider(event: LogEvent,
                               role: LogSignerRole,
                               keyProvider: KeyProvider,
                               logBinding: Log OR LogReader) -> LogEvent
  canonical = logBinding.Canonical(event)
  ValidateProviderMatchesEventRole(event, role, keyProvider)
  IF role == PreviousOperational THEN
    signature = keyProvider.SignKey(event.previousOperationalKid, canonical)
  ELSE
    signature = keyProvider.Sign(canonical)
  END
  RETURN AddRoleSignature(event, role, signature)
END
```

The bound log binding, not caller-supplied bytes, determines canonical content.
This operation does not require providers for any other role and never exports
private key material. If a method needs caller-supplied signed metadata that is
not represented by `LogEvent`, its binding-specific prepared-event signer is
used instead; see the
[C2SP transparency-log binding](11-c2sp-tlog-binding.md#prepared-event-model) for
one concrete design.

#### `WriteSignedEvent(event: LogEvent) -> LogRef`

Appends an already-signed lifecycle event. Implementations MUST reject events
missing any `RequiredLogSignatures(event)` field.

This generic method is available only when the binding can derive and reserve
all method-owned append metadata internally. It MUST fail before signing or
writing a later chained event when authoritative predecessor state has not been
reserved. C2SP callers use its prepared-event flow for every event after
genesis.

```
FUNCTION WriteSignedEvent(event: LogEvent) -> LogRef
  IF localLog IS nil THEN
    RAISE ArgumentError("local write log is required")
  END
  ValidateRequiredLogSignaturesPresent(event)
  RETURN localLog.WriteEvent(event)
END
```

#### `SignAndWriteEvent(event: LogEvent) -> LogRef`

Convenience helper for the single-process case. The input MAY already contain
some required signatures. The manager adds only missing signatures for roles it
is configured to produce, then calls `WriteSignedEvent`. If any required
signature is still missing, it fails before writing. Distributed signing flows
call `SignEvent` on each signing machine and then `WriteSignedEvent` once all
required signature fields are present.

```
FUNCTION SignAndWriteEvent(event: LogEvent) -> LogRef
  FOR each role IN RequiredLogSignatures(event)
    IF SignatureForRoleMissing(event, role) AND IsConfiguredForRole(role) THEN
      event = SignEvent(event, role)
    END
  END
  RETURN WriteSignedEvent(event)
END
```

---

#### `GetKeySet() -> JWKS`

Returns the local identity's agent public key set for publication at the `ku` endpoint. The endpoint MUST be served over HTTPS with a valid TLS certificate whose host matches the identity FQDN.

```
FUNCTION GetKeySet() -> JWKS
  key = keyProvider.SigningKey() // public key only, includes kid and alg for draft 01
  RETURN JWKS{ keys: [key] }                // draft 01 live endpoints expose exactly one current key
END
```

#### `GetEntityKeySet() -> JWKS`

Returns the accountable-entity public key set for publication at the `ek` endpoint. The endpoint host MUST equal `gi` or be beneath it with DNS-label boundary matching, and it MUST be served over HTTPS with a valid TLS certificate for the actual `ek` URI host.

```
FUNCTION GetEntityKeySet() -> JWKS
  key = entityKeyProvider.SigningKey()      // public key only, includes kid and alg for draft 01
  RETURN JWKS{ keys: [key] }                // draft 01 live endpoints expose exactly one current key
END
```

---

#### `CreateTxtRecord() -> string`

Builds and signs the `_dnsid` TXT record for publication at `_dnsid.{domain}`. The identity owner or its operator MUST set this DNS record. When using a registry, the registry may handle publication on the identity's behalf.

```
FUNCTION BuildUnsignedDnsIdTxtRecord(identity: IdentityConfig) -> DnsIdTxtRecord
  profileID = identity.publishProfile OR "dnsid-draft-01"
  profile = ResolveIdentityRecordProfile(profileID)
  IF profile == nil OR NOT profile.PublishAllowed() THEN
    RAISE ArgumentError("unsupported DNSid publish profile: " + profileID)
  END
  RETURN profile.BuildUnsignedRecord(identity, entityKeyProvider, keyProvider)
END

FUNCTION CreateTxtRecord() -> string
  record = BuildUnsignedDnsIdTxtRecord(config.identity)
  profile = record.Profile()
  signingProvider = profile.RecordSigningProvider(entityKeyProvider, keyProvider)
  signingKey = signingProvider.SigningKey()
  signingKey.SignatureAlg(profile=profile) // validates required alg/key binding
  sig = signingProvider.Sign(ASCIIBytes(record.Canonical()))
  record.sg = profile.EncodeRecordSignature(sig)
  RETURN record.Serialize()               // DKIM-style tag=value pairs, semicolon-separated
END
```

---

#### `VerifyDomain(domain: string, peerCert?: TLSCertificate) -> VerifiedDomain`

Verifies a DNSid identity according to the protocol, then enforces any configured
[counterparty acceptance](#counterparty-acceptance). This does not authorize an
action or change protocol validity. DNSid-aware application verify methods call
this internally. When
`fl=mtls`, `peerCert` is evidence from the caller's application connection;
`VerifyDomain` does not provision certificates or define the runtime
authentication exchange, and no relationship between that certificate and `ku`
is required.

The pseudocode below expresses trust dependencies, not a requirement to perform
all network operations serially. A verifier MUST authenticate `sg` before
following `su` or log network locations learned from the record. After that
point, implementations SHOULD execute independent fetch and verification work
concurrently where dependencies permit, using bounded concurrency. A definitive
verification failure SHOULD cancel outstanding work for that invocation; this
scheduling optimization MUST NOT weaken any validation or evidence requirement.

```
FUNCTION VerifyDomain(domain: string, peerCert?: TLSCertificate) -> VerifiedDomain
  domain = NormalizeFQDN(domain)

  // cache is already scoped to this manager's immutable verification context.
  // Cache check: return the cached result if present and not yet expired.
  // On a cache hit, re-fetch su only when statusCheckInterval has elapsed.
  // statusCheckInterval=0 gives spec-strict interactive behavior.
  IF cache != nil THEN
    cached = cache.Get(domain)
    IF cached != nil THEN
      // fl=mtls applies to the current application connection, not to the
      // previously verified identity evidence. Enforce it before every cached return.
      EnforceConnectionPolicy(cached.record, domain, peerCert)
      IF Now() - cached.lastStatusCheckAt < Duration(config.verification.statusCheckInterval) THEN
        EnforceCounterpartyAcceptance(cached)
        RequireFreshIdentityEvidence(cached)
        RETURN cached
      END
      cachedCopy = Clone(cached)
      // A transport-level fetch failure raises StatusUnavailable (transient).
      (status, _) = httpsFetcher.FetchStrictJSON(cachedCopy.record.su)
      status.Validate()
      IF status.state != "ACTIVE" THEN
        cache.Evict(domain)
        RAISE VerificationError{Code: StatusNotActive, Transient: false, AgentState: status.state}
      END
      cachedCopy.registryStatus = status
      cachedCopy.lastStatusCheckAt = Now()
      cache.Put(domain, cachedCopy)  // Put rejects expired results; cache evidence even if acceptance later denies.
      EnforceCounterpartyAcceptance(cachedCopy)
      RequireFreshIdentityEvidence(cachedCopy)
      RETURN cachedCopy
    END
  END

  // Step 1: Fetch and parse the _dnsid TXT record.
  (records, dnssecState) = dnsResolver.FetchTXT("_dnsid." + domain)
  IF dnssecState == FAILED THEN
    RAISE VerificationError{Code: DNSSECFailed, Transient: false}
  END
  IF config.verification.dnssecMode == "validated" AND dnssecState == UNKNOWN THEN
    RAISE VerificationError{Code: DNSSECFailed, Transient: false, Message: "DNSSEC validation state unavailable"}
  END
  IF config.verification.dnssecMode == "required" AND dnssecState != VALID THEN
    RAISE VerificationError{Code: DNSSECFailed, Transient: false}
  END
  IF len(records) != 1 THEN
    RAISE VerificationError{Code: RecordInvalid, Transient: false, Message: "expected exactly one _dnsid TXT record"}
  END
  raw = records[0].ConcatenateStrings()
  dnsTTL = records[0].TTL
  dnsExpiresAt = DNSResponseAcquiredAt(records[0]) + dnsTTL
  record = DnsIdTxtRecord.Parse(raw)    // exact v= selector preserved during profile dispatch
  record.IdentityFQDN = domain
  record.Validate()

  // Step 2: Fetch the profile-selected record-signing JWKS and verify sg.
  signerKeyURI = record.SignatureVerificationKeyURI()          // draft 01: ek
  signerKeyAllowedHost = record.SignatureVerificationKeyAllowedHost() // draft 01: gi domain boundary
  signerKeyDomainBoundary = record.SignatureVerificationKeyAllowsDomainBoundary() // draft 01: true
  (recordSigningJwks, recordSigningTlsCert) = httpsFetcher.FetchStrictJSON(signerKeyURI, allowedHost=signerKeyAllowedHost, domainBoundary=signerKeyDomainBoundary)
  recordSigningJwks.ValidateRecordSigning(profile=record.Profile())

  canonical = record.Canonical()
  parsedSig = ParseRecordSignature(record)  // profile-owned; draft 01 is bare base64url
  signingKey = VerifyRecordSignatureWithProfile(record, recordSigningJwks, canonical, parsedSig)

  // Step 3: Fetch or alias the profile-selected runtime/application JWKS.
  runtimeKeyURI = record.RuntimeKeyURI()          // draft 01: ku
  runtimeKeyAllowedHost = record.RuntimeKeyAllowedHost() // draft 01: identity FQDN
  IF runtimeKeyURI == signerKeyURI THEN
    jwks = recordSigningJwks
    tlsCert = recordSigningTlsCert
  ELSE
    (jwks, tlsCert) = httpsFetcher.FetchStrictJSON(runtimeKeyURI, allowedHost=runtimeKeyAllowedHost)
  END
  operationalKey = record.Profile().ValidateVerifiedKeys(signingKey, jwks)

  // Step 4: Construct a bound LogReader for this counterparty's log method.
  IF logRegistry != nil THEN
    logReader = logRegistry.NewReader(record.lr)
  ELSE
    logReader = NoopLogReader(method=LogMethod(record.lr))
  END

  // Classify the governance relationship independently of ek host validation.
  // For a delegated cross-domain identity, bilateral ISSUANCE is the only valid
  // relationship proof, so the absence of a usable reader is a permanent failure.
  IF NOT record.Profile().HasStructuralGovernanceRelationship(record) AND
     logReader IS NoopLogReader THEN
    RAISE VerificationError{Code: LogError, Transient: false,
                            Message: "delegated governance relationship requires verified ISSUANCE evidence"}
  END

  // Step 5: Perform the selected profile's required lifecycle checks. Draft 01
  // verifies bilateral ISSUANCE and operational continuity independently of fl=logchk.
  // This also verifies the exact domain and gi in ISSUANCE for both structural
  // and delegated governance relationships.
  record.Profile().VerifyLifecycleBinding(record, logReader, signingKey, operationalKey)

  // Step 6: Validate operational key age if ka tag is present.
  keyBoundAt = ZeroTime
  IF record.ka != "" THEN
    keyAgeThumbprint = record.KeyAgeSubjectThumbprint(signingKey, jwks)
    keyBoundAt = logReader.KeyTimestamp(domain, keyAgeThumbprint)
    IF Now() - keyBoundAt > ParseDuration(record.ka) THEN
      RAISE VerificationError{Code: KeyAgeExceeded, Transient: false}
    END
  END

  // Step 7: Handle connection-specific policy flags. The same helper runs on
  // cache hits so cached identity evidence never substitutes for the current peer.
  EnforceConnectionPolicy(record, domain, peerCert)

  // Step 8: Check status endpoint. Transport/unreachable status is transient and
  // yields an indeterminate interactive result; stale or non-ACTIVE status fails.
  // A transport-level fetch failure raises StatusUnavailable (transient).
  (status, _) = httpsFetcher.FetchStrictJSON(record.su)
  status.Validate()
  IF status.state != "ACTIVE" THEN
    RAISE VerificationError{Code: StatusNotActive, Transient: false, AgentState: status.state}
  END

  // Step 9: Operation-level logchk is caller policy. VerifyDomain records the flag
  // but does not decide whether the next operation is high-value or irreversible.
  // Callers inspect result.RequiresLogCheck() and invoke VerifyLogEvidence for
  // operations that require current complete-log evidence.

  result = VerifiedDomain{
    domain:             domain,
    record:             record,
    jwks:               jwks,
    recordSigningJwks:     recordSigningJwks,
    signingKey:            signingKey,
    tlsCert:               tlsCert,
    recordSigningTlsCert:  recordSigningTlsCert,
    registryStatus:     status,
    verifiedAt:         Now(),
    dnsTTL:             dnsTTL,
    dnsExpiresAt:       dnsExpiresAt,
    keyBoundAt:         keyBoundAt,
    lastStatusCheckAt:  Now(),
    dnssecState:        dnssecState,
    logReader:          logReader,
  }

  IF cache != nil AND dnsTTL > ZeroDuration THEN
    cache.Put(domain, result)  // Put rejects expired results; identity evidence only, no cached acceptance decision.
  END
  EnforceCounterpartyAcceptance(result)
  RequireFreshIdentityEvidence(result, freshDNSLookup=true)
  RETURN result
END

FUNCTION EnforceConnectionPolicy(record: DnsIdTxtRecord,
                                 domain: string,
                                 peerCert?: TLSCertificate)
  flags = record.PolicyFlags()
  IF flags.Has("mtls") THEN
    IF peerCert == nil THEN
      RAISE VerificationError{Code: TLSError, Transient: false,
                              Message: "mTLS required but peer certificate is missing"}
    END
    peerCert.ValidateAgainstFQDN(domain)
  END
END
```

`EnforceConnectionPolicy` is shown as an internal helper, not a required public
API. Bindings may structure the check differently, but MUST apply it to the
current peer certificate before every successful `VerifyDomain` return,
including status-refresh and no-refresh cache hits.

`EnforceCounterpartyAcceptance` is an internal helper implementing
[Counterparty Acceptance](#counterparty-acceptance), not a second verification
API. It checks the configured allowlist and optional pins; with no policy it
makes no acceptance decision. An allowlist match MUST NOT skip any mandatory
evidence checks. Its result is never stored in the cache. Bindings SHOULD place
this check at their shared per-invocation verification boundary, outside
coalesced evidence work, rather than duplicate it in lookup/cache helpers.
The pseudocode shows the required ordering for each return path, not a required
internal code layout. Both acceptance and the final freshness check MUST run
before every successful return; neither may be skipped when the other fails.
The pseudocode places acceptance first because a policy denial is deterministic
and more actionable for the caller than a freshness failure that a retry would
resolve only to be denied again. Either order prevents expired evidence from
being returned: expired evidence is already invisible to `IdentityCache.Get`,
and a failed freshness check evicts it. A binding MAY run the freshness check
first if it documents that choice; the observable contract is that both
failures are rejections and success requires both to pass.

`RequireFreshIdentityEvidence` is also an internal check, not a new public API.
Immediately before each successful return, it checks the runtime and
record-signing TLS validity bounds and any `ka` bound, and requires
`Now() < dnsExpiresAt` for positive DNS TTLs. An elapsed bound evicts any cached
entry and fails with the corresponding verification error (`TLSError`,
`KeyAgeExceeded`, or transient `DNSResolution` for expired DNS evidence).
A caller may retry within its overall deadline; the SDK must not retry forever.
Updating `verifiedAt` or refreshing status MUST NOT extend `dnsExpiresAt`.

A zero DNS TTL permits use only by the verification operation that acquired the
response, never positive-cache reuse. `freshDNSLookup=true` permits that one
use without a DNS lifetime check; TLS and key-age checks still apply. A completed
zero-TTL lookup MUST NOT satisfy a later invocation through caching or completed
in-flight work. No arbitrary grace period or fallback TTL replaces a returned
zero TTL. These rules do not define status-response freshness.

SDK validation must cover:

| Scenario | Required result |
|---|---|
| DNS acquired at `t=0`, TTL 30 s, verification completes at `t=35` | Fail/retry; do not grant a new 30 s cache lifetime. |
| A cache hit expires while a required status fetch is in progress | No stale successful return or cache reinsertion. |
| DNS TTL is zero and other evidence is valid | Current fresh-lookup operation may succeed; the next call needs a new lookup. |
| TLS/key-age evidence expires during verification, including with zero DNS TTL | Fail; the zero-TTL exception applies only to DNS reuse. |

---

#### `VerifyLogEvidence(vd: VerifiedDomain, at?: timestamp) -> LoggedStateEvidence`

Performs the operation-level complete-history and non-revocation check using the
`LogReader` already bound to `vd.record.lr`. `at` defaults to `Now()`. The helper
is operation-independent: applications decide when an operation is high-value
or irreversible and may invoke it when `vd.RequiresLogCheck()` is true or when
local policy requires the same evidence without `fl=logchk`.

```
FUNCTION VerifyLogEvidence(vd: VerifiedDomain,
                           at: timestamp = Now()) -> LoggedStateEvidence
  RETURN vd.logReader.VerifyNonRevocation(vd.domain, at)
END
```

The helper returns [`LoggedStateEvidence`](06-log-bindings.md#logreader-interface),
not a boolean. Unreachable logs raise transient `LogError`; missing, stale,
incomplete, or invalid evidence raises permanent `LogError`. This check does not
refresh `su`; callers requiring current status for the operation call
`VerifyDomain` according to their configured status-freshness policy.

---

#### `LoadDomainLog(vd: VerifiedDomain) -> DomainLog`

Loads the full verified event history using the `LogReader` already bound to `vd.record.lr` during `VerifyDomain`; event verification rules are owned by [06-log-bindings.md](06-log-bindings.md). Raises if `vd.logReader` is a `NoopLogReader`.

```
FUNCTION LoadDomainLog(vd: VerifiedDomain) -> DomainLog
  events = vd.logReader.RebuildHistory(vd.domain)  // raises if NoopLogReader; verifies proofs, consistency, and event signatures per event-type rules
  RETURN DomainLog{ domain: vd.domain, events: events }
END
```

`DomainLog` and `DomainSnapshot.historicalState` describe verified history only.
They do not replace `VerifiedDomain`'s fresh protocol-status result and MUST NOT
be used to upgrade a missing, stale, or non-active `su` response.

---

#### `EvictDomain(domain: string)`

Removes a domain from the `IdentityManager`'s cache. Call this when an out-of-band notification (e.g. a registry webhook, a revocation event from the log) indicates that the cached identity for a domain is no longer valid. The next `VerifyDomain` call for the domain will perform a full re-verification.

```
FUNCTION EvictDomain(domain: string)
  IF cache != nil THEN
    cache.Evict(NormalizeFQDN(domain))
  END
END
```

---

## Error Types

Four error types are defined. `ParseError` and `ValidationError` arise before any network I/O when parsing or validating data structures directly. `VerificationError` covers all failures during live verification. `ArgumentError` signals SDK API misuse by the caller. The four are non-overlapping and not in a subtype relationship. When `VerifyDomain` or another `Verify*` method encounters a parse or validation failure internally, it wraps that failure as `VerificationError{Code: RecordInvalid}` and preserves the original error as the cause.

---

### `ParseError`

Raised by `DnsIdTxtRecord.Parse` when the TXT record RDATA is structurally malformed or uses an unsupported `v=` value. The raw DNS data cannot be interpreted as a supported DNSid record. Never transient; retry will not help.

Examples: missing or non-first `v=` tag; unsupported `v=` value such as a future profile `DNSid2` when only the draft 01 selectors are implemented; duplicate tag names; tag name or tag value containing prohibited characters; a malformed method prefix passed to `LogRegistry.NewReader`.

For unsupported `v=` values, see [Version String Convention](07-protocol-data-types.md#version-string-convention).

---

### `ValidationError`

Raised by `DnsIdTxtRecord.Validate`, `NormalizeFQDN`, and `AgentStatus.Validate` when data is parseable but violates semantic constraints. Never transient.

Examples: malformed `gi`; `ek` host not under `gi`; `ku` host not equal to identity FQDN; `ek` and `ku` keys sharing a thumbprint; `ka` value not in the permitted set; unknown identity state string.

---

### `VerificationError`

Raised by `VerifyDomain` and all `Verify*` methods when a live verification step fails. Carries a structured code and transient flag so callers can decide whether to retry and what to surface to users or logs.

| Field        | Type               | Description |
|--------------|--------------------|-------------|
| `Code`       | `VerificationCode` | Identifies the failure category. |
| `Transient`  | bool               | `true` if the failure may resolve on retry (network reachability). `false` for integrity failures and policy rejections. |
| `AgentState` | string             | Populated only when `Code` is `StatusNotActive`. One of: `PENDING`, `PROVISIONING`, `VERIFYING`, `RETIRED`, `REVOKED`. |
| `Message`    | string             | Human-readable description; acceptance errors MUST NOT disclose configured allowlists or pins. |
| `VerifiedGovernanceID` | string | For `CounterpartyNotAccepted`, the observed profile-selected verified governance ID; absent for other codes. |
| `VerifiedEntityKeyThumbprint` | string | For `CounterpartyNotAccepted`, the observed verified record-signing key's RFC 7638 SHA-256 thumbprint; absent for other codes. |

```
ENUM VerificationCode
  DNSResolution    // DNS lookup failed (network error or NXDOMAIN). Transient.
  DNSSECFailed     // DNSSEC validation attempted and failed; record MUST be rejected. Permanent.
  RecordInvalid    // Wrong number of TXT records, or parse/validation failure raised inside
                   // VerifyDomain (e.g. missing required tag). Permanent.
  SignatureInvalid // The profile-selected record-signing key could not verify the sg tag. Permanent.
  TLSError         // TLS certificate error; non-HTTPS redirect on the profile-selected JWKS URI or su;
                   // or host-changing redirect where the selected profile disallows it. Permanent.
                   // Host-changing HTTPS redirects are permitted for su unless local policy is stricter.
                   // (cu is not fetched during core protocol verification; TLS requirements apply
                   // if an application fetches the capabilities document separately.)
  KeyAgeExceeded   // Signing key is older than the ka tag permits. Permanent.
  StatusUnavailable // su endpoint was unreachable or had a transport-level failure. Transient; the DNSid interactive result is INDETERMINATE.
  StatusNotActive  // su endpoint returned a state other than ACTIVE or a stale response. See AgentState. Permanent.
  LogError      // Log unreachable (Transient), or inclusion-proof or event check failed (Permanent).
  CounterpartyNotAccepted // Configured policy denied the verified counterparty. Permanent.
END
```

For `LogError`, `Transient` is `true` when the log service is unreachable and
`false` when a cryptographic proof fails or required evidence is absent.
`CounterpartyNotAccepted` is always permanent and does not mean the DNSid record
is cryptographically invalid. Its structured observed-identity fields support
local audit; they do not disclose configured alternatives or imply request-signature
verification. Messages, serialized causes, and other error details MUST NOT echo
the configured allowlist or pins. Applications choose whether to expose observed
identity details externally.

---

### `ArgumentError`

Raised when a caller passes an invalid argument to an SDK method. Indicates a programming error in the calling code, not a data or network condition. Never transient; the caller must fix the invocation.

Examples: `audience` is empty in `CreateJWT`; `additionalClaims` overrides a reserved JWT claim; an unknown signature component name is passed to `CreateSignedHttpRequest`; `kid` contains `#`; a `LogRegistry`-provided reader does not satisfy the `Log` interface; a JOSE algorithm is unsupported or unmapped during signing; `LogRegistry.Register` is called with a malformed method name. Parsing a malformed reference in `NewReader` instead raises `ParseError`.

---

### KeyProvider Interface

A standardized interface for key management systems. Implementations may wrap
local key files, cloud KMS, or HSMs. The SDK never handles private key material
directly.

Most SDK users only provide the agent `keyProvider`. Draft 01 setup/admin flows also use an accountable-entity provider:

| Provider | Published at | Used for |
|------|--------------|----------|
| `entityKeyProvider` | `ek` JWKS | `_dnsid` TXT `sg` and accountable-entity lifecycle signatures. |
| `keyProvider` | `ku` JWKS | Agent runtime/application signatures, ISSUANCE countersignature, and KEY_ROTATION authorization. |

The current public keys for these providers MUST be distinct by RFC 7638 JWK
thumbprint. Live draft 01 JWKS endpoints expose exactly one current key per provider.
Superseded keys are not retained on live endpoints; historical verification uses
public key material recorded in the lifecycle log.

Keys progress through three local management states. During operational rotation,
the new public key is published before the event append while its private key
remains locally pending for application signing; application signing pauses until
publication and append converge.

| State | Description | In draft 01 live JWKS? | Used for signing? |
|-------|-------------|----------------------|-------------------|
| Pending | Generated but not yet promoted locally | Only during the bounded publish-before-append rotation window | Binding-owned proof via `SignKey` only |
| Active | Current application signing key for this provider | Yes, except while the pending successor is published during rotation | Yes, except while rotation is reconciling |
| Superseded | Rotated out; retained only in log/archive/KMS for audit | No | No |

```
INTERFACE KeyProvider

  // --- Runtime methods (called internally by the SDK) ---

  // Returns the JWK representation of this provider's current active public
  // signing key. Draft 01 keys MUST include kid and alg. Any kid returned by the
  // SDK's KeyProvider MUST NOT contain '#', because application-layer JWS and
  // HTTP Message Signature helpers encode key IDs as `{domain}#{kid}`.
  SigningKey() -> JWK

  // Returns this provider's JWK by ID. Raises if not found.
  JWK(kid: string) -> JWK

  // Returns this provider's active key ID. For draft 01 live JWKS publication this
  // is a single-element list; old profiles or non-live archival APIs may expose
  // broader lists outside the draft 01 key-service path.
  ListKeyIds() -> []string

  // Signs the given payload with this provider's current active signing key.
  // Returns raw signature bytes.
  Sign(payload: bytes) -> bytes

  // Signs with a specific pending or active key during a rotation transaction.
  // The previous active key authorizes draft 01 KEY_ROTATION; bindings may also
  // require proof of possession from the pending new key.
  SignKey(kid: string, payload: bytes) -> bytes

  // --- Management methods (called by operator code during key rotation) ---

  GenerateKey() -> kid
  Activate(kid: string)
  Supersede(kid: string)

END
```

---

### IdentityCache

Cache for verified domain results. Held by `IdentityManager` and consulted at the start of every `VerifyDomain` call. Avoids redundant DNS lookups, JWKS fetches, and TLS connections for frequently-contacted identities.

A cache MUST be manager-private by default. An injected cache or shared backend
MUST isolate results by verification context; the domain-only interface below
operates within that context's namespace. Sharing a namespace is permitted only
when callers explicitly establish identical, immutable verification policy and
trust configuration. Matching domain names alone is insufficient. The context
includes DNSSEC mode and resolver trust, status-freshness policy, HTTPS trust and
fetch restrictions, supported verification profiles, log-reader/trust-policy
selection, and configured counterparty acceptance policy. This requires no new
wire field or public cache-key format.

Security-relevant configuration changes MUST invalidate the affected namespace
or select a fresh one before verification under the new context. In-flight work
under the previous context MUST NOT populate or satisfy the new context. Using
a new manager with a fresh private cache or namespace is sufficient; no policy
hashing, mutable configuration, or cross-manager namespace sharing is required.

Implementation requirements:
- `Get` MUST return `nil` when `Now() >= VerifiedDomain.Expiry()`.
- `Put` MUST use the original absolute `result.Expiry()`, not restart a TTL. Already-expired and zero-DNS-TTL results MUST NOT be stored.
- Implementations MUST be safe for concurrent use from multiple goroutines/threads.
- `IdentityManager` SHOULD coalesce concurrent cache misses and required status
  refreshes for the same normalized domain within the same verification context.
  Coalescing reusable identity work
  MUST NOT skip per-invocation policy such as checking the current mTLS peer
  and evaluating current counterparty acceptance. Coalesced work shares protocol
  evidence only; each caller independently runs acceptance before returning.
- Invalid protocol evidence and failure results MUST NOT be inserted into this
  positive cache. Eligible verified identity evidence, including a successful
  status refresh, MUST be cached before counterparty acceptance is evaluated.
  Acceptance denial does not invalidate that evidence; neither the decision nor
  the error is cached. Every invocation still evaluates
  acceptance independently before returning successfully.
- If a required status refresh fails, the error is returned and the stale cached
  result MUST NOT be returned as successful verification.

SDK validation MUST cover these context-isolation cases; the shared pure-data
vectors do not exercise live caches or concurrent verification:

| Scenario | Required result |
|---|---|
| `auto` manager caches DNSSEC `UNKNOWN`; a `required` manager uses the same backend | No cross-context hit or coalesced result; the required manager verifies independently and rejects `UNKNOWN`. |
| Managers differ in accepted log roots, resolver trust, or HTTPS trust/fetch restrictions | Neither manager consumes the other's cached verification result. |
| Policy changes while an old-context verification is in flight | The old result cannot repopulate or satisfy the new context. |
| Identical immutable contexts explicitly share a namespace | Reuse is permitted, but expiry, status freshness, and current-peer checks still apply per invocation. |

Negative caching, circuit breaking, and distributed cache tiers are optional
deployment concerns rather than requirements of this interface. They may
suppress repeated work but MUST preserve typed failures and MUST NOT convert
expired or failed verification into a successful `VerifiedDomain` result.

```
INTERFACE IdentityCache

  // Returns the cached VerifiedDomain for a domain, or nil if not cached or expired.
  Get(domain: string) -> VerifiedDomain | nil

  // Stores a verified domain result. Entry expires at result.Expiry().
  Put(domain: string, result: VerifiedDomain)

  // Removes a domain from the cache immediately (used by IdentityManager.EvictDomain).
  Evict(domain: string)

END
```


---

### HTTPSFetcher Interface

Pluggable HTTPS JSON fetch dependency. Decouples `VerifyDomain` from any
particular runtime HTTP stack while preserving DNSid TLS and redirect semantics.
Language bindings may expose this dependency as a function, configured HTTP
client, transport, session, or other idiomatic abstraction.

```
INTERFACE HTTPSFetcher

  // Fetches and parses a JSON document from an HTTPS URL.
  // Must perform full TLS certificate validation per RFC 9525, reject non-HTTPS
  // URLs and non-HTTPS redirects, and return the peer TLS certificate used for
  // cache-expiry calculations. If allowedHost is supplied, redirects MUST remain
  // at that exact host unless domainBoundary is true, in which case redirects may
  // remain at allowedHost or its subdomains with DNS-label boundary matching.
  FetchStrictJSON(url: string, allowedHost?: string, domainBoundary?: bool) -> (JSONValue, TLSCertificate)

END
```

`VerifyDomain` uses `HTTPSFetcher` for the profile-selected TXT signature
verification JWKS URI with the profile-selected `allowedHost` and boundary mode,
and for the status `su` URL without `allowedHost` unless local policy is stricter.
`TransportConfig` may configure a default fetcher, but it does not change the
signed TXT record or protocol validation rules.

An SDK-provided fetcher MUST reject URL credentials and fragments, impose finite
request deadlines, redirect counts, and decoded response-size limits, support
cancellation, and require HTTP `200 OK`. It MUST validate every resolved
destination address and connect to an address that was validated so DNS
rebinding cannot bypass the check. The same validation applies independently to
every redirect hop. Loopback, private, link-local, multicast, reserved, and
otherwise non-routable destinations are rejected by default. The only
exception is `TransportConfig.privateAddressHosts`
([05: Private Address Hosts](05-transport-and-registry.md#private-address-hosts)):
a destination whose hostname matches a configured entry MAY resolve to loopback
or private-use addresses. Everything else still applies to a matching host:
every resolved address is validated, the connection goes to a validated
address, link-local, multicast, reserved, and unspecified addresses remain
rejected, and every redirect hop is matched and validated independently. An
SDK MUST NOT exempt any hostname, TLD, or address class without a configured
entry. Limits apply while streaming the response, not only after buffering, and
language bindings MUST document their finite defaults.

SDK-managed transports SHOULD reuse connections. Retry and circuit-breaker
policy remains a transport or deployment concern; any retry performed internally
MUST remain within the invocation's deadline and resource bounds.

---

### DNSResolver Interface

Pluggable DNS resolver dependency. Decouples `VerifyDomain` from the system resolver so deployments can substitute a DNSSEC-validating library, a trusted DoT/DoH upstream, or a test double. Production bindings SHOULD use encrypted DNS transport (DoT or DoH) when the platform supports it; this does not by itself establish DNSSEC validation.

```
INTERFACE DNSResolver

  // Fetches TXT records for the given DNS owner name.
  // name is a normalized FQDN without trailing dot (e.g. "_dnsid.agent.example.com").
  // Implementations MUST treat it as an absolute name — no search-domain expansion.
  // Returns the record set and the DNSSEC validation state of the response.
  FetchTXT(name: string) -> ([]TXTRecord, DNSSECState)

END
```

The default implementation used when no `DNSResolver` is supplied:
- If `TransportConfig.dnsServer` is set and the language binding provides a default resolver, query that resolver for TXT records.
- Otherwise, query the host language/runtime resolver when the binding supports a safe default.
- `RegistryConfig.registryUrl` is not resolver configuration; it is used only for registry control-plane API calls.
- Return non-negative finite TTLs with acquisition timing sufficient to preserve absolute DNS expiry. `DNSResponseAcquiredAt` above denotes this internal timing, not a required resolver API. Capture receipt time before further verification; cached resolvers must return remaining TTLs or the original absolute expiry. If timing is unavailable, using lookup start time is conservative. An expired cached DNS answer is not a newly acquired zero-TTL response. A conservative default such as 300 seconds is permitted only when the TTL itself is unavailable, never when it is zero.
- A resolver that performs DNSSEC validation MUST return `VALID`, `UNSIGNED`, or `FAILED` as appropriate. A resolver that cannot determine DNSSEC validation state MUST return `UNKNOWN`; it MUST NOT claim that an unvalidated response is `UNSIGNED`.
- A binding MAY require explicit resolver injection when its runtime has no safe default DNS lookup facility. It MUST NOT require DNSSEC-aware resolver injection merely because the default resolver returns `UNKNOWN`; the default `auto` policy intentionally supports that reduced-assurance result.
- A stub resolver MUST trust an upstream resolver's authenticated-data indication only when that resolver is explicitly trusted and reached over a secure channel or equivalent trusted local path. DoH or DoT protects the channel but does not by itself prove that the upstream performs DNSSEC validation.
- `VerifyDomain` MUST abort on `FAILED` in every mode. It MUST retain the returned state in `VerifiedDomain` so callers can apply operation-specific assurance policy.

---

### DNSSECState

Outcome of DNSSEC validation for a DNS response.

```
ENUM DNSSECState
  UNSIGNED   // zone has no DNSSEC; verification proceeds at lower assurance
  VALID      // chain of trust from root to zone validated successfully
  FAILED     // DNSSEC validation failed; record MUST be rejected
  UNKNOWN    // resolver did not perform or cannot report DNSSEC validation;
             // verification may proceed only under the auto policy without DNS-origin assurance
END
```

`UNKNOWN` is an SDK capability/result state, not a claim that the zone is
unsigned and not a successful DNSSEC validation outcome. Implementations MUST
surface it distinctly from `UNSIGNED`. This preserves a usable base profile on
platforms whose system resolver does not expose DNSSEC results while preventing
an assurance upgrade based on unavailable evidence.

---

### DNSSECMode

Controls how `VerifyDomain` responds to the `DNSSECState` returned by `DNSResolver`. Regardless of mode, `FAILED` means DNSSEC validation failed; `VerifyDomain` MUST abort and MUST NOT suppress the failure.

```
ENUM DNSSECMode
  auto      // (default) Hard-fail on FAILED. Proceed on VALID, UNSIGNED, or UNKNOWN,
            // retaining the state so callers can distinguish the assurance obtained.
  validated // Require a resolver that reports definitive DNSSEC state. Proceed on VALID
            // or UNSIGNED; fail on FAILED or UNKNOWN.
  required  // Fail unless dnssecState is VALID. Use for high-assurance deployments
            // where DNS-origin authentication independent of WebPKI is required.
END
```

`auto` is opportunistic validation, not an assertion that DNSSEC succeeded. It
keeps the base profile usable with ordinary system resolvers while still
rejecting every known validation failure. Deployments that require every lookup
to pass through a validating resolver but still accept provably unsigned zones
use `validated`. Deployments that require DNS-rooted origin authentication use
`required`.

---

## Core Flows

### Initial Setup of Local Identity

```
1. IdentityManager.new(config{identity, verification, transport}, deps{keyProvider, entityKeyProvider, logRegistry})
2. Persist one durable issuance operation; protocol status remains non-active.
3. GetEntityKeySet() -> publish at ek; GetKeySet() -> publish at ku; publish su.
4. CreateTxtRecord(); publish the returned signed record at _dnsid.{domain}.
5. Verify the externally served ek, ku, su, and DNS representations.
6. event = ISSUANCE{
     domain,
     governanceId,
     initialOperationalPublicKey,
     initialOperationalThumbprint,
     initialOperationalKid,
     initialOperationalAlg,
     initialEntityPublicKey,
     initialEntityThumbprint,
     initialEntityKid,
     initialEntityAlg,
     timestamp,
   }
   Prepare, entity-sign, and operationally countersign the exact same bytes.
7. Submit the exact persisted bytes and verify accepted entry hash/reference.
8. Change su to ACTIVE.
9. Mark the durable issuance operation complete.
```

A failure after log acceptance retries status/publication convergence with the
same accepted ISSUANCE; it never creates a second issuance. DNS publication or
registry `READY` alone does not activate the identity.

---

### Operational Key Rotation

Draft 01 KEY_ROTATION rotates only the operational (`ku`) key. Superseded
operational keys are removed from the live `ku` JWKS; historical verification
uses public key material recorded in the log. The previous operational key is
the base-protocol authority. A registry login or administrator role never
substitutes for that signature. A log binding may require additional signatures;
`c2sp-tlog` also requires proof of possession by the new key.

```
1. previousKey = keyProvider.SigningKey()
2. previousKid = previousKey.kid
3. newKid = keyProvider.GenerateKey()              // remains pending
4. newKey = keyProvider.JWK(newKid)
5. event = KEY_ROTATION{
     domain,
     previousOperationalKid:        previousKid,
     previousOperationalThumbprint: previousKey.Thumbprint(),
     newOperationalKid:             newKid,
     newOperationalAlg:             newKey.SignatureAlg(),
     newOperationalPublicKey:       newKey,
     newOperationalThumbprint:      newKey.Thumbprint(),
     timestamp:                     Now(),
   }
6. reservation = logBinding.ReservePredecessor(previousKey.Thumbprint())
7. prepared = logBinding.PrepareEvent(event, reservation)
                                                      // includes binding-owned chain metadata
8. prepared.Sign(PreviousOperational, keyProvider.SignKey(previousKid, prepared.signedBytes))
9. Add every binding-owned signature. For c2sp-tlog:
     prepared.Sign(NewOperational, keyProvider.SignKey(newKid, prepared.signedBytes))
10. Construct and durably persist the managed-rotation recovery state, including
    the exact complete prepared bytes, their hash, the idempotency key, both key
    bindings, and `applicationSigningPaused=true`.
11. Invoke the required application-signing controller to pause new signatures.
    If either persistence or pausing fails, do not submit the rotation.
12. Publish JWKS{keys: [newKey]} at ku, advance registry state with an
    expected-previous-key CAS, and verify the externally served representation.
    Do not publish an old/new overlap. The local new key remains pending for
    application signing.
13. Append the exact persisted prepared bytes unchanged, enforcing reservation CAS.
14. Persist every submission transition. On an indeterminate result, remain paused
    while the registry reconciles the same bytes; never regenerate the event.
15. After an accepted result is bound to the exact entry hash and new key, persist
    acceptance before local reconciliation.
16. keyProvider.Activate(newKid)
17. keyProvider.Supersede(previousKid)
18. Persist `activated=true`, then resume application signing and persist
    `applicationSigningPaused=false`. A failure at any boundary resumes from the
    latest durable state rather than creating a new rotation.
19. If no TXT tag changed, the DNSid TXT record need not be re-signed. If ku URI
    or any other TXT tag changed, CreateTxtRecord() re-signs with the entity key.
```

Publication of the new live key precedes the immutable `KEY_ROTATION` append,
as required by draft 01. These are not an atomic distributed transaction, so
implementations expose a durable, server-reconciled operation rather than
claiming one-shot atomicity. During the bounded publication-to-append interval,
continuity verification fails closed. Runtimes MUST prevent new application
signatures from the time the recoverable rotation is first persisted until local
activation is durably complete.

After activation, a counterparty still caching the previous `ku` may reject
new-key application signatures until its identity evidence expires or is
explicitly evicted. Operators SHOULD measure this cache-lifetime window and
plan rotation accordingly. It does not justify publishing overlapping live
keys, bypassing continuity checks, or accepting signatures under an unverified
replacement key.

#### Managed Rotation Recovery Contract

An SDK-managed rotation entry point MUST require two injected dependencies; they
are not optional advisory callbacks:

```
PersistRotation(rotationState) -> void
SetApplicationSigningPaused(paused: boolean) -> void
```

`PersistRotation` represents durable storage chosen by the application. The SDK
does not prescribe a database, file format, or transaction library, but it MUST
call this dependency before the first submission and after every recoverable
state transition. `SetApplicationSigningPaused` controls the application's
signing boundary; setting it to `true` MUST complete before submission begins.
SDKs MUST reject a managed rotation invocation that omits either dependency.

The durable state MUST contain enough information to validate and resume the
same operation after process restart: normalized domain, exact log reference,
previous and new key bindings (IDs and thumbprints, or an equivalent binding),
exact completed entry bytes and their SHA-256 hash (stored or recomputable and
checked), idempotency key, latest structured submission result, whether local
activation completed, and whether application signing is paused. The pending
private key remains in the injected `KeyProvider`, whose storage MUST make that
key recoverable by the recorded key ID after restart.

Resume validates the durable record before taking action and fails closed on an
entry-hash, log-reference, or key-binding mismatch. Its state handling is:

- prepared, submitting, or indeterminate: ensure signing is paused and retry the
  exact bytes with the same idempotency key;
- accepted but not activated: do not create a new event; reconcile activation and
  supersession idempotently from the accepted record;
- activated but still paused: resume signing and persist the completed state;
- rejected: return a terminal typed submission error without resubmission.

Failures after completed bytes have been fixed return a typed submission or
activation error carrying the latest recoverable rotation state. Persistence,
pause, activation, supersession, and unpause failures never discard that state.
In particular, unpausing before `activated=true` is durably stored is forbidden.

If the previous private key is unavailable or suspected compromised, this flow
MUST NOT be used: revoke and reissue the identity instead.

Accountable-entity (`ek`) key continuity, accountability transfer, and recovery
are not defined by draft 01; changing `ek` or `gi` without a future profile's
continuity proof is reissuance or local-policy risk.

---

### Registry Status Change (e.g. Revocation)

```
1. Registry durably persists revocation intent, reason, transition time, and
   one retry owner.
2. Registry updates status endpoint (su) to REVOKED immediately and disables
   operational use; a log outage does not delay this decision.
3. The retry owner reserves the predecessor, prepares and entity-signs the exact
   REVOCATION bytes, and appends them until accepted using one idempotency key.
4. Registry may notify the local identity runtime out-of-band.
5. Any IdentityCache entries for this domain should be evicted
   (VerifyDomain will fail on next call due to REVOKED state)
6. Mark evidence convergence complete while retaining historical verification
   material under the deployment retention policy.
```

Exactly one coordinator owns the append. An SDK helper MUST NOT independently
append the same revocation when the registry owns convergence. Retirement uses
the same ordering with protocol status `RETIRED`.

## Non-Goals

These are not core `IdentityManager` responsibilities:

- creating or verifying JWTs
- creating or verifying compact JWS payloads
- signing outbound HTTP requests
- verifying inbound HTTP Message Signatures
- exposing framework-specific middleware
- maintaining JWT `jti` replay stores or HTTP signature nonce stores
- fetching or interpreting capabilities documents beyond validating the signed
  `cu` field
