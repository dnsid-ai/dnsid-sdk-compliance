# Configuration Loading

This document defines how SDK configuration reaches a constructor from
sources other than code: environment variables, a deployment file, and a
DNSid CLI identity directory. It owns the environment variable schema, the
merge rule, and the contract for convenience constructors. It does not change
protocol wire behavior or the types defined in
[01](01-core-identity-manager.md#initialization),
[05](05-transport-and-registry.md), and [11](11-c2sp-tlog-binding.md).

## Principle

**Loaders parse; constructors default.**

A loader returns a partial configuration containing only the fields that are
present in its source. A loader MUST NOT default, derive, infer, or fabricate a
value, and MUST NOT read a second source to fill a gap in the first. Defaults
and validation are applied exactly once, by the constructor of the owning type
(`IdentityManager`, `RegistryClient`, log-trust factories, profile verifiers).

Consequences:

- Missing required fields stay absent. Construction then fails with
  `ArgumentError` naming the field. No placeholder value (such as a no-op log
  reference) may be substituted to satisfy a required field.
- Empty or whitespace-only source values are treated as absent, so the
  constructor default applies. A loader MUST NOT pass an empty string, zero, or
  empty list in place of an omitted field, because the constructor treats
  explicit empty values as meaningful
  ([01: Configuration Ownership and Loading](01-core-identity-manager.md#configuration-ownership-and-loading)).
- Defaults documented in 01, 02, 03, 05, 09, 10, and 11 are constructor
  defaults. They follow one presence rule: `DefaultIfMissing` from
  [03](03-jose-jwt-jws.md#profile-configuration) tests presence, not
  truthiness. A loader never applies them.
- Constructors MUST NOT read environment variables or files.

## Loaded Configuration

Every source produces the same partial shape:

```
TYPE LoadedConfig
  dnsid?: DnsidConfig               // partial; sections and fields present only when sourced
  logTrust?: LogTrust               // atomic section, see below
  registry?: RegistryConfig         // partial
  keySource?: KeySource
END

TYPE LogTrust
  managed?: boolean                 // true selects the embedded managed catalog (11: DNSid-Managed Trust)
  profile?: object                  // trust profile document (11: Trust Profiles)
  policyDocument?: bytes            // trusted tlog-policy document (11: Verification Convenience Factory)
  policyUrl?: string                // explicit trust-policy URL (11: Verification Convenience Factory)
END

TYPE KeySource
  cliDirectory?: string             // DNSid CLI identity directory (01: Initialization from DNSid CLI Configuration)
  entityKeyPath?: string            // accountable-entity key file; CLI loader resolves a relative entity_key_path against the directory of the config.json that carries it
  keyStorePath?: string             // binding-defined local key store file
END
```

`LogTrust` MUST contain exactly one variant when `Construct` uses it; zero or
more than one fails with `ArgumentError`. `managed: false` is rejected with
`ArgumentError`; omit the field instead. When the caller supplies
`deps.logRegistry`, `logTrust` is not inspected. `logTrust` is atomic under
merge: a later source that sets any variant replaces the whole section.

`dnsid.identity` is present only when the source supplies at least one identity
field. A source that supplies no identity field yields a verification-only
configuration.

`KeySource` variants are not exclusive: `dnsid local run` exports both
`DNSID_CONFIG_DIR` and `DNSID_KEY_STORE` for one agent. When both are present,
`cliDirectory` supplies the operational key provider and `keyStorePath` is
unused; `entityKeyPath` supplies the entity key provider whenever present.

## Sources

| Source | Encoding | Defined in |
|---|---|---|
| Environment | `DNSID_*` variables | [Environment Variables](#environment-variables) |
| Deployment file | JSON document | [Deployment File](#deployment-file) |
| DNSid CLI directory | `config.json` plus key files | [01: Initialization from DNSid CLI Configuration](01-core-identity-manager.md#initialization-from-dnsid-cli-configuration) |
| Code | `DnsidConfig` and `IdentityManagerDependencies` supplied by the caller | [01: Initialization](01-core-identity-manager.md#initialization) |

Each configuration source has one loader. Registry credentials are secrets,
not loaded configuration: they are supplied explicitly to `RegistryClient` or
read directly by `RegistryClientFromEnvironment`, never stored in `LoadedConfig`.
The CLI directory loader maps the persisted
snake_case publication fields into `dnsid.identity` and records the directory
as `keySource.cliDirectory`; it MUST NOT derive `statusUrl` from `server_url`
or substitute any log reference.

### Environment Variables

Variables are read by exact name. A variable that is unset, empty, or
whitespace-only is absent. Values are trimmed. The `DNSID_` namespace is shared
with deployment tooling, so unknown `DNSID_*` variables are ignored rather than
rejected.

| Variable | Maps to | Parse |
|---|---|---|
| `DNSID_DOMAIN` | `dnsid.identity.domain` | string |
| `DNSID_GOVERNANCE_ID` | `dnsid.identity.governanceId` | string |
| `DNSID_STATUS_URL` | `dnsid.identity.statusUrl` | string |
| `DNSID_LOG_REF` | `dnsid.identity.logRef` | string |
| `DNSID_EK_URL` | `dnsid.identity.ekUrl` | string |
| `DNSID_KU_URL` | `dnsid.identity.kuUrl` | string |
| `DNSID_PUBLISH_PROFILE` | `dnsid.identity.publishProfile` | string |
| `DNSID_CAPABILITIES_URL` | `dnsid.identity.capabilitiesUrl` | string |
| `DNSID_DNSSEC_MODE` | `dnsid.verification.dnssecMode` | `auto`, `validated`, or `required`; anything else is `ArgumentError` |
| `DNSID_DNS_SERVER` | `dnsid.transport.dnsServer` | string |
| `DNSID_CA_BUNDLE` | `dnsid.transport.caBundlePath` | string |
| `DNSID_PRIVATE_HOSTS` | `dnsid.transport.privateAddressHosts` | comma-separated; entries trimmed, empties dropped; absent when nothing remains |
| `DNSID_LOG_POLICY_URL` | `logTrust.policyUrl` | string |
| `DNSID_LOG_POLICY_FILE` | `logTrust.policyDocument` | path; loader reads the file bytes |
| `DNSID_LOG_TRUST_PROFILE_FILE` | `logTrust.profile` | path; loader reads and parses the file |
| `DNSID_REGISTRY_URL` | `registry.registryUrl` | string |
| `DNSID_API_KEY` | `RegistryClientFromEnvironment` only; not `LoadedConfig` | trimmed secret, absent if empty |
| `DNSID_CONFIG_DIR` | `keySource.cliDirectory` | string |
| `DNSID_KEY_STORE` | `keySource.keyStorePath` | string |

Configuration fields without a variable (`policyFlags`, `maxKeyAge`,
`statusCheckInterval`, `trustedEntities`, `logTrust.managed`,
`keySource.entityKeyPath`, and all profile settings) are set through the deployment file or the
code overlay. Add a variable here when a consumer needs one; do not add
binding-local names.

Variables that deployment tooling exports for the hosted application
(`DNSID_PUBLIC_URL`, `DNSID_AGENT_NAME`, `DNSID_AGENT_PORT`,
`DNSID_AGENT_UPSTREAM`, `DNSID_SERVER`) are not SDK configuration. SDK loaders
do not read or return them. Tooling that exports an environment for SDK
consumers SHOULD emit `DNSID_REGISTRY_URL`, not only the CLI's `DNSID_SERVER`.

### Deployment File

The deployment file is the JSON encoding of `LoadedConfig` minus
`keySource`, which is never written to a shared file. Registry credentials
are never part of `LoadedConfig` or the deployment file.
It is an umbrella-package convenience, not a core type: each section maps 1:1
onto an existing type with no cross-section logic.

```json
{
  "dnsid": { "verification": { "dnssecMode": "required", "trustedEntities": [{ "governanceId": "acme.example" }] } },
  "logTrust": { "managed": true },
  "registry": { "registryUrl": "https://registry.example" }
}
```

| Section | Maps to |
|---|---|
| `dnsid` | `DnsidConfig`, validated by the `IdentityManager` constructor. |
| `logTrust` | `LogTrust`; exactly one of `managed`, `profile` (inline document), or `policyUrl`. `policyDocument` has no file member; supply it through `DNSID_LOG_POLICY_FILE` or code. |
| `registry` | `RegistryConfig`, validated by the `RegistryClient` constructor. |

The file loader MUST reject unknown members and mistyped values, and SHOULD
reject duplicate members where the platform parser makes that available.
Profile settings (`jose`, `oidc`, `webBotAuth`, `httpMessageSignatures`) are
not sections today; add them as siblings when a consumer needs them. Runtime
objects such as checkpoint stores and injected fetchers stay code-only.

## Merge

```
FUNCTION Merge(base: LoadedConfig, overlay: LoadedConfig) -> LoadedConfig
```

- Field-wise: a field present in `overlay` replaces the same field in `base`;
  a field absent in `overlay` leaves `base` unchanged.
- Presence, not truthiness: an explicit empty list, empty string, or zero in
  `overlay` replaces the base value.
- Lists replace; they are never concatenated or deduplicated across sources.
- `logTrust` is replaced as a whole section when `overlay` sets any variant.
- A section absent from both stays absent.

A binding whose partial configuration uses value fields that cannot distinguish
omission from a scalar's zero value (such as `0` or `""`) treats that zero value
as absent in `Merge`. A code overlay cannot use that value to clear a loaded
nonzero field; this exception does not apply to an explicitly empty list where
presence can be represented. Bindings MUST document which fields are affected.
Callers that need to clear one can set the desired value on the merged config
before passing it to `Construct`.

When a convenience constructor combines sources, the order is fixed: DNSid CLI
directory, deployment file, environment, code overlay; later wins. Callers
composing sources themselves may choose any order.

## Construction

Construction consumes a merged `LoadedConfig` and caller-supplied dependencies.
It fills only dependencies the caller did not supply; caller dependencies win
and any loaded value they displace is ignored. Bindings whose dependency
injection is opaque (functional options) expose `logRegistry`, `keyProvider`,
and `entityKeyProvider` in an inspectable form so `Construct` can observe
presence.

```
FUNCTION Construct(loaded: LoadedConfig, deps: IdentityManagerDependencies) -> IdentityManager
  ValidateDnsidConfig(loaded.dnsid)       // SHOULD: fail on configuration before reading key files or fetching policy
  IF deps.logRegistry ABSENT AND loaded.logTrust PRESENT THEN
    deps.logRegistry = LogRegistryFromTrust(loaded.logTrust, loaded.dnsid.transport)
  END
  IF loaded.dnsid.identity PRESENT AND loaded.keySource PRESENT THEN
    IF deps.keyProvider ABSENT THEN
      deps.keyProvider = OperationalKeyProviderFrom(loaded.keySource, loaded.dnsid.identity.domain)
    END
    IF deps.entityKeyProvider ABSENT AND loaded.keySource.entityKeyPath PRESENT THEN
      deps.entityKeyProvider = FileKeyProvider(loaded.keySource.entityKeyPath)
    END
  END
  RETURN IdentityManager(loaded.dnsid, deps)
END
```

`Construct` adds no configuration values. The factories it calls are
constructors and apply their own defaults, like any other constructor.

`LogRegistryFromTrust` dispatches on the single `LogTrust` variant.
`managed: true` calls the
[managed factory](11-c2sp-tlog-binding.md#dnsid-managed-trust) with no options.
`profile`, `policyDocument`, and `policyUrl` call the
[generic factory](11-c2sp-tlog-binding.md#verification-convenience-factory)
with that one trust input, `transport` set to `loaded.dnsid.transport` so the
policy fetch honors `caBundlePath` and `privateAddressHosts`, and the same
fixed defaults the managed factory documents: checkpoint maximum age 10
minutes, maximum stream-bundle lifetime 10 minutes, allowed clock skew zero.
Freshness, limits, and bundle requirements are not loadable; a deployment that
needs different values constructs the registry with the generic factory and
injects `deps.logRegistry`.

`OperationalKeyProviderFrom` uses `cliDirectory` when present, otherwise
`keyStorePath`, and locates CLI key files under the effective identity domain
as [01](01-core-identity-manager.md#initialization-from-dnsid-cli-configuration)
requires. `IdentityManager(config, deps)` is the ordinary constructor; it
applies every default and performs every validation.

The registry path takes `loaded.registry` and an independently supplied
credential. `RegistryClientFromEnvironment` reads `DNSID_API_KEY` directly,
trims it, and passes it to `RegistryClient` without storing it in `LoadedConfig`.
Explicit caller credentials take precedence. The constructor applies the
[05](05-transport-and-registry.md#registry-responsibilities) loopback default
when `registryUrl` is absent.

## Convenience Constructors

Bindings MAY offer one-call identity-manager constructors. Each MUST be
expressible as `Load → Merge → Construct` with no defaulting, derivation, or
dependency selection of its own. The registry convenience constructor follows
the separate credential path above.

```
IdentityManagerFromEnvironment(env?, overlay?: DnsidConfig, deps?) -> IdentityManager
  = Construct(Merge(LoadEnvironment(env), {dnsid: overlay}), deps)

IdentityManagerFromDnsid(directory?, overlay?: DnsidConfig, deps?) -> IdentityManager
  = Construct(Merge(LoadCliDirectory(directory), {dnsid: overlay}), deps)

IdentityManagerFromFile(path, overlay?: DnsidConfig, deps?) -> IdentityManager
  = Construct(Merge(LoadFile(path), {dnsid: overlay}), deps)

RegistryClientFromEnvironment(env?) -> RegistryClient
  = RegistryClient(LoadEnvironment(env).registry, Trim(env["DNSID_API_KEY"]))
```

Names and argument passing are binding-idiomatic. `LoadCliDirectory` with no
directory reads `~/.dnsid`; that is a source-location default, not a
configuration default, and is permitted. It does not consult
`DNSID_CONFIG_DIR`; that variable reaches `Construct` through
`LoadEnvironment` as `keySource.cliDirectory`, so under `dnsid local run` the
one-liner is `IdentityManagerFromEnvironment()`. An environment with no
`DNSID_DOMAIN` yields a verification-only manager; an environment exported by
`dnsid local env` (transport, DNSSEC mode, `DNSID_LOG_POLICY_URL`) yields a
manager that can verify draft 01 identities without further wiring. The
environment variable names for log trust are the same ones `dnsid record
verify` reads; there are no SDK-local aliases.

## Validation Scenarios

| Scenario | Required result |
|---|---|
| Only transport and verification variables set | Verification-only manager; `identity` absent. |
| `DNSID_DOMAIN` set, `DNSID_LOG_REF` absent | Construction fails with `ArgumentError`; no placeholder log reference. |
| `DNSID_STATUS_URL` absent, `DNSID_REGISTRY_URL` set | `statusUrl` absent; not derived from the registry URL. |
| CLI `config.json` without `status_url`, with `server_url` | `statusUrl` absent; not derived. |
| `DNSID_DNS_SERVER` empty or whitespace | Field absent; constructor default applies. |
| `DNSID_API_KEY` set | `LoadEnvironment` contains no credential; `RegistryClientFromEnvironment` passes it only to the registry client. |
| `DNSID_PRIVATE_HOSTS=" , "` | Field absent. |
| `DNSID_DNSSEC_MODE=bogus` | Loader fails with `ArgumentError` before construction. |
| File sets `trustedEntities: [a]`, overlay sets `[]` | Result is `[]`, deny all. |
| File sets `trustedEntities: [a]`, overlay omits it | Result is `[a]`. |
| File `logTrust.managed`, environment `DNSID_LOG_POLICY_URL` | Result is `policyUrl` only. |
| `DNSID_LOG_POLICY_FILE` and `DNSID_LOG_POLICY_URL` both set | Construction fails with `ArgumentError`; the loader does not pick one. |
| `logTrust` loaded, `deps.logRegistry` supplied | Caller's registry used; loaded trust ignored. |
| `DNSID_LOG_POLICY_URL`, `DNSID_CA_BUNDLE`, `DNSID_PRIVATE_HOSTS=.test` set | Policy fetch uses the CA bundle and private-host allowance; verification of a `.test` draft 01 identity succeeds with no further wiring. |
| `DNSID_LOG_TRUST_PROFILE_FILE` set, profile carries bundle verifier keys | Registry constructs with the 10-minute bundle lifetime default; no `ArgumentError`. |
| `DNSID_CONFIG_DIR` and `DNSID_KEY_STORE` both set | Operational key from the CLI directory; key store unused. |
| CLI `config.json` with `entity_key_path`, no caller `entityKeyProvider` | Entity key provider loaded from the resolved path. |
| `IdentityManagerFromDnsid()` with `DNSID_CONFIG_DIR` set | Reads `~/.dnsid`; the variable is not consulted. |
| Same inputs through a convenience constructor and through manual `Load → Merge → Construct` | Identical validated snapshot and dependency wiring. |
| `DNSID_PUBLIC_URL`, `DNSID_AGENT_PORT`, `DNSID_SERVER` set | Ignored by SDK loaders. |
| Deployment file with unknown member, or `logTrust` with zero or two variants and no caller `logRegistry` | Loader or construction fails with `ArgumentError`. |
| Invalid `dnsid` config together with a `policyUrl` | Construction fails with `ArgumentError` without fetching the policy. |
| Any constructor invoked with environment variables or files present | Constructor reads neither. |
