# Transport and Registry Workflows

This document defines SDK-managed HTTPS transport helpers and registry
control-plane workflows. These are useful SDK features, but they are distinct
from peer identity verification.

## Transport Responsibilities

#### `CreateDnsidHttpClient(transportConfig: TransportConfig) -> HttpClient`

*Application-layer transport helper. Not defined by the DNSid protocol.*

Creates an SDK-managed HTTP client for DNSid-aware HTTPS requests. The client applies `TransportConfig.dnsServer` for HTTPS origin name resolution and `TransportConfig.caBundlePath` for TLS trust augmentation without mutating global process or runtime DNS, HTTP, or TLS settings.

`TransportConfig` is the `DnsidConfig.transport` section for an identity manager,
not a dependency object. Standalone transport helpers accept the same type.
See [Configuration Ownership and Loading](01-core-identity-manager.md#configuration-ownership-and-loading)
for snapshot, validation, loading, and injected-transport conflict rules.

`TransportConfig` fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `dnsServer` | string | no | DNS server used by SDK-managed DNS TXT verification and SDK-managed HTTPS origin resolution. Intended for product and development environments that need resolver injection; not a DNSid protocol field. Example forms include `127.0.0.1:7753` and `dns-compose:53`. |
| `caBundlePath` | string | no | Path to an additional PEM CA bundle used for SDK-managed HTTPS verification, including JWKS, status, registry, and requests made through DNSid HTTP transport helpers. This augments the platform trust store and does not disable TLS verification. Intended for development or private PKI deployments; not a DNSid protocol field. |
| `privateAddressHosts` | []string | no | Hostnames, or leading-dot suffixes such as `.test`, whose SDK-managed HTTPS destinations may resolve to loopback or private-use addresses. Empty by default. See [Private Address Hosts](#private-address-hosts). Not a DNSid protocol field. |

Language bindings SHOULD expose this capability through their platform's
idiomatic HTTP abstraction, such as a configured HTTP client, transport,
session, or request function. Development CLIs may inject these values through
environment variables such as `DNSID_DNS_SERVER`, `DNSID_CA_BUNDLE`, and
`DNSID_PRIVATE_HOSTS` (comma-separated); explicit SDK loaders may read them as
defaults for `TransportConfig`, but explicit caller configuration wins. Constructors and transport helpers do not read the
environment implicitly. The helper is intended for registry workflows,
[`JWKS`](07-protocol-data-types.md#jwks) /
[`AgentStatus`](07-protocol-data-types.md#agentstatus) / capabilities
fetches, and application requests that need the same DNSid transport
configuration.

#### Private Address Hosts

SDK-managed HTTPS fetches reject loopback, private, link-local, multicast,
reserved, and otherwise non-routable destinations by default
([01: HTTPSFetcher Interface](01-core-identity-manager.md#httpsfetcher-interface)).
Local development and testnet deployments, such as a `dnsid local` stack that
serves `*.test` agents, JWKS, status, and log resources from loopback, need a
way to reach those services without weakening the guard elsewhere.
`privateAddressHosts` is that opt-in.

Semantics:

- Entries are hostnames or leading-dot suffixes. `agent.example.test` matches
  only that name; `.test` matches `test` and every name beneath it, with
  DNS-label boundary matching (`evil-test` and `evil.test.example` do not
  match `.test`). Matching is case-insensitive and ignores a trailing dot.
- A matching host may resolve to loopback (`127.0.0.0/8`, `::1`) or private-use
  (RFC 1918, RFC 4193) addresses. Link-local, multicast, reserved, unspecified,
  and other non-routable classes are still rejected, and a resolution that
  mixes public and non-public addresses is rejected.
- Matching is per destination hostname, evaluated independently for the
  initial request and every redirect hop. It never exempts IP-literal URLs.
- Every other fetcher guarantee is unchanged: validated resolution, connection
  to the validated address, TLS verification (use `caBundlePath` for a local
  CA), HTTPS scheme, exact `200 OK`, finite deadlines, redirect counts, and
  streamed size limits.
- The setting applies to every fetch the SDK makes with this `TransportConfig`:
  JWKS, status, and capabilities documents, OIDC discovery and JWKS, and the
  C2SP verification factory's default resource fetcher when it is given this
  configuration. It does not apply to injected fetchers
  ([01: injected-transport conflicts](01-core-identity-manager.md#configuration-ownership-and-loading)).
- Entries are validated at construction: IP literals, ports, schemes, paths,
  and credentials are rejected with `ArgumentError`.
- There is no built-in exemption. SDKs MUST NOT treat `.test`, `.localhost`,
  `.internal`, or any other name as allowed unless it is configured. Reserved
  TLDs are ordinary suffix entries; `.test` is the expected entry for a local
  `dnsid` stack, and development tooling that starts such a stack SHOULD emit
  or export `DNSID_PRIVATE_HOSTS=.test` alongside `DNSID_DNS_SERVER` and
  `DNSID_CA_BUNDLE`.

```
FUNCTION CreateDnsidHttpClient(transportConfig: TransportConfig) -> HttpClient
  client = NewHttpClient()
  IF transportConfig.dnsServer != "" THEN
    client.SetResolver(transportConfig.dnsServer)
  END
  IF transportConfig.caBundlePath != "" THEN
    client.AddTrustedCABundle(transportConfig.caBundlePath)
  END
  RETURN client
END
```

---

## Registry Responsibilities

Registry workflows are operator/control-plane operations. `RegistryConfig` contains registry control-plane settings such as `registryUrl`. `VerifyDomain` must continue to verify external identities from the signed DNSid record and the record's `su` endpoint, not from `RegistryConfig.registryUrl`. In pseudocode, `config.identity` refers to the manager's `IdentityConfig`.
Registry settings are owned by `RegistryClient`, not `DnsidConfig`. Configuring
this control-plane client MUST NOT approve its registrants or populate the
verifier's `trustedEntities` allowlist. Registry-backed dynamic acceptance
is outside the initial SDK acceptance surface.

`RegistryConfig` fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `registryUrl` | string | no | Base URL of the DNSid registry for managing the local identity's own registration and status publication workflows. Never used by `VerifyDomain` to validate external identities. HTTPS is required except for plain HTTP to a literal loopback host (`localhost`, `127.0.0.1`, `[::1]`); userinfo, query, and fragment are rejected. SDKs MAY default it to the local `dnsid local` registry (`http://127.0.0.1:7755`); hosted deployments must set it explicitly. |

During the Internet-Draft period, registry and SDK releases publish the same
latest fully supported submitted numbered selector, initially
`dnsid-draft-01`. Registries MUST NOT publish `DNSid1`, dated selectors, or an
unsubmitted draft selector. When publication advances after a new IETF
submission, the observed DNS record must contain that expected numbered selector.

Registry publication has two distinct authority models. The selected model is
determined by who controls the accountable-entity key referenced by `ek`, not
merely by who operates the DNS hosting service:

| Publication authority | `sg` signer | SDK responsibility |
|---|---|---|
| Client-controlled | The SDK's accountable-entity key provider | Validate and sign registry-prepared canonical content, then submit the signature. |
| Registry-managed | The registry's accountable-entity signer | Register the operational public key, complete required lifecycle authorization, and wait for the registry to sign and publish. |

The operational key referenced by `ku` MUST NOT sign a draft 01 `sg`. An SDK MUST
NOT silently substitute the operational key when an entity key is unavailable,
and MUST NOT ask a registry-managed identity to produce a client signature.

#### `PublishClientControlledRecord(registryClient: RegistryClient) -> PublishedRecord`

Publishes a DNSid TXT record when the SDK controls the accountable-entity key.
The registry supplies or confirms the canonical record content to be signed;
`PublishClientControlledRecord` signs that canonical byte sequence with the
current active entity key and returns the DNS publication result. Before
signing, the SDK MUST parse and validate the registry-supplied canonical content
as a [`DnsIdTxtRecord`](07-protocol-data-types.md#dnsidtxtrecord), resolve its
profile, confirm that the profile is publishable by this SDK and matches
`config.identity.publishProfile` (default `dnsid-draft-01`), and confirm
that all profile-known tags match exactly the unsigned record this identity would
have produced locally for the same `IdentityConfig` and active entity and agent keys. Unknown tags
present in the registry's canonical content (such as registry-managed expiry or
policy tags) are accepted as-is and included in the signed bytes without
comparison; the SDK MUST NOT strip or reorder them before signing. Because the entity signing key ID is not carried
inside the TXT record's canonical bytes, registry workflows that select or
confirm a signing key MUST return the entity signing `kid` as response metadata and the
SDK MUST compare it with the local active entity key. This prevents a registry from
tricking the SDK into signing unsupported or non-publishable profile bytes. This
helper is distinct from
[`CreateTxtRecord()`](01-core-identity-manager.md#core-methods),
which constructs and signs a local TXT record string for publication outside the
registry workflow. The registry workflow steps in the pseudocode are abstract
operations, not required public `RegistryClient` method names.

```
FUNCTION PublishClientControlledRecord(registryClient: RegistryClient) -> PublishedRecord
  registration = registryClient.GetRegistration(config.identity.domain)
  IF registration.publicationAuthority != "client" THEN
    RAISE ValidationError("registry controls accountable-entity publication")
  END

  expected = BuildUnsignedDnsIdTxtRecord(config.identity)
  profile = expected.Profile()
  signingProvider = profile.RecordSigningProvider(entityKeyProvider, keyProvider)
  signingKey = signingProvider.SigningKey()
  IF signingKey.kid == "" THEN
    RAISE ValidationError("active record-signing key missing kid")
  END

  canonicalResponse = registryClient.CanonicalRecordContent(config.identity.domain, signingKey.kid)
  IF canonicalResponse.signingKid != signingKey.kid THEN
    RAISE ValidationError("registry canonical content targets a different active signing kid")
  END
  canonical = canonicalResponse.canonical

  registryRecord = DnsIdTxtRecord.ParseUnsignedCanonical(canonical)
  registryRecord.IdentityFQDN = config.identity.domain
  registryRecord.Validate()

  registryProfile = ResolveIdentityRecordProfile(registryRecord.v)
  IF registryProfile == nil OR NOT registryProfile.PublishAllowed() THEN
    RAISE ValidationError("registry canonical content uses an unsupported DNSid publish profile")
  END
  IF registryRecord.v != expected.v THEN
    RAISE ValidationError("registry canonical content uses an unexpected DNSid version")
  END
  IF registryRecord.KnownTagsCanonical() != expected.KnownTagsCanonical() THEN
    RAISE ValidationError("registry canonical content does not match local unsigned DNSid record")
  END
  // Unknown tags in registryRecord (e.g. registry-managed expiry) are accepted
  // as-is. Sign the full canonical bytes the registry returned, not a stripped copy.

  signingKey.SignatureAlg(profile=registryProfile) // validates required alg/key binding
  sig = signingProvider.Sign(ASCIIBytes(canonical))
  RETURN registryClient.PublishSignature(config.identity.domain, registryProfile.EncodeRecordSignature(sig))
END
```

SDKs that already expose `PublishToRegistry` MAY retain it as a deprecated
compatibility alias for `PublishClientControlledRecord`. New APIs and examples
SHOULD use the authority-specific name. The alias MUST perform the same
publication-authority check; it is not an escape hatch for registry-managed
identities.

The exact known-tag comparison is intentionally fail-closed. A caller using the
current product's client-controlled flow must configure the SDK with the values
the registration established: the numbered publish profile, `gi`, `ek`, `ku`,
`lr`, `su`, optional `cu`, and `ka=90d`. The management status response does not
currently supply an authoritative `IdentityConfig`, so SDKs MUST NOT guess these
values from unrelated response fields. Product adapters MAY expose a separate
typed setup result containing them, but generic registry clients must require
the caller to provide the effective protocol configuration.

#### `AwaitRegistryManagedPublication(registryClient: RegistryClient) -> PublishedRecord`

Waits for publication when the registry controls the accountable-entity key and
DNS publication. The SDK supplies the operational public key during registration
and completes any lifecycle authorization required by the selected log binding,
including operational-key consent for ISSUANCE. It does not request canonical
TXT bytes for local entity signing and does not call `PublishSignature`.

After the registry reports publication complete, the SDK resolves the published
`_dnsid` record through its configured DNS transport and validates it normally.
The returned `PublishedRecord` describes the observed DNS record and retains the
registry's raw workflow response. A registry `READY` state without an observed,
valid record is not publication success.

Publication confirmation uses the same internal protocol-evidence verification
as `VerifyDomain`, preserving configured DNSSEC, transport/log trust, status,
freshness, and applicable connection checks, but does not run counterparty
acceptance. This control-plane operation MUST NOT mutate policy, implicitly
allowlist the local entity, or expose a public acceptance-bypass option. Public
`VerifyDomain`, including calls on the local domain, continues to enforce
acceptance. The internal helper below is conceptual, not a new public API.

```
FUNCTION AwaitRegistryManagedPublication(registryClient: RegistryClient) -> PublishedRecord
  registration = registryClient.GetRegistration(config.identity.domain)
  IF registration.publicationAuthority != "registry" THEN
    RAISE ValidationError("client controls accountable-entity publication")
  END

  LOOP
    registration = registryClient.GetRegistration(config.identity.domain)
    IF registration.registryStatus IN ["REJECTED", "CANCELLED", "ERROR", "REVOKED", "RETIRED"] THEN
      RAISE RegistryWorkflowError(registration)
    END
    IF registration.registryStatus == "READY" AND registration.dnsPublished THEN
      BREAK
    END
    WaitAccordingToRegistryRetryPolicy()
  END

  verified = VerifyPublicationEvidence(config.identity.domain) // Protocol checks, not counterparty acceptance.
  expectedProfile = config.identity.publishProfile OR "dnsid-draft-01"
  IF verified.record.v != expectedProfile THEN
    RAISE ValidationError("published DNSid record uses an unexpected version")
  END
  RETURN PublishedRecord.FromVerifiedDomain(registration, verified)
END
```

The current product API uses registry-managed publication for managed draft 01
identities: the registry holds the entity signer and publishes automatically
after accepted lifecycle issuance. For self-managed identities, `/record`
selects the single current accountable-entity key at
`https://{gi}/.well-known/dnsid/entity.jwks`, and `/signature` accepts the bare
draft 01 signature produced by that key. The operational key at `ku` remains
separate and does not sign the TXT record.

#### Registry Custody and Pins

For the Identity Digital Live product, the organization entity key is held in
registry-managed KMS custody and served under the governance domain through the
`dnsid.<gi>` CNAME arrangement. Pinning that key pins the organization's
registry-custodied key material, not a customer-held private key or the registry's
log key. Registry key replacement and record re-signing, including compromise
recovery or governance-domain changes, can invalidate relying-party pins. A
changed governance ID also requires an explicit allowlist update. The SDK
provides no automatic pin-update or rotation-notification guarantee.

These are product deployment considerations, not DNSid protocol requirements.
Relying parties using pins must arrange authenticated enrollment and coordinated
updates; see [Counterparty Acceptance](01-core-identity-manager.md#counterparty-acceptance).

### Managed Lifecycle Operation Contract

DNS, status, key hosting, registry storage, and a lifecycle log are not one
atomic system. Each managed issuance, rotation, revocation, retirement, or
migration therefore has one durable coordinator and exactly one retry owner.

```
TYPE LifecycleOperation
  operationId: string
  identityInstanceId: string
  domain: string
  operationType: issuance | key_rotation | revocation | retirement | migration
  semanticIntent: object          // immutable after preparation
  desiredStateBySystem: map[string]any
  observedStateBySystem: map[string]any
  preparedEntryBytes?: bytes
  completedEntryBytes?: bytes
  entryHash?: string
  idempotencyKey?: string
  submissionState?: prepared | submitting | indeterminate | accepted | rejected
  acceptedIndex?: integer
  finalReference?: string
  retryOwner: string
  lastError?: RegistrySubmissionError
  convergenceState: pending | retrying | indeterminate | complete | terminal_failure
  createdAt: timestamp
  updatedAt: timestamp
END
```

The coordinator retries an unknown append outcome with the identical entry
bytes and idempotency key. Once submission may have begun, it never regenerates
timestamps, signatures, or chain metadata. An idempotency key reused with
different bytes is rejected. Only an expired preparation durably known never to
have entered submission may be replaced.

Protocol status and convergence are reported separately. Revocation can return
protocol `REVOKED` while log evidence is `pending`; issuance cannot return
protocol `ACTIVE` until bilateral ISSUANCE is accepted and the verification
resources are published. SDKs MUST NOT race a registry-owned append with a
second local append. They may sign or countersign prepared bytes only for
operations that require a client-held key, such as issuance and key rotation,
and may poll the one coordinator's operation. Registry-owned revocation is
requested through the lifecycle mutation endpoint; it is not a prepared-event
SDK flow.

For migration, the coordinator acquires an exclusive lifecycle-write lease,
persists and verifies the previous-log cutoff, appends and verifies the inbound
MIGRATION in the destination stream, then re-signs and publishes DNS with the
new `lr`. Future writes route permanently to the destination before the lease is
released. A failed DNS update retries publication against the already accepted
migration event; it does not create another event. Until DNS changes, the old
`lr` remains authoritative. Afterward, the destination `lr` returns the stitched
history.

---

### RegistryClient

Operator-side client for DNSid registry workflows for the local identity's own managed records. `RegistryClient` is not used by `VerifyDomain` when validating external identities; protocol verification always fetches the `su` endpoint asserted in the signed TXT record.

Registry preparation responses remain untrusted transport values until the
selected log binding parses and validates them:

```
TYPE PreparedRegistryEvent
  entryBytes: bytes       // exact response body; never decoded and re-encoded
  logReference: string    // exact DNSID-Log-Reference response-header value
END
```

`PreparedRegistryEvent` is not a `PreparedC2spTlogEvent`. The former preserves
untrusted registry bytes and reference text; the latter is produced only after
the C2SP binding parses those bytes against that reference and validates the
expected identity, keys, signatures, log context, and chain fields.

```
FUNCTION RegistryClient(baseUrl: string) -> RegistryClient

RegistryClient.GetRegistration(domain: string) -> AgentRegistration
  // GET {baseUrl}/api/v1/agent/{domain}/status.
  // The current product requires an owning-organization session credential or
  // organization API key for Live identities because the response can contain
  // a proof nonce. SDKs MUST NOT retry a failed authenticated Live read as an
  // unauthenticated request. Legacy status reads remain public.

RegistryClient.RegisterLiveAgent(input: LiveAgentRegistrationInput,
                                 idempotencyKey: string) -> LiveProvisioningResponse
  // POST {baseUrl}/api/v1/agent with tier="live" and managed=true.
  // Send idempotencyKey as the required Idempotency-Key header. The request
  // supplies public_key, omits domain and zone_id, and omits environment or
  // sets it to production. Only HTTP 202 is decoded as LiveProvisioningResponse,
  // never AgentRegistration; Live provisioning has not completed at this point.
  // While status is challenge_pending, domain is parsed from the validated
  // challenge transcript so it can address the proof routes.

RegistryClient.SubmitLiveProof(domain: string, request: LiveProofRequest,
                               idempotencyKey: string) -> LiveProofResponse
  // POST {baseUrl}/api/v1/agent/{domain}/proof. request.requestId must equal
  // idempotencyKey. The signature is unpadded base64url over the exact bytes
  // obtained by base64url-decoding the latest registration or reissue response's
  // challengeMessage. The current product adapter accepts only HTTP 202 and
  // rejects private JWK members before network I/O.

RegistryClient.ReissueLiveProof(domain: string, requestId: string,
                                publicKeyJwk: Ed25519 JWK,
                                idempotencyKey: string) -> LiveProofReissueResponse
  // POST {baseUrl}/api/v1/agent/{domain}/proof/reissue with JSON body
  // { "request_id": requestId }. requestId must equal idempotencyKey.
  // publicKeyJwk is the same public key submitted during registration; it is
  // local validation context and MUST NOT be serialized into the request body.
  // The SDK rejects invalid or private key material before network I/O and
  // rejects a replacement transcript unless keyId equals this key's RFC 7638
  // thumbprint. This operation only replaces an expired, unused proof challenge
  // and accepts only HTTP 202. Its replacement challengeMessage supersedes every
  // earlier one.

RegistryClient.CanonicalRecordContent(domain: string, signingKid: string) -> CanonicalRecordContentResponse
  // POST {baseUrl}/api/v1/agent/{domain}/record with JSON body { "signingKid": signingKid }.
  // Registry returns the exact unsigned Canonical() string it wants this identity to sign,
  // plus the signing kid it associated with the request. The SDK MUST validate both
  // before signing; this response is not trusted input. In the current product
  // API, caller signing through this endpoint is the client-controlled flow.
  // Registry-managed draft 01 publication does not use this operation.

RegistryClient.PublishSignature(domain: string, sig: string) -> PublishedRecord
  // POST {baseUrl}/api/v1/agent/{domain}/signature with JSON body { "signature": sig }.
  // sig MUST be encoded according to the selected publication profile. The
  // current product's self-managed route requires a bare draft 01 entity-key
  // signature.
  // Registry publishes or returns the signed DNSid TXT record after the SDK signs
  // the registry-provided canonical content. The response's publication status is
  // control-plane workflow state, not protocol AgentStatus.
  // Registry-managed draft 01 publication is automatic and does not call this operation.

RegistryClient.PrepareIssuance(domain: string,
                               idempotencyKey: string) -> PreparedRegistryEvent
  // POST {baseUrl}/api/v1/agent/{domain}/tlog/issuance/prepare with an empty
  // request body. Send idempotencyKey as the Idempotency-Key header.
  // The registry uses the authenticated identity's previously registered
  // operational public key and returns the exact partially signed canonical JCS
  // entry bytes as the response body. It also returns the bound C2SP stream
  // reference in the required DNSID-Log-Reference response header.
  // Treat both values as untrusted input. Parse the entry with the bound log
  // implementation, independently reproduce signedBytes, verify the domain,
  // governance identity, accountable-entity key and signature, local operational
  // public key, log context, and seq=0, then add only the operational signature.
  // A retry uses the same idempotency key and must receive byte-identical prepared
  // content; submission uses the same key and exact completed entry bytes.

RegistryClient.PrepareKeyRotation(domain: string, request: KeyRotationPreparationRequest,
                                  idempotencyKey: string) -> PreparedRegistryEvent
  // POST {baseUrl}/api/v1/agent/{domain}/tlog/key-rotation/prepare.
  // Send idempotencyKey as the Idempotency-Key header and encode request using the
  // wire fields previous_key_id and public_key.
  // Treat the returned envelope as untrusted input. Parse it with the bound log
  // implementation, independently reproduce signedBytes, verify the domain,
  // previous key, new key, log context, and stream-chain fields, then add the
  // previous-key authorization and every binding-owned signature.

RegistryClient.RevokeAgent(domain: string, agentId: string, reason: RegistryRevocationReason) -> LifecycleResponse
  // POST {baseUrl}/api/v1/agent/{domain}/revoke with JSON body
  // { "agent_id": agentId, "reason": reason }.
  // The registry persists REVOKED before scheduling cleanup and transparency-log
  // convergence. The SDK MUST NOT prepare or append a second REVOCATION event.
  // If scheduling fails after persistence, the registry returns a retryable error.
  // Retries carry the immutable agent ID because the domain may have been
  // re-registered. The same identity and reason schedule one durable coordinator;
  // a different reason is a conflict.

RegistryClient.RetireAgent(domain: string, agentId: string) -> LifecycleResponse
  // POST {baseUrl}/api/v1/agent/{domain}/retire with JSON body
  // { "agent_id": agentId }. The immutable agent ID prevents a retry from
  // retiring a replacement identity registered under the same domain. The
  // registry owns RETIREMENT append and convergence; the SDK MUST NOT append one.

RegistryClient.SubmitPreparedEvent(domain: string, entryBytes: bytes,
                                   idempotencyKey: string) -> SubmissionResult
  // POST {baseUrl}/api/v1/agent/{domain}/tlog/events with entryBytes as the exact
  // application/json request body and idempotencyKey as the Idempotency-Key header.
  // Submits the exact complete canonical bytes. A timeout or indeterminate result
  // is retried with the same bytes and idempotency key.
  // A non-2xx response is normalized to a typed indeterminate/rejected
  // SubmissionResult or raises RegistrySubmissionError after preserving the
  // registry error code and retry classification. It is not reduced to a generic
  // HTTP error and is never reported as an accepted result.
```

For a managed `ku` rotation, the SDK generates the new key locally and never
sends private material to the registry. In the current product,
`PrepareKeyRotation` requires an owning-organization session credential or
organization API key; an agent self-auth bearer credential is deliberately not
accepted because the key being replaced must not authorize its own replacement.
This control-plane authorization does not replace commit authority from the
previous operational signature. For the `c2sp-tlog` binding the SDK also signs
with the pending new key as proof of possession. Before submission, the SDK durably persists the exact
rotation state and pauses application signing through required injected
dependencies. After receiving an accepted submission result bound to the exact
entry hash and new key, it persists acceptance, activates the new key, supersedes
the old key, persists activation, and only then resumes signing. If submission is
indeterminate after publication but before the immutable append converges,
signing remains paused while the registry reconciles the same entry; it does not
create a replacement rotation. Restart recovery follows the core
[managed rotation recovery contract](01-core-identity-manager.md#managed-rotation-recovery-contract).

Registry implementations MAY expose additional setup and publication methods,
including registration, verification, and registry-managed TXT publication.
These are operator workflows, not part of
[`VerifyDomain`](01-core-identity-manager.md#core-methods)
trust establishment. SDK designs SHOULD expose those workflows through explicit
data types rather than unstructured registry responses.

#### CanonicalRecordContentResponse

Registry-prepared canonical TXT record content for a local identity signing workflow.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `canonical` | string | yes | Unsigned `DnsIdTxtRecord.Canonical()` content to be parsed, validated, and signed only after it matches the SDK's locally constructed record. |
| `signingKid` | string | yes | Registry's view of the active entity signing key ID for this canonical content. Must equal `entityKeyProvider.SigningKey().kid`. |

#### KeyRotationPreparationRequest

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `previousKeyId` | string | yes | RFC 7638 thumbprint of the SDK's current operational key. The registry rejects a stale or concurrent rotation. |
| `publicKey` | JWK | yes | One pending public signing key, including `kid` and `alg`; private JWK members are forbidden. |

The idempotency key is supplied separately as transport metadata. Reusing it
with different key material fails. A second preparation against the same
previous key also fails, even with another idempotency key.

#### AgentRegistrationInput

Input for every registration mode other than managed Live.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `domain` | string | conditional | Agent FQDN for a self-managed identity. Omit when the registry assigns the managed identity's domain or when `zoneId` selects a managed zone. |
| `name` | string | no | Human-readable registry metadata. Not published in the DNSid record. |
| `metadata` | map[string]any | no | Registry-specific metadata. Not used by protocol verification. |
| `publicKeyJwk` | JWK | no | Public signing key material supplied during registration when the registry workflow needs it. Private JWK members are forbidden. Managed Live uses the separate `LiveAgentRegistrationInput`. |
| `environment` | `"sandbox"` or `"production"` | no | Registry environment. Defaults to `production` when omitted; other values are rejected. Does not affect the registration mode. |
| `managed` | boolean | no | Whether the registry should manage DNS/JWKS publication for the identity. When true, `zoneId` is required. |
| `zoneId` | string | no | Registry-managed zone in which the server assigns the identity domain. Mutually exclusive with `domain`; setting it makes the registration managed. |
| `capabilitiesUrl` | string | no | HTTPS capabilities-document URL to publish as `cu`. |

The registration mode is determined only by `managed` and `zoneId`; the
environment is orthogonal metadata. An omitted environment defaults to
`production` and SDKs send the effective value explicitly rather than relying on
a server default. A self-managed helper supplies a domain in either
environment; a zone-managed helper supplies `zoneId` instead of a domain. The
current JSON wire names are `public_key`, `zone_id`, and `capabilities_url`.

These invariants apply to every public registration entry point, including a
generic `RegisterAgent` method, not only named convenience helpers. A request is
registry-managed when `managed` is true or `zoneId` is set. SDKs MUST reject
contradictory input before making a request: `domain` and `zoneId` cannot both
be set; `managed=true` requires `zoneId`; a managed registration omits
`domain`; and a self-managed registration requires `domain` and forbids
`zoneId`. The current product adapter accepts only HTTP 201 for this ordinary
registration shape; HTTP 202 is reserved for managed Live registration and MUST
NOT be parsed as `AgentRegistration`.

#### LiveAgentRegistrationInput

Input for the managed Live operation. Keeping fixed discriminators out of this
type prevents generic registration fields from creating ambiguous modes.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | no | Human-readable registry metadata. |
| `publicKeyJwk` | Ed25519 JWK | yes | One `OKP`/`Ed25519` public signing key using `alg="EdDSA"`. Private JWK members are forbidden. |
| `environment` | `"production"` | no | Omit or set to `production`. |
| `capabilitiesUrl` | string | no | HTTPS capabilities-document URL to publish as `cu`. |

The client sets `tier="live"` and `managed=true`; callers cannot override them.
`domain` and `zoneId` are not fields in this input. The idempotency key is
required transport metadata rather than a JSON field.

Managed Live registration is a separate operation, even though it uses the same
HTTP route. It requires a public key, an omitted domain and zone, and either an
omitted environment or `environment="production"`. It also requires an
`Idempotency-Key` and returns HTTP 202 `LiveProvisioningResponse`, not the HTTP
201 `AgentRegistration` shape. The returned `requestId` is retained for every
retry and proof operation. The base64url-decoded `challengeMessage` is the exact
byte sequence signed by the registered private key. Parsing it for routing or
validation MUST NOT change the bytes that are signed.

The server retains a legacy local Live mode selected by `tier="live"` and
`managed=false`, returning HTTP 201 through a different challenge workflow. It
is intentionally outside this portable SDK contract. Generic registration
methods MUST reject `tier="live"` rather than accidentally selecting or parsing
that legacy mode; a product-specific legacy adapter may expose it separately.

#### Live Provisioning Types

```
TYPE LiveChallengeTranscript
  protocol: string  // exactly "dnsid-live-provisioning-pop/v1"
  orgId: string
  agentId: string
  fqdn: string
  keyId: string
  nonce: string
  expiresAt: timestamp
END

TYPE LiveProvisioningResponse
  requestId: string
  agentId: string
  status: string
  challenge: string
  challengeMessage: string // unpadded base64url-encoded bytes
  domain: string           // derived; present while challenge_pending
  challengeTranscript: LiveChallengeTranscript // derived; present while challenge_pending
END

TYPE LiveProofRequest
  requestId: string
  challenge: string
  publicKeyJwk: Ed25519 JWK
  signature: string        // unpadded base64url Ed25519 signature
END

TYPE LiveProofResponse
  requestId: string
  agentId: string
  status: string
END

TYPE LiveProofReissueResponse
  requestId: string
  agentId: string
  status: string
  challenge: string
  challengeMessage: string // unpadded base64url-encoded bytes
  domain: string           // derived from challengeTranscript.fqdn
  challengeTranscript: LiveChallengeTranscript
END
```

For `challenge_pending`, the SDK base64url-decodes `challengeMessage`, parses its
UTF-8 JSON object, and rejects the response unless every transcript field is
present, `protocol` has the value above, `agentId` and `nonce` equal the outer
response, `keyId` equals the RFC 7638 thumbprint of the submitted public key,
`fqdn` is a valid agent domain, and `expiresAt` is a valid timestamp. It then
exposes `fqdn` as normalized `domain`. A successful reissue has the same
requirements, using the required reissue `publicKeyJwk` to validate `keyId`.
Other replay statuses may carry empty `challenge` and
`challengeMessage` strings; required wire fields do not imply non-empty values,
and derived `domain` and `challengeTranscript` are then absent.

The transcript's current wire names are `org_id`, `agent_id`, `key_id`, and
`expires_at`. Other current Live wire names are `request_id`, `agent_id`,
`public_key`, and `challenge_message`. Live registration, status, proof, and
proof reissue require an owning-organization session credential or organization
API key. SDKs MUST preserve the same request ID/idempotency key and public key
across retries, and callers MUST supply that original public key when requesting
a replacement challenge. Managed Live currently supports only an
`OKP`/`Ed25519` public key with `alg="EdDSA"`; SDKs reject other algorithms before
network I/O. Every
registration and proof entry point MUST also reject private JWK members before
network I/O, including private members nested in a JWKS-shaped input; public-key
fields must never silently serialize the source object's raw private
representation.

#### AgentRegistration

Registry registration or verification result for a local identity.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `domain` | string | yes | Registered agent FQDN. |
| `publicationAuthority` | `"client"` or `"registry"` | yes | Registry declaration of who controls the accountable-entity key and signs the DNSid record. For the current product API, `managed="dnsid"` maps to `"registry"` and `managed="self"` maps to `"client"`; other implementations MUST report this explicitly rather than infer it solely from DNS hosting, profile tags, or key availability. |
| `registryStatus` | string | yes | Registry-controlled registration workflow state exactly as returned by the management API, such as `PENDING`, `VERIFICATION`, `VERIFIED`, `READY`, `REJECTED`, `CANCELLED`, `ERROR`, `REVOKED`, or `RETIRED`. This is not protocol `AgentStatus.state`. |
| `dnsPublished` | boolean | no | Registry observation that DNS publication completed. Meaningful for registry-managed publication; successful SDK publication still requires resolving and validating the record. |
| `protocolStatus` | AgentStatus | no | Complete protocol-facing lifecycle status, when the registry response supplies authoritative state, transition time, and conditional revocation reason. SDKs MUST NOT construct this object solely by mapping `registryStatus`; they MAY obtain it from the identity's `su` endpoint or an equivalent complete protocol-status object returned by the registry. |
| `oidcIssuerUrl` | string | no | Exact `oidc_issuer_url` returned by the registry. Persist it for OIDC operations rather than deriving an issuer from the registry hostname. |
| `registryUrl` | string | yes | Registry base URL that produced the result. |
| `raw` | any | no | Original registry response for diagnostics or registry-specific extensions. |

Registry workflow state and protocol lifecycle state are separate namespaces.
An SDK MAY expose a registry-specific helper that maps workflow state to a
protocol state for display or polling, but that mapping is not an
[`AgentStatus`](07-protocol-data-types.md#agentstatus): the DNSid protocol status
also requires the actual time of the most recent protocol transition and, for
`REVOKED`, its reason. In particular, SDKs MUST NOT fabricate
`lastTransitionAt`, and publication readiness does not by itself prove protocol
`ACTIVE` state. Polling helpers MUST treat both `REVOKED` and `RETIRED` as
terminal rather than waiting until timeout.

#### PublishedRecord

Result of a registry-managed DNS TXT publication workflow.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `domain` | string | yes | Identity FQDN whose record was published. |
| `ownerName` | string | yes | DNS owner name for the TXT record, normally `_dnsid.{domain}`. |
| `txtRecord` | string | yes | Serialized `_dnsid` TXT record content published or returned by the registry. |
| `ttl` | number (seconds) | yes | DNS TTL associated with the published record. |
| `publicationStatus` | string | yes | Registry-controlled publication workflow state exactly as returned by the signature/publication API, such as `publishing` or `ready_for_publication`. This is not protocol `AgentStatus.state`. |
| `protocolStatus` | AgentStatus | no | Complete protocol-facing lifecycle status after publication, only when obtained from the authoritative `su` endpoint or supplied as an equivalent complete object by the registry. It MUST NOT be synthesized from `publicationStatus`. |
| `raw` | any | no | Original registry response for diagnostics or registry-specific extensions. |

#### RegistrySubmissionError

Typed failure from prepared-event submission. A binding may instead normalize a
structured non-2xx response to the equivalent typed indeterminate or rejected
`SubmissionResult`; both surfaces preserve the registry's stable `errorCode`
and retry classification. An error object additionally carries the HTTP status
and a `retrySameEntry` flag. For the current product adapter,
`TLOG_SUBMISSION_BUSY` and `TLOG_SUBMISSION_INDETERMINATE` retry the identical
`entryBytes` with the same idempotency key. `IDEMPOTENCY_MISMATCH`,
`TLOG_PREPARATION_MISMATCH`, and `TLOG_INVALID_ENTRY` are terminal for those
prepared bytes. Unknown transport failures remain indeterminate and MUST NOT
cause a replacement event to be created.
