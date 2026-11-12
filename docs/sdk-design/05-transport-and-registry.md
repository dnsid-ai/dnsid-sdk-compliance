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
session, or request function. The environment variables that populate this
section (`DNSID_DNS_SERVER`, `DNSID_CA_BUNDLE`, `DNSID_PRIVATE_HOSTS`) are
defined in [12](12-configuration-loading.md#environment-variables); constructors
and transport helpers do not read the environment. The helper is intended for registry workflows,
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

- Entries are hostnames or leading-dot suffixes. `agent.test` matches
  only that name; `.test` matches `test` and every name beneath it, with
  DNS-label boundary matching (`evil-test` and `test.example` do not
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

### Unified Registration

The SDK registration contract below follows
[merged PR #2631](https://github.com/Identity-Digital/dnsid/pull/2631)
(commit `4d9c7b6789b29fb47a6266f1c9f8df16590bf776`). It adds GI/root selectors
and authoritative publication configuration. Existing supported selectors and
managed Live creation remain available; protocol verification is unchanged.
Implementation trackers remain at their reviewed baselines.

Registry workflows are operator/control-plane operations. `RegistryConfig` contains registry control-plane settings such as `registryUrl`. `VerifyDomain` must continue to verify external identities from the signed DNSid record and the record's `su` endpoint, not from `RegistryConfig.registryUrl`. In pseudocode, `config.identity` refers to the manager's `IdentityConfig`.
Registry settings are owned by `RegistryClient`, not `DnsidConfig`. Configuring
this control-plane client MUST NOT approve its registrants or populate the
verifier's `trustedEntities` allowlist. Registry-backed dynamic acceptance
is outside the initial SDK acceptance surface.

`RegistryConfig` fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `registryUrl` | string | no | Base URL of the DNSid registry for managing the local identity's own registration and status publication workflows. Never used by `VerifyDomain` to validate external identities. HTTPS is required except for plain HTTP to a literal loopback host (`localhost`, `127.0.0.1`, `[::1]`); userinfo, query, and fragment are rejected. The `RegistryClient` constructor MAY default it to the local `dnsid local` registry (`http://127.0.0.1:7755`) when absent; hosted deployments must set it explicitly. Populated from `DNSID_REGISTRY_URL` per [12](12-configuration-loading.md#environment-variables). |

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
product's client-controlled flow configures the SDK from the registration's
[`PublicationConfig`](#publicationconfig): the numbered publish profile, `gi`,
`ek`, `ku`, `lr`, `su`, and any supplied `cu` and `ka`. SDKs MUST preserve this
snapshot rather than guess values from the requested selectors, environment,
registry hostname, or later organization defaults. A registry without this
setup result requires the caller to supply the effective protocol configuration.
Control-plane configuration does not replace validation of canonical signing
content or verification of the published record.

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
valid record is not publication success. This confirmation follows ISSUANCE.
Preparation instead uses authenticated [`dnsPublished`](#agentregistration)
while `PROVISIONING`, without waiting for `READY` or public `ACTIVE`.

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

The Identity Digital API uses registry-managed publication for managed draft 01
identities: the registry holds the entity signer and publishes while registration
is `PROVISIONING`, before ISSUANCE preparation and operational countersigning.
For self-managed identities, `/record` selects the single current accountable-entity key at the registration's
[`PublicationConfig.ekUrl`](#publicationconfig), and `/signature` accepts the
bare draft 01 signature produced by that key. The operational key at `ku`
remains separate and does not sign the TXT record.

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

### Registration and ISSUANCE

Identity Digital registration remains `PROVISIONING` through infrastructure
setup, signed publication, and bilateral ISSUANCE, whose operational signature
proves key possession. Management status has no nonce fields. `VERIFICATION`
and `VERIFIED` remain readable but do not establish completion. SDKs MUST NOT
request, sign, submit, or reissue registration nonces, including from saved metadata.

Publication authority and operational-key custody are independent:

| Publication authority | Operational key | ISSUANCE workflow |
|---|---|---|
| Registry-managed | Caller-held | Registry publishes and prepares an entity-signed ISSUANCE; the caller validates it, adds the operational signature, and submits the completed bytes. |
| Registry-managed | Registry custody | Registry publishes, signs with the distinct entity and operational keys, and submits the completed bilateral entry. |
| Client-controlled | Caller-held | Owner signs and publishes the identity record, constructs and signs the bilateral genesis, and submits the completed bytes. |
| Client-controlled | Registry custody | Owner signs and publishes the identity record and submits an entity-signed genesis; the registry validates publication and adds the custodied operational signature. |

Client-controlled record signing is available during `PROVISIONING`. Before new
owner-produced ISSUANCE is admitted, the registry checks the live signed DNS
record against the assigned domain, GI, log stream, accountable-entity key, and
current operational key. A record-signature response alone is not proof of DNS
publication. A publication failure returns `TLOG_PUBLICATION_REQUIRED`; the SDK
retains the exact envelope and idempotency key for retry.

Activation requires an accepted bilateral entry and receipt bound to the current
identity, operational key, and GI, together with publication and applicable
JWKS, TLS, and serving readiness. The registry checks these conditions under the
identity's activation guard. Assignment, publication, a submitted envelope, or a
workflow notification alone does not establish protocol `ACTIVE`.

Ordinary registration has a 48-hour ISSUANCE deadline after preparation/publication;
continuation retains the absolute deadline. Live waits for ISSUANCE while the
operation remains eligible, without a server-side issuance deadline. Each SDK
call still has a finite deadline, and cancellation preserves recovery state.

During publication, ISSUANCE, and public-readiness waits, each polling cycle
MUST refresh authenticated management state and check for failure or terminal
outcomes. `ERROR`, `REJECTED`, `CANCELLED`, `REVOKED`, and `RETIRED` stop polling;
permanent management-read errors also stop the call. Transient read failures
follow the bounded retry policy. Stopping preserves exact envelopes and
idempotency keys without canceling registration or creating a replacement.

An `ERROR` is not automatically resumed by create or polling. Self-managed
owners can explicitly retry verification through `/api/v1/agent/{domain}/verify`
for any error code. That retry returns to `PROVISIONING` and rechecks publication
and ISSUANCE. Managed terminal failures require staff disposition.

Operational private-key claim is an explicit owner action available only at
registry `READY`, after accepted ISSUANCE. Claim and key deletion do not activate
an identity; [custody replay](11-c2sp-tlog-binding.md#owner-only-custody-issuance)
remains valid after claim.

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
different bytes is rejected. Expired preparations may be replaced only under
[11's durable reclaimability rules](11-c2sp-tlog-binding.md#submission-and-idempotency).

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

### Known Foundry Create

[13: Known Foundry Create](13-known-foundry.md) defines the Identity Digital product
facade `Create(name)` and its handle, in a separate module. It is built on the
low-level methods below and uses named caller-key Live registration, never
sandbox creation. Ordinary registry defaults and replay behavior are defined
separately below.

### RegistryClient

Operator-side client for DNSid registry workflows for the local identity's own managed records. `RegistryClient` is not used by `VerifyDomain` when validating external identities; protocol verification always fetches the `su` endpoint asserted in the signed TXT record.

Omitted transport configuration and an empty `TransportConfig` MUST apply the
same protected defaults: validated destinations, TLS, finite deadlines/cancellation,
redirect bounds, and streamed decoded-size limits. Authenticated registry operations
MUST reject redirects without forwarding credentials or replaying the request to
the redirect target. Only the documented literal loopback registry permits
HTTP/local access without `privateAddressHosts`.
Compressed bodies are decoded once; adapters wrapping decoded bytes MUST remove
stale encoding/length metadata. Tests cover omitted versus empty configuration,
compressed responses, and decoded-size overflow.

Registry preparation responses remain untrusted transport values until the
selected log binding parses and validates them:

```
TYPE PreparedRegistryEvent
  entryBytes: bytes       // exact response body; never decoded and re-encoded
END
```

`PreparedRegistryEvent` is not a `PreparedC2spTlogEvent`. The former preserves
untrusted registry bytes; the latter is produced only after the C2SP binding
parses those bytes against a bound log reference and validates the expected
identity, keys, signatures, log context, and chain fields.

```
FUNCTION RegistryClient(baseUrl: string) -> RegistryClient

RegistryClient.RegisterAgent(input: AgentRegistrationInput,
                             idempotencyKey?: string) -> AgentRegistration
  // POST {baseUrl}/api/v1/agent. Accept only HTTP 201.
  // If supplied, send idempotencyKey as the Idempotency-Key header, not JSON.
  // Preserve creation facts before reading authenticated agent detail to obtain
  // publicationAuthority. See PublicationConfig and Registration Replay and Recovery.
  // Foundry Create/Active in 13 uses RegisterLiveAgent instead of this ordinary flow.

RegistryClient.GetOrganizationOnboarding() -> OrganizationOnboardingResponse
  // GET {baseUrl}/api/v1/org/onboarding with an organization API key or admin session.
  // Explicit account read; no agent creation or constructor/loader side effects.
  // Use the configured transport policies, deadline, and cancellation budget.

RegistryClient.GetRegistration(domain: string) -> AgentRegistration
  // GET {baseUrl}/api/v1/agent/{domain}/status using an owning-organization
  // session credential or organization API key. SDKs MUST NOT retry a failed
  // authenticated read anonymously.
  // This management route is distinct from the record's public su endpoint.

RegistryClient.RegisterLiveAgent(input: LiveAgentRegistrationInput,
                                 idempotencyKey: string) -> AgentRegistration
  // POST {baseUrl}/api/v1/agent with tier="live" and managed=true.
  // Send idempotencyKey as the required Idempotency-Key header. The request
  // supplies public_key, omits domain, zone_id, governance_domain, and root_domain,
  // and omits environment or sets it to production.
  // Accept only HTTP 201, including replay, and decode the assigned identity,
  // domain, registry status, publication_config, and oidc_issuer_url.
  // Validate the response Idempotency-Key header against the submitted key.
  // Persist creation facts before authenticated detail reads; 201 does not
  // establish publication, accepted ISSUANCE, or protocol ACTIVE.

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
  // Uses the registered operational public key; returns untrusted exact
  // entity-signed canonical entry bytes. Requires authenticated dnsPublished == true
  // including while PROVISIONING under AgentRegistration's publication rules.
  // Validation, countersigning, and retry follow 11: Split ISSUANCE Flow and
  // Submission and Idempotency.

RegistryClient.PrepareKeyRotation(domain: string, request: KeyRotationPreparationRequest,
                                  idempotencyKey: string) -> PreparedRegistryEvent
  // POST {baseUrl}/api/v1/agent/{domain}/tlog/key-rotation/prepare.
  // Send idempotencyKey as the Idempotency-Key header and encode request using the
  // wire fields previous_key_id and public_key.
  // Treat the returned envelope as untrusted input. Parse it with the bound log
  // implementation against the identity's verified log reference, independently reproduce signedBytes, verify the domain,
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
  // Submits complete canonical bytes unchanged; entry_hash must match those bytes.
  // Persistence, retry, and structured failures follow 11: Submission and Idempotency.

RegistryClient.SubmitOwnerIssuance(domain: string, ownerEntryBytes: bytes,
                                  idempotencyKey: string) -> SubmissionResult
  // POST {baseUrl}/api/v1/agent/{domain}/tlog/events with the exact canonical
  // entity-signed ISSUANCE body and the Idempotency-Key header.
  // For client-controlled publication with a registry-custodied operational key.
  // entry_hash identifies the server-completed entry, not the uploaded body.
  // Validation, completion, and replay follow 11: Owner-Only Custody ISSUANCE.
```

ISSUANCE uses [11's split-signing validation](11-c2sp-tlog-binding.md#split-issuance-flow),
[submission and idempotency](11-c2sp-tlog-binding.md#submission-and-idempotency), and,
for owner-only envelopes, [custody verification](11-c2sp-tlog-binding.md#owner-only-custody-issuance).

`PrepareKeyRotation` requires an owning-organization session credential or API key,
not agent self-auth. This control-plane authorization does not replace the previous
operational signature; `c2sp-tlog` also requires new-key proof of possession.
Private keys stay in customer-controlled providers. Persistence, signing pause,
acceptance/publication checks, activation, and restart follow the core
[rotation contract](01-core-identity-manager.md#operational-key-rotation).

#### Managed Operational Endpoints

SDKs consume registry-established `kuUrl` and entity-signed TXT `ku`; they never
synthesize paths from a name, thumbprint, provider alias, or registry hostname.
Host/cardinality constraints remain profile-owned. Fresh verification uses signed
current `ku`; historical verification uses accepted log evidence, not an old-URL
fallback. Rotation follows the current [core contract](01-core-identity-manager.md#operational-key-rotation).

Key-specific URL conventions, old-URL retention and hosted terminal serving are
E7/E8 product work, not prerequisites added to initial Foundry create. This design
does not mandate a new hosted path or overlapping live keys.

Registry implementations MAY expose additional setup and publication methods,
including verification and registry-managed TXT publication.
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

#### Account Binding Discovery

`GetOrganizationOnboarding` reads the existing organization-scoped onboarding
endpoint. Registry and discovery response parsing MUST ignore additional JSON
members. Unrecognized values MUST NOT satisfy required readiness or authority
checks or authorize replacement. Setup validates these fields:

| Setup value | Wire field | Validation |
|---|---|---|
| Stable organization ID | `org_id` | Nonempty account ID; compare configured/saved values byte-exact without reformatting. |
| Expected governance ID | `governance_domain` | Valid domain; compare any configured/saved GI. |
| Live governance proof | `gi.domain`, `gi.state`, `gi.gate_authorized` | GI object present, matching domain, state `verified`, and `gate_authorized` equal to `true`: the registry confirms acceptable governance-domain proof for this organization. |
| Entity-key delegation | `ek.status` | Must be `verified` before discovery supplies ready setup bindings. |

Absent or pending proofs are not verified. Onboarding does not return the entity
key URL; Foundry create reads it from `PublicationConfig.ekUrl`. Preserve 503 when
onboarding is unavailable and authorization errors when access is denied. This read
alone does not show that the server supports named create.

#### AgentRegistrationInput

Input for unified registration. Names below are language-neutral; bindings use
idiomatic public names and serialize the exact JSON wire names shown.

| Field | Wire name | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| `domain` | `domain` | string | no | Exact agent FQDN requested. Hosting is resolved by the registry, not selected by this field. Mutually exclusive with `rootDomain`. |
| `governanceDomain` | `governance_domain` | string | no | Expected accountable governance identifier (`gi`). With no `domain`, also selects an authorized root as described below. It is not an arbitrary signer override. |
| `rootDomain` | `root_domain` | string | no | Active delegated zone owned by the caller's organization under which the registry assigns a name. Not a zone ID. May be combined with `governanceDomain`. |
| `publicKeyJwk` | `public_key` | JWK | conditional | Public signing key required whenever the registry assigns the name or manages the identity. Optional for a self-managed exact domain whose JWKS is verified externally. Private JWK members are forbidden. |
| `name` | `name` | string | no | Ordinary registry metadata; at most 255 characters after trimming, not published in DNS. Foundry's required exact name belongs to the separate named Live workflow; ordinary trimming/fingerprint rules stay unchanged. |
| `capabilitiesUrl` | `capabilities_url` | string | no | HTTPS capabilities-document URL to publish as `cu`. |

New registration omits legacy selector defaults. Existing entry points may
retain `environment`, `tier`, `managed`, and `zone_id`: the server maps supported
combinations and rejects unsupported ones. Production plus `managed=true`
selects the configured production root; `zone_id` selects a caller-owned active
zone. Explicit GI/root selectors take precedence over environment/managed
defaults. SDKs MUST NOT silently discard selectors or invent GI/root translations.
Managed Live remains the separate operation below.

##### Resolution and Validation

| Supplied selectors | Registry resolution |
|---|---|
| `domain` | Preserve the exact normalized FQDN. An enclosing active zone owned by the caller makes it managed; otherwise use the self-managed flow if authorized. A domain does not guarantee client-controlled publication. |
| No `domain`, with `rootDomain` | Generate a name under that exact caller-owned active zone. If `governanceDomain` is also supplied, it must match the accountability that applies to the identity. |
| Only `governanceDomain` | The registry's verified governance domain selects its configured production root. The caller's verified governance domain selects its single eligible active zone under that GI. Other organizations' GIs do not authorize access. |
| No selectors | A public-key-only request generates a managed name under the configured sandbox root. Organization eligibility does not silently promote this default to production. |

SDKs MUST accept public-key-only input, reject `domain` plus `rootDomain`,
validate domain selectors and HTTPS capabilities URLs, and reject private JWK
material before network I/O. An assigned name requires a public key. For an
exact domain, the registry determines hosting and whether a key is required;
SDKs MUST NOT infer self-management from the request shape. Ownership, verified
GI evidence, active delegation, admission, and quota remain server checks.

SDKs preserve HTTP status and registry error codes without dropping selectors
or falling back to another root. Multiple eligible roots return 409
`AMBIGUOUS_ROOT`; callers choose `rootDomain`. An inactive root or GI mismatch
returns 400 `BAD_REQUEST`, an unauthorized GI returns 403
`GOVERNANCE_NOT_AUTHORIZED`, and unavailable infrastructure returns 503
`SERVICE_UNAVAILABLE`.

##### Named Foundry Registration

[Foundry create/active](13-known-foundry.md) uses the named caller-key Live
path below, not ordinary `RegisterAgent`. Names are exact and case-sensitive under
[13's rules](13-known-foundry.md#name-normalization). Pending, ERROR,
CANCELLED, and REJECTED identities keep name ownership. These rules do not apply
to ordinary registration or status-wait APIs.

A wrong supplied key returns HTTP 409 `KEY_MISMATCH` (in-flight server contract).
Keep all other HTTP statuses and codes as returned, including Live
`IDEMPOTENCY_CONFLICT` and ordinary `IDEMPOTENCY_MISMATCH`. SDK-local error
categories do not imply new server codes. Server behavior that the SDK assumes is
listed in the [server requirements](../known-foundry-server-requirements.md).

##### Registration Replay and Recovery

Ordinary creation permits an omitted `Idempotency-Key`. Retry-safe callers supply
one as transport metadata; retries MUST retain the same key and complete request,
including legacy selectors. SDKs MUST NOT automatically retry an unknown creation
outcome without a key or use an assigned domain as replacement request input.

Preserve the immutable ID, domain, publication configuration, and returned OIDC
issuer before a follow-up read. A timeout, invalid response, failed detail read,
or `MANAGED_GOVERNANCE_UNAVAILABLE` response can leave an identity already created.
Errors retain the request/key and any known creation facts, not a claim that no
agent exists.

Idempotency claims are scoped to the authenticated organization. Within retention,
identical keyed retries address the original identity without resolving a new
root, even after zone deactivation. Publication configuration is
recomputed: stale or unverified managed governance returns 409
`MANAGED_GOVERNANCE_UNAVAILABLE`, so successful replay is not unconditional.
SDKs do not allocate another identity or silently replace saved publication
configuration or trust policy. Changed input can return 422
`IDEMPOTENCY_MISMATCH` or a preceding validation/authorization/infrastructure
error; preserve the actual error and original key.

#### LiveAgentRegistrationInput

Input for the managed Live operation. Keeping fixed discriminators out of this
type prevents generic registration fields from creating ambiguous modes.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | conditional | Optional for low-level Live calls; required by Foundry Create, with exact case-sensitive comparison under 13. |
| `publicKeyJwk` | Ed25519 JWK | yes | One `OKP`/`Ed25519` public signing key using `alg="EdDSA"`. Private JWK members are forbidden. |
| `environment` | `"production"` | no | Omit or set to `production`. |
| `capabilitiesUrl` | string | no | HTTPS capabilities-document URL to publish as `cu`. |

The client sets `tier="live"` and `managed=true`; callers cannot override them.
`domain`, `zoneId`, `governanceDomain`, and `rootDomain` are not fields in this
input. The idempotency key is required transport metadata rather than a JSON field.

The [RegisterLiveAgent contract](#registryclient) defines HTTP 201 creation and
replay responses. Retries preserve the identical request, public key, and
idempotency key; the server's internal operation ID may differ and is never
substituted or derived.

Live registration and status reads require an owning-organization session
credential or organization API key. Managed Live supports an `OKP`/`Ed25519`
public key with `alg="EdDSA"`. SDKs reject other algorithms and private JWK
members before network I/O, including private members nested in a JWKS-shaped
input. Public-key fields must never serialize a source object's private material.

The portable Live adapter is caller-key and managed. Generic registration methods
reject `tier="live"`; callers use `RegisterLiveAgent` with its explicit contract.

#### AgentRegistration

Registry registration or verification result for a local identity.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Immutable registry agent ID, retained across retries and supplied to instance-safe lifecycle mutations. |
| `domain` | string | yes | Registered agent FQDN. |
| `publicationConfig` | PublicationConfig | conditional | Authoritative publication snapshot; required for the Identity Digital adapter, decoded from `publication_config`. Retained with the immutable ID and domain. |
| `publicationAuthority` | `"client"` or `"registry"` | yes | Registry declaration of who controls the accountable-entity key and signs the DNSid record. For the current product API, `managed="dnsid"` maps to `"registry"` and `managed="self"` maps to `"client"`; other implementations MUST report this explicitly rather than infer it solely from DNS hosting, profile tags, or key availability. |
| `registryStatus` | string | yes | Registry-controlled registration workflow state exactly as returned by the management API, such as `PENDING`, `PROVISIONING`, `READY`, `REJECTED`, `CANCELLED`, `ERROR`, `REVOKED`, or `RETIRED`. This is not protocol `AgentStatus.state`. |
| `dnsPublished` | boolean | conditional | Decoded from `dns_published`; required on authenticated agent detail for Identity Digital registry-managed publication. `true` permits ISSUANCE preparation during `PROVISIONING`; `false` means poll within the call deadline. Absent or non-boolean returns `UnsupportedRegistry` with known facts, without preparation or replacement. Public completion still requires resolving and validating the record. |
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
`ACTIVE` state. Polling helpers MUST still treat REVOKED and RETIRED as terminal;
existing registry-status wait helpers otherwise retain their current semantics.
Foundry `Active` separately applies [13's workflow outcomes](13-known-foundry.md#registry-states)
and public evidence checks, including retained name ownership after CANCELLED/REJECTED.

#### PublicationConfig

Registry-established unsigned identity-record configuration, not verification
evidence or a trust-policy update. All fields are strings; the Identity Digital
adapter requires the first six and preserves omission of the final two.

| Field | Wire name | Record/config value |
|-------|-----------|---------------------|
| `publishProfile` | `publish_profile` | Exact publish selector (`v`). |
| `governanceId` | `governance_id` | Selected accountable GI (`gi`). |
| `kuUrl` | `ku_url` | Operational key endpoint (`ku`). |
| `ekUrl` | `ek_url` | Accountable-entity key endpoint (`ek`). |
| `logRef` | `log_ref` | Bound log reference (`lr`). |
| `statusUrl` | `status_url` | Protocol status endpoint (`su`). |
| `capabilitiesUrl` | `capabilities_url` | Optional capabilities URL (`cu`). |
| `maxKeyAge` | `max_key_age` | Optional key age (`ka`); preserve omission rather than invent a value. |

Validate the returned profile and fields and any expected GI. The returned domain
must equal the normalized exact-domain request or lie strictly beneath an explicit
root at a DNS-label boundary. Reject mismatches and unknown publication-authority
values while retaining known creation facts.
Persist this snapshot and any OIDC issuer; do not derive them from registry URLs,
request defaults, or later organization settings. These values do not grant
counterparty trust.

Ordinary creation does not report publication authority. Obtain it from
authenticated agent detail (`managed="dnsid"` or `managed="self"`) before choosing
a publication workflow; a failed read must not cause guessing.

##### Unified Registration Acceptance Cases

Registry-client tests cover the behavior below. Identity replay and
governance persistence also require server integration tests, not SDK coordination.

| Case | Expectation |
|------|-------------|
| Key-only, exact-domain, root, and GI-selected creation | Correct wire selectors and returned domain/GI; no inferred hosting or injected legacy defaults. |
| Invalid inputs | Reject conflicting selectors, missing keys for assigned names, invalid URLs, and private JWK members, including nested JWKS material. |
| Authenticated read or mutation returns a redirect, including to the same origin | Reject; no request or credential reaches the redirect target. |
| Registry or discovery response carries unknown JSON members, including unknown readiness or authority values | Ignore the members; they never satisfy readiness or authority checks or authorize replacement. |
| Invalid response or root/admission failure | Fail closed, preserve known creation facts and server errors, and make no fallback request. |
| Managed Live create and replay | HTTP 201 with ID, domain, registry status, publication configuration, issuer, and matching response Idempotency-Key; no inference of ACTIVE. |
| Keyed ordinary replay, including stale GI or changed input | Preserve the original request/key and known identity; retain governance/mismatch errors without replacement allocation or cross-organization replay. |
| Foundry named Live create and durable operation recovery | [Server acceptance checks](../known-foundry-server-requirements.md#acceptance-checks) establish tenant isolation, atomic convergence and replay-expiry safety. Replacement is separately gated. |
| Timeout or post-creation failure | Retain known facts for recovery; never imply that failure proves no identity exists. |
| Caller-key and registry-custodied ISSUANCE | Distinct entity and operational signatures over the same identity-bound event; publication and accepted ISSUANCE precede ACTIVE. |
| Client-controlled publication and owner-only custody handoff | Verify live signed publication, preserve exact owner bytes, and verify the receipt against the completed bilateral entry. |
| Owner-envelope replay after READY-only claim | Original completed bytes and receipt; no new signature or append. |
| Owner handoff receipt has a different signed payload, entity signature, key binding, or completed-entry hash | Fail closed; no local completion or key activation. |
| Owner handoff accepted-entry evidence is not yet available | Resumable outcome; retain the same owner envelope and idempotency key. |
| Management reports VERIFICATION or VERIFIED | Preserve the readable value; no nonce request and no inference of completion. |
| Management failure, terminal state, or permanent read error during ISSUANCE or public-readiness polling | Stop the call with known facts; preserve exact envelopes and idempotency keys without cancellation or replacement. |
| Registry-managed detail reports `PROVISIONING` and `dnsPublished == true` | Prepare ISSUANCE without waiting for READY or public ACTIVE. |
| Registry-managed detail reports `dnsPublished == false` | Bounded publication polling; no preparation or activation. |
| Identity Digital registry-managed detail omits `dnsPublished` or returns a non-boolean | `UnsupportedRegistry` with known facts; no preparation or replacement. |
| Missing publication or serving readiness | No activation; retain the same identity, key, and operation for recovery. |

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
prepared bytes. Foundry create MUST perform [issuance recovery](13-known-foundry.md#issuance-recovery)
before making the operation failure final. Unknown transport failures remain
indeterminate and MUST NOT cause a replacement event to be created.
