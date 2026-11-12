# Known Foundry Create

> **Product profile.** Known Foundry is Identity Digital's hosted agent-identity
> product. `create(name)` works only against the Identity Digital registry with
> Foundry named create enabled. It is not part of the DNSid protocol, and other
> registries do not implement it. Use the low-level
> [registry APIs](05-transport-and-registry.md) for any other registry.

Shared SDK design for the Known Foundry `create(name)` call and the identity handle
it returns. Owner: [E5](https://github.com/Identity-Digital/known-foundry/issues/5)
([design issue #49](https://github.com/Identity-Digital/known-foundry/issues/49)).
It builds on [core](01-core-identity-manager.md), [registry](05-transport-and-registry.md),
[log binding](11-c2sp-tlog-binding.md), and [configuration](12-configuration-loading.md).
It is separate from protocol wire rules, ordinary registration, and counterparty acceptance.

Assumptions about server behavior are recorded in the
[server requirements](../known-foundry-server-requirements.md).

## Scope and Ownership

Foundry create uses the named caller-key Live path from
[E2](https://github.com/Identity-Digital/known-foundry/issues/2). The adapter sends
`tier="live"`, `managed=true`, `name`, and `public_key` through `RegisterLiveAgent`.
The server selects the domain. The SDK never selects, buys, or guesses a domain, and
never falls back to sandbox registration.

| Owner | Responsibility |
|---|---|
| SDK (E5) | Provider wiring, durable recovery state, registry/issuance adapters, bounded retries, typed errors, public readiness checks, CLI. |
| Operator | Supplies the operational key, created before `Create` runs. Supplies credentials and configuration. |
| Server (E2) | Authentication, authorization, quotas, name ownership, domain allocation, durable workflow recovery. |
| E6 | Key providers, provisioning, and key convergence across replicas. |
| E7 / E8 | Rotation; revoke, retire, and terminal serving. |

Low-level registry and signing APIs stay available.

## Module Placement

Each binding ships Foundry create in its own module. Core, the registry client,
and configuration loading never import it. `FoundryConfig` is a plain data type
owned by the configuration loader; the Foundry module imports and validates it.
Each binding's module path and call are recorded in its
[implementation tracker](implementations/).

The module holds the facade, handle, store, and Foundry-specific errors. It must
not re-export generic APIs under Foundry names, and the core package must not
re-export Foundry create.

## Public Workflow

Names are language-neutral; each binding uses its native spelling, context, and
cancellation conventions.

```
Create(name: string) -> FoundryIdentity

TYPE FoundryIdentity
  domain: string                 // immutable assigned domain
  state?: AgentStatus.state      // last public protocol observation; absent until observed
  registryStatus?: string        // last control-plane observation
  Active() -> FoundryIdentity
  Sign(data: bytes) -> bytes
  IdentityManager() -> IdentityManager
END
```

The configured facade loads configuration under [12](12-configuration-loading.md),
so an application needs one import and one `create(name)` call. Explicit dependency
injection uses the same implementation.

`Create` validates configuration, resolves the organization, obtains the signing key,
creates or reopens one server identity, and durably records its ID and domain. It
does not wait for protocol `ACTIVE`. If the server accepted the operation but no
domain is known yet, `Create` returns a resumable error with the known facts.

`Active` completes bilateral ISSUANCE, then waits for the public checks in
[Durable Setup](#durable-setup). Its operational signature proves possession of
the registered key. Each call makes a new public observation. Registry `READY`
or workflow completion alone does not satisfy `Active`. `state`
holds only a real public observation, never a value mapped from `registryStatus`.

The SDK starts no background task. If the process stops after `Create`, the server
can wait for the customer countersignature. Callers normally call `Active` directly
after `Create`. Cancellation keeps progress and never cancels the server identity.

### Signing

The handle owns the core
[application-signing controller](01-core-identity-manager.md#managed-rotation-recovery-contract).
`Sign` and the manager returned by `IdentityManager()` use the same controller, so
profile helpers (JWT, HTTP message signatures, Web Bot Auth) follow the same rules.
`Sign` signs raw bytes through the provider and adds no new format.

`IdentityManager()` builds the manager with the normal core constructor from the
saved domain, GI, and publication configuration. Until the publication
configuration is saved (step 3 of [Durable Setup](#durable-setup)),
`IdentityManager()` returns `SigningPaused` and builds nothing. Core keeps its
construction rules; the handle never passes placeholder values. Later calls
return the same manager.

Signing is paused:

- until `Active` verifies the identity, or `Create` reopens a `complete` operation
  whose provider key matches the saved current key binding and whose saved state
  records no terminal state or pause;
- during rotation, as defined in core;
- after an observation finds a terminal state or a key-binding mismatch.

While paused, signing returns a typed `SigningPaused` error. The key check compares
against the public key recorded when signing was enabled; it does not add a provider
or network call per signature. The pause protects the application from producing
signatures that verifiers reject. It is not a security boundary: code with access to
the provider can sign directly.

Reopening a `complete` operation after a restart enables signing without a network
check, so a restart does not depend on DNS or log availability. Call `Active` to
refresh the public observation. A refresh that finds a terminal state or mismatch
saves it (`registryStatus`, `signingPaused`) and pauses signing, so a restart stays
paused. Only a later `Active` that verifies the identity again clears a mismatch
pause; a terminal state is never cleared.

With saved state, repeated `Create` calls reopen the same identity, including after
rotation, without another issuance. A replica without saved state after rotation
derives a new `registrationKey` from its current key, and the server returns the
existing identity (pending E2 confirmation in [08](08-open-questions.md#known-foundry-create)).
It recovers the earlier ISSUANCE under [Issuance Recovery](#issuance-recovery). `Create`
never replaces a terminal identity.

### Name Normalization

Names are exact, case-sensitive Unicode strings: nonempty, valid Unicode scalar
values, at most 255 scalar values. This matches
[server PR #3150](https://github.com/Identity-Digital/dnsid/pull/3150). Do not trim,
normalize, or re-case names before hashing, storage, transmission, or comparison.
`agent`, `Agent`, and `agent ` are distinct; NFC and decomposed spellings are distinct.

Names are account handles, not domains, and are not published. Use digests or safe
encodings for storage keys and escape names in diagnostics. Any further name policy
needs an agreed server rule and shared vectors.

## Configuration and Trust

`LoadedConfig.foundry` holds the optional `organizationId` and `governanceId`
expectations ([`FoundryConfig` in 12](12-configuration-loading.md#loaded-configuration)). `Create` reads the
organization ID and GI from authenticated onboarding
([05](05-transport-and-registry.md#account-binding-discovery)) and compares them
with configured and saved values before any mutation: the organization ID
byte-exact, and the GI as a normalized domain under 05. Never select named
state by name alone across organizations. A credential for a different organization
fails before creation.

The entity key comes from `publicationConfig.ekUrl`. The Foundry facade does not
accept ordinary `domain`, `rootDomain`, or `governanceDomain` selectors.

Log trust requires explicit `logTrust` or an injected `LogRegistry`. Checkpoint stores
follow [12](12-configuration-loading.md#construction). All SDK networking uses the
loaded transport settings. Public checks use a separate client without credentials;
registry credentials never reach DNS, public JWKS, status, or log hosts, or redirects.

The registry is trusted to allocate the domain and to sign publication with the
entity key. Before completion, `Active` verifies that signed `ku` serves the
provider's RFC 7638 thumbprint, or a successor authorized by verified lifecycle
history. Public readiness uses a fresh, isolated verification and does not change
application `trustedEntities` or `VerifyDomain` policy.

### Server Compatibility and Enablement

If the onboarding read in step 1 returns 404 or 405, or a response without `org_id`
or `ek.status`, `Create` returns `UnsupportedRegistry` before any mutation. A response
without `governance_domain` or `gi` is an organization that has not started governance
onboarding: it is not ready ([05](05-transport-and-registry.md#account-binding-discovery)),
and `Create` returns the resumable not-ready error before any mutation. This rejects registries
that are not Identity Digital. It does not detect an Identity Digital server
without Foundry named create.

There is no other runtime capability check. A released Foundry adapter targets a server
contract that has passed
[server acceptance](../known-foundry-server-requirements.md#acceptance-checks).
Record the supported server revision with each SDK release. Do not enable creation
against the ordinary 24-hour replay-cache contract. If E2/E5 agree a version or
capability negotiation, unsupported servers must fail before mutation. Replacement
and E7 rotation hosting have separate gates.

## Durable Setup

`Create` does steps 1–3. `Active` does steps 4–7. Each step persists progress before
the next mutation. Each call uses one finite deadline.

1. Validate the name, configuration, provider, and algorithm. Read onboarding.
   Lock, load, and validate named state.
2. Obtain the signing key. If the provider's `ListKeyIds()` is empty, return
   `KEY_MISSING`. `Create` never generates, provisions, or selects a key; key
   provisioning and replica convergence stay with E6
   ([open decision](08-open-questions.md#known-foundry-create)). The Live adapter requires Ed25519. Persist
   bindings, creation intent, provider reference, and the provider's public JWK (the
   creation key) before creation.
3. Creation is unresolved until both the ID and the domain are saved. If it is
   unresolved, derive `registrationKey`, rebuild the identical
   request, and call `RegisterLiveAgent` with `registrationKey` as the
   `Idempotency-Key` header. Accept HTTP 201 `AgentRegistration` and validate the
   response `Idempotency-Key` header. Persist ID, domain, publication configuration,
   OIDC issuer, and registry status before any detail read. A response without
   complete creation facts is not success; retain known facts and the original
   request/key for recovery. Once ID and domain are saved, use authenticated reads,
   not another create. Validate that publication authority is registry-managed.
4. Read authenticated progress and wait for signed identity publication while
   registration is `PROVISIONING`, or return a customer-action or error result.
   Read the entity key from saved `publicationConfig.ekUrl`. This prerequisite
   uses publication progress, not `VerifyDomain` or
   `AwaitRegistryManagedPublication`, which require `ACTIVE`. Apply
   [Registry States](#registry-states).
5. If saved state records an accepted ISSUANCE, verify it. If the registry reports
   `READY` and no ISSUANCE is saved, recover it under [Issuance Recovery](#issuance-recovery);
   never prepare another. Otherwise run the shared
   issuance coordinator: prepare, validate, countersign, verify the completed entry
   including its own signature, persist exact bytes, submit with
   `issuanceKey` as the `Idempotency-Key` header. Apply
   [Issuance Recovery](#issuance-recovery) before reporting a final failure.
6. Wait for registry convergence, then verify public DNS, HTTPS, and log evidence: domain,
   profile, GI, entity key, log, current provider key, protocol `ACTIVE` at signed
   `su`, and fresh lifecycle evidence through `VerifyLogEvidence`. Use signed current
   `ku`. Bound propagation polling, including `RecordNotFound`.
7. Persist completion, enable signing, and return.

Live issuance waits while the server operation remains eligible, without a
server-side issuance deadline. Each `Active` call is bounded; a deadline or
cancellation retains the same identity, key, and issuance progress.

## Organization and Creation Replay

Derive keys with RFC 8785 JCS, UTF-8, SHA-256, and unpadded base64url. `initialKeyId`
is the RFC 7638 thumbprint of the initial public key.

```
registrationKey = base64url-no-pad(SHA-256(JCS([
  "dnsid-managed-registration-v1", organizationId, name, initialKeyId
])))
issuanceKey = base64url-no-pad(SHA-256(JCS([
  "dnsid-managed-issuance-v1", registrationKey
])))
```

The Live request and response `Idempotency-Key` headers equal `registrationKey`;
the server's internal operation ID can differ. When saved state exists, keep its
initial key binding through retries, credential changes, and rotation. Without
saved state, use the provider's current key. Freeze creation input while the
outcome is unknown.

Replicas that use the same key and name converge on one server identity. They also
converge on one ISSUANCE through [Issuance Recovery](#issuance-recovery). A replica
with a different key receives `KEY_MISMATCH` and the known facts; the SDK does not
pick, copy, or adopt keys. A replica without saved state relies on the server
returning the identity on replay (SR-5).

The SDK does not decide name reuse, replacement, or cleanup. It relies on the server
assumptions in the
[server requirements](../known-foundry-server-requirements.md#proposal-name-reuse-and-failed-provisioning).

These vectors freeze the derivation. Serialize the string arrays with RFC 8785
string escaping; a general JSON encoder can differ (for example by escaping `<`,
`>`, `&`, or U+2028). All rows use organization
`11111111-1111-4111-8111-111111111111` and `initialKeyId`
`kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`. Names are shown as JSON string literals.

| Name | `registrationKey` |
|---|---|
| `"billing-agent"` | `2sWNUpI4tnAzJ3quPrT78uJNVdo96m4En3cZsggktcA` (`issuanceKey` `pxQMSC0k-V9nn9qLqMRDczyUxyNyQE87LbGuK5SEWGw`) |
| `"agent"` | `ksFWEjxU0Yf_F7-_UEwFWQ3J97VRmQPVLjVM5l-3YlY` |
| `"Agent"` | `43mRUDBHeMLHZ6AZKy6RTQXox_LZxBDLa3IXLQ0qCGI` |
| `"agent "` | `eVX-4H-42OOxnU2EbgtKoEzYad0bIaaRoCkf5T2BIEM` |
| `"caf\u00e9"` | `kBdivhIHZhZ_20_Ku_KnIVYE7x0iSw4K1ceQb2s6fxs` |
| `"cafe\u0301"` | `WxS5QzyfB3D0utVhJDzJQTY6eXDMagDV3tqOImr_u6A` |
| `"\u00a0cafe\u0301\u3000"` | `x6ARjxrBFYbZ1jCSznnOWBUX9DpFr4edVmYy1zLnyTc` |
| U+1F600 repeated 255 times | `AEttzAMd8C-GpyQqR_y5G-IfIawJpRWIMi4ZpfbkqWU` |
| `"a\"b"` | `2bWVuTgcCN056vagU5cF40TRXcroeKQCLhd5hTVjhcM` |
| `"a\\b"` | `g8sOgOWQxkQncp1g_H2nI81dTe-60Y8p6ryb87s3Vrk` |
| `"a\u0001b"` | `oNMzk-Vz7VqZ75bxvj4srioM6Dtxd0lNFT3W_-uOF0A` |
| `"a\nb"` | `yM6te8_oTYfg8b2Co21WukeVw4SfYQgCG9brN_W9Bio` |
| `"<a>&"` | `D-ZrRgfx1r9BUVg-wF9Pbey_cfLsZjWeOUCRCsYhTnk` |
| `"a\u2028b"` | `-0mnonROfh4y6N--aNbASSi_x7pWEcBu8-Ldwmop4mU` |
| `"a\u007fb"` | `V9Xm6mXYXgQCT7DLYtBfT-etOMFRmX9mgKK60ocWtTA` |
| `"a/b"` | `vQvjQxYsTU1TyU3oai2SQY07iNjuCrSBPH5fCjHqhiE` |

Rejected names: empty, any lone surrogate (for example `"\ud800"`), and 256 scalar
values (for example U+1F600 repeated 256 times).

## Issuance Recovery

The SDK reads lifecycle history only when it expects an ISSUANCE to exist: after a
rejection, or when the registry reports `READY` and no ISSUANCE is saved. It does
not scan the log before preparation, and it never treats empty history as proof
that no ISSUANCE exists.

A rejection is final for the submitted bytes only. When the server rejects
preparation or submission, read lifecycle history and verify any accepted ISSUANCE
against the identity, the initial public key, entity key, and log trust before
recording a final failure. The ISSUANCE's operational key must equal the saved
creation key, or the creation key must follow from it through verified KEY_ROTATION
events and match signed `ku`. The second case is a replica that started without saved
state after rotation: save the ISSUANCE key as `initialPublicKey` and the creation key
as `currentPublicKey`; `creationInput` keeps the creation key. If the history is empty or has no ISSUANCE yet, return
a resumable error; the log can lag the server. Unavailable or invalid evidence
stays an error. Another replica can have submitted different
valid signature bytes; adopt its verified accepted entry. Never treat its receipt as
acceptance of the local bytes, and never resubmit an accepted event.

Retry an unknown outcome with the same bytes and key. Replace an expired preparation
only when the server state permits it under
[11](11-c2sp-tlog-binding.md#submission-and-idempotency); keep the same issuance key.
Otherwise return a recoverable error.

Whether `TLOG_INVALID_ENTRY` for locally verified bytes ends the operation, and
whether the issuance key may prepare again after it, are server decisions
([08](08-open-questions.md#known-foundry-create)). Until decided, it stays a
resumable error that keeps the registry code.

## Registry States

Registry states and protocol `AgentStatus.state` are separate. During issuance
and public-readiness waits, each polling cycle refreshes authenticated management
state and applies the outcomes below. Permanent management-read errors stop the
call; transient read failures follow the bounded retry policy.

| Registry state | Handle behavior |
|---|---|
| `PENDING` | Wait for provisioning progress. |
| `PROVISIONING` | Wait for publication, then complete bilateral ISSUANCE. |
| `VERIFICATION`, `VERIFIED` | Preserve as readable management values and wait for current registration progress. Never request a nonce or treat either value as completion. |
| `READY` | Recover or verify accepted ISSUANCE and run public checks. Not proof of `ACTIVE`. |
| `ERROR` | Return a workflow error with known facts. Resume only through an agreed server recovery path. |
| `REJECTED`, `CANCELLED` | Return a typed workflow outcome. The name stays owned. |
| `REVOKED`, `RETIRED` | Terminal. Pause signing, stop waiting, keep history. |
| Unknown | Keep it for diagnostics. Never treat it as ready or as a released name. |

The SDK never releases a name, restarts `ERROR`, or replaces an identity by calling
create.

## Completed-Operation Resume

Verify historical issuance from retained public bindings and log inclusion; the
initial private key need not exist after rotation. Before enabling signing, check the
current provider key against the saved current binding (restart) or against fresh
signed `ku` and lifecycle continuity (`Active`). Rotation changes the key but keeps
ID, domain, and history. Pending rotations resume through the core rotation
coordinator. A superseded local key pauses signing; the SDK never generates a key to
fix a mismatch.

Same-name replacement after revoke or retire is disabled until E2 agrees how
replacement intent differs from a delayed create. Until then, a terminal identity
returns a typed terminal error. See the
[name-reuse proposal](../known-foundry-server-requirements.md#proposal-name-reuse-and-failed-provisioning).

## Storage and Recovery

`FoundryStore` creates, loads, and updates named operations.
`FileFoundryStore(directory)` is the default, at `~/.dnsid/foundry/` when no
directory is given. It keys state by
`(registry URL, organization ID, exact name)`, using digests for paths. The SDK and
CLI share the default location; callers can inject a store. How stored operations
stay reachable after a name is reused is defined with replacement (SR-8).

An exclusive in-process and cross-process lock covers each `Create` or `Active` call.
A competing caller waits for the lock until its deadline, then gets a typed busy
error. Handles release the lock between calls and reload state when they take it
again. A write must not commit after the lock is released.

Files are owner-only and updated atomically and durably. Validate missing, corrupt,
or conflicting state before mutation. Never generate a key to repair state. Document
backup needs and the limits of container-local storage.

### Portable Recovery Document

Stores import and export UTF-8 RFC 8785 JSON. `schemaVersion` is `1`. Reject
duplicate members, invalid Unicode, and unknown versions or phases. Preserve unknown
members on rewrite. Omit optional members until known. Byte strings are unpadded
base64url; timestamps are RFC 3339 UTC.

| Member | Value |
|---|---|
| `schemaVersion`, `phase` | `1`; `creation-pending`, `identity-known`, `issuance-accepted`, or `complete`. |
| `registryUrl`, `organizationId`, `name` | Operation key. |
| `governanceId`, `logTrust` | Resolved expected bindings, using 12's names. |
| `keySource`, `currentKeySource` | Non-secret provider reference; current reference after rotation if different. |
| `initialPublicKey`, `currentPublicKey` | Initial JWK; current JWK after verified rotation if different. |
| `creationInput` | Frozen Live request fields (05 wire names). |
| `identityId`, `domain` | Creation facts. |
| `registrationKey`, `issuanceKey` | Deterministic operation keys, retained unchanged through retries. |
| `registryStatus`, `signingPaused` | Last observed registry status; `true` after an observed terminal state or key-binding mismatch. |
| `publicationConfig`, `oidcIssuerUrl`, `entityPublicKey` | Publication snapshot, issuer, and entity public JWK. |
| `issuance` | Prepared and completed bytes, `entryHash`, submission state (per 11), log reference and index, acceptance facts. |

`identity-known` covers a saved ID and domain, publication waiting, and ISSUANCE
preparation and submission; the `issuance` member records that progress. Each
phase requires the members needed to resume it. Drop issuance bytes only after
their outcome is durably known. Documents never contain private keys or
credentials; the destination reopens the same provider key or a verified successor.

## Retry, Deadlines, and Errors

Each call has one finite deadline covering locks, provider calls, network, storage,
and retries. Pass the deadline to provider calls that accept cancellation. For a
provider call that does not, check the deadline before and after the call; the
provider's own timeout bounds the call. Do not change the `KeyProvider` interface
for this. Retry transient failures and unknown outcomes only with the same input
and bytes. Integrity, policy, and binding failures stop.

Typed errors carry the phase, HTTP status and wire code, known ID and domain,
registry state, and whether the operation can resume. Callers never parse message
text. Errors keep progress; calling `Create` or `Active` again resumes.

| Error | Meaning |
|---|---|
| `KEY_MISSING` | The provider has no active key (`ListKeyIds()` is empty). |
| `KEY_MISMATCH` | The supplied key differs from the existing identity (server HTTP 409). Remedy text points to the one-identity-per-cloud guidance ([D9, #63](https://github.com/Identity-Digital/known-foundry/issues/63)). |
| `KEY_REVOKED` | The organization API credential is revoked (E4). Not inferred from a generic 403. |
| `SigningPaused` | Signing is paused; see [Signing](#signing). |
| `UnsupportedRegistry` | The registry does not serve the Identity Digital onboarding contract; see [Server Compatibility](#server-compatibility-and-enablement). |
| Busy, deadline, unsupported contract or algorithm, workflow outcome, terminal identity | Separate categories with structured causes. |

Keep `422 IDEMPOTENCY_MISMATCH` and Live `409 IDEMPOTENCY_CONFLICT` as their own
codes. Keep all other server codes unchanged.

## CLI and Quick Starts

[#52](https://github.com/Identity-Digital/known-foundry/issues/52) adds
`dnsid create <name>` and `dnsid retire <name>`. Create uses the same configuration
and store, calls `Create` then `Active`, and succeeds only after public readiness.
JSON output goes to stdout; progress and warnings go to stderr. On timeout or error,
it reports the known ID, domain, and how to resume. Rerunning resumes.

Retire finds the identity in the local store, asks the operator to type the name
(the E8 confirmation; a CLI prompt, not a request member), and then calls the
existing retire endpoint. It reports
"pending" until it observes public convergence. Without local state it returns a
typed error; lookup by name needs a server endpoint that E2 has not defined.
`dnsid rotate` belongs to E7.

The `init` refactor ([#2600](https://github.com/Identity-Digital/dnsid/issues/2600),
[#2651](https://github.com/Identity-Digital/dnsid/issues/2651)) can share key and
publication helpers. Quick starts ([#53](https://github.com/Identity-Digital/known-foundry/issues/53))
use `create` then `active`, show the local-key warning or a KMS configuration, and
never describe registry `READY` as `ACTIVE`.

## Security Considerations

The registry credential is supplied by the caller and is never written to
configuration or recovery files. Credential scopes, expiry, and revocation belong
to E4. Organization API keys can affect other identities. Responses must pass
binding, signature, TLS, and log-trust checks before countersigning or completion.
The registry's signing authority is a trust assumption; a compromised registry can
misrepresent identities. See the [threat model](../security/THREAT_MODEL.md) and
[inventory](../security/INVENTORY.md).

## Validation Scenarios

Bindings share these hosted scenarios against the local registry or emulator, run in
the cross-SDK daily workflow. Server persistence proof stays in
[server acceptance](../known-foundry-server-requirements.md#acceptance-checks).

| Case | Required result |
|---|---|
| Name and hash vectors | Same bytes across bindings; no normalization. |
| Configuration from file, environment, code; invalid provider or algorithm | Same bindings; fail before mutation; no fallback. |
| Configuration contains `dnsid.identity` (for example `DNSID_GOVERNANCE_ID` in the environment) | `ArgumentError` before any registry call. |
| Wrong organization or onboarding not ready, including absent `gi` or `governance_domain` | Fail before create; not ready is resumable, not `UnsupportedRegistry`. |
| Registry without the onboarding endpoint | `UnsupportedRegistry`; no mutation. |
| Empty provider | `KEY_MISSING`; no key generated or selected; no registry mutation. |
| Same-key replicas, with and without saved state | One identity, one ISSUANCE. |
| Different-key replicas | One wins; others get `KEY_MISMATCH` with known facts. |
| Caller exits after `Create` | Signing paused; next call resumes. |
| Lost create responses, issuance timeouts, replay-cache expiry | Same operation; no new domain or key. |
| Published `PROVISIONING` identity awaiting caller signature | Prepare, validate, countersign, persist, and submit ISSUANCE before waiting for READY. |
| `ERROR`, `REJECTED`, `CANCELLED`, terminal, unknown states | Correct typed outcome; no name release or replacement. |
| Competing valid countersignatures; invalid then valid local countersignature | Losing bytes rejected; winner recovered; an invalid local signature is never persisted or submitted, and the next attempt countersigns the same prepared bytes. |
| Interruption at each phase | Same-bytes recovery; no recreation. |
| `READY` without public `ACTIVE`; wrong GI, key, or log | Bounded wait or failure; signing paused. |
| Restart of a `complete` operation; rotated or superseded key | Signing enabled only for the verified current key; no reissuance. |
| Replica without saved state after rotation, using the current key | Existing identity; earlier ISSUANCE recovered, none prepared; signing only after the current key matches signed `ku` through verified rotation history. |
| Profile helper through `IdentityManager()` before `Active` | `SigningPaused`, from `IdentityManager()` before publication configuration is saved, otherwise from signing. |
| CLI create, rerun, retire | Same results as the SDK; no secrets in output. |

### Implementation Acceptance Checklist

- [ ] Shared scenario inputs and expected observations for the table above.
- [ ] Every binding passes the same scenarios; API spelling may differ, behavior
  may not. Per-binding status is in the implementation trackers.
- [ ] CLI runs the same scenarios through the same facade.
- [ ] Scenarios run in the daily workflow with SDK and server revisions recorded.
  Missing adapters or prerequisites never report a pass.
