# Managed Registration

Shared SDK design for the Known Foundry `create(name)` call and the identity handle
it returns. Owner: [E5](https://github.com/Identity-Digital/known-foundry/issues/5)
([design issue #49](https://github.com/Identity-Digital/known-foundry/issues/49)).
It builds on [core](01-core-identity-manager.md), [registry](05-transport-and-registry.md),
[log binding](11-c2sp-tlog-binding.md), and [configuration](12-configuration-loading.md).
It does not change protocol wire rules, ordinary registration, or counterparty acceptance.

Assumptions about server behavior are recorded in the
[server requirements](../managed-registration-server-requirements.md).

## Scope and Ownership

Foundry create uses the named caller-key Live/pool path from
[E2](https://github.com/Identity-Digital/known-foundry/issues/2). The adapter sends
`tier="live"`, `managed=true`, `name`, and `public_key` through `RegisterLiveAgent`.
The server selects the domain. The SDK never selects, buys, or guesses a domain, and
never falls back to sandbox registration.

| Owner | Responsibility |
|---|---|
| SDK (E5) | Provider wiring, durable recovery state, registry/proof/issuance adapters, bounded retries, typed errors, public readiness checks, CLI. |
| Operator | Supplies the operational key, or a provider that can provision one. Supplies credentials and configuration. |
| Server (E2) | Authentication, authorization, quotas, name ownership, domain allocation, durable workflow recovery. |
| E6 | Key providers, provisioning, and key convergence across replicas. |
| E7 / E8 | Rotation; revoke, retire, and terminal serving. |

Low-level registry and signing APIs stay available.

## Public Workflow

Names are language-neutral. TypeScript and Python use `create`; Go uses `Create`.
Each binding uses its native context and cancellation conventions.

```
Create(name: string) -> ManagedIdentity

TYPE ManagedIdentity
  domain: string                 // immutable assigned domain
  state?: AgentStatus.state      // last public protocol observation; absent until observed
  registryStatus?: string        // last control-plane observation
  Active() -> ManagedIdentity
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

`Active` completes the required proof and issuance, then waits for the public checks
in [Durable Setup](#durable-setup). Each call makes a new public observation. Registry
`READY`, `VERIFIED`, or workflow completion alone does not satisfy `Active`. `state`
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

Signing is paused:

- until `Active` verifies the identity, or `Create` reopens a `complete` operation
  whose provider key matches the saved current key binding;
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
pauses signing.

Repeated `Create` calls reopen the same identity, including after rotation, without
another issuance. They never replace a terminal identity.

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

```
TYPE ManagedRegistrationConfig
  organizationId?: string    // expected registry account ID
  governanceId?: string      // expected governance domain (gi)
END
```

`LoadedConfig.registration` holds these optional expectations. `Create` reads the
organization ID and GI from authenticated onboarding
([05](05-transport-and-registry.md#account-binding-discovery)) and compares them
byte-exact with configured and saved values before any mutation. Never select named
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

There is no runtime capability check. A released Foundry adapter targets a server
contract that has passed
[server acceptance](../managed-registration-server-requirements.md#acceptance-checks).
Record the supported server revision with each SDK release. Do not enable creation
against the ordinary 24-hour replay-cache contract. If E2/E5 agree a version or
capability negotiation, unsupported servers must fail before mutation. Replacement
and E7 rotation hosting have separate gates.

## Durable Setup

`Create` does steps 1–3. `Active` does steps 4–8. Each step persists progress before
the next mutation. Each call uses one finite deadline.

1. Validate the name, configuration, provider, and algorithm. Read onboarding.
   Lock, load, and validate named state.
2. Obtain the signing key. If the provider has no key and supports
   `EnsureSigningKey()`, call it; the provider owns how it provisions or converges
   keys. Otherwise return `KEY_MISSING`. The Live adapter requires Ed25519. Persist
   bindings, creation intent, provider reference, and the public JWK before creation.
3. If creation is unresolved, derive `registrationKey`, rebuild the identical
   request, and call `RegisterLiveAgent`. Validate `requestId` and any challenge
   against the sent request. Persist ID, domain, and proof facts. If the identity is
   already known, use authenticated reads, not another create.
4. If the server requires a proof challenge, use `SubmitLiveProof` and
   `ReissueLiveProof`. Persist the exact challenge and signature before submission.
   Sign the decoded `challengeMessage` bytes unchanged. Reissue only an expired,
   unused challenge on the same operation and key.
5. Wait for `VERIFIED` or `READY`, or a customer-action or error result. Read the
   publication configuration and entity key from `ekUrl`. Apply
   [Registry States](#registry-states).
6. Recover and verify an accepted ISSUANCE first. Otherwise run the shared issuance
   coordinator: prepare, validate, countersign, persist exact bytes, submit with
   `issuanceKey` as the `Idempotency-Key` header. Apply
   [Issuance Recovery](#issuance-recovery) before reporting a final failure.
7. Wait for publication, then verify public DNS, HTTPS, and log evidence: domain,
   profile, GI, entity key, log, current provider key, protocol `ACTIVE` at signed
   `su`, and fresh lifecycle evidence through `VerifyLogEvidence`. Use signed current
   `ku`. Bound propagation polling, including `RecordNotFound`.
8. Persist completion, enable signing, and return.

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

The Live `request_id` equals `registrationKey`; the server's internal operation ID
can differ. When saved state exists, keep its initial key binding through retries,
credential changes, and rotation. Without saved state, use the provider's current
key. Freeze creation input while the outcome is unknown.

Replicas that use the same key and name converge on one server identity. They also
converge on one ISSUANCE through [Issuance Recovery](#issuance-recovery). A replica
with a different key receives `KEY_MISMATCH` and the known facts; the SDK does not
pick, copy, or adopt keys. A replica without saved state relies on the server
returning the identity on replay (SR-5).

The SDK does not decide name reuse, replacement, or cleanup. It relies on the server
assumptions in the
[server requirements](../managed-registration-server-requirements.md#proposal-name-reuse-and-failed-provisioning).

This check freezes the derivation, including distinct Unicode spellings. Compact
UTF-8 JSON is JCS for these string-only arrays.

```python
import base64, hashlib, json

def validate_name(value):
    if not value or len(value) > 255 or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError("invalid registration name")
    return value

def digest(fields):
    data = json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()

fields = ["dnsid-managed-registration-v1", "11111111-1111-4111-8111-111111111111",
          validate_name("billing-agent"), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"]
key = digest(fields)
assert key == "2sWNUpI4tnAzJ3quPrT78uJNVdo96m4En3cZsggktcA"
assert digest(["dnsid-managed-issuance-v1", key]) == "pxQMSC0k-V9nn9qLqMRDczyUxyNyQE87LbGuK5SEWGw"
assert validate_name("\u00a0cafe\u0301\u3000") == "\u00a0cafe\u0301\u3000"
assert validate_name("\U0001f600" * 255) == "\U0001f600" * 255
names = ["agent", "Agent", "agent ", "café", "cafe\u0301", "\u00a0cafe\u0301\u3000"]
assert len({digest(fields[:2] + [validate_name(n), fields[3]]) for n in names}) == len(names)
assert digest(fields[:2] + ["café", fields[3]]) == "kBdivhIHZhZ_20_Ku_KnIVYE7x0iSw4K1ceQb2s6fxs"
for invalid in ["", "\ud800", "\U0001f600" * 256]:
    try:
        validate_name(invalid)
    except ValueError:
        pass
    else:
        raise AssertionError("accepted invalid name")
```

## Issuance Recovery

A rejection is final for the submitted bytes only. Before recording a final failure,
read lifecycle history and verify any accepted ISSUANCE against the identity, initial
public key, entity key, and log trust. Another replica can have submitted different
valid signature bytes; adopt its verified accepted entry. Never treat its receipt as
acceptance of the local bytes, and never resubmit an accepted event.

Retry an unknown outcome with the same bytes and key. Replace an expired preparation
only when the server state permits it under
[11](11-c2sp-tlog-binding.md#submission-and-idempotency); keep the same issuance key.
Otherwise return a recoverable error. Go and TypeScript have coordinators; Python
needs the same coordinator ([#51](https://github.com/Identity-Digital/known-foundry/issues/51)).

## Registry States

Registry states and protocol `AgentStatus.state` are separate. Existing registry
wait helpers stay unchanged.

| Registry state | Handle behavior |
|---|---|
| `PENDING`, `PROVISIONING`, `VERIFICATION` | Complete required proof or wait. |
| `VERIFIED`, `READY` | Continue issuance and public checks. Not proof of `ACTIVE`. |
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
[name-reuse proposal](../managed-registration-server-requirements.md#proposal-name-reuse-and-failed-provisioning).

## Storage and Recovery

`ManagedRegistrationStore` creates, loads, and updates named operations.
`FileRegistrationStore(directory)` is the default and keys state by
`(registry URL, organization ID, exact name)`, using digests for paths. The SDK and
CLI share the default location; callers can inject a store. Historical operations
stay addressable by ID after a name is reused.

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
| `schemaVersion`, `phase` | `1`; `creation-pending`, `identity-known`, `proof-pending`, `issuance-accepted`, or `complete`. |
| `registryUrl`, `organizationId`, `name` | Operation key. |
| `governanceId`, `logTrust` | Resolved expected bindings, using 12's names. |
| `keySource`, `currentKeySource` | Non-secret provider reference; current reference after rotation if different. |
| `initialPublicKey`, `currentPublicKey` | Initial JWK; current JWK after verified rotation if different. |
| `creationInput` | Frozen Live request fields (05 wire names). |
| `identityId`, `domain`, `requestId` | Creation facts. |
| `proof` | Exact challenge, signature request, and latest outcome. |
| `publicationConfig`, `oidcIssuerUrl`, `entityPublicKey` | Publication snapshot, issuer, and entity public JWK. |
| `issuance` | Prepared and completed bytes, `entryHash`, submission state (per 11), log reference and index, acceptance facts. |

Each phase requires the members needed to resume it. Drop proof and issuance bytes
only after their outcome is durably known. Documents never contain private keys or
credentials; the destination reopens the same provider key or a verified successor.

## Retry, Deadlines, and Errors

Each call has one finite deadline covering locks, provider calls, network, storage,
and retries. Retry transient failures and unknown outcomes only with the same input
and bytes. Integrity, policy, and binding failures stop.

Typed errors carry the phase, HTTP status and wire code, known ID and domain,
registry state, and whether the operation can resume. Callers never parse message
text. Errors keep progress; calling `Create` or `Active` again resumes.

| Error | Meaning |
|---|---|
| `KEY_MISSING` | The provider has no key and cannot provision one. |
| `KEY_MISMATCH` | The supplied key differs from the existing identity (server HTTP 409, PR #3304). Remedy text points to the one-identity-per-cloud guidance (D9). |
| `KEY_REVOKED` | The organization API credential is revoked (E4). Not inferred from a generic 403. |
| `SigningPaused` | Signing is paused; see [Signing](#signing). |
| Busy, deadline, unsupported contract or algorithm, workflow outcome, terminal identity | Separate categories with structured causes. |

Keep `422 IDEMPOTENCY_MISMATCH` and Live `409 IDEMPOTENCY_CONFLICT` as their own
codes. Keep all other server codes unchanged.

## CLI and Quick Starts

[#52](https://github.com/Identity-Digital/known-foundry/issues/52) adds
`dnsid create <name>` and `dnsid retire <name>`. Create uses the same configuration
and store, calls `Create` then `Active`, and succeeds only after public readiness.
JSON output goes to stdout; progress and warnings go to stderr. On timeout or error,
it reports the known ID, domain, and how to resume. Rerunning resumes.

Retire finds the identity in the local store, or by name through the registry, and
calls the existing retire endpoint with the E8 type-the-name confirmation. It reports
"pending" until it observes public convergence. `dnsid rotate` belongs to E7.

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
[server acceptance](../managed-registration-server-requirements.md#acceptance-checks).

| Case | Required result |
|---|---|
| Name and hash vectors | Same bytes across bindings; no normalization. |
| Configuration from file, environment, code; invalid provider or algorithm | Same bindings; fail before mutation; no fallback. |
| Wrong organization or onboarding not ready | Fail before create. |
| Empty provider, with and without `EnsureSigningKey` | Provisioned key, or `KEY_MISSING`. |
| Same-key replicas, with and without saved state | One identity, one ISSUANCE. |
| Different-key replicas | One wins; others get `KEY_MISMATCH` with known facts. |
| Caller exits after `Create` | Signing paused; next call resumes. |
| Proof expiry, lost responses, replay-cache expiry | Same operation; no new domain or key. |
| `ERROR`, `REJECTED`, `CANCELLED`, terminal, unknown states | Correct typed outcome; no name release or replacement. |
| Competing valid countersignatures; invalid then valid countersignature | One accepted ISSUANCE; key not poisoned. |
| Interruption at each phase | Same-bytes recovery; no recreation. |
| `READY` without public `ACTIVE`; wrong GI, key, or log | Bounded wait or failure; signing paused. |
| Restart of a `complete` operation; rotated or superseded key | Signing enabled only for the verified current key; no reissuance. |
| Profile helper through `IdentityManager()` before `Active` | `SigningPaused`. |
| CLI create, rerun, retire | Same results as the SDK; no secrets in output. |

### Implementation Acceptance Checklist

- [ ] Shared scenario inputs and expected observations for the table above.
- [ ] Go, Python, and TypeScript pass the same scenarios; API spelling may differ,
  behavior may not.
- [ ] CLI runs the same scenarios through the same facade.
- [ ] Scenarios run in the daily workflow with SDK and server revisions recorded.
  Missing adapters or prerequisites never report a pass.
