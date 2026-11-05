# Managed Registration

Shared SDK design for Known Foundry's `create(name)` surface and identity handle,
owned by [E5](https://github.com/Identity-Digital/known-foundry/issues/5) and
[its design issue](https://github.com/Identity-Digital/known-foundry/issues/49).
This composes [core](01-core-identity-manager.md),
[registry](05-transport-and-registry.md), [log binding](11-c2sp-tlog-binding.md), and
[configuration](12-configuration-loading.md); it does not change protocol wire
rules, ordinary registration defaults, or counterparty acceptance.

The SDK owns provider selection, recovery storage, registry/proof/issuance adapters,
and bounded retries. Consumers supply configuration and credentials, not recovery
callbacks. Bindings provide idiomatic equivalent APIs and a default file-backed
store. Low-level registry and signing APIs remain available.

## Scope and Ownership

Foundry creation uses the named caller-key Live/pool path being developed under
[E2](https://github.com/Identity-Digital/known-foundry/issues/2), not ordinary
sandbox registration. The current adapter sends `tier="live"`, `managed=true`,
`name`, and `public_key` through `RegisterLiveAgent`. The server chooses a prepared
pool domain or the agreed Live registration fallback. The SDK never selects an
inventory domain, purchases one, or falls back to sandbox.

Authentication, authorization, verified-domain gates, quotas, name ownership,
allocation, and durable server workflow recovery remain product responsibilities.
The client retains operational-key custody. Server-side key download/custody is
not the implementation of this SDK surface. Provider selection and atomic first-key
discovery belong to [E6](https://github.com/Identity-Digital/known-foundry/issues/6).
Rotation belongs to [E7](https://github.com/Identity-Digital/known-foundry/issues/7),
and terminal lifecycle serving to [E8](https://github.com/Identity-Digital/known-foundry/issues/8).

## Public Workflow

Names below are language-neutral; bindings use TypeScript `create`, Python
`create`, and Go `Create`, with native context/cancellation conventions. A configured
facade supplies the dependencies; its environment/file convenience entry point
loads them under 12, so the application needs one import and `create(name)`.
Explicit configuration/dependency injection remains available through the same
implementation, not a second workflow.

```
Create(name: string) -> ManagedIdentity

TYPE ManagedIdentity
  domain: string                 // immutable assigned domain
  state?: AgentStatus.state      // last public protocol observation, absent until known
  registryStatus?: string        // separate control-plane observation
  Active() -> ManagedIdentity
  Sign(data: bytes) -> bytes
END
```

`Create` validates configuration, resolves the organization, creates or recovers
one provider key and one server identity, and durably records its immutable ID and
domain before returning. It does not wait for protocol `ACTIVE`. A successful
HTTP 202 may therefore return a handle that still needs proof, issuance, or
publication. `domain` comes from a validated create/proof transcript or an
authenticated read, never from a name, key, registry hostname, or guessed suffix.
If an accepted operation has no recoverable domain yet, return a resumable error
with every known fact rather than fabricate a handle/domain or create again.

`Active` drives or resumes the required client proof and issuance work, then waits
for the public completion checks in [Durable Setup](#durable-setup). It returns the
same identity handle with fresh protocol/log evidence available through the
binding's existing evidence types. Every invocation makes a new public observation;
a stored `complete` marker does not prove current readiness. Registry `READY`,
`VERIFIED`, or workflow completion alone never satisfies this call. `state` contains
only a real public protocol observation, not a mapping from registry state; it is
a snapshot, not a background subscription.

No unowned background task is required. If the caller stops after `Create`, the
server may wait for a customer signature; the SDK does not promise progress while
its process is absent. Server recovery must continue already accepted work, but
cannot manufacture that signature. Callers should normally invoke `Active`
immediately. Cancellation preserves progress and never cancels the server identity.

`Sign` delegates to the selected provider's existing byte-signing primitive; it
introduces no new envelope, JWT, HTTP-signature, or key-ID format. Applications use
the existing profile helpers for those formats. Signing through the handle MUST
remain disabled until `Active` has verified the initial publication/key binding,
and while rotation is paused or a terminal/binding failure is known. Each call
checks the selected provider still matches that binding; configuration changes
cannot replace it. This is not a new per-sign network check or a guarantee that
remote status has not changed since the last observation. Existing profile and
verification freshness rules still apply.

Repeated `Create` calls reopen the saved immutable identity, including after
rotation, without another issuance. They MUST NOT implicitly replace a terminal
identity. Conflicting deployment or key bindings fail rather than modify it.

### Name Normalization

For this Foundry adapter, names are exact, case-sensitive Unicode strings. Require
valid Unicode scalar values, a nonempty string, and at most 255 scalar values,
matching the named Live direction in
[server PR #3150](https://github.com/Identity-Digital/dnsid/pull/3150).
Do not trim whitespace, normalize Unicode, re-case, or apply domain normalization
before hashing, storage selection, transmission, or comparison. Thus `agent`,
`Agent`, and `agent ` are distinct; NFC and decomposed spellings are also distinct.
An explicit name in a lower-level input must equal the workflow argument exactly.
Names are account handles, not domains, and are not published in DNS or log entries.

Use safe encoded/digested storage keys and escape names in diagnostics; exact
comparison does not make names safe filesystem paths or terminal output. Additional
control-character, whitespace-only, or confusable-name policy needs an agreed
server rule and matching cross-SDK vectors, not a binding-local transformation.

## Configuration and Trust

```
TYPE ManagedRegistrationConfig
  organizationId?: string    // stable registry account ID
  governanceId?: string      // expected accountable governance domain
  entityKeyUrl: string       // independently configured HTTPS bootstrap endpoint
END
```

`LoadedConfig.registration` is setup configuration, not core identity or counterparty
acceptance. Resolve organization ID and GI from authenticated onboarding and compare
all configured/saved bindings before key generation or a create/proof/issuance mutation.
Organization ID is the byte-exact `org_id` string, not the GI or a credential hash.
Resolve it before selecting named state; never search across organizations by name
alone. Require verified GI and entity-key delegation. A credential for a different
organization fails locally before creation; server authorization remains mandatory.

`entityKeyUrl` stays configured because onboarding does not return a complete JWKS
URL. Validate it and GI before mutation and against publication facts before
countersigning. Fetch its JWKS under the effective transport/resource policies,
select the profile's entity signing key, and retain its public binding for recovery.
These are expectations, not creation selectors. The Foundry facade does not accept
ordinary `domain`, `rootDomain`, or `governanceDomain` selectors. It never translates
expected GI into a root; the named Live server path owns allocation/accountability.

Log trust requires explicit `logTrust` or an injected `LogRegistry`, with independent
trust roots. Validate the returned/signed log reference against it. Product presets
must be explicit. Durable checkpoint stores are opened and injected under
[12](12-configuration-loading.md#construction); setup does not reset checkpoint
trust or invent persistence settings. SDK-managed networking uses the loaded
transport settings throughout. Public checks use a separate credential-free client;
registry credentials MUST NOT reach DNS, public JWKS/status/log hosts, or redirects.

The registry is trusted to allocate the domain and use the accountable-entity key
to sign its publication. Pinning that entity key does not independently constrain
the registry's choice of operational key. Before completion, verify that signed `ku`
serves the provider's RFC 7638 thumbprint, or a successor authorized by verified
lifecycle history. Overlay validated publication fields without changing transport,
DNSSEC, freshness, log trust, or application acceptance policy.

Public readiness uses fresh, isolated verification with expected GI and the
independently bootstrapped entity pin, not application caches or local-key shortcuts.
This does not modify application `trustedEntities`, pins, or the policy of public
`VerifyDomain`, including calls for the local domain.

### Server Compatibility and Enablement

The hash version below is a derivation domain separator, not a server capability
advertisement. Existing onboarding has no agreed `managed_registration` field.
Do not add that wire requirement or a caller acknowledgement flag as a substitute
for server support.

A released Foundry adapter MUST target a server contract/deployment whose named
creation, replay-expiry, caller-key proof, and issuance recovery checks have passed
[server acceptance](../managed-registration-server-requirements.md#acceptance-checks).
Record the supported server revision/contract and deployment with the SDK release;
this release gate is not a runtime capability probe. Until negotiation is agreed,
do not claim automatic detection of an incompatible deployment. Initial creation
must not be enabled against the current ordinary 24-hour replay-cache contract.
Machine-readable version/capability negotiation remains an E2/E5 decision; when
agreed, unsupported contracts must fail before mutation. Key-specific URL/rotation
hosting is a separate E7 gate, not a prerequisite for initial creation. Replacement
has its own gate and remains unavailable until generation intent is agreed.

## Durable Setup

`Create` performs steps 1–3; `Active` performs steps 4–8. Both persist progress before
subsequent mutations and use one finite deadline/cancellation budget per invocation.

1. Validate the exact name, static configuration, selected workflow, and provider
   availability/algorithm under 12 before discovery or mutations. Obtain authenticated
   account bindings and lock/load/validate named state. Deployment support is the
   release gate above, not an invented onboarding capability read.
2. Persist account/trust bindings, creation intent, and a stable provider locator
   before generation. Open the existing key or atomically create/recover one there.
   Persist its immutable provider reference and initial public JWK before creation.
   The current caller-key Live adapter requires Ed25519/EdDSA; reject unsupported
   provider algorithms without silently substituting a local key.
3. If creation is unresolved, derive `registrationKey`, reconstruct the identical
   `LiveAgentRegistrationInput`, and call `RegisterLiveAgent`. Retain all known
   response facts even on error. Validate `requestId` against the sent key and any
   challenge transcript against organization, agent, domain, key, and expiry. Persist
   immutable ID/domain and pending proof facts before returning the handle. If the
   identity is known, use authenticated reads, not another fresh create. Validate
   and retain publication configuration/issuer when returned; a 202 alone need not
   contain them. A response missing facts needed for safe continuation is resumable,
   not permission to guess them.
4. If the server requires a proof challenge, use the existing `SubmitLiveProof` and
   `ReissueLiveProof` flow. Persist the exact challenge bytes, signature/request, and
   outcome before subsequent effects; sign decoded `challengeMessage` without
   re-encoding it. Reissue only an expired unused challenge on the same operation/key.
   Do not submit old proof after adopting a reissue. A replay already past proof
   resumes polling, not a new challenge. Removing this challenge is a server decision;
   it would not remove the ISSUANCE countersignature.
5. Wait for the issuance prerequisite (`VERIFIED` or `READY`) or a structured
   customer-action/error result. Obtain and validate publication authority/configuration
   and the trusted entity key before countersigning. Require registry authority;
   do not infer it from a request domain or print self-hosting instructions for a
   registry-managed identity. Apply [Registry States](#registry-states).
6. Recover and verify accepted ISSUANCE first. Otherwise use the shared resumable
   issuance coordinator for preparation, independent validation, countersigning,
   exact-byte persistence, submission, and acceptance binding. Send `issuanceKey`
   as the `Idempotency-Key` header; neither derived key is a JSON body member.
   Apply [Issuance Recovery](#issuance-recovery) before making submission failure
   final. The registry owns append/publication; consumers provide no activation callback.
7. After accepted issuance, await registry-managed publication and independently
   verify public DNS/HTTPS/log evidence: domain, profile, expected GI/entity key,
   assigned log, current provider key, protocol `ACTIVE` at signed `su`, and fresh
   complete lifecycle evidence through `VerifyLogEvidence`. Use signed current `ku`,
   never an old endpoint fallback or synthesized URL. Bound expected propagation
   polling, including `RecordNotFound`; ordinary verifier classification stays unchanged.
8. Persist verified completion before enabling handle signing and returning. A
   later `Active` call repeats the public observation without preparation/append.

## Organization and Creation Replay

Derive keys with RFC 8785 JCS, UTF-8, SHA-256, and unpadded base64url. `initialKeyId`
is the initial public key's RFC 7638 thumbprint, not a provider alias or raw-JWK hash.
Use the exact name and onboarding organization ID.

```
registrationKey = base64url-no-pad(SHA-256(JCS([
  "dnsid-managed-registration-v1", organizationId, name, initialKeyId
])))
issuanceKey = base64url-no-pad(SHA-256(JCS([
  "dnsid-managed-issuance-v1", registrationKey
])))
```

The current Live adapter's `request_id` equals the caller's registration key; the
server's canonical operation ID can differ and is not reconstructed by the SDK.
Retain the returned request ID for proof/reissue. Keep the initial public binding
through retries, credential replacement, and rotation; never rederive an unfinished
operation from a rotated key. Freeze all creation input while its outcome is unknown.

Matching replicas need the same provider key as well as the same name/input. The
hash cannot reconcile independently generated keys. Atomic first-key discovery must
converge at a shared locator; otherwise require an existing shared key reference.
Local per-host stores alone do not provide multi-host convergence. A failed or
ambiguous lookup MUST NOT trigger generation of another key.

Durable server identity/operation bindings must outlive the replay cache. Expiry,
cleanup, timeout, deletion, or retry MUST NOT turn a delayed request into a new
identity. This does not require converting all ordinary replay-cache rows into
permanent rows: E2 owns durable operation/history storage and old-generation lookup.
Known identities resume by immutable binding; missing local state is not replacement
authorization. Historical request outcomes and current name ownership must not be
confused, including after revoke/retire. Same-name creation with changed metadata
must not mutate an existing operation; retain the original frozen request and surface
its structured conflict. The complete server fingerprint/error matrix belongs to E2.

This executable check freezes exact-name derivation, including distinct Unicode
spellings. Compact UTF-8 JSON is JCS for these string-only arrays.

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

A rejection is final for submitted bytes, not proof that no ISSUANCE exists.
Before persisting final submission failure, recover lifecycle history and verify
accepted ISSUANCE against the retained identity, initial public key, entity binding,
and independent log trust. Another replica may have produced different valid
signature bytes; adopt its verified accepted entry/inclusion, never its receipt as
acceptance of the losing bytes. Do not resubmit an accepted event.

Unknown outcomes retain exact persisted bytes and retry under the same key.
Unavailable/missing evidence does not authorize another issuance. Replace an expired
preparation only when durable server state establishes reclaimability under
[11](11-c2sp-tlog-binding.md#submission-and-idempotency); persist the replacement
before submission and keep the same issuance key. If that state cannot be established,
return a recoverable error. Invalid countersignatures must not permanently consume
the server submission binding. These are acceptance requirements, not claims about
current Go/TypeScript coordinator coverage; Python needs the same coordinator.

## Registry States

Registry workflow states and protocol `AgentStatus.state` are separate namespaces.
Keep existing low-level registry-status wait helpers unchanged; `Active` applies this
Foundry workflow contract and public verification.

| Registry states | Foundry handle behavior |
|---|---|
| `PENDING`, `PROVISIONING`, `VERIFICATION` | Retain identity; complete required proof or wait. No replacement. |
| `VERIFIED`, `READY` | Resume issuance/publication/public evidence checks. Not proof of ACTIVE. |
| `ERROR` | Return retained facts and a workflow error; ERROR is not replacement permission or proof the business operation is terminal. Resume only through an agreed server recovery path. |
| `REJECTED`, `CANCELLED` | Stop this wait with a typed workflow outcome. Name ownership remains; no fresh-key replacement inferred. |
| `REVOKED`, `RETIRED` | Terminal identity. Stop signing/waiting, retain history. Intentional same-name replacement needs the separate generation contract below. |
| Unknown state | Preserve it for diagnostics; never interpret it as ready, recoverable mutation permission, or name release. |

The in-flight ownership index excludes only revoke/retire and soft-deleted rows.
Soft deletion is not SDK replacement authorization; delayed-replay/history safety
must still pass E2 acceptance. Provisioning-failure cleanup and customer-action
policy remain open; the SDK does not free names or restart ERROR by calling create.

## Completed-Operation Resume

Verify historical issuance using retained public bindings/hash/inclusion; the
initial private key need not remain after authorized rotation. Open the current
provider reference and verify its signing key against fresh signed TXT/`ku` and
lifecycle continuity before enabling a new handle's signer. Rotation can change
key/URL while preserving ID/domain/history. Registration observes completed rotations;
pending rotations use the existing recovery coordinator, not another ISSUANCE.
A handle holding a superseded key pauses signing and requires reconciliation to
the verified successor; it never generates a replacement key to fix the mismatch.

The PRD permits same-name creation after revoke/retire with a new domain/log stream;
the old domain stays assigned and serves terminal history in V1. E2 still must agree
how intentional replacement differs from a delayed create. This design does not add
a `replaces` wire field, operation nonce, or replacement endpoint. Until that contract
and its proof exist, a terminal resume returns a typed error, not automatic replacement.
A future explicit replacement archives the old operation and uses a fresh provider
locator/key; no timeout, missing key, or missing state authorizes it.

## Storage and Recovery

`ManagedRegistrationStore` durably creates, loads, and transitions named operations.
`FileRegistrationStore(directory)` stores multiple identities by validated
`(registry URL, organization ID, exact name)`. The default SDK and CLI entry points
share the binding's documented state/key locations; explicit stores remain injectable.
Use digests/safe encodings, not raw names as paths. Persist/check the full tuple and
isolate configurations, keys, and locks across tenants. Historical operations remain
addressable by immutable ID rather than being overwritten when names are reused.

An exclusive in-process/cross-process lock covers loading through return/error for
each invocation, including `Active`. Handles release it between calls; they reload
and validate durable state when reacquiring it. Competitors receive a typed busy
error within the call's deadline. Storage must prevent an unresolved write from
committing after lock release. Reconcile indeterminate writes before more mutations.

Files require owner-only access, atomic durable updates (including directory
durability where required), and documented interrupted-process lock recovery.
Validate missing, corrupt, conflicting, or partial artifacts before mutation. Key
intent/locator precedes generation; recover that key or report ambiguous initialization,
never silently generate another. Empty new state differs from incomplete state.

### Portable Recovery Document

Stores support cross-binding import/export as UTF-8 RFC 8785 canonical JSON, rejecting
duplicate members and invalid Unicode. `schemaVersion` is `1`; unsupported versions
or phases fail without rewriting and include upgrade guidance. Preserve unknown
members on rewrite. These unreleased documents replace the earlier normalized-name
proposal; never guess or silently remap existing state under another name rule.

Optional members are omitted until known. Counters/indexes are nonnegative safe
integers, byte strings unpadded base64url, and timestamps RFC 3339 UTC.

| Member | Value |
|---|---|
| `schemaVersion`, `phase` | `1`; `key-pending`, `creation-pending`, `identity-known`, `proof-pending`, `issuance-accepted`, or `complete`. |
| `registryUrl`, `organizationId`, `name` | Required exact named-operation tuple. |
| `governanceId`, `entityKeyUrl`, `logTrust` | Resolved expected bindings; trust uses 12's names. Injected dependencies must be supplied again and match saved bindings. |
| `keySource`, `currentKeySource` | Non-secret 12 key-source data: original locator/reference, and current reference after verified rotation when different. |
| `initialPublicKey` | Initial public JWK, retained once known. |
| `creationInput` | Frozen unresolved Live request fields under 05's wire names; `name`/`public_key` reconstructed from the corresponding members. |
| `identityId`, `domain` | Immutable creation facts, retained as soon as individually known. |
| `requestId`, `proof` | Returned Live request ID; exact challenge message, decoded binding, completed proof request, and latest outcome as known. Never the private key. |
| `publicationConfig`, `oidcIssuerUrl`, `entityPublicKey` | Validated publication snapshot, exact returned issuer when present, and trusted entity public JWK once obtained. |
| `issuance` | Prepared/completed bytes, SHA-256 lowercase-hex completed `entryHash`, submission state/error, log reference/index, and verified acceptance facts as known. Submission states follow 11. |

`key-pending` retains generation intent; `creation-pending` requires the initial
public/provider binding and reconstructible request. `identity-known` retains known
creation facts; `proof-pending` additionally retains the exact proof context.
`issuance-accepted` requires validated publication/entity bindings and accepted
entry retrieval facts. `complete` additionally records public verification, not
an evergreen ACTIVE claim. Validate every recorded phase before mutation.

Remove exact proof/issuance bytes only after their outcome is durably known and
sufficient verified retrieval facts remain. Until then unknown submission uses
identical bytes. Retain the initial public binding and identity facts in every
later phase. Failed historical retrieval is an error, not permission to issue again.
Import transfers no private keys or credentials; the destination must reopen the
same provider key or a verified successor. Document backup requirements and the
limits of ephemeral/container-local storage.

## Retry, Deadlines, and Errors

Each `Create`/`Active` call has one finite budget covering lock acquisition, provider
calls, network requests, storage, verification, and retries. Bindings document a
finite default and honor native cancellation. Retry classified transient failures
and unknown outcomes only with the same operation/input/bytes. Bounded propagation
polling may explicitly retry `RecordNotFound`; it does not change that verifier
error's non-transient classification. Integrity, policy, and binding failures stop.

Typed errors retain phase, HTTP status/wire code, immutable identity facts, registry
state, latest progress, and whether/how the same operation can resume. Distinguish:

- `KEY_MISSING`: the required local/provider key cannot be opened; do not generate
  over an established binding. This is distinct from the server's keyless custody flow.
- `KEY_MISMATCH`: an available/supplied key differs from the existing identity.
  The in-flight server spelling is HTTP 409 `KEY_MISMATCH` (PR #3304).
- `KEY_REVOKED`: preserve an authoritative credential/key revocation result; do
  not infer it from an ordinary 403, missing key, or generic provisioning failure.
- Busy, deadline, unsupported contract/algorithm, workflow outcome, and terminal
  identity: separate typed categories, retaining structured causes.

Do not relabel ordinary `422 IDEMPOTENCY_MISMATCH` or Live
`409 IDEMPOTENCY_CONFLICT` as a missing key. Preserve earlier authorization,
validation, quota, and infrastructure errors. Final missing-key/revocation wire
codes and remedy text remain an E2/E4 contract task. Recovery guidance must say
which key/store/operation to restore and point multi-region operators to a shared
same-cloud key; one identity per cloud is the V1 model, not cross-cloud key copying.

## CLI and Quick Starts

[E5 #52](https://github.com/Identity-Digital/known-foundry/issues/52) adds
`dnsid create <name>` and `dnsid retire <name>`. Create uses the same provider and
recovery configuration, invokes `Create` then `Active`, and returns success only
after public readiness. JSON output is machine-readable; warnings/progress go to
stderr. A timeout/nonzero exit reports known ID/domain and recovery guidance without
printing secrets or implying rollback. Rerunning resumes the same operation.
Retire uses the existing instance-safe registry endpoint and type-the-name
confirmation from E8; it never locally appends RETIREMENT. It must not report full
public/log convergence before observing it; an accepted-only result is labeled as
pending. `dnsid rotate <name>` remains E7.

The existing `init` refactor is tracked by
[server #2600](https://github.com/Identity-Digital/dnsid/issues/2600) and
[#2651](https://github.com/Identity-Digital/dnsid/issues/2651). Reuse its durable
key/publication helpers, but select hosting instructions by server-resolved
authority, not `--domain` or environment. Do not duplicate the old init mode branches
inside create. Console Go/Python/TypeScript/CLI snippets (E5 #53) use this same
Create/Active contract, show the local-development warning or configured KMS, and
never describe registry READY as protocol ACTIVE.

## Security Considerations

Setup uses a caller-supplied organization credential, preferably expiring, and never
persists it in deployment or recovery files. A replacement same-organization
credential resumes the same operation. Expiry limits duration, not privileges:
current organization API keys can affect other identities. Name-bound/create-only
scopes are an E4/security dependency, not a guarantee of this SDK. The threat model
and data inventory distinguish these design requirements from shipped coverage.

Untrusted registry/public responses must pass binding, signature, resource, TLS,
and independent log-trust checks before countersigning or completion. An invalid
response must not erase already accepted facts. Account handles and recovery files
are not public protocol data, but require safe paths, permissions, and backups.
Registry signing authority remains a trust assumption; this flow cannot prevent a
compromised registry/entity signer from misrepresenting identities to counterparties.

## Validation Scenarios

Bindings share observable scenarios; server persistence/concurrency proof stays in
[server acceptance](../managed-registration-server-requirements.md#acceptance-checks).
Extend the existing cross-SDK daily workflow with hosted-flow adapters against the
local registry/emulator. No SDK-produced expected verdicts or missing-adapter passes.

| Cases | Required result |
|---|---|
| Exact-name/hash vectors; case, whitespace, composed/decomposed Unicode, invalid scalar/length | Same bytes/keys across bindings; no silent normalization. |
| Configured facade through file/environment/code; invalid workflow/provider/algorithm | Same effective bindings; fail before mutation without sandbox/file fallback. |
| Wrong configured organization or account/delegation not ready | Fail before key generation/create; never create in the credential's other organization. |
| Concurrent first use, same name across tenants, unsafe path-like names | Isolated safe storage; shared locator yields one key and server identity, or explicit unsupported discovery. |
| Create returns pending handle; caller exits before Active | No false ACTIVE/signing; next invocation resumes required client work on the same identity. |
| Initial 202; retry without challenge/domain; proof expiry/reissue; unknown proof response | Preserve known facts/request ID; no guessed domain, duplicate allocation, stale proof, or new key. |
| Lost create response; replay-cache expiry; pending/ERROR/rejected/cancelled/terminal states | Correct same-operation recovery/outcome; no inferred name release or replacement. |
| Changed request/key; missing key; revoked credential/key | Distinct typed categories with status/code and actionable recovery guidance. |
| Independent replicas with different valid signature bytes; invalid countersignature then valid one | One accepted ISSUANCE; recover and verify winner, never bind its receipt to losing bytes or poison the submission key. |
| Interrupt generation, proof, preparation, submission, acceptance, publication, compaction | Durable same-key/exact-byte recovery; no mutation after lock release or corruption-driven recreation. |
| Registry READY but no public ACTIVE/log inclusion; propagation absence; wrong GI/key/profile/log | Bounded wait or failure; no success/signing until complete public verification. |
| Completed operation, verified rotation, superseded local provider, unknown enum/member/version | Reobserve without reissuance; select only verified current key; preserve unknown document members and fail safely on unsupported phases/versions. |
| CLI create/retire, JSON output, warning, rerun, delegated managed hosting | Same SDK flow; correct completion claims; no secrets, stdout pollution, or incorrect self-hosting instructions. |
| Revoke/retire and delayed old creates | Old identity/domain/history remain terminal; replacement disabled until the agreed generation contract passes proof. |
