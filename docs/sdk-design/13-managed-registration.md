# Managed Registration

This document defines the portable SDK workflow for creating a registry-managed
identity and making it publicly verifiable. It composes the contracts in
[01](01-core-identity-manager.md), [05](05-transport-and-registry.md),
[11](11-c2sp-tlog-binding.md), and [12](12-configuration-loading.md), preserving
DNSid wire behavior, registration selectors, and lifecycle authority.

The SDK owns recovery storage, issuance-store adapters, entity-key retrieval,
and retries for the ordinary managed flow. Bindings MUST expose equivalent
behavior through idiomatic APIs and provide a local file-backed store.
Existing low-level APIs remain available for custom deployments. The SDK MUST
provide the registry client implementation needed by this workflow; consumers
supply configuration, credentials, and storage, not a recovery adapter.

## Scope and Ownership

Managed registration sits above core, configuration loading, registry clients,
and log bindings. It MUST NOT add hosted-product behavior to `IdentityManager`
or to public identity verification. Place it in an umbrella SDK module or a
separate package where dependency direction requires that.

The first workflow supports ordinary registration with registry-controlled
entity signing and publication. Client-controlled publication and the separate
Live proof workflow are not implicit fallbacks. If registration returns an
unsupported authority or workflow, preserve the creation facts and return a
typed error; creation may already have occurred.

Domain eligibility, account onboarding, quotas, organization authorization,
domain pools, and customer-name allocation remain registry/product operations.
They are not DNSid protocol requirements.

## Public Workflow

Names below are language-neutral. Signatures abbreviate native cancellation,
deadline, and injected-dependency parameters.

```
RegisterManagedIdentity(name: string,
                        loaded: LoadedConfig,
                        credential,
                        store: ManagedRegistrationStore,
                        input?: AgentRegistrationInput) -> ManagedRegistrationResult
```

`RegisterManagedIdentity` creates or resumes one durable local setup operation
and returns after the public completion checks below. Errors report the assigned
domain and immutable registration ID when known, the observed registry workflow
state, and separate setup convergence state. Registry `PROVISIONING`, `VERIFIED`,
or `READY` is progress, not successful protocol `ACTIVE`.

The result contains the retained registration/publication snapshot,
a configured local `IdentityManager`, `PublishedRecord`, and
`LoggedStateEvidence`. It is evidence at an observation time, not a perpetual
promise of activity or application authorization.

The required name selects local state within the configured registry and
organization. Trim leading/trailing whitespace, reject an empty name or more than
255 Unicode code points, and preserve case. Use that name as the registration's
`name` display field; an explicit `input.name` must match it. Names are not domains
and never appear in DNS or lifecycle entries.

Calling the workflow again for the same registry/organization/name resumes the
same operation.
After completion it opens that identity and checks current public evidence;
it does not register again, prepare another ISSUANCE, or append an event merely
because the process restarted. Conflicting input or deployment bindings fail
rather than changing the operation. During initial setup, an explicitly supplied
registration public key MUST match the selected operational provider; otherwise
the workflow supplies its public key without sending private key material.
Completed-operation resume uses the rotation-aware checks below.

## Configuration and Trust

```
TYPE ManagedRegistrationConfig
  organizationId?: string    // stable registry account ID; configured or discovered
  governanceId?: string      // expected accountability; configured, saved, or discovered
  entityKeyUrl: string       // independently selected HTTPS bootstrap endpoint
END
```

`LoadedConfig.registration` carries this setup configuration. It does not add
values to core `IdentityConfig` or alter counterparty acceptance.
Resolve a non-secret organization ID and expected GI before key generation or
creation. Prefer configured values, then matching saved bindings; use the SDK-owned
[authenticated onboarding read](05-transport-and-registry.md#account-binding-discovery)
for missing values. Organization ID must be configured or discovered before selecting
the named store: never search across organizations by name alone. Once the tuple
locates saved state, it can supply the saved GI. If discovery is needed, compare
all supplied/saved values with its response, require verified governance and
entity-key delegation, and persist the resolved bindings before key generation.
A configured or saved binding is never silently replaced by a response.

Discovery is an effectful workflow step, not a loader/constructor side effect or
consumer callback. If it is unavailable and required bindings are missing, return
a configuration/discovery error; fully configured registries need no discovery call.
The current endpoint does not return `entityKeyUrl`, which remains independently
configured and MUST NOT be fabricated from its CNAME or response.

The organization ID is the registry's stable account identifier, not a credential
hash or caller-invented label. GI is its verified domain, not that account ID.
Credential replacement and GI changes do not change the organization ID. The
server authenticates the actual organization and validates the derived request key
against it; local configuration is not authorization. Validate the resolved expected
GI and configured entity endpoint before creation; they MUST match the returned
publication snapshot before countersigning. Fetch the entity JWKS
through SDK transport with the existing security/resource policies and select
the record-signing key using the publication profile, not a first-key heuristic.
Persist the selected public key and its thumbprint for issuance recovery.
Setup expectations are not registration selectors. Request a particular GI/root
through `input` under the rules in 05; do not silently translate an expected GI
into another selector or fall back to a different root. An omitted input uses
the ordinary public-key request with the selected name, which must still satisfy
the expectations.
When `input.governanceDomain` is explicit, normalize and compare it with the
resolved expected GI before key generation or network mutations. If both are
configured, reject a contradiction before discovery. A mismatch
returns an argument error. Root eligibility and effective publication bindings
remain registry checks. The placement of selectors and expectations is an
[open configuration question](08-open-questions.md#managed-registration-configuration).

Log trust remains an explicit `logTrust` selection or injected `LogRegistry`.
Validate the assigned log reference with its selected binding and independently
configured trust roots. Product adapters may impose additional known log/root
constraints.
A GI does not imply an agent-domain suffix: customer-accountable agents may use
an unrelated registry-operated domain.

Consume loaded configuration from code, a deployment file, environment, or
explicitly merged sources. Constructors do not discover sources. Credentials
remain separately supplied secrets; neither deployment configuration nor recovery
state stores them. Explicit injected providers/networking remain caller-owned;
SDK-managed networking honors the effective transport configuration for registry,
bootstrap, publication, and verification operations. An explicit hosted-product
preset may provide reviewed setup endpoints and log trust. Preset selection
MUST be explicit.

Overlay the retained creation-time publication snapshot into local identity
configuration without modifying transport, DNSSEC, freshness, log trust, or
counterparty acceptance. Existing loaded identity fields must agree with recovery
state; do not silently discard or replace them. A changed authenticated detail
response or creation replay is not permission to replace the saved snapshot.

For final checks, setup constructs an isolated credential-free verifier with
its resolved, persisted expected GI and independently bootstrapped entity-key
pin. The application manager and its caches are not the evidence source. This
setup-specific policy does not infer approval from local identity fields and
does not return an acceptance-free `VerifiedDomain` through a new public API.
Setup MUST NOT insert that entity into the application's `trustedEntities`
allowlist, widen pins, or retry an acceptance denial without policy. The local
manager returned to the application retains the caller's original verification
policy. General public `VerifyDomain` continues to enforce that policy, including
when called on the local domain.

## Durable Setup

Use one durable setup operation that composes the existing binding-owned issuance
state; do not build a competing lifecycle coordinator or append path.

1. Validate the name, static configuration, and request shape. Resolve selected
   provider availability and configuration before account discovery or mutations;
   an injected provider wins. Resolve the organization ID, acquire exclusive access
   to this registry/organization/name, then validate saved state and resolve GI.
   Discovery shares the invocation's deadline and transport settings.
2. For new or unresolved creation, persist resolved account/trust bindings, named
   setup intent, any extra creation inputs, and a stable key locator before key
   generation. Do not recreate discarded inputs when resuming a known identity. On resume, reject
   conflicting bindings or unresolved creation inputs without changing the operation.
3. Recover or select the operational provider, or durably generate one key at the
   saved locator. The file default emits a production-safety warning; cloud
   generation stays inside the provider. Persist its reference and initial public
   key binding. Derive registration/issuance keys on demand from those saved facts;
   reconstruct creation input instead of storing a duplicate request object.
   No registry call receives private material.
4. If creation is unresolved, register/replay the reconstructed identical input
   and derived key. If the immutable identity is already known, read that identity
   and resume its next phase rather than issuing another creation request.
   Preserve post-creation errors and durably retain ID, domain, publication
   configuration, and OIDC issuer before discarding creation-only inputs.
5. Check authority and expected deployment bindings. Wait for the applicable
   ownership-verification prerequisite; registry workflow state is not protocol
   identity evidence.
6. Select and persist the trusted entity public key. If the opened identity
   already has an accepted ISSUANCE, recover and validate that entry with the
   existing binding, retain its evidence, and do not prepare or append another.
   Otherwise delegate preparation, validation, countersigning, exact-byte
   persistence, submission, and acceptance binding to the existing managed-issuance
   implementation. Registry READY alone does not establish accepted issuance.
7. After acceptance, use `AwaitRegistryManagedPublication` to observe valid public
   publication. The registry owns the log append.
8. Use public DNS/HTTPS/log verification without owner credentials or local-key
   evidence shortcuts. Check the assigned domain/log instance, publication
   profile, expected GI/entity key, current operational key, protocol `ACTIVE`,
   and fresh complete lifecycle evidence through `VerifyLogEvidence`.
9. Durably mark setup complete and return the result.

Registry-owned status/publication is observed, not controlled by an application
callback. A consumer of this workflow MUST NOT have to provide a no-op activation
controller or publish endpoints. Internal issuance adapters still preserve their
required durable ordering. Publication confirmation remains the internal
protocol-only control-plane operation defined in 05; setup's expected-binding
check is not a public counterparty-acceptance bypass.

## Organization and Creation Replay

Ordinary keyed creation uses the permanent server-side idempotency and named-agent
contract in [05](05-transport-and-registry.md#registration-replay-and-recovery).
No recovery adapter or organization-lookup callback is required.

Derive keys using RFC 8785 canonical JSON (JCS), UTF-8, SHA-256, and unpadded
base64url. `initialKeyId` is the RFC 7638 thumbprint of the initial operational
public key, not a hash of raw JWK JSON or a provider-assigned alias.

```
registrationKey = base64url-no-pad(SHA-256(JCS([
  "dnsid-managed-registration-v1", organizationId, name, initialKeyId
])))
issuanceKey = base64url-no-pad(SHA-256(JCS([
  "dnsid-managed-issuance-v1", registrationKey
])))
```

This runnable encoding check uses the thumbprint of the RFC 8032 test-1 Ed25519
public key. Compact UTF-8 JSON below is JCS for these string-only arrays.

```python
import base64, hashlib, json

def digest(fields):
    data = json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()

fields = ["dnsid-managed-registration-v1", "11111111-1111-4111-8111-111111111111",
          "billing-agent", "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"]
key = digest(fields)
assert key == "2sWNUpI4tnAzJ3quPrT78uJNVdo96m4En3cZsggktcA"
assert digest(["dnsid-managed-issuance-v1", key]) == "pxQMSC0k-V9nn9qLqMRDczyUxyNyQE87LbGuK5SEWGw"
assert digest(fields[:2] + ["research-agent", fields[3]]) != key
```

Persist the normalized name, organization ID, and initial public key binding in
named local configuration. Compute its thumbprint and both replay keys on demand;
separate durable copies are not required. Retain the initial binding through
credential replacement, retries, and operational-key rotation; never rehash with
the current rotated key. Independently starting replicas using the same organization/name/
initial key derive the same creation and issuance keys. Complete registration
input must also agree; changed selectors or metadata are not matching retries.

The server validates `registrationKey` using the authenticated organization's ID,
request name, and initial public key. A wrong configured organization therefore
fails before allocation, even if the supplied credential is valid for another
organization. Request-key storage remains organization-scoped; a global key
namespace is unnecessary. The server also enforces one nonterminal identity per
organization/name, independently of the request key. A different key for an
occupied name fails rather than allocating another identity. Same-name opening
with a rotated key must preserve the existing identity and verified rotation
continuity, not initiate another ISSUANCE.

While creation is unresolved, reconstruct and retry the same complete input and
derived key after a timeout or lost response. Name/public key come from saved
bindings; freeze any additional selectors/metadata until creation is known. The
key identifies the operation but does not permit changed request contents: server
fingerprint checks still apply. Once ID/domain and validated creation facts are
durable, resume through identity reads and later phases, not another create.
The server retains the binding permanently, including after retirement or
deletion; replay never allocates a replacement. No retention window, first-attempt
timestamp, replay deadline, or reconciliation callback is required. HTTP deadlines
bound an invocation, not the lifetime of its registration key.

Validate creation responses against the reconstructed input and initial public
key; validate subsequent reads against retained immutable identity and trust
bindings, using verified rotation continuity for the current operational key. Preserve any known identity and publication
snapshot on errors. Missing local creation facts are not proof that no identity
exists. Registries without this server contract are not supported by the automatic
managed workflow; low-level APIs remain available without an automatic-retry
promise. SDKs MUST NOT replace this requirement with an unimplemented adapter or
an acknowledgement flag such as `--server-contract-verified`. Server work and
acceptance checks are tracked in [Managed Registration Server Requirements](../managed-registration-server-requirements.md).

## Completed-Operation Resume

Keep immutable identity and creation-publication facts, the initial public-key
binding, entity pin, and bound issuance acceptance/reference as historical setup
evidence. Completed state need not keep a duplicate original request or issuance
bytes. Recover the historical entry through the existing log binding, verify its
hash/inclusion and signatures against saved bindings, and validate the current
operational key against fresh verified lifecycle history and the provider's
current signing key. Authorized rotations may change that key while preserving
the original setup operation and immutable identity.

Validate the original issuance against its saved historical public material;
its old private key is not required to open a completed identity. The returned
manager uses the verified current signing key and current signed publication.
Authorized rotation may change the `ku` URL as well as its key. Retain the
creation-time publication snapshot as historical evidence; do not reject a new
key-specific URL merely because it differs from that snapshot. Validate the
current signed TXT, profile-owned URL constraints, and accepted rotation
continuity before configuring the manager with the observed URL. Do not derive
the URL from the new thumbprint or fall back to a retained old key endpoint.
A different key or publication change without verified lifecycle authority
returns a typed binding error. The registration workflow
observes completed rotations; it does not initiate or finish pending rotations.
Pending rotation uses the existing rotation recovery coordinator.

While creation is unresolved, explicit input must match its frozen semantic
inputs, including the initial public key; omitted input reconstructs them. Once
creation is durable, creation-only options no longer select an operation. Validate
explicit assertions against retained identity facts, and reject attempts to change
creation-only selectors/metadata without a creation call; callers can omit input
on resume. Keep a canonical semantic fingerprint if needed for these comparisons,
not the full request. The stricter initial-provider/key check still applies to
unfinished issuance.
A terminal public identity returns a typed error with its history retained.
Replaying its original registration key never creates a replacement. To replace a
revoked or retired identity, explicitly start new state for the same name after
confirming the previous identity is terminal. Retain the previous operation's
history and generate/select a fresh operational key that has never belonged to
that named identity, including its rotation history. The new key produces a new
registration key; no generation nonce is needed. Missing state, missing private
material, or a timeout is not permission to replace an identity. The server
atomically moves the name to the replacement while the old domain and log stream
remain terminal and unchanged.

## Storage and Recovery

`ManagedRegistrationStore` provides exclusive durable creation, loading, and
transition persistence for named setup operations, including issuance state.
`FileRegistrationStore(directory)` is a root for multiple identities, not one
shared identity slot. Locate each local configuration by the tuple of validated
registry URL, organization ID, and normalized name. Persist the tuple and verify
it on load. Bindings may use a digest or safely encoded path components; raw names
MUST NOT be interpreted as filesystem paths. Different organizations or registries
with the same name have separate configuration, key references, and locks.

The local configuration holds initial key bindings, phase-specific creation inputs,
identity/trust facts, and recovery progress, not merely deployment settings. It stays separate from the
shared deployment file in 12 and private key files. Explicit replacement preserves
historical operations rather than overwriting them. Bindings may reuse existing
storage interfaces; custom database storage remains optional.

Exclusive access for one registry/organization/name covers loading, validation,
key handling, and every transition
through completion or error. Release it on return, cancellation, or failure after
persisting recoverable transitions. A competing invocation returns a typed busy
error. Deadline/cancellation applies to lock acquisition as well as network work.

Before generating a key, persist enough intent and a stable key locator to
recover that same key after interruption. A provider must support durable
rediscovery at this boundary or report an ambiguous key-creation failure.
Partial initialization is validated before another key is generated. An empty
new store is distinct from a store with incomplete or inconsistent artifacts.

`FileRegistrationStore(directory)` MUST provide:

- restrictive permissions or equivalent owner-only platform access controls;
- exclusive access and a documented interrupted-process lock recovery policy;
- atomic durable updates, including directory durability where the platform
  requires it, or explicit filesystem/platform prerequisites;
- common durable facts: normalized name, organization ID, registry binding,
  initialization intent/key locator, initial public key, current provider reference,
  phase, effective account/deployment/trust bindings, and historical replacements;
- unresolved creation: additional original selectors/metadata needed to reconstruct
  the same semantic input; name/public key need no duplicate request representation;
- known identity: immutable ID/domain, validated creation-publication snapshot,
  OIDC issuer if returned, trusted entity key, and optional creation fingerprint;
- unresolved issuance: binding-owned exact prepared/completed bytes and outcomes;
- accepted issuance: bound entry hash/reference and verified acceptance facts needed
  to recover and verify the historical entry through the log binding;
- key files managed by the SDK key provider, separate from public recovery data;
- validation of missing, corrupt, inconsistent, or conflicting recovery state
  before another network mutation.

Creation-only input may be removed in the atomic transition that durably records
validated creation facts. Exact issuance bytes may be removed only after acceptance
is durably bound to their hash/reference and verified inclusion; the replacement
state must permit retrieval and validation of that same historical entry. Keep
raw bytes while acceptance/inclusion is unresolved. Cleanup must never erase the
last safe recovery path or cause another preparation/submission. Failure to recover
a compacted historical entry returns an error, not permission to issue again.
This compacts completed recovery data; it does not relax binding-owned persistence
or exact-byte retry ordering.

After submission may have begun, only the original completed bytes and derived
replay key may be retried. Accepted issuance is not resubmitted; terminal outcomes
remain terminal. Missing current private material or an unexplained provider/key
mismatch returns a typed error with recovery guidance. During unfinished setup,
use the original key binding; after completion, use verified rotation continuity.
Key loss does not authorize replacement creation or rotation.

The store is operational recovery data, not a shared deployment file. Bindings
must document backup requirements and that ephemeral/container-local storage is
not durable across host replacement. Do not place credentials or private JWKs
in public recovery data. Do not add compatibility shims for example-specific
historical file formats to the portable contract.

## Retry, Deadlines, and Errors

The workflow owns client-side retry scheduling; callers do not wrap it in a
second retry loop. Registry append/convergence ownership remains as defined in
05. All child operations share a finite overall deadline and cancellation
budget; native bindings document a finite default. Cancellation does not undo
creation or discard recovery state.

Retry classified transient failures and unknown outcomes with their original
requests/bytes. During publication convergence, narrowly classified absence of
expected DNS resources may be retried within the budget. Do not retry every
verification error: signature, binding, unsupported-profile, policy, and
terminal registry failures stop. Exceeding a resource limit or deadline returns
an error with recovery state preserved.

Errors preserve the underlying structured registry/binding category and report
the failed setup phase, known immutable identity, and whether the same operation
can be resumed. Missing-key and conflicting-state failures are distinguishable
from propagation delays. Error details do not expose credentials, private keys,
or configured acceptance policy.

## Validation Scenarios

Bindings MUST test the same observable behavior, with shared conformance cases
for workflow ordering and recovery:

| Scenario | Required result |
|---|---|
| Fresh managed setup | Account/intent/key bindings and needed creation inputs persisted before mutations; derived keys need no stored copies; success only after public completion checks. |
| Identical inputs from file, environment, and code | Same effective configuration and setup behavior; credentials kept outside configuration and recovery state. |
| Concurrent use of one named local state | One exclusive operation from load through return; competing caller receives a typed busy error. |
| Same name in different organizations or registries | Separate local configurations, key references, and locks. |
| Empty name, invalid entityKeyUrl, or conflicting input.name | Argument error before account discovery, key generation, or network mutations. |
| Account bindings absent from config/state | Discover missing organization ID/GI through authenticated onboarding; persist verified bindings before key generation. |
| Configured/saved bindings conflict with discovery | Binding error before key generation or creation; saved state unchanged. |
| Discovery unavailable, pending/unverified GI, or pending EK delegation | No fabricated bindings or creation; return configuration/discovery/readiness error. |
| Organization ID absent with same-name state in several organizations | Discover credential's organization first; never choose a store by name alone. |
| Selected provider unavailable or malformed | Fail before discovery or mutations; no local-provider fallback. |
| Name contains path separators or traversal syntax | Safe state addressing; no access outside the store root. |
| Same organization/name/initial public key in independent stores | Same registration and issuance keys; server converges on one identity and one ISSUANCE. |
| New local store opens an already issued matching named identity | Recover verified existing issuance; no new preparation or append, then perform public completion checks. |
| Existing nonterminal name with a different unrotated key | Server binding conflict; no additional identity or silent key replacement. |
| Interrupted initial key generation/persistence | Recover the same key from saved intent/locator or report ambiguous partial initialization before further mutations. |
| Credentials replaced within the same organization | Resume the original operation with the same replay keys. |
| Credential organization differs from configured organization ID | Server rejects the derived registration key before allocation, without disclosure; original state retained. |
| Creation response lost | Reconstruct identical input and key from minimal state, including frozen optional fields; replay addresses original operation. |
| Identity already durable but detail read fails | Retain identity and phase; resume through identity read, not another create. |
| Configuration changes optional creation fields after an unknown outcome | Reject rather than replay changed input under the same derived key. |
| Completed state compacted after verified inclusion | Recover the same historical issuance by bound hash/reference; verify without raw local entry bytes or another issuance. |
| Crash during phase-specific cleanup | Atomic state preserves either pending inputs/bytes or sufficient validated next-phase facts. |
| Resume after a long interruption or local clock change | Same request/key addresses the original operation; no replay expiration or time-based recovery policy. |
| Replay returns a conflicting identity/key | Typed binding error; retained facts unchanged and no replacement allocation. |
| Interrupt before/after preparation, submission, acceptance, publication, or completion persistence | Resume at every boundary; unknown append uses identical bytes; accepted append is not repeated. |
| Missing key, conflicting provider/input, corrupt outcome, or absent signed bytes while submission/inclusion is unresolved | Typed failure before another mutation; no replacement key/identity. |
| Explicit requested GI disagrees with expected GI | Configured contradiction fails before discovery; a discovered contradiction fails before key generation or creation. |
| Returned authority, GI, entity endpoint/key, publication snapshot, log instance, or operational binding disagrees | Stop before unauthorized countersigning or success. |
| Registry READY but DNS/evidence absent | Continue bounded convergence or return a resumable error. |
| Invalid signature, policy denial, terminal rejection, or unsupported profile | Fail closed without broad retry or policy modification. |
| Cancellation/deadline after a mutation | Recovery preserved; no success and no implicit rollback/recreation. |
| Completed operation resumed | Same immutable identity, new public observation, no creation/preparation/append. |
| Completed operation resumed after authorized key rotation | Original registration/issuance keys unchanged; validate historical issuance separately and configure the verified current key without the old private key. |
| Authorized rotation changes the signed ku URL | Preserve the historical creation snapshot; configure the observed current URL only after signed publication and rotation continuity checks. Never synthesize the URL or fall back to the old endpoint. |
| Completed operation resumed with an unexplained key change or pending rotation | Binding error or existing rotation recovery guidance; setup does not rotate. |
| Completed identity is revoked/retired | Typed terminal error on original-operation resume; original history retained. |
| Explicit same-name replacement after revocation/retirement | Fresh operational key and derived request key, new immutable ID/domain/stream; previous history retained. |
| Replacement reuses an initial or rotated key of the previous identity | Server rejects it; no replacement allocation. |
| Setup entity excluded by application allowlist | Setup does not change the allowlist; returned manager's public verification still enforces it. |
| Local identity absent versus a matching supplied identity snapshot | Same setup checks; conflicting supplied snapshot fails. |
