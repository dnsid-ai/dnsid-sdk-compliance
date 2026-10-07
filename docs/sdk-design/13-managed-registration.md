# Managed Registration

This document defines the portable SDK workflow for creating a registry-managed
identity and making it publicly verifiable. It composes the contracts in
[01](01-core-identity-manager.md), [05](05-transport-and-registry.md),
[11](11-c2sp-tlog-binding.md), and [12](12-configuration-loading.md), preserving
DNSid wire behavior, registration selectors, and lifecycle authority.

The SDK owns recovery storage, issuance-store adapters, entity-key retrieval,
and retries for the ordinary managed flow. Bindings MUST expose equivalent
behavior through idiomatic APIs and provide a local file-backed store.
Existing low-level APIs remain available for custom deployments.

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
RegisterManagedIdentity(loaded: LoadedConfig,
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

Calling the workflow again against the same store resumes the same operation.
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
  governanceId: string       // independently configured expected accountability
  entityKeyUrl: string       // independently selected HTTPS bootstrap endpoint
END
```

`LoadedConfig.registration` carries this setup configuration. It does not add
values to core `IdentityConfig` or alter counterparty acceptance. The expected
GI and entity endpoint MUST be validated before creation and MUST match the
returned publication snapshot before countersigning. Fetch the entity JWKS
through SDK transport with the existing security/resource policies and select
the record-signing key using the publication profile, not a first-key heuristic.
Persist the selected public key and its thumbprint for issuance recovery.
Setup expectations are not registration selectors. Request a particular GI/root
through `input` under the rules in 05; do not silently translate an expected GI
into another selector or fall back to a different root. An omitted input uses
the ordinary public-key-only request, which must still satisfy the expectations.
When `input.governanceDomain` is explicit, normalize and compare it with the
configured expected GI before key generation or network mutations. A mismatch
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
its explicitly configured expected GI and independently bootstrapped entity-key
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

1. Validate static configuration and request shape. Acquire exclusive store
   access, then load and validate existing recovery state before key selection,
   generation, or network mutations.
2. Resolve the stable owning organization through the registry adapter using the
   supplied credential. Validate its match with saved state and establish the
   adapter's replay/reconciliation capability. Persist the setup intent, registry,
   organization, input, replay policy, and distinct registration/issuance replay
   keys before key generation.
3. Recover or select the operational provider, or durably create one local key.
   Persist its stable provider reference/public binding and the complete
   registration request before creation. No registry call receives private material.
4. Register or replay the identical request/key. Preserve all known creation
   facts and recoverable post-creation errors. Retain immutable ID, domain,
   publication configuration, and OIDC issuer before subsequent work.
5. Check authority and expected deployment bindings. Wait for the applicable
   ownership-verification prerequisite; registry workflow state is not protocol
   identity evidence.
6. Select and persist the trusted entity public key. Delegate preparation,
   validation, countersigning, exact-byte persistence, submission, and acceptance
   binding to the existing managed-issuance implementation.
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

The registry adapter MUST resolve a stable owning-organization identifier from
an authenticated server response before creation. Persist it with the registry
binding and validate it with the current credential on resume before mutations.
Credential replacement within that organization is supported. A mismatch or
unavailable authenticated binding returns a typed error. Credential hashes and
caller-supplied organization labels are insufficient to establish this binding.
This is an adapter capability requirement, not a new portable registry endpoint.

The adapter MUST provide at least one safe recovery mechanism:

- a documented minimum creation-idempotency retention guarantee, including its
  scope and start conditions; or
- authenticated reconciliation of the original organization/request key that
  resolves its identity or establishes that submitting that same request is safe.

Safe reconciliation preserves an authoritative operation claim or equivalent
replay guarantee through any subsequent submission. A plain "not found" result
is inconclusive.

Validate capability before creation. Persist the selected recovery mechanism and
the first attempt's start time before sending the request. For retention-based
replay, also persist the guarantee and derive a conservative deadline from the
minimum retention, accounting for clock uncertainty across restarts. Retries keep
that original deadline; later responses do not reset it. A reconciliation-only
adapter resolves each unknown creation outcome before another submission.
A transport error or an unauthenticated/missing lookup result does not establish
safe replay.

Replay an unknown creation outcome only within the established guarantee. Beyond
that bound, or when time/guarantee validity is uncertain, use safe reconciliation
or return a reconciliation-required error. A resolved identity must match the
original request, operational public key, and retained creation facts. Preserve
any known identity without allocating a replacement. Missing local creation facts
are not proof that no identity exists.

## Completed-Operation Resume

Keep the original request, initial public key, entity pin, and exact issuance
bytes as historical setup evidence. For completed setup, validate the current
operational key against fresh verified lifecycle history and the provider's
current signing key. Authorized rotations may change that key while preserving
the original setup operation and immutable identity.

Validate the original issuance against its saved historical public material;
its old private key is not required to open a completed identity. The returned
manager uses the verified current signing key. A different key without verified
rotation continuity returns a typed binding error. The registration workflow
observes completed rotations; it does not initiate or finish pending rotations.
Pending rotation uses the existing rotation recovery coordinator.

An explicit input on resume must match the saved original creation request,
including any originally supplied public key. Omitted input reuses that request.
The stricter original-provider/key check still applies to unfinished issuance.
A terminal public identity returns a typed error with its history retained.

## Storage and Recovery

`ManagedRegistrationStore` provides exclusive durable creation, loading, and
transition persistence for one setup operation, including the issuance state.
Bindings may reuse their existing storage interfaces internally. Custom database
storage remains possible without requiring it from ordinary consumers.

Exclusive access covers loading, validation, key handling, and every transition
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
- initialization intent/key locator, authenticated organization and registry
  binding, recovery mechanism/first-attempt time and any replay guarantee/deadline,
  original complete request,
  replay keys, creation facts, retained snapshot,
  effective setup/deployment bindings and trust reference, provider reference/public
  key binding, trusted entity key, exact prepared and completed issuance
  bytes/outcomes, and convergence progress;
- key files managed by the SDK key provider, separate from public recovery data;
- validation of missing, corrupt, inconsistent, or conflicting recovery state
  before another network mutation.

After submission may have begun, only the original completed bytes and replay
key may be retried. Accepted issuance is not resubmitted; terminal outcomes
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
| Fresh managed setup | Key/request/intent persisted before mutations; success only after public completion checks. |
| Identical inputs from file, environment, and code | Same effective configuration and setup behavior; credentials kept outside configuration and recovery state. |
| Concurrent use of one local store | One exclusive operation from load through return; competing caller receives a typed busy error. |
| Interrupted initial key generation/persistence | Recover the same key from saved intent/locator or report ambiguous partial initialization before further mutations. |
| Credentials replaced within the same organization | Resume the original operation with the same replay keys. |
| Credentials resolve to another organization or cannot establish ownership | Typed error before mutations; original operation retained. |
| Adapter provides no replay guarantee or safe reconciliation | Capability error before creation. |
| Timeout after creation or failure of detail read | Original request/key and known creation facts retained; replay within the adapter's guarantee addresses the original operation. |
| Unknown creation outcome beyond safe replay retention or with uncertain time | Safe reconciliation or a reconciliation-required error; original deadline unchanged. |
| Reconciliation returns a conflicting identity/key or an inconclusive lookup | Typed error; no replacement allocation. |
| Interrupt before/after preparation, submission, acceptance, publication, or completion persistence | Resume at every boundary; unknown append uses identical bytes; accepted append is not repeated. |
| Missing key, conflicting provider/input, corrupt outcome, or absent signed bytes after submission | Typed failure before another mutation; no replacement key/identity. |
| Explicit requested GI disagrees with configured expected GI | Argument error before key generation or network mutations. |
| Returned authority, GI, entity endpoint/key, publication snapshot, log instance, or operational binding disagrees | Stop before unauthorized countersigning or success. |
| Registry READY but DNS/evidence absent | Continue bounded convergence or return a resumable error. |
| Invalid signature, policy denial, terminal rejection, or unsupported profile | Fail closed without broad retry or policy modification. |
| Cancellation/deadline after a mutation | Recovery preserved; no success and no implicit rollback/recreation. |
| Completed operation resumed | Same immutable identity, new public observation, no creation/preparation/append. |
| Completed operation resumed after authorized key rotation | Validate historical issuance separately; verified current key configures the returned manager without requiring the old private key. |
| Completed operation resumed with an unexplained key change or pending rotation | Binding error or existing rotation recovery guidance; setup does not rotate. |
| Completed identity is revoked/retired | Typed terminal error; original history retained. |
| Setup entity excluded by application allowlist | Setup does not change the allowlist; returned manager's public verification still enforces it. |
| Local identity absent versus a matching supplied identity snapshot | Same setup checks; conflicting supplied snapshot fails. |
