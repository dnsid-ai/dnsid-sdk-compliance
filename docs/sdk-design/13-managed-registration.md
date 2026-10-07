# Managed Registration

This document defines the portable SDK workflow for creating a registry-managed
identity and making it publicly verifiable. It composes the contracts in
[01](01-core-identity-manager.md), [05](05-transport-and-registry.md),
[11](11-c2sp-tlog-binding.md), and [12](12-configuration-loading.md); it does not
change DNSid wire behavior, registration selectors, or lifecycle authority.

The target is that TypeScript, Python, and Go consumers do not implement their
own recovery files, issuance-store adapters, entity-key fetches, or retry loops
for the ordinary managed flow. Bindings MUST expose equivalent behavior through
idiomatic APIs and provide a local file-backed store. Existing low-level APIs
remain available for custom deployments.

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
BeginManagedRegistration(loaded: LoadedConfig,
                         credential,
                         store: ManagedRegistrationStore,
                         input?: AgentRegistrationInput) -> ManagedIdentityHandle

RegisterManagedIdentity(loaded, credential, store, input?) -> ManagedRegistrationResult
  = BeginManagedRegistration(loaded, credential, store, input?).Active()

ManagedIdentityHandle.Active() -> ManagedRegistrationResult
```

`BeginManagedRegistration` creates or resumes one durable local setup operation.
It returns a handle after the assigned immutable identity is known, without
claiming that public verification has completed. `Active` drives remaining setup
and returns only after the completion checks below. The eager convenience
function uses exactly that path, with no second implementation of setup.

A handle exposes the assigned domain and immutable registration ID, observed
registry workflow state, and separate setup convergence state. Registry
`PROVISIONING`, `VERIFIED`, or `READY` MUST NOT be exposed as successful protocol
`ACTIVE`. The result contains the retained registration/publication snapshot,
a configured local `IdentityManager`, `PublishedRecord`, and
`LoggedStateEvidence`. It is evidence at an observation time, not a perpetual
promise of activity or application authorization.

Calling the workflow again against the same store resumes the same operation.
After completion it opens that identity and checks current public evidence;
it does not register again, prepare another ISSUANCE, or append an event merely
because the process restarted. Conflicting input or deployment bindings fail
rather than changing the operation. An explicitly supplied registration public
key MUST match the selected operational provider; otherwise the workflow
supplies its public key without sending private key material.

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
A future named-product facade resolves its authorized creation context explicitly.

Log trust remains an explicit `logTrust` selection or injected `LogRegistry`.
Validate the assigned log reference with its selected binding and caller trust;
a reference returned by the registry or a prepared event never supplies its own
trust roots. Product adapters may impose additional known log/root constraints.
A GI does not imply an agent-domain suffix: customer-accountable agents may use
an unrelated registry-operated domain.

Consume loaded configuration from code, a deployment file, environment, or
explicitly merged sources. Constructors do not discover sources. Credentials
remain separately supplied secrets; neither deployment configuration nor recovery
state stores them. Explicit injected providers/networking remain caller-owned;
SDK-managed networking honors the effective transport configuration for registry,
bootstrap, publication, and verification operations. An explicit hosted-product
preset may provide reviewed setup
endpoints and log trust, but a registry URL alone MUST NOT select such a preset.

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

1. Validate static configuration and request shape before network mutations.
2. Select an injected/configured operational provider, or durably create a local
   key through the file store. Retain its stable provider reference and public
   binding. No registry call receives private material.
3. Durably create the complete registration request and distinct replay keys for
   registration and issuance before creation. Bind recovery to the registry and,
   where the adapter exposes it, the authenticated organization.
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
   publication. Never race the registry with an independent log append.
8. Use public DNS/HTTPS/log verification without owner credentials or local-key
   evidence shortcuts. Check the assigned domain/log instance, publication
   profile, expected GI/entity key, current operational key, protocol `ACTIVE`,
   and fresh complete lifecycle evidence through `VerifyLogEvidence`.
9. Durably mark setup complete and return the result.

An unknown creation outcome may be replayed only while the adapter's original
idempotency guarantee applies. If retention has expired or safe replay cannot be
established, return a reconciliation-required error unless the adapter can
resolve the original operation/immutable identity safely. Missing local creation
facts are not proof that no identity exists.

Registry-owned status/publication is observed, not controlled by an application
callback. A consumer of this workflow MUST NOT have to provide a no-op activation
controller or publish endpoints. Internal issuance adapters still preserve their
required durable ordering. Publication confirmation remains the internal
protocol-only control-plane operation defined in 05; setup's expected-binding
check is not a public counterparty-acceptance bypass.

## Storage and Recovery

`ManagedRegistrationStore` provides exclusive durable creation, loading, and
transition persistence for one setup operation, including the issuance state.
Bindings may reuse their existing storage interfaces internally. Custom database
storage remains possible without requiring it from ordinary consumers.

`FileRegistrationStore(directory)` MUST provide:

- restrictive permissions or equivalent owner-only platform access controls;
- exclusive access and a documented interrupted-process lock recovery policy;
- atomic durable updates, including directory durability where the platform
  requires it, or explicit filesystem/platform prerequisites;
- the original complete request, replay keys, creation facts, retained snapshot,
  effective setup/deployment bindings and trust reference, provider reference/public
  key binding, trusted entity key, exact prepared and
  completed issuance bytes/outcomes, and convergence progress;
- key files managed by the SDK key provider, separate from public recovery data;
- validation of missing, corrupt, inconsistent, or conflicting recovery state
  before another network mutation.

After submission may have begun, only the original completed bytes and replay
key may be retried. Accepted issuance is not resubmitted; terminal outcomes
remain terminal. A missing key or provider/key mismatch on an existing operation
is a typed failure with recovery guidance, not a reason to generate another key,
replace an identity, or administratively authorize rotation.

The store is operational recovery data, not a shared deployment file. Bindings
must document backup requirements and that ephemeral/container-local storage is
not durable across host replacement. Do not place credentials or private JWKs
in public recovery data. Do not add compatibility shims for
example-specific historical file formats to the portable contract.

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
terminal registry failures stop. Resource limits and deadlines never allow a
partial result to be reported as active.

Errors preserve the underlying structured registry/binding category and report
the failed setup phase, known immutable identity, and whether the same operation
can be resumed. Missing-key and conflicting-state failures are distinguishable
from propagation delays. Error details do not expose credentials, private keys,
or configured acceptance policy.

## Future Named Product Creation

A hosted product may eventually expose `create("billing-agent")` over this
workflow. This is a future product facade, not an additional portable
`RegistryClient` operation or an implementation requirement for this change.
The design must permit that facade without weakening the contracts above.

A stable product handle and a request idempotency key solve different problems:

- A handle resolves an organization-scoped application name to a current immutable
  identity over restarts, machines, API-key replacement within that organization,
  and requests beyond transport-idempotency retention.
- A request key protects one concrete creation/submission operation. It does not
  establish persistent name uniqueness or resolve an existing identity.

`AgentRegistrationInput.name` is display metadata today, not a unique lookup key.
Do not implement named creation by setting that field or hashing the name into
an `Idempotency-Key`. The product needs an authenticated durable name mapping,
atomic first-create resolution, and explicit conflict/key-binding semantics.
Concurrent processes must not independently issue identities for the same
handle or silently attach different operational keys to one identity. A read-only
credential may resolve a handle only where product authorization permits it;
it never gains create authority from an SDK convenience method.

The facade can return an existing/provisioning handle and expose `active()`, or
wait eagerly through the same completion path. It must document which behavior
it selects. Returning a handle quickly is not evidence of public readiness.
A missing local key for an existing handle fails explicitly; credentials alone
cannot recover private material or authorize an unsigned key replacement.

Revocation/retirement ends an immutable identity. A product may define a later
explicit named-create invocation to allocate a replacement and move the handle,
but it must preserve the old domain/history and distinguish a new identity
generation from replay of an interrupted operation. Portable setup recovery
never automatically recreates a terminal identity.

Changing key-provider configuration does not itself authorize a key change.
Rediscover the same key where supported, migrate custody without changing public
material where the provider supports it, or perform the existing authorized
rotation with the previous key. With no previous key, use explicit terminal
lifecycle handling and replacement, not a silent swap.

The Known Foundry draft PRD dated October 2, 2026 describes this named-create
journey, but also contains working notes proposing ephemeral keys and short-lived
entity delegations instead of durable per-agent operational keys. Those are
alternative presentation/custody proposals, not settled DNSid setup behavior.
Keep them in a separately specified extension; do not weaken bilateral ISSUANCE,
operational continuity, key-loss handling, or open verifier semantics here.
Product onboarding, `.io` pools, registration hints/gates, automatic rotation
scheduling, and particular cloud-provider configuration also remain separately
owned. The portable workflow accommodates injected key providers without
claiming all product adapters are implemented.

## Validation Scenarios

Bindings MUST test the same observable behavior, with shared conformance cases
for workflow ordering and recovery:

| Scenario | Required result |
|---|---|
| Fresh managed setup | Key/request/intent persisted before mutations; success only after public completion checks. |
| Identical inputs from file, environment, and code | Same effective configuration and setup behavior; credentials never serialized. |
| Concurrent use of one local store | One exclusive operation; no duplicate creation or issuance. |
| Timeout after creation or failure of detail read | Original request/key and known creation facts retained; replay within the adapter's guarantee addresses the original operation. |
| Unknown creation outcome beyond safe request-key replay retention | Reconciliation required; no blind replay or replacement allocation. |
| Interrupt before/after preparation, submission, acceptance, publication, or completion persistence | Resume at every boundary; unknown append uses identical bytes; accepted append is not repeated. |
| Missing key, conflicting provider/input, corrupt outcome, or absent signed bytes after submission | Typed failure before another mutation; no replacement key/identity. |
| Returned authority, GI, entity endpoint/key, publication snapshot, log instance, or operational binding disagrees | Stop before unauthorized countersigning or success. |
| Registry READY but DNS/evidence absent | Continue bounded convergence or return resumable error; never ACTIVE success. |
| Invalid signature, policy denial, terminal rejection, or unsupported profile | Fail closed without broad retry or policy modification. |
| Cancellation/deadline after a mutation | Recovery preserved; no success and no implicit rollback/recreation. |
| Completed operation resumed | Same immutable identity, new public observation, no creation/preparation/append. |
| Setup entity excluded by application allowlist | Setup does not change the allowlist; returned manager's public verification still enforces it. |
| Local identity absent versus a matching supplied identity snapshot | Same setup checks; conflicting supplied snapshot fails. |

Future product tests additionally need organization-scoped named resolution,
concurrent first creation with conflicting keys, credential-scope enforcement,
restarts beyond request-key retention, missing-key recovery, and explicit
replacement generations. Those tests do not turn current display metadata into
a name-allocation protocol.
