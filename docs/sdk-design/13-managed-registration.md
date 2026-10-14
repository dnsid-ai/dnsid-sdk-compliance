# Managed Registration

This workflow composes [core](01-core-identity-manager.md),
[registry](05-transport-and-registry.md), [log binding](11-c2sp-tlog-binding.md), and
[configuration](12-configuration-loading.md) contracts to create a managed identity
and verify it publicly. The SDK supplies the registry client, recovery storage,
issuance adapters, entity-key retrieval, and retries. Consumers supply configuration,
credentials, and storage, not recovery callbacks. Bindings provide equivalent
idiomatic APIs and a local file-backed store; low-level APIs remain available.

## Scope and Ownership

Managed registration belongs above core and MUST NOT change `IdentityManager` or
public verification policy. It supports ordinary registry-controlled entity signing
and publication, not client-controlled publication or the separate Live workflow.
An unsupported authority/workflow returns a typed error retaining any creation facts.
Account eligibility, quotas, authorization, and domain allocation remain product
operations, not DNSid protocol requirements.

## Public Workflow

Names are language-neutral; native deadline, cancellation, and dependency parameters
are abbreviated.

```
RegisterManagedIdentity(name: string,
                        loaded: LoadedConfig,
                        credential,
                        store: ManagedRegistrationStore,
                        input?: AgentRegistrationInput) -> ManagedRegistrationResult
```

Normalize the name under [Name Normalization](#name-normalization). It selects
state within the registry/organization and supplies the request's `name` display
field; normalized explicit `input.name` must match. It is not a domain and is not
published in DNS or lifecycle entries.

The call returns only after the public completion checks in [Durable Setup](#durable-setup).
Registry `PROVISIONING`, `VERIFIED`, or `READY` is not protocol `ACTIVE`. The result
contains the retained registration/publication snapshot, configured `IdentityManager`,
`PublishedRecord`, and `LoggedStateEvidence` at the observation time.

Repeated calls resume the same operation. Completed operations get a new public
observation without creation, preparation, or append. Conflicting input or deployment
bindings fail rather than modify that operation.

### Name Normalization

SDKs and servers MUST apply these rules before hashing, state selection, or name
comparison, in this order:

1. Require valid Unicode scalar values.
2. Remove leading and trailing characters in Unicode `White_Space`: U+0009–U+000D,
   U+0020, U+0085, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F,
   U+205F, and U+3000.
3. Apply Unicode NFC and preserve case.
4. Reject remaining characters in Unicode general categories `Cc` (control) or
   `Cf` (format), including format-based zero-width and bidi controls.
5. Reject an empty result or more than 255 Unicode scalar values.

No other transformation is permitted. Domain normalization does not apply.

## Configuration and Trust

```
TYPE ManagedRegistrationConfig
  organizationId?: string    // stable registry account ID
  governanceId?: string      // expected accountable governance domain
  entityKeyUrl: string       // independently configured HTTPS bootstrap endpoint
END
```

`LoadedConfig.registration` is setup configuration, not core identity or counterparty
acceptance. Resolve organization ID and GI from configuration, matching saved bindings,
or [authenticated onboarding](05-transport-and-registry.md#account-binding-discovery)
before key generation. Organization ID must be known before selecting named state;
never search across organizations by name alone. Matching state can then supply GI.
Discovery compares all supplied/saved bindings, requires verified GI and entity-key
delegation, and fails if unavailable when needed. Configured bindings do not remove
the mandatory server-capability check. Persist resolved bindings before generation;
never overwrite a conflict.
`organizationId` is the exact `org_id` string supplied by authenticated onboarding,
including when configured in advance. SDKs MUST compare it byte-exact and MUST NOT
re-case or reformat it. It is not the GI or a credential hash.

`entityKeyUrl` remains configured because discovery does not return it. Validate GI
and endpoint before creation and against returned publication facts before countersigning.
Fetch JWKS under SDK transport/resource policies, select the profile's record-signing
key, and persist its public binding for issuance recovery.

Expectations do not select a registry root. Request GI/root through `input` using
[05's selector rules](05-transport-and-registry.md#resolution-and-validation), without
implicit translation or fallback. Normalize explicit `input.governanceDomain` and
compare it with expected GI before generation or creation; configured contradictions
fail before discovery. An omitted input sends name/public key only. GI need not be
an agent-domain suffix. Selector/expectation duplication remains an
[open question](08-open-questions.md#managed-registration-configuration).

Log trust requires explicit `logTrust` or an injected `LogRegistry`. Validate the
assigned log reference against that binding and its independent trust roots;
product adapters may impose additional log/root constraints. Service presets must
be explicit. Injected providers/networking remain caller-owned; SDK-managed networking
uses loaded transport settings throughout. Credentials stay outside deployment and
recovery data. Use an expiring setup credential; an expired credential can be
replaced by one for the same organization without changing the operation.

The registry is trusted to allocate the domain and use the accountable-entity key
to sign its publication. Entity-key pinning verifies that signer, not the registry's
choice of operational key. Before persisting completion, the SDK MUST verify that
the public key at signed `ku` has the provider's RFC 7638 thumbprint, with any change
from the initial key authorized by verified lifecycle history.

Overlay retained identity publication fields without changing transport, DNSSEC,
freshness, log trust, or acceptance policy. Supplied identity fields must agree with
saved state; authenticated reads/replays cannot silently replace it. Authorized
rotation changes are handled under [Completed-Operation Resume](#completed-operation-resume).

Final checks use an isolated, credential-free verifier with expected GI and the
independently bootstrapped entity pin, not application caches or local-key shortcuts.
This setup policy does not change the application's `trustedEntities`, pins, or
acceptance policy, or expose a new acceptance-free public verification API. The
returned manager's public `VerifyDomain`, including for its own domain, still enforces
the caller's policy.

## Durable Setup

1. Validate name, static configuration, and request shape. Resolve provider availability
   and settings under [12](12-configuration-loading.md#operational-key-source-selection)
   before discovery or mutations. Read authenticated onboarding, require the
   advertised server contract, resolve organization ID, lock/load named state,
   validate it, and resolve GI.
2. For new/unresolved creation, persist account/trust bindings, intent, extra creation
   inputs, and a stable key locator before generation. Recover/select the provider
   or generate one recoverable key there. Persist provider reference and initial
   public key before creation. Explicit `input.publicKeyJwk` must match that key;
   otherwise supply its public JWK. Private material never goes to the registry.
3. If creation is unresolved, reconstruct identical input and derive its replay key
   below. Send `registrationKey` as the `Idempotency-Key` header of `RegisterAgent`,
   retaining known facts even on error. Save immutable ID,
   domain, validated publication configuration, and returned OIDC issuer before
   discarding creation-only inputs. If identity is already known, read it and resume
   the next phase instead of creating again.
4. Check supported authority and expected bindings; wait for registry `VERIFIED` or
   `READY` within the call's deadline. A terminal state or `ERROR` stops the call
   without issuance and retains creation facts under [Registry States](#registry-states).
   Select and persist the trusted entity public key.
5. Recover and validate an existing accepted ISSUANCE through the log binding, without
   another preparation/append. Otherwise use the existing managed-issuance implementation
   for preparation, validation, countersigning, exact-byte persistence, submission,
   and acceptance binding. Send `issuanceKey` as the `Idempotency-Key` header of
   `SubmitPreparedEvent`; neither replay key is a JSON body member. Apply
   [Issuance Recovery](#issuance-recovery) before treating a submission failure as
   final. The registry owns the append; consumers need no activation or publication
   callback.
6. After acceptance, use `AwaitRegistryManagedPublication`. Its internal protocol-only
   confirmation is not a public counterparty-acceptance bypass.
7. Verify through public DNS/HTTPS/log resources: assigned domain/log instance,
   publication profile, expected GI/entity key, current operational key, protocol
   `ACTIVE`, and fresh complete lifecycle evidence via `VerifyLogEvidence`.
8. Persist completion and return.

## Organization and Creation Replay

Automatic managed recovery requires the permanent, organization-scoped server
contract in [05](05-transport-and-registry.md#registration-replay-and-recovery).
Before creation or automatic recovery, the SDK MUST obtain authenticated onboarding
and require `managed_registration` to contain `dnsid-managed-registration-v1`.
Missing or unsupported capability returns a typed unsupported-contract error before
mutations. The identifier covers the complete server contract, not only hash derivation;
[Server Requirements](../managed-registration-server-requirements.md) defines its gate.
An acknowledgement flag cannot establish support.

Derive keys with RFC 8785 JCS, UTF-8, SHA-256, and unpadded base64url. `initialKeyId`
is the initial public key's RFC 7638 thumbprint, not a provider alias or raw-JWK hash.

```
registrationKey = base64url-no-pad(SHA-256(JCS([
  "dnsid-managed-registration-v1", organizationId, name, initialKeyId
])))
issuanceKey = base64url-no-pad(SHA-256(JCS([
  "dnsid-managed-issuance-v1", registrationKey
])))
```

Keep the initial public binding through retries, credential replacement, and rotation;
never rederive from a rotated key. Stored copies of the derived keys are unnecessary.
Matching replicas derive the same keys, but complete creation input must also match.
While creation is unresolved, freeze selectors/metadata needed to reconstruct that
input. Once validated identity facts are durable, resume via identity reads.

This runnable check uses the RFC 8032 test-1 Ed25519 thumbprint. Compact UTF-8 JSON
is JCS for these string-only arrays.

```python
import base64, hashlib, json, unicodedata

WHITE_SPACE = "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"

def normalize_name(value):
    value = unicodedata.normalize("NFC", value.strip(WHITE_SPACE))
    if not value or len(value) > 255 or any(
        unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value
    ):
        raise ValueError("invalid registration name")
    return value

def digest(fields):
    data = json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()

fields = ["dnsid-managed-registration-v1", "11111111-1111-4111-8111-111111111111",
          "billing-agent", "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"]
key = digest(fields)
assert key == "2sWNUpI4tnAzJ3quPrT78uJNVdo96m4En3cZsggktcA"
assert digest(["dnsid-managed-issuance-v1", key]) == "pxQMSC0k-V9nn9qLqMRDczyUxyNyQE87LbGuK5SEWGw"
assert digest(fields[:2] + ["research-agent", fields[3]]) != key
assert normalize_name("\u00a0cafe\u0301\u3000") == "café"
assert normalize_name("café") == normalize_name("\u00a0cafe\u0301\u3000")
assert len(normalize_name("\U0001f600" * 255)) == 255
for invalid in ["", "a\u200bb", "a\u202eb", "\ufeffagent", "a\x00b", "\ud800", "\U0001f600" * 256]:
    try:
        normalize_name(invalid)
    except ValueError:
        pass
    else:
        raise AssertionError("accepted invalid name")
non_ascii = fields[:2] + [normalize_name("\u00a0cafe\u0301\u3000"), fields[3]]
assert digest(non_ascii) == "kBdivhIHZhZ_20_Ku_KnIVYE7x0iSw4K1ceQb2s6fxs"
```

## Issuance Recovery

A rejection is final for the submitted bytes, not proof that no ISSUANCE exists.
Before persisting a final submission failure, the SDK MUST recover lifecycle history
and verify any accepted ISSUANCE against the retained identity, initial public key,
entity binding, and log trust. If another replica's valid countersignature won, adopt
that verified entry and its inclusion evidence. Do not bind the losing bytes to the
winner's receipt or resubmit the accepted event.

If acceptance or an in-flight submission remains unresolved, retain recoverable state.
Missing or unavailable log evidence does not permit another issuance. Replace an
expired preparation only when durable server state establishes that it is reclaimable
under [11](11-c2sp-tlog-binding.md#submission-and-idempotency). Persist the
replacement before submission and keep the same issuance key. Unknown submission
outcomes always retry the exact persisted bytes.

## Registry States

Registry workflow states do not determine protocol `ACTIVE` state.

| Registry states | Named setup behavior |
|---|---|
| `PENDING`, `PROVISIONING`, `VERIFICATION` | Retain identity and wait for verification; replacement is forbidden. |
| `VERIFIED`, `READY` | Resume issuance/publication checks; public evidence is required for completion. |
| `ERROR` | Return a resumable workflow error with retained facts; server recovery may resume the same identity. Replacement is forbidden. |
| `REJECTED`, `CANCELLED`, `REVOKED`, `RETIRED` | Terminal; resume returns a terminal error with history retained. Explicit fresh-key replacement is permitted. |

## Completed-Operation Resume

Verify historical issuance against retained public bindings and hash/inclusion;
the original private key is not needed. Validate the provider's current signing key
and observed signed TXT/`ku` against fresh lifecycle history before configuring the
manager. Authorized rotation may change key and URL while preserving the immutable
identity and historical creation snapshot. Follow profile URL constraints; never
synthesize a new URL or use a retained old endpoint as current-key fallback.
Unexplained changes fail with a binding error. Registration only observes completed
rotations; pending rotations use the existing rotation recovery coordinator.

Unresolved creation requires matching frozen input. After creation, validate explicit
assertions against retained identity facts and reject changes to creation-only
selectors/metadata. A retained semantic fingerprint may support comparisons without retaining
the full request. If no comparable fingerprint remains, reject supplied creation-only
selectors/metadata rather than guessing; callers may omit input on resume. Unfinished
issuance still requires the initial provider/key binding.

Terminal identities return typed errors with history retained. Replacement requires
explicit new state after a confirmed terminal state and `input.replaces` equal to
the previous immutable identity ID, plus a fresh key, never an
initial or rotated key of the previous named identity. Preserve its history; the
new key derives a new request key without a generation nonce. The server's
[replacement contract](05-transport-and-registry.md#named-managed-registration)
assigns a new immutable ID/domain/log stream while old replays remain old. Missing
state/key material or a timeout does not authorize replacement or rotation.

## Storage and Recovery

`ManagedRegistrationStore` durably creates, loads, and transitions named operations,
including the portable issuance state below. `FileRegistrationStore(directory)` holds
multiple identities addressed by validated `(registry URL, organization ID, name)`.
The named slot selects the current operation; replacement archives the previous
operation by immutable ID rather than overwriting it. Persist and check the tuple on
load. Use a digest or safe encoding, never raw names as filesystem paths;
configurations, keys, and locks are tenant-isolated.

Exclusive access covers loading through return/error, including in-process and
cross-process contention. Competing invocations receive a typed busy error.
Deadline/cancellation includes lock acquisition. Persist recoverable progress before
subsequent mutations. An interrupted invocation resumes from the last durable
state rather than relying on cancellation cleanup.

File storage MUST provide owner-only access, atomic durable updates (including
required directory durability or documented platform prerequisites), and an
interrupted-process lock recovery policy. Validate missing, corrupt, conflicting,
or partial artifacts before further mutations. Persist key intent/locator before
generation; recover that same key or report ambiguous initialization, never silently
generate another. Distinguish empty new state from incomplete state.

### Portable Recovery Document

Stores MUST support import/export of recovery documents across SDK bindings. The
storage layout is implementation-owned; the document format is UTF-8 RFC 8785
canonical JSON. Reject duplicate members and invalid Unicode. `schemaVersion` is
`1`; unsupported versions or phases fail without rewriting state and include upgrade
guidance. Preserve unknown members on rewrite. Migrations MUST preserve bindings,
exact pending bytes, and accepted evidence.

The following are document member names, not binding-native field names. Optional
members are omitted until known. Counters and indexes are nonnegative safe integers;
byte strings use unpadded base64url and timestamps use RFC 3339 UTC strings.

| Member | Value |
|---|---|
| `schemaVersion` | `1`. |
| `phase` | `key-pending`, `creation-pending`, `identity-known`, `issuance-accepted`, or `complete`. |
| `registryUrl`, `organizationId`, `name` | Required named-operation tuple. |
| `governanceId`, `entityKeyUrl` | Resolved expected bindings. |
| `logTrust` | Configured trust data using [12's `LogTrust`](12-configuration-loading.md#loaded-configuration) member names; injected dependencies must be supplied again and match the saved log/entity bindings. |
| `keySource` | Non-secret [12 `KeySource`](12-configuration-loading.md#loaded-configuration) data, including the persisted generation locator or immutable key reference. No private material. |
| `currentKeySource` | Same shape as `keySource`; current provider reference after verified rotation, when different. |
| `initialPublicKey` | Initial public JWK, retained once known. |
| `creationInput` | Unresolved request using [05's wire field names](05-transport-and-registry.md#agentregistrationinput); omit duplicate `name`, `public_key`, and `replaces`, reconstructed from the corresponding document members. |
| `identityId`, `domain` | Immutable creation result. |
| `publicationConfig` | Creation snapshot using [05's wire field names](05-transport-and-registry.md#publicationconfig). |
| `oidcIssuerUrl`, `entityPublicKey` | Returned issuer when present and trusted entity public JWK when selected. |
| `creationFingerprint` | Optional SHA-256, unpadded base64url, of canonical JSON for the normalized complete creation request. |
| `replaces` | Previous immutable identity ID for an explicit replacement. |
| `issuance` | Object with `preparedBytes`, `entryBytes`, `entryHash`, `state`, `errorCode`, `logReference`, and `index`, as known. `state` uses [11's submission states](11-c2sp-tlog-binding.md#submission-and-idempotency); `entryHash` is the SHA-256 lowercase hex digest of exact completed bytes. Accepted `logReference`/`index` locate the entry for verified retrieval. |

An injected key provider need not have a portable implementation. Its public-key
binding remains portable; resume requires a provider for that same key. Importing
recovery state does not transfer private keys or credentials. Stores validate required
facts for the recorded phase before any mutation.

Retain only facts needed by the current phase. Once known, identity and public-key
bindings remain in every later phase:

| Phase | Durable facts |
|---|---|
| All | Schema version, registry/organization/name, resolved account/trust bindings, key intent/locator, replacement ID if any. |
| `key-pending` | Creation inputs needed after generation; initial public key and provider reference if already known. |
| `creation-pending` | Initial public key and provider reference; selectors/metadata to reconstruct identical input, without duplicate name/public key or replay keys. |
| `identity-known` | Immutable ID/domain, validated creation-publication snapshot, returned issuer when present, optional creation fingerprint; entity public key once selected and any exact prepared/completed issuance bytes and outcomes. |
| `issuance-accepted`, `complete` | Initial public and trusted entity bindings, bound entry hash/reference and verified acceptance/inclusion facts sufficient to retrieve the historical entry; `complete` additionally records that public readiness was verified. |

Remove creation-only inputs atomically with validated creation facts. Remove exact
issuance bytes only after durable acceptance and verified inclusion, with enough
retained facts to retrieve/verify the same entry. Until then, unknown submission
retries use identical completed bytes and the same derived key. Accepted issuance
is not resubmitted; final failure requires [Issuance Recovery](#issuance-recovery).
Failed historical retrieval returns an error, never permission to issue again.

Recovery data stays separate from shared deployment and private-key storage; it
contains no credentials or private JWKs. Missing private material or an unexplained
provider/key mismatch fails with recovery guidance. Document backup requirements
and the limits of ephemeral/container-local storage. Replacement preserves prior
operations rather than overwriting them; custom stores may reuse existing interfaces.

## Retry, Deadlines, and Errors

The SDK schedules retries within one finite deadline/cancellation budget, with a
binding-documented finite default. The budget covers lock acquisition, network
calls, verification, storage, and any awaited progress callbacks, not just retry delays.
Storage MUST prevent an unresolved write from committing after lock release;
reconcile indeterminate outcomes before further mutations.
Cancellation preserves recovery state and does not undo creation. Retry classified
transient failures, unknown outcomes with the same input/bytes, and narrowly
classified missing DNS resources during propagation.
Signature, binding, unsupported-profile, policy, and terminal registry failures stop;
resource/deadline limits return recoverable errors.

Errors preserve structured registry/binding categories and report failed phase,
known immutable identity, workflow/convergence state, and resumability. Distinguish
missing-key/conflicting-state errors from propagation delays. Do not expose credentials,
private keys, or acceptance policy.

## Validation Scenarios

Bindings MUST cover these observable cases. Provider configuration checks belong to
[12](12-configuration-loading.md#validation-scenarios); server concurrency/persistence
checks belong to [Server Requirements](../managed-registration-server-requirements.md#acceptance-checks).

| Cases | Required result |
|---|---|
| Fresh setup; equivalent file/environment/code inputs; absent versus matching supplied identity | Same bindings and public completion checks; conflicting identity fails. |
| Invalid name/endpoint/input.name; configured GI contradiction | Fail before discovery or mutations; all bindings apply identical name normalization and hash vectors. |
| Missing/unsupported server contract | Fail before creation/recovery mutations. |
| Cross-binding recovery import; unknown members/version/phase | Resume the same operation; preserve unknown members; unsupported version/phase fails without rewriting. |
| Missing account bindings; discovery unavailable, unverified, or conflicting | Resolve organization before state selection; persist only matching verified bindings before generation, otherwise fail. |
| Same name across organizations/registries; traversal-like names; concurrent local calls | Isolated safe paths/keys/locks; one operation, typed busy error for competitors. |
| Matching replicas or new state opening an issued identity | Same replay keys/immutable identity; recover existing issuance without another preparation/append. |
| Interrupted generation; missing/corrupt/conflicting artifacts | Recover original key or fail before further mutation; no replacement generation. |
| Credential replacement; wrong credential organization; occupied name with another key | Same-org resume succeeds; server rejects conflicts before allocation without disclosure. |
| Lost creation response; changed optional input; long interruption/clock change | Identical reconstructed replay or conflict; no expiration or replacement. |
| Known identity with failed detail read; conflicting replay; changed/missing saved issuer | Preserve facts; resume authenticated reads, not creation; authoritative binding loss/change fails. |
| Interrupt each preparation/submission/acceptance/publication/completion boundary | Resume safely; unknown submission uses exact bytes, accepted issuance is not repeated. |
| Reclaimable expired preparation; competing nondeterministic countersignatures | Re-prepare only with durable reclaimability; recover the winner's verified issuance before final failure, never bind its receipt to losing bytes. |
| Registry ERROR or a terminal registry state | ERROR retains a resumable identity; only the four terminal states permit explicit replacement. |
| Crash during compaction; unresolved bytes missing; completed entry retrieval | Preserve pending data or sufficient verified next-phase facts; otherwise fail without reissuing. |
| Wrong authority, GI, endpoint/key, publication profile, log instance, or operational binding | Stop before unauthorized countersigning or success. |
| Registry READY without public evidence; stalled observer; deadline/cancellation after mutation or during storage | Bounded return/resumable error; retain facts, prevent late writes after lock release, reconcile unknown outcomes; no success, rollback, or recreation. |
| Invalid signature/profile, policy denial, or terminal rejection | Fail closed without broad retry or policy changes. |
| Completed resume; authorized key/ku rotation; old private key unavailable | New public observation of same identity, verified current key/URL, historical issuance intact. |
| Unexplained change or pending rotation | Binding error or existing rotation recovery guidance; no rotation by setup or old-URL fallback. |
| Terminal resume; explicit fresh-key replacement; reuse of historical keys | Retain history; replacement only after confirmed terminal state and server-enforced fresh key. |
| Setup entity excluded by application allowlist | Setup does not widen policy; returned manager's public verification still denies it. |
