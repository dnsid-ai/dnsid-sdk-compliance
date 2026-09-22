# C2SP Transparency Log Binding

This document incorporates the breaking pre-1.0 correction to `c2sp-tlog`:
logical event identity and predecessor chaining exclude signatures. The method
name, envelope `v:1`, and bundle `@v1` remain unchanged; there is no second
method or old-format fallback. Deploy corrected readers, writers, monitors, and
bundle producers together and retire incompatible clients. Preserve existing
streams whose complete histories verify under the corrected contract, including
already-conforming public ISSUANCE-only histories; no re-signing or reference
change is needed for those histories. Terminal histories remain terminal.
Nonconforming histories cannot be continued under these rules: retain their
bytes/proofs as historical evidence and use fresh streams for new conforming
histories. Inventory histories and reconcile outstanding submissions before
cutover; never replace bytes that may already have been appended. Do not run
incompatible and corrected writers concurrently on the same stream or rely on
old readers rejecting the corrected format.

This document defines the language-agnostic SDK design for the DNSid
`c2sp-tlog` lifecycle-log binding. It specializes the shared abstractions in
[`06-log-bindings.md`](06-log-bindings.md) and does not change the shared
`LogEvent` model.

The authoritative DNSid wire contract is the
C2SP TLog Method Specification at revision `d5a65d06f76eff4db81e50f8767a600d2ca7fc2a` (`log-method-extensions/c2sp-tlog-log-method.md` in the DNSid specification repository).
This immutable source includes reference syntax, event mappings, and the complete
bundle schema/signature/freshness rules. The SDK mapping
below does not replace that method specification. The focused corrected-contract
checks are documented under [conformance](conformance/README.md#c2sp-event-identity).
Earlier signed `fixtures/c2sp-*.json` and cross-SDK matrix results predate this
correction and are not evidence of compliance with it; their replacement and
full SDK integration validation are required before release. Implementations MUST also follow the exact C2SP
specification versions pinned by the DNSid Log Method Registry — those base
specifications are public at [c2sp.org](https://c2sp.org). The SDK design below
defines how those protocol requirements are exposed safely and consistently
across language bindings.

## Responsibilities

The binding answers:

> How does an SDK prepare, sign, submit, retrieve, and verify DNSid lifecycle
> events carried by a C2SP tiled transparency log?

The binding owns:

- parsing and canonicalizing `c2sp-tlog` references;
- mapping shared `LogEvent` values to C2SP DNSid event envelopes;
- signed method context and lifecycle-stream chain metadata;
- split lifecycle signing without sharing private keys;
- canonical entry serialization and safe append submission;
- C2SP checkpoints, tiles, entry bundles, inclusion proofs, policies, and
  witness cosignatures; and
- complete-stream verification and reconstruction in C2SP log-index order.

It does not own DNS publication, registry business state, C2SP log or witness
private keys, or application-layer signatures.

## Standards and Versioning

The exact dependency pins from method §1.1 are:

- [tlog-checkpoint@v1.0.0](https://c2sp.org/tlog-checkpoint@v1.0.0)
- [tlog-tiles@v0.1.0](https://c2sp.org/tlog-tiles@v0.1.0)
- [tlog-proof at `ab17a74116563005f908b9167e6421cc929a5c2b`](https://github.com/C2SP/C2SP/blob/ab17a74116563005f908b9167e6421cc929a5c2b/tlog-proof.md)
- [tlog-policy at `1896a5aea5559b3203d275d0206d872f59348cf5`](https://github.com/C2SP/C2SP/blob/1896a5aea5559b3203d275d0206d872f59348cf5/tlog-policy.md)
- [tlog-witness@v1.0.0](https://c2sp.org/tlog-witness@v1.0.0)
- [tlog-cosignature@v1.0.1](https://c2sp.org/tlog-cosignature@v1.0.1)
- [tlog-mirror at `d0fe789122c75b903bfc1680b0b8b8dc570f0db3`](https://github.com/C2SP/C2SP/blob/d0fe789122c75b903bfc1680b0b8b8dc570f0db3/tlog-mirror.md)
- [signed-note@v1.0.0](https://c2sp.org/signed-note@v1.0.0)

Production SDK releases MUST identify the exact versions they implement. They
MUST NOT silently reinterpret entries, checkpoints, proofs, policies, or
cosignatures according to a different C2SP revision. Compatibility with a later
revision is an explicit policy decision and requires interoperability tests.

## Reference and Binding Context

The method name is exactly `c2sp-tlog`. Its reference has this form:

```text
c2sp-tlog:<scope>:<log-prefix>#<stream-id>
```

The parser follows the method specification exactly, including splitting the
remainder at the final raw `#`, canonical URL validation, scope validation, and
checkpoint-origin derivation. It returns a bound reference:

```
TYPE C2spTlogReference
  scope: string              // public, testnet, or private-*
  logPrefix: URL
  logOrigin: string          // checkpoint origin derived from logPrefix
  streamId: string
  lr: string                 // complete canonical reference, without @index
END
```

For version 1, `streamId` identifies one identity instance. Writers generate at
least 128 bits of cryptographically secure randomness and encode it as unpadded
base64url. The bare FQDN is invalid because it cannot distinguish a replacement
after revocation or retirement. The binding MUST still compare every event's
signed `fqdn`, `stream_id`, and complete `lr` with the identity instance being
verified; `streamId` is not an authorization boundary.

The opaque stream ID is protocol machinery, not a human-facing discovery key.
Deployments SHOULD expose a stable FQDN-based lookup for the current portable
bundle, such as `GET /streams/<fqdn>`. For the standard SDK bundle source, the
URL is exactly `{log-prefix}/streams/{url-path-escaped-normalized-fqdn}?format=bundle`,
derived only after `sg` authenticates the complete `lr`. It is never derived
from registry configuration or an unauthenticated record. Replacing a
terminated identity changes the signed bundle's `lr`, but not that lookup URL.
The resolver selects the current identity instance from authoritative state and
MUST NOT merge events from an older stream that reused the same FQDN. Historical
lookup by opaque stream ID is deployment-specific.

A `C2spTlogBinding` is constructed with one bound `C2spTlogReference`. Its
canonicalization, preparation, append, and read operations MUST reject an event
or entry whose signed context does not match that reference.

A final event reference appends `@<index>` to the complete bound reference:

```text
c2sp-tlog:<scope>:<log-prefix>#<stream-id>@<index>
```

`index` is a canonical non-negative decimal integer with no leading zeroes
unless it is exactly `0`. Parsing a final reference removes the final `@index`
only after the method reference and stream fragment have been parsed.

## Shared Interface Mapping

`C2spTlogBinding` implements the shared `LogReader` contract. It implements the
shared `Log` write contract only for events whose complete signed method
metadata can be derived internally without ambiguity.

For ISSUANCE in every scope, the binding can derive `seq=0`, so the generic
`Canonical(event)` and `WriteEvent(event)` flow MAY be supported. For later
events, the previous logical event ID, sequence, and state hash are required
before signing. Generic `Canonical(event)` and `WriteEvent(event)` MUST fail
before signing or appending unless the binding has an authoritative,
concurrency-safe way to derive and reserve that metadata. Callers otherwise use
the prepared-event API below.

The binding MUST NOT add C2SP context, chain, checkpoint, proof, or receipt
fields to the shared `LogEvent` type. On verified reads it returns ordinary
`LogEvent` values in increasing C2SP log-index order.

## Event Envelope

A complete entry is:

```text
JCS(event including top-level sigs)
```

Every version 1 envelope contains:

| Field | Requirement |
|---|---|
| `v` | Integer `1`. |
| `kind` | String `dnsid.lifecycle`. |
| `type` | Supported DNSid lifecycle event type. |
| `fqdn` | Normalized DNSid FQDN. |
| `ts` | Whole Unix epoch seconds represented as a safe JSON integer. |
| `sigs` | Top-level lifecycle-signature object; required on a complete entry. |

The binding maps event-specific lifecycle fields according to the DNSid method
specification. Version 1 supports `ISSUANCE`, `KEY_ROTATION`, `REVOCATION`,
`RETIREMENT`, `MIGRATION`, and `DELEGATION`. An unsupported event type fails
preparation and direct parsing. During a global-log scan, an unrelated,
unsupported, malformed, cross-context, or signature-invalid candidate is
ignored when it cannot be authenticated and bound to the selected FQDN's
lifecycle. An authenticated event with an invalid chain or lifecycle transition
is fatal as described under Stream Completeness and Logged State.

Complete entry bytes MUST be canonical JCS, contain no repeated JSON member
names, and be between 1 and 65,535 bytes inclusive. Parsers MUST reject alternate
JSON encodings even when they decode to the same value.

Unknown signed envelope fields MUST be preserved during prepared-event parsing,
canonicalization, signature collection, and verification. They remain covered
by lifecycle signatures but have no SDK semantics unless a supported extension
defines them. Converting a prepared envelope to `LogEvent` and back is therefore
not a safe way to collect another signature.

## Signed Context and Stream Chain

In every scope, every event includes these signed fields:

| Field | Required value |
|---|---|
| `method` | `c2sp-tlog` |
| `log_origin` | Origin derived from the bound `log-prefix`. |
| `stream_id` | Stream ID from the bound reference. |
| `lr` | Complete bound `c2sp-tlog` reference without an entry index. |

Define logical event identity independently of complete entry bytes:

```text
signedBytes = JCS(event without top-level sigs)
eventId = base64url-no-pad(SHA-256(ASCII("dnsid-c2sp-event-v1") || 0x00 || signedBytes))
```

The separator is one zero byte, with no trailing newline. `eventId` is derived
metadata; top-level `event_id` is prohibited in signed envelopes. Hashes use
canonical unpadded base64url of exactly 32 bytes. Unknown signed fields remain
hashed. Different signatures can change complete-entry leaf hashes without
changing event identity; different signed payloads remain distinct even if
their requested effect is the same. Equal IDs with unequal signed bytes fail
as an integrity error. Signers still sign `signedBytes`, not the ID.

Stream-chain rules apply in every scope:

| Event position | Required fields | Prohibited fields |
|---|---|---|
| First ISSUANCE or inbound MIGRATION | `seq=0` | `prev_event_id`, `prev_state_hash`, `prev_index`, `prev_leaf_hash` |
| Every later applied event | `seq`, `prev_event_id`, `prev_state_hash` | `prev_index`, `prev_leaf_hash` |

For later events, `seq` is the previous logical event's sequence plus one and
`prev_event_id` is its derived ID. `prev_state_hash` is:

```text
base64url-no-pad(SHA-256(ASCII("dnsid-c2sp-state-v1") || JCS(previous computed state)))
```

The existing state hash has no separator or trailing newline; only the event-ID
hash above includes the zero-byte separator.

Exact entry bytes, leaf hashes, indexes, and proofs remain inclusion evidence,
not lifecycle identity. Never normalize signatures before Merkle verification.

The version 1 computed state is exactly this JSON object, with the shown member
names and uppercase status values:

```json
{
  "fqdn": "agent.example",
  "status": "ACTIVE",
  "entity_thumb": "<RFC 7638 thumbprint>",
  "operational_thumb": "<RFC 7638 thumbprint>"
}
```

ISSUANCE initializes `ACTIVE` state. Verified inbound MIGRATION imports the
previous history's FQDN, governance identity, entity key, active operational
key, and `ACTIVE` state before computing the destination genesis state.
KEY_ROTATION replaces `operational_thumb`. REVOCATION and RETIREMENT replace
`status` with `REVOKED` and `RETIRED`, respectively. DELEGATION leaves this
state unchanged. An outbound MIGRATION is not valid in a C2SP stream; migration
out is represented only by the destination method's inbound event. SDKs MUST
hash this exact state rather than a language-native object or the lifecycle
event itself.

```
TYPE C2spChain
  sequence: integer
  previousEventId?: string
  previousStateHash?: string
END
```

The binding MUST recompute and compare every chain value. Merely checking that a
hash field is non-empty is insufficient. Chain fields help detect missing or
reordered middle events but do not prove that the verifier has seen the latest
event; fresh complete logged-state verification still requires completeness and
freshness, and never replaces a fresh protocol-status response.

## Lifecycle Signatures

All lifecycle signatures cover exactly:

```text
JCS(event after removing the top-level sigs member)
```

Adding or replacing a signature MUST NOT change those signed bytes.

| Event | Envelope signatures | SDK signer roles |
|---|---|---|
| `ISSUANCE` | `sigs.ae`, `sigs.op` | `Entity`, `OperationalCountersignature` |
| `KEY_ROTATION` | `sigs.prev_op`, `sigs.new_op` | `PreviousOperational`, binding-owned `NewOperational` |
| `REVOCATION` | `sigs.ae` | `Entity` |
| `RETIREMENT` | `sigs.ae` | `Entity` |
| `MIGRATION` | `sigs.ae` | `Entity` |
| `DELEGATION` | `sigs.ae` | `Entity` |

```
ENUM C2spSignerRole
  Entity
  OperationalCountersignature
  PreviousOperational
  NewOperational
END
```

The first three roles reuse their shared DNSid meanings. `NewOperational` is
owned by this binding and is used only for the new-key proof of possession on
`KEY_ROTATION`.

`sigs.prev_op` is the base DNSid rotation authorization. `sigs.new_op` is an
additional C2SP-binding proof of possession and MUST NOT replace or weaken the
previous-key authorization.

A completed `sigs` object contains exactly the required roles; each signature
object contains exactly `kid` and unpadded base64url `sig`. Every required role
must verify before a new payload is considered authenticated. Missing/invalid
countersignatures cannot create a contradiction. Both valid high-S and low-S
ES256 signatures are accepted; signature canonicalization is not the replay
boundary.
Before signing or verification, the binding validates that:

- each key is a public signing JWK with a supported `alg` and non-empty `kid`;
- each `kid` selects the key required for its role;
- embedded key material and declared thumbprints agree;
- current accountable-entity and operational keys are distinct by RFC 7638
  thumbprint; and
- every signature verifies over the same prepared signed bytes.

DNSid lifecycle signatures are distinct from C2SP checkpoint signatures and
witness cosignatures. Log-infrastructure signatures remain outside the DNSid
event envelope.

## Prepared Event Model

The method-specific prepared form preserves signed fields that do not belong in
the shared `LogEvent`:

```
TYPE PreparedC2spTlogEvent
  reference: C2spTlogReference
  envelope: JSON object       // includes all known and unknown signed fields;
                              // sigs may be absent or partial before completion
  signedBytes: bytes          // JCS(envelope without top-level sigs)
  eventId: string             // locally derived; unchanged by adding signatures
  requiredSignatures: []C2spSignerRole
  predecessorReservation?: C2spPredecessorReservation
END

TYPE C2spPredecessorReservation
  streamRevision: string    // opaque compare-and-swap value
  sequence: integer
  previousEventId: string
  previousStateHash: string
END
```

`PreparedC2spTlogEvent` is immutable apart from adding a role signature. An SDK
MAY model it functionally rather than exposing mutable state. It MUST NOT expose
a way to alter signed fields while retaining existing signatures.

Language bindings provide equivalent operations:

```
INTERFACE C2spTlogBinding
  ReservePredecessor(expectedOperationalThumbprint?: string) -> C2spPredecessorReservation
  PrepareEvent(event: LogEvent,
               reservation?: C2spPredecessorReservation) -> PreparedC2spTlogEvent
  ParsePreparedEvent(bytes: bytes,
                     reference: C2spTlogReference) -> PreparedC2spTlogEvent
  SignPreparedEvent(prepared: PreparedC2spTlogEvent,
                    role: C2spSignerRole,
                    keyProvider: KeyProvider) -> PreparedC2spTlogEvent
  EntryBytes(prepared: PreparedC2spTlogEvent) -> bytes
  WritePreparedEvent(prepared: PreparedC2spTlogEvent,
                     idempotencyKey: string) -> LogRef
END
```

These names are illustrative; language bindings use idiomatic naming while
preserving the operations and invariants.

`ReservePredecessor` reads verified authoritative stream state and acquires a
single-use compare-and-swap reservation for that revision. The optional
thumbprint makes key-rotation staleness explicit. Deployments may perform this
operation in their registry coordinator rather than inside a local SDK object,
but they preserve the same result and precondition.

### PrepareEvent

Preparation:

1. validates the shared lifecycle event and supported type;
2. maps it to the version 1 C2SP envelope;
3. derives and validates signed reference context;
4. for genesis, derives `seq=0`; otherwise requires an authoritative,
   concurrency-safe predecessor reservation and derives the stream-chain fields
   from it;
5. removes any caller-supplied signatures unless they can be proven to cover the
   resulting envelope;
6. computes `signedBytes` and `eventId`; and
7. reports all base and binding-owned required signer roles.

Preparation does not append and does not require any private key.
Caller-supplied chain values without an authoritative reservation are rejected.
The reservation is method-owned coordination state, not signed wire content.
A parsed envelope alone does not recreate a reservation. Before append, the
binding must either retain the reservation or resolve the same durable
reservation from the idempotency record; otherwise it fails before writing.

### ParsePreparedEvent

Prepared bytes received from another process are untrusted. Parsing MUST:

- reject duplicate members, malformed JSON, unsupported envelope versions and
  event types, unsafe integers, malformed keys, malformed signatures, and
  unsupported signature-envelope shapes;
- require the received representation to be canonical JCS;
- validate the complete bound context and chain shape;
- preserve unknown signed fields;
- reconstruct `signedBytes` by removing only the top-level `sigs`, and derive
  `eventId` locally rather than trusting server-supplied metadata; and
- validate every existing signature before allowing another role to sign.

Validating an existing signature on a later lifecycle event can require the
accepted entity or operational key from prior stream state. The binding MUST
obtain that key from already verified state or require it as explicit trusted
verification context. A language binding MAY therefore make signing
asynchronous or accept a cancellation/network context; it MUST NOT treat a
`kid` in the prepared envelope as a trust anchor.

A signer MUST NOT sign a server-supplied `signedBytes` field without parsing the
envelope and independently reproducing those bytes.

### SignPreparedEvent

Signing validates that the supplied provider's selected public key matches the
event key required for the role by RFC 7638 thumbprint. It then signs
`prepared.signedBytes` and adds only the requested signature object. It MUST
reject an unsupported role, missing role key, key mismatch, algorithm mismatch,
or attempt to replace a different valid signature without explicit caller
authorization.

An accountable-entity process may hold only the entity provider. An operational
process may hold only the operational provider. Neither process needs access to
the other's private key.

### EntryBytes

Serialization requires every signature listed in `requiredSignatures`, verifies
all of them, inserts the complete `sigs` object, and returns exact canonical JCS
entry bytes. It does not append.

### WritePreparedEvent

This is a safe high-level append operation. Before append it MUST validate:

- canonical complete entry encoding and size;
- bound method, origin, stream, reference, and FQDN;
- supported event type and all lifecycle fields;
- required key metadata, thumbprints, algorithms, signer roles, and signatures;
- exact stream-chain values against authoritative prior state; and
- the predecessor reservation's compare-and-swap precondition.

It then appends the exact validated entry bytes without changing or
reserializing signed content. A raw appender that skips lifecycle authorization
validation is an internal transport primitive, not the public safe write API.
If another event advanced the stream after preparation, append fails with a
terminal stale-preparation result before any bytes enter the log.

## Split ISSUANCE Flow

Delegated issuance commonly places the accountable-entity key at a registry or
governance service and the operational key at the agent. The SDK flow is:

1. The operational side supplies its public `ku` key and requested identity
   context to the authenticated accountable-entity service.
2. The service validates the request, constructs ISSUANCE with `gi`, historical
   `ek` and `ku` public material, public signed context, and `seq=0`.
3. The service prepares the C2SP envelope and adds `sigs.ae`.
4. The operational SDK parses the partially signed prepared envelope as
   untrusted input. It validates FQDN, `gi`, `ek`, its own `ku`, `lr`, origin,
   stream, `seq=0`, canonical encoding, and `sigs.ae`.
5. The operational SDK adds `sigs.op` over the identical `signedBytes`.
6. The fully signed canonical entry is submitted with a durable idempotency key.
7. The service revalidates both signatures and all context, persists the exact
   entry bytes, and appends them unchanged.
8. The service returns the assigned log index, final `LogRef`, and any available
   acceptance or proof status.

The initial challenge or registration signature is not a substitute for
`sigs.op`; it generally covers different bytes. The service MUST NOT reuse the
accountable-entity key as the operational key, synthesize `sigs.op`, or require
custody of the operational private key.

## Split KEY_ROTATION Flow

A managed operational-key rotation keeps both private keys at the agent and uses
the registry only to prepare authoritative stream metadata, publish the managed
`ku` endpoint, and append the completed event:

1. The agent generates one pending new operational key and retains the current
   previous key.
2. The agent requests preparation with the previous-key thumbprint, new public
   JWK, and a durable idempotency key.
3. The registry verifies that the identity is active and managed, both keys are
   valid and distinct, the previous thumbprint matches both registry state and
   verified lifecycle history, and no competing rotation occupies that
   previous-key slot.
4. The registry prepares `KEY_ROTATION` with authoritative stream-chain metadata
   and persists the exact unsigned canonical envelope plus both key bindings.
5. The SDK parses the envelope as untrusted input and independently verifies its
   FQDN, log context, chain, timestamp, previous thumbprint, and complete new JWK.
6. The SDK adds `sigs.prev_op` with the previous key and `sigs.new_op` with the
   pending new key over the identical `signedBytes`.
7. The registry revalidates canonical encoding, preparation continuity, both
   signatures, current protocol status, prior logged state, and the persisted
   key bindings.
8. The registry publishes the new key as the sole live `ku` key and advances
   its internal active-key record with an expected-previous-key compare-and-swap.
9. The registry appends the exact persisted completed bytes unchanged.
10. After publication and append converge, the agent activates the new private
    key for application signing and supersedes the previous key.

Steps 8 and 9 cannot be one atomic transaction. The durable submission record
therefore remains retryable after process failure, and the registry reconciles
stale submitting or indeterminate records without relying on the caller. Until
the append completes, current continuity verification fails closed. The agent
MUST persist the exact completed entry and pause application signing before
submission can cause publication. It remains paused until acceptance is bound to
those bytes and local activation is durably recorded. The SDK requires durable
persistence and signing-control dependencies and resumes from their recorded
state as defined by the core
[managed rotation recovery contract](01-core-identity-manager.md#managed-rotation-recovery-contract).
Loss or suspected compromise of the previous key uses revocation and reissuance,
never an administrative signature substitute.

## Submission and Idempotency

C2SP standardizes verification resources, not DNSid event submission. A
deployment-specific submission adapter MAY be exposed through `RegistryClient`
or another operator client, but its SDK contract is typed and explicit:

```
PrepareIssuance(domain, idempotencyKey) -> PreparedRegistryEvent
PrepareKeyRotation(domain, previousKeyId, newPublicKey, idempotencyKey) -> PreparedRegistryEvent
SubmitPreparedEvent(domain, entryBytes, idempotencyKey) -> SubmissionResult
```

The common registry client does not expose prepared `REVOCATION` or
`RETIREMENT`: a managed registry owns those status transitions, entity
signatures, and append retries, and the SDK invokes its lifecycle mutation
instead. Operator-specific clients may expose prepared later-event APIs when a
client-held entity key makes split signing necessary, but those APIs are not
part of the portable `RegistryClient` contract. Every event after genesis still
uses an authoritative predecessor reservation and exact-byte submission
contract.

`PreparedRegistryEvent` is the untrusted transport container defined by the
registry design: exact `entryBytes` plus the exact bound `logReference`. The SDK
passes both to `ParsePreparedEvent`; only the resulting validated
`PreparedC2spTlogEvent` may be countersigned. This type boundary prevents an
authenticated registry response from being mistaken for a binding-validated
event.

For the current registry adapter, `PrepareIssuance` sends an empty request body.
The service derives the operational public key from the authenticated identity's
previously registered key and returns exact partially signed canonical entry
bytes plus the required bound log reference. The SDK treats that response as
untrusted and verifies it against the expected domain, governance identity,
accountable-entity key, local operational key, log context, and `seq=0` before
countersigning. Other operator APIs may gather issuance inputs differently, but
MUST expose the same prepared-event validation boundary rather than asking the
SDK to trust server-supplied signed bytes.

The service authenticates and authorizes preparation and submission. Submission
accepts already prepared canonical entry bytes and MUST NOT add, remove, or
rewrite signed fields.

The idempotency mapping is durable:

- the same identity, idempotency key, and entry-byte hash returns the original
  submission state or accepted result;
- reuse of the key with different bytes is rejected; and
- retries after timeout or process restart reuse the identical persisted bytes.

Logical event deduplication is not submission idempotency. An equal `eventId`
never permits replacing durable bytes with a different signature or accepting
a receipt whose exact entry hash does not match the submitted bytes.

The adapter preserves structured failure semantics. A non-2xx response becomes
a typed `indeterminate`/`rejected` `SubmissionResult` or a typed
`RegistrySubmissionError`, never a generic failure or a successful result. Both
representations retain the registry error code and whether the same bytes are
retryable. Busy, indeterminate, timeout, and unknown transport outcomes retry
only the identical persisted entry with the same idempotency key. Validation,
preparation mismatch, and idempotency mismatch failures are terminal for that
prepared entry. An SDK MUST NOT turn an unclassified failure into a fresh
rotation or issuance attempt.

Preparation state includes an expiry and the reserved prior-stream revision.
Only an expired preparation that is durably known never to have entered
submission may be atomically replaced. `submitting`, `indeterminate`, and
`accepted` records are never reclaimed or regenerated.
Concurrent stream advancement causes a deterministic stale-preparation error
rather than silent chain-field replacement. The assigned index and final event
reference are append results and are not retroactively inserted into the signed
entry.

```
TYPE SubmissionResult
  state: prepared | submitting | indeterminate | accepted | rejected
  entryHash: string
  index?: integer
  logRef?: LogRef
  errorCode?: string
END
```

The current product returns `SubmissionResult` for successful accepted or
replayed submissions and uses structured non-2xx errors for busy, rejected, and
indeterminate outcomes. Other adapters may return the full state union directly,
but callers apply the same retry rules in either representation. On every
accepted response, including the first attempt, the SDK verifies `entryHash`
against the exact submitted bytes before activating a new key or advancing local
state.

If an authorized event with invalid chain fields is nevertheless included, the
stream is in terminal verification failure. Neither the registry nor an SDK
resubmits corrected bytes or appends a corrective successor; historical
inclusion of the valid prefix may still be reported separately.

## Destination-Only Migration

The C2SP binding records only inbound MIGRATION as genesis of a fresh
identity-instance stream. Migration out of C2SP is represented by the
destination method's inbound event; the old C2SP stream receives no outbound or
terminal MIGRATION event.

To rebuild an inbound migration, the binding:

1. requires MIGRATION to be the first applied destination event, with `seq=0`
   and no previous-chain fields;
2. requires `new_lr` to equal the bound destination reference, `prev_lr` to
   differ, and `prev_ref` to be a final reference belonging to `prev_lr`;
3. recursively verifies the previous method's history through `prev_ref`, with
   cycle detection and configured recursion, history-size, and response-size
   limits;
4. requires the imported logged state to be `ACTIVE`;
5. verifies the MIGRATION accountable-entity signature with the historical
   entity key established by the imported history;
6. imports the FQDN, governance identity, entity public key, active operational
   public key, and thumbprints; and
7. returns one stitched history containing the previous history, the MIGRATION
   event exactly once, then later verified destination events.

`prev_ref` is the signed cutoff: entries appended later to the old stream are
not part of the migrated history. Migration preserves logged `ACTIVE` state and
key continuity. It cannot import `REVOKED` or `RETIRED` history and does not
create a replacement identity.

For a C2SP source, `prev_ref` must identify a fully signature-valid occurrence
of the final applied logical event through its exact index. A later copy is
allowed, but every logical event and conflict through that cutoff must be
verified. The first destination successor names the MIGRATION `eventId`, not
a source index or leaf. This is ordinary migration of conforming histories,
not an upgrade path for pre-correction development streams.

## Read Surface

The standard C2SP tiled-log read surface remains the supported log contract:

```text
GET <log-prefix>/checkpoint
GET <log-prefix>/tile/<level>/<tile>[.p/<width>]
GET <log-prefix>/tile/entries/<bundle>[.p/<width>]
```

An SDK source fetches checkpoints, tiles, and entry bundles with bounded
responses, safe redirects, and deployment-appropriate authentication. Entry
bundles are sequences of big-endian uint16 length-prefixed entries and are
verified against corresponding level-zero tile hashes before their contents are
trusted.

Server-specific JSON entry wrappers are optional diagnostics and MUST NOT be
required by the portable reader.

The binding exposes a source abstraction so deployments can provide a direct
tile scanner, mirror, archive, portable bundle, or indexed source without
changing verification logic:

```
TYPE C2spProvenEntry
  index: integer
  entryBytes: bytes
  inclusionProof: bytes
  checkpoint: bytes
END

TYPE C2spStreamEvidence
  entries: []C2spProvenEntry
  checkpoint: bytes
  completenessMode: string
  completeThroughSize?: integer
END

INTERFACE C2spTlogSource
  FetchCheckpoint(reference: C2spTlogReference) -> bytes
  ReadEntry(reference: C2spTlogReference, index: integer) -> C2spProvenEntry
  LoadStream(reference: C2spTlogReference, fqdn: string) -> C2spStreamEvidence
END

TYPE TrustedC2spCheckpoint
  origin: string
  treeSize: integer
  rootHash: bytes
  witnessTime: timestamp
END

INTERFACE TrustedC2spCheckpointStore
  Load(origin: string) -> TrustedC2spCheckpoint?
  CompareAndSwap(
    origin: string,
    expected: TrustedC2spCheckpoint?,
    candidate: TrustedC2spCheckpoint
  ) -> bool
END

OPTIONAL INTERFACE C2spConsistencyProofSource
  FetchConsistencyProof(
    reference: C2spTlogReference,
    fromSize: integer,
    toSize: integer
  ) -> []bytes
END
```

`C2spTlogSource` returns untrusted evidence. The binding, not the source,
performs canonical entry, proof, checkpoint, policy, signature, chain, and
completeness verification. A source MUST NOT be treated as complete merely
because it implements `LoadStream`.

A global-log scanner distinguishes an invalid entry candidate from failure to
obtain a trustworthy complete view. Non-DNSid entries, entries for another
FQDN, unsupported versions or event types, invalid lifecycle signatures, and
entries that fail method-context or per-entry inclusion validation are omitted
from the selected stream. They do not abort reconstruction. Failure to fetch or
authenticate the checkpoint, tiles, entry bundles, witness policy, or the
source's asserted completeness remains fatal. Sources MAY prefilter invalid
candidates to avoid poisoning, but the binding still validates every returned
entry and MUST NOT trust that prefilter as verification.

Omission cannot hide a fully authenticated new payload with an invalid chain
or transition. Resolve signer authority and suppress logical replays using the
rules under Stream Completeness and Logged State, including historical
predecessor authority and terminal histories. Do not treat structurally
parseable signed chain errors as encoding noise before authenticating them.

## Checkpoint, Proof, and Policy Verification

Before returning a verified event, the reader:

1. obtains a C2SP policy from a source accepted independently of the log;
2. parses the signed checkpoint and requires its origin to match the bound
   reference;
3. verifies the accepted log signature and witness quorum;
4. verifies checkpoint consistency with previously trusted state when one
   exists;
5. verifies the entry index, RFC 6962/SHA-256 leaf hash, inclusion proof, and
   checkpoint root;
6. verifies canonical DNSid entry encoding and lifecycle signatures; and
7. enforces timestamp, context, stream-chain, and lifecycle rules.

For `public` scope, policy requires independent witnesses. A policy fetched from
`<log-prefix>/dnsid-policy` is advisory unless its digest, signing key,
distribution channel, registry entry, or another trust anchor is accepted by
local policy. The file uses the official line-oriented C2SP `tlog-policy`
format with `log`, `witness`, `group`, and `quorum` directives, not
deployment-specific JSON.

C2SP `tlog-proof@v1` is the portable single-entry proof format. Optional `extra`
data has no security semantics unless independently authenticated. Witness
cosignatures are checkpoint note signatures, not DNSid event signatures.

The official line-oriented policy grammar permits a `witness` directive to
omit its URL when the policy is consumed only by a verifier:

```text
witness <name> <verifier-key> [<witness-url>]
```

The URL is a transport hint for software that contacts the witness. It is not
part of witness-key trust and a verification-only parser accepts both forms.

Append-only consistency state is scoped by checkpoint origin. After checkpoint
signature and witness-policy verification, a reader loads the previously
trusted checkpoint for that origin. A smaller tree is a rollback and fails. An
equal-size tree MUST have the same root. For a larger tree, the reader verifies
either an RFC 6962 consistency proof supplied by
`C2spConsistencyProofSource`, or the old prefix root when a verified complete
scan contains all leaves through the old tree size. It then atomically advances
the store with `CompareAndSwap`; on a lost race it reloads and repeats the
consistency check against the newer trusted checkpoint. A reader MUST NOT split
verification and advancement into separate non-atomic writes.

An in-memory store protects only the lifetime of one process. Deployments that
require rollback resistance across restarts inject durable storage. A first
checkpoint for an origin is trust-on-first-use unless the store was seeded out
of band; this does not replace independent policy and key trust.

The binding derives verifiable time from accepted timestamped quorum signatures.
`eventTime` is the signed event `ts` used for lifecycle snapshots and key age.
`includedBy` is the minimum timestamp among the signatures used to satisfy the
checkpoint quorum. `checkpointFreshnessTime` is the `includedBy` value for the
checkpoint used as fresh complete evidence. `eventTime` MUST NOT be later than
`includedBy` plus allowed clock skew. Fresh complete logged-state and
non-revocation evidence require `checkpointFreshnessTime` to satisfy local
freshness policy. If no accepted `includedBy` can be established,
timestamp-based checks fail closed.

## Stream Completeness and Logged State

A valid inclusion proof establishes that one entry exists. It does not establish
that all events for an FQDN were returned. The binding therefore separates:

- historical inclusion of a particular event; and
- fresh complete logged-state verification.

Fresh logged-state, non-revocation, and retirement decisions require a complete
stream view through a fresh accepted checkpoint. Operational continuity requires
a complete verified view through the current key but does not become current
protocol status. Supported
completeness modes are those defined by the method specification, including
full scan, trusted or monitored index, committed index, mirror/archive, and a
verified `dnsid-c2sp-stream-bundle@v1`. An untrusted index plus individual
inclusion proofs is not sufficient to prove absence of a later event.

A completeness assertion covers the first fully valid occurrence of each
logical event and every authenticated conflict under the authority rules below.
Later copies and unauthenticated noise may be omitted, but neither signed
forks nor the first fully valid occurrence may be omitted to change the result
or ordering. Scanners and trusted-index bundles must agree.

A `dnsid-c2sp-stream-bundle@v1` parser preserves and validates its signed
`fqdn`, `lr`, checkpoint, policy hash, complete-through tree size,
completeness mode, event entries and proofs, computed logged state, expiry, and
bundle signature. The reader requires the expected normalized FQDN and exact
complete `lr`; values selected by the bundle itself are not sufficient.
Accepted bundle verifier keys and the policy document are supplied independently
of the log origin and bundle. The discovery object
`{log-prefix}/dnsid-bundle-signer`, when present, is never a trust anchor.
Multiple accepted bundle verifier keys MAY overlap during a coordinated signer
rotation. Accepting the bundle signer and its asserted completeness mode is a
local policy decision; the reader still verifies the checkpoint and witness
quorum, every supplied C2SP proof, and lifecycle signatures/chain under the
candidate rules below, plus computed state, freshness, and signed expiry.
`state.event_count` counts applied logical events, not entry copies. The wire
summary is `state.logged_state`; SDKs expose it as `loggedState`, never as
protocol status.

The reader applies logical events in first fully verified occurrence order,
never sorting by `seq` or `ts`. Before returning stitched history to the shared
reducer, it applies the method's candidate rules:

1. Establish canonical encoding, inclusion, and exact signed context. Invalid
   global-log candidates cannot introduce state or keys. Accepted checkpoint,
   consistency, bundle inclusion, and completeness failures remain fatal.
2. If the canonical signed payload already identifies an applied event, ignore
   its lifecycle effect before rechecking current-key or terminal authority.
   Signature variants, including invalid-signature copies, cannot undo earlier
   authorization, reset key age, advance sequence, or move first-applied index.
3. For a new payload naming an applied predecessor, resolve all signer roles
   from that predecessor's verified post-state, including now-superseded keys.
   Otherwise use current verified state solely to recognize authenticated
   malformed-chain candidates. Initial ISSUANCE/MIGRATION retains bilateral
   or verified imported authority; later ISSUANCE cannot bootstrap a different
   entity key. Never trust a candidate `kid` or unverified predecessor.
4. Require every role signature for a new authenticated payload. Missing or
   invalid signatures, including stripped countersignatures, are noise and
   cannot reserve a logical ID.
5. Fully authenticated new payloads must continue the exact current logical
   predecessor, sequence, and state hash and satisfy timestamp and lifecycle
   rules. Signed forks, distinct duplicate genesis, and new post-terminal
   transitions are fatal, not omitted to recover earlier ACTIVE state.

Retain applied IDs, signed bytes, and post-states within configured history
limits. All copies consume input/scan limits even when deduplicated. A successor
cannot be applied before its predecessor. Structurally parseable signed chain
errors are checked after authentication, not hidden as encoding noise.

Ignoring an unauthenticated candidate never establishes completeness. Every
supplied bundle inclusion proof still verifies against its exact complete entry
bytes, even for ignored copies. An invalid lifecycle signature with a valid
inclusion proof is not itself an invalid Merkle proof. A direct `ReadEvent`
or exported proof claiming a valid signed occurrence must verify all of that
occurrence's signatures under historical authority; an ignored invalid-signature
copy cannot be returned as a valid standalone signed event or migration cutoff.

Failure of the accepted checkpoint, policy, witness quorum, or completeness
evidence is fatal rather than a candidate omission. REVOCATION and RETIREMENT
are terminal, and an unauthenticated event cannot introduce a key that
authorizes later events. Historical inclusion and the valid prefix before an
authenticated contradiction MAY still be reported separately.

If completeness, accepted-checkpoint freshness, chain continuity, or required
historical key material cannot be established, fresh complete logged-state verification fails
closed. Historical inclusion MAY still be reported separately. A fresh logged
`ACTIVE` result never replaces the fresh `ACTIVE` response required from `su`.

## Scope and Trust Policy

| Scope | Transport and trust expectations |
|---|---|
| `public` | HTTPS, independently anchored policy, accepted log signature, independent witness quorum, durable public read surface, and complete logged-state mechanism. |
| `testnet` | Out-of-band local trust anchors; HTTP and self-witnessing may be accepted only by explicit local policy. |
| `private-*` | Out-of-band endpoints, credentials, trust anchors, witness policy, and completeness guarantees for the declared verifier population. |

SDK defaults MUST NOT label a self-witnessed deployment `public`. Log keys,
witness keys, accountable-entity keys, and operational keys are separate roles.

## Trust Profiles

A DNSid C2SP trust profile is versioned, independently distributed JSON that
binds one exact log scope and prefix to its C2SP policy and accepted stream-bundle
signers:

```json
{
  "version": 1,
  "scope": "public",
  "log_prefix": "https://log.example",
  "tlog_policy": "log log.example+...\nwitness ...\nquorum ...\n",
  "bundle_verifier_keys": ["dnsid-stream-bundle+...+..."]
}
```

Version 1 has exactly these members. `scope` and `log_prefix` use the same
canonical rules as an `lr`; the policy MUST parse as the pinned C2SP policy
revision and its log key name MUST equal the checkpoint origin derived from
`log_prefix`; `bundle_verifier_keys` contains one or more signed-note Ed25519
verifier-key strings whose underlying public keys are distinct from each other
and from every checkpoint log or witness key. Their signed-note key IDs MUST
also be unique within the profile so a bundle `kid` selects exactly one key.
Unknown versions, members, duplicate JSON members, duplicate keys or key IDs,
malformed policy or keys, overlapping key roles, and mismatched origins fail
closed. Runtime limits, freshness, fallback, and checkpoint persistence are
local application policy and are not profile members.

An official service profile is selected explicitly and shipped through a
versioned SDK or release/configuration channel. SDKs MUST also accept a
caller-supplied profile in the same format. They MUST NOT infer a profile from
an identity's `lr`, or automatically trust a profile, policy, or signer fetched
from the log origin. A copy served at the log origin, including
`dnsid-bundle-signer`, is discovery and deployment diagnostics only.

`bundle_verifier_keys` is an array so a profile can accept old and new signers
during rotation. The operator distributes `[old, new]` before changing the
active signer and removes `old` only after the compatibility window. A client
that did not receive the transition fails closed after cutover. Automatic
root-key update requires a separately designed signed-metadata system and is
not part of this profile.

## Verification Convenience Factory

Bindings that provide both `c2sp-tlog` verification and a built-in bounded
standard-resource scanner MUST expose an idiomatic convenience factory for the
ordinary verification setup. The factory returns a `LogRegistry` with the
`c2sp-tlog` method registered, or an equivalent value directly accepted by the
binding's verification-only `IdentityManager` initializer:

```
TYPE C2spScanLimits
  maxTreeSize?: integer              // default 1,000,000 entries
  maxCheckpointBytes?: integer       // default 1,048,576 bytes
  maxEntryBundleBytes?: integer      // default 16,777,472 bytes
  maxTotalEntryBytes?: integer       // default 268,435,456 bytes
END

TYPE C2spResourceFetchGuarantees
  httpsOnly: boolean
  rejectsRedirects: boolean
  validatesAllResolvedAddresses: boolean
  connectsToValidatedAddress: boolean
  boundsResponseDuringRead: boolean
END

INTERFACE C2spBoundedResourceFetcher
  FetchBounded(url: string, maxBytes: integer) -> bytes
  SecurityGuarantees() -> C2spResourceFetchGuarantees
END

TYPE C2spTlogVerificationOptions
  trustProfile?: C2spTlogTrustProfile
  policyDocument?: bytes
  policyUrl?: string
  maxPolicyBytes?: integer
  resourceFetcher?: C2spBoundedResourceFetcher
  transport?: TransportConfig
  scanLimits?: C2spScanLimits
  trustedCheckpointStore?: TrustedC2spCheckpointStore
  checkpointMaxAge?: duration
  allowedClockSkew?: duration
  bundleVerifierKeys?: []bytes
  maxBundleLifetime?: duration
  maxStreamBundleBytes?: integer
  maxStreamBundleEvents?: integer
  requireStreamBundle?: boolean
END

CreateC2spTlogVerificationRegistry(options: C2spTlogVerificationOptions) -> LogRegistry
```

Names are illustrative. A language binding may call the bounded resource
fetcher a transport and may express cancellation, deadlines, durations, and
capability declarations idiomatically, but it preserves the same behavior.

Exactly one of `trustProfile`, `policyDocument`, and `policyUrl` is required.
When `trustProfile` is selected, direct bundle verifier keys MUST NOT also be
supplied; its exact scope and log prefix constrain every reader created by the
factory. `policyDocument` is already trusted caller input. `policyUrl` is an explicitly caller-selected
absolute HTTPS trust-policy location. The factory MUST NOT infer a policy URL
from an unverified identity record, its `lr`, or its log prefix. In particular,
the advisory `<log-prefix>/dnsid-policy` location does not become a trust anchor
through discovery. Testnet and deployment tooling SHOULD export the policy URL
as separate trusted configuration, including any non-default port, rather than
asking an application to reconstruct it from `lr`.

The effective bundle verifier keys come from the selected trust profile or the
direct `bundleVerifierKeys` option. When that set is empty, the factory uses the
standard bounded raw scanner. When one or more independently trusted verifier
keys are supplied, the factory uses stream bundles as the preferred evidence source for ordinary
reader operations. `maxBundleLifetime` is then required and positive; bundle
byte and event limits retain finite SDK defaults. `requireStreamBundle` requires
at least one verifier key and disables raw-scan fallback. This mode is useful for
deployment validation and environments where an unexpectedly unavailable bundle
endpoint must be visible as failure.

The default raw-scan ceiling is one million entries and 256 MiB of aggregate
entry bytes per scan, not a cheap lookup. Operators SHOULD reuse verification
registries, transports, and checkpoint stores, observe fallback frequency and
bytes/time spent, and lower existing limits or require bundles where predictable
cost matters. `requireStreamBundle` disables evidence fallback, not the bounded
`ReadEvent` discovery scan described below. All resources and migration hops
remain inside the invocation's [overall budget](README.md#verification-resource-budgets).
No new indexing service or telemetry API is required by this guidance.

The bundle source derives the exact endpoint from the authenticated bound
reference, fetches it with the same bounded resource fetcher, requires `200 OK`,
rejects redirects, and verifies the expected FQDN and exact `lr` in addition to
the full bundle contract above. In preferred mode it MAY fall back to the raw
scanner only for HTTP `404`, `408`, `429`, or `5xx`, when a transport or body
read fails with an explicitly transient error before a complete response body
is obtained, or when an otherwise valid bundle advances a stored checkpoint
but no consistency-proof source is available. In the last case the complete raw
scan MUST independently recompute and verify both the stored prefix root and the
new checkpoint root before advancing the checkpoint store. An interrupted or
truncated body read is availability failure; a completely read body that is
truncated or malformed bundle evidence is invalid evidence. Redirects, other
HTTP statuses, unsafe destinations, response-limit violations, rollback,
equal-size root conflicts, an invalid supplied consistency proof, and any
completely obtained body that is malformed, expired, policy-mismatched,
unknown-signer, signature-invalid, incomplete, or otherwise invalid fail closed
instead of silently downgrading to a scan. `requireStreamBundle` disables both
availability and missing-consistency-evidence fallback. Audit and testnet
callers can continue to select raw scanning by omitting bundle verifier keys.

A final event reference contains an opaque stream ID, not the identity FQDN
needed for the standard bundle URL. A `ReadEvent` implementation MAY use the raw
scanner only to discover the referenced event's FQDN, but it MUST then rebuild
the event's complete lifecycle through the preferred or required bundle source
and require the referenced logical event to appear in that verified history
before returning it. A fully signature-valid later copy may resolve to an
already applied event, but the requested occurrence's exact index and proof
must still verify and be retained; do not substitute the first copy's evidence. This discovery read is not bundle fallback; `requireStreamBundle`
still prohibits returning evidence when that bundle fetch or verification
fails.

`transport` and `resourceFetcher` are mutually exclusive; supplying both is an
`ArgumentError`. When no resource fetcher is supplied, the SDK constructs one
from `transport` (or an empty `TransportConfig`) that applies `dnsServer`,
`caBundlePath`, and `privateAddressHosts` exactly as the core HTTPS fetcher does
([05: Private Address Hosts](05-transport-and-registry.md#private-address-hosts)),
and that:

- rejects URL credentials and fragments;
- rejects redirects rather than following them;
- resolves and rejects every disallowed destination address, then connects to
  an address that was actually validated so DNS rebinding cannot bypass the
  check;
- bounds the decoded response while reading it, not after buffering it;
- requires HTTP status `200 OK`; and
- supports cancellation or finite deadlines so a resource read cannot wait
  indefinitely.

The policy response is limited by `maxPolicyBytes`, which defaults to 1 MiB.
The factory then parses the official `tlog-policy` format. Unsafe destinations,
redirects, oversized responses, invalid options, and malformed policy documents
are deterministic non-transient failures. A genuine timeout or unavailable
remote endpoint may be transient.

A supplied resource fetcher is trusted caller infrastructure, but it MUST expose
a bounded fetch operation and explicitly report the guarantees above. The
factory validates those guarantees before accepting it for `policyUrl` or a
`public` log and rejects insufficient capabilities as early as the language's
factory model permits. It also checks the returned byte length defensively;
that check does not replace bounding during the read. A testnet fetcher may
implement an explicit hostname-scoped private or loopback allowlist, with the
same semantics as `privateAddressHosts`, while still validating every
resolution and connecting to the validated address. Transports
that cannot provide the stated guarantees, including intentionally redirecting
or plain-HTTP private transports, remain available through the lower-level
composition API rather than weakening the safe factory. The same fetcher
instance is used for the policy and standard log resources so custom DNS, TLS,
proxy, credential, and timeout behavior does not diverge between them.

C2SP standard-resource geometry is fixed, not a resource-limit option. A full
entry bundle contains 256 entries; only the final bundle may be partial. Each
entry is at most 65,535 bytes and has a two-byte length prefix, so the default
maximum bundle response is exactly:

```text
256 * (2 + 65,535) = 16,777,472 bytes
```

A caller may choose a lower `maxEntryBundleBytes` to reject unusually large
logs, but MUST NOT configure a different entries-per-bundle value. All supplied
limits are positive integers. `maxTotalEntryBytes` independently limits the
aggregate scan, so accepting a tree size does not promise acceptance of every
possible tree of that size.

`allowedClockSkew` defaults to zero and MUST be non-negative.
`checkpointMaxAge`, when supplied, MUST be positive and configures the local
freshness policy used by fresh complete logged-state and non-revocation checks.
When it is absent, historical inclusion, bilateral binding, and operational
continuity may still be verified, but `VerifyNonRevocation` and any operation
requiring fresh logged-state evidence fail closed. C2SP policy files do not set
this application-local freshness decision.

The factory registers the parsed policy and built-in complete scanner and
defaults to a process-lifetime in-memory trusted-checkpoint store when no store
is supplied. One store instance is shared by every reader created from the
returned registry. Documentation MUST identify the default as
restart-ephemeral and direct deployments needing rollback protection across
restarts to inject durable storage.

The factory eagerly validates mutually exclusive options, ranges, URL shape,
fetcher capabilities, policy retrieval, and policy syntax. Validation that
depends on a later `lr`, such as whether the policy covers its checkpoint
origin, fails when that reader is constructed or first used, before evidence is
accepted.

This convenience API does not replace the lower-level composition surface.
Bindings continue to expose policy parsing, custom source/scanner construction,
method registration, and checkpoint-store injection for private transports,
portable bundles, mirrors, archives, and other advanced deployments.

## DNSid-Managed Trust

Bindings MUST expose a separately named, opt-in convenience factory for
verification against the reviewed trust roots of DNSid-managed DNSid
logs. Calling this factory is an application trust decision; it is product
convenience, not DNSid or C2SP protocol authority. The generic verification
factory above never selects these roots when caller trust is omitted.

The initial managed catalog is:

| Scope | Canonical log prefix | Embedded trust |
|---|---|---|
| `public` | `https://log.dnsid.dev` | One reviewed `dnsid-c2sp-tlog-trust-profile@v1` document. |
| `public` | `https://log.dnsid.ai` | One reviewed `dnsid-c2sp-tlog-trust-profile@v1` document. |

Both initial entries prefer verified stream bundles, with raw scanning only under
the availability and missing-consistency-evidence fallback rules below.

The catalog is private SDK data, not a new wire format. Each entry contains an
ordinary trust profile or policy document supported by the generic factory.
SDK releases vendor reviewed snapshots from the maintained product source; SDK
builds and runtime verification MUST NOT download, discover, or rewrite managed
trust material. A profile, policy, signer, or update advertised by a log origin
is not trusted unless a later SDK release or explicit caller configuration
independently accepts it.

The managed factory parses the complete `c2sp-tlog` `lr` and dispatches on
exactly:

```text
(scope, canonical log_prefix)
```

The parser MUST first enforce the ordinary reference grammar and canonical URL
rules. Selection MUST NOT use prefix, suffix, hostname-substring, environment
label, policy-origin inference, or fallback to another catalog entry. Unknown
selectors, wrong scopes, deceptive hostnames, and malformed or noncanonical
references fail closed. In the ordinary `IdentityManager` flow this selection
occurs only after `sg` authenticates the record containing `lr`.

For each catalog entry, the implementation constructs an ordinary generic
verification registry and registers one outer exact-dispatch factory. It reuses
the selected registry's bound reader rather than implementing verification a
second time. One supplied or default resource fetcher and one checkpoint store
are shared across all catalog entries. Catalog construction MUST parse and
validate every embedded document, require each profile selector or policy origin
to agree with its catalog selector, and reject duplicate selectors.
Caller-supplied trust MUST NOT be merged into this managed catalog.

The language-agnostic surface is:

```
TYPE DnsidManagedVerificationOptions
  resourceFetcher?: C2spBoundedResourceFetcher
  trustedCheckpointStore?: TrustedC2spCheckpointStore
END

CreateDnsidManagedVerificationRegistry(options?: DnsidManagedVerificationOptions) -> LogRegistry
```

Names, asynchronous construction, and cancellation are language-idiomatic. The
managed options expose only shared infrastructure: a bounded safe resource
fetcher, a trusted checkpoint store, and any idiomatic cancellation signal.
Callers needing different trust, freshness, limits, or bundle requirements use
the generic verification factory.

With no options, the managed factory uses the generic safe fetcher and scan
limits plus these fixed defaults:

- checkpoint maximum age: 10 minutes;
- maximum stream-bundle lifetime: 10 minutes;
- allowed clock skew: zero;
- verified stream bundles preferred for profile-backed entries, with raw
  scanning for those entries only under the availability and
  missing-consistency-evidence fallback rules above;
- policy-only entries use the bounded raw scanner directly; and
- one in-memory checkpoint store shared by every catalog entry and reader from
  that managed registry.

An invalid or untrusted bundle never triggers raw fallback. The default store is
registry-lifetime and normally retained for process lifetime, but it is
restart-ephemeral. Long-running deployments that require rollback resistance
across restarts SHOULD inject durable storage and reuse the managed registry
rather than constructing one per verification.

## Errors

Bindings use the shared SDK error taxonomy and distinguish at least:

- malformed reference or entry;
- unsupported profile, event, algorithm, or C2SP version;
- canonicalization failure;
- missing or invalid lifecycle signature;
- signer-role key mismatch;
- context or chain mismatch;
- stale preparation or idempotency conflict;
- append rejection or indeterminate submission;
- invalid checkpoint, proof, policy, or witness quorum;
- incomplete stream history; and
- stale logged-state evidence.

Parse, option, unsafe-destination, redirect, response-limit, canonicalization,
signature, context, and chain errors are non-transient. A retry cannot repair
those errors without changing input or configuration. Genuine network outages,
timeouts, pending submissions, and unavailable checkpoints may be transient.
An indeterminate append result is retried with the same idempotency key and exact
entry bytes, never by regenerating timestamps or signatures.

## Conformance and Interoperability

Each SDK implementation provides tests for:

- reference parsing and origin derivation;
- canonical signed bytes and complete entry bytes for every supported event;
- duplicate-member and non-canonical JSON rejection;
- required context and exact logical predecessor chain validation in every scope;
- ES256 high-S/low-S variants before and after originals, independently re-signed
  identical payloads, stripped/invalid countersignatures, and successors that
  remain valid when a copy appears before the original;
- different leaf hashes with equal logical IDs, unchanged key age/sequence on
  replay, signed extension/timestamp differences, historical-key forks, and
  genuinely new post-terminal conflicts;
- first-occurrence completeness and logical event counts agreeing between
  scanners and bundles, with invalid supplied proofs still fatal;
- exact signed migration cutoffs, valid later-copy cutoffs, recursive/cyclic or
  unavailable source history, and destination MIGRATION predecessor IDs;
- all signer-role success and failure cases;
- split ISSUANCE across independent accountable-entity and operational
  providers;
- KEY_ROTATION with both `prev_op` and `new_op`;
- exact-byte idempotent append and crash recovery;
- checkpoint, inclusion proof, consistency, witness quorum, and policy failures;
- complete versus incomplete stream behavior;
- factory rejection of zero or multiple policy sources, malformed HTTPS URLs,
  redirects, unsafe destinations, oversized policy responses, invalid fetcher
  capabilities, and invalid limits;
- the fixed 256-entry bundle geometry and exact 16,777,472-byte default maximum;
- one checkpoint store shared across readers and restart-ephemeral default-store
  behavior;
- configured checkpoint freshness and clock skew, including fail-closed
  non-revocation when freshness is absent or stale;
- factory-to-`IdentityManager` verification from raw standard C2SP resources;
- factory-to-`IdentityManager` verification through the authenticated
  `{log-prefix}/streams/{fqdn}?format=bundle` endpoint, including exact FQDN and
  `lr` binding, signer rotation overlap, required-bundle mode, bounded reads,
  permitted availability and missing-consistency-evidence fallback, and no
  fallback after invalid bundle bytes or consistency contradictions;
- trust-profile conformance covering exact scope/prefix binding, multiple
  bundle verifier keys for rotation, caller-supplied profiles, and rejection of
  unknown or duplicate members, malformed or colliding keys, bundle/checkpoint
  key-role overlap, and policy-origin mismatch;
- managed-catalog selection covering exact development and production
  selectors, wrong scopes, unknown and deceptive prefixes, and malformed or
  noncanonical references; and
- shared published vectors accepted and rejected identically by every SDK.

Factory integration tests use a maintained local or hermetic fixture rather
than requiring a mutable public example domain. Documentation may additionally
name a maintained public verification target, but examples using placeholders
MUST explain how to provision or locate a compatible target.

At least one interoperability test MUST prepare and accountable-entity-sign an
ISSUANCE in one SDK, operationally countersign it in another SDK, append it
without changing the entry, and verify it from raw C2SP checkpoint, tile, and
entry-bundle resources in every supported SDK.
