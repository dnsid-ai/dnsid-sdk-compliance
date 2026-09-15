# Log Bindings

This document defines shared lifecycle log abstractions and log-derived domain
state. Concrete log methods are specified in separate binding documents.
The [C2SP transparency-log binding](11-c2sp-tlog-binding.md) is the first such
concrete design.

This document owns the shared SDK reducer; concrete bindings own selection,
ordering, and proof mechanics. Managed cross-system coordination is defined in
[`05-transport-and-registry.md`](05-transport-and-registry.md).

## Responsibilities

The log module answers:

> How does the SDK write, read, and verify lifecycle evidence for DNSid
> identities?

### Implemented lifecycle interpretation

The base draft describes a six-state status progression but defines signed core
log events only for issuance, key rotation, revocation, retirement, migration,
and delegation. In the current profile, pre-active states are live protocol
status and product workflow—not portable signed lifecycle events. SDKs use three
separate models:

| Model | States | Authority |
|---|---|---|
| Product workflow | Deployment-specific | Registry or provisioning system |
| Protocol status | `PENDING`, `PROVISIONING`, `VERIFYING`, `ACTIVE`, `RETIRED`, `REVOKED` | Fresh `su` response |
| Verified lifecycle history | Internal `UNISSUED`, then `ACTIVE`, `RETIRED`, or `REVOKED` | Registered log-method verification followed by the shared reducer below |

Product workflow states MUST NOT be mechanically converted into protocol status.
In particular, publication readiness does not prove `ACTIVE`, and a rejected,
cancelled, or failed registration is not automatically `RETIRED`. Interactive
verification continues to require a fresh `ACTIVE` status response. SDKs MUST
NOT define DNSid wire events for `PENDING`, `PROVISIONING`, or `VERIFYING` under
the current profile; deployments may record those transitions in their own
audit logs.

Status and lifecycle-log evidence combine as follows:

| Status response | Log evidence | Result |
|---|---|---|
| Fresh `ACTIVE` | Required bilateral ISSUANCE and operational continuity are valid | Ordinary verification may succeed. |
| Fresh `ACTIVE` | Required complete-log evidence is unavailable, incomplete, stale, or contradictory | Verification requiring `logchk` fails. |
| Terminal or provisioning status | Any | Interactive verification fails. |
| Missing or stale status | Any | Log evidence does not upgrade the identity to current `ACTIVE`. |
| Fresh `ACTIVE` | A verified terminal log event is discovered | Fail because the status and log conflict. |
| Fresh terminal status | Terminal log evidence is pending | Current use fails immediately; deployments may report evidence convergence separately. |

Every SDK applies the same reducer to verified lifecycle history. The reducer
has one internal pre-history state, `UNISSUED`, and three materialized states:

| Current state | Event | Result | Additional requirement |
|---|---|---|---|
| `UNISSUED` | `ISSUANCE` | `ACTIVE` | Establish distinct entity and operational keys from verified key material. |
| `UNISSUED` | any other event | reject | A lifecycle history requires issuance genesis. |
| `ACTIVE` | `ISSUANCE` | reject | A verified history contains exactly one issuance genesis. |
| `ACTIVE` | `KEY_ROTATION` | `ACTIVE` | Previous thumbprint equals the active operational key; new key material matches its thumbprint; old and new keys differ. |
| `ACTIVE` | `DELEGATION` | `ACTIVE` | No core identity-state or key-state change. |
| `ACTIVE` | `MIGRATION` | `ACTIVE` | The binding has verified the previous history, final previous entry, and handoff to a different log reference. |
| `ACTIVE` | `REVOCATION` | `REVOKED` | A valid reason code is required. |
| `ACTIVE` | `RETIREMENT` | `RETIRED` | Graceful terminal transition. |
| `REVOKED` or `RETIRED` | any event | reject | Terminal identities cannot return to `ACTIVE`. |

Replacing a terminated identity creates a fresh identity verification history
selected by a fresh `lr`; it is not another `ISSUANCE` in the terminated
history and imports no trust depth from that history. This remains true when a
deployment reuses the same FQDN.

`MIGRATION` changes the log carrying an active identity, not the identity state.
`LogReader.RebuildHistory` MUST verify the previous log through
`finalEntryRef`, recursively when necessary, and return one stitched verified
history: the previous history, the migration event exactly once, then verified
events from the new log. If that stitching cannot be verified, rebuilding the
history fails. Stream closure, candidate selection, duplicate-effect handling,
and imported-state proofs remain binding-owned; the shared reducer never treats
an unverified inbound `MIGRATION` as genesis.

Lifecycle event selection and lifecycle reduction are distinct. A binding first
selects and verifies the applied event history according to its registered
method, including its duplicate and invalid-candidate rules. The shared reducer
then rejects any invalid transition that survives that boundary. Correct
signatures do not make an invalid transition valid. If a registered method has
already authenticated an event as belonging to the lifecycle, a chain or
transition failure aborts logged-state verification rather than silently
restoring the preceding state.

### DomainLog

The full verified event history for a domain, loaded from the lifecycle log via
[`IdentityManager.LoadDomainLog`](01-core-identity-manager.md#core-methods).
All events have had their inclusion proofs and profile/event-selected
authorizing signatures verified by the `LogReader` / read binding before being
stored here. Event timestamps are signed lifecycle metadata validated under the
log method's rules; method-owned acceptance, receipt, or log times stay with the
log binding. `SnapshotAt` is pure computation over the loaded history — no I/O.

Fields:

| Field | Type | Description |
|---|---|---|
| `domain` | string | Identity FQDN |
| `events` | []LogEvent | All events in verified lifecycle order, with inclusion proofs, timestamps, append-only consistency, method-owned ordering constraints, and profile/event-selected authorizing signatures verified |

```
FUNCTION DomainLog.SnapshotAt(at: timestamp) -> DomainSnapshot
  IF len(events) == 0 THEN
    RAISE VerificationError("no lifecycle events for " + domain)
  END

  state = ""
  activeKey = nil
  activeKeyThumbprint = ""
  keyBoundAt = ZeroTime
  governanceId = ""
  eventsUpTo = []

  // Preserve the verified lifecycle order supplied by the log binding. Do not
  // sort by timestamp here; timestamps are signed lifecycle metadata, not the
  // log method's ordering primitive. SnapshotAt returns only a verified lifecycle
  // prefix. If the requested timestamp would require skipping a future-timestamped
  // event and then applying a later log event, reject the non-prefix boundary.
  pastSnapshotBoundary = false
  FOR each event in events
    IF event.domain != domain THEN
      RAISE VerificationError("lifecycle event domain mismatch for " + domain)
    END
    IF event.timestamp > at THEN
      pastSnapshotBoundary = true
      CONTINUE
    END
    IF pastSnapshotBoundary THEN
      RAISE VerificationError("snapshot time is not a verified lifecycle prefix for " + domain)
    END
    eventsUpTo.append(event)

    IF state == "" AND event.type != "ISSUANCE" THEN
      RAISE VerificationError("first lifecycle event must be ISSUANCE")
    END

    IF state IN {"REVOKED", "RETIRED"} THEN
      RAISE VerificationError("event after terminal identity state")
    END

    SWITCH event.type
      CASE "ISSUANCE":
        IF state != "" THEN
          RAISE VerificationError("duplicate ISSUANCE in one identity history")
        END
        IF event.initialEntityPublicKey == nil OR event.initialOperationalPublicKey == nil OR
           Thumbprint(event.initialEntityPublicKey) != event.initialEntityThumbprint OR
           Thumbprint(event.initialOperationalPublicKey) != event.initialOperationalThumbprint OR
           event.initialEntityThumbprint == event.initialOperationalThumbprint THEN
          RAISE VerificationError("ISSUANCE key binding is invalid")
        END
        state = "ACTIVE"
        activeKey = event.initialOperationalPublicKey
        activeKeyThumbprint = event.initialOperationalThumbprint
        keyBoundAt = event.timestamp
        governanceId = event.governanceId
      CASE "KEY_ROTATION":
        IF state != "ACTIVE" THEN
          RAISE VerificationError("KEY_ROTATION outside an ACTIVE issuance")
        END
        IF event.previousOperationalThumbprint != activeKeyThumbprint THEN
          RAISE VerificationError("KEY_ROTATION does not continue from the active key")
        END
        IF event.newOperationalPublicKey == nil OR
           Thumbprint(event.newOperationalPublicKey) != event.newOperationalThumbprint OR
           event.newOperationalThumbprint == activeKeyThumbprint THEN
          RAISE VerificationError("KEY_ROTATION new key is invalid")
        END
        activeKey = event.newOperationalPublicKey
        activeKeyThumbprint = event.newOperationalThumbprint
        keyBoundAt = event.timestamp
      CASE "REVOCATION":
        IF state != "ACTIVE" THEN
          RAISE VerificationError("REVOCATION outside an ACTIVE issuance")
        END
        IF event.reason NOT IN {"keyCompromise", "policyViolation", "superseded", "cessationOfOperation"} THEN
          RAISE VerificationError("invalid REVOCATION reason")
        END
        state = "REVOKED"
      CASE "RETIREMENT":
        IF state != "ACTIVE" THEN
          RAISE VerificationError("RETIREMENT outside an ACTIVE issuance")
        END
        state = "RETIRED"
      CASE "MIGRATION":
        IF state != "ACTIVE" OR event.previousLog == event.newLog THEN
          RAISE VerificationError("invalid MIGRATION")
        END
        // The binding has already verified and stitched the handoff.
      CASE "DELEGATION":
        IF state != "ACTIVE" THEN
          RAISE VerificationError("DELEGATION outside an ACTIVE issuance")
        END
        // Delegation does not change core identity or key state.
      DEFAULT:
        RAISE VerificationError("unsupported lifecycle event type")
    END
  END

  IF len(eventsUpTo) == 0 THEN
    RAISE VerificationError("no lifecycle events for " + domain + " at or before " + at)
  END

  IF state == "" OR activeKey == nil THEN
    RAISE VerificationError("no ISSUANCE event found for " + domain + " at or before " + at)
  END

  RETURN DomainSnapshot{
    domain:              domain,
    historicalState:     state,
    activeKey:           activeKey,
    activeKeyThumbprint: activeKeyThumbprint,
    keyBoundAt:          keyBoundAt,
    governanceId:        governanceId,
    snapshotAt:          at,
    events:              eventsUpTo,
  }
END

```

---

### DomainSnapshot

The materialized state of a domain at a specific point in time, derived from a
`DomainLog`. Contains no live data. The prefix preserves the verified order
supplied by the log binding. If a timestamp boundary would require a non-prefix
subsequence, or the prefix violates the lifecycle reducer, `SnapshotAt` raises
instead of returning a snapshot. A replacement identity has a different fresh
`DomainLog`; snapshots never cross identity histories.

| Field | Type | Description |
|---|---|---|
| `domain` | string | Identity FQDN |
| `historicalState` | string | Verified history state at `snapshotAt`. One of: `ACTIVE`, `REVOKED`, `RETIRED`. This is not current protocol status. |
| `activeKey` | JWK | Public key that was bound at `snapshotAt`. Full key material preserved from ISSUANCE or KEY_ROTATION event |
| `activeKeyThumbprint` | string | RFC 7638 thumbprint of `activeKey` |
| `keyBoundAt` | timestamp | When `activeKey` was introduced (ISSUANCE or KEY_ROTATION timestamp) |
| `governanceId` | string | `gi` value from the ISSUANCE event |
| `snapshotAt` | timestamp | The requested point in time |
| `events` | []LogEvent | Verified lifecycle prefix at or before `snapshotAt` |

---

### Log Interface

Write interface for the local identity's immutable log. Implementations may wrap
a blockchain, CT-style transparency log, SCITT transparency service, or any
append-only verifiable log. The `Log` interface covers only the local write
path; reading and verifying log entries — including for the local identity's own
history — is handled by [`LogReader`](#logreader-interface). A concrete
implementation typically satisfies both interfaces;
[`LogRegistry`](#logregistry) uses the type assertion to derive the local write
log from the registered factory.

```
INTERFACE Log

  // Returns the canonical byte representation of the event for this log method.
  // Called by IdentityManager.CanonicalizeLogEvent to produce the bytes that are signed.
  // MUST exclude signature fields and produce identical output to LogReader.Canonical
  // for the same event and any internally derived method metadata so signatures
  // written here are verifiable on read. If caller-supplied method metadata is
  // required, this method MUST fail before returning bytes; the binding uses a
  // method-specific canonicalization helper instead.
  Canonical(event: LogEvent) -> bytes

  // Appends a signed event to the log. The event MUST already carry all
  // required profile/event-selected signature fields before WriteEvent is called.
  // Some log methods require method-owned append metadata; those bindings MUST
  // either compute it internally or fail before writing and expose a method-specific
  // prepare/canonicalize/write path without adding that metadata to the shared
  // LogEvent type.
  // Returns a LogRef identifying the recorded entry.
  WriteEvent(event: LogEvent) -> LogRef

END
```

---

### LogReader Interface

Read and verify interface for a specific log entry, bound at construction to a full `lr` value. The implementation stores the `entryRef` internally; callers do not pass it per-method. All methods MUST verify cryptographic inclusion proofs, verifiable timestamps, append-only consistency, and any method-owned ordering or stream-continuity constraints before returning success.

`LogRegistry.NewReader` returns a `NoopLogReader` for unknown methods; every method on `NoopLogReader` raises `VerificationError("no LogReader registered for method 'X'")`.

```
INTERFACE LogReader

  // Returns the canonical byte representation of the event for this log method.
  // Used to verify profile/event-selected authorizing signatures on events read
  // from the log. MUST exclude signature fields and produce identical output to
  // Log.Canonical for the same event and any internally derived method metadata.
  Canonical(event: LogEvent) -> bytes

  // Returns the timestamp at which the given key thumbprint was bound to the domain
  // (ISSUANCE or KEY_ROTATION event). Used for ka validation.
  // MUST verify inclusion proof, timestamp proof, and append-only consistency.
  KeyTimestamp(domain: string, keyThumbprint: string) -> timestamp

  // Verifies the draft 01 bilateral ISSUANCE binding for the current TXT record.
  // MUST verify inclusion proof, timestamp proof, append-only consistency, the
  // accountable-entity signature over ISSUANCE, and the operational-key
  // countersignature over the same canonical ISSUANCE content. The event must
  // match the current record's domain and gi, and its entity public key material
  // must correspond to the current ek key.
  VerifyBilateralBinding(record: DnsIdTxtRecord, entityKey: JWK, operationalKey: JWK) -> BilateralBinding

  // Verifies that currentOperationalThumbprint is either the ISSUANCE operational
  // key or is connected to it by a valid KEY_ROTATION continuity chain. Each
  // KEY_ROTATION is signed by the previous operational key over the new public key
  // material and thumbprints.
  VerifyOperationalContinuity(domain: string, initialOperationalThumbprint: string, currentOperationalThumbprint: string)

  // Verifies that no REVOCATION event exists for the domain at or before the given
  // timestamp. Raises if a REVOCATION entry is found, if the log cannot be queried,
  // or if the log binding cannot prove complete history for the method's verification
  // scope. A proof for one event is not sufficient to prove non-revocation.
  // MUST verify the cryptographic evidence required by the log binding.
  VerifyNonRevocation(domain: string, at: timestamp) -> LoggedStateEvidence

  // Reads a single event by its log reference.
  // MUST verify inclusion proof and timestamp proof before returning.
  ReadEvent(ref: LogRef) -> LogEvent

  // Rebuilds the full event history for the domain in the log binding's verified
  // lifecycle order. This order is method-defined; it is not necessarily event
  // timestamp order. MUST verify inclusion proofs, timestamp proofs, append-only
  // consistency, method-owned ordering/stream-continuity metadata, and
  // profile/event-selected authorizing signatures according to event-type-specific
  // rules. ISSUANCE bootstrap and KEY_ROTATION continuity cannot be inferred from
  // the generic "current active key" rule alone; implementations MUST NOT treat a
  // key introduced by an unverifiable event as valid for later events. Events that
  // fail the applicable signature rule MUST NOT be returned.
  RebuildHistory(domain: string) -> []LogEvent

END
```

`BilateralBinding` is the verified ISSUANCE binding returned by
`VerifyBilateralBinding`:

| Field | Description |
|---|---|
| `initialOperationalThumbprint` | Operational key thumbprint recorded in ISSUANCE. |
| `initialEntityThumbprint` | Entity key thumbprint recorded in ISSUANCE. |
| `timestamp` | ISSUANCE timestamp. |

`LoggedStateEvidence` prevents a bare non-revocation boolean from discarding
the proof boundary on which it depends:

| Field | Description |
|---|---|
| `logReference` | Complete identity-instance `lr` verified by the binding. |
| `loggedState` | Verified lifecycle-history state through `historyEnd`; never current protocol status. |
| `historyStart` | Method-specific genesis reference included in the verified history. |
| `historyEnd` | Method-specific final applied event reference, if any. |
| `completeThrough` | Opaque method-specific log position through which completeness was established. |
| `completenessMode` | Binding-defined accepted completeness mechanism. |
| `checkpoint` | Opaque accepted checkpoint or equivalent log-state evidence. |
| `freshnessTime` | Independently verified freshness time, when current non-revocation was requested. |

The binding MUST reject rather than return this evidence if the requested
history bounds, completeness, checkpoint acceptance, or required freshness
cannot be established. Callers still fetch and validate fresh protocol status;
`loggedState == ACTIVE` never upgrades a missing, stale, or non-active `su`
response.

---

### LogRegistry

The single injection point for all log interaction. Holds one factory per log method. Factories produce objects implementing `LogReader`; those that also implement `Log` can serve as the local write log. `IdentityManager` uses the registry at construction to derive `localLog` when local log writes are needed and during `VerifyDomain` to construct counterparty readers when log evidence may be required.

DNSid log methods may be public, private, consortium-scoped, access-controlled, or based on portable receipts within the method's declared verification scope. The SDK does not assume public queryability. A `LogReader` implementation is responsible for satisfying that method's verification procedure, including authentication to an access-controlled log or verification of portable cryptographic receipts.

Concrete bindings define their own event encoding, canonical form, proof format,
query surface, trust policy, and method-owned metadata. The shared interfaces do
not imply JSON: for example, a COSE-based binding can use COSE byte strings and
receipts while still satisfying `Log` and `LogReader`.

### Method-owned metadata

`LogEvent` represents DNSid lifecycle semantics only. Log-method mechanics such as
inclusion proofs, checkpoints, witness state, append-only consistency data,
sequence counters, previous-entry pointers, previous leaf hashes, stream-state
hashes, receipt bytes, and transport-specific envelope fields are owned by the
log binding. They MUST NOT be added to the shared `LogEvent` type unless they
change DNSid lifecycle semantics across log methods.

A binding MAY expose method-specific helper APIs for preparing append metadata,
canonicalizing with that metadata, writing with that metadata, or inspecting raw
receipts, acceptance timestamps, or log times. Those helpers are outside the
common `Log`/`LogReader` contract. If a method requires caller-supplied metadata
before signatures can be produced, the common `Canonical(event)`/`WriteEvent(event)`
flow is insufficient for that event and MUST fail before signing or writing; the
binding-specific flow MUST be used. For example, a DNSid binding profile over an
index-ordered transparency log may require signed stream fields or chained state
fields prepared before signing unless the binding can derive them internally. On
the read path, the binding MUST verify method-owned metadata before returning a
`LogEvent`; callers of `DomainLog` see only verified lifecycle events.

When a method's signed event envelope allows extension fields, unknown signed
fields MUST remain part of that method's canonical signature verification and
MUST be ignored unless a supported extension defines semantics for them. Bindings
MUST still reject malformed encodings, duplicate object members where the method
requires unique names, non-canonical numeric forms where the method requires
canonical numbers, and unsupported signature-envelope shapes.

For index-ordered transparency logs, lifecycle order may be log-index order
within the verified stream, not event timestamp order. A DNSid binding profile
verifies any required stream-chain fields, such as sequence numbers and previous
leaf/state hashes, internally and returns ordinary `LogEvent` values in verified
log-index order.

**LogRef format:** `{method}:{entry-ref}`, where:
- `method` matches `[a-z][a-z0-9-]*` — lowercase, starts with a letter, alphanumeric and hyphens only (consistent with URL scheme syntax).
- `entry-ref` is everything after the first `":"` — format is method-specific and opaque at this layer. Entry refs may themselves contain colons.
- A string with no `":"`, an empty method, or a method that does not match the pattern is malformed and raises `ParseError`.

```
TYPE LogRegistry

  // Registers a factory for the given method name (e.g. "ctlog" or "scitt").
  // method must match [a-z][a-z0-9-]*; raises ArgumentError if not.
  // The factory receives the full lr string and returns a LogReader bound to that entry reference.
  // If the returned LogReader also implements Log, it can be used as the local write log.
  Register(method: string, factory: func(lr: string) -> LogReader)

  // Splits lr on the first ":" to extract the method prefix (must match [a-z][a-z0-9-]*),
  // then calls the registered factory for that method.
  // Returns a NoopLogReader if no factory is registered for the method —
  // all NoopLogReader methods raise VerificationError{Code: LogError, Transient: false,
  // Message: "no LogReader registered for method 'X'"}. NoopLogReader is SDK
  // ergonomics only: it lets non-log-dependent interactive verification succeed, but it
  // does not make log evidence optional when required by draft 01 bilateral binding, ka, logchk, or local policy.
  // Raises ParseError if lr is malformed (no colon, empty method, or method violates [a-z][a-z0-9-]*).
  NewReader(lr: string) -> LogReader

END
```

See [Log Events](#log-events) for the full event type catalogue.

---

## Log Events

[Reference](https://datatracker.ietf.org/doc/draft-ihsanullah-dnsid/)

Lifecycle event signer roles are profile-owned. For draft 01, the
accountable-entity record-signing key discovered through `ek` signs core
lifecycle events except `KEY_ROTATION`, which is signed by the previous
operational key discovered through `ku`. `ISSUANCE` is additionally
countersigned by the initial operational key. Historical event verification uses
public key material recorded in the lifecycle log, not whatever the live `ek` or
`ku` endpoints currently serve.

These base signature requirements are a floor. A log-method binding MAY require
additional lifecycle signatures, but it MUST NOT omit, replace, or weaken a base
authorization signature. Generic profile helpers such as
`RequiredLogSignatures(event)` report only the base profile roles; binding-owned
preparation, parsing, and verification enforce method-specific additions.

Every `LogEvent` has these common lifecycle fields in addition to the event-specific fields
below. Method-owned verification metadata is intentionally excluded; see
[Method-owned metadata](#method-owned-metadata).

| Field | Description |
|-------|-------------|
| `type` | Event type identifier (`ISSUANCE`, `KEY_ROTATION`, etc.) |
| `sig` | Base64url authorizing signature over the event's log-method-specific canonical serialization, excluding `sig` and countersignature fields. For draft 01, this is the accountable-entity signature on core events except `KEY_ROTATION`; on `KEY_ROTATION`, it is the previous-operational-key signature. |
| `operationalCountersig` | Base64url operational-key countersignature. Required on `ISSUANCE`; profile-defined elsewhere. |

The caller populates event data and either passes it to
[`SignAndWriteEvent`](01-core-identity-manager.md#core-methods) for the
single-process case, or uses `CanonicalizeLogEvent`, `SignEvent`, and
`WriteSignedEvent` to collect signatures across multiple SDK instances before
submission. Canonical serialization is log-method-specific, and `Log.Canonical`
and `LogReader.Canonical` MUST produce identical output for the same event while
excluding signature fields. If the method requires caller-supplied append metadata
before canonicalization, the generic canonicalize/sign/write flow MUST fail before
signing and the caller MUST use the binding-specific flow. On the read path,
`LogReader` MUST verify inclusion proofs, timestamps, append-only consistency,
and event signatures according to these event-type rules; unverifiable events are
not part of a valid `DomainLog`.

### Core Events (Required)

**`ISSUANCE`** — Accountable-entity adoption and bilateral binding of a DNSid
operational key.

| Field          | Description |
|----------------|-------------|
| `domain`       | Identity FQDN |
| `governanceId` | Accountable-entity domain (`gi`) |
| `initialOperationalKid` | Key ID of initial DNSid operational key |
| `initialOperationalAlg` | JOSE alg of initial DNSid operational key |
| `initialOperationalPublicKey` | JWK public key material for the initial operational key |
| `initialOperationalThumbprint` | RFC 7638 thumbprint of the initial operational key |
| `initialEntityKid` | Key ID of initial accountable-entity record-signing key |
| `initialEntityAlg` | JOSE alg of initial accountable-entity record-signing key |
| `initialEntityPublicKey` | JWK public key material for the initial entity key |
| `initialEntityThumbprint` | RFC 7638 thumbprint of the initial entity key |
| `timestamp`    | Issuance time |
| `sig` | Accountable-entity signature verified against the entity public key material recorded in this event |
| `operationalCountersig` | Countersignature verified against the initial operational public key material recorded in this event |

Both signatures cover the same canonical ISSUANCE content. The event must match
the current TXT record's DNSid FQDN and `gi`; the recorded entity key must
correspond to the current `ek` key unless a future profile defines entity-key
continuity.

---

**`KEY_ROTATION`** — Rotation to a new DNSid operational key. Establishes
continuity from the previous operational key.

| Field                  | Description |
|------------------------|-------------|
| `domain`               | Identity FQDN |
| `previousOperationalKid` | Key ID of the previous operational key retained for the authorizing signature |
| `previousOperationalThumbprint` | JWK thumbprint of the previous operational key |
| `newOperationalKid` | Key ID of the new operational key |
| `newOperationalAlg` | JOSE alg of the new operational key |
| `newOperationalPublicKey` | New operational JWK public key material |
| `newOperationalThumbprint` | JWK thumbprint of the new operational key |
| `timestamp`            | Rotation time |
| `sig` | Signature by the previous operational key over at least domain, event type, previous thumbprint, new public key material, new thumbprint, and timestamp |

For base draft 01, this previous-operational signature is the only required
`KEY_ROTATION` authorization. It authorizes continuity from the prior operational
key to the new key. An accountable-entity signature and a new-operational-key
signature are not base requirements. TXT re-signing is required only when a TXT
tag value changes.

**`REVOCATION`** — Permanent, forced termination. Work products from the triggering period should be treated as suspect.

| Field            | Description |
|------------------|-------------|
| `domain`         | Identity FQDN |
| `timestamp`      | Revocation time |
| `reason`         | One of: `keyCompromise`, `policyViolation`, `superseded`, `cessationOfOperation` |

Signed by the accountable-entity record-signing key recorded in ISSUANCE or a
future profile-defined entity-key-continuity proof.

---

**`RETIREMENT`** — Graceful end-of-life. Signatures produced before retirement remain verifiable.

| Field       | Description |
|-------------|-------------|
| `domain`    | Identity FQDN |
| `timestamp` | Retirement time |

Signed by the accountable-entity record-signing key.

`MIGRATION` is destination-only: the event is genesis in the new log stream and
is authorized by the accountable-entity key established by the verified
previous history through `finalEntryRef`. The destination binding imports only
an `ACTIVE` previous history and returns one stitched history. No outbound event
is appended to the old stream.

---

**`MIGRATION`** — Transfer of identity history to a new log technology.

| Field            | Description |
|------------------|-------------|
| `domain`         | Identity FQDN |
| `previousLog` | Previous log reference (`lr`) |
| `newLog`      | New log reference |
| `finalEntryRef`  | Reference to the last entry on the previous log |
| `timestamp`      | Migration time |

Signed by the accountable-entity record-signing key.

### Optional Events

**`DELEGATION`** — Grants a delegatee identity permission to act on behalf of this identity within a defined scope.

| Field         | Description |
|---------------|-------------|
| `domain`      | Delegating identity FQDN |
| `delegatee`   | Delegatee identity FQDN |
| `scope`       | Permitted operations |
| `expiry`      | Delegation expiry time |
| `timestamp`   | Delegation time |
