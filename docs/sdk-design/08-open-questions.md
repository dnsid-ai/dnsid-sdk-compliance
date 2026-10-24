# SDK Design Open Questions

This document tracks SDK design questions that are not yet resolved.

1. **Contradictions while replaying anchored genesis candidates.**
   [Genesis selection anchored on the record `ek`](11-c2sp-tlog-binding.md#genesis-selection-anchored-on-the-record-ek)
   classifies each authenticated genesis candidate by the entity key its replay
   ends with. It does not yet say how an anchored reader treats an
   authenticated chain or transition contradiction found while replaying a
   candidate before that candidate is known to match the record `ek`. Treating
   it as fatal would let a self-authenticated spam genesis with its own
   contradicting successor abort verification of a valid stream. Treating it as
   noise would report a contradiction in the matching history as a selection
   failure instead of its own category. The shared vectors place
   contradictions only in streams with a single genesis candidate and expect the
   contradiction's own category.

## Resolved Questions

Operation-level `logchk` uses the operation-independent
`VerifyLogEvidence(verifiedDomain, at)` primitive defined in
[`01-core-identity-manager.md`](01-core-identity-manager.md#verifylogevidencevd-verifieddomain-at-timestamp---loggedstateevidence).
Applications and deployment policy decide when to invoke it; protocol code does
not accept business-operation taxonomies.

Cross-system lifecycle ordering and recovery are resolved. The shared reducer
is defined in [`06-log-bindings.md`](06-log-bindings.md), managed operation
coordination in [`05-transport-and-registry.md`](05-transport-and-registry.md),
and C2SP-specific stream and migration rules in
[`11-c2sp-tlog-binding.md`](11-c2sp-tlog-binding.md).

## Future Base-Protocol Clarifications

These editorial and interoperability clarifications are desirable in a future
base-protocol revision but do not block the current SDK profile:

1. State that `PENDING`, `PROVISIONING`, and `VERIFYING` are status and
   provisioning states, not signed lifecycle events.
2. Define activation as publication of required verification resources plus
   accepted bilateral ISSUANCE.
3. List the required authorizing signer or signers for every event type.
4. State that `REVOKED` and `RETIRED` terminate one identity-instance history
   and that same-domain replacement begins a distinct history.
5. State how inbound MIGRATION is authorized, how prior history is cut off and
   stitched, and that a valid migration preserves `ACTIVE` state.
6. Separate mandatory ISSUANCE and key-continuity evidence from policy-gated
   fresh, complete log checking.
