# SDK Design Open Questions

This document tracks SDK design questions that are not yet resolved.

## Open Questions

### KMS-first restart before local activation

**OPEN:** After explicit AWS KMS or Google Cloud KMS first-key creation, what
happens if the application restarts before local activation and only the
immutable resource reference has been handed off, without saved provider state?
The pending-versus-active result of reference-only reopening and any required
state handoff remain undecided. This question does not define a new persistence
mechanism or authorize automatic activation.

The existing saved-pending-state rule in
[12](12-configuration-loading.md#google-cloud-kms-lifecycle-acceptance-cases)
remains unchanged. The ordinary already-activated reopen path is described in
[01](01-core-identity-manager.md#kms-first-operational-key-creation).

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
