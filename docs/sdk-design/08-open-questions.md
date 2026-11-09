# SDK Design Open Questions

This document tracks SDK design questions that are not yet resolved.

## Known Foundry Create

Design: [13](13-known-foundry.md). Server assumptions and gates:
[server requirements](../known-foundry-server-requirements.md).

| Decision | Owner |
|---|---|
| Name reuse, replacement intent, failed-provisioning recovery (see the [proposal](../known-foundry-server-requirements.md#proposal-name-reuse-and-failed-provisioning)) | E2 #45–#47 |
| Confirm that create after rotation with the current key (no local state) returns the existing identity, as PR #3304 does; superseded-key lookup | E2 #47 |
| E2 confirmation of the SR-5 `domain` member on replay; compatibility negotiation | E2 #47 / E5 |
| Whether the Live proof challenge stays | E2 #46 |
| After `TLOG_INVALID_ENTRY` for an ISSUANCE: whether it can be transient, and whether the same issuance key may prepare again (SR-6 versus the reclaim rule in [11](11-c2sp-tlog-binding.md#submission-and-idempotency)) | E2 #46 |
| Final error codes, including `NAME_IN_USE` | E2 / E4 |
| Replica key convergence on an empty key store (known-foundry #62) and how it relates to explicit KMS-first creation (dnsid-sdk-compliance #57). Until decided, Foundry `Create` provisions no keys. | E6 |
| Foundry-specific routing selector, if needed | Product / E2 |

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
