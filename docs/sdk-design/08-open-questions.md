# SDK Design Open Questions

This document tracks SDK design questions that are not yet resolved.

There are no unresolved shared protocol/lifecycle design questions at this time.
The portable managed-registration contract is defined in
[13](13-managed-registration.md). Future named-product behavior has the open
questions below; those do not block the portable workflow.

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

## Future Named Product Creation

Before implementing a hosted `create(name)` facade, settle:

1. Persistent name scope and normalization, authenticated resolution, atomic
   first-create claims, and conflicts between independently generated local keys.
   A display name and a finite-retention request key do not define these semantics.
2. Whether `create` waits for verified readiness or returns a provisioning handle
   with `active()`. Both must use one setup implementation and report progress
   separately from protocol status.
3. Explicit replacement generations after revocation/retirement, without treating
   an interrupted original operation as permission to allocate a replacement.
4. Key-provider rediscovery and transitions. Configuration alone cannot authorize
   a different operational key; local-to-cloud transitions must preserve the key
   or use the existing signed rotation flow.
5. The Known Foundry draft PRD's persistent operational-key journey versus its
   working-note proposal for ephemeral keys and entity-issued delegations. A
   separately specified presentation extension is needed for the latter; current
   bilateral issuance and lost-key behavior remain unchanged.

These are product/extension decisions, not changes to portable verification.
The Known PRD also assigns eligibility to verified customer governance domains;
a product adapter must not assume the agent domain is inside that GI namespace
or silently fall back to sandbox creation when eligibility fails.

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
