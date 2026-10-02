# SDK Design Open Questions

This document tracks SDK design questions that are not yet resolved.

## Unified Registration Profile

Integration decisions for the
[proposed registration profile](05-transport-and-registry.md#unified-registration-profile-proposed):

1. **Replacement Live admission:** settle its endpoint, authorization, inputs,
   and response separately; new Live creation stays disabled until then.
2. **Publication authority:** prefer returning it at creation to avoid the
   extra authenticated detail read and partial-success recovery. Lifecycle/status
   routing remains server work under
   [#2599](https://github.com/Identity-Digital/dnsid/issues/2599).
3. **Server guarantees:** replay after zone/organization changes and durable
   accountability across persistence paths need server integration proof under
   [#2598](https://github.com/Identity-Digital/dnsid/issues/2598). SDKs retain the
   original request rather than repair server allocation or lifecycle state.

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
