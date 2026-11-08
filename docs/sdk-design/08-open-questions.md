# SDK Design Open Questions

This document tracks SDK design questions that are not yet resolved.

## Open Questions

None currently.

## Resolved Questions

### KMS-first restart before local activation

After restart, deliberate operator or application selection of the handed-off
immutable AWS KMS key ARN or Google Cloud KMS version reference is sufficient to
use that existing key as the local signer, even if it was never locally activated
before restart. No saved provider state or persisted proof of prior activation
is required for this reference-only startup. Creation still leaves the key
pending; cloud-enabled state alone does not authorize signing, and the SDK does
not automatically discover or select keys. Selection does not replace an
established signer without authorized rotation, bypass saved pending or
superseded provider state or managed-rotation recovery checks, or satisfy external
publication and issuance requirements.

The contract is defined in
[01](01-core-identity-manager.md#kms-first-operational-key-creation), with
[acceptance cases in 12](12-configuration-loading.md#google-cloud-kms-lifecycle-acceptance-cases).

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
