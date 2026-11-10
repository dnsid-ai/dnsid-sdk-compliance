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
| Final error codes, including `NAME_IN_USE` and the refusal of a new key on a REVOKED or RETIRED name (status, code, and whether it carries the ID, domain, and status) | E2 / E4 |
| Replica key convergence on an empty key store (known-foundry #62) and how it relates to explicit KMS-first creation (dnsid-sdk-compliance #57). Until decided, Foundry `Create` provisions no keys. | E6 |
| Foundry-specific routing selector, if needed | Product / E2 |

## Open Questions

### Azure Key Vault first-key provisioning and references

What explicit first-key provisioning operation and immutable reference form
should `azure-key-vault` support? The selectable provider name in
[12](12-configuration-loading.md#loaded-configuration) does not settle these
semantics. The [KMS-first contract in 01](01-core-identity-manager.md#kms-first-operational-key-creation)
defines AWS KMS and Google Cloud KMS only; Azure remains undefined.

### Startup identity discovery, publication evidence, and ownership

For configuration-managed startup, including without saved provider or rotation state,
how is an initial identity distinguished from an existing identity, how is its
publication binding established, and which responsibilities belong to the SDK
versus the application? The startup publication-discovery algorithm and policy
for absent or unreachable publication evidence remain unspecified in
[12](12-configuration-loading.md#operational-key-source-selection).

This open question does not authorize configuration-only signer replacement.
The [no-replacement requirements in 01](01-core-identity-manager.md#kms-first-operational-key-creation)
and the setup/recovery binding-error result in 12 before application signing,
including a selected key conflicting with an
existing verified `ku` publication, remain unchanged. Deliberate immutable-reference
selection still permits local provider open and local Active signing without
prior activation, saved state, or current publication; neither local open nor
successful `Construct` establishes identity continuity or authorizes application
signing for a conflicting existing identity. Saved provider state
and managed-rotation recovery bindings remain authoritative. Initial unpublished
identity construction remains allowed under the
[ordered setup](01-core-identity-manager.md#publication-and-issuance).

## Resolved Questions

### KMS-first restart before local activation

After restart, deliberate operator or application selection of the handed-off
immutable AWS KMS key ARN or Google Cloud KMS version reference is sufficient to
use that existing key as the local signer, even if it was never locally activated
before restart. No saved provider state or persisted proof of prior activation
is required for this reference-only startup. The selected reopened key is
locally Active, with the ordinary `SigningKey()` and active-only `ListKeyIds()`
behavior. Creation still leaves the key Pending in the creating provider process;
cloud-enabled state alone does not authorize signing, and the SDK does not
automatically discover or select keys. Selection does not replace an
established signer without authorized rotation, bypass saved pending or
superseded provider state or managed-rotation recovery checks, or satisfy external
publication and issuance requirements. Without saved state, startup cannot
reconstruct unavailable supersession history; the selected-reference binding
check is not proof of current publication or rotation eligibility.

The contract is defined in
[01](01-core-identity-manager.md#kms-first-operational-key-creation), with
[AWS acceptance cases](12-configuration-loading.md#aws-kms-lifecycle-acceptance-cases)
and [Google acceptance cases](12-configuration-loading.md#google-cloud-kms-lifecycle-acceptance-cases) in 12.

### Operation-level log checking

Operation-level `logchk` uses the operation-independent
`VerifyLogEvidence(verifiedDomain, at)` primitive defined in
[`01-core-identity-manager.md`](01-core-identity-manager.md#verifylogevidencevd-verifieddomain-at-timestamp---loggedstateevidence).
Applications and deployment policy decide when to invoke it; protocol code does
not accept business-operation taxonomies.

### Cross-system lifecycle ordering and recovery

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
