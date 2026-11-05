# SDK Design Open Questions

This document tracks SDK design questions that are not yet resolved.

The Foundry product decisions below do not change the shared protocol reducer or
verification profiles. Current design and server evidence are in
[13](13-managed-registration.md) and the
[server requirements](../managed-registration-server-requirements.md).

## Managed Registration Configuration

Foundry Create uses named caller-key Live/pool provisioning. Its configured GI is
an independently validated expectation, not a routing selector; it does not accept
ordinary `input.governanceDomain`/root selectors. Ordinary registration retains 05's
existing selector rules. This removes the former duplication from the Foundry API.

## Foundry Server Contract Decisions

| Decision | Owner / required outcome |
|---|---|
| Intentional same-name replacement versus delayed old create, including soft deletion and replay-cache expiry | E2 #45/#47: review the [new-key replacement proposal](../managed-registration-server-requirements.md#proposal-name-reuse-and-failed-provisioning), then agree generation/intent and historical lookup before enabling replacement. Proposal only; no assumed `replaces` wire field. |
| Missing/expired proof or signature, ERROR and failed provisioning | E2 #46: review the [failed-attempt proposal](../managed-registration-server-requirements.md#proposal-name-reuse-and-failed-provisioning), then agree recovery, abandonment and safe name/resource release. Removing the proof challenge does not remove ISSUANCE countersigning. |
| Accepted/replay responses without domain/publication fields; machine-readable compatibility | E2 #47 / E5: expose sufficient immutable facts/authenticated recovery and agree negotiation. No presumed onboarding capability field. |
| Foundry-specific routing when sharing a deployment with other Live organizations | Product / E2: current adapter uses Live; introduce a distinct selector only if different rules require it. |
| Final error/fingerprint matrix and credential authorization/revocation | E2 / E4: provide required authorization and structured errors. SDKs preserve distinct missing-key, mismatch and revoked categories; they do not choose credential scopes or renewal policy. |
| Key initialization/distribution, provider algorithms and replica recovery | E6: owns setup and coordination outside the SDK facade. SDKs consume a usable supplied key and report conflicts; they do not require shared-locator convergence or prescribe replica recovery. |
| Quotas/rates, cleanup, public hosting and terminal/rotation retention | E2 / ABU-1 / E7 / E8: settle product policies and pass integration acceptance; SDKs consume returned/signed URLs. |

Source issues and release gates are linked in the server requirements. Their open
PRs are implementation direction, not evidence of merged or deployed support.
SDK-owned failure/retry behavior and cross-binding acceptance are defined in
[13](13-managed-registration.md#retry-deadlines-and-errors). External decisions
record ownership and the contract needed by the SDK, not policy chosen here.

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
