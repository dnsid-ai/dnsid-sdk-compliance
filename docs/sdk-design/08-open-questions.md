# SDK Design Open Questions

This document tracks SDK design questions that are not yet resolved.

## Unified Registration Profile

The [proposed registration contract](05-transport-and-registry.md#unified-registration-profile-proposed)
requires independent review by the repository's SDK maintainers. It does not
establish shipped registry behavior or advance implementation-coverage baselines.
The following integration questions block claiming the profile is delivered:

1. **Replacement Live admission:** settle its endpoint, authorization, inputs,
   and response under [#2599](https://github.com/Identity-Digital/dnsid/issues/2599).
   Until that contract exists, new Live creation fails before network I/O;
   existing status/proof/reissue operations remain supported.
2. **Resolved hosting and lifecycle routing:** decide whether creation returns
   explicit hosting/publication-authority facts or requires an authenticated
   detail read. The proposal preserves `publication_config` and retains creation
   results if that read fails; it does not infer hosting from selectors or
   environment. [#2599](https://github.com/Identity-Digital/dnsid/issues/2599)
   must align lifecycle/status consumers with persisted facts.
3. **Stable replay and durable accountability:** prove that a successful create
   replays after zone deactivation or organization changes, and that every
   persistence path preserves the selected GI/accountability across restart.
   These are server integration obligations under
   [#2598](https://github.com/Identity-Digital/dnsid/issues/2598), not SDK retry
   workarounds. Coordinate registry and binding releases rather than advertise
   this guarantee from documentation alone.

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
