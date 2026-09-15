# SDK Design Agent Instructions

These instructions apply to files in `docs/sdk-design/`.

## General Rules

- These are language-agnostic SDK design documents. Do not add Go-, TypeScript-, Python-, or harness-specific implementation requirements unless a document is explicitly about that binding.
- Prefer additive edits. Keep existing documented protocol/profile behavior stable unless the user explicitly asks to revise it.
- DNSid is a protocol; Identity Digital's product/registry behavior must not be treated as protocol authority.
- Keep version-specific identity-record behavior under `07-protocol-data-types.md` profile sections instead of scattering conditionals across the document set.
- Do not add compatibility shims or legacy variants. DNSid is pre-1.0: replace obsolete behavior when directed, but keep documented identity-record profiles immutable for verification of existing signed records.

## Updating Identity Record Behavior Profiles

Use this when given a new DNSid spec or draft markdown document that changes `_dnsid` TXT record behavior.

1. Read the new spec completely before editing.
2. Identify exact `v=` value(s). Do not invent selectors or normalize names.
3. Update `07-protocol-data-types.md` first.
4. Add a new subsection under `Identity Record Behavior Profiles` for each submitted numbered draft.
5. Treat numbered draft profile subsections as frozen except for typo fixes or clarifications that do not change behavior.
6. During the Internet-Draft period, advance the `DNSid1` verification selector to the new numbered profile only after that draft is submitted and fully implemented.
7. Document the new profile's required tags, optional known tags, and behavior deltas from the closest previous profile.
8. Add new tags to the `DnsIdTxtRecord` data model only when SDKs must preserve, expose, validate, serialize, or sign them.
9. Update `CreateTxtRecord` generation to emit the exact submitted numbered draft selector. Never publish `DNSid1` before version 1 becomes an RFC.
10. Ensure parsed records preserve the exact `v=` value before signature verification.
11. Avoid scattered version conditionals in `01-core-identity-manager.md`; route profile-owned behavior through parse, validate, canonicalization, and signature-key-selection operations.
12. Keep support for unpublished work-in-progress drafts off the release branch and out of released SDKs.

Security guardrails:

- Never normalize, rewrite, or replace a parsed `v=` value before signature verification.
- Numbered `dnsid-draft-<nn>` identifiers are immutable. Pre-RFC `DNSid1` is the specification-defined exception: it selects the latest submitted draft fully supported by that SDK release, while remaining the exact signed wire value.
- When version 1 becomes an RFC, `DNSid1` freezes permanently to that RFC behavior.
- Unknown future versions fail closed with a non-retryable parse/unsupported-version error.
- Signature verification key selection is profile-owned.

## Updating SDK Implementation Coverage

Use this when reviewing Go, TypeScript, or Python SDKs against these design docs.

### Baselines and Review Mode

1. Read the target `implementations/{go,typescript,python}.md` first. Its `Analysis Details` table is the authoritative baseline for that SDK: use the recorded full SDK commit and design-docs commit. Do not substitute the summary values in `implementations/README.md` if they differ.
2. Record the current design repo commit, SDK branch, SDK commit, package version, and date before making claims.
3. Verify that both recorded commits resolve and are ancestors of the current heads. If a baseline is unavailable, history was rewritten, or the prior file does not represent a complete review, obtain the missing history or perform a full review.
4. Otherwise, use an incremental review by default:
   - In the design repo, enumerate every commit after the recorded design-docs commit that touched `docs/sdk-design/` or root `fixtures/`, excluding `docs/sdk-design/implementations/` and `docs/sdk-design/AGENTS.md`. Include `conformance/` fixtures and documentation, root wire fixtures, generation vectors, and conformance metadata because they can change required behavior. Inspect uncommitted changes in these paths too; do not attribute them to a committed baseline.
   - In the SDK repo, enumerate every commit after the recorded SDK commit across the entire repository, not only commits in expected source directories.
   - Inspect each range's commit subjects and name/status changes first, then inspect the aggregate diffs. Inspect individual commit diffs when the aggregate diff hides intent, includes a revert, or is otherwise ambiguous.
5. Map the two change sets to coverage rows before loading implementation files:
   - Re-review rows whose linked design requirements changed or whose SDK implementation, tests, dependencies, configuration, generated artifacts, or public surface changed.
   - Follow callers and dependencies when a changed helper has cross-cutting effects. Changes to parsing, validation, defaults, errors, cryptography, canonicalization, key selection, transport, or caching require a broader impact review.
   - Refresh evidence line numbers for any cited SDK file changed since the baseline, even when behavior is unchanged.
   - Preserve rows only after confirming that neither change set can affect them; unchanged source files need not be reloaded.
6. Perform a full review instead of an incremental one when impact cannot be bounded confidently, a large refactor or public API redesign occurred, a new design area was added, security-critical behavior changed broadly, or the existing tracker is internally inconsistent.

Useful starting commands are `git log --reverse --name-status <baseline>..HEAD -- <scope>` and `git diff <baseline>..HEAD -- <scope>`. The commit list establishes intent and coverage; the aggregate diff establishes the resulting state.

### Coverage Update Requirements

1. Review every impacted row and add rows for every new design requirement. Do not mark behavior implemented based only on exported names; verify required behavior, validation, error handling, and defaults.
2. Evidence must cite concrete file paths and line numbers. Prefer implementation evidence, with tests as support.
3. Mark behavior as `Implemented`, `Partial`, `Missing`, or `Not applicable` according to the legend in `implementations/README.md`.
4. Record material divergences under `Findings`, and record validation commands actually run. Choose tests based on the impacted behavior; run the full SDK and shared compliance suites for broad or cross-cutting changes.
5. Update the target file's analysis metadata to the exact reviewed heads even when no coverage status changes.
6. Update only the relevant `implementations/{go,typescript,python}.md` file unless the user asks otherwise.
