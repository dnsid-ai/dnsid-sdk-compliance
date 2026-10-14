# Focused WBA Conformance Check — 2026-10-14

This records measured shared-harness results and SDK follow-up work, not a full
SDK review. The authoritative full-review baselines in the binding trackers
remain unchanged. No SDK source files were changed by this compliance update.

## Tested heads

Design base: `6752d10c7b85b4d5ac7bfeaacabb28c9ac1a7c1f`, plus this working-tree
update to the profile contracts, adapters, and generated fixtures.

| SDK | Branch | Commit | Package version |
|---|---|---|---|
| Go | `feat/webbotauth-verification` | `5deca1eeba2f82436f181f7e0ec37a0dbcc05a51` | Local checkout (`dev`) |
| TypeScript | `feat/web-bot-auth-verification` | `73a2b7291b0bdf19096b210f6b81ef34b421b488` | `0.26.0` |
| Python | `feat/wba-request-verification` | `927d0144ef96de732e5c8baabab972d49961de80` | `0.25.0` |

All three SDK working trees were clean. TypeScript used the built distribution;
Python used the editable installation; Go used the local workspace and native
test bridge.

## Results

Full shared run: `2026-10-14T17:38:00Z`.

| SDK | Full shared compliance | WBA expectations | Missing verifier cases |
|---|---|---|---:|
| Go | 311/314 | 118/121 | 0 |
| TypeScript | 313/314 | 120/121 | 0 |
| Python | 314/314 | 121/121 | 0 |

The full run exited with status 1 because four expectations remain unmet. No
known-bug markers or relaxed expectations were added. WBA totals include
signature-base construction, signing, directory serving, and verification.
Uncached alternatives require observed fresh discovery; they do not claim
cache-reuse coverage.

## Go follow-up

1. **Honor dictionary-member extraction for Content-Digest.**
   `wba-base-keyed-digest-without-content` fails: the base for
   `"content-digest";key="sha-256"` contains `sha-256=:YWJj:` instead of the
   selected Item `:YWJj:`. The special case in
   `httpsig/http_signatures.go:658–663` bypasses the ordinary dictionary-member
   extraction immediately below it. Apply the shared field-extraction rules
   rather than adding a WBA-specific workaround.

2. **Snapshot pointed-to configuration values.**
   `wba-sign-configuration-snapshot-flag` fails. `webbotauth.New` stores the
   configuration by value at `webbotauth/webbotauth.go:144`, but its
   `IncludeSignatureAgent` pointer still refers to caller-owned storage. Changing
   that Boolean after construction changes signing policy through
   `webbotauth/webbotauth.go:353–354`. Copy pointed-to values in all WBA
   construction paths; preserve omission/default semantics.

3. **Return ArgumentError for malformed recipient policy.**
   `wba-verify-malformed-required-coverage` fails. The option-validation loop at
   `webbotauth/verification.go:112–114` returns the shared component validator's
   VerificationError for `@unknown`. Translate invalid caller policy to
   ArgumentError at this boundary, without changing wire-evidence error handling.

## TypeScript follow-up

1. **Validate required components in request context.**
   `wba-verify-response-only-required-coverage` fails. The loop at
   `packages/web-bot-auth/src/verify.ts:118` validates component syntax but permits
   response-only `@status`, then reports missing coverage as VerificationError.
   Reject `@status` and components with `req` as ArgumentError before discovery.
   Keep exact parameter equality for valid request coverage requirements.

## Python follow-up

No shared expectation failed at the tested head. This does not establish all
native matrix coverage. Check the remaining native obligations below rather
than treating the shared result as a complete SDK review.

## Adapter scope and remaining coverage

All adapters call native verification. The Python and TypeScript adapters inject
identity evidence and failures at the public resolver boundary. Go calls the
core identity manager with the SDK's native DNS/HTTPS/log fixture dependencies.
Discovery exercises real TLS and the SDK's address guard. The Go bridge uses
native fixture helpers through an overlay without modifying the SDK checkout.
TypeScript buffers fixed fixture response bytes before verification to avoid a
Node stream-bridge cancellation race.

Remaining native obligations include certificate/key-age bounds with zero DNS
TTL, all numeric configuration boundaries, configuration accessor ownership,
and repeated stream replay without retained buffers or lost cleanup. Optional
cache support needs original acquisition/age/deadline tests; the current
adapters perform fresh discovery. Full native SDK suites, live partner
interoperability, and performance benchmarks were not rerun for this update.

Validation completed:

- `git diff --check`
- `.venv/bin/python -m unittest discover -s harness -p 'test_*.py'` — 20 passed
- `.venv/bin/python harness/generate_wba_fixtures.py --check`
- Ruff checks on the changed WBA fixture/adapter/test modules; the existing
  non-executable generator shebang warning was excluded.
- Go shim packages compiled with `go test ./...`.
- Native Go bridge ran with the race detector for all 76 verifier operations.
- TypeScript shim and adapter passed `node --check`.
- Full shared harness run against the heads above.

To reproduce after SDK fixes, rebuild the shims/distribution and run `make run`.
For a smaller iteration, run the harness with `--filter wba --sdks go` or
`--filter wba --sdks ts` after rebuilding the corresponding SDK adapter.
