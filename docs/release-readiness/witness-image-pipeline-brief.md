# Brief: c2sp-ledger-witness — remove AWS/ECR from the public repo

Handoff for whoever owns the container/deploy pipeline. Context lives in `STATUS.md` (W1, W5).

## Goal

`Identity-Digital/c2sp-ledger-witness` is going public. It is the witness binary partners will run
independently for the DNSid transparency log. Two requirements from the release review:

1. Nothing in the public repo may reference our AWS infrastructure (Legal review §1: "infrastructure
   detail, security-sensitive configuration").
2. The public repo's CI must not push to our private ECR or hold cloud credentials in scope.

Separately, partners need a **public, verifiable image** to run (`PARTNER_HOSTING_REQUIREMENTS.md`
already says `<image-by-digest>` but nothing public exists), and the InfoSec checklist requires
signed artifacts, SBOM, and build provenance for official releases (OSS-003/010/011/012).

## Findings

- All AWS coupling is in **one file**: `.github/workflows/build-image.yml`. It contains the AWS
  account ID, the IAM role ARN (`dnsid-ci-app`), the ECR repository name, and region. It runs
  `on: push` for **every branch**, with `id-token: write`, assumes the role via GitHub OIDC, and
  pushes `sha-<short>` tags to ECR.
- Nothing else in the repo references AWS, ECR, or EKS: not the Go code, Dockerfile, README, or partner
  doc. The `/healthz` endpoint added in the same PR (#3) is generic and stays.
- The Dockerfile is already partner-appropriate: multi-stage, `scratch` base, static binary, non-root
  `65532`, `EXPOSE 7667`.
- The file (and the account ID) is present in **4 of the repo's 11 commits** (`4cdfdff` onward).
- No releases, tags, or public images exist today. Nothing to migrate.

## Proposal

**In the public repo (`release-readiness` branch, not yet pushed):**

1. Delete `.github/workflows/build-image.yml`.
2. Add `release.yml`, triggered on `v*` tags:
   - build the existing Dockerfile for `linux/amd64` (+`arm64` if cheap)
   - push to `ghcr.io/${{ github.repository }}` using `GITHUB_TOKEN` only — no cloud credentials
     anywhere in the repo, ever
   - cosign keyless signature on the image (`sigstore/cosign-installer`, OIDC identity = the workflow)
   - CycloneDX SBOM (`anchore/sbom-action`, as the SDKs do) attached to the GitHub Release
   - all actions SHA-pinned (repo convention; `ci.yml` already follows it)
   - `${{ github.repository }}` in the image path so it follows the repo if the org changes (see W2 —
     the GitHub org / Go module path is an open decision and must be settled before publish)
3. Update `PARTNER_HOSTING_REQUIREMENTS.md` §8: replace `<image-by-digest>` with the GHCR path and
   add the `cosign verify` one-liner partners run before pulling.

**On the private side (not in this repo):**

4. Point the internal EKS deploy at the public GHCR image **by digest** (or build from a pinned tag
   of the public repo, if you'd rather not depend on GHCR). Wherever that pipeline lives — likely the
   platform monorepo — is where the ECR push belongs if you still want a mirror.
5. Remove the OIDC subject `repo:Identity-Digital/c2sp-ledger-witness:*` from the `dnsid-ci-app`
   role's trust policy. Once public, that repo must not be able to assume anything in our account.
   Consider renaming the role/ECR repo if the names themselves are considered sensitive.

## Ramifications

- **History.** Deleting the file does not remove the account ID from commits `4cdfdff`..`caf588f`.
  Two options: (a) publish history as-is — AWS's position is that account IDs are not secrets, and
  step 5 makes the role unassumable; or (b) publish a **clean snapshot** (squash to one commit). With
  11 commits and no external consumers, (b) costs nothing here; recommended, but it is a recorded
  decision (`STATUS.md` decision #2), not an engineering default.
- **Do not push `release-readiness` before deleting the workflow** — `on: push` will fire one more
  ECR build from the public-to-be branch.
- **Deploy dependency flips.** Today internal deploy consumes our own ECR build. After this, it
  consumes a public artifact (or a source build). Pin by digest, not tag; GHCR availability becomes
  a deploy-time dependency unless mirrored.
- **Trust anchor for partners.** Cosign keyless ties image authenticity to *this GitHub repo's
  workflow identity*. That means the org/repo name in the certificate is what partners verify —
  another reason W2 (org decision) has to precede the first tagged release.
- **Reproducibility.** Not required now (OSS-022 is Should/P2). `-trimpath -ldflags="-s -w"` and a
  pinned base image get most of the way; note it as future work.
- **Cost / ops.** GHCR is free for public images. Cosign/SBOM add ~1 min to the release job. No
  new accounts — everything runs on `GITHUB_TOKEN`.

## Open questions for you

1. History: snapshot or keep? (see Ramifications)
2. Should internal deploy consume the GHCR image, or build from source? Either satisfies the
   review; the former is less duplication, the latter removes the GHCR dependency.
3. Multi-arch (`arm64`) — worth it for partners, or `amd64` only?
4. Who owns the `dnsid-ci-app` trust-policy change (step 5)?
