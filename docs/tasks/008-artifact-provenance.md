# 008: Enable workflow artifact attestations

Status: In progress
Depends on: 005

Implementation authorized 2026-10-30. Maintainer acceptance and any real
Copilot/model-quality evaluation remain pending. The shipping Bash extension
and task 006's release/cutover gates are unchanged.

## Context

`gh secure` enables security best practices. For provenance attestations this
means recognizing adoption and helping add workflow configuration, not
inspecting existing distributions or verifying signatures.

Normal unselected `gh secure`, dry-run and `status` inspect default-branch
workflow sources. Recognizable attestation configuration anywhere means there
is nothing to enable. Stop early and report adoption; do not audit all
publishers, permissions, conditions or subjects.

Without adoption, identify recognized publishing configuration lacking an
identifiable attestation path and distinguish it from scripts/actions/reusable
workflows that need manual review. Caches and ephemeral Actions uploads alone
are not publishing evidence. No recognized publisher is a scoped observation,
not proof that the repository publishes nothing.

Read [CONTRIBUTING.md](../../CONTRIBUTING.md), the [specification](../spec.md)
and [architecture](../architecture/README.md) before changing this feature.

## Scope and non-goals

- Read at most 100 workflows, each bounded to 1 MiB, at one default-branch
  commit. Preserve immutable source selection, deterministic findings and
  early exit on adoption.
- Recognize official build-provenance actions,
  literal npm provenance publishing, explicit Docker provenance and explicit
  PyPI attestations. SBOM attestations never establish provenance adoption:
  continue scanning and retain publisher findings. The unified action only
  counts in default provenance mode, not SBOM or custom-predicate mode.
  Report `adopted`, never `verified`.
- Recognize Docker, npm, PyPI, crates.io, RubyGems and Maven publishing
  configuration, plus shell `gh release create/upload`. Unexpanded release
  Actions and other unknown publishing paths need review.
- Provide optional local Copilot assistance behind explicit content-sharing
  and allowance consent. Validate and print an unapplied patch; never apply,
  commit, push, create a PR or trigger a workflow. Ordinary checks, dry-run and
  existing adoption never invoke a model.
- Initial automatic assistance covers one unambiguous OCI build/push step with
  an identifiable configured subject name and named digest output. The new
  attestation step uses the future build output expression. No existing image,
  package, released file or digest is required.
- Preserve existing settings totals, feature selection, shared target
  resolution and the shipping Bash script.

Explicitly out of scope: registry requests, package manifest/version
resolution, Actions run/job history, existing artifact/attestation retrieval,
Sigstore/TUF trust management and cryptographic verification. Users already
have `gh attestation verify` for verification. Do not duplicate it here.
Gradle and NuGet remain deferred.

## Superseded design history

An earlier implementation expanded the feature into bounded runtime artifact
discovery, public registry digest resolution and Sigstore verification.
It also exposed `--deep-provenance` and `--run-limit`.

On 2026-10-30 the maintainer explicitly clarified that this was outside the
plugin's purpose: enable workflow attestations only; existing adoption means
no work. This decision supersedes all earlier runtime-inspection requirements
and acceptance criteria. The runtime resolver, GitHub run/attestation readers,
registry client, verifier, associated tests and crypto dependencies were
removed from the PR, along with those flags. The `provenance` command now
performs the same source-only adoption check as normal use.

The earlier release-scope decision remains: only recognize shell `gh release
create/upload`, not specific release Actions selected without usage evidence.
Earlier readability work separating adoption recognition, traversal and
finding rendering remains. Pre-PR review also fixed separate Bash syntax
checks and isolated Copilot configuration to prevent configured hooks from
executing despite model-tool denial.

## Prompt

> Keep task 008 focused on enabling workflow attestations. Read default-branch
> sources and stop on recognizable adoption. Otherwise identify publishing
> configuration and provide actionable enablement guidance. Never resolve
> existing artifacts, fetch existing attestations or perform verification.
>
> Optional Copilot assistance must require explicit consent, a clean matching
> checkout and compatible source revision. Run with tools disabled and
> isolated configuration, validate a narrowly scoped additive patch preserving
> existing behavior, and print it without applying it. Ambiguous workflows
> receive manual guidance. Test the boundaries offline without live targets,
> model calls, publishing or repository mutations.

## Acceptance criteria

- Normal unselected use, status and explicit `provenance` use source-only
  checks; explicit settings selectors remain settings-only.
- Existing adoption takes precedence over other findings and prevents any
  assistance attempt. It is not a claim that existing signatures are valid or
  every artifact is covered.
- No production path or dependency performs artifact/registry/attestation
  resolution or cryptographic verification. Removed runtime flags are rejected.
- Workflow read fixtures reject unexpected endpoints and writes, enforce
  immutable source reads and stop retrieval on adoption. Missing/inaccessible
  or malformed source cannot silently become clean results.
- Assistance requires consent and clean matching source, handles cancellation
  and invalid model output explicitly, preserves token permissions/builds/
  publishing, and produces an applicable unapplied patch.
- OCI assistance requires no pre-existing digest: only the configured subject
  name and future publishing-step output. Dynamic or ambiguous subject names
  receive manual guidance.
- Offline tests, lint, build and vet pass; docs and PR description reflect the
  enablement-only scope. No live/model-quality evidence is implied.

## Completion record

The enablement-only correction removes runtime discovery, registry and
verification code and their tests, deletes the Sigstore/TUF dependency graph,
and removes runtime flags/consent prompts. Workflow source reading and
source-based assistance no longer depend on a historical run or existing
artifact. Package publishing recognition, including Twine, is configuration
detection only; no package identity is resolved.

Regression fixtures cover adoption precedence and assistance short-circuiting,
removed-flag rejection, dry-run, immutable bounded workflow reads, configured
subject names (including simple repository expressions), ambiguous publisher
rejection and validated unapplied patches.

Post-correction offline evidence:

- Go 1.27.3 `make check test-race vet vulncheck` passed, including module
  consistency, Go/workflow/Bash lint, build, offline tests, race tests and vet.
  Vulnerability scanning reported no vulnerabilities.
- Go 1.26.7 with `GOPROXY=off GOSUMDB=off` passed
  `go test -mod=readonly ./...` and `go vet -mod=readonly ./...`.
- `git diff --check` passed. CLI help exposes source-only `provenance` and
  consented `assist`, with no runtime-inspection flags.
- `go.sum` is identical to the pre-feature baseline; `go.mod` only promotes
  the existing YAML dependency to direct use. No Sigstore/TUF dependencies remain.

Remaining limitations: the adoption heuristic intentionally accepts conditional,
or incomplete provenance configuration as adoption. Scripts, reusable workflows
and dynamic publishers may need manual review. Automatic patches remain
OCI-only and require explicit effective token permissions. No real Copilot
invocation/model-quality trial or live target test has been performed.

Branch: `trevrosen-task-006-release-preparation`.
Task 006 release preparation remains in the same PR; publication, uploaded
release/install/upgrade/runtime evidence and Bash retirement remain separate
unfulfilled gates requiring their existing approvals.

### Provenance-only adoption and reviewable fixtures

The maintainer clarified that SBOM adoption is not provenance adoption.
Removed `actions/attest-sbom` from early-exit recognition and excluded unified
`actions/attest` configured for SBOM or a custom predicate. SBOM steps do not
make a recognized publisher disappear; source retrieval continues until actual
provenance configuration is recognized. Conditional provenance behavior is
unchanged. Suggestion validation distinguishes the inserted provenance step
from an existing pinned SBOM step, preserving the latter and rejecting its
removal or modification.

Detection tests now include complete workflow fixtures under
`internal/provenance/testdata/workflows/` for SBOM-only publishing (both action
forms), build provenance, native npm provenance, reusable publishing and
upload/cache-only CI. A repository-level case checks provenance precedence
across files; a GitHub read fixture ensures scanning continues past SBOM but
stops on provenance.

The five test files added by this PR now use named fields, readable multiline
YAML/JSON and descriptive subtests rather than compressed positional tables.
Small command-string boundaries remain inline; representative workflow cases
are inspectable files.

Post-change validation passed: Go 1.27.3 `make check test-race vet`,
Go 1.26.7 offline tests for `internal/provenance`, `internal/github` and
`internal/cmd`, and `git diff --check`. No model calls or live target
operations were used.
