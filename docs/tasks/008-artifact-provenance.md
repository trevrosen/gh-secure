# 008: Detect missing artifact provenance and assist local remediation

Status: In progress
Depends on: 005

Implementation authorized 2026-10-30. This is separate from task 006's release
work. The maintainer will review artifact resolution code before any PR is
opened; a critical implementation review is required before that handoff.
Implementation and offline verification are complete; maintainer code review
and acceptance remain pending.

## Context

Users should be able to discover distributable build outputs produced and
published by their repository's GitHub Actions workflows and identify missing
build-provenance attestations as an actionable security finding, alongside the
repository checks already performed by `gh-secure`.

"Artifact" means a software distribution subject in the sense used by
[GitHub artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations):
container images, published packages, release binaries, and other distributed
build outputs. Container images and externally published packages are explicit
targets, not deferred categories. Actions caches and ephemeral workflow artifact
uploads are not the target inventory. An upload may be an intermediate step
toward publishing a distribution, but its presence alone does not establish a
distributed artifact or a missing-provenance finding.

For remediation, offer optional local Copilot assistance to edit the producing
workflow so future artifacts receive provenance attestations. The user reviews
the changes and handles committing, pushing, and opening a pull request.
Detection must not require Copilot or a paid GitHub subscription.

Read the [specification](../spec.md), especially its inspection taxonomy and
safety contract, and the [architecture](../architecture/README.md). Extend those
documents with the approved new behavior before implementing it. The existing
six settings checks and five feature groups retain their totals. The approved
default static check adds source reads and a separate report, never prompts,
model calls or local edits.

## Scope and non-goals

Agreed requirements:

- Discover container images, published packages (including external
  registries), and other distributed outputs built on Actions, and assess
  whether they have build-provenance attestations. Use publishing workflows and
  run evidence to identify these outputs; do not limit discovery to the Actions
  artifacts API.
  Release support is detection-only for `gh release create/upload`; release
  Actions, asset enumeration/resolution and release attestation checks are
  deferred until usage statistics inform adapter selection.
- Do not equate an attestation action appearing in YAML with evidence that a
  particular artifact is attested. Do not flag caches or ephemeral Actions
  uploads merely for lacking attestations.
- Report confirmed missing provenance as a security finding. Distinguish it
  from verified provenance, unavailable/unsupported checks, incomplete
  inspection, and repositories where no relevant artifacts were observed.
- Keep detection deterministic and independent of model access.
- Offer optional, explicitly consented local Copilot-assisted workflow edits.
  Use the user's authenticated Copilot access and remaining allowance; do not
  assume a paid plan, a particular model, or a fixed number of free requests.
- Leave review, commits, pushes, and PR creation to the user. Explain that
  workflow changes affect future builds and do not retroactively attest earlier
  artifacts.

Non-goals:

- Hosted Copilot task assignment, automatic PR creation, commits, pushes,
  merges, or changes to repository settings.
- Running workflows, rebuilding or executing downloaded artifacts, publishing
  releases/packages, or generating attestations from the developer's machine.
- Claiming provenance establishes that an artifact is safe or vulnerability-free.
- Exhaustive historical coverage, all package registries, arbitrary build
  systems, or GHES support without an explicitly approved expansion of scope.
- Replacing or retiring the shipping Bash extension.

## Decision gates before implementation

The original design questions and implementation choices are recorded below.
The maintainer explicitly selected the registry scope and initially separate commands;
the later workflow-first default decision below supersedes command isolation.
the bounded window proposal was skipped, so implementation uses the documented
conservative defaults rather than claiming that a window was explicitly chosen.

1. **Publication discovery and registry coverage.** Container images, externally
   published packages are in scope; releases are limited to `gh` publication
   detection by the maintainer's later scope reduction. Determine the initial
   registry/package ecosystems and publishing patterns the tool can inspect
   reliably, including external registry authentication and immutable artifact
   identity. Establish how each published output is linked to its producing
   run, workflow revision, and digest. Report unsupported publishing patterns or
   inaccessible registries as coverage gaps, not as evidence of absent outputs
   or absent attestations. Do not substitute ephemeral Actions upload inventory
   for discovery of distributed software.
2. **Inspection window.** Choose bounded run selection and pagination limits,
   including branches, successful/failed runs, deleted or unavailable published
   versions. Release history is not enumerated. Output must disclose the inspected window and any
   truncation, rather than claiming the entire repository is covered.
3. **Evidence and availability.** Verify GitHub's current APIs, authentication,
   public/private repository entitlement, and digest/attestation semantics.
   Define when absence is established, how the attestation subject maps to
   published file/package digests and container image manifests or indexes,
   and what provenance verification must validate about repository/workflow
   identity. Mutable tags alone are not immutable artifact identities. Permission failures,
   unavailable digests, and inconclusive searches must remain unknown.
4. **CLI and exit contract.** Decide whether this is an opt-in feature,
   separate subcommand, or default status check; define selection/aliases,
   summary counts, exit codes, and dry-run behavior. Local assistance must be
   separately requested, never a side effect of status or ordinary enablement.
5. **Local assistance interface.** Evaluate Copilot CLI programmatic mode versus
   the Go SDK before choosing one. Define checkout requirements, allowed
   workflow/helper-file edits, usage disclosure, cancellation, and how the
   proposed diff is presented. No unattended model-selected shell execution or
   remote writes. Define whether assistance may prepare a patch rather than
   applying edits directly.

## Prompt

> Read CONTRIBUTING.md, the specification, architecture, and this task. First
> resolve the decision gates with the maintainer and record the approved
> behavior in the specification; do not choose an AI integration merely because
> it is available. Verify current official publication/discovery, registry, and
> attestation APIs and their support/entitlement requirements. Target distributed
> software, not Actions caches or ephemeral workflow uploads.
>
> Implement bounded, read-only artifact discovery and provenance assessment,
> with evidence-linked findings and explicit unknown/unsupported/coverage
> outcomes. Reuse repository resolution, authenticated GitHub API access, error
> handling, and CLI/UI boundaries. Do not download large artifact bodies
> implicitly or execute artifacts.
>
> Add optional local Copilot-assisted remediation behind explicit consent.
> Supply the relevant workflow revision and finding evidence, treat repository
> contents and logs as untrusted input, constrain file/tool permissions, and
> propose minimal workflow edits to attest the intended build outputs with
> narrowly scoped permissions. Preserve existing build and publishing behavior;
> explain any permission additions and pin reviewed action revisions.
>
> Require a local checkout matching the selected repository and a compatible
> workflow revision. Preserve pre-existing local changes; refuse conflicting
> edits rather than overwriting them. Missing Copilot, authentication failure,
> exhausted quota, cancellation, and invalid generated changes must produce
> actionable diagnostics, leave detection usable, and never be reported as a
> successful repair. Provide manual guidance when assistance is unavailable.
>
> Validate generated changes structurally and against the finding before
> presenting them as ready for review. Explain what remains unverified until
> the user merges the changes and a subsequent build produces verifiable
> provenance. Never commit, push, create a PR, trigger a run, or attest an
> artifact. Add offline tests and update directly related documentation. Record
> actual evidence and remaining limitations without treating model-generated
> text or YAML presence as proof of remediation.

## Acceptance criteria

- Normal unselected use and status perform source-only attestation adoption
  discovery, stopping at recognizable configuration without claiming runtime
  verification or complete coverage. If no adoption is found, recognized
  publishers lacking identifiable paths are distinct from unresolved code.
  `--deep-provenance` cannot invoke runtime inspection without separate consent;
  dry-run, decline, EOF and nonterminal input cannot trigger escalation.
- Maintainer decisions and resulting CLI/API/evidence contracts are recorded
  before implementation. Existing command behavior and shipping Bash remain
  unchanged except for explicitly approved additions.
- Offline fixtures cover container image publication, external package
  publication, and detection-only `gh release` commands across multiple workflows/runs, correct
  producer association, pagination and truncation, unavailable/deleted published
  versions, no distributed outputs, permission/rate-limit failures, unavailable
  APIs, and missing or ambiguous digests. Caches and ephemeral workflow uploads
  alone do not produce missing-provenance findings.
- Provenance fixtures cover verified subjects, confirmed absence, mismatched
  digests/identities, malformed or unverifiable attestations, and inconclusive
  lookup. An SBOM or unrelated attestation alone does not satisfy the
  build-provenance requirement.
- Findings identify the artifact, producing run/workflow where established,
  evidence, and remediation guidance. Coverage limits and unknowns are visible;
  no-artifacts and inaccessible-artifacts cases cannot become a false clean bill
  of health.
- Detection works without Copilot and sends no mutating GitHub requests.
  Status and dry-run never invoke a model or edit local files.
- Assistance requires explicit consent and compatible local context. Tests
  cover unavailable CLI/SDK, missing authentication, quota exhaustion, dirty or
  mismatched checkouts, cancellation, unsafe tool requests, unexpected file
  edits, and malformed/inapplicable generated patches.
- Assisted output targets the intended artifact paths/digests and producing job,
  explains required OIDC/attestation permissions, and preserves workflow
  behavior. Unsupported or ambiguous workflows receive guidance rather than
  speculative automatic edits.
- The tool presents the proposed diff and next steps, never creates a PR or
  commits/pushes changes, and continues reporting the original finding until
  subsequent evidence establishes that artifacts are attested.
- Normal tests are offline and credential-free, using fake Copilot responses.
  Build, lint, vet, and relevant regression tests pass. Any live evaluation or
  model-quality trial requires separately approved targets/access and records
  its limitations; fixture tests alone do not prove model-generated edit quality.

## Completion record

Implementation and offline verification completed on 2026-10-30. Maintainer
review and acceptance remain pending. No live target evaluation, model-quality
trial, publication, or PR creation has been authorized or performed.

Decisions:

- The maintainer initially selected GitHub Releases, GHCR/Docker Hub, npm, PyPI, crates.io,
  RubyGems, and Maven Central. Initial external registry reads are public and
  anonymous; private registries and unrecognized publishing patterns remain
  visible coverage gaps.
- The maintainer subsequently narrowed releases to detecting `gh release create`
  and `gh release upload` shell commands. Removed softprops/precompile release
  adapters, release/asset API reads, producer matching and `--release-limit`.
  Other `gh release` operations do not count as publication. Release Actions
  remain generic unsupported coverage until usage statistics guide future
  adapters. No release assets or their attestations are inspected.
- The maintainer revised the initial separate-command design: normal unselected
  `gh secure`, dry-run and `status` now perform static default-branch workflow
  configuration inspection. Source is pinned to one commit, bounded to 100
  workflow files, with no recent-run enumeration or registry reads. Recognized
  attestation configuration anywhere causes an early "adopted" result, including
  official attestation actions and explicit supported publisher-native settings.
  The maintainer explicitly accepted this adoption heuristic: it does not
  validate every subject/permission/condition or best-practice edge case.
  Without adoption evidence, publishers missing identifiable paths and unexpanded
  scripts/actions/reusable workflows remain findings. No configuration is
  claimed as verified runtime provenance. Other branches/history and
  publisher-native provenance are explicitly outside this static assessment.
  Settings totals and explicit feature selection remain unchanged.
- `--deep-provenance` on normal unselected invocation or status enables an offer
  after unresolved static findings. A separate default-no confirmation describes
  the bounded run and registry work. `--yes` cannot approve it, dry-run
  suppresses escalation, and decline/EOF/nonterminal input never triggers it.
  Explicit `gh secure provenance` remains the noninteractive opt-in. Runtime
  verification does not erase the static configuration finding.
- Explicit `gh secure provenance` and `gh secure provenance assist` remain for
  deeper inspection and consented patch authoring. Runtime inspection defaults
  to the latest 20 completed runs across
  branches, including failures. `--run-limit` allows 1-100.
  Reaching a bound or incomplete job listings is explicitly reported.
- Assessment concerns GitHub-hosted SLSA build provenance for immutable SHA256
  subjects. Missing means a successful, complete, explicitly empty GitHub
  provenance lookup for a resolved publication, not proof that no
  registry-native attestation exists. A 404, missing fields, unsupported digest,
  ambiguous producer, or failed cryptographic verification remains unknown.
  Public-good Sigstore verification checks signature, transparency inclusion,
  timestamp, digest, and authenticated repository/workflow/source/run identity.
  Private-repository trust and GHES are initially unsupported.
- Local assistance uses Copilot CLI programmatic mode rather than adding the
  SDK runtime dependency. It receives workflow/evidence text in an empty
  temporary directory, with all model tools disabled, and returns a constrained
  suggestion. It never sees the checkout as its working directory. Suggestions
  are validated and printed as unapplied patches; no file changes, commits,
  pushes, PRs or workflow runs occur. Explicit `--consent` discloses content
  sharing and account allowance usage. Dry-run never invokes Copilot.
- Initial automatic suggestions cover unambiguous OCI build/push digest outputs
  and preserve explicit effective token permissions. Package/release publishers,
  dynamic expressions and ambiguous outputs receive manual guidance rather
  than speculative edits.

### Critical review and corrections

A read-only critical code review identified Docker Hub short references being
rejected and `rubygems/release-gem` being recognized without a usable static
identity resolver. Short references now normalize to `docker.io` (including
`library/` for single-component names) in discovery and assistance. The RubyGems
release action now explicitly reports unsupported gemspec evaluation; literal
`gem push pkg/name-version.gem` remains supported. Regression fixtures cover both.

The final integration review also tightened uncertain producer evidence:
earlier arbitrary scripts/actions retain source-mutation uncertainty; expanded
distributions respect the total 200-output bound. The earlier filename/tag
release matching was subsequently removed entirely by the approved scope reduction.
Normal settings and workflow checks share one resolved repository target,
avoiding duplicate repository prompts or a change of target between reports.
The early adoption heuristic intentionally does not validate attestation
conditions/permissions/subjects; this is the maintainer's approved product
tradeoff, not evidence that these best practices were verified.

### Actual offline evidence

- With Go 1.27.3 selected on `PATH`, `GOROOT` unset and
  `GOTOOLCHAIN=local`, `make check test-race vet vulncheck` passed.
  This includes dependency tidy-diff, Go/action/shell lint, build, credential-free
  offline tests, race tests and vet. `govulncheck` reported zero affected
  vulnerabilities; it additionally reported one imported-package and three
  required-module vulnerabilities not called by this program. New transitive
  dependencies were updated to `golang.org/x/net v0.60.0` and
  `google.golang.org/grpc v1.83.1` rather than suppressing findings.
- Go 1.26.7 with `GOPROXY=off GOSUMDB=off` passed
  `go test -mod=readonly ./...` and `go vet -mod=readonly ./...`.
  The declared source floor, go-gh and Cobra pins are preserved.
- `scripts/build-release.sh v0.0.0-task008-check` built all six approved
  OS/CPU targets using Go 1.27.3. The native macOS arm64 binary printed
  `gh-secure v0.0.0-task008-check`; `file` identified the expected six
  architectures. This was a local build label, not a Git tag or published
  release. Other-platform launches, installation and upgrade were not tested.
- Command fixtures cover default/status routing without runtime enumeration,
  explicit deep-scan flag propagation, separate consent, default-no, EOF,
  nonterminal input, dry-run suppression and preserving the original finding.
  HTTP fixtures enforce immutable source reads, no mutating requests and
  stopping further workflow reads once adoption evidence is encountered.
- Cryptographic fixtures verify a real signed upstream public-good bundle
  against offline trust and reject tampered signatures, subjects, authenticated
  identities, predicates and transparency evidence. Copilot fixtures test
  constrained unapplied patches and incompatible/dirty/concurrently modified
  checkouts; an accepted patch passes `git apply --check`.
- CLI help was inspected locally without invoking a model. `git diff --check`
  passed. The root shipping Bash extension is unchanged.
- After narrowing releases to `gh` detection, Go 1.27.3
  `make check test-race vet` passed again. Regression fixtures distinguish
  `gh release create/upload` from list/view/download/delete, classify release
  Actions as unsupported, retain detection-only findings without digest
  verification, and reject the removed `--release-limit` flag. The GitHub
  adapter no longer exposes or calls release/asset endpoints.
- The readability follow-up keeps `ScanWorkflow` focused on sorted job/step
  traversal and publisher dispatch. Helpers separately assemble producer
  evidence, expand OCI identities, select working directories and resolve
  packages. Publisher-exclusion and source-change predicates remain distinct.
  Unsupported gemspec handling precedes resolution; unsupported manifest kinds
  are rejected before file reads, and the unused hard-coded gemspec path is gone.
  Existing findings/diagnostics and ordering are preserved. Added regression
  cases for directory precedence, distinct action policies and exact OCI
  diagnostics. Go 1.27.3 `make check test-race vet` and `git diff --check`
  passed after this refactor.
- A second comprehension pass moved repository-wide adoption precedence out of
  command wiring into `CheckWorkflowSources`, split adoption recognition from
  traversal, and separated per-step configuration findings. Runtime per-run
  discovery and local patch authoring are now helpers distinct from their
  orchestration. Regression fixtures preserve adoption precedence over malformed
  sibling workflows, sorted finding order, native-setting recognition boundaries,
  incomplete execution evidence and failure diagnostic order. Go 1.27.3
  `make check test-race vet` and `git diff --check` passed after this pass.
- Gradle and NuGet were discussed but explicitly deferred by the maintainer.
  Registry-of-record coverage aligned with Dependabot is a future direction;
  no new ecosystem support or package downloads were added. The architecture
  documents the small detection/identity/registry extension points without adding
  a generalized plugin framework.

### Remaining limitations and review handoff

The full pre-PR review covered tracked edits and all untracked additions,
including task 006 release preparation, command wiring, GitHub/registry reads,
cryptographic trust, assistance validation and documentation. Fixes:

- Split the Makefile's `bash -n` invocation: Bash parses only its first script
  operand, so the former two-operand command did not validate the release script.
- Isolate Copilot state with a temporary `COPILOT_HOME`, explicitly disable
  all user/repository hooks and IDE auto-connect, and omit user MCP/plugin
  configuration. Tool denial alone does not prevent configured hooks from
  executing. Authentication may require an explicit token rather than saved
  login state. A regression test checks the actual command construction,
  isolated settings, stripped ambient overrides and tool-denial flags without
  launching a model or consuming allowance.
- Classify shell `twine upload` as unsupported instead of implying resolved
  PyPI support and then unconditionally adding an unsupported-script problem.
  The PyPI action remains supported; a regression test ensures Twine receives
  review/unsupported findings and performs no speculative manifest lookup.

After these fixes Go 1.27.3 `make check test-race vet vulncheck` passed, with
zero affected vulnerabilities (one imported-package and three module
vulnerabilities not called by this program). Go 1.26.7 offline tests/vet and
`git diff --check` also passed on the final changes.

- No real target assessment or real Copilot-generated suggestion has been
  evaluated. Fixture success does not establish model quality, account
  entitlement, current CLI/provider behavior, or live registry/API compatibility.
  Any such trial needs separately approved targets/access.
- The default adoption check intentionally stops at the first recognizable
  attestation configuration, including SBOM as awareness. It can miss other
  unattested outputs and broken or skipped attestation steps. It reports adoption
  only, never verified provenance. Unrecognized scripts/actions/reusable workflows
  remain review gaps if no adoption evidence is found.
- Deep inspection is public-only for registry metadata and public-good GitHub
  trust. Private registries/repository trust and GHES are unsupported. npm
  versions exposing only SHA512 integrity remain unknown rather than downloading
  package bytes. Maven covers literal root coordinates and the primary JAR,
  not inherited/multi-module/classifier outputs. Runtime-modified manifests,
  dynamic expressions and replaced outputs retain uncertain association.
- Automatic patch suggestions remain limited to unambiguous OCI outputs with
  explicit effective token permissions; package/release edits require manual
  guidance. No change retroactively attests earlier distributions.
- Review entry points: `internal/provenance/configuration.go` (default adoption),
  `internal/github/workflows.go` (source selection/early exit),
  `internal/provenance/workflow.go` (workflow-to-publication resolution),
  `internal/provenance/registry.go` (immutable registry identities),
  `internal/provenance/inspect.go` and `verify.go` (runtime evidence), and
  `internal/provenance/assist.go` (local suggestion boundary).

Branch: `trevrosen-task-006-release-preparation`. Task 006 preparation and task
008 implementation coexist uncommitted on this session branch. No PR will be
opened before maintainer inspection. Task 006's publication, install/upgrade,
runtime-matrix and Bash-retirement gates remain separate and unfulfilled.
