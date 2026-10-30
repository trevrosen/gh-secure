# Go extension architecture

Status: proposed implementation design. The Go extension foundation and library
preference are recorded in [ADR 0001](decisions/0001-go-extension-foundation.md).
Behavior is governed by the [specification](../spec.md).

## Goals and constraints

- Ship a compiled `gh-secure` extension invoked as `gh secure`.
- Use small, testable Go packages rather than translating shell globals into Go.
- Share GitHub CLI authentication, repository selection, API, and terminal
  conventions without importing its command application wholesale.
- Make inspection, confirmation, mutation, and reporting separate operations.
- Preserve explicit safety checks and report failures without false success.

## Intended layout

Task 002 establishes the entry point, command/UI boundaries, and ordered feature
registry. Task 003 adds repository resolution, the read adapter, typed inspection
results, and status rendering. Task 004 adds inspection-derived feature plans,
typed writes, and independent operation results. Task 005 adds confirmation,
orchestration, and enablement summaries. Release integration remains task-006
work:

```text
cmd/gh-secure/main.go       process entry point and exit-code mapping
internal/cmd/              Cobra root/status commands, enable handler, flags, wiring
internal/repository/       explicit/current/prompted target resolution and metadata
internal/github/           authenticated REST adapter, DTOs, endpoint error mapping
internal/security/         feature registry, inspection, feature planning/apply/results
internal/ui/               terminal streams, confirmations, human-readable rendering
internal/provenance/       workflow configuration, publication discovery, registry identities, verification and patch suggestions
testdata/                  sanitized shared fixtures only when needed
docs/                      specification, architecture decisions, task prompts
```

Keep tests beside the packages they exercise. Use package-local `testdata` for
fixtures that are not shared. Do not introduce a public `pkg/` API, plugin
framework, generic dependency container, or one package per trivial type.

## Dependency policy

| Concern | Preferred building block |
| --- | --- |
| Commands and flags | `github.com/spf13/cobra`, also used by `cli/cli` |
| Repository and host selection | `github.com/cli/go-gh/v2/pkg/repository` |
| Authenticated REST and host routing | `github.com/cli/go-gh/v2/pkg/api`, with `pkg/auth` only where needed |
| Terminal and table conventions | `github.com/cli/go-gh/v2/pkg/term` and `pkg/tableprinter` where appropriate |
| Confirmation prompts | Evaluate `github.com/cli/go-gh/v2/pkg/prompter` behind the UI boundary |
| HTTP fixtures | `net/http/httptest`; evaluate `github.com/cli/go-gh/v2/pkg/api` test facilities before adding another library |
| Release binaries | `cli/gh-extension-precompile`, configured for `./cmd/gh-secure` |

Use the standard library for contexts, JSON, errors, HTTP test servers, and simple
formatting. Check actual exported APIs and compatible versions during
implementation. Shared origin alone is not justification for a new dependency.
Avoid `github.com/cli/cli/v2/internal/...` (not importable here), and require an ADR
before importing other `cli/cli/v2` application packages. Do not implement a
separate token store or login flow. Direct REST calls are preferred over
subprocesses running `gh api` and parsing its output.

## Responsibilities and dependency direction

`main -> cmd -> security -> feature implementations -> GitHub adapter`

The command layer also wires repository resolution and UI implementations.
Define small interfaces at their consumers, extracting them when real tests or
implementations need them. Core feature logic must not depend on Cobra, terminal
globals, or process exit calls.

- **Repository:** carries host, owner, name, default branch, visibility, and known
  permission information. Resolve once per command; do not default a failed
  metadata lookup to branch `main`.
- **GitHub adapter:** owns request paths, typed payloads, pagination, host-specific
  URLs, and response/error decoding. Encode branch names correctly as path
  parameters. Never treat every HTTP error as "disabled."
- **Feature implementations:** inspect current state and describe/apply missing
  operations. Keep the five canonical names and aliases in one ordered registry.
  Feature plans live in `internal/security`, depend on a narrow `Writer`
  interface, and snapshot inspections without I/O. Only known-disabled settings
  may invoke the writer; unknown/unsupported states remain failures. Keep simple
  feature mappings together instead of creating trivial per-feature packages.
- **Orchestrator:** selects and deduplicates features, obtains confirmations,
  prevents writes in dry-run, applies operations sequentially, and aggregates
  results. It preserves sub-operation results for Dependabot.
- **UI:** owns explanatory text, prompts, status output, summaries, and next-step
  links. Inject input/output/error streams and prompt capability.

## State and execution model

Use typed states, not shell return codes or booleans alone:

- Inspection: enabled, disabled, unknown, or unsupported, with diagnostic context.
- Execution: already enabled, planned (dry-run), enabled, declined/skipped,
  failed, or partially enabled.

Carry individual check/operation results so that a feature group cannot hide a
failed sub-operation. An active ruleset is advisory metadata, not proof that the
default branch satisfies the legacy protection baseline.

Enablement flow:

1. Parse and validate input without network calls.
2. Resolve target and authenticated client; inspect repository metadata and
   permission eligibility.
3. Inspect selected features and construct operations for missing settings.
4. Collect mode/feature confirmations, including the explicit ruleset safeguard.
5. For dry-run, render planned operations without executing any mutations.
6. Otherwise apply approved operations in canonical order; preserve independent
   failures for the summary. Stop on cancellation or a fatal prerequisite failure.
7. Render actual outcomes and map them to the approved exit-code contract.

`status` performs inspection only and does not require the enablement permission
preflight. Thread `context.Context` through network operations; connect interrupt
handling at the entry point. Do not automatically retry writes, roll back settings,
or report asynchronous CodeQL configuration as a completed successful analysis.
Avoid persistent response caching of security settings.

Task 008 adds a workflow-first configuration check to normal unselected
enablement, dry-run, and status, reported separately from the settings registry.
`internal/github/workflows.go` resolves default-branch source to an immutable
commit and `internal/provenance/configuration.go` discovers publication and
attestation adoption without run or registry requests. Source retrieval stops
at the first recognized adoption evidence; this intentionally does not establish
complete publisher coverage or validate best practices. Unexpanded scripts,
actions and reusable workflows are review gaps. Configuration never establishes
actual artifact provenance. Explicit feature selectors remain settings-only.
The explicit `provenance` command performs the same adoption check.
There is no deeper artifact-inspection path: run enumeration, registry
resolution, attestation retrieval and cryptographic verification are outside
the product's enablement scope. Verification belongs to `gh attestation verify`.
Release recognition only detects `gh release create/upload` in shell text;
release Actions require manual review pending evidence-driven adapter selection.

Keep extension points concrete rather than introducing an ecosystem plugin
framework. To add an ecosystem, update source-level publisher recognition in
`workflow.go` and its enablement guidance. Add adoption recognition in
`configuration.go` only when there is a known explicit attestation setting.
Each addition needs fixtures for publishing configuration, explicit adoption
and dynamic/unsupported inputs, without executing build scripts or resolving
existing artifacts. Gradle and NuGet remain deferred; Dependabot's
ecosystems with registries of record are a coverage roadmap, not a claim that
dependency-update support implies provenance support.

`CheckWorkflowSources` owns repository-wide adoption precedence and deterministic
finding order; command handlers retrieve sources, render results and dispatch
explicitly consented enablement assistance only when no adoption exists.
`AssistanceTarget` selects one static OCI publisher; `publisherSubject` extracts
its configured image name. It does not resolve a tag or fetch a digest:
the proposed step uses the publishing step's future `outputs.digest` expression.
Copilot is optional and receives text with no tools in an empty scratch
directory with isolated Copilot state. Explicit settings disable hooks and IDE
auto-connect; ambient executable configuration is not inherited. Authentication
may require an explicit token because saved login state is not copied.
A constrained validator permits only an additive pinned OCI
attestation step and scoped permissions. The resulting patch is printed, not
applied. User checkout, remote, source SHA and concurrent changes are checked
outside the model boundary.

## Test and release strategy

- Table-driven unit tests: aliases, validation, ordering, states, result aggregation.
- HTTP adapter tests: methods, paths, typed bodies, headers, pagination, malformed
  responses, permissions, rate limits, and unavailable settings.
- Command tests: injected streams, fake repository/client/prompter, both prompt
  modes, EOF, non-TTY behavior, `--yes`, help/version, and status.
- Dry-run tests: a transport that rejects every mutating request, not merely
  assertions that output contains "dry run."
- No normal test may require a token, a real repository, or GitHub connectivity.
  Remote-discovery tests may construct an isolated temporary git repository.
  Any live mutation smoke test requires a separately approved disposable target.
- CI runs the Makefile targets: build, offline tests, and vet on Linux, macOS,
  and Windows; the race detector on Linux; lint (including actionlint) and
  govulncheck on the current Go release. Validate release asset names and a
  `gh extension install`/upgrade path before retiring the shell entry point.

Pin dependencies and release actions at implementation time. Do not create a
release, tag, or change the default installation path as part of scaffolding.
