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

These paths describe future code, not directories created by this documentation:

```text
cmd/gh-secure/main.go       process entry point and exit-code mapping
internal/cmd/              Cobra root/status commands, flags, dependency wiring
internal/repository/       explicit/current/prompted target resolution and metadata
internal/github/           authenticated REST adapter, DTOs, endpoint error mapping
internal/security/         feature registry, inspection/planning/apply orchestration
internal/security/features/ branch protection, reporting, secrets, Dependabot, CodeQL
internal/ui/               terminal streams, confirmations, human-readable rendering
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

## Test and release strategy

- Table-driven unit tests: aliases, validation, ordering, states, result aggregation.
- HTTP adapter tests: methods, paths, typed bodies, headers, pagination, malformed
  responses, permissions, rate limits, and unavailable settings.
- Command tests: injected streams, fake repository/client/prompter, both prompt
  modes, EOF, non-TTY behavior, `--yes`, help/version, and status.
- Dry-run tests: a transport that rejects every mutating request, not merely
  assertions that output contains "dry run."
- No normal test may require a token, a real repository, or GitHub connectivity.
  Any live mutation smoke test requires a separately approved disposable target.
- Establish build/test/vet CI once Go exists. Validate release asset names and
  a `gh extension install`/upgrade path before retiring the shell entry point.

Pin dependencies and release actions at implementation time. Do not create a
release, tag, or change the default installation path as part of scaffolding.
