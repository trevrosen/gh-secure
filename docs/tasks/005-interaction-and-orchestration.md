# 005: Wire confirmation, planning, and summaries

Status: Done
Depends on: 004

## Context

Complete the enablement workflow in the [specification](../spec.md), using the
inspection and mutation components from tasks 003 and 004.

## Scope and non-goals

End-to-end enablement, safety gates, dry-run, and reporting. No release cutover.

## Prompt

> Wire repository permission preflight, private-repository warnings, feature
> selection, single-confirmation and step-by-step modes, --yes, and dry-run.
> Require explicit ruleset-overlap confirmation even with --yes, following the
> approved non-TTY/EOF contract. Keep planning separate from apply so dry-run and
> declined operations cannot reach write methods. Apply in canonical order, retain
> independent failures, stop on cancellation, and render truthful feature and
> sub-operation summaries with host-aware follow-up links and policy advice.
> Map results to approved exit codes. Add command-level offline tests covering
> the complete specification, and document intentional differences from Bash.

## Acceptance criteria

- Default/all/subset invocations and both interactive modes are covered.
- Active rulesets with --yes, declines, EOF/non-TTY, permission denial, private
  repositories, cancellation, and unknown checks have explicit tests.
- Dry-run's transport rejects every write method across all five groups.
- Planned, declined, already-enabled, applied, partial, and failed outcomes remain
  distinguishable; failures cannot produce an all-success summary.
- Tests assert exact exit codes and request counts, not just output substrings.
- Build, test, and vet checks pass without credentials or network.

## Completion record

Completed 2026-10-28.

- Wired production `enable` through the existing lazy dependencies. Flow:
  resolve target, create the client, fetch metadata, warn on private
  repositories, fail closed unless metadata reports admin or maintain
  permission (undisclosed permissions are denied after exactly one request),
  inspect only the selected features (rulesets only with branch protection),
  plan, render the plan, collect every confirmation, then apply or preview,
  look up the advisory policy, and render the summary.
- Planning stays separate from writes. `Approve` collects every decision before
  the first write. Declined and blocked plans resolve without calling execute,
  and dry-run uses `PreviewPlans`, which has no writer. The command fixture
  rejects every write method in dry-run across all five groups.
- Confirmation: one subset confirmation for explicit selections; for the
  default selection, a mode choice (all at once or step by step) only when more
  than one feature needs changes. `y`/`yes`/`n`/`no` are case-insensitive, an
  empty answer declines, and invalid answers re-prompt. Prompts go to stderr
  and read one line without buffering past it. `--yes` answers ordinary
  confirmations only. Non-TTY without `--yes`, EOF, and cancellation abort
  confirmation with exit 1 and zero writes. Unsupported approval modes fail
  closed.
- The active-ruleset safeguard is asked after ordinary confirmations, including
  with `--yes` and in dry-run, and never for a declined feature. An explicit no
  declines branch protection. A non-TTY or EOF answer blocks only branch
  protection (failed, exit 1) while other approved features continue. Unknown
  rulesets block protection without a prompt.
- Outcomes: planned, declined, already enabled, applied, partial, failed, and
  not attempted are distinct in per-feature and per-setting lines and totals.
  Failures dominate declines and successes, so a failure cannot produce an
  all-success summary. Exit 0 covers applied, already-enabled, planned, and
  voluntarily declined results; any failure, partial result, blocked safeguard,
  or interruption exits 1.
- Cancellation during apply keeps accepted writes, marks later features not
  attempted, skips the policy lookup, and exits 1. Cancellation during
  inspection or confirmation sends no writes.
- Summaries include host-aware settings and overview links, the
  private-reporting link only when that setting is applied or already enabled,
  the CodeQL run URL as accepted (not completed) analysis, and the security
  policy URL or an advisory that never changes the exit code.

Intentional differences from Bash:

- Inspection and planning happen before confirmation, so prompts list only
  features that need changes. Already-enabled features are never counted or
  prompted, and nothing is prompted when nothing can be written.
- No extra "proceed step by step?" prompt. The mode choice is offered only for
  the default selection.
- Dry-run follows the same confirmations and safeguards and, without `--yes`,
  needs a terminal. It prints a plan, then a dry-run summary.
- Feature explanations and documentation links appear in the plan for every
  selected feature, without marketing claims.
- An initial decline still renders a summary with declined outcomes and the
  policy advisory and exits 0.
- Prompts are written to stderr so stdout contains only the plan and summary.

Design note: confirmations use a small line reader behind `ui.Approver`
rather than go-gh `prompter`. The interactive prompter would require a real
terminal in tests, and the injected-stream reader keeps the exact non-TTY, EOF,
and cancellation contract deterministic and offline. A later task can swap the
implementation behind the same `security.Approver` interface.

Validation:

- Go 1.27.1: `make check` (module tidy diff, golangci-lint v2.14.0 with 0
  issues, `bash -n gh-secure`, build, offline tests), `make test-race`,
  `make vet`, `make fmt-check`, `go mod verify`, and empty `gofmt -l` passed.
  `go test -count=5 ./internal/...` passed.
- Go 1.26.7 (`GOTOOLCHAIN=go1.26.7`): build, vet, and offline `go test
  -mod=readonly ./...` passed.
- Command-level tests drive `Execute` through the real REST adapter with an
  injected GHES transport and fake credentials. They assert exact exit codes,
  exact prompts on stderr, exact write requests in order, total request counts
  for the permission preflight, and parsed per-feature outcomes. No live GitHub
  settings were read or changed. Module files, the shipping Bash script, and
  release workflows are unchanged.

Review pass:

- Split `Approve` into mode selection and per-feature approval.
- Removed the flag parameter from plan execution.
- Replaced template mutation in `withoutWrites`.
- Shared one terminal-availability check across repository and confirmation
  prompts, with cancellation taking precedence.
- Fixed a nil-error panic path in plan rendering and variable shadowing.
- Made the cancellation test reader idempotent.
- Removed tautological, redundant, and third-party-wording test assertions.
- Made the private-repository stderr assertion exact.

Limitations: the real read adapter still reports legacy protection and
Dependabot alerts as unknown on ambiguous 404s (the accepted 003/004
behavior), so live runs report those settings as failed instead of writing
them. Command tests use an explicit known-disabled inspection wrapper to
exercise their orchestration and real write requests. Task 006 is Ready.
