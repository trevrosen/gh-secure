# 005: Wire confirmation, planning, and summaries

Status: Blocked
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

Not started.
