# 004: Implement typed feature mutations

Status: Done
Depends on: 003

## Context

Implement the five feature groups in the
[API inventory](../spec.md#feature-and-api-inventory) behind the architecture's
feature and GitHub adapter boundaries.
Task 003's [verified read semantics](../spec.md#verified-read-semantics-task-003-2026-10-26)
retain ambiguous protection/Dependabot 404s as unknown and do not infer a missing
policy from undocumented community-profile fields. Never turn those results
into missing-state writes; validate any additional evidence before using it.

## Scope and non-goals

Inspection-derived operations and typed mutation adapters. Keep public enablement
unavailable until task 005 wires confirmations and dry-run safety.

## Prompt

> Implement operations for legacy branch protection, private vulnerability
> reporting, secret push protection, both Dependabot settings, and CodeQL default
> setup. Reuse inspection state and skip unnecessary writes. Send the specified
> typed JSON once per necessary operation; do not port the shell's duplicate
> private-reporting PUT or branch-protection fallback request. Preserve existing
> protection instead of reconciling it, and never mutate rulesets. Capture
> Dependabot sub-operation outcomes and partial failures. Preserve CodeQL run_url
> without claiming analysis completion. Test exact methods, paths, request bodies,
> and error handling with local fixtures. Do not wire an unconfirmed CLI write path.

## Acceptance criteria

- All five groups have exact payload/method/path tests and no-op enabled tests.
- Dependabot covers each one-setting-missing case and both partial-failure orders.
- Permission, unavailable-feature, malformed-response, and write failure tests
  preserve diagnostic context and never report success on failure.
- No implicit write retry, rule editing, workflow creation, or real API call.
- Existing status tests still prove zero mutations.

## Completion record

Completed 2026-10-28.

- Verified all six mutation contracts against official REST documentation and
  public OpenAPI schemas; recorded sources and response limitations in the
  [specification](../spec.md#verified-mutation-semantics-task-004-2026-10-28).
- Added typed single-request adapters for the branch-protection baseline,
  private reporting, push protection, both Dependabot settings, and CodeQL
  default setup. Bodyless PUTs remain bodyless, branch names are escaped, and
  CodeQL accepts documented 200/202 objects with optional tracking fields.
  Preserved a supplied HTTPS run URL without claiming completed analysis.
- Shared request serialization, strict response decoding, and safe error mapping
  with the read adapter. Diagnostics preserve methods, paths, HTTP statuses,
  cancellation, and typed HTTP errors without exposing bodies or credentials.
  Write redirects are refused to prevent replay or method changes.
- Added immutable inspection-derived feature plans and a narrow writer boundary
  in the existing security package rather than introducing trivial per-feature
  packages. Plans perform no I/O, skip enabled settings, and never write from
  unknown/unsupported inspections. Missing/duplicate/invalid inspections fail
  explicitly. Branch writes require known rulesets and explicit overlap approval
  when active rulesets exist; existing protection is not reconciled.
- Added individual operation and feature outcomes. Dependabot preserves both
  outcomes and typed failures, continues independent operations after a failure,
  and reports partial results instead of success. Cancellation stops further
  writes while preserving earlier accepted operations; cancellation that
  arrives during or after the final accepted write does not turn a fully applied
  feature into a partial one.
- Review follow-up: feature-to-setting mapping now lives in the feature registry
  (with a test keeping it aligned with status display order), bodyless PUTs share
  one helper, read-only and write test fixtures are separate helpers, and new
  exported identifiers and tests carry doc comments.
- Added offline exact-method/path/payload/status tests, no-op tests for all five
  groups, both one-setting-missing Dependabot cases, both partial-failure orders,
  both failures, mixed unknown/disabled settings, permission/availability/rate
  limits, malformed responses, safe diagnostics, redirect refusal, input
  validation, and cancellation. Adapter/plan integration tests prove ambiguous
  404s cannot produce writes and existing protection is preserved.
- Kept CLI enablement, `--yes`, and `--dry-run` unavailable. Extended real
  dependency-wiring tests to prove they still fail before inspection or writes.
  Existing status tests continue to reject all mutations.

Validation:

- Go 1.27.1: `make check`, `make test-race`, `make fmt-check`, and `go mod verify`
  passed. Lint reports zero issues. Changed adapter/security/command packages
  also passed three repeated race-enabled runs.
- Go 1.26.7: offline full tests, vet, module tidy diff, and build passed with the
  installed minimum toolchain, `GOROOT` unset, and `GOTOOLCHAIN=local`.
- Mutation tests use fake credentials and local HTTP servers or injected
  transports only. No live GitHub settings were read or changed. Module files,
  dependencies, the shipping Bash script, install paths, and release workflows
  are unchanged.

No task-004 blockers remain. Task 005 is Ready. The conservative read limitations
remain intentional: absent legacy protection and disabled Dependabot alerts
cannot be inferred from ambiguous 404s, even though their typed mutation adapters
are implemented and covered with explicit disabled fixtures. No additional read
evidence or fallback write was introduced.
