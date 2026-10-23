# 004: Implement typed feature mutations

Status: Blocked
Depends on: 003

## Context

Implement the five feature groups in the
[API inventory](../spec.md#feature-and-api-inventory) behind the architecture's
feature and GitHub adapter boundaries.

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

Not started.
