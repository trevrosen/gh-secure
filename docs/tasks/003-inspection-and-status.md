# 003: Implement repository inspection and status

Status: Blocked
Depends on: 002

## Context

Implement the repository and six-check status sections of the
[specification](../spec.md) using the [architecture](../architecture/README.md).

## Scope and non-goals

Authenticated read adapter, repository resolution, feature inspection, and status
rendering. No enablement mutations.

## Prompt

> Use cli/go-gh/v2 to resolve explicit/current/prompted repositories and route
> authenticated REST reads to the correct host. Implement typed metadata and all
> six status checks, paginated active-ruleset information, and community-policy
> advisory inspection for later enablement use. Distinguish disabled, unknown,
> and unsupported outcomes using endpoint-specific documented behavior; retain
> actionable errors without exposing tokens. Do not default metadata errors to
> branch main or require enablement permission preflight for status. Build status
> rendering and exit mapping against the approved contract. Inject clients,
> streams, and prompts. Test with local HTTP fixtures and fakes only.

## Acceptance criteria

- Six checks and ruleset annotations match the specified counts and semantics.
- Explicit, GH_REPO/current, and prompted target paths have offline tests.
- Host routing, escaped branch paths, paginated rulesets, missing fields,
  malformed responses, permission failures, rate limits, and cancellation are tested.
- Status cannot send mutations; its test transport rejects all write methods.
- Neither API failure nor an inaccessible policy file produces false "disabled"
  or "missing" claims.

## Completion record

Not started.
