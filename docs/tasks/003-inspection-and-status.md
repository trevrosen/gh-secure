# 003: Implement repository inspection and status

Status: Done
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

Completed 2026-10-26.

- Added shared strict repository validation, explicit/GH_REPO/remote/prompted
  resolution through go-gh, typed metadata, and host-aware web URLs. Prompt input
  requires actual terminal capability; EOF/non-TTY and cancellation fail clearly.
  Evaluated go-gh's survey-based prompter: it requires file-descriptor streams.
  The current single repository-input prompt uses injected standard-library
  streams instead, preserving buffer/pipe tests and EOF/cancellation semantics.
- Added authenticated, context-aware GET adapters with no persistent response
  caching or environment-driven HTTP body logging. Metadata is fetched once,
  branch paths escape `/`, rulesets include inherited policies and every page,
  and malformed/failed pages cannot produce a known partial aggregate.
- Implemented all six checks, truthful enabled totals, unknown/unsupported
  diagnostics, paused-update information, host-aware follow-up links, and
  approved exit mapping. Status has no enablement permission preflight, advisory
  policy request, or write path. Fatal prerequisites and cancellation stop reads.
- Added community-profile advisory inspection for later enablement use. Public
  API verification found no documented `files.security` field; missing/null
  metadata is not assessed, never evidence of a missing policy. An explicit
  valid URL is retained if supplied. Advisory results remain independent.
- Recorded public API sources and verified mappings in the spec. In particular,
  branch-protection and Dependabot 404s remain unknown rather than relying on
  undocumented messages or assuming metadata access proves endpoint permission.
  Public-only reporting availability establishes unsupported on private repos.
  These limitations preserve the approved fail-closed contract; downstream
  planning cannot turn unknown checks into missing-state writes.
- Added offline resolver, local HTTP adapter, orchestration, renderer, prompt,
  and command integration tests. Tests assert methods, encoded paths, headers,
  host/API-host routing, pagination, required fields, malformed responses,
  access/rate-limit failures, token-safe diagnostics, exact counts/exits, EOF,
  cancellation, no admin/maintain requirement, and rejection of all mutations.
  Fake tokens and isolated git/HTTP fixtures require no live credentials/repo.
- Updated development documentation and task queue. Enablement and dry-run
  remain explicitly unavailable. No shell, install path, release, or live
  repository settings were changed.

Validation:

- Go 1.27.1: build to `bin/gh-secure`, offline `go test -race ./...`, `go vet
  ./...`, `go mod verify`, and `go mod tidy -diff` passed.
- Go 1.26.7: build, offline `go test ./...`, `go vet ./...`, and `go mod tidy
  -diff` passed using the installed minimum toolchain with inherited `GOROOT`
  unset and `GOTOOLCHAIN=local`.
- Standard test/build/vet commands use `-mod=readonly`; offline test runs use
  `GOPROXY=off GOSUMDB=off` after dependency resolution. Direct dependency pins
  and the Go floor are unchanged; module files include newly used go-gh
  transitive packages.
- Formatting, whitespace, executable help/version, invalid-input exits, and
  preservation of the root Bash entry point checked separately. No normal
  tests or executable smoke checks query live GitHub settings.

No task-003 blockers remain. Task 004 is Ready, with the documented conservative
inspection limitations retained. Runtime release-matrix and install/upgrade
evidence still belong to task 006, not this completion record.
