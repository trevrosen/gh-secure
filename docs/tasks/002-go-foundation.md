# 002: Establish the Go extension foundation

Status: Done
Depends on: 001

## Context

Follow the approved [specification](../spec.md) and
[architecture](../architecture/README.md), especially
[ADR 0001](../architecture/decisions/0001-go-extension-foundation.md).
Task 001 approved Go 1.26.7 as the minimum, Go 1.27.1 as the current CI
toolchain, and go-gh v2.17.0 / Cobra v1.10.2 as verified dependency candidates.
Validate compilation and pin exact dependencies here; the approved behavior
and support contract is recorded in the spec.

## Scope and non-goals

Module, executable, command parsing, dependency injection, and baseline CI.
No security API mutations or installation cutover.

## Prompt

> Create module github.com/GitHubSecurityLab/gh-secure with cmd/gh-secure and
> internal command/UI boundaries. Verify and pin compatible Go, Cobra, and
> cli/go-gh/v2 versions. Implement root/status command parsing, canonical feature
> names/aliases, deduplication, validation, help, and build-injected version output.
> Match the approved status-argument and exit-code contracts. Inject streams and
> dependencies so tests need neither credentials nor git repository discovery.
> Keep unfinished enablement/status execution explicitly unavailable, never a
> success-shaped stub. Build to a non-conflicting output such as bin/gh-secure;
> leave the root Bash entry point intact. Add offline command tests and Go CI
> for build, tests, and vet. Document development commands and chosen versions.

## Acceptance criteria

- Help/version run without network or credentials; invalid flags/targets fail.
- All aliases, duplicates, selections, and interspersed flags are tested.
- Version behavior matches the specification; no inherited hard-coded shell
  version is presented as a released Go binary.
- `go build ./cmd/gh-secure`, `go test ./...`, and `go vet ./...` pass.
- The shell entry point and current extension installation remain unchanged.

## Completion record

Completed 2026-10-26.

- Created module `github.com/GitHubSecurityLab/gh-secure`, pinning go-gh v2.17.0
  and Cobra v1.10.2 with Go 1.26.7 as the minimum and checksummed dependencies.
  Imported go-gh's exported terminal API; API/auth/repository execution remains
  deferred rather than eagerly initializing clients during parsing.
- Added the thin executable with interrupt context and build-injected `main.version`
  (default `dev`), command/UI boundaries, injected execution handlers and streams,
  and one ordered canonical feature/alias registry.
- Added offline tests for every name/alias, all/default/explicit selections,
  deduplication/order, interspersed/combined flags, shared root/status flags,
  malformed/missing repositories, invalid arguments, strict status combinations,
  help/version, context/error exit mapping, and explicit unavailable execution.
  Forced terminal output cannot establish prompt input capability.
- Default enablement/status handlers return clear exit-1 diagnostics without
  discovery, credential lookup, reads, writes, or false success. Invalid
  invocations return 2 before execution handlers. Real execution remains task
  003/status and task 005/enablement work.
- Added minimum/current Go build/test/vet CI with revision-pinned checkout/setup-go
  actions, read-only workflow permissions, formatting/module checks, and offline
  tests after dependency download. CI is configured, not claimed remotely run.
- Documented safe development builds, version injection, selected versions,
  offline testing, and the incomplete development executable. Root Bash and
  installation are unchanged; no release/tag/live mutation was performed.

Validation:

- Go 1.27.1: `go build -mod=readonly -o bin/gh-secure ./cmd/gh-secure`,
  `GOPROXY=off GOSUMDB=off go test -mod=readonly ./...`,
  `go vet -mod=readonly ./...`, `go mod tidy -diff`, and `go mod verify` passed.
- Go 1.26.7: build, offline tests, vet, and `go mod tidy -diff` passed.
  Downloaded/verified the minimum toolchain first. For offline tests, invoked its
  installed binary with `GOTOOLCHAIN=local` and unset the inherited Homebrew
  `GOROOT`; automatic switching with `GOSUMDB=off` cannot verify the toolchain,
  and the inherited 1.27.1 `GOROOT` is incompatible with the 1.26.7 compiler.
  Neither workaround changes repository or global environment configuration.
- Executable smoke tests passed for help, exact `gh-secure dev` output,
  linker-injected `v2.0.0-rc.1` on root/status, operational exit 1, invalid-input
  exit 2, and the minimum-toolchain executable. Removed named smoke binaries.
- Used explicit `-o bin/...` for the build acceptance check: bare
  `go build ./cmd/gh-secure` would overwrite the shipping Bash executable.
- The editor test tool had no Go test provider; ran the Go CLI tests instead.
  Formatting/module consistency and `git diff --check` passed; the shipping
  script has no diff. No live API calls are part of normal tests.

No behavior/architecture deviations or remaining task-002 blockers. Task 003 is
Ready. CI execution on GitHub and the six-platform release/runtime/install matrix
are not local test claims; release/cutover work remains task 006.
