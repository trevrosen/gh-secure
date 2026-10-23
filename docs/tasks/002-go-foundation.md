# 002: Establish the Go extension foundation

Status: Ready
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

Not started.
