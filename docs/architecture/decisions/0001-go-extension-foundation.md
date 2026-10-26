# ADR 0001: Build a Go extension on GitHub CLI's shared libraries

Status: accepted; foundation dependencies verified and pinned by task 002.
Date: 2026-10-23

## Context

The existing extension is a single Bash script that shells out to `gh`. The port
should retain the extension experience while making behavior modular, typed, and
testable. The project should reuse libraries in common with
[`cli/cli`](https://github.com/cli/cli) as much as practical.

## Decision

Build a Go module with a thin `cmd/gh-secure` entry point and private `internal`
packages. Prefer [`cli/go-gh/v2`](https://github.com/cli/go-gh), the CLI team's
extension-facing Go library, for authenticated requests, repository discovery,
and terminal conventions. Use Cobra for the command tree, as GitHub CLI does.

Reuse supported library APIs rather than copying GitHub CLI internals or embedding
its entire application. Keep direct REST requests and feature-specific payloads
behind a local adapter. Evaluate
[`cli/gh-extension-precompile`](https://github.com/cli/gh-extension-precompile)
for distribution once the Go port is ready.

## Alternatives

- **Continue using `gh` subprocesses for everything:** preserves shell coupling
  and text parsing; reserve subprocess use for a demonstrated library gap.
- **Import the CLI application:** couples this extension to a much broader
  application surface; internal packages cannot be imported by this module.
- **Implement authentication and discovery independently:** duplicates CLI
  conventions and risks inconsistent credential and host behavior.

## Consequences

Tests can inject adapters rather than execute `gh` or modify real repositories.
Library upgrades and their Go requirements must be reviewed and pinned. The Go
binary still participates in the authenticated GitHub CLI extension environment;
it does not introduce its own login or credential storage.

This decision does not approve new commands, changed confirmation semantics,
broader platform promises, or a release cutover. Those require the
[specification's decision gates](../../spec.md#decisions-required-before-implementation).

## Implementation evidence

Task 002 (2026-10-26) pins go-gh v2.17.0 and Cobra v1.10.2 with Go 1.26.7 as
the source minimum. Build, offline tests, and vet pass locally on Go 1.26.7 and
1.27.1. The UI boundary uses go-gh terminal streams and checks actual terminal
input independently of forced terminal output. Repository/REST/prompt integration
remains assigned to tasks 003-005; task 001's spec records the checked exported
APIs. This implements the accepted direction without an architectural change.

## References

- [GitHub CLI shared dependency manifest](https://github.com/cli/cli/blob/trunk/go.mod)
- [go-gh usage and conventions](https://github.com/cli/go-gh#readme)
- [Creating GitHub CLI extensions](https://docs.github.com/en/github-cli/github-cli/creating-github-cli-extensions)
- [Precompiled extension releases](https://github.com/cli/gh-extension-precompile#readme)
