# 006: Validate and ship the compiled extension

Status: Ready
Depends on: 005

## Context

All [port acceptance gates](../spec.md#port-acceptance-gates) must pass before the
Go binary replaces the root shell extension.

## Scope and non-goals

Precompiled release workflow, install/upgrade verification, user documentation,
and an explicitly approved shell-to-Go transition. No new feature scope.

## Prompt

> Audit implementation coverage against the approved spec and record evidence for
> every acceptance gate. Configure cli/gh-extension-precompile for cmd/gh-secure,
> pin reviewed action revisions and toolchain inputs, and use minimal workflow
> permissions. Verify asset names and compilation for the approved OS/CPU matrix.
> Test fresh installation and upgrade from the shell extension using isolated
> gh configuration and a maintainer-approved candidate release; do not disturb
> the user's installed extensions. Document supported versions, intentional
> behavior changes, build/test commands, and fallback/rollback instructions.
> Resolve how the root script is retired before changing it. Obtain explicit
> approval before publishing a tag/release or performing live mutation smoke
> tests; use only an approved disposable repository for those tests.

## Acceptance criteria

- Full offline tests, build/vet checks, and approved platform builds pass.
- Release artifacts launch with correct version information; install and upgrade
  smoke checks exercise the intended compiled executable, not the old shell.
- All acceptance evidence and any remaining host/feature limitations are recorded.
- README and contributing instructions describe the implementation actually
  shipped; release/rollback instructions are usable.
- No stable release or shell removal occurs with unresolved acceptance failures
  or without the required maintainer approval.

## Completion record

Not started.
