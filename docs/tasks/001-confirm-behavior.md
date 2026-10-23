# 001: Confirm behavior and migration decisions

Status: Done
Depends on: None

## Context

The [specification](../spec.md) inventories the current script and separates
intentional behavior from proposed corrections. Its decision gates block coding.

## Scope and non-goals

Approve a testable compatibility contract. No Go implementation, shell changes,
release automation, or live repository mutations.

## Prompt

> Read the shell implementation, root README, specification, architecture, and
> ADR 0001. Check the behavioral inventory against the script. Work with the
> maintainer to resolve each specification decision gate: exit codes,
> non-interactive ruleset confirmation, status arguments, unknown/unsupported
> states, intentional corrections, and support/cutover policy. Verify available
> library/toolchain constraints before recommending minimum versions. Ask focused
> questions rather than treating recommendations as approvals. Update the spec
> with decisions and a behavior-to-test checklist for downstream tasks. Add an ADR
> if a technical choice changes the architecture. Do not implement the Go port.

## Acceptance criteria

- Every decision gate has an explicit resolution or remains a documented blocker.
- The approved contract covers partial failures, prompt EOF, active rulesets
  with `--yes`, dry-run, and status exit semantics.
- Each port acceptance gate has an assigned downstream task and planned test.
- Task 002 becomes Ready only when all its prerequisite decisions are resolved.

## Completion record

Completed 2026-10-23.

- Read the entire shell implementation, root README, spec, architecture, ADR 0001,
  and downstream task prompts. Confirmed the inventory against the script;
  explicitly added the branch-protection fallback write and Dependabot dry-run's
  unnecessary preview of already-enabled settings to the correction table.
- Obtained explicit maintainer approval for all five gates: 0/1/2 exits
  (unsupported checks and cancellation return 1), required-input and ruleset
  safeguards, strict status arguments, fail-closed inspection/corrections, and
  verified version/support/cutover policy. Also approved confirmation parsing,
  invalid-input re-prompting, and collecting approvals before writes.
- Updated the spec with the approved contract and a behavior-to-test checklist
  assigning every acceptance gate to tasks 002-006. EOF at ordinary prompts
  aborts before writes; unavailable/EOF ruleset approval is a feature-local
  failure that permits independent approved work. Voluntary declines are not
  failures. Dry-run preserves safeguards and cannot mutate.
- Verified public upstream manifests and exported repository/REST interfaces
  using read-only `gh api` calls: go-gh v2.17.0 requires Go 1.26.7; Cobra v1.10.2
  declares Go 1.15. Reviewed go-gh conventions and precompile v2.2.0 documentation.
  `go version` reported go1.27.1 darwin/arm64; `gh --version` reported 2.101.0.
  Full versioned evidence and remaining implementation checks are in the spec.
- Validation: documentation-only change; no Go tests/build/vet exist or were run.
  Ran `git diff --check` after editing. No dependency installation, shell change,
  release action, or live repository mutation was performed.
- No architecture change or new ADR was needed. No behavior decision blockers
  remain for task 002, which is now Ready. Exact pins/compilation remain task 002
  work; six-target runtime/install/upgrade evidence and separate publication/
  shell-retirement approvals remain task 006 gates, not approvals to release now.
