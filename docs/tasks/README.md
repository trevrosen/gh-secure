# Development task prompts

These files are executable work instructions for a contributor or coding agent,
not evidence that the Go implementation exists. Use the
[template](_template.md) for new tasks.

## Queue

| ID | Task | Status | Depends on |
| --- | --- | --- | --- |
| [001](001-confirm-behavior.md) | Confirm behavior and migration decisions | Done | None |
| [002](002-go-foundation.md) | Establish the Go extension foundation | Done | 001 |
| [003](003-inspection-and-status.md) | Implement repository inspection and status | Done | 002 |
| [004](004-feature-enablement.md) | Implement typed feature mutations | Done | 003 |
| [005](005-interaction-and-orchestration.md) | Wire confirmation, planning, and summaries | Done | 004 |
| [006](006-release-and-cutover.md) | Validate and ship the compiled extension | In progress | 005 |
| [007](007-ci-hardening.md) | Harden and extend Go CI | Done | 005 |
| [008](008-artifact-provenance.md) | Enable workflow artifact attestations | In progress | 005 |

Statuses: Ready, In progress, Blocked, Done. A dependency is satisfied only when
its acceptance criteria and completion record are reviewed. Update this table
and the task together. Do not start downstream work with unresolved behavior
decisions merely because the files are numbered.

Task 008 remains In progress pending maintainer acceptance. Its workflow check
detects attestation adoption and stops early; optional local assistance suggests
enablement patches. Runtime artifact/attestation resolution and verification
are explicitly out of scope and have been removed from the PR.

## Prompt usage

Each task contains context, scope, non-goals, a prompt, and measurable acceptance
criteria. Read its linked specification and architecture first. Ask for unresolved
product decisions instead of inventing them. Keep a task bounded; record newly
discovered work as a separate numbered task when it is outside scope.

A completion record must identify changes, actual checks/results, any approved
deviations, and remaining blockers. Do not store credentials or sensitive live
API responses in prompts, fixtures, or completion records.
