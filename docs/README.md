# Go port development guide

This directory is the design and implementation record for porting `gh-secure`
from Bash to a modular Go GitHub CLI extension. The shell extension remains the
shipping implementation; these documents do not mean the port is implemented.

## Document structure

| Location | Purpose |
| --- | --- |
| [Specification](spec.md) | Observable behavior, compatibility baseline, acceptance criteria, and unresolved product decisions |
| [Architecture](architecture/README.md) | Package boundaries, dependency policy, execution model, and testing strategy |
| [Architecture decisions](architecture/decisions/0001-go-extension-foundation.md) | Numbered records of significant technical decisions and their consequences |
| [Tasks](tasks/README.md) | Ordered, reviewable implementation prompts with dependencies and completion evidence |

Read the specification and architecture before starting a task. The specification
owns **what** the tool does; architecture owns **how** it is organized; tasks
describe bounded changes that implement both. If they disagree, resolve the
disagreement in documentation before implementing it.

## Working agreement

1. Select a ready task from the [task index](tasks/README.md). Copy its prompt into
   the development session, retaining its ID in the resulting change description.
2. Resolve any decisions blocking that task. Do not silently convert a proposal
   or an accidental shell behavior into a new compatibility requirement.
3. Implement only its scope, adding deterministic tests and related documentation.
4. Record the actual changes, validation commands and results, and outstanding
   limitations in the task's completion record. Never mark unrun checks as passed.
5. Review against the task's acceptance criteria before marking it done.

Keep task prompts in version control, not just in chat history. Split new work
using the [task template](tasks/_template.md). Use monotonically increasing task
and decision IDs; do not renumber existing records. Supersede decisions with a
new record rather than erasing their history.

## Migration boundaries

- Preserve the current installation and invocation until the Go implementation
  passes its acceptance gates and a deliberate cutover is reviewed.
- Do not replace or edit the shell implementation merely to make Go tests pass.
- Prefer GitHub CLI's extension-facing libraries and shared dependencies; see
  [ADR 0001](architecture/decisions/0001-go-extension-foundation.md).
- Task 002 provides a Go module, command foundation, and build/test/vet CI with
  the approved minimum/current toolchains and pinned dependencies. See
  [Contributing](../CONTRIBUTING.md#go-port) for safe development build commands.
  Task 003 adds authenticated read-only status, target resolution, and offline
  HTTP fixtures. Enablement/dry-run planning and Go release automation remain
  unimplemented.
