# Repository instructions for Copilot

Read `CONTRIBUTING.md`, `docs/spec.md`, `docs/architecture/README.md`, and the
relevant task in `docs/tasks/` before changing the Go port. The root `gh-secure`
Bash script remains the shipping extension until the cutover gates pass.
Build Go with `make build`, never a bare build that could overwrite that script.

## PR workflow

- Base focused feature branches on up-to-date `main` and target `main` with
  pull requests unless another base is explicitly requested. Do not push
  changes directly to `main`.
- Run `make hooks` in each clone before pushing. Never bypass the pre-push gate
  with `--no-verify`, disable it, or weaken checks to get a push through.
- Do not reopen or append new work to an already merged PR.
- Before opening a PR, review the entire diff against its intended base,
  including new files, tests, documentation, and workflow changes. Do not review
  only the most recent commit.
- Report meaningful findings with file locations, fix in-scope issues, and
  disclose unresolved risks. Never claim a check or review ran when it did not.

## Pre-PR review checklist

- **Spec and scope:** verify behavior against the specification, task acceptance
  criteria, and previously completed tasks. Remove accidental scope expansion,
  stale wiring, and redundant implementations. Update directly related docs.
- **Readability:** use precise identifiers and focused functions. Prefer guard
  clauses over deep nesting, switches inside switches, mutable sentinel flags,
  and mixed return/fall-through paths. Extract helpers only when they clarify
  intent; do not split flat dispatch solely to satisfy a complexity score.
- **Correctness:** trace every success, error, cancellation, and partial-result
  path. Check malformed/missing/duplicate API fields, pagination, resource
  cleanup, error wrapping, and state transitions. Preserve independent outcomes.
  Avoid silent failures, success-shaped fallbacks, and automatic retries of
  mutations.
- **Security:** keep credentials out of code, fixtures, logs, errors, and PR
  text. Check input validation, repository/host selection, URL handling,
  permissions, and least-privilege workflow permissions. Never follow mutation
  redirects or perform live mutations as a normal test.
- **Mutation safeguards:** only known-disabled settings may produce writes.
  Unknown/unsupported states and ambiguous 404s must not become disabled.
  Legacy branch protection requires known rulesets and explicit approval of
  active-ruleset overlap. Preserve confirmation and dry-run boundaries.
- **Tests:** keep tests tied to observable requirements rather than helper
  implementation details. Remove irrelevant/no-op assertions; cover changed
  behavior and boundary/error paths with offline fixtures. Do not add blanket
  linter suppressions or weaken assertions to make checks pass.
- **Validation:** run `make check` before pushing or opening a PR. For changes
  to Go concurrency, cancellation, shared state, or HTTP lifecycle, also run
  `make test-race`. For hooks, run `make test-hooks`. Fix failures before
  continuing; report environmental blockers rather than bypassing them.

Automated checks complement, but do not replace, this review. A passing linter
is not proof of correctness or security.
