# 007: Harden and extend Go CI

Status: Done
Depends on: 005

## Context

Task 002 added the `Go` workflow: build, offline tests, module consistency,
and vet on the minimum and current Go versions, plus golangci-lint and
`bash -n`. It ran on every push and on pull requests, so each pull-request
commit was checked twice. It tested only Linux, although `gh` extensions also
run on macOS and Windows, and it did not run the race detector, check for
known vulnerabilities, or lint the workflow itself. See the
[architecture test strategy](../architecture/README.md#test-and-release-strategy)
and [contributing guide](../../CONTRIBUTING.md#build-and-validate).

## Scope and non-goals

Workflow triggers, concurrency, timeouts, the OS/toolchain matrix, Makefile
targets for pinned tools, Dependabot configuration, and related documentation.
Fix only small, clear portability failures that the new platforms expose.
Release and precompile workflows, artifact attestation, and other task-006 work
are out of scope. So are application behavior and the shipping Bash script.

## Prompt

> Harden the existing Go workflow rather than replacing it. Run pull-request
> checks once, add manual dispatch, cancel superseded pull-request runs, and
> bound job time. Add the race detector, macOS and Windows build/test coverage,
> govulncheck, and actionlint. Add the tools as pinned Makefile targets that
> follow the `bin/tools` pattern, and have CI call Makefile targets so local
> runs reproduce it. Keep `make check` fast and offline-capable once tools are
> installed. Add weekly Dependabot updates for actions and Go modules. Pin every
> third-party action to a verified full commit SHA and keep the token
> read-only. Fix small portability failures and report larger ones.

## Acceptance criteria

- Pull-request commits trigger one workflow run. Pushes trigger runs only for
  `main` and `port-to-go`, and manual dispatch is available.
- Superseded pull-request runs are cancelled, and every job has a timeout.
- Build, offline tests, module consistency, and vet pass on Linux, macOS, and
  Windows with the current Go release, and on Linux with the go.mod minimum.
  Linux also passes `make test-race`.
- `make lint` includes actionlint, and `make vulncheck` runs govulncheck. Both
  use Makefile-pinned versions and pass in CI.
- Dependabot checks GitHub Actions and Go modules weekly.
- Actions are pinned to verified SHAs, checkout does not persist credentials,
  and the workflow requests only `contents: read`.

## Completion record

Changes:

- `.github/workflows/go.yml`: push triggers are limited to `main` and
  `port-to-go`; pull requests targeting any base, which includes stacked pull
  requests, and `workflow_dispatch` also run it. A concurrency group cancels
  superseded pull-request runs but not branch pushes. Every job has a
  15-minute timeout, and the read-only token is no longer persisted by
  checkout. `GOTOOLCHAIN=local` is set for the whole workflow.
- The `test` matrix runs `make deps`, `mod-check`, `build`, `test-offline`,
  and `vet` on `ubuntu-latest`, `macos-latest`, and `windows-latest` with Go
  1.27.3, and on Linux with the go.mod minimum, 1.26.7. Linux entries also run
  `make test-race`. `windows-latest` (Server 2025) has no GNU Make, so the job
  installs Chocolatey `make` 4.4.1, pinned, and runs recipes in Git Bash.
- `lint` runs `make lint` on Go 1.27.3. `vulncheck` is a separate job that runs
  `make vulncheck` on Go 1.27.3, so lint failures do not hide vulnerability
  results.
- I removed the inline `gofmt -l` step because the golangci-lint `gofmt`
  formatter in `make lint` already reports it. To confirm, I introduced a
  misformatted file locally, and `make lint` failed with a `(gofmt)` finding.
- Makefile: `install-tool` installs each pinned tool under a versioned name in
  `bin/tools`. It adds actionlint v1.7.12 (`make lint-workflows`, now part of
  `make lint`) and govulncheck v1.9.0 (`make vulncheck`), and `make tools`
  installs all three tools. actionlint runs with `-shellcheck= -pyflakes=` so
  local and CI results do not depend on optional tools on `PATH`. Ubuntu
  runners have ShellCheck, but typical local machines do not. Tool rules no
  longer depend on the Makefile itself, because the versioned file name already
  forces a reinstall when a version changes.
- `.gitattributes` (`* text=auto eol=lf`): on the first Windows run,
  `make mod-check` failed because Git's default `core.autocrlf` checked out
  `go.sum` with CRLF line endings, so `go mod tidy -diff` reported every line.
  LF checkouts also protect gofmt and the Bash script for Windows contributors.
  The index was already all-LF, so no files were renormalized.
- `.github/dependabot.yml`: weekly `github-actions` and `gomod` updates, each
  with a seven-day cooldown.
- Documentation: CONTRIBUTING (toolchains, tools, CI jobs, triggers,
  Dependabot), architecture test strategy, the development guide, and the task
  index.

Decisions:

- Current Go moved from 1.27.1 to 1.27.3. With 1.27.1, `make vulncheck` found
  9 reachable standard-library vulnerabilities, fixed in 1.27.2 and 1.27.3. It
  found no reachable third-party module vulnerabilities. With 1.27.3 it reports
  none. The 1.26.7 CI entry stays because it checks the declared go.mod
  minimum. govulncheck runs only on the current release, because
  standard-library findings describe the scanning toolchain and release
  binaries should be built with the current patch release.
- `make check` is unchanged apart from actionlint inside `make lint`, which is
  offline once installed. `make vulncheck` needs the vulnerability database, so
  it stays out of `make check`.

Validation:

- Local, Go 1.27.1 (macOS arm64): `make check` passed (module tidy diff,
  actionlint, golangci-lint with 0 issues, `bash -n`, build, offline tests).
  `make test-race`, `make vet`, and `make tools` from an empty `bin/tools` also
  passed.
- Local Go 1.27.3 and 1.26.7 toolchain binaries, with `GOTOOLCHAIN=local`:
  `mod-check`, `build`, `test-offline`, and `vet` passed on both. 1.27.3 also
  passed `test-race`. `make vulncheck` reported "No vulnerabilities found" on
  1.27.3 and exited 3 with the standard-library findings above on 1.27.1.
- `GOOS=windows GOARCH=amd64 go vet ./...` and a Windows test-binary compile
  passed.
- GitHub Actions results are recorded in the pull request.

Limitations and follow-ups:

- The go.mod minimum (1.26.7) predates the standard-library fixes. Release
  builds should use the current patch release. Raising the minimum is a
  separate decision.
- Dependabot does not update Makefile tool versions, the Go versions in the
  workflow matrix, or the Chocolatey `make` pin. `dependabot.yml` takes effect
  only after it reaches the default branch.
- New vulnerability-database entries can fail `vulncheck` without a code change.
  There is no scheduled vulnerability scan.
- Artifact attestation (Sigstore build provenance) is deferred until the port
  lands in the upstream public repository. Use `actions/attest` (v4.2.2 was
  current) with job-scoped `id-token: write` and `attestations: write`.
  Release-asset attestation belongs with task 006.
