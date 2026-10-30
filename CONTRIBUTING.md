# Contributing to gh-secure

Thank you for your interest in contributing to this project! We welcome contributions of all kinds: bug reports, feature requests, documentation improvements, and code changes.

## Getting Started

1. Fork the repository and clone your fork locally.
2. Ensure you have the [GitHub CLI](https://cli.github.com) (`gh`) installed and authenticated.
3. The shipping extension is the root Bash script (`gh-secure`), which requires
   no build step. The Go port has a separate development build described below.

### Go port

Before working on the Go port, read the [development guide](./docs/README.md),
[specification](./docs/spec.md), and [architecture](./docs/architecture/README.md).
Implementation prompts and their dependencies are tracked in
[docs/tasks](./docs/tasks/README.md). Start with a ready task, resolve its decision
gates, and record validation evidence before marking it complete. The Bash script
remains the shipping extension until the port's acceptance and cutover gates pass.

#### Toolchain and dependencies

- Go 1.26.7 minimum; CI checks Go 1.26.7 and the current Go release, 1.27.3.
- `github.com/cli/go-gh/v2` v2.17.0 for shared GitHub CLI conventions.
- `github.com/spf13/cobra` v1.10.2 for command parsing.
- `gh` 2.101.0 is the initial supported/tested runtime baseline. Go unit tests and
  help/version do not require `gh`, authentication, a git remote, or a real repo.

The module path is `github.com/GitHubSecurityLab/gh-secure`, matching the intended
extension distribution repository, even when developing in a fork.

#### Build and validate

Run from the repository root:

```bash
make           # Show all available targets
make deps      # Download application dependencies
make check     # Module consistency, Go/workflow/Bash lint, build, and offline tests
```

`make build` always specifies `-o bin/gh-secure`: bare `go build ./cmd/gh-secure` would overwrite
the still-shipping root Bash script. Build output is ignored by git. Do not
install the development binary over the shipping extension.

`make lint` automatically installs golangci-lint v2.14.0 and actionlint v1.7.12
into `bin/tools` on first use (`make tools` installs every pinned tool, including
govulncheck v1.9.0); no global installation or application dependency change is
needed. The first installation needs network access and a Go toolchain new
enough to build the tools (CI uses Go 1.27.3). Subsequent runs reuse the pinned
binaries. Versions are defined in the Makefile and shared by local development
and CI; Dependabot does not update them.
Override `GO` if needed, for example `make test GO=/path/to/go`.

The explicit linter set in [.golangci.yml](./.golangci.yml) checks errors,
HTTP response cleanup, context usage, suspicious constructs, redundant
conversions, spelling, unused code, and Go vet/staticcheck diagnostics, including
tests. Standard exclusions cover errors documented as safe to ignore
(such as writes to in-memory buffers). One narrowly scoped errorlint exception
preserves discovery failures as diagnostic context while wrapping the prompt
failure; optional staticcheck quick-fix suggestions are disabled. Do not add
blanket package or test exclusions to silence findings. Go formatting and import organization are
checked too. `make fmt` applies those formatting changes; `make fmt-check`
checks them without editing. `make lint` also checks the shipping script with
`bash -n`; this is syntax validation, not ShellCheck or a live execution.
`make lint-workflows` (part of `make lint`) checks `.github/workflows` with
actionlint. Its optional ShellCheck integration is disabled so local and CI
results do not depend on what is installed on `PATH`.

Use `make test`, `make test-race` (requires CGO), and `make vet` for focused
validation. `make vulncheck` runs govulncheck against reachable code; it needs
network access for the vulnerability database, so it is not part of
`make check`. Standard-library findings depend on the Go toolchain running the
scan, so run it with the current Go release. `make clean` removes only the
development binary, retaining cached tools and leaving the shipping script
untouched.

CI ([.github/workflows/go.yml](./.github/workflows/go.yml)) runs its checks
through Makefile targets, so `make check` plus `make test-race`, `make vet`, and `make vulncheck`
reproduce it locally:

- `test`: `make deps`, `mod-check`, `build`, `test-offline`, and `vet` on Linux,
  macOS, and Windows with Go 1.27.3, and on Linux with Go 1.26.7. Linux jobs
  also run `make test-race`. Windows installs GNU Make 4.4.1 with Chocolatey
  and runs recipes in Git Bash. [.gitattributes](./.gitattributes) keeps LF
  line endings on every platform; CRLF checkouts break `make mod-check`.
- `lint`: `make lint` on Go 1.27.3.
- `vulncheck`: `make vulncheck` on Go 1.27.3.

Workflows run on pull requests (any base branch, so stacked pull requests are
checked), on pushes to `main` and `port-to-go`, and on manual dispatch. A newer
push cancels an in-progress pull-request run. Actions are pinned to full
commit SHAs and the workflow token is read-only. Dependabot
([.github/dependabot.yml](./.github/dependabot.yml)) proposes weekly action and
Go module updates after a seven-day cooldown.

After downloading dependencies, tests can also run with module-network access
disabled:

```bash
make test-offline
```

Use an already installed compatible toolchain for this offline command; Go's
automatic toolchain download/verification itself needs network/checksum access.
CI installs the toolchain first and sets `GOTOOLCHAIN=local` to prevent a silent
upgrade from masking minimum-version incompatibility.

#### Development executable

```bash
./bin/gh-secure --help
./bin/gh-secure --version
./bin/gh-secure status --help
./bin/gh-secure status --repo owner/repo
go build -mod=readonly -ldflags "-X main.version=dev-local" -o bin/gh-secure ./cmd/gh-secure
```

An ordinary build prints `gh-secure dev`; linker injection supplies the version
for candidate/release builds. A version string is not authorization to publish.
Read-only status is implemented. It resolves explicit, `GH_REPO`/remote, or
interactively prompted targets and inspects all six checks using GitHub CLI
authentication. It does not require the enablement admin/maintain preflight and
never sends write requests. Help/version still need no credentials or discovery.

Status returns 0 for known enabled/disabled checks, 1 for unknown/unsupported
checks or incomplete inspection, and 2 for invalid invocations. Ambiguous 404s
remain unknown rather than being presented as disabled; see the
[verified read semantics](./docs/spec.md#verified-read-semantics-task-003-2026-10-26).
Summaries explicitly separate the four states, for example:
`Summary (6 checks): 1 enabled, 4 disabled, 1 unknown, 0 unsupported`.
The final incomplete-inspection diagnostic names unresolved checks or rulesets;
interrupted runs show a partial summary rather than counting uninspected checks
as unknown.
Active rulesets are annotations, not proof of legacy protection or a seventh
enabled check. Paused Dependabot updates are called out explicitly.

Enablement, including `--yes` and `--dry-run`, still fails explicitly with exit 1
before inspecting or changing a repository. Task 004 provides internal typed
mutations and inspection-derived plans, but does not wire a CLI write path.
Plans only apply known-disabled settings, preserve independent Dependabot
outcomes, and retain optional CodeQL run links without claiming analysis has
completed. Unknown/unsupported inspections cannot become writes, and mutation
redirects and automatic retries are not allowed. See the
[verified mutation semantics](./docs/spec.md#verified-mutation-semantics-task-004-2026-10-28).
Permission preflight, confirmations, dry-run dispatch, and enablement rendering
remain task-005 work.
Status rejects feature selectors and enablement-only flags on either side of
`status`.

The command package accepts injected streams and execution handlers; normal
tests use fake credentials, local HTTP fixtures, and an isolated local git
fixture for remote discovery. They require no real repository or GitHub
connectivity. Add tests beside the affected package; never use a live mutation
as an ordinary test.

#### Release preparation

The root Bash script remains the shipping extension. Task 006's release workflow
builds draft releases only when a `v*` tag is pushed; creating a tag or publishing
a candidate/stable release still requires explicit maintainer approval. Do not
retire the Bash script or run live mutation smoke tests without their separate
approvals. See the [release and rollback guide](./docs/release.md) for the
supported runtime baseline, build matrix, migration behavior, and recovery
commands.

#### Provenance development

The workflow-source check and opt-in local enablement assistance are documented in
[task 008](./docs/tasks/008-artifact-provenance.md) and the
[specification](./docs/spec.md#task-008-workflow-attestation-enablement).
Static default-branch configuration analysis lives in
`internal/provenance/configuration.go` and `internal/github/workflows.go`.
It must not query run history or report artifact-level verification.
Publisher recognition lives in `internal/provenance/workflow.go`; optional
source-only OCI patch assistance lives in `assist.go` and `subject.go`.
Do not add artifact/registry resolution, run-history inspection, attestation
retrieval or cryptographic verification. Verification belongs to
`gh attestation verify`, not this enablement plugin.

Normal tests use local GitHub transports and fake Copilot responses. Do not use
your Copilot allowance, query a real target repository, or trigger publishing
as an ordinary test. Generated assistance must remain a reviewed, unapplied
suggestion and cannot claim to repair historical artifacts. No existing
artifact or published digest is required to suggest attestation enablement.

## Making Changes

1. Create a new branch for your changes: `git checkout -b my-feature`
2. Make your changes and run the relevant offline tests. Use the Go validation
   commands above for Go changes.
3. For shipping Bash changes, preserve both `--yes` and interactive
   (step-by-step) modes; prefer offline fixtures or dry-run checks.
4. Live mutation smoke tests require separate explicit approval of a disposable
   target. Never run enablement against a real repository merely to test a change.
5. Commit your changes with clear, descriptive commit messages.
6. Push to your fork and open a Pull Request against the `main` branch.

## Coding Conventions

- Follow [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html) conventions.
- Format Go with `gofmt`; keep core logic independent of Cobra and process exits.
- Use meaningful variable names and add comments for non-obvious logic.
- Keep functions focused and well-named.
- Test edge cases (missing permissions, private repos, already-enabled features).

## Reporting Bugs

**Please do NOT open a public GitHub issue for security vulnerabilities.** Instead, please follow the instructions in [SECURITY.md](./SECURITY.md).

For all other bugs, please open an issue on GitHub with:
- A clear description of the problem.
- Steps to reproduce the issue.
- Expected vs. actual behavior.
- Environment details (OS, `gh` version, shell).

## Suggesting Features

Open an issue describing:
- The use case or problem you'd like to solve.
- Your proposed approach (if you have one).
- Any alternatives you've considered.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.
