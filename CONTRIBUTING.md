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

- Go 1.26.7 minimum; CI checks Go 1.26.7 and 1.27.1.
- `github.com/cli/go-gh/v2` v2.17.0 for shared GitHub CLI conventions.
- `github.com/spf13/cobra` v1.10.2 for command parsing.
- `gh` 2.101.0 is the initial supported/tested runtime baseline. Go unit tests and
  help/version do not require `gh`, authentication, a git remote, or a real repo.

The module path is `github.com/GitHubSecurityLab/gh-secure`, matching the intended
extension distribution repository, even when developing in a fork.

#### Build and validate

Run from the repository root:

```bash
go mod download
go build -mod=readonly -o bin/gh-secure ./cmd/gh-secure
go test -mod=readonly ./...
go vet -mod=readonly ./...
go mod tidy -diff
gofmt -l cmd internal
```

Always specify `-o bin/gh-secure`: bare `go build ./cmd/gh-secure` would overwrite
the still-shipping root Bash script. Build output is ignored by git. Do not
install the development binary over the shipping extension.

After downloading dependencies, tests can also run with module-network access
disabled:

```bash
GOPROXY=off GOSUMDB=off go test -mod=readonly ./...
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
go build -mod=readonly -ldflags "-X main.version=dev-local" -o bin/gh-secure ./cmd/gh-secure
```

An ordinary build prints `gh-secure dev`; linker injection supplies the version
for candidate/release builds. A version string is not authorization to publish.
Only parsing/help/version are implemented in this foundation. Enablement and
status execution explicitly fail with exit 1 and do not inspect or mutate a
repository, including with `--yes` or `--dry-run`. Invalid invocations return 2.
Status rejects feature selectors and enablement-only flags on either side of
`status`. Repository resolution, API inspection, prompts, and mutations belong
to later tasks.

The command package accepts injected streams and execution handlers; normal
tests use fakes, not credentials, shell commands, or live GitHub APIs. Add tests
beside the affected package. Use local HTTP fixtures when API adapters arrive;
never use a live mutation as an ordinary test.

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
