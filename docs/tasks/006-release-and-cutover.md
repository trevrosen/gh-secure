# 006: Validate and ship the compiled extension

Status: In progress
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

In progress, 2026-10-30.

Implemented:

- Added `.github/workflows/release.yml`, triggered only by `v*` tag pushes.
  It grants only `contents: write`, uses checkout with persisted credentials
  disabled, pins `cli/gh-extension-precompile` v2.2.0 to reviewed commit
  `76961aa3bd1123d0a6fd42d0a41aca0696937c39`, and requests Go 1.27.3.
  The precompile action creates draft releases; this task did not create or
  publish a tag or release. Its existing-release path uploads with `--clobber`,
  so rerunning against an existing release requires explicit maintainer
  approval and is documented as such.
- Added `scripts/build-release.sh` to build exactly the approved six OS/CPU
  targets, name assets in the `gh-secure_v{version}_{os}-{arch}` convention
  (with `.exe` on Windows), and inject the tag into `main.version`.
- Extended `make lint` to syntax-check the release build script as well as the
  shipping Bash extension.
- Updated README and contributor guidance, and added
  [release/rollback instructions](../release.md) covering support baselines,
  intentional behavior differences, build commands, migration, and recovery.
  The Bash script and current installation path remain unchanged.

Acceptance audit and evidence:

- Tasks 002-005 completion records document offline command/API/mutation tests,
  and task 007 records the platform CI matrix and security checks. Verified the
  main commit's successful Go workflow run at
  https://github.com/trevrosen/gh-secure/actions/runs/40801046695; its lint,
  vulnerability, Linux Go 1.26.7/1.27.3, macOS Go 1.27.3, and Windows Go 1.27.3
  jobs all succeeded. Job logs show those platform jobs ran Linux x64, macOS
  arm64, and Windows amd64. This is CI evidence for those three platform
  combinations, not the other three runtime combinations or release artifacts.
- Built all six release assets locally with Go 1.27.3 using
  `./scripts/build-release.sh v2.0.0-rc.1`. The filenames and Windows `.exe`
  suffixes match the intended asset convention; launched the native Darwin
  arm64 binary and verified `gh-secure v2.0.0-rc.1`. Linux amd64/arm64,
  Darwin amd64, and Windows amd64/arm64 runtime execution, uploaded-release
  asset names, isolated fresh install, and shell-to-binary upgrade remain
  unverified.
- On Go 1.27.3/macOS arm64, `make check`, `make test-race`, `make vet`, and
  `git diff --check` passed. `make check` included module consistency,
  actionlint, golangci-lint (0 issues), Bash syntax checks, build, and offline
  tests. The downloaded toolchain was invoked with its matching GOROOT rather
  than the machine's inherited Go 1.27.1 GOROOT.
- A candidate tag/release, release publication, live mutation smoke tests, and
  Bash retirement each remain explicitly approval-gated. No approval was given
  and none of these actions was performed.

Remaining blockers before task completion:

1. Launch each of the five remaining artifacts on its target platform and
   check its injected version; confirm uploaded release asset names.
2. Obtain maintainer approval for a disposable candidate release and perform
   fresh-install and Bash-to-binary upgrade tests with isolated `gh`
   configuration. Verify the rollback commands against that installation.
3. Record remaining CI/platform/host limitations. Do not claim broad GHES
   support. Separate maintainer approval is still required before publishing
   the candidate/stable release or retiring the shell; live mutation tests need
   their own approval.

No stable release, candidate release, tag, shell removal, or live repository
mutation was performed.
