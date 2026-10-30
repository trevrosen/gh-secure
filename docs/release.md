# Release and rollback

## Current status

The root `gh-secure` Bash script and the existing installation path remain the
shipping extension. The precompile workflow is configured to create a **draft**
release after a `v*` tag is pushed. No candidate or stable tag/release has been
created by this task. A maintainer must separately approve creating a candidate
tag/release, publishing a release, and retiring the Bash entry point. Live
mutation smoke tests also require separate approval and an approved disposable
repository.

The workflow pins `cli/gh-extension-precompile` v2.2.0 to commit
`76961aa3bd1123d0a6fd42d0a41aca0696937c39`, uses Go 1.27.3, and builds only
these six precompiled targets:

| OS | CPU |
| --- | --- |
| Linux | amd64, arm64 |
| macOS | amd64, arm64 |
| Windows | amd64, arm64 |

Users installing precompiled releases do not need Go. The source-build minimum
is Go 1.26.7. The supported GitHub CLI baseline is `gh` 2.101.0; initial host
support is github.com. GHES routing is retained, but GHES feature support is not
promised.

## Build and verification

From the repository root:

```bash
make deps
make check
make test-race
make vet
make vulncheck
```

`make vulncheck` needs access to the vulnerability database. The release
workflow builds tag-versioned binaries into `dist/` with CGO disabled. To
reproduce the artifact build locally without creating a release:

```bash
GOTOOLCHAIN=go1.27.3 ./scripts/build-release.sh v2.0.0-rc.1
./dist/gh-secure_v2.0.0-rc.1_darwin-arm64 --version
```

The six named artifacts were built with Go 1.27.3 on macOS arm64; the native
Darwin arm64 executable reports `gh-secure v2.0.0-rc.1`. This is not
cross-platform runtime, release-upload, or install/upgrade evidence. Release
acceptance still requires launch verification on the remaining five target
OS/CPU combinations and fresh-install and shell-to-binary upgrade checks using
an isolated `gh` configuration and an approved candidate release. Do not use a
maintainer's normal extension installation for these checks.

The precompile action uploads with `--clobber` when a release for the tag
already exists. Re-running the workflow against an existing release can replace
its assets; do so only with explicit maintainer approval.

## Migration and behavior

When a candidate or stable binary release has been approved and published, a
fresh installation uses the standard command:

```bash
gh extension install GitHubSecurityLab/gh-secure --pin v2.0.0-rc.1
```

For an existing shell installation, the intended upgrade command is:

```bash
gh extension upgrade gh-secure
```

The shell-to-binary upgrade path is not yet verified; do not treat these
commands as tested until the approved isolated candidate smoke check has passed.

The Go implementation intentionally differs from shell behavior in several
safety-critical cases:

- Ambiguous API failures remain unknown/errors instead of being reported as
  disabled, and a failed metadata lookup never invents a default branch.
- Enablement requires the repository permission preflight. `--yes` does not
  bypass the active-ruleset safeguard.
- Dry-run does not send writes; failed writes are not retried, and existing
  rulesets are not changed.
- Dependabot sub-operation failures remain visible rather than being hidden by
  a successful sibling operation.

## Rollback

The original shell implementation is preserved at commit
`a04d1c144f5d1b63a8aa5cd7946e8ceafa709a2a`. To replace a Go binary installation
with that script version:

```bash
gh extension install GitHubSecurityLab/gh-secure \
  --force \
  --pin a04d1c144f5d1b63a8aa5cd7946e8ceafa709a2a
```

This rollback command has not yet been exercised against a candidate
installation. If the CLI refuses to replace the installed binary, remove only
the `gh-secure` extension and reinstall the pinned shell commit:

```bash
gh extension remove gh-secure
gh extension install GitHubSecurityLab/gh-secure \
  --pin a04d1c144f5d1b63a8aa5cd7946e8ceafa709a2a
```

Do not delete the user's configuration or other extensions. Keep the shell
entry point and its source commit available until the upgrade and rollback paths
have been verified and cutover is explicitly approved.
