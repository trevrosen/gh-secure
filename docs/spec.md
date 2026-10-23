# Go port specification

Status: approved target contract (maintainer decisions, 2026-10-23), with observed
behavior distinguished from intentional corrections. Baseline:
[`gh-secure`](../gh-secure) and [user documentation](../README.md)
at commit `a04d1c144f5d1b63a8aa5cd7946e8ceafa709a2a` (script version `1.0.0`).
No Go functionality is implemented by this document.

## Scope

Port the existing single-repository security enablement and status workflows to
Go. Public repositories remain the primary audience. Preserve `gh secure` as the
entry point and the existing feature names and flags.

Not included: bulk/org-wide changes, ruleset creation or editing, custom security
policies, Dependabot version-update configuration, advanced CodeQL workflow
generation, creating a security policy file, a TUI, or new JSON/config-file APIs.

## Observed command contract

```text
gh secure [flags] [feature ...]
gh secure status [--repo <owner/repo>]
```

| Flag | Behavior |
| --- | --- |
| `-r`, `--repo owner/repo` | Explicit target; otherwise discover the current repository, then prompt if discovery fails |
| `-y`, `--yes` | Bypass ordinary enablement confirmations, but NOT the active-ruleset safeguard |
| `-n`, `--dry-run` | Inspect and preview; perform no mutations |
| `-v`, `--version` | Print `gh-secure <version>` and exit |
| `-h`, `--help` | Print help and exit |

Unknown arguments and malformed explicit repositories fail. Help and version
need no authentication or repository. Feature flags may be interspersed with
feature arguments. With no selection all five groups run; otherwise the selected
groups run in the canonical order below, not argument order. The shell effectively
executes duplicate selections once, though its confirmation count includes them.

The shell parser accepts enablement flags and feature arguments alongside
`status`, but status still checks everything and does not mutate. The approved Go
contract rejects these combinations; see the decisions below.

## Repository, permissions, and interaction

- Explicit input must identify exactly `owner/repo`, with nonempty components.
- The shell uses `gh repo view` for discovery. Go should reuse CLI discovery,
  respecting `GH_REPO`, authenticated host selection, and git remotes.
- Enablement fetches repository metadata, warns for private repositories, and
  proceeds only when admin or maintain permission is reported. This preflight is
  not a guarantee: each endpoint may require additional permission or entitlement.
- Status does not run the enablement permission preflight.
- A selected subset gets one confirmation; choosing all features interactively
  offers either one all-features confirmation or step-by-step confirmations.
  Declining the initial confirmation aborts without mutations.
- Already-enabled features do not need normal per-feature confirmation.
- When legacy branch protection is absent and active rulesets are found, the shell
  requires a separate explicit confirmation even with `--yes`. Preserve that
  safeguard. Do not infer that a ruleset actually covers the default branch.
- Dry-run still reads current state and follows confirmation safeguards. It must
  never send PUT, PATCH, POST, or DELETE requests.
- Terminal output has feature explanations, enabled/disabled indications,
  summaries, and follow-up security links. Preserve information and meaning, not
  exact banners, colors, Unicode glyphs, or line wrapping.

## Feature and API inventory

All paths below are relative to `repos/{owner}/{repo}` on the resolved API host.
Repository metadata includes `default_branch`, `private`, permission fields, and
`security_and_analysis`. Use the actual default branch, with safe path encoding.

| Order / group / alias | Inspection | Missing-state mutation |
| --- | --- | --- |
| 1. `branch-protection` / `bp` | GET `/branches/{default_branch}/protection`; GET `/rulesets` for active enforcement names/count | PUT `/branches/{default_branch}/protection` with the baseline below |
| 2. `vulnerability-reporting` / `vr` | GET `/private-vulnerability-reporting`, `enabled` | PUT `/private-vulnerability-reporting` |
| 3. `secret-scanning` / `ss` | GET repository, `security_and_analysis.secret_scanning_push_protection.status` | PATCH repository with `security_and_analysis.secret_scanning_push_protection.status = "enabled"` |
| 4. `dependabot` / `dep` | GET `/vulnerability-alerts` (enabled success response); GET `/automated-security-fixes`, `enabled` | Independently PUT `/vulnerability-alerts` and `/automated-security-fixes` when missing |
| 5. `code-scanning` / `cs` | GET `/code-scanning/default-setup`, `state == "configured"` | PATCH `/code-scanning/default-setup` with `{"state":"configured","query_suite":"default"}` |

Branch protection's intended JSON baseline:

```json
{
  "required_status_checks": null,
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
```

Existing legacy branch protection is treated as already enabled, not reconciled
to this baseline. Existing active rulesets are not edited. Secret scanning here
means enabling push protection, not independently enabling all secret scanning
settings; do not promise automatic availability on private repositories.
Dependabot means alerts and **security** updates, not version updates.
CodeQL default setup success means configuration was accepted, not that analysis
completed; display `run_url` if returned.

Validate endpoint-specific success/disabled/unavailable responses against current
GitHub API documentation in the relevant implementation task. A blanket 404 or
403 interpretation is not safe: lack of access and feature availability can
overlap. Paginate rulesets before calculating active names/counts.

## Status and summaries

Status reports six checks: legacy branch protection, private vulnerability
reporting, secret scanning push protection, Dependabot alerts, Dependabot security
updates, and CodeQL default setup. Report active rulesets alongside protection,
but do not count rulesets as an enabled seventh check or as legacy protection.
Count only known enabled checks toward the six-check total.

Enablement summarizes the selected five feature groups, preserving independent
Dependabot operation results. Distinguish applied, already enabled, planned,
declined, partial, and failed outcomes; dry-run must not claim "newly enabled."
Provide security settings/overview links for the resolved web host, the private
reporting link when appropriate, and the CodeQL run link if supplied.

The shell checks GET `/community/profile` at the end to suggest adding a security
policy when `.files.security.url` is absent. Keep that advisory read distinct from
feature enablement. A failed advisory lookup must not assert that the policy is
missing or obscure the primary result.

## Approved intentional corrections

These are not compatibility requirements to reproduce shell accidents:

| Observed shell behavior | Proposed Go behavior |
| --- | --- |
| Most check failures become "not enabled"; metadata failure can default to `main` | Preserve unknown/unsupported/error states; never invent a default branch |
| Private reporting issues two PUT requests for one enablement | One typed mutation, no automatic duplicate write |
| Branch protection retries a failed form-field PUT with raw JSON | One correctly typed JSON PUT, no automatic write retry |
| Dependabot can warn on failed writes yet return success | Track partial/failure results and reflect them in summary and exit status |
| Dependabot dry-run previews both operations even when one is enabled | Plan only missing settings; retain already-enabled sub-operation results |
| Declines and failures share a summary bucket; final exit can be zero after failures | Separate user choices from operational failures |
| Dry-run outcomes are grouped as newly enabled | Explicit planned outcomes with zero mutations |
| Ruleset listing considers only the default response page | Inspect every page before warning or counting |
| Missing values and repeated selections have shell parser quirks | Validate missing values and normalize/deduplicate before confirmation |
| Prompt EOF/non-TTY and status argument combinations are not a clear contract | Use the explicit approved input and argument rules below |

## Decisions required before implementation

All five gates were resolved with explicit maintainer approval in
[task 001](tasks/001-confirm-behavior.md) on 2026-10-23. These decisions govern the
Go port, not the still-shipping shell implementation.

### 1. Exit codes

| Code | Contract |
| --- | --- |
| 0 | Successful inspection/enablement, successful dry-run, or voluntary decline/initial abort; known disabled checks alone do not fail status |
| 1 | Operational or partial failure, unknown required check, unsupported requested check, unavailable required input/EOF, or cancellation (including Ctrl-C) |
| 2 | Invalid invocation, including malformed explicit repository, missing flag value, unknown argument, and rejected status combinations |

An unsupported check returns 1 in both status and enablement, even when its
unavailability is known rather than an API failure. A voluntary decline does not
erase independent failures. A dry-run still returns 1 for failed inspection or
safeguards. Status counts only known enabled checks out of six and returns 1 if
any required check is unknown or unsupported.

Cancellation stops further requests and summarizes operations already accepted;
do not roll back or retry writes. Cancellation before apply performs no writes.
The community-policy lookup remains advisory: report lookup failure as a warning,
do not claim a policy is missing, and do not replace the primary exit result.

### 2. Prompts, EOF, and active rulesets

- Prompt only with terminal input capability. Output styling or forced terminal
  rendering does not establish input capability. Do not consume piped answers
  as an implicit approval mechanism.
- Without prompt capability, ordinary enablement needing confirmation requires
  `--yes`; missing repository input requires an explicit/discoverable target.
  Fail clearly with exit 1 instead of waiting for input. `--yes` does not supply
  a repository or approve the ruleset safeguard.
- Accept `y`/`yes` and `n`/`no` case-insensitively; an empty confirmation means no.
  Re-prompt on other input and on invalid enablement-mode choices. EOF at any
  required prompt is an operational failure, not a voluntary decline.
- Collect all required mode/feature/safeguard confirmations before applying any
  writes. EOF during confirmation therefore cannot leave a partly applied run.
- When missing legacy protection overlaps active rulesets, require separate
  explicit approval even with `--yes`. If that safeguard cannot be answered,
  skip branch protection with an explicit diagnostic and exit 1; other approved,
  independently eligible features may proceed. Do not add a force flag.
  An explicit no is instead a voluntary decline, not a failure.
- EOF at an ordinary confirmation aborts before apply with exit 1. EOF at the
  ruleset safeguard follows the feature-local skip rule above; still collect any
  remaining required confirmations before applying independent operations.
- Dry-run follows the same safeguards. Already-enabled settings need no ordinary
  per-feature approval, and no prompt is needed when there is nothing to approve.

### 3. Status arguments

Status accepts `--repo`/`-r`, `--help`/`-h`, and `--version`/`-v`.
Reject feature selectors and `--yes`/`-y` or `--dry-run`/`-n` with exit 2 before
network access, whether they appear before or after `status`. Do not inherit
enablement-only flags merely because Cobra supports persistent flags.

### 4. Inspection taxonomy and corrections

All corrections in the table above are approved. Render enabled, disabled,
unknown, and unsupported distinctly with actionable diagnostics. Disabled means
an endpoint-specific response establishes that the setting is off; unsupported
requires positive availability evidence. Ambiguous 403/404 responses, absent
fields, malformed responses, and transport/auth/rate-limit errors must not become
disabled or unsupported by default. Validate endpoint-specific mappings in task
003 against the API documentation; that work cannot relax this contract.

Do not construct writes for an unknown or unsupported setting. Failure to inspect
rulesets blocks the branch-protection write, not just its warning. Continue
independent eligible features after feature-local failures, preserving failed
Dependabot sub-operations; stop on cancellation or fatal prerequisites such as
unresolved repository, failed metadata, or failed enablement permission preflight.
Deduplicate normalized feature selections before confirmation and use canonical
order for planning, execution, and reporting.

### 5. Support baseline and cutover

| Concern | Approved initial policy |
| --- | --- |
| Source-build minimum | Go 1.26.7; task 002 validates the minimum and current Go 1.27.1 in CI |
| Dependency candidates | `cli/go-gh/v2` v2.17.0 and Cobra v1.10.2; task 002 verifies compilation and pins exact dependencies |
| GitHub CLI | `gh` 2.101.0 minimum supported/tested baseline; older versions are not asserted broken but need install/auth/upgrade evidence before lowering the floor |
| Host | github.com supported initially; retain host-aware routing and offline GHES fixtures, without promising GHES feature support |
| OS/CPU | Linux, macOS, Windows, each on amd64 and arm64 |
| Development version | A non-release value such as `dev`, never the shell's hard-coded `1.0.0` |
| Migration release | Target v2.0.0, preceded by a separately approved v2.0.0-rc.N candidate |

The version floor is based on the verified dependency requirements below, not
an assumption that the locally installed Go is the minimum. Users installing
precompiled binaries do not need Go. Exact pins, toolchain setup, and action
revisions belong to implementation tasks, not task 001.

Keep the Bash entry point and current installation path unchanged through tasks
002-005. Task 006 must compile all six targets and record launch, isolated fresh
installation, and shell-to-binary upgrade evidence before claiming support.
Unavailable runtime coverage blocks release unless the maintainer explicitly
approves reducing the matrix. Require all acceptance gates and usable rollback
instructions before cutover. Publishing any candidate/stable tag or release and
retiring Bash each require separate explicit maintainer approval; this policy is
not authorization to perform them. Live mutation tests still require a separately
approved disposable repository.

### Verification evidence

Checked on 2026-10-23 using read-only public upstream GitHub API requests and local
version commands:

- [`go-gh` v2.17.0 go.mod](https://github.com/cli/go-gh/blob/v2.17.0/go.mod)
  declares Go 1.26.7.
- [Cobra v1.10.2 go.mod](https://github.com/spf13/cobra/blob/v1.10.2/go.mod)
  declares Go 1.15; it does not raise the selected floor.
- [`repository.Current` and `Parse`](https://github.com/cli/go-gh/blob/v2.17.0/pkg/repository/repository.go)
  support `GH_REPO`, configured hosts, and git remotes. The library parser accepts
  more forms than this CLI contract: validate explicit/prompted `owner/repo`
  before calling it; preserve host-aware library discovery for `GH_REPO`/remotes.
- [`api.NewRESTClient`, `RequestWithContext`, and `DoWithContext`](https://github.com/cli/go-gh/blob/v2.17.0/pkg/api/rest_client.go)
  provide host-aware authenticated requests and cancellation. The preferred
  `prompter`, `term`, and `tableprinter` packages exist; their concrete integration
  and input-capability behavior still require implementation validation.
- [`gh-extension-precompile` v2.2.0](https://github.com/cli/gh-extension-precompile/tree/v2.2.0)
  documents `go_version_file`, `go_build_options` for a nested command, prerelease
  tags, and platform asset naming. Task 006 still must verify exact artifacts
  and installation/upgrade behavior.
- Local `go version`: `go1.27.1 darwin/arm64`; local `gh --version`: `2.101.0`.
  These checks are not compilation, cross-platform, or minimum-version test
  evidence. No dependencies were installed and no live security settings changed.

## Port acceptance gates

- Every alias, flag, mode, selection order, and accepted/rejected combination has
  a command test tied to this specification.
- All six checks and five feature groups have enabled, disabled, error, and
  availability coverage, including Dependabot partial failure and active rulesets.
- HTTP tests assert exact request paths, methods, typed JSON, and pagination.
  Already-enabled settings receive no unnecessary writes.
- Dry-run and status pass tests whose transport rejects all mutating requests.
- Tests cover explicit/discovered/prompted targets, private-repository warnings,
  permissions, non-default branch names containing `/`, auth/host errors,
  EOF/non-TTY, cancellation, and approved exit-code mapping.
- Ordinary tests are offline and credential-free. Live repository mutations
  require explicit approval and cannot be the sole evidence of correctness.
- Build, tests, vet, platform artifacts, and install/upgrade smoke checks pass
  before the shell is retired. Document intentional behavior changes for users.

### Behavior-to-test checklist and ownership

These are planned tests, not passing test claims. Primary owners must record
actual evidence in their task completion records; later tasks retain earlier
coverage.

| Gate / behavior | Downstream owner | Planned verification |
| --- | --- | --- |
| Flags, all names/aliases, interspersed flags, default selection, deduplication and canonical order | 002; 005 integration | Table-driven command tests assert exact normalized selection/count/order and invalid-input exit 2 before client/discovery calls |
| Help/version, strict status combinations, malformed/missing repo values | 002 | Offline command tests for root/status shared flags and enablement flags/selectors on either side of status; no auth/network for valid help/version |
| Six checks and five groups: enabled, disabled, unknown/error, unsupported | 003 inspection; 004 operations; 005 summaries | Endpoint fixtures and fake feature results assert distinct states, six-check totals, no writes for unknown/unsupported, and exit 1 for both |
| Repository selection, host routing, metadata, visibility and permissions | 003; 005 preflight | Explicit, GH_REPO, remote and prompted fakes; auth/host failures; no invented branch; status without admin/maintain; enablement warning and permission-denial cases |
| Exact REST contract and rulesets | 003 reads; 004 writes | HTTP fixtures assert methods, escaped slash-containing branch paths, typed bodies, headers, pagination (active ruleset on a later page), malformed/absent fields, rate limits, permission/availability errors |
| No unnecessary/duplicate writes or retries | 004; 005 integration | Assert zero writes for enabled settings, one write per missing setting, no retry after failure, existing protection preserved, and no ruleset mutation |
| Dependabot aggregation | 004; 005 integration | Each one-setting-missing case, both partial-failure orders, both failures, already-enabled and declined settings; exact sub-operation summaries and exit codes; dry-run plans only missing settings |
| Interactive all/subset modes, --yes, EOF, non-TTY, ruleset safeguard | 005; 003 target input | Injected prompt/stream tests cover yes/no/empty/invalid input, invalid mode re-prompt, unique subset count, initial decline, ordinary EOF abort, ruleset EOF/non-TTY feature-local failure, and no writes before all approvals |
| Dry-run and status cannot mutate | 003 status; 005 all groups/modes | Transport rejects PUT/PATCH/POST/DELETE; assert zero writes, safeguards still enforced in dry-run, planned rather than newly-enabled results, and correct failure exits |
| Continuation, cancellation and exact exit mapping | 003 reads; 005 orchestration | Assert independent work continues after feature-local failure; fatal prerequisites/cancellation stop further requests; Ctrl-C maps to 1; summaries retain accepted writes without rollback/retry |
| Truthful outcomes and follow-up information | 005 | Assert applied/already/planned/declined/partial/failed remain distinct, host-aware links, CodeQL run URL without analysis-completion claim, and advisory lookup failure warns without false missing-policy advice or changing the primary exit |
| Offline builds/tests/vet and supported versions | 002 baseline; 005 regression; 006 release | Credential-free tests using local HTTP fixtures/fakes; minimum/current toolchain CI, build/test/vet results; no live API requirement in normal tests |
| Platform artifacts, install/upgrade, versioning and cutover | 006 | Six platform builds and recorded runtime/install/upgrade evidence using isolated gh config and approved candidate; confirm executable/version, document differences and rollback, and obtain explicit publication/shell-retirement approvals |
