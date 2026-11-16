# 009: Make status and enablement visibility-aware

Status: Done
Depends on: 005

## Context

The product targets public repositories, but nothing prevents users from
running it on private or internal repositories, and it currently treats them
like public ones with a warning
([spec: repository, permissions, and interaction](../spec.md#repository-permissions-and-interaction);
[architecture](../architecture/README.md)).
For non-public repositories that produces misleading or noisy results:

- Private vulnerability reporting is documented as public-only. The Go port
  marks it `unsupported`, so `status` and default enablement return exit 1
  when that check is evaluated, even if every applicable setting is enabled.
- The Go port enables push protection, but not secret scanning itself. On
  GitHub.com, organization-owned private/internal repositories require
  [GitHub Secret Protection](https://docs.github.com/en/billing/concepts/product-billing/github-advanced-security)
  for repository-level push protection and
  [GitHub Code Security](https://docs.github.com/en/code-security/reference/code-scanning/troubleshoot-analysis-errors/private-repository-enablement)
  for CodeQL default setup. Confirm prerequisites and host-specific
  entitlements before changing these features.
- Organization or enterprise security configurations can be attached to a
  repository and enforced, which can prevent repository-level changes to
  affected settings. Organization policy can also stop repository
  administrators from changing Advanced Security features. In those cases a
  repository admin cannot change the setting, and the right next step is to
  contact the appropriate organization or enterprise administrator. Currently
  this can appear as a generic 403/422 failure.
- Repository metadata exposes `visibility` (`public`, `private`, `internal`);
  the adapter reads only the `private` boolean, so internal repositories cannot
  be distinguished from private ones.
- Organization security managers can configure security features without
  admin or maintain permission, but the enablement preflight rejects them.

The public-repository experience is the primary audience and must not regress.

## Approved decisions

The maintainer approved these decisions during implementation and review:

1. Public-only checks use a distinct `not applicable` state on private/internal
   repositories. It is displayed, excluded from status totals, and does not
   fail status. Unknown visibility remains unknown.
2. Default enablement omits inapplicable features from private/internal plans.
   An explicit selector reports not applicable without requesting the
   feature-specific endpoint or attempting a write.
3. Licensing/unavailable API results remain unknown. Policy control is
   recognized only from a positively retrieved attached security configuration
   that is enforced and has an explicit per-feature setting. Explicit `not_set`
   is not enforced. A failed or ambiguous configuration lookup blocks writes;
   an unknown setting in a known enforced configuration blocks the affected
   write. A 403/404 does not establish that no configuration exists.
4. Enablement preflight remains limited to reported admin/maintain permission;
   security-manager role discovery or bypass is out of scope.
5. Internal repositories follow private-repository behavior.
6. Preserve the Bash extension's behavior: enable push protection only, not
   base secret scanning. For private/internal or unknown visibility, require
   existing enabled base scanning before attempting a push-protection write.
   This supersedes the earlier proposal to enable base scanning only with
   confirmed entitlement.

## Scope and non-goals

In scope: repository metadata (visibility and relevant `security_and_analysis`
fields), the inspection-state model where needed, status and enablement
rendering, exit-code mapping for non-applicable checks, preflight messaging,
and related specification, README, and help text.

Out of scope: changing the shipping Bash script, purchasing or enabling
licenses, editing organization or enterprise security configurations or
policies, organization-wide rollout, and unrelated new security features. Do not
weaken the existing mutation safeguards: only known-disabled settings may
produce writes, and ambiguous 403/404 responses must not become `disabled` or
`not applicable`.

## Prompt

> Read the specification, architecture, tasks 003-005, and the existing
> inspection, planning, and rendering code before editing. Resolve the decision
> gates with the maintainer first. Then make status and enablement
> visibility-aware: read repository visibility, tailor explanations and
> next steps to public, private, and internal repositories, and present
> features that do not apply or are controlled by licensing or organization
> policy in a way that is accurate, does not inflate failure counts, and guides
> the user to the appropriate administrator. Keep the public-repository output
> and exit codes unchanged except where a decision explicitly changes them.
> Reuse the existing typed states and adapter patterns; add a state only if
> approved.
> Add offline fixtures for each visibility, entitlement-unavailable and
> enforced-configuration cases (if approved evidence exists), ambiguous
> 403/404 responses, dry-run, and explicit selectors. Update the
> specification, README, and help. Do not modify the Bash script or perform
> live mutations.

## Acceptance criteria

- Status and enablement report the repository's visibility, including
  `internal`, from documented metadata; missing or unrecognized visibility is
  handled without assuming public.
- Public repositories produce the same checks, totals, writes, and exit codes
  as before unless an approved decision explicitly changes them.
- On private and internal repositories, private vulnerability reporting is
  presented according to the approved decision; it neither sends a request nor
  makes an otherwise fully enabled repository report failure.
- Default private/internal enablement omits public-only checks; explicitly
  selecting one reports not applicable without making a feature-specific
  request or write.
- Features unavailable because of licensing or enforced organization/enterprise
  configuration are identified only from approved, documented evidence and
  direct users to the appropriate administrator for the setting, policy, or
  entitlement. Ambiguous responses remain `unknown` and never produce writes.
- The enablement preflight and its messaging match the approved
  security-manager decision.
- Explicit selectors, dry-run, `--yes`, and the ruleset safeguard behave as
  approved for each visibility; dry-run sends no mutations.
- Offline tests cover the cases above; `make check` and `make test-race` pass.
- The specification, README (including "free for open source" and
  prerequisites), and help describe visibility-specific behavior.

## Completion record

Implemented visibility-aware metadata, status, enablement planning, policy
annotations, and conservative private/internal push-protection handling. An
unresolved configuration relationship blocks writes, and base secret scanning
is never mutated. Added offline coverage for public/private/internal and unknown visibility,
not-applicable selectors, policy evidence, entitlement failures, and
zero-mutation paths. Updated the specification, architecture, README,
contributor guide, task index, and command help. The root Bash script remains
unchanged and is still the shipping extension.

Verification: `make check` passed (dependency consistency, lint, Bash syntax,
Go build/tests, and hook tests); `make test-race` passed. No live mutations were
performed.

Remaining limitation: licensing is not inferred from disabled or inaccessible
API responses. An ambiguous 404 can block all writes on a non-public repository
even if no configuration is attached. Private/internal push-protection writes
require existing enabled base scanning; organization security-manager preflight
support remains out of scope.
