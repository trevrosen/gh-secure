package security

import (
	"context"
	"errors"
	"fmt"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
)

// RequireEnablementPermission passes only when metadata reports admin or maintain
// permission. Undisclosed permissions fail closed. Individual endpoints may still
// require additional permission or entitlement.
func RequireEnablementPermission(repo repository.Repository) error {
	granted := func(permission *bool) bool { return permission != nil && *permission }
	if granted(repo.Permissions.Admin) || granted(repo.Permissions.Maintain) {
		return nil
	}
	return fmt.Errorf("enabling security features on %s requires admin or maintain permission, which GitHub did not report for this account", repo.Target)
}

// PlanFeatures plans each selected feature from one inspection report.
func PlanFeatures(report StatusReport, features []Feature) ([]FeaturePlan, error) {
	plans := make([]FeaturePlan, 0, len(features))
	for _, feature := range features {
		plan, err := PlanFeature(report, feature)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

// ApprovalMode is the interactive choice offered when all features are selected.
type ApprovalMode int

const (
	// ApproveAll asks one confirmation for every feature that needs changes.
	ApproveAll ApprovalMode = iota + 1
	// ApproveEach asks a separate confirmation for each feature that needs changes.
	ApproveEach
)

// Approver collects confirmations. Implementations return an error, never a
// decline, when input is unavailable, ends (EOF), or is canceled.
type Approver interface {
	// ChooseMode selects single or per-feature confirmation.
	ChooseMode(ctx context.Context) (ApprovalMode, error)
	// ConfirmFeatures asks once for every listed feature that needs changes.
	ConfirmFeatures(ctx context.Context, repo repository.Repository, features []Feature) (bool, error)
	// ConfirmFeature asks for one feature in per-feature mode.
	ConfirmFeature(ctx context.Context, feature Feature) (bool, error)
	// ConfirmRulesetOverlap asks the safeguard that --yes never answers.
	ConfirmRulesetOverlap(ctx context.Context, rulesets Rulesets) (bool, error)
}

// ApprovalOptions carries the command-line choices that affect confirmation.
type ApprovalOptions struct {
	// Yes approves ordinary confirmations, never the active-ruleset safeguard.
	Yes bool
	// ExplicitSelection uses one subset confirmation instead of offering modes.
	ExplicitSelection bool
}

// Decision records how one feature plan may proceed after confirmation.
type Decision struct {
	// Declined means the user voluntarily declined the feature's writes.
	Declined bool
	// Blocked explains why a required safeguard could not be answered.
	Blocked error
	// AllowRulesetOverlap records explicit approval of the overlap safeguard.
	AllowRulesetOverlap bool
}

// Approve collects every required confirmation before any write, returning one
// decision per plan. Ordinary-confirmation failures (non-TTY without --yes, EOF)
// and cancellation abort with an error. An unanswerable overlap safeguard blocks
// only branch protection; the remaining confirmations are still collected.
func Approve(ctx context.Context, approver Approver, plans []FeaturePlan, options ApprovalOptions) ([]Decision, error) {
	decisions := make([]Decision, len(plans))
	var pending []FeaturePlan
	var positions []int
	for index, plan := range plans {
		if plan.NeedsApproval() {
			pending = append(pending, plan)
			positions = append(positions, index)
		}
	}
	if len(pending) == 0 {
		return decisions, nil
	}

	mode, err := approvalMode(ctx, approver, len(pending), options)
	if err != nil {
		return nil, err
	}
	if mode == ApproveAll {
		features := make([]Feature, len(pending))
		for index, plan := range pending {
			features[index] = plan.Feature()
		}
		approved, err := approver.ConfirmFeatures(ctx, pending[0].Repository(), features)
		if err != nil {
			return nil, err
		}
		if !approved {
			for _, position := range positions {
				decisions[position].Declined = true
			}
			return decisions, nil
		}
	}

	for index, plan := range pending {
		decision, err := approveFeature(ctx, approver, plan, mode == ApproveEach)
		if err != nil {
			return nil, err
		}
		decisions[positions[index]] = decision
	}
	return decisions, nil
}

// preapproved means --yes answered every ordinary confirmation.
const preapproved ApprovalMode = 0

// approvalMode offers the mode choice only for the default all-feature selection
// when more than one feature needs approval.
func approvalMode(ctx context.Context, approver Approver, pending int, options ApprovalOptions) (ApprovalMode, error) {
	switch {
	case options.Yes:
		return preapproved, nil
	case options.ExplicitSelection || pending == 1:
		return ApproveAll, nil
	}
	mode, err := approver.ChooseMode(ctx)
	if err != nil {
		return 0, err
	}
	if mode != ApproveAll && mode != ApproveEach {
		return 0, fmt.Errorf("unsupported confirmation mode %d", mode)
	}
	return mode, nil
}

// approveFeature asks the per-feature confirmation when requested, then the
// overlap safeguard. A declined feature is never asked the safeguard.
func approveFeature(ctx context.Context, approver Approver, plan FeaturePlan, askFeature bool) (Decision, error) {
	if askFeature {
		approved, err := approver.ConfirmFeature(ctx, plan.Feature())
		if err != nil {
			return Decision{}, err
		}
		if !approved {
			return Decision{Declined: true}, nil
		}
	}
	if !plan.RequiresRulesetConfirmation() {
		return Decision{}, nil
	}
	approved, err := approver.ConfirmRulesetOverlap(ctx, plan.Rulesets())
	switch {
	case ctx.Err() != nil:
		return Decision{}, ctx.Err()
	case err != nil:
		return Decision{Blocked: fmt.Errorf("active-ruleset overlap was not approved: %w", err)}, nil
	case approved:
		return Decision{AllowRulesetOverlap: true}, nil
	default:
		return Decision{Declined: true}, nil
	}
}

// EnablementResult aggregates feature results in canonical order.
type EnablementResult struct {
	// Repository is the target whose features were evaluated.
	Repository repository.Repository
	// DryRun records that no writes could have been sent.
	DryRun bool
	// Features contains results for every evaluated feature.
	Features []FeatureResult
	// NotAttempted lists selected features skipped after cancellation.
	NotAttempted []Feature
	// Interrupted records why evaluation stopped before every feature was reached.
	Interrupted error
}

// Err reports failed or partial features and interruption. Declines, planned
// operations, and already-enabled settings are successful outcomes.
func (r EnablementResult) Err() error {
	var problems []error
	for _, feature := range r.Features {
		if err := feature.Err(); err != nil {
			problems = append(problems, err)
		}
	}
	if r.Interrupted != nil {
		problems = append(problems, fmt.Errorf("interrupted with %d feature(s) not attempted: %w", len(r.NotAttempted), r.Interrupted))
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("security enablement incomplete: %w", errors.Join(problems...))
}

// ApplyPlans executes approved plans sequentially in canonical order. Declined
// and blocked plans never reach writer. Cancellation stops later features.
func ApplyPlans(ctx context.Context, writer Writer, plans []FeaturePlan, decisions []Decision) EnablementResult {
	return executePlans(ctx, plans, decisions, func(plan FeaturePlan, options ApplyOptions) FeatureResult {
		return plan.Apply(ctx, writer, options)
	})
}

// PreviewPlans reports planned outcomes for approved plans. It has no writer, so
// a dry run cannot send mutations.
func PreviewPlans(ctx context.Context, plans []FeaturePlan, decisions []Decision) EnablementResult {
	result := executePlans(ctx, plans, decisions, FeaturePlan.Preview)
	result.DryRun = true
	return result
}

// executePlans resolves declined and blocked plans without execute and fails
// closed, attempting nothing, if decisions do not match plans one-to-one.
func executePlans(ctx context.Context, plans []FeaturePlan, decisions []Decision, execute func(FeaturePlan, ApplyOptions) FeatureResult) EnablementResult {
	var result EnablementResult
	if len(plans) > 0 {
		result.Repository = plans[0].Repository()
	}
	if len(decisions) != len(plans) {
		result.Interrupted = fmt.Errorf("internal error: %d decisions for %d plans", len(decisions), len(plans))
		for _, plan := range plans {
			result.NotAttempted = append(result.NotAttempted, plan.Feature())
		}
		return result
	}
	for index, plan := range plans {
		if err := ctx.Err(); err != nil {
			result.Interrupted = err
			for _, remaining := range plans[index:] {
				result.NotAttempted = append(result.NotAttempted, remaining.Feature())
			}
			break
		}
		decision := decisions[index]
		var feature FeatureResult
		switch {
		case decision.Declined:
			feature = plan.Decline()
		case decision.Blocked != nil:
			feature = plan.Block(decision.Blocked)
		default:
			feature = execute(plan, ApplyOptions{AllowRulesetOverlap: decision.AllowRulesetOverlap})
		}
		result.Features = append(result.Features, feature)
	}
	return result
}
