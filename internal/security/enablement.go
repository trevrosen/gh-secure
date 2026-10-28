package security

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
)

// Mutation records acceptance of a setting change, not completion of analysis.
type Mutation struct {
	// RunURL is an optional CodeQL setup tracking link supplied by GitHub.
	RunURL string
}

// Writer applies a single missing setting without retries or additional inspection.
type Writer interface {
	// Enable sends one typed mutation for a setting already known to be disabled.
	Enable(context.Context, repository.Repository, CheckID) (Mutation, error)
}

// Outcome distinguishes accepted writes, existing settings, and failures.
type Outcome string

const (
	// OutcomeAlreadyEnabled means no write was needed.
	OutcomeAlreadyEnabled Outcome = "already enabled"
	// OutcomeApplied means GitHub accepted every needed write.
	OutcomeApplied Outcome = "applied"
	// OutcomeFailed means no operation succeeded.
	OutcomeFailed Outcome = "failed"
	// OutcomePartial means some operations succeeded and others failed or were skipped.
	OutcomePartial Outcome = "partial"
)

// OperationResult preserves an individual setting's outcome and diagnostic.
type OperationResult struct {
	// ID identifies the setting.
	ID CheckID
	// Outcome is applied, already enabled, or failed for one setting.
	Outcome Outcome
	// RunURL is an optional CodeQL setup tracking link from an accepted write.
	RunURL string
	// Err explains a failed operation.
	Err error
}

// FeatureResult retains independent outcomes, including partial Dependabot changes.
type FeatureResult struct {
	// Feature identifies the feature group.
	Feature Feature
	// Operations contains attempted or evaluated settings in canonical order.
	Operations []OperationResult
	// stopped records why remaining operations were not evaluated.
	stopped error
}

// Err joins failures without discarding typed errors or cancellation.
func (r FeatureResult) Err() error {
	failures := []error{r.stopped}
	for _, operation := range r.Operations {
		if operation.Err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", operation.ID, operation.Err))
		}
	}
	return errors.Join(failures...)
}

// Outcome cannot report complete success after a failure or interrupted apply.
func (r FeatureResult) Outcome() Outcome {
	successes, applied := 0, false
	for _, operation := range r.Operations {
		if operation.Outcome == OutcomeAlreadyEnabled || operation.Outcome == OutcomeApplied {
			successes++
		}
		applied = applied || operation.Outcome == OutcomeApplied
	}
	switch {
	case successes == 0:
		return OutcomeFailed
	case successes < len(r.Operations) || r.Err() != nil:
		return OutcomePartial
	case applied:
		return OutcomeApplied
	default:
		return OutcomeAlreadyEnabled
	}
}

// FeaturePlan snapshots existing inspections without doing I/O.
type FeaturePlan struct {
	feature    Feature
	repository repository.Repository
	checks     []Check
	rulesets   Rulesets
}

// PlanFeature requires exactly one valid inspection for each selected setting.
// Unknown and unsupported states are retained as failures, never missing writes.
func PlanFeature(report StatusReport, feature Feature) (FeaturePlan, error) {
	ids, ok := featureChecks(feature)
	if !ok {
		return FeaturePlan{}, fmt.Errorf("cannot plan unrecognized feature %q", feature)
	}
	plan := FeaturePlan{feature: feature, repository: report.Repository, rulesets: report.Rulesets}
	plan.rulesets.Active = slices.Clone(report.Rulesets.Active)
	for _, id := range ids {
		check, err := singleInspection(report.Checks, id)
		if err != nil {
			return FeaturePlan{}, err
		}
		plan.checks = append(plan.checks, check)
	}
	return plan, nil
}

// singleInspection returns the only inspection for id and rejects missing,
// duplicate, or invalid entries.
func singleInspection(checks []Check, id CheckID) (Check, error) {
	var matches []Check
	for _, check := range checks {
		if check.ID == id {
			matches = append(matches, check)
		}
	}
	if len(matches) == 0 {
		return Check{}, fmt.Errorf("missing inspection for %s", id)
	}
	if len(matches) > 1 {
		return Check{}, fmt.Errorf("duplicate inspection for %s", id)
	}
	if !matches[0].Inspection.State.Valid() {
		return Check{}, fmt.Errorf("invalid inspection state for %s", id)
	}
	return matches[0], nil
}

// Checks returns a copy for confirmation and dry-run rendering.
func (p FeaturePlan) Checks() []Check { return slices.Clone(p.checks) }

// RequiresRulesetConfirmation identifies missing protection with active rulesets.
func (p FeaturePlan) RequiresRulesetConfirmation() bool {
	return p.feature == BranchProtection && len(p.checks) == 1 &&
		p.checks[0].Inspection.State == Disabled && p.rulesets.Known && len(p.rulesets.Active) > 0
}

// ApplyOptions carries explicit approval of the independent overlap safeguard.
// Ordinary CLI confirmations and dry-run dispatch remain task-005 responsibilities.
type ApplyOptions struct {
	AllowRulesetOverlap bool
}

// Apply executes only known-disabled settings. Independent failures do not prevent
// the other Dependabot operation. Cancellation stops further writes; a write that
// was accepted before cancellation is still reported as applied.
func (p FeaturePlan) Apply(ctx context.Context, writer Writer, options ApplyOptions) FeatureResult {
	result := FeatureResult{Feature: p.feature}
	if len(p.checks) == 0 {
		result.stopped = errors.New("cannot apply an uninitialized feature plan")
		return result
	}
	for _, check := range p.checks {
		if err := ctx.Err(); err != nil {
			result.stopped = err
			break
		}
		result.Operations = append(result.Operations, p.applyCheck(ctx, writer, options, check))
	}
	return result
}

// applyCheck evaluates one planned setting and writes only when it is known to be
// disabled and every safeguard passes.
func (p FeaturePlan) applyCheck(ctx context.Context, writer Writer, options ApplyOptions, check Check) OperationResult {
	failed := func(err error) OperationResult {
		return OperationResult{ID: check.ID, Outcome: OutcomeFailed, Err: err}
	}
	if check.Inspection.State == Enabled {
		return OperationResult{ID: check.ID, Outcome: OutcomeAlreadyEnabled}
	}
	if check.Inspection.State != Disabled {
		return failed(fmt.Errorf("cannot enable setting with %s inspection: %s", check.Inspection.State, check.Inspection.Detail))
	}
	if check.ID == LegacyProtection && !p.rulesets.Known {
		return failed(fmt.Errorf("active rulesets are unknown: %s", p.rulesets.Detail))
	}
	if p.RequiresRulesetConfirmation() && !options.AllowRulesetOverlap {
		return failed(errors.New("active rulesets require explicit overlap approval"))
	}
	if writer == nil {
		return failed(errors.New("mutation writer is unavailable"))
	}
	mutation, err := writer.Enable(ctx, p.repository, check.ID)
	if err != nil {
		return failed(err)
	}
	return OperationResult{ID: check.ID, Outcome: OutcomeApplied, RunURL: mutation.RunURL}
}
