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
	// OutcomePlanned means a dry run found a needed, approved write and sent nothing.
	OutcomePlanned Outcome = "planned"
	// OutcomeDeclined means the user voluntarily declined a needed write.
	OutcomeDeclined Outcome = "declined"
)

// OperationResult preserves an individual setting's outcome and diagnostic.
type OperationResult struct {
	// ID identifies the setting.
	ID CheckID
	// Outcome is applied, already enabled, planned, declined, or failed for one setting.
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
// A voluntary decline never hides an independent failure.
func (r FeatureResult) Outcome() Outcome {
	counts := make(map[Outcome]int)
	for _, operation := range r.Operations {
		counts[operation.Outcome]++
	}
	successes := counts[OutcomeApplied] + counts[OutcomeAlreadyEnabled] + counts[OutcomePlanned]
	switch {
	case len(r.Operations) == 0 || (r.Err() != nil && successes == 0):
		return OutcomeFailed
	case r.Err() != nil:
		return OutcomePartial
	case counts[OutcomeDeclined] > 0:
		return OutcomeDeclined
	case counts[OutcomeApplied] > 0:
		return OutcomeApplied
	case counts[OutcomePlanned] > 0:
		return OutcomePlanned
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

// Feature identifies the planned feature group.
func (p FeaturePlan) Feature() Feature { return p.feature }

// Repository returns the metadata the plan was inspected against.
func (p FeaturePlan) Repository() repository.Repository { return p.repository }

// Checks returns a copy for confirmation and dry-run rendering.
func (p FeaturePlan) Checks() []Check { return slices.Clone(p.checks) }

// Rulesets returns the active-ruleset annotation used by the overlap safeguard.
func (p FeaturePlan) Rulesets() Rulesets {
	rulesets := p.rulesets
	rulesets.Active = slices.Clone(p.rulesets.Active)
	return rulesets
}

// RequiresRulesetConfirmation identifies missing protection with active rulesets.
func (p FeaturePlan) RequiresRulesetConfirmation() bool {
	return p.feature == BranchProtection && len(p.checks) == 1 &&
		p.checks[0].Inspection.State == Disabled && p.rulesets.Known && len(p.rulesets.Active) > 0
}

// NeedsApproval reports whether any setting could be written once approved.
// Enabled settings and settings that can only fail need no confirmation.
func (p FeaturePlan) NeedsApproval() bool {
	for _, check := range p.checks {
		if _, settled := p.settle(check, ApplyOptions{AllowRulesetOverlap: true}); !settled {
			return true
		}
	}
	return false
}

// ApplyOptions carries explicit approval of the independent overlap safeguard.
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

// Preview reports the writes Apply would send, as planned outcomes, without I/O.
func (p FeaturePlan) Preview(options ApplyOptions) FeatureResult {
	return p.resolve(func(check Check) OperationResult {
		if result, settled := p.settle(check, options); settled {
			return result
		}
		return OperationResult{ID: check.ID, Outcome: OutcomePlanned}
	})
}

// Decline records a voluntary decline for every setting that needed a write.
// Settings that could not be written keep their failures.
func (p FeaturePlan) Decline() FeatureResult {
	return p.withoutWrites(OutcomeDeclined, nil)
}

// Block records reason as the failure of every setting that needed a write,
// such as an overlap safeguard that could not be answered.
func (p FeaturePlan) Block(reason error) FeatureResult {
	return p.withoutWrites(OutcomeFailed, reason)
}

// withoutWrites resolves each writable setting to outcome without writing.
func (p FeaturePlan) withoutWrites(outcome Outcome, err error) FeatureResult {
	return p.resolve(func(check Check) OperationResult {
		if result, settled := p.settle(check, ApplyOptions{AllowRulesetOverlap: true}); settled {
			return result
		}
		return OperationResult{ID: check.ID, Outcome: outcome, Err: err}
	})
}

// resolve maps every planned setting without I/O.
func (p FeaturePlan) resolve(operation func(Check) OperationResult) FeatureResult {
	result := FeatureResult{Feature: p.feature}
	if len(p.checks) == 0 {
		result.stopped = errors.New("cannot resolve an uninitialized feature plan")
	}
	for _, check := range p.checks {
		result.Operations = append(result.Operations, operation(check))
	}
	return result
}

// applyCheck writes one setting when every safeguard passes.
func (p FeaturePlan) applyCheck(ctx context.Context, writer Writer, options ApplyOptions, check Check) OperationResult {
	if result, settled := p.settle(check, options); settled {
		return result
	}
	if writer == nil {
		return failedOperation(check.ID, errors.New("mutation writer is unavailable"))
	}
	mutation, err := writer.Enable(ctx, p.repository, check.ID)
	if err != nil {
		return failedOperation(check.ID, err)
	}
	return OperationResult{ID: check.ID, Outcome: OutcomeApplied, RunURL: mutation.RunURL}
}

// settle returns the final result for a setting that must not be written, or
// settled=false when the setting is known to be disabled and every safeguard passes.
func (p FeaturePlan) settle(check Check, options ApplyOptions) (result OperationResult, settled bool) {
	switch {
	case check.Inspection.State == Enabled:
		return OperationResult{ID: check.ID, Outcome: OutcomeAlreadyEnabled}, true
	case check.Inspection.State != Disabled:
		return failedOperation(check.ID, fmt.Errorf("cannot enable setting with %s inspection: %s", check.Inspection.State, check.Inspection.Detail)), true
	case check.ID == LegacyProtection && !p.rulesets.Known:
		return failedOperation(check.ID, fmt.Errorf("active rulesets are unknown: %s", p.rulesets.Detail)), true
	case p.RequiresRulesetConfirmation() && !options.AllowRulesetOverlap:
		return failedOperation(check.ID, errors.New("active rulesets require explicit overlap approval")), true
	default:
		return OperationResult{}, false
	}
}

func failedOperation(id CheckID, err error) OperationResult {
	return OperationResult{ID: id, Outcome: OutcomeFailed, Err: err}
}
