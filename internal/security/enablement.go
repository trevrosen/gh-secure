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
	RunURL string
}

// Writer applies a single missing setting without retries or additional inspection.
type Writer interface {
	Enable(context.Context, repository.Repository, CheckID) (Mutation, error)
}

// Outcome distinguishes accepted writes, existing settings, and failures.
type Outcome string

const (
	OutcomeAlreadyEnabled Outcome = "already enabled"
	OutcomeApplied        Outcome = "applied"
	OutcomeFailed         Outcome = "failed"
	OutcomePartial        Outcome = "partial"
)

// OperationResult preserves an individual setting's outcome and diagnostic.
type OperationResult struct {
	ID      CheckID
	Outcome Outcome
	RunURL  string
	Err     error
}

// FeatureResult retains independent outcomes, including partial Dependabot changes.
type FeatureResult struct {
	Feature    Feature
	Operations []OperationResult
	stopped    error
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
	if r.Err() != nil || successes != len(r.Operations) || successes == 0 {
		if successes > 0 {
			return OutcomePartial
		}
		return OutcomeFailed
	}
	if applied {
		return OutcomeApplied
	}
	return OutcomeAlreadyEnabled
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
	var ids []CheckID
	switch feature {
	case BranchProtection:
		ids = []CheckID{LegacyProtection}
	case VulnerabilityReporting:
		ids = []CheckID{PrivateReporting}
	case SecretScanning:
		ids = []CheckID{PushProtection}
	case Dependabot:
		ids = []CheckID{DependabotAlerts, DependabotUpdates}
	case CodeScanning:
		ids = []CheckID{CodeQLSetup}
	default:
		return FeaturePlan{}, fmt.Errorf("cannot plan unrecognized feature %q", feature)
	}
	plan := FeaturePlan{feature: feature, repository: report.Repository, rulesets: report.Rulesets}
	plan.rulesets.Active = slices.Clone(report.Rulesets.Active)
	for _, id := range ids {
		found := false
		for _, check := range report.Checks {
			if check.ID != id {
				continue
			}
			if found {
				return FeaturePlan{}, fmt.Errorf("duplicate inspection for %s", id)
			}
			switch check.Inspection.State {
			case Enabled, Disabled, Unknown, Unsupported:
			default:
				return FeaturePlan{}, fmt.Errorf("invalid inspection state for %s", id)
			}
			plan.checks = append(plan.checks, check)
			found = true
		}
		if !found {
			return FeaturePlan{}, fmt.Errorf("missing inspection for %s", id)
		}
	}
	return plan, nil
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
// the other Dependabot operation; cancellation stops further writes.
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
		operation := OperationResult{ID: check.ID, Outcome: OutcomeFailed}
		switch check.Inspection.State {
		case Enabled:
			operation.Outcome = OutcomeAlreadyEnabled
		case Disabled:
			switch {
			case check.ID == LegacyProtection && !p.rulesets.Known:
				operation.Err = fmt.Errorf("active rulesets are unknown: %s", p.rulesets.Detail)
			case p.RequiresRulesetConfirmation() && !options.AllowRulesetOverlap:
				operation.Err = errors.New("active rulesets require explicit overlap approval")
			case writer == nil:
				operation.Err = errors.New("mutation writer is unavailable")
			default:
				mutation, err := writer.Enable(ctx, p.repository, check.ID)
				operation.Err = err
				if err == nil {
					operation.Outcome = OutcomeApplied
					operation.RunURL = mutation.RunURL
				}
			}
		default:
			operation.Err = fmt.Errorf("cannot enable setting with %s inspection: %s", check.Inspection.State, check.Inspection.Detail)
		}
		result.Operations = append(result.Operations, operation)
		if err := ctx.Err(); err != nil {
			result.stopped = err
			break
		}
	}
	return result
}
