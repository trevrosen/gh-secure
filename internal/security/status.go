package security

import (
	"context"
	"fmt"
	"strings"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
)

// State describes what an inspection can establish about a setting.
type State string

const (
	// Enabled means the setting is known to be enabled.
	Enabled State = "enabled"
	// Disabled means an endpoint-specific response establishes that the setting is off.
	Disabled State = "disabled"
	// Unknown means the setting could not be reliably inspected.
	Unknown State = "unknown"
	// Unsupported means positive evidence establishes feature unavailability.
	Unsupported State = "unsupported"
)

// CheckID identifies an individual security check, including Dependabot's two settings.
type CheckID string

const (
	// LegacyProtection checks legacy default-branch protection, not rulesets.
	LegacyProtection CheckID = CheckID(BranchProtection)
	// PrivateReporting checks private vulnerability reporting.
	PrivateReporting CheckID = CheckID(VulnerabilityReporting)
	// PushProtection checks secret scanning push protection.
	PushProtection CheckID = CheckID(SecretScanning)
	// DependabotAlerts checks dependency vulnerability alerts.
	DependabotAlerts CheckID = "dependabot-alerts"
	// DependabotUpdates checks automated security updates, not version updates.
	DependabotUpdates CheckID = "dependabot-updates"
	// CodeQLSetup checks configuration, not completed analysis.
	CodeQLSetup CheckID = CheckID(CodeScanning)
)

// Inspection carries a setting's state and any actionable diagnostic.
type Inspection struct {
	// State records the inspection outcome.
	State State
	// Detail explains unavailable, indeterminate, or failed inspection.
	Detail string
}

// Check associates an individual setting with its inspection outcome.
type Check struct {
	// ID identifies the setting being inspected.
	ID CheckID
	// Label is the human-readable setting name.
	Label string
	// Inspection is the observed setting state.
	Inspection Inspection
}

// Rulesets describes active rulesets without claiming default-branch coverage.
type Rulesets struct {
	// Known is true only after every page was successfully inspected.
	Known bool
	// Active contains the names of all active rulesets when Known is true.
	Active []string
	// Detail explains an incomplete ruleset inspection.
	Detail string
}

// Policy describes an advisory security-policy lookup independently of feature checks.
type Policy struct {
	// State is Enabled for an explicit policy URL or Unknown when not assessed.
	State State
	// URL points to the known security policy, when present.
	URL string
	// Detail explains a failed or indeterminate advisory lookup.
	Detail string
}

// Reader supplies the read-only operations needed for status inspection.
type Reader interface {
	// Repository fetches required metadata without enforcing enablement permissions.
	Repository(context.Context, repository.Target) (repository.Repository, error)
	// Inspect checks one setting using the resolved metadata.
	Inspect(context.Context, repository.Repository, CheckID) Inspection
	// Rulesets inspects every page of active-ruleset metadata.
	Rulesets(context.Context, repository.Repository) Rulesets
}

// StatusReport preserves all six checks and the independent ruleset annotation.
type StatusReport struct {
	// Repository is the metadata used for the inspection.
	Repository repository.Repository
	// Checks contains the six checks in canonical display order.
	Checks []Check
	// Rulesets is advisory metadata, not a seventh security check.
	Rulesets Rulesets
}

// EnabledCount counts only checks whose state is known to be enabled.
func (r StatusReport) EnabledCount() int {
	return r.Count(Enabled)
}

// Count returns the number of inspected checks in the given state.
// Uninspected checks and ruleset annotations are not included.
func (r StatusReport) Count(state State) int {
	count := 0
	for _, check := range r.Checks {
		if check.Inspection.State == state {
			count++
		}
	}
	return count
}

// Err identifies unresolved checks and rulesets, while known disabled settings
// remain successful.
func (r StatusReport) Err() error {
	var unresolved []string
	if len(r.Checks) != 6 {
		unresolved = append(unresolved, fmt.Sprintf("%d/6 checks completed", len(r.Checks)))
	}
	for _, check := range r.Checks {
		switch check.Inspection.State {
		case Enabled, Disabled:
		case Unknown, Unsupported:
			unresolved = append(unresolved, fmt.Sprintf("%s: %s", check.Label, check.Inspection.State))
		default:
			unresolved = append(unresolved, fmt.Sprintf("%s: invalid inspection state", check.Label))
		}
	}
	if !r.Rulesets.Known {
		unresolved = append(unresolved, "active rulesets: unknown")
	}
	if len(unresolved) > 0 {
		return fmt.Errorf("security inspection incomplete: %s", strings.Join(unresolved, "; "))
	}
	return nil
}

// InspectStatus fetches metadata once, then checks settings and rulesets sequentially.
// Cancellation stops further reads; independent feature-local failures are preserved.
func InspectStatus(ctx context.Context, reader Reader, target repository.Target) (StatusReport, error) {
	if err := ctx.Err(); err != nil {
		return StatusReport{}, err
	}
	repo, err := reader.Repository(ctx, target)
	if err != nil {
		return StatusReport{}, fmt.Errorf("inspect repository metadata: %w", err)
	}
	report := StatusReport{Repository: repo, Rulesets: Rulesets{Detail: "not inspected"}}
	checks := []struct {
		id    CheckID
		label string
	}{
		{LegacyProtection, "Legacy branch protection"},
		{PrivateReporting, "Private vulnerability reporting"},
		{PushProtection, "Secret scanning push protection"},
		{DependabotAlerts, "Dependabot alerts"},
		{DependabotUpdates, "Dependabot security updates"},
		{CodeQLSetup, "CodeQL default setup"},
	}
	for _, check := range checks {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		result := reader.Inspect(ctx, repo, check.id)
		report.Checks = append(report.Checks, Check{ID: check.id, Label: check.label, Inspection: result})
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if check.id == LegacyProtection {
			report.Rulesets = reader.Rulesets(ctx, repo)
		}
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	return report, nil
}
