package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
)

// featureGuidance explains why each feature matters and where to learn more.
var featureGuidance = map[security.Feature]struct {
	why  string
	docs string
}{
	security.BranchProtection: {
		"Blocks force pushes and deletions and requires a reviewed pull request before changes reach the default branch.",
		"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches",
	},
	security.VulnerabilityReporting: {
		"Gives researchers and users a private path to report vulnerabilities before they are public.",
		"https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability",
	},
	security.SecretScanning: {
		"Push protection blocks pushes that contain supported secrets such as API keys and tokens.",
		"https://docs.github.com/code-security/secret-scanning/about-secret-scanning",
	},
	security.Dependabot: {
		"Alerts on dependencies with known vulnerabilities and opens pull requests that update them. Version updates are not configured.",
		"https://docs.github.com/en/code-security/getting-started/dependabot-quickstart-guide",
	},
	security.CodeScanning: {
		"CodeQL default setup detects common vulnerabilities in code and pull requests.",
		"https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning",
	},
}

// RenderPreflight warns on ErrOut before enabling features on a private repository.
func (s Streams) RenderPreflight(repo repository.Repository) error {
	if !repo.Private {
		return nil
	}
	return writeAll(s.ErrOut, "repository warning", fmt.Sprintf(
		"Warning: %s is private. Private vulnerability reporting is unavailable for private repositories, "+
			"and other features may require additional licensing or entitlements.\n", repo.Target))
}

// RenderPlan explains each selected feature and the action planned for each setting.
func (s Streams) RenderPlan(plans []security.FeaturePlan, dryRun bool) error {
	var text strings.Builder
	if dryRun {
		text.WriteString("Dry run: settings are inspected, but no changes will be made.\n")
	}
	if len(plans) > 0 {
		repo := plans[0].Repository()
		fmt.Fprintf(&text, "Security enablement plan for %s (default branch %q)\n", repo.Target, repo.DefaultBranch)
	}
	for _, plan := range plans {
		guidance := featureGuidance[plan.Feature()]
		fmt.Fprintf(&text, "\n%s\n  %s\n  Docs: %s\n", plan.Feature(), guidance.why, guidance.docs)
		preview := plan.Preview(security.ApplyOptions{AllowRulesetOverlap: true})
		checks := plan.Checks()
		for index, operation := range preview.Operations {
			fmt.Fprintf(&text, "  %-36s %-12s %s\n", operation.ID.Label(), checks[index].Inspection.State, plannedAction(operation))
		}
		if plan.Feature() == security.BranchProtection {
			fmt.Fprintf(&text, "  Active rulesets: %s\n", rulesetsSummary(plan.Rulesets()))
			if plan.RequiresRulesetConfirmation() {
				text.WriteString("  Adding legacy protection requires separate approval, even with --yes.\n")
			}
		}
	}
	text.WriteString("\n")
	return writeAll(s.Out, "enablement plan", text.String())
}

func plannedAction(operation security.OperationResult) string {
	switch operation.Outcome {
	case security.OutcomeAlreadyEnabled:
		return "no change needed"
	case security.OutcomePlanned:
		return "will enable if approved"
	default:
		return fmt.Sprintf("cannot enable: %v", operation.Err)
	}
}

// RenderEnablement summarizes every feature and setting outcome, then follow-up
// links. A nil policy means the advisory lookup was skipped.
func (s Streams) RenderEnablement(result security.EnablementResult, policy *security.Policy) error {
	var text strings.Builder
	if result.DryRun {
		fmt.Fprintf(&text, "Dry-run summary for %s (no changes were made)\n", result.Repository.Target)
	} else {
		fmt.Fprintf(&text, "Enablement summary for %s\n", result.Repository.Target)
	}
	totals := make(map[security.Outcome]int)
	privateReportingOn := false
	for _, feature := range result.Features {
		outcome := feature.Outcome()
		totals[outcome]++
		fmt.Fprintf(&text, "  %-25s %s\n", feature.Feature, outcome)
		for _, operation := range feature.Operations {
			fmt.Fprintf(&text, "    %-36s %s\n", operation.ID.Label(), operationDetail(operation))
			if operation.ID == security.PrivateReporting &&
				(operation.Outcome == security.OutcomeApplied || operation.Outcome == security.OutcomeAlreadyEnabled) {
				privateReportingOn = true
			}
		}
	}
	for _, feature := range result.NotAttempted {
		fmt.Fprintf(&text, "  %-25s not attempted\n", feature)
	}
	if result.Interrupted != nil {
		fmt.Fprintf(&text, "Interrupted: %v\n", result.Interrupted)
	}
	fmt.Fprintf(&text, "\nTotals: %d applied, %d already enabled, %d planned, %d declined, %d partial, %d failed, %d not attempted\n",
		totals[security.OutcomeApplied], totals[security.OutcomeAlreadyEnabled], totals[security.OutcomePlanned],
		totals[security.OutcomeDeclined], totals[security.OutcomePartial], totals[security.OutcomeFailed], len(result.NotAttempted))

	baseURL := result.Repository.Target.WebURL()
	fmt.Fprintf(&text, "\nSecurity settings: %s/settings/security_analysis\nSecurity overview: %s/security\n", baseURL, baseURL)
	if privateReportingOn {
		fmt.Fprintf(&text, "Private reporting: %s/security/advisories/new\n", baseURL)
	}
	if policy != nil {
		if policy.State == security.Enabled {
			fmt.Fprintf(&text, "Security policy: %s\n", policy.URL)
		} else {
			fmt.Fprintf(&text, "Security policy advisory: %s\n", policy.Detail)
		}
	}
	return writeAll(s.Out, "enablement summary", text.String())
}

func operationDetail(operation security.OperationResult) string {
	switch {
	case operation.Outcome == security.OutcomeFailed && operation.Err != nil:
		return "failed: " + operation.Err.Error()
	case operation.Outcome == security.OutcomePlanned:
		return "planned (would enable)"
	case operation.RunURL != "":
		return fmt.Sprintf("%s; configuration accepted, analysis may still be running: %s", operation.Outcome, operation.RunURL)
	default:
		return string(operation.Outcome)
	}
}

// writeAll writes text with one call, treating a short write as failure.
func writeAll(writer io.Writer, what, text string) error {
	written, err := io.WriteString(writer, text)
	if err == nil && written != len(text) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", what, err)
	}
	return nil
}
