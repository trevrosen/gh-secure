package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
)

// RenderStatus writes six-check results and independent active-ruleset information.
// Not-applicable checks are excluded from totals; unknown checks never count as enabled.
func (s Streams) RenderStatus(report security.StatusReport) error {
	var text strings.Builder
	fmt.Fprintf(&text, "Security status for %s\nDefault branch: %q\n", report.Repository.Target, report.Repository.DefaultBranch)
	fmt.Fprintf(&text, "Visibility: %s\n", report.Repository.Visibility)
	if report.Repository.VisibilityDetail != "" {
		fmt.Fprintf(&text, "  %s\n", report.Repository.VisibilityDetail)
	}
	if control, blocked := security.ConfigurationControl(report.Repository, security.LegacyProtection); blocked {
		fmt.Fprintf(&text, "Security configuration: %s\n", control.Detail)
	}
	if report.Repository.Visibility != repository.VisibilityPublic {
		fmt.Fprintf(&text, "Secret scanning: %s\n", statusMetadata(report.Repository.SecretScanning))
	}
	text.WriteString("\n")
	for _, check := range report.Checks {
		if !check.Inspection.State.Valid() {
			return fmt.Errorf("invalid inspection state for %s", check.ID)
		}
		fmt.Fprintf(&text, "  %-36s %s\n", check.Label, check.Inspection.State)
		if check.Inspection.Detail != "" {
			fmt.Fprintf(&text, "    %s\n", check.Inspection.Detail)
		}
		if check.ID == security.LegacyProtection {
			fmt.Fprintf(&text, "    Active rulesets: %s\n", rulesetsSummary(report.Rulesets))
		}
	}
	complete := len(report.Checks) == 6
	summaryLabel := "Summary (6 checks)"
	if !complete {
		summaryLabel = "Partial summary"
	}
	if complete && report.ApplicableCount() != 6 {
		summaryLabel = fmt.Sprintf("Summary (%d applicable checks)", report.ApplicableCount())
	}
	fmt.Fprintf(&text, "\n%s: %d enabled, %d disabled, %d unknown, %d unsupported\n",
		summaryLabel, report.Count(security.Enabled), report.Count(security.Disabled),
		report.Count(security.Unknown), report.Count(security.Unsupported))
	if !complete {
		fmt.Fprintf(&text, "Inspection incomplete: %d/6 checks completed\n", len(report.Checks))
	}
	baseURL := report.Repository.Target.WebURL()
	fmt.Fprintf(&text, "\nSecurity settings: %s/settings/security_analysis\nSecurity overview: %s/security\n", baseURL, baseURL)
	for _, check := range report.Checks {
		if check.ID == security.PrivateReporting && check.Inspection.State == security.Enabled {
			fmt.Fprintf(&text, "Private reporting: %s/security/advisories/new\n", baseURL)
		}
	}
	return writeAll(s.Out, "security status", text.String())
}

func statusMetadata(value string) string {
	switch value {
	case "enabled", "disabled":
		return value
	default:
		return "unknown"
	}
}

// rulesetsSummary describes active rulesets without implying branch protection.
func rulesetsSummary(rulesets security.Rulesets) string {
	if !rulesets.Known {
		return "unknown; " + rulesets.Detail
	}
	if len(rulesets.Active) == 0 {
		return "0; not proof of default-branch protection"
	}
	names := make([]string, len(rulesets.Active))
	for index, name := range rulesets.Active {
		names[index] = strconv.Quote(name)
	}
	return fmt.Sprintf("%d (%s); not proof of default-branch protection", len(names), strings.Join(names, ", "))
}
