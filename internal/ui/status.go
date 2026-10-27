package ui

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/GitHubSecurityLab/gh-secure/internal/security"
)

// RenderStatus writes six-check results and independent active-ruleset information.
// Unknown and unsupported checks are never counted as enabled.
func (s Streams) RenderStatus(report security.StatusReport) error {
	var text strings.Builder
	fmt.Fprintf(&text, "Security status for %s\nDefault branch: %q\n", report.Repository.Target, report.Repository.DefaultBranch)
	visibility := "public"
	if report.Repository.Private {
		visibility = "private"
	}
	fmt.Fprintf(&text, "Visibility: %s\n\n", visibility)
	for _, check := range report.Checks {
		switch check.Inspection.State {
		case security.Enabled, security.Disabled, security.Unknown, security.Unsupported:
		default:
			return fmt.Errorf("invalid inspection state for %s", check.ID)
		}
		fmt.Fprintf(&text, "  %-36s %s\n", check.Label, check.Inspection.State)
		if check.Inspection.Detail != "" {
			fmt.Fprintf(&text, "    %s\n", check.Inspection.Detail)
		}
		if check.ID == security.LegacyProtection {
			if !report.Rulesets.Known {
				fmt.Fprintf(&text, "    Active rulesets: unknown; %s\n", report.Rulesets.Detail)
			} else {
				names := make([]string, len(report.Rulesets.Active))
				for index, name := range report.Rulesets.Active {
					names[index] = strconv.Quote(name)
				}
				fmt.Fprintf(&text, "    Active rulesets: %d", len(names))
				if len(names) > 0 {
					fmt.Fprintf(&text, " (%s)", strings.Join(names, ", "))
				}
				text.WriteString("; not proof of default-branch protection\n")
			}
		}
	}
	summaryLabel := "Summary (6 checks)"
	if len(report.Checks) != 6 {
		summaryLabel = "Partial summary"
	}
	fmt.Fprintf(&text, "\n%s: %d enabled, %d disabled, %d unknown, %d unsupported\n",
		summaryLabel, report.Count(security.Enabled), report.Count(security.Disabled),
		report.Count(security.Unknown), report.Count(security.Unsupported))
	if len(report.Checks) != 6 {
		fmt.Fprintf(&text, "Inspection incomplete: %d/6 checks completed\n", len(report.Checks))
	}
	baseURL := report.Repository.Target.WebURL()
	fmt.Fprintf(&text, "\nSecurity settings: %s/settings/security_analysis\nSecurity overview: %s/security\n", baseURL, baseURL)
	for _, check := range report.Checks {
		if check.ID == security.PrivateReporting && check.Inspection.State == security.Enabled {
			fmt.Fprintf(&text, "Private reporting: %s/security/advisories/new\n", baseURL)
		}
	}
	written, err := io.WriteString(s.Out, text.String())
	if err == nil && written != text.Len() {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("write security status: %w", err)
	}
	return nil
}
