package ui

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
)

// TestRenderStatus preserves unknown states, ruleset caveats, paused updates, and host links.
func TestRenderStatus(t *testing.T) {
	var out bytes.Buffer
	report := security.StatusReport{
		Repository: repository.Repository{
			Target:        repository.Target{Host: "github.example.com", Owner: "team", Name: "project"},
			DefaultBranch: "release/security", Private: true,
		},
		Checks: []security.Check{
			{ID: security.LegacyProtection, Label: "Legacy branch protection", Inspection: security.Inspection{State: security.Disabled}},
			{ID: security.PrivateReporting, Label: "Private vulnerability reporting", Inspection: security.Inspection{State: security.Unsupported, Detail: "public repositories only"}},
			{ID: security.PushProtection, Label: "Secret scanning push protection", Inspection: security.Inspection{State: security.Unknown, Detail: "permissions required"}},
			{ID: security.DependabotAlerts, Label: "Dependabot alerts", Inspection: security.Inspection{State: security.Enabled}},
			{ID: security.DependabotUpdates, Label: "Dependabot security updates", Inspection: security.Inspection{State: security.Enabled, Detail: "security updates are paused"}},
			{ID: security.CodeQLSetup, Label: "CodeQL default setup", Inspection: security.Inspection{State: security.Disabled}},
		},
		Rulesets: security.Rulesets{Known: true, Active: []string{"organization\npolicy"}},
	}
	if err := (Streams{Out: &out}).RenderStatus(report); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"Summary (6 checks): 2 enabled, 2 disabled, 1 unknown, 1 unsupported\n", "paused",
		`"organization\npolicy"`, "not proof of default-branch protection",
		"https://github.example.com/team/project/settings/security_analysis",
		"https://github.example.com/team/project/security",
	} {
		if !strings.Contains(out.String(), text) {
			t.Errorf("missing %q from %q", text, out.String())
		}
	}
	if strings.Contains(out.String(), "organization\npolicy") || strings.Contains(out.String(), "Private reporting:") {
		t.Errorf("unsafe ruleset name or unsupported reporting link: %q", out.String())
	}
}

type failedWriter struct{}

// Write simulates a closed output stream.
func (failedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// TestRenderStatusErrors surfaces invalid states and output failures.
func TestRenderStatusErrors(t *testing.T) {
	if err := (Streams{Out: failedWriter{}}).RenderStatus(security.StatusReport{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write failure lost: %v", err)
	}

	report := security.StatusReport{Checks: []security.Check{{Inspection: security.Inspection{State: "invalid"}}}}
	if err := (Streams{Out: io.Discard}).RenderStatus(report); err == nil {
		t.Fatal("invalid inspection state was rendered as a valid result")
	}
}

// TestRenderPartialStatus distinguishes uninspected checks from unknown results.
func TestRenderPartialStatus(t *testing.T) {
	var out bytes.Buffer
	report := security.StatusReport{
		Repository: repository.Repository{
			Target:        repository.Target{Host: "github.com", Owner: "owner", Name: "repo"},
			DefaultBranch: "main",
		},
		Checks: []security.Check{
			{ID: security.CodeQLSetup, Label: "CodeQL default setup", Inspection: security.Inspection{State: security.Enabled}},
		},
	}
	if err := (Streams{Out: &out}).RenderStatus(report); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"Partial summary: 1 enabled, 0 disabled, 0 unknown, 0 unsupported\n",
		"Inspection incomplete: 1/6 checks completed\n",
	} {
		if !strings.Contains(out.String(), text) {
			t.Errorf("missing %q from %q", text, out.String())
		}
	}
	if strings.Contains(out.String(), "Summary (6 checks)") {
		t.Error("partial inspection was presented as a complete summary")
	}
}
