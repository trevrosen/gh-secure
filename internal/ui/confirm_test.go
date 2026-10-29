package ui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
)

// TestConfirmAnswers checks accepted answers, empty-as-no, re-prompts, and EOF.
func TestConfirmAnswers(t *testing.T) {
	tests := []struct {
		input   string
		want    bool
		prompts int
		eof     bool
	}{
		{"y\n", true, 1, false},
		{"YES\r\n", true, 1, false},
		{" n \n", false, 1, false},
		{"No\n", false, 1, false},
		{"\n", false, 1, false},
		{"maybe\nyep\ny\n", true, 3, false},
		{"", false, 1, true},
		{"y", false, 1, true},
		{"maybe\n", false, 2, true},
	}
	for _, test := range tests {
		var errOut bytes.Buffer
		approver := NewApprover(Streams{In: strings.NewReader(test.input), ErrOut: &errOut, CanPrompt: true})
		got, err := approver.ConfirmFeature(t.Context(), security.CodeScanning)
		want := "Enable code-scanning? [y/N]: " + strings.Repeat("Please answer y or n [y/N]: ", test.prompts-1)
		if got != test.want || errors.Is(err, io.EOF) != test.eof || (err != nil) != test.eof || errOut.String() != want {
			t.Errorf("input=%q: got=%v err=%v prompts=%q", test.input, got, err, errOut.String())
		}
	}
}

// TestChooseMode checks both modes, invalid-choice re-prompts, and EOF.
func TestChooseMode(t *testing.T) {
	tests := []struct {
		input string
		want  security.ApprovalMode
		eof   bool
	}{
		{"1\n", security.ApproveAll, false},
		{" 2 \n", security.ApproveEach, false},
		{"all\n0\n2\n", security.ApproveEach, false},
		{"3\n", 0, true},
	}
	for _, test := range tests {
		approver := NewApprover(Streams{In: strings.NewReader(test.input), ErrOut: io.Discard, CanPrompt: true})
		got, err := approver.ChooseMode(t.Context())
		if got != test.want || errors.Is(err, io.EOF) != test.eof || (err != nil) != test.eof {
			t.Errorf("input=%q: got=%v err=%v", test.input, got, err)
		}
	}
}

// TestPromptsShareInputWithoutOverReading checks consecutive prompts each see
// their own answer line from one input stream.
func TestPromptsShareInputWithoutOverReading(t *testing.T) {
	streams := Streams{In: strings.NewReader("2\nowner/repo\nn\n"), ErrOut: io.Discard, CanPrompt: true}
	approver := NewApprover(streams)
	mode, modeErr := approver.ChooseMode(t.Context())
	repo, repoErr := streams.PromptRepository(t.Context())
	approved, confirmErr := approver.ConfirmFeature(t.Context(), security.Dependabot)
	if mode != security.ApproveEach || repo != "owner/repo" || approved || errors.Join(modeErr, repoErr, confirmErr) != nil {
		t.Fatalf("mode=%v repo=%q approved=%v errors=%v %v %v", mode, repo, approved, modeErr, repoErr, confirmErr)
	}
}

// TestConfirmWithoutTerminal checks distinct non-TTY errors that leave input
// unread and print no prompt, and that cancellation takes precedence.
func TestConfirmWithoutTerminal(t *testing.T) {
	input := strings.NewReader("y\n")
	var errOut bytes.Buffer
	approver := NewApprover(Streams{In: input, ErrOut: &errOut})
	_, modeErr := approver.ChooseMode(t.Context())
	_, featuresErr := approver.ConfirmFeatures(t.Context(), repository.Repository{}, []security.Feature{security.Dependabot})
	_, overlapErr := approver.ConfirmRulesetOverlap(t.Context(), security.Rulesets{Known: true, Active: []string{"policy"}})
	if !errors.Is(modeErr, errConfirmationUnavailable) || !errors.Is(featuresErr, errConfirmationUnavailable) ||
		!errors.Is(overlapErr, errOverlapUnavailable) || input.Len() != len("y\n") || errOut.Len() != 0 {
		t.Fatalf("errors=%v / %v / %v unread=%d prompts=%q", modeErr, featuresErr, overlapErr, input.Len(), errOut.String())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := approver.ConfirmFeature(ctx, security.Dependabot); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if _, err := approver.ChooseMode(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

// TestRenderPlan checks explanations, per-setting actions, ruleset notes, and
// the dry-run banner.
func TestRenderPlan(t *testing.T) {
	report := security.StatusReport{
		Repository: repository.Repository{
			Target: repository.Target{Host: "github.com", Owner: "owner", Name: "repo"}, DefaultBranch: "main",
		},
		Checks: []security.Check{
			{ID: security.LegacyProtection, Inspection: security.Inspection{State: security.Disabled}},
			{ID: security.DependabotAlerts, Inspection: security.Inspection{State: security.Unknown, Detail: "HTTP 404"}},
			{ID: security.DependabotUpdates, Inspection: security.Inspection{State: security.Enabled}},
		},
		Rulesets: security.Rulesets{Known: true, Active: []string{"policy"}},
	}
	plans, err := security.PlanFeatures(report, []security.Feature{security.BranchProtection, security.Dependabot})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := (Streams{Out: &out}).RenderPlan(plans, true); err != nil {
		t.Fatal(err)
	}
	want := "Dry run: settings are inspected, but no changes will be made.\n" +
		"Security enablement plan for github.com/owner/repo (default branch \"main\")\n" +
		"\nbranch-protection\n" +
		"  Blocks force pushes and deletions and requires a reviewed pull request before changes reach the default branch.\n" +
		"  Docs: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches\n" +
		"  Legacy branch protection             disabled     will enable if approved\n" +
		"  Active rulesets: 1 (\"policy\"); not proof of default-branch protection\n" +
		"  Adding legacy protection requires separate approval, even with --yes.\n" +
		"\ndependabot\n" +
		"  Alerts on dependencies with known vulnerabilities and opens pull requests that update them. Version updates are not configured.\n" +
		"  Docs: https://docs.github.com/en/code-security/getting-started/dependabot-quickstart-guide\n" +
		"  Dependabot alerts                    unknown      cannot enable: cannot enable setting with unknown inspection: HTTP 404\n" +
		"  Dependabot security updates          enabled      no change needed\n\n"
	if out.String() != want {
		t.Errorf("plan:\n%s\nwant:\n%s", out.String(), want)
	}
}
