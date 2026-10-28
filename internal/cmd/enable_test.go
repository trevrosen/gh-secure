package cmd

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/GitHubSecurityLab/gh-secure/internal/security"
)

const (
	modePrompt = "How should changes be confirmed?\n" +
		"  1) Confirm all features at once\n" +
		"  2) Confirm each feature step by step\n" +
		"Choose 1 or 2: "
	allFeaturesPrompt = "Enable 5 security feature(s) on github.example.com/owner/repo (branch-protection, vulnerability-reporting, secret-scanning, dependabot, code-scanning)? [y/N]: "
	retryPrompt       = "Please answer y or n [y/N]: "
	overlapPrompt     = "Active rulesets exist (1 (\"org policy\"); not proof of default-branch protection) and may already govern the default branch.\n" +
		"Add legacy branch protection anyway? Rulesets will not be changed. [y/N]: "
)

// TestEnableInteractiveSelections covers default/all/subset invocations, both
// modes, answer parsing, declines, --yes, non-TTY, and EOF with exact prompts,
// writes, outcomes, and exit codes.
func TestEnableInteractiveSelections(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		input     string
		canPrompt bool
		// enabled lists settings that start enabled; all others are disabled.
		enabled  []security.CheckID
		code     int
		prompts  string
		writes   []string
		outcomes map[string]string
		errOut   string
	}{
		{
			name: "default all-at-once", input: "1\ny\n", canPrompt: true,
			prompts: modePrompt + allFeaturesPrompt, writes: allWrites,
			outcomes: allOutcomes("applied"),
		},
		{
			name: "default step by step with re-prompts", input: "3\n2\ny\nn\nmaybe\nY\nyes\n\n", canPrompt: true,
			prompts: modePrompt + "Please choose 1 or 2: " +
				"Enable branch-protection? [y/N]: Enable vulnerability-reporting? [y/N]: " +
				"Enable secret-scanning? [y/N]: " + retryPrompt +
				"Enable dependabot? [y/N]: Enable code-scanning? [y/N]: ",
			writes: []string{writeProtection, writePush, writeAlerts, writeFixes},
			outcomes: map[string]string{
				"branch-protection": "applied", "vulnerability-reporting": "declined", "secret-scanning": "applied",
				"dependabot": "applied", "code-scanning": "declined",
			},
		},
		{
			name: "explicit all features use one confirmation", args: []string{"cs", "dep", "ss", "vr", "bp"}, input: "y\n", canPrompt: true,
			prompts: allFeaturesPrompt, writes: allWrites, outcomes: allOutcomes("applied"),
		},
		{
			name: "subset re-prompts then applies in canonical order", args: []string{"cs", "bp", "secret-scanning"}, input: "sure\nYES\n", canPrompt: true,
			prompts: "Enable 3 security feature(s) on github.example.com/owner/repo (branch-protection, secret-scanning, code-scanning)? [y/N]: " + retryPrompt,
			writes:  []string{writeProtection, writePush, writeCodeQL},
			outcomes: uniformOutcomes("applied",
				security.BranchProtection, security.SecretScanning, security.CodeScanning),
		},
		{
			name: "duplicates and already-enabled features are not counted", args: []string{"dep", "vr", "dependabot", "vulnerability-reporting"},
			enabled: []security.CheckID{security.PrivateReporting, security.DependabotAlerts}, input: "y\n", canPrompt: true,
			prompts: "Enable 1 security feature(s) on github.example.com/owner/repo (dependabot)? [y/N]: ",
			writes:  []string{writeFixes},
			outcomes: map[string]string{
				"vulnerability-reporting": "already enabled", "dependabot": "applied",
			},
		},
		{
			name: "default mode skipped when only one feature needs changes", input: "y\n", canPrompt: true,
			enabled: []security.CheckID{
				security.LegacyProtection, security.PrivateReporting, security.PushProtection,
				security.DependabotAlerts, security.DependabotUpdates,
			},
			prompts: "Enable 1 security feature(s) on github.example.com/owner/repo (code-scanning)? [y/N]: ",
			writes:  []string{writeCodeQL},
			outcomes: map[string]string{
				"branch-protection": "already enabled", "vulnerability-reporting": "already enabled",
				"secret-scanning": "already enabled", "dependabot": "already enabled", "code-scanning": "applied",
			},
		},
		{
			name: "initial decline aborts without writes", input: "1\nn\n", canPrompt: true,
			prompts: modePrompt + allFeaturesPrompt, writes: []string{}, outcomes: allOutcomes("declined"),
		},
		{
			name: "empty subset answer declines", args: []string{"bp"}, input: "\n", canPrompt: true,
			prompts:  "Enable 1 security feature(s) on github.example.com/owner/repo (branch-protection)? [y/N]: ",
			writes:   []string{},
			outcomes: uniformOutcomes("declined", security.BranchProtection),
		},
		{
			name: "yes without terminal applies without prompts", args: []string{"--yes"}, input: "n\n",
			writes: allWrites, outcomes: allOutcomes("applied"),
		},
		{
			name: "no terminal without yes fails before writes", input: "y\n", code: 1, writes: []string{},
			errOut: "Error: confirmation incomplete; no changes were made: terminal input is unavailable for confirmation; rerun with --yes to approve ordinary confirmations\n",
		},
		{
			name: "EOF at mode prompt fails before writes", input: "", canPrompt: true, code: 1,
			prompts: modePrompt, writes: []string{},
			errOut: "Error: confirmation incomplete; no changes were made: read confirmation mode: input ended before an answer: EOF\n",
		},
		{
			name: "EOF at a step-by-step prompt fails before writes", input: "2\ny\ny", canPrompt: true, code: 1,
			prompts: modePrompt + "Enable branch-protection? [y/N]: Enable vulnerability-reporting? [y/N]: ",
			writes:  []string{},
			errOut:  "Error: confirmation incomplete; no changes were made: read confirmation: input ended before an answer: EOF\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEnableFixture("disabled")
			for _, id := range test.enabled {
				fixture.states[id] = "enabled"
			}
			run := fixture.run(t, t.Context(), append([]string{"--repo", "owner/repo"}, test.args...), strings.NewReader(test.input), test.canPrompt)
			if run.code != test.code || !slices.Equal(fixture.writes(), test.writes) {
				t.Fatalf("code=%d writes=%q\nstdout=%s\nstderr=%s", run.code, fixture.writes(), run.out, run.errOut)
			}
			if run.errOut != test.prompts+test.errOut {
				t.Errorf("stderr=%q\nwant   %q", run.errOut, test.prompts+test.errOut)
			}
			if test.canPrompt && run.unread != "" {
				t.Errorf("prompts left input unread: %q", run.unread)
			}
			if !test.canPrompt && run.unread != test.input {
				t.Errorf("non-terminal input was consumed: unread=%q", run.unread)
			}
			if test.outcomes == nil {
				if strings.Contains(run.out, "summary for") {
					t.Errorf("aborted run rendered a summary: %s", run.out)
				}
				return
			}
			if got := summaryOutcomes(t, run.out); !maps.Equal(got, test.outcomes) {
				t.Errorf("outcomes=%v; want %v", got, test.outcomes)
			}
		})
	}
}

// TestEnableRulesetSafeguard checks that --yes never approves an active-ruleset
// overlap and that an unanswerable safeguard skips only branch protection.
func TestEnableRulesetSafeguard(t *testing.T) {
	others := []string{writePVR, writePush, writeAlerts, writeFixes, writeCodeQL}
	blocked := "Error: security enablement incomplete: branch-protection: active-ruleset overlap was not approved: "
	tests := []struct {
		name      string
		args      []string
		input     string
		canPrompt bool
		code      int
		prompts   string
		writes    []string
		bp        string
		others    string
		errOut    string
	}{
		{name: "yes still asks; approval writes", args: []string{"--yes"}, input: "y\n", canPrompt: true,
			prompts: overlapPrompt, writes: allWrites, bp: "applied", others: "applied"},
		{name: "explicit no is a decline", args: []string{"--yes"}, input: "n\n", canPrompt: true,
			prompts: overlapPrompt, writes: others, bp: "declined", others: "applied"},
		{name: "non-terminal skips branch protection", args: []string{"--yes"}, input: "y\n", code: 1,
			writes: others, bp: "failed", others: "applied",
			errOut: blocked + "terminal input is unavailable for the active-ruleset safeguard, which --yes cannot approve\n"},
		{name: "EOF skips branch protection", args: []string{"--yes"}, input: "", canPrompt: true, code: 1,
			prompts: overlapPrompt, writes: others, bp: "failed", others: "applied",
			errOut: blocked + "read confirmation: input ended before an answer: EOF\n"},
		{name: "asked after ordinary confirmations", input: "1\ny\ny\n", canPrompt: true,
			prompts: modePrompt + allFeaturesPrompt + overlapPrompt, writes: allWrites, bp: "applied", others: "applied"},
		{name: "dry run enforces the safeguard", args: []string{"--yes", "--dry-run"}, input: "y\n", code: 1,
			writes: []string{}, bp: "failed", others: "planned",
			errOut: blocked + "terminal input is unavailable for the active-ruleset safeguard, which --yes cannot approve\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEnableFixture("disabled")
			fixture.rulesets = []string{"org policy"}
			fixture.rejectWrites = slices.Contains(test.args, "--dry-run")
			run := fixture.run(t, t.Context(), test.args, strings.NewReader(test.input), test.canPrompt)
			if run.code != test.code || !slices.Equal(fixture.writes(), test.writes) {
				t.Fatalf("code=%d writes=%q\nstdout=%s\nstderr=%s", run.code, fixture.writes(), run.out, run.errOut)
			}
			if run.errOut != test.prompts+test.errOut {
				t.Errorf("stderr=%q\nwant   %q", run.errOut, test.prompts+test.errOut)
			}
			want := allOutcomes(test.others)
			want[string(security.BranchProtection)] = test.bp
			if got := summaryOutcomes(t, run.out); !maps.Equal(got, want) {
				t.Errorf("outcomes=%v; want %v", got, want)
			}
		})
	}
}

// TestEnableUnknownRulesetsBlockProtection checks failed ruleset inspection blocks
// the protection write without a safeguard prompt, while other features proceed.
func TestEnableUnknownRulesetsBlockProtection(t *testing.T) {
	fixture := newEnableFixture("disabled")
	fixture.rulesetsFail = true
	run := fixture.run(t, t.Context(), []string{"--yes"}, strings.NewReader(""), true)
	if run.code != 1 || !slices.Equal(fixture.writes(), allWrites[1:]) {
		t.Fatalf("code=%d writes=%q stderr=%s", run.code, fixture.writes(), run.errOut)
	}
	want := allOutcomes("applied")
	want[string(security.BranchProtection)] = "failed"
	if got := summaryOutcomes(t, run.out); !maps.Equal(got, want) {
		t.Errorf("outcomes=%v; want %v", got, want)
	}
	if !strings.HasPrefix(run.errOut, "Error: security enablement incomplete: branch-protection: active rulesets are unknown: GET repos/owner/repo/rulesets?") {
		t.Errorf("stderr=%q", run.errOut)
	}
}

// TestEnablePermissionPreflight checks fatal permission denial after exactly one
// metadata request, and that maintain permission is sufficient.
func TestEnablePermissionPreflight(t *testing.T) {
	denied := "Error: enabling security features on github.example.com/owner/repo requires admin or maintain permission, which GitHub did not report for this account\n"
	tests := []struct {
		name        string
		permissions string
		code        int
		requests    int
		errOut      string
	}{
		{"denied", `{"admin":false,"maintain":false,"push":true}`, 1, 1, denied},
		{"undisclosed", "", 1, 1, denied},
		{"maintain", `{"admin":false,"maintain":true}`, 0, 12, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEnableFixture("disabled")
			fixture.permissions = test.permissions
			run := fixture.run(t, t.Context(), []string{"--yes"}, strings.NewReader(""), false)
			if run.code != test.code || len(fixture.requests) != test.requests || run.errOut != test.errOut {
				t.Fatalf("code=%d requests=%q stderr=%q", run.code, fixture.requests, run.errOut)
			}
			if test.code != 0 && run.out != "" {
				t.Errorf("denied run rendered output: %s", run.out)
			}
		})
	}
}

// TestEnablePrivateRepository checks the private warning and that unsupported
// private reporting fails without a request while other features apply.
func TestEnablePrivateRepository(t *testing.T) {
	fixture := newEnableFixture("disabled")
	fixture.private = true
	run := fixture.run(t, t.Context(), []string{"--yes"}, strings.NewReader(""), false)
	wantWrites := []string{writeProtection, writePush, writeAlerts, writeFixes, writeCodeQL}
	if run.code != 1 || !slices.Equal(fixture.writes(), wantWrites) || slices.Contains(fixture.requests, "GET "+pvrPath) {
		t.Fatalf("code=%d requests=%q", run.code, fixture.requests)
	}
	warning := "Warning: github.example.com/owner/repo is private. Private vulnerability reporting is unavailable for private repositories, " +
		"and other features may require additional licensing or entitlements.\n"
	failure := "Error: security enablement incomplete: vulnerability-reporting: cannot enable setting with unsupported inspection: " +
		"private vulnerability reporting is available only for public repositories\n"
	if run.errOut != warning+failure {
		t.Errorf("stderr=%q", run.errOut)
	}
	want := allOutcomes("applied")
	want[string(security.VulnerabilityReporting)] = "failed"
	if got := summaryOutcomes(t, run.out); !maps.Equal(got, want) {
		t.Errorf("outcomes=%v; want %v", got, want)
	}
	if strings.Contains(run.out, "/security/advisories/new") {
		t.Errorf("private reporting link offered for an unsupported setting: %s", run.out)
	}
}

// TestEnableOutcomesAndFollowUp checks distinct outcomes, partial Dependabot
// results, continuation after failures, links, and advisory policy handling.
func TestEnableOutcomesAndFollowUp(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*enableFixture)
		args     []string
		code     int
		writes   []string
		outcomes map[string]string
		lines    []string
		absent   []string
	}{
		{
			name: "all already enabled needs no prompt or write", setup: func(f *enableFixture) {
				for id := range f.states {
					f.states[id] = "enabled"
				}
				f.policy = `{"files":{"security":{"url":"https://github.example.com/owner/repo/blob/main/SECURITY.md"}}}`
			},
			writes: []string{}, outcomes: allOutcomes("already enabled"),
			lines: []string{
				"Totals: 0 applied, 5 already enabled, 0 planned, 0 declined, 0 partial, 0 failed, 0 not attempted",
				"Private reporting: https://github.example.com/owner/repo/security/advisories/new",
				"Security policy: https://github.example.com/owner/repo/blob/main/SECURITY.md",
			},
		},
		{
			name: "unknown alerts make Dependabot partial", args: []string{"--yes", "dep"},
			setup: func(f *enableFixture) { f.states[security.DependabotAlerts] = "unknown" },
			code:  1, writes: []string{writeFixes}, outcomes: map[string]string{"dependabot": "partial"},
			lines: []string{
				"    Dependabot alerts                    failed: cannot enable setting with unknown inspection: GET repos/owner/repo/vulnerability-alerts: HTTP 404; not found or inaccessible; this does not establish that the setting is disabled",
				"    Dependabot security updates          applied",
			},
		},
		{
			name: "failed write continues with later features", args: []string{"--yes"},
			setup: func(f *enableFixture) {
				f.failWrites[writeAlerts] = true
				f.failWrites[writePVR] = true
				f.runURL = "https://github.example.com/owner/repo/actions/runs/42"
			},
			code: 1, writes: allWrites,
			outcomes: map[string]string{
				"branch-protection": "applied", "vulnerability-reporting": "failed", "secret-scanning": "applied",
				"dependabot": "partial", "code-scanning": "applied",
			},
			lines: []string{
				"Totals: 3 applied, 0 already enabled, 0 planned, 0 declined, 1 partial, 1 failed, 0 not attempted",
				"    CodeQL default setup                 applied; configuration accepted, analysis may still be running: https://github.example.com/owner/repo/actions/runs/42",
				"Security settings: https://github.example.com/owner/repo/settings/security_analysis",
				"Security overview: https://github.example.com/owner/repo/security",
			},
			absent: []string{"/security/advisories/new"},
		},
		{
			name: "policy lookup failure is advisory", args: []string{"--yes", "vr"},
			setup:  func(f *enableFixture) { f.policy = "" },
			writes: []string{writePVR}, outcomes: map[string]string{"vulnerability-reporting": "applied"},
			lines: []string{
				"Private reporting: https://github.example.com/owner/repo/security/advisories/new",
				"Security policy advisory: GET repos/owner/repo/community/profile: HTTP 500; check repository access, feature availability, and host support",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEnableFixture("disabled")
			test.setup(fixture)
			run := fixture.run(t, t.Context(), test.args, strings.NewReader(""), true)
			if run.code != test.code || !slices.Equal(fixture.writes(), test.writes) {
				t.Fatalf("code=%d writes=%q\nstdout=%s\nstderr=%s", run.code, fixture.writes(), run.out, run.errOut)
			}
			if (run.code == 0) != (run.errOut == "") {
				t.Errorf("stderr=%q", run.errOut)
			}
			if got := summaryOutcomes(t, run.out); !maps.Equal(got, test.outcomes) {
				t.Errorf("outcomes=%v; want %v", got, test.outcomes)
			}
			assertLines(t, run.out, test.lines)
			for _, text := range test.absent {
				if strings.Contains(run.out, text) {
					t.Errorf("unexpected %q in:\n%s", text, run.out)
				}
			}
		})
	}
}

// TestEnableDryRun checks every group is planned, confirmation still applies,
// already-enabled settings are retained, and the transport never sees a write.
func TestEnableDryRun(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		input     string
		canPrompt bool
		setup     func(*enableFixture)
		code      int
		outcomes  map[string]string
		lines     []string
	}{
		{name: "all five groups with yes", args: []string{"--dry-run", "--yes"}, outcomes: allOutcomes("planned"),
			lines: []string{
				"Dry run: settings are inspected, but no changes will be made.",
				"Dry-run summary for github.example.com/owner/repo (no changes were made)",
				"    Dependabot alerts                    planned (would enable)",
				"Totals: 0 applied, 0 already enabled, 5 planned, 0 declined, 0 partial, 0 failed, 0 not attempted",
			}},
		{name: "confirmation approved", args: []string{"-n"}, input: "1\ny\n", canPrompt: true, outcomes: allOutcomes("planned")},
		{name: "confirmation declined", args: []string{"-n"}, input: "1\nn\n", canPrompt: true, outcomes: allOutcomes("declined")},
		{name: "confirmation unavailable", args: []string{"-n"}, input: "y\n", code: 1},
		{name: "only missing Dependabot setting is planned", args: []string{"-n", "-y", "dep"},
			setup:    func(f *enableFixture) { f.states[security.DependabotAlerts] = "enabled" },
			outcomes: map[string]string{"dependabot": "planned"},
			lines: []string{
				"    Dependabot alerts                    already enabled",
				"    Dependabot security updates          planned (would enable)",
			}},
		{name: "unknown setting still fails", args: []string{"-n", "-y", "cs"}, code: 1,
			setup:    func(f *enableFixture) { f.states[security.CodeQLSetup] = "unknown" },
			outcomes: map[string]string{"code-scanning": "failed"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEnableFixture("disabled")
			fixture.rejectWrites = true
			if test.setup != nil {
				test.setup(fixture)
			}
			run := fixture.run(t, t.Context(), test.args, strings.NewReader(test.input), test.canPrompt)
			if run.code != test.code || len(fixture.writes()) != 0 {
				t.Fatalf("code=%d writes=%q\nstdout=%s\nstderr=%s", run.code, fixture.writes(), run.out, run.errOut)
			}
			if test.outcomes == nil {
				return
			}
			if !strings.Contains(run.out, "Dry-run summary for github.example.com/owner/repo (no changes were made)\n") {
				t.Errorf("dry run used the enablement summary:\n%s", run.out)
			}
			if got := summaryOutcomes(t, run.out); !maps.Equal(got, test.outcomes) {
				t.Errorf("outcomes=%v; want %v", got, test.outcomes)
			}
			assertLines(t, run.out, test.lines)
		})
	}
}

// TestEnableCancellation checks cancellation before and during apply: no
// writes before apply, accepted writes retained, later features not attempted.
func TestEnableCancellation(t *testing.T) {
	t.Run("during apply", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		fixture := newEnableFixture("disabled")
		fixture.afterRequest = func(request string) {
			if request == writePVR {
				cancel()
			}
		}
		run := fixture.run(t, ctx, []string{"--yes"}, strings.NewReader(""), false)
		if run.code != 1 || !slices.Equal(fixture.writes(), []string{writeProtection, writePVR}) ||
			slices.Contains(fixture.requests, "GET "+profilePath) {
			t.Fatalf("code=%d requests=%q stderr=%q", run.code, fixture.requests, run.errOut)
		}
		want := map[string]string{
			"branch-protection": "applied", "vulnerability-reporting": "applied",
			"secret-scanning": "not attempted", "dependabot": "not attempted", "code-scanning": "not attempted",
		}
		if got := summaryOutcomes(t, run.out); !maps.Equal(got, want) {
			t.Errorf("outcomes=%v; want %v", got, want)
		}
		if run.errOut != "Error: security enablement incomplete: interrupted with 3 feature(s) not attempted: context canceled\n" {
			t.Errorf("stderr=%q", run.errOut)
		}
	})
	t.Run("during inspection", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		fixture := newEnableFixture("disabled")
		fixture.afterRequest = func(request string) {
			if request == "GET "+rulesetsPath {
				cancel()
			}
		}
		run := fixture.run(t, ctx, []string{"--yes"}, strings.NewReader(""), false)
		if run.code != 1 || len(fixture.writes()) != 0 || len(fixture.requests) != 2 || run.errOut != "Error: context canceled\n" {
			t.Fatalf("code=%d requests=%q stderr=%q", run.code, fixture.requests, run.errOut)
		}
	})
	t.Run("during confirmation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		fixture := newEnableFixture("disabled")
		run := fixture.run(t, ctx, nil, cancelingInput{cancel: cancel}, true)
		if run.code != 1 || len(fixture.writes()) != 0 || !strings.HasSuffix(run.errOut, "context canceled\n") {
			t.Fatalf("code=%d writes=%q stderr=%q", run.code, fixture.writes(), run.errOut)
		}
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("prompt never read input")
		}
	})
}
