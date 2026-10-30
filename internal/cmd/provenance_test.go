package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/GitHubSecurityLab/gh-secure/internal/provenance"
	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/ui"
)

func TestProvenanceCommandContract(t *testing.T) {
	tests := []struct {
		args     []string
		expected int
		called   bool
	}{
		{[]string{"provenance"}, 0, true},
		{[]string{"provenance", "--repo", "o/r"}, 0, true},
		{[]string{"provenance", "--help"}, 0, false},
		{[]string{"provenance", "assist", "--help"}, 0, false},
		{[]string{"provenance", "--run-limit", "0"}, 2, false},
		{[]string{"provenance", "--run-limit", "5"}, 2, false},
		{[]string{"--deep-provenance"}, 2, false},
		{[]string{"status", "--deep-provenance"}, 2, false},
		{[]string{"provenance", "--release-limit", "20"}, 2, false},
		{[]string{"provenance", "--repo", "../escape"}, 2, false},
		{[]string{"provenance", "anything"}, 2, false},
		{[]string{"provenance", "--yes"}, 2, false},
		{[]string{"provenance", "assist"}, 2, false},
		{[]string{"provenance", "assist", "--workflow", ".github/workflows/release.yml", "--job", "publish"}, 2, false},
		{[]string{"provenance", "assist", "--workflow", ".github/workflows/release.yml", "--job", "publish", "--consent"}, 0, true},
		{[]string{"provenance", "assist", "--workflow", ".github/workflows/release.yml", "--job", "publish", "--dry-run"}, 0, true},
		{[]string{"provenance", "assist", "--workflow", "../release.yml", "--job", "publish", "--consent"}, 2, false},
	}
	for _, tt := range tests {
		t.Run(joinArgs(tt.args), func(t *testing.T) {
			called := false
			code, _, errOut := execute(t, tt.args, Dependencies{
				Provenance: func(_ context.Context, options ProvenanceOptions) error {
					called = true
					return nil
				},
			})
			if code != tt.expected || called != tt.called {
				t.Fatalf("code %d called %v, want %d/%v: %s", code, called, tt.expected, tt.called, errOut)
			}
		})
	}
}

func joinArgs(args []string) string {
	out := ""
	for _, arg := range args {
		out += arg + " "
	}
	return out
}

func TestDefaultChecksShareResolvedTarget(t *testing.T) {
	for _, args := range [][]string{nil, {"status"}} {
		resolutions, checks := 0, 0
		target := repository.Target{Host: "example.ghe.com", Owner: "o", Name: "r"}
		check := func(ctx context.Context) error {
			got, ok := ctx.Value(targetContextKey{}).(repository.Target)
			if !ok || got != target {
				t.Fatalf("shared target missing: %+v", got)
			}
			checks++
			return nil
		}
		code, _, _ := execute(t, args, Dependencies{
			Resolve: func(context.Context, string) (repository.Target, error) {
				resolutions++
				return target, nil
			},
			Enable:        func(ctx context.Context, _ EnableOptions) error { return check(ctx) },
			Status:        func(ctx context.Context, _ StatusOptions) error { return check(ctx) },
			WorkflowCheck: func(ctx context.Context, _ StatusOptions) error { return check(ctx) },
		})
		if code != 0 || resolutions != 1 || checks != 2 {
			t.Fatalf("exit %d resolutions %d checks %d", code, resolutions, checks)
		}
	}
}

func TestProvenanceOperationalFailure(t *testing.T) {
	code, _, _ := execute(t, []string{"provenance"}, Dependencies{
		Provenance: func(context.Context, ProvenanceOptions) error { return errors.New("incomplete") },
	})
	if code != 1 {
		t.Fatalf("got exit %d", code)
	}
}

func TestNormalCommandsCheckWorkflowConfigurationWithoutRuntimeInspection(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want bool
	}{
		{nil, true},
		{[]string{"--dry-run"}, true},
		{[]string{"status"}, true},
		{[]string{"dependabot"}, false},
		{[]string{"--help"}, false},
	} {
		t.Run(joinArgs(tt.args), func(t *testing.T) {
			called := false
			code, _, _ := execute(t, tt.args, Dependencies{
				Enable: func(context.Context, EnableOptions) error { return nil },
				Status: func(context.Context, StatusOptions) error { return nil },
				WorkflowCheck: func(context.Context, StatusOptions) error {
					called = true
					return errors.New("configuration requires review")
				},
				Provenance: func(context.Context, ProvenanceOptions) error {
					t.Fatal("default commands must not enumerate runtime artifacts or invoke assistance")
					return nil
				},
			})
			if called != tt.want || tt.want && code != 1 || !tt.want && code != 0 {
				t.Fatalf("called %v exit %d", called, code)
			}
		})
	}
}

func TestAdoptedConfigurationSkipsAssistance(t *testing.T) {
	// No consent, selected workflow, or checkout is needed once adoption exists.
	// Reaching the assistance path would fail this test before any model call.
	var output bytes.Buffer
	err := handleWorkflowSources(t.Context(), ui.Streams{Out: &output}, ProvenanceOptions{Assist: true},
		"o/r", strings.Repeat("a", 40), nil,
		[]provenance.ConfigurationFinding{{State: "adopted"}})
	if err != nil || !strings.Contains(output.String(), "adopted") {
		t.Fatalf("output %s error %v", output.String(), err)
	}
}

func TestDryRunDoesNotInvokeAssistance(t *testing.T) {
	var output bytes.Buffer
	err := handleWorkflowSources(t.Context(), ui.Streams{Out: &output}, ProvenanceOptions{Assist: true, DryRun: true},
		"o/r", strings.Repeat("a", 40), nil,
		[]provenance.ConfigurationFinding{{State: "missing"}})
	if err == nil || !strings.Contains(err.Error(), "configuration") || !strings.Contains(output.String(), "Guidance:") {
		t.Fatalf("output %s error %v", output.String(), err)
	}
}
