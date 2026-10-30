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
		{
			args:     []string{"provenance"},
			expected: 0,
			called:   true,
		},
		{
			args:     []string{"provenance", "--repo", "o/r"},
			expected: 0,
			called:   true,
		},
		{
			args:     []string{"provenance", "--help"},
			expected: 0,
			called:   false,
		},
		{
			args:     []string{"provenance", "assist", "--help"},
			expected: 0,
			called:   false,
		},
		{
			args:     []string{"provenance", "--run-limit", "0"},
			expected: 2,
			called:   false,
		},
		{
			args:     []string{"provenance", "--run-limit", "5"},
			expected: 2,
			called:   false,
		},
		{
			args:     []string{"--deep-provenance"},
			expected: 2,
			called:   false,
		},
		{
			args:     []string{"status", "--deep-provenance"},
			expected: 2,
			called:   false,
		},
		{
			args:     []string{"provenance", "--release-limit", "20"},
			expected: 2,
			called:   false,
		},
		{
			args:     []string{"provenance", "--repo", "../escape"},
			expected: 2,
			called:   false,
		},
		{
			args:     []string{"provenance", "anything"},
			expected: 2,
			called:   false,
		},
		{
			args:     []string{"provenance", "--yes"},
			expected: 2,
			called:   false,
		},
		{
			args:     []string{"provenance", "assist"},
			expected: 2,
			called:   false,
		},
		{
			args: []string{
				"provenance", "assist",
				"--workflow", ".github/workflows/release.yml",
				"--job", "publish",
			},
			expected: 2,
			called:   false,
		},
		{
			args: []string{
				"provenance", "assist",
				"--workflow", ".github/workflows/release.yml",
				"--job", "publish",
				"--consent",
			},
			expected: 0,
			called:   true,
		},
		{
			args: []string{
				"provenance", "assist",
				"--workflow", ".github/workflows/release.yml",
				"--job", "publish",
				"--dry-run",
			},
			expected: 0,
			called:   true,
		},
		{
			args: []string{
				"provenance", "assist",
				"--workflow", "../release.yml",
				"--job", "publish",
				"--consent",
			},
			expected: 2,
			called:   false,
		},
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
	return strings.Join(args, " ")
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
	tests := []struct {
		args []string
		want bool
	}{
		{
			args: nil,
			want: true,
		},
		{
			args: []string{"--dry-run"},
			want: true,
		},
		{
			args: []string{"status"},
			want: true,
		},
		{
			args: []string{"dependabot"},
			want: false,
		},
		{
			args: []string{"--help"},
			want: false,
		},
	}

	for _, tt := range tests {
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
