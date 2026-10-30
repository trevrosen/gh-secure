package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

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
		{[]string{"provenance", "--repo", "o/r", "--run-limit", "5"}, 0, true},
		{[]string{"provenance", "--help"}, 0, false},
		{[]string{"provenance", "assist", "--help"}, 0, false},
		{[]string{"provenance", "--run-limit", "0"}, 2, false},
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
					if options.RunLimit < 1 {
						t.Fatalf("unvalidated options %+v", options)
					}
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

func TestDeeperInspectionRequiresFlagAndSeparateConsent(t *testing.T) {
	for _, tt := range []struct {
		name, input                    string
		flag, terminal, dryRun, called bool
	}{
		{"ordinary", "y\n", false, true, false, false},
		{"approved", "y\n", true, true, false, true},
		{"declined", "n\n", true, true, false, false},
		{"default no", "\n", true, true, false, false},
		{"EOF", "", true, true, false, false},
		{"nonterminal", "y\n", true, false, false, false},
		{"dry-run", "y\n", true, true, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			streams := ui.Streams{In: strings.NewReader(tt.input), Out: &output, ErrOut: &output, CanPrompt: tt.terminal}
			called := false
			err := finishWorkflowCheck(t.Context(), streams, StatusOptions{
				Repository: "o/r", OfferDeepProvenance: tt.flag, DryRun: tt.dryRun,
			}, func(_ context.Context, options ProvenanceOptions) error {
				called = true
				if options.Assist || options.Consent || options.RunLimit != 20 || options.Repository != "o/r" {
					t.Fatalf("unsafe deeper options: %+v", options)
				}
				return nil
			})
			if called != tt.called || err == nil {
				t.Fatalf("called %v error %v", called, err)
			}
			if (!tt.flag || tt.dryRun) && output.Len() != 0 {
				t.Fatalf("unexpected prompt: %s", output.String())
			}
		})
	}
}

func TestDeepProvenanceFlagRouting(t *testing.T) {
	for _, args := range [][]string{{"--deep-provenance", "--yes"}, {"status", "--deep-provenance"}} {
		called := false
		code, _, _ := execute(t, args, Dependencies{
			Enable: func(context.Context, EnableOptions) error { return nil },
			Status: func(context.Context, StatusOptions) error { return nil },
			WorkflowCheck: func(_ context.Context, options StatusOptions) error {
				called = true
				if !options.OfferDeepProvenance {
					t.Fatal("flag not propagated")
				}
				return nil
			},
		})
		if !called || code != 0 {
			t.Fatalf("called %v exit %d", called, code)
		}
	}
}
