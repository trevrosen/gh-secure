package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/GitHubSecurityLab/gh-secure/internal/security"
	"github.com/GitHubSecurityLab/gh-secure/internal/ui"
)

type unexpectedInput struct{}

// Read panics to detect unexpected input consumption during command parsing.
func (unexpectedInput) Read([]byte) (int, error) {
	panic("command parsing must not read input")
}

func execute(t *testing.T, args []string, deps Dependencies) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Execute(context.Background(), args, "dev", ui.Streams{
		In: unexpectedInput{}, Out: &out, ErrOut: &errOut,
	}, deps)
	return code, out.String(), errOut.String()
}

// TestEnableParsing checks feature selection and enablement flag combinations.
func TestEnableParsing(t *testing.T) {
	all := []security.Feature{
		security.BranchProtection, security.VulnerabilityReporting, security.SecretScanning,
		security.Dependabot, security.CodeScanning,
	}
	tests := []struct {
		name string
		args []string
		want EnableOptions
	}{
		{"default", nil, EnableOptions{Features: all}},
		{"long flags", []string{"--repo", "owner/repo", "--yes", "--dry-run"}, EnableOptions{Repository: "owner/repo", Features: all, Yes: true, DryRun: true}},
		{"short flags", []string{"-r", "owner/repo", "-yn"}, EnableOptions{Repository: "owner/repo", Features: all, Yes: true, DryRun: true}},
		{"equals", []string{"--repo=owner/repo", "--yes=true", "--dry-run=true"}, EnableOptions{Repository: "owner/repo", Features: all, Yes: true, DryRun: true}},
		{"false flags", []string{"--yes=false", "--dry-run=false"}, EnableOptions{Features: all}},
		{"interspersed", []string{"cs", "-y", "bp", "--repo", "owner/repo", "dep", "-n"}, EnableOptions{Repository: "owner/repo", Features: []security.Feature{security.BranchProtection, security.Dependabot, security.CodeScanning}, ExplicitSelection: true, Yes: true, DryRun: true}},
		{"duplicates", []string{"bp", "branch-protection", "bp", "cs", "code-scanning"}, EnableOptions{Features: []security.Feature{security.BranchProtection, security.CodeScanning}, ExplicitSelection: true}},
		{"explicit all", []string{"cs", "dep", "ss", "vr", "bp"}, EnableOptions{Features: all, ExplicitSelection: true}},
		{"separator", []string{"-y", "--", "dep"}, EnableOptions{Features: []security.Feature{security.Dependabot}, ExplicitSelection: true, Yes: true}},
		{"repo punctuation", []string{"-r", "Owner-1/repo_name.v2"}, EnableOptions{Repository: "Owner-1/repo_name.v2", Features: all}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			deps := Dependencies{
				Enable: func(ctx context.Context, got EnableOptions) error {
					calls++
					if ctx == nil || !reflect.DeepEqual(got, test.want) {
						t.Errorf("got %#v, want %#v (context %v)", got, test.want, ctx)
					}
					return nil
				},
				Status: func(context.Context, StatusOptions) error {
					t.Fatal("unexpected status execution")
					return nil
				},
			}
			code, out, errOut := execute(t, test.args, deps)
			if code != 0 || calls != 1 || out != "" || errOut != "" {
				t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, out, errOut)
			}
		})
	}
}

// TestEveryFeatureSpellingThroughCommand checks command dispatch for names and aliases.
func TestEveryFeatureSpellingThroughCommand(t *testing.T) {
	for _, feature := range security.Features() {
		for _, name := range []string{string(feature.Name), feature.Alias} {
			t.Run(name, func(t *testing.T) {
				calls := 0
				code, _, errOut := execute(t, []string{name}, Dependencies{
					Enable: func(_ context.Context, options EnableOptions) error {
						calls++
						if !reflect.DeepEqual(options.Features, []security.Feature{feature.Name}) || !options.ExplicitSelection {
							t.Fatalf("unexpected options: %#v", options)
						}
						return nil
					},
				})
				if code != 0 || calls != 1 {
					t.Fatalf("code=%d calls=%d stderr=%q", code, calls, errOut)
				}
			})
		}
	}
}

// TestStatusParsing checks repository flags before and after the status subcommand.
func TestStatusParsing(t *testing.T) {
	for _, args := range [][]string{
		{"status"}, {"status", "--repo", "owner/repo"},
		{"-r", "owner/repo", "status"}, {"status", "--repo=owner/repo"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			calls := 0
			code, out, errOut := execute(t, args, Dependencies{
				Enable: func(context.Context, EnableOptions) error {
					t.Fatal("unexpected enablement execution")
					return nil
				},
				Status: func(_ context.Context, options StatusOptions) error {
					calls++
					wantRepo := "owner/repo"
					if len(args) == 1 {
						wantRepo = ""
					}
					if options.Repository != wantRepo {
						t.Errorf("repo=%q; want %q", options.Repository, wantRepo)
					}
					return nil
				},
			})
			if code != 0 || calls != 1 || out != "" || errOut != "" {
				t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, out, errOut)
			}
		})
	}
}

// TestInvalidInvocationNeverExecutes checks validation exits without invoking handlers.
func TestInvalidInvocationNeverExecutes(t *testing.T) {
	tests := [][]string{
		{"unknown"}, {"--unknown"}, {"-x"}, {"-r"}, {"--repo"},
		{"--repo="}, {"-r", ""}, {"--yes=maybe"}, {"--dry-run=maybe"},
		{"--", "--yes"}, {"status", "status"}, {"bp", "status"},
		{"status", "--repo"}, {"status", "--unknown"}, {"status", "--repo="},
	}
	for _, repo := range []string{
		"repo", "/repo", "owner/", "owner/repo/extra", "https://github.com/owner/repo",
		"github.com/owner/repo", "owner/repo name", " owner/repo", "owner/repo\n",
		"owner/..", "./repo", "owner/repo?query", "owner/repo#fragment",
		"owner/repo%2Fextra", "owner\\repo",
	} {
		tests = append(tests, []string{"--repo", repo}, []string{"status", "--repo", repo})
	}
	for _, flag := range []string{"--yes", "-y", "--dry-run", "-n", "--yes=false", "--dry-run=false", "-yn"} {
		tests = append(tests, []string{flag, "status"}, []string{"status", flag})
	}
	for _, feature := range security.Features() {
		for _, name := range []string{string(feature.Name), feature.Alias} {
			tests = append(tests, []string{"status", name}, []string{name, "status"})
		}
	}
	for _, args := range tests {
		t.Run(fmt.Sprintf("%q", args), func(t *testing.T) {
			deps := Dependencies{
				Enable: func(context.Context, EnableOptions) error {
					t.Fatal("invalid invocation reached enablement")
					return nil
				},
				Status: func(context.Context, StatusOptions) error {
					t.Fatal("invalid invocation reached status")
					return nil
				},
			}
			code, out, errOut := execute(t, args, deps)
			if code != 2 || out != "" || !strings.HasPrefix(errOut, "Error: ") ||
				!strings.Contains(errOut, "gh secure --help") || strings.Count(errOut, "Error: ") != 1 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
			}
		})
	}
}

// TestHelpAndVersionDoNotExecute checks informational output without invoking handlers.
func TestHelpAndVersionDoNotExecute(t *testing.T) {
	for _, args := range [][]string{
		{"--help"}, {"-h"}, {"status", "--help"}, {"-h", "status"},
		{"status", "-h"}, {"help", "status"},
		{"--version"}, {"-v"}, {"status", "--version"}, {"--version", "status"},
		{"status", "-v"}, {"-v", "status"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			deps := Dependencies{
				Enable: func(context.Context, EnableOptions) error {
					t.Fatal("help/version reached enablement")
					return nil
				},
				Status: func(context.Context, StatusOptions) error {
					t.Fatal("help/version reached status")
					return nil
				},
			}
			code, out, errOut := execute(t, args, deps)
			if code != 0 || out == "" || errOut != "" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
			}
			if strings.Contains(strings.Join(args, " "), "version") ||
				strings.Contains(strings.Join(args, " "), "-v") {
				if out != "gh-secure dev\n" {
					t.Errorf("version output=%q", out)
				}
			} else if !strings.Contains(out, "Usage:") {
				t.Errorf("missing help usage: %q", out)
			}
		})
	}
}

// TestHelpDescribesRegistryAndStatusFlags checks feature help and status flag boundaries.
func TestHelpDescribesRegistryAndStatusFlags(t *testing.T) {
	_, rootHelp, _ := execute(t, []string{"--help"}, Dependencies{})
	for _, feature := range security.Features() {
		if !strings.Contains(rootHelp, string(feature.Name)) || !strings.Contains(rootHelp, "("+feature.Alias+")") {
			t.Errorf("help missing feature %v", feature)
		}
	}
	for _, text := range []string{"--yes", "--dry-run", "--repo", "--version", "--help", "not implemented yet", "active rulesets"} {
		if !strings.Contains(rootHelp, text) {
			t.Errorf("help missing %q", text)
		}
	}
	_, statusHelp, _ := execute(t, []string{"status", "--help"}, Dependencies{})
	if strings.Contains(statusHelp, "--yes") || strings.Contains(statusHelp, "--dry-run") {
		t.Errorf("status advertises enablement-only flags: %s", statusHelp)
	}
}

// TestInjectedVersion checks version output on both root and status commands.
func TestInjectedVersion(t *testing.T) {
	for _, args := range [][]string{{"-v"}, {"status", "--version"}} {
		var out, errOut bytes.Buffer
		code := Execute(context.Background(), args, "v2.0.0-rc.1", ui.Streams{
			In: unexpectedInput{}, Out: &out, ErrOut: &errOut,
		}, Dependencies{})
		if code != 0 || out.String() != "gh-secure v2.0.0-rc.1\n" || errOut.Len() != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
	}
}

// TestMissingHandlersFailExplicitly checks safe failure without runtime prerequisites.
func TestMissingHandlersFailExplicitly(t *testing.T) {
	t.Setenv("GH_CONFIG_DIR", t.TempDir())
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	t.Setenv("GITHUB_ENTERPRISE_TOKEN", "")
	t.Setenv("PATH", "")
	for _, args := range [][]string{nil, {"status"}, {"bp", "-yn"}, {"--repo", "owner/repo", "-y"}} {
		t.Run(fmt.Sprintf("%q", args), func(t *testing.T) {
			code, out, errOut := execute(t, args, Dependencies{})
			wantDiagnostic := "not implemented yet"
			if len(args) > 0 && args[0] == "status" {
				wantDiagnostic = "handler is unavailable"
			}
			if code != 1 || out != "" || !strings.Contains(errOut, wantDiagnostic) ||
				!strings.Contains(errOut, "no repository was inspected or changed") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
			}
		})
	}
}

// TestOperationalErrorsAndContext checks context propagation and operational failure exits.
func TestOperationalErrorsAndContext(t *testing.T) {
	for _, status := range []bool{false, true} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			failure := errors.New("endpoint failed")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			checkContext := func(got context.Context) error {
				calls++
				if got != ctx {
					t.Fatal("command lost its injected context")
				}
				return failure
			}
			deps := Dependencies{
				Enable: func(ctx context.Context, _ EnableOptions) error { return checkContext(ctx) },
				Status: func(ctx context.Context, _ StatusOptions) error { return checkContext(ctx) },
			}
			args := []string{}
			if status {
				args = []string{"status"}
			}
			for _, canceled := range []bool{false, true} {
				if canceled {
					cancel()
				}
				var out, errOut bytes.Buffer
				code := Execute(ctx, args, "dev", ui.Streams{
					In: unexpectedInput{}, Out: &out, ErrOut: &errOut,
				}, deps)
				wantError := "endpoint failed"
				if canceled {
					wantError = "context canceled"
				}
				if code != 1 || out.Len() != 0 || !strings.Contains(errOut.String(), wantError) ||
					strings.Contains(errOut.String(), "for usage") {
					t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
				}
			}
			if calls != 1 {
				t.Fatalf("canceled command executed a dependency: calls=%d", calls)
			}
		})
	}
}
