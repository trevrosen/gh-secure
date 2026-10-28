package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/GitHubSecurityLab/gh-secure/internal/github"
	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
	"github.com/GitHubSecurityLab/gh-secure/internal/ui"
)

type statusTransport func(*http.Request) (*http.Response, error)

// RoundTrip dispatches fixture responses and rejects every mutating request.
func (f statusTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodGet {
		return nil, errors.New("status test transport rejects mutations")
	}
	return f(request)
}

// TestStatusCommandReadOnly checks real REST inspection, output, request counts, and exits.
func TestStatusCommandReadOnly(t *testing.T) {
	tests := []struct {
		mode       string
		code       int
		summary    string
		calls      int
		extraText  string
		diagnostic string
	}{
		{"enabled", 0, "Summary (6 checks): 6 enabled, 0 disabled, 0 unknown, 0 unsupported", 7, "Active rulesets: 1", ""},
		{"disabled", 0, "Summary (6 checks): 2 enabled, 4 disabled, 0 unknown, 0 unsupported", 7, "disabled", ""},
		{"mixed unknown", 1, "Summary (6 checks): 1 enabled, 4 disabled, 1 unknown, 0 unsupported", 7, "unknown", "security inspection incomplete: Legacy branch protection: unknown"},
		{"alerts ambiguous", 1, "Summary (6 checks): 5 enabled, 0 disabled, 1 unknown, 0 unsupported", 7, "unknown", "security inspection incomplete: Dependabot alerts: unknown"},
		{"unsupported", 1, "Summary (6 checks): 5 enabled, 0 disabled, 0 unknown, 1 unsupported", 6, "public repositories", "security inspection incomplete: Private vulnerability reporting: unsupported"},
		{"rulesets failure", 1, "Summary (6 checks): 6 enabled, 0 disabled, 0 unknown, 0 unsupported", 7, "Active rulesets: unknown", "security inspection incomplete: active rulesets: unknown"},
		{"malformed setting", 1, "Summary (6 checks): 5 enabled, 0 disabled, 1 unknown, 0 unsupported", 7, "invalid JSON", "security inspection incomplete: CodeQL default setup: unknown"},
		{"metadata failure", 1, "", 1, "", ""},
		{"canceled", 1, "Partial summary: 1 enabled, 0 disabled, 0 unknown, 0 unsupported", 3, "Inspection incomplete", "context canceled"},
	}
	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			t.Setenv("GH_CONFIG_DIR", t.TempDir())
			var out, errOut bytes.Buffer
			streams := ui.Streams{In: unexpectedInput{}, Out: &out, ErrOut: &errOut}
			target := repository.Target{Host: "github.example.com", Owner: "owner", Name: "repo"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			transport := statusTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Host != target.Host {
					t.Errorf("request sent to wrong host: %s", request.URL.Host)
				}
				status, body := http.StatusOK, ""
				disabled := test.mode == "disabled" || test.mode == "mixed unknown"
				switch request.URL.EscapedPath() {
				case "/api/v3/repos/owner/repo":
					private := test.mode == "unsupported"
					push := "enabled"
					if disabled {
						push = "disabled"
					}
					body = fmt.Sprintf(`{"default_branch":"release/test","private":%t,"permissions":{"admin":false,"maintain":false},"security_and_analysis":{"secret_scanning_push_protection":{"status":%q}}}`, private, push)
					if test.mode == "metadata failure" {
						status, body = 404, `{"message":"Not Found"}`
					}
				case "/api/v3/repos/owner/repo/branches/release%2Ftest/protection":
					body = `{"url":"https://github.example.com/protection"}`
					if test.mode == "mixed unknown" {
						status, body = 404, `{"message":"Not Found"}`
					}
				case "/api/v3/repos/owner/repo/rulesets":
					body = `[{"id":1,"name":"organization policy","enforcement":"active"}]`
					if test.mode == "rulesets failure" {
						status, body = 403, `{"message":"Forbidden"}`
					}
					if test.mode == "canceled" {
						cancel()
						return nil, ctx.Err()
					}
				case "/api/v3/repos/owner/repo/private-vulnerability-reporting":
					body = fmt.Sprintf(`{"enabled":%t}`, !disabled)
				case "/api/v3/repos/owner/repo/vulnerability-alerts":
					status = 204
					if test.mode == "alerts ambiguous" {
						status, body = 404, `{"message":"Not Found"}`
					}
				case "/api/v3/repos/owner/repo/automated-security-fixes":
					body = fmt.Sprintf(`{"enabled":%t,"paused":false}`, !disabled)
				case "/api/v3/repos/owner/repo/code-scanning/default-setup":
					body = `{"state":"configured"}`
					if disabled {
						body = `{"state":"not-configured"}`
					}
					if test.mode == "malformed setting" {
						body = `{`
					}
				default:
					t.Errorf("unexpected read: %s", request.URL)
					return nil, errors.New("unexpected status request")
				}
				return &http.Response{
					StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
					Body: io.NopCloser(strings.NewReader(body)), Request: request,
				}, nil
			})
			resolutions := 0
			handler := NewStatusHandler(streams, func(_ context.Context, explicit string) (repository.Target, error) {
				resolutions++
				if explicit != "owner/repo" {
					t.Errorf("explicit repository lost: %q", explicit)
				}
				return target, nil
			}, func(got repository.Target) (security.Reader, error) {
				if got != target {
					t.Fatalf("factory target=%v; want %v", got, target)
				}
				return github.NewClient(api.ClientOptions{Host: got.Host, AuthToken: "fixture-token", Transport: transport})
			})
			code := Execute(ctx, []string{"status", "--repo", "owner/repo"}, "dev", streams, Dependencies{Status: handler})
			if code != test.code || calls != test.calls || resolutions != 1 {
				t.Fatalf("code=%d calls=%d resolutions=%d stdout=%q stderr=%q", code, calls, resolutions, out.String(), errOut.String())
			}
			if test.summary != "" && !strings.Contains(out.String(), test.summary+"\n") {
				t.Errorf("incorrect summary: %q", out.String())
			}
			if test.extraText != "" && !strings.Contains(out.String(), test.extraText) {
				t.Errorf("missing %q: %q", test.extraText, out.String())
			}
			if test.mode == "metadata failure" && out.Len() != 0 {
				t.Errorf("metadata failure produced a misleading status: %s", out.String())
			}
			if (test.code != 0) != (errOut.Len() > 0) {
				t.Errorf("incorrect diagnostics: %q", errOut.String())
			}
			if test.diagnostic != "" && errOut.String() != "Error: "+test.diagnostic+"\n" {
				t.Errorf("diagnostic=%q; want %q", errOut.String(), test.diagnostic)
			}
			if out.Len() > 0 && !strings.Contains(out.String(), "https://github.example.com/owner/repo/security") {
				t.Errorf("missing host-aware link: %q", out.String())
			}
		})
	}
}

// TestStatusPrerequisiteFailures checks resolution and client errors before inspection.
func TestStatusPrerequisiteFailures(t *testing.T) {
	for _, failResolution := range []bool{false, true} {
		var out, errOut bytes.Buffer
		streams := ui.Streams{Out: &out, ErrOut: &errOut}
		handler := NewStatusHandler(streams, func(context.Context, string) (repository.Target, error) {
			if failResolution {
				return repository.Target{}, errors.New("discovery failed")
			}
			return repository.Target{Host: "github.example.com", Owner: "owner", Name: "repo"}, nil
		}, func(repository.Target) (security.Reader, error) {
			if failResolution {
				t.Fatal("client initialized after resolution failure")
			}
			return nil, errors.New("authentication failed")
		})
		if code := Execute(context.Background(), []string{"status"}, "dev", streams, Dependencies{Status: handler}); code != 1 || out.Len() != 0 || errOut.Len() == 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
	}
}

// TestDefaultDependenciesAreLazy checks real wiring without credentials, git, or network.
func TestDefaultDependenciesAreLazy(t *testing.T) {
	t.Setenv("GH_CONFIG_DIR", t.TempDir())
	t.Setenv("GH_HOST", "github.com")
	t.Setenv("GH_REPO", "owner/repo")
	for _, name := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "PATH"} {
		t.Setenv(name, "")
	}
	for _, args := range [][]string{{"--help"}, {"--version"}, {"status", "-h"}, {"status", "-v"}} {
		var out, errOut bytes.Buffer
		streams := ui.Streams{In: unexpectedInput{}, Out: &out, ErrOut: &errOut}
		if code := Execute(context.Background(), args, "dev", streams, DefaultDependencies(streams)); code != 0 || errOut.Len() != 0 {
			t.Fatalf("help/version needs runtime prerequisites: code=%d err=%q", code, errOut.String())
		}
	}
	var out, errOut bytes.Buffer
	streams := ui.Streams{In: unexpectedInput{}, Out: &out, ErrOut: &errOut}
	if code := Execute(context.Background(), []string{"status"}, "dev", streams, DefaultDependencies(streams)); code != 1 ||
		!strings.Contains(errOut.String(), "authentication") || out.Len() != 0 {
		t.Fatalf("expected authentication failure: code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	for _, args := range [][]string{nil, {"bp", "--yes"}, {"cs", "--dry-run"}} {
		out.Reset()
		errOut.Reset()
		if code := Execute(t.Context(), args, "dev", streams, DefaultDependencies(streams)); code != 1 ||
			out.Len() != 0 || !strings.Contains(errOut.String(), "not implemented yet") ||
			!strings.Contains(errOut.String(), "no repository was inspected or changed") {
			t.Fatalf("unconfirmed enablement became available: args=%v code=%d stdout=%q stderr=%q", args, code, out.String(), errOut.String())
		}
	}
}
