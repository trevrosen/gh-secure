package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/GitHubSecurityLab/gh-secure/internal/security"
)

// TestMutationContracts checks exact methods, paths, payloads, and accepted statuses.
func TestMutationContracts(t *testing.T) {
	tests := []struct {
		name     string
		check    security.CheckID
		method   string
		path     string
		body     string
		status   int
		response string
		runURL   string
	}{
		{
			"branch protection", security.LegacyProtection, http.MethodPut,
			"/branches/release%2Fsecurity/protection",
			`{"required_status_checks":null,"enforce_admins":false,"required_pull_request_reviews":{"required_approving_review_count":1,"dismiss_stale_reviews":true,"require_code_owner_reviews":false},"restrictions":null,"allow_force_pushes":false,"allow_deletions":false,"required_conversation_resolution":true}`,
			200, `{"url":"https://api.github.com/protection"}`, "",
		},
		{"reporting", security.PrivateReporting, http.MethodPut, "/private-vulnerability-reporting", "", 204, "", ""},
		{"push protection", security.PushProtection, http.MethodPatch, "", `{"security_and_analysis":{"secret_scanning_push_protection":{"status":"enabled"}}}`, 200, `{"security_and_analysis":{"secret_scanning_push_protection":{"status":"enabled"}}}`, ""},
		{"push protection optional metadata", security.PushProtection, http.MethodPatch, "", `{"security_and_analysis":{"secret_scanning_push_protection":{"status":"enabled"}}}`, 200, `{}`, ""},
		{"alerts", security.DependabotAlerts, http.MethodPut, "/vulnerability-alerts", "", 204, "", ""},
		{"security updates", security.DependabotUpdates, http.MethodPut, "/automated-security-fixes", "", 204, "", ""},
		{"CodeQL accepted", security.CodeQLSetup, http.MethodPatch, "/code-scanning/default-setup", `{"state":"configured","query_suite":"default"}`, 202, `{"run_id":123,"run_url":"https://api.github.com/repos/owner/repo/code-scanning/default-setup/runs/123"}`, "https://api.github.com/repos/owner/repo/code-scanning/default-setup/runs/123"},
		{"CodeQL synchronous", security.CodeQLSetup, http.MethodPatch, "/code-scanning/default-setup", `{"state":"configured","query_suite":"default"}`, 200, `{}`, ""},
		{"CodeQL optional tracking", security.CodeQLSetup, http.MethodPatch, "/code-scanning/default-setup", `{"state":"configured","query_suite":"default"}`, 202, `{}`, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := fixtureWriteClient(t, "github.example.com", func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != test.method || r.URL.EscapedPath() != "/api/v3/repos/owner/repo"+test.path {
					t.Errorf("request=%s %s; want %s %s", r.Method, r.URL.EscapedPath(), test.method, test.path)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if test.body == "" {
					if len(body) != 0 {
						t.Errorf("unexpected body: %s", body)
					}
				} else {
					var got, want any
					if err := json.Unmarshal(body, &got); err != nil {
						t.Error(err)
					}
					if err := json.Unmarshal([]byte(test.body), &want); err != nil {
						t.Error(err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Errorf("body=%s; want %s", body, test.body)
					}
					if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
						t.Errorf("incorrect content type: %s", r.Header.Get("Content-Type"))
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.response)
			})
			repo := fixtureRepo()
			repo.Target.Host = "github.example.com"
			mutation, err := client.Enable(t.Context(), repo, test.check)
			if err != nil || calls != 1 || mutation.RunURL != test.runURL {
				t.Fatalf("mutation=%+v calls=%d error=%v", mutation, calls, err)
			}
		})
	}
}

// TestMutationFailuresAreNotRetried checks single-attempt failures and safe diagnostics.
func TestMutationFailuresAreNotRetried(t *testing.T) {
	for _, test := range []struct {
		check  security.CheckID
		status int
		method string
		path   string
		hint   string
	}{
		{security.LegacyProtection, 403, "PUT", "/branches/release%2Fsecurity/protection", "permissions"},
		{security.PrivateReporting, 422, "PUT", "/private-vulnerability-reporting", "validation"},
		{security.PushProtection, 401, "PATCH", "", "authentication"},
		{security.DependabotAlerts, 404, "PUT", "/vulnerability-alerts", "inaccessible"},
		{security.DependabotUpdates, 500, "PUT", "/automated-security-fixes", "feature availability"},
		{security.CodeQLSetup, 409, "PATCH", "/code-scanning/default-setup", "in progress"},
		{security.CodeQLSetup, 503, "PATCH", "/code-scanning/default-setup", "host support"},
		{security.CodeQLSetup, 429, "PATCH", "/code-scanning/default-setup", "rate limited"},
	} {
		t.Run(fmt.Sprintf("%s/%d", test.check, test.status), func(t *testing.T) {
			calls := 0
			client := fixtureWriteClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != test.method || r.URL.EscapedPath() != "/repos/owner/repo"+test.path {
					t.Errorf("unexpected write: %s %s", r.Method, r.URL.EscapedPath())
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				fmt.Fprint(w, `{"message":"fixture-secret"}`)
			})
			mutation, err := client.Enable(t.Context(), fixtureRepo(), test.check)
			if err == nil || calls != 1 || mutation != (security.Mutation{}) {
				t.Fatalf("mutation=%+v calls=%d error=%v", mutation, calls, err)
			}
			diagnostic := err.Error()
			for _, text := range []string{test.method, "repos/owner/repo" + test.path, fmt.Sprintf("HTTP %d", test.status), test.hint} {
				if !strings.Contains(diagnostic, text) {
					t.Errorf("missing %q in diagnostic: %s", text, diagnostic)
				}
			}
			if strings.Contains(diagnostic, "fixture-secret") {
				t.Errorf("response or credential exposed: %s", diagnostic)
			}
			var httpError *api.HTTPError
			if !errors.As(err, &httpError) || httpError.StatusCode != test.status {
				t.Errorf("typed HTTP failure lost: %v", err)
			}
		})
	}
}

// TestMutationResponsesMustMatchContract rejects unexpected statuses and unverifiable bodies.
func TestMutationResponsesMustMatchContract(t *testing.T) {
	for _, test := range []struct {
		name     string
		check    security.CheckID
		status   int
		response string
	}{
		{"protection missing URL", security.LegacyProtection, 200, `{}`},
		{"protection wrong URL type", security.LegacyProtection, 200, `{"url":42}`},
		{"protection unexpected success", security.LegacyProtection, 202, `{}`},
		{"reporting unexpected success", security.PrivateReporting, 200, `{}`},
		{"alerts unexpected success", security.DependabotAlerts, 200, `{}`},
		{"updates unexpected success", security.DependabotUpdates, 202, `{}`},
		{"repository null", security.PushProtection, 200, `null`},
		{"repository array", security.PushProtection, 200, `[]`},
		{"repository contradictory state", security.PushProtection, 200, `{"security_and_analysis":{"secret_scanning_push_protection":{"status":"disabled"}}}`},
		{"CodeQL empty body", security.CodeQLSetup, 202, ``},
		{"CodeQL null", security.CodeQLSetup, 202, `null`},
		{"CodeQL invalid JSON", security.CodeQLSetup, 202, `{`},
		{"CodeQL trailing content", security.CodeQLSetup, 202, `{} {}`},
		{"CodeQL wrong run ID type", security.CodeQLSetup, 202, `{"run_id":"fixture-secret"}`},
		{"CodeQL wrong URL type", security.CodeQLSetup, 202, `{"run_url":42}`},
		{"CodeQL unsafe URL", security.CodeQLSetup, 202, `{"run_url":"http://example.com/run"}`},
		{"CodeQL credential URL", security.CodeQLSetup, 202, `{"run_url":"https://fixture-secret@example.com/run"}`},
		{"CodeQL unexpected success", security.CodeQLSetup, 204, ``},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := fixtureWriteClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.response)
			})
			mutation, err := client.Enable(t.Context(), fixtureRepo(), test.check)
			if err == nil || calls != 1 || mutation != (security.Mutation{}) {
				t.Fatalf("unverified write reported success: mutation=%+v calls=%d error=%v", mutation, calls, err)
			}
			if strings.Contains(err.Error(), "fixture-secret") {
				t.Errorf("invalid response leaked: %v", err)
			}
		})
	}
}

// TestMutationRedirectsAreNotFollowed refuses to replay writes at redirect targets.
func TestMutationRedirectsAreNotFollowed(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   int
		location string
	}{
		{"same-origin replay", 307, "https://api.github.com/repos/owner/renamed"},
		{"method downgrade", 302, "https://api.github.com/repos/owner/renamed"},
		{"cross-origin replay", 307, "https://untrusted.invalid/repos/owner/repo"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := fixtureWriteClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", test.location)
				w.WriteHeader(test.status)
			})
			_, err := client.Enable(t.Context(), fixtureRepo(), security.PushProtection)
			if err == nil || calls != 1 || !strings.Contains(err.Error(), "redirect refused") {
				t.Fatalf("redirect followed or hidden: calls=%d error=%v", calls, err)
			}
		})
	}
}

// TestMutationTransportFailureAndCancellation checks redacted transport errors and pre-write cancellation.
func TestMutationTransportFailureAndCancellation(t *testing.T) {
	t.Setenv("GH_CONFIG_DIR", t.TempDir())
	calls := 0
	client, err := NewClient(api.ClientOptions{
		Host: "github.com", AuthToken: "fixture-secret",
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("network failed with fixture-secret")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Enable(t.Context(), fixtureRepo(), security.CodeQLSetup); err == nil ||
		strings.Contains(err.Error(), "fixture-secret") || !strings.Contains(err.Error(), "PATCH repos/owner/repo/code-scanning/default-setup") || calls != 1 {
		t.Fatalf("unsafe, missing, or retried transport failure: calls=%d error=%v", calls, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := client.Enable(ctx, fixtureRepo(), security.CodeQLSetup); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("canceled write reached transport: calls=%d error=%v", calls, err)
	}
}

// TestMutationRejectsInvalidInputsBeforeWriting checks local validation before any request.
func TestMutationRejectsInvalidInputsBeforeWriting(t *testing.T) {
	for _, name := range []string{"private reporting", "missing branch", "invalid target", "unknown check"} {
		t.Run(name, func(t *testing.T) {
			client := fixtureWriteClient(t, "github.com", func(http.ResponseWriter, *http.Request) {
				t.Error("invalid mutation reached the server")
			})
			repo, check := fixtureRepo(), security.LegacyProtection
			switch name {
			case "private reporting":
				repo.Private, check = true, security.PrivateReporting
			case "missing branch":
				repo.DefaultBranch = ""
			case "invalid target":
				repo.Target.Name = "../repo"
			case "unknown check":
				check = "invalid"
			}
			if _, err := client.Enable(t.Context(), repo, check); err == nil {
				t.Fatal("invalid mutation succeeded")
			}
		})
	}
}

// TestAmbiguousInspectionCannotProduceWrites keeps ambiguous 404 inspections from becoming writes.
func TestAmbiguousInspectionCannotProduceWrites(t *testing.T) {
	for _, test := range []struct {
		feature security.Feature
		id      security.CheckID
	}{
		{security.BranchProtection, security.LegacyProtection},
		{security.Dependabot, security.DependabotAlerts},
		{security.Dependabot, security.DependabotUpdates},
	} {
		t.Run(string(test.id), func(t *testing.T) {
			calls := 0
			client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(404)
				fmt.Fprint(w, `{"message":"Not Found"}`)
			})
			repo := fixtureRepo()
			inspection := client.Inspect(t.Context(), repo, test.id)
			report := security.StatusReport{Repository: repo, Rulesets: security.Rulesets{Known: true}}
			for _, id := range []security.CheckID{security.LegacyProtection, security.DependabotAlerts, security.DependabotUpdates} {
				state := security.Inspection{State: security.Enabled}
				if id == test.id {
					state = inspection
				}
				report.Checks = append(report.Checks, security.Check{ID: id, Inspection: state})
			}
			plan, err := security.PlanFeature(report, test.feature)
			if err != nil {
				t.Fatal(err)
			}
			result := plan.Apply(t.Context(), client, security.ApplyOptions{})
			if inspection.State != security.Unknown || result.Err() == nil || calls != 1 {
				t.Fatalf("ambiguous read became a write or success: inspection=%+v calls=%d result=%+v", inspection, calls, result)
			}
		})
	}
}

// TestExistingProtectionIsNeverReconciled leaves existing protection unchanged.
func TestExistingProtectionIsNeverReconciled(t *testing.T) {
	calls := 0
	client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.EscapedPath() != "/repos/owner/repo/branches/release%2Fsecurity/protection" {
			t.Errorf("unexpected inspection: %s", r.URL)
		}
		fmt.Fprint(w, `{"url":"https://api.github.com/protection","enforce_admins":{"enabled":true},"required_pull_request_reviews":{"required_approving_review_count":3}}`)
	})
	repo := fixtureRepo()
	plan, err := security.PlanFeature(security.StatusReport{
		Repository: repo,
		Checks: []security.Check{{
			ID: security.LegacyProtection, Inspection: client.Inspect(t.Context(), repo, security.LegacyProtection),
		}},
		Rulesets: security.Rulesets{Detail: "rulesets unavailable"},
	}, security.BranchProtection)
	if err != nil {
		t.Fatal(err)
	}
	result := plan.Apply(t.Context(), client, security.ApplyOptions{})
	if calls != 1 || result.Err() != nil || result.Outcome() != security.OutcomeAlreadyEnabled || plan.RequiresRulesetConfirmation() {
		t.Fatalf("existing protection was not preserved: calls=%d outcome=%s error=%v", calls, result.Outcome(), result.Err())
	}
}

// TestDependabotHTTPPartialFailures checks independent Dependabot writes over HTTP.
func TestDependabotHTTPPartialFailures(t *testing.T) {
	for _, failedPath := range []string{"/vulnerability-alerts", "/automated-security-fixes"} {
		t.Run(failedPath, func(t *testing.T) {
			var paths []string
			client := fixtureWriteClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				if r.Method != http.MethodPut {
					t.Errorf("unexpected method %s", r.Method)
				}
				if r.URL.Path == "/repos/owner/repo"+failedPath {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(403)
					fmt.Fprint(w, `{"message":"fixture-secret"}`)
					return
				}
				w.WriteHeader(204)
			})
			plan, err := security.PlanFeature(security.StatusReport{
				Repository: fixtureRepo(),
				Checks: []security.Check{
					{ID: security.DependabotAlerts, Inspection: security.Inspection{State: security.Disabled}},
					{ID: security.DependabotUpdates, Inspection: security.Inspection{State: security.Disabled}},
				},
			}, security.Dependabot)
			if err != nil {
				t.Fatal(err)
			}
			result := plan.Apply(t.Context(), client, security.ApplyOptions{})
			if !reflect.DeepEqual(paths, []string{"/repos/owner/repo/vulnerability-alerts", "/repos/owner/repo/automated-security-fixes"}) ||
				result.Outcome() != security.OutcomePartial || result.Err() == nil || len(result.Operations) != 2 {
				t.Fatalf("writes=%v result=%+v outcome=%s error=%v", paths, result, result.Outcome(), result.Err())
			}
			if !strings.Contains(result.Err().Error(), "PUT repos/owner/repo"+failedPath+": HTTP 403") ||
				strings.Contains(result.Err().Error(), "fixture-secret") {
				t.Errorf("unsafe or missing partial-failure diagnostic: %v", result.Err())
			}
			failedIndex := 0
			if failedPath == "/automated-security-fixes" {
				failedIndex = 1
			}
			if result.Operations[failedIndex].Outcome != security.OutcomeFailed ||
				result.Operations[1-failedIndex].Outcome != security.OutcomeApplied {
				t.Errorf("sub-operation outcomes lost: %+v", result.Operations)
			}
		})
	}
}

// responseReader adapts a function to an io.Reader response body.
type responseReader func([]byte) (int, error)

// Read delegates to the wrapped function.
func (read responseReader) Read(buffer []byte) (int, error) { return read(buffer) }

// TestMutationInFlightCancellation stops writes cancelled before or during the response.
func TestMutationInFlightCancellation(t *testing.T) {
	for _, phase := range []string{"before response", "during response"} {
		t.Run(phase, func(t *testing.T) {
			t.Setenv("GH_CONFIG_DIR", t.TempDir())
			received, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			calls := 0
			client, err := NewClient(api.ClientOptions{
				Host: "github.com", AuthToken: "fixture-token",
				Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					calls++
					waitForCancellation := func() error {
						close(received)
						select {
						case <-request.Context().Done():
							return request.Context().Err()
						case <-release:
							return errors.New("test transport released")
						}
					}
					if phase == "before response" {
						return nil, waitForCancellation()
					}
					return &http.Response{
						StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": {"application/json"}},
						Body: io.NopCloser(responseReader(func([]byte) (int, error) {
							return 0, waitForCancellation()
						})), Request: request,
					}, nil
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			waitContext, stopWaiting := context.WithTimeout(t.Context(), 5*time.Second)
			defer stopWaiting()
			result := make(chan error, 1)
			go func() {
				_, writeErr := client.Enable(ctx, fixtureRepo(), security.CodeQLSetup)
				result <- writeErr
			}()
			select {
			case <-received:
			case err := <-result:
				t.Fatalf("write failed before %s: %v", phase, err)
			case <-waitContext.Done():
				t.Fatalf("write did not reach %s", phase)
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) || calls != 1 || !strings.Contains(err.Error(), "PATCH repos/owner/repo/code-scanning/default-setup") {
					t.Fatalf("write cancellation lost or retried: calls=%d error=%v", calls, err)
				}
			case <-waitContext.Done():
				t.Fatal("write did not stop after cancellation")
			}
		})
	}
}
