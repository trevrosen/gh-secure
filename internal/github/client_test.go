package github

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip adapts a test function to an HTTP transport.
func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func fixtureClient(t *testing.T, host string, handler http.HandlerFunc) *Client {
	t.Helper()
	return fixtureAPIClient(t, host, handler, true)
}

func fixtureAPIClient(t *testing.T, host string, handler http.HandlerFunc, readOnly bool) *Client {
	t.Helper()
	t.Setenv("GH_CONFIG_DIR", t.TempDir())
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if readOnly && request.Method != http.MethodGet {
			t.Errorf("status attempted a mutation: %s %s", request.Method, request.URL)
			return nil, errors.New("test transport rejects mutations")
		}
		wantHost := "api.github.com"
		if host != "github.com" {
			wantHost = host
		}
		if request.URL.Host != wantHost {
			t.Errorf("API host=%q, want %q", request.URL.Host, wantHost)
		}
		if request.Header.Get("Authorization") != "token fixture-secret" ||
			request.Header.Get("Accept") != "application/vnd.github+json" ||
			request.Header.Get("X-GitHub-Api-Version") != "2022-11-28" ||
			request.Header.Get("User-Agent") != "gh-secure" {
			t.Errorf("incorrect authentication or API headers")
		}
		clone := request.Clone(request.Context())
		clone.URL.Scheme = endpoint.Scheme
		clone.URL.Host = endpoint.Host
		clone.Host = endpoint.Host
		return server.Client().Transport.RoundTrip(clone)
	})
	client, err := NewClient(api.ClientOptions{Host: host, AuthToken: "fixture-secret", Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func fixtureRepo() repository.Repository {
	return repository.Repository{
		Target:        repository.Target{Host: "github.com", Owner: "owner", Name: "repo"},
		DefaultBranch: "release/security", PushProtection: "enabled",
	}
}

// TestRepositoryMetadata checks required fields, private visibility, and optional permissions.
func TestRepositoryMetadata(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		fail bool
	}{
		{"complete", `{"default_branch":"release/security","private":true,"permissions":{"admin":false,"maintain":true},"security_and_analysis":{"secret_scanning_push_protection":{"status":"enabled"}}}`, false},
		{"permissions omitted", `{"default_branch":"trunk","private":false}`, false},
		{"branch missing", `{"private":false}`, true},
		{"branch null", `{"default_branch":null,"private":false}`, true},
		{"branch empty", `{"default_branch":"","private":false}`, true},
		{"visibility missing", `{"default_branch":"trunk"}`, true},
		{"malformed", `{"private":`, true},
		{"wrong type", `{"default_branch":42,"private":false}`, true},
		{"null", `null`, true},
		{"trailing", `{"default_branch":"trunk","private":false} {}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/owner/repo" {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				fmt.Fprint(w, test.body)
			})
			repo, err := client.Repository(context.Background(), fixtureRepo().Target)
			if (err != nil) != test.fail {
				t.Fatalf("repository=%+v err=%v", repo, err)
			}
			if test.name == "complete" && (!repo.Private || repo.DefaultBranch != "release/security" ||
				repo.Permissions.Maintain == nil || !*repo.Permissions.Maintain || repo.PushProtection != "enabled") {
				t.Fatalf("lost metadata: %+v", repo)
			}
			if test.name == "permissions omitted" && repo.Permissions.Admin != nil {
				t.Fatal("missing permission treated as false")
			}
		})
	}
}

// TestInspectionMappings checks endpoint-specific results and malformed response handling.
func TestInspectionMappings(t *testing.T) {
	tests := []struct {
		name   string
		check  security.CheckID
		path   string
		status int
		body   string
		want   security.State
	}{
		{"protection enabled", security.LegacyProtection, "/branches/release%2Fsecurity/protection", 200, `{"url":"https://api.github.com/repos/owner/repo/branches/release%2Fsecurity/protection"}`, security.Enabled},
		{"protection undocumented error message", security.LegacyProtection, "/branches/release%2Fsecurity/protection", 404, `{"message":"Branch not protected"}`, security.Unknown},
		{"protection inaccessible", security.LegacyProtection, "/branches/release%2Fsecurity/protection", 404, `{"message":"Not Found"}`, security.Unknown},
		{"protection missing fields", security.LegacyProtection, "/branches/release%2Fsecurity/protection", 200, `{}`, security.Unknown},
		{"reporting enabled", security.PrivateReporting, "/private-vulnerability-reporting", 200, `{"enabled":true}`, security.Enabled},
		{"reporting disabled", security.PrivateReporting, "/private-vulnerability-reporting", 200, `{"enabled":false}`, security.Disabled},
		{"reporting missing", security.PrivateReporting, "/private-vulnerability-reporting", 200, `{}`, security.Unknown},
		{"reporting invalid", security.PrivateReporting, "/private-vulnerability-reporting", 200, `{"enabled":"false"}`, security.Unknown},
		{"reporting forbidden", security.PrivateReporting, "/private-vulnerability-reporting", 403, `{"message":"Forbidden"}`, security.Unknown},
		{"alerts enabled", security.DependabotAlerts, "/vulnerability-alerts", 204, ``, security.Enabled},
		{"alerts ambiguous", security.DependabotAlerts, "/vulnerability-alerts", 404, `{"message":"Not Found"}`, security.Unknown},
		{"alerts unexpected success", security.DependabotAlerts, "/vulnerability-alerts", 200, `{}`, security.Unknown},
		{"updates enabled", security.DependabotUpdates, "/automated-security-fixes", 200, `{"enabled":true,"paused":false}`, security.Enabled},
		{"updates disabled", security.DependabotUpdates, "/automated-security-fixes", 200, `{"enabled":false,"paused":false}`, security.Disabled},
		{"updates paused", security.DependabotUpdates, "/automated-security-fixes", 200, `{"enabled":true,"paused":true}`, security.Enabled},
		{"updates paused missing", security.DependabotUpdates, "/automated-security-fixes", 200, `{"enabled":true}`, security.Unknown},
		{"updates null", security.DependabotUpdates, "/automated-security-fixes", 200, `{"enabled":null}`, security.Unknown},
		{"updates inaccessible", security.DependabotUpdates, "/automated-security-fixes", 404, `{"message":"Not Found"}`, security.Unknown},
		{"CodeQL enabled", security.CodeQLSetup, "/code-scanning/default-setup", 200, `{"state":"configured"}`, security.Enabled},
		{"CodeQL disabled", security.CodeQLSetup, "/code-scanning/default-setup", 200, `{"state":"not-configured"}`, security.Disabled},
		{"CodeQL unknown state", security.CodeQLSetup, "/code-scanning/default-setup", 200, `{"state":"other"}`, security.Unknown},
		{"CodeQL missing", security.CodeQLSetup, "/code-scanning/default-setup", 200, `{}`, security.Unknown},
		{"CodeQL unavailable", security.CodeQLSetup, "/code-scanning/default-setup", 403, `{"message":"Forbidden"}`, security.Unknown},
		{"malformed JSON", security.CodeQLSetup, "/code-scanning/default-setup", 200, `{`, security.Unknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.EscapedPath() != "/repos/owner/repo"+test.path {
					t.Errorf("escaped path=%s; want %s", r.URL.EscapedPath(), test.path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			})
			got := client.Inspect(context.Background(), fixtureRepo(), test.check)
			if got.State != test.want || (got.State == security.Unknown && got.Detail == "") {
				t.Fatalf("got %+v; want %s", got, test.want)
			}
			if test.name == "updates paused" && !strings.Contains(got.Detail, "paused") {
				t.Fatalf("paused updates were hidden: %+v", got)
			}
		})
	}
}

// TestPushProtectionMetadata checks explicit states without additional API requests.
func TestPushProtectionMetadata(t *testing.T) {
	client := fixtureClient(t, "github.com", func(http.ResponseWriter, *http.Request) {
		t.Error("push protection must reuse repository metadata")
	})
	for _, test := range []struct {
		value string
		want  security.State
	}{{"enabled", security.Enabled}, {"disabled", security.Disabled}, {"", security.Unknown}, {"other", security.Unknown}} {
		repo := fixtureRepo()
		repo.PushProtection = test.value
		if got := client.Inspect(context.Background(), repo, security.PushProtection); got.State != test.want {
			t.Errorf("status %q: %+v", test.value, got)
		}
	}
}

// TestRulesetsPagination checks later-page active rulesets and fail-closed aggregates.
func TestRulesetsPagination(t *testing.T) {
	for _, failure := range []string{"", "request", "malformed", "null", "missing", "loop", "duplicate"} {
		t.Run(failure, func(t *testing.T) {
			calls := 0
			client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path != "/repos/owner/repo/rulesets" || r.URL.Query().Get("per_page") != "100" || r.URL.Query().Get("includes_parents") != "true" {
					t.Errorf("incorrect ruleset request %s", r.URL)
				}
				if r.URL.Query().Get("page") == "1" {
					w.Header().Set("Link", `<https://api.github.com/repos/owner/repo/rulesets?page=2&per_page=100>; rel="next"`)
					fmt.Fprint(w, `[{"id":1,"name":"advisory","enforcement":"evaluate"},{"id":2,"name":"disabled","enforcement":"disabled"}]`)
					return
				}
				switch failure {
				case "request":
					w.WriteHeader(403)
					fmt.Fprint(w, `{"message":"Forbidden"}`)
				case "malformed":
					fmt.Fprint(w, `{`)
				case "null":
					fmt.Fprint(w, `null`)
				case "missing":
					fmt.Fprint(w, `[{"id":3,"name":"missing enforcement"}]`)
				case "loop":
					w.Header().Set("Link", `<https://api.github.com/repos/owner/repo/rulesets?page=1>; rel="next"`)
					fmt.Fprint(w, `[]`)
				case "duplicate":
					fmt.Fprint(w, `[{"id":2,"name":"duplicate","enforcement":"active"}]`)
				default:
					fmt.Fprint(w, `[{"id":3,"name":"organization policy","enforcement":"active"}]`)
				}
			})
			got := client.Rulesets(context.Background(), fixtureRepo())
			if calls != 2 || got.Known != (failure == "") {
				t.Fatalf("calls=%d rulesets=%+v", calls, got)
			}
			if failure == "" && (len(got.Active) != 1 || got.Active[0] != "organization policy") {
				t.Fatalf("incorrect active rulesets: %+v", got)
			}
			if failure != "" && (len(got.Active) != 0 || got.Detail == "") {
				t.Fatalf("failed pagination produced misleading aggregate: %+v", got)
			}
		})
	}
}

// TestPolicyAdvisory avoids treating undocumented or inaccessible metadata as absence.
func TestPolicyAdvisory(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   security.State
	}{
		{"present", 200, `{"files":{"security":{"url":"https://github.com/owner/repo/blob/main/SECURITY.md"}}}`, security.Enabled},
		{"null undocumented field", 200, `{"files":{"security":null}}`, security.Unknown},
		{"missing files", 200, `{}`, security.Unknown},
		{"missing field", 200, `{"files":{}}`, security.Unknown},
		{"missing URL", 200, `{"files":{"security":{}}}`, security.Unknown},
		{"unsafe URL", 200, `{"files":{"security":{"url":"https://user:password@example.com/"}}}`, security.Unknown},
		{"forbidden", 403, `{"message":"Forbidden"}`, security.Unknown},
		{"inaccessible", 404, `{"message":"Not Found"}`, security.Unknown},
		{"malformed", 200, `{`, security.Unknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/owner/repo/community/profile" {
					t.Errorf("incorrect advisory path %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			})
			got := client.Policy(context.Background(), fixtureRepo())
			if got.State != test.want || (test.want == security.Unknown && got.Detail == "") {
				t.Fatalf("policy=%+v, want %s", got, test.want)
			}
		})
	}
}

// TestReadErrorsPreserveSafeDiagnostics checks access, rate limits, host routing, and redaction.
func TestReadErrorsPreserveSafeDiagnostics(t *testing.T) {
	for _, code := range []int{401, 403, 404, 429, 500} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			client := fixtureClient(t, "github.example.com", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v3/repos/owner/repo" {
					t.Errorf("incorrect GHES path: %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				if code == 403 {
					w.Header().Set("X-RateLimit-Remaining", "0")
				}
				w.WriteHeader(code)
				fmt.Fprint(w, `{"message":"fixture-secret"}`)
			})
			target := fixtureRepo().Target
			target.Host = "github.example.com"
			_, err := client.Repository(context.Background(), target)
			if err == nil || strings.Contains(err.Error(), "fixture-secret") || !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", code)) {
				t.Fatalf("unsafe or missing diagnostic: %v", err)
			}
			if (code == 403 || code == 429) && !strings.Contains(err.Error(), "rate limited") {
				t.Errorf("missing rate-limit diagnostic: %v", err)
			}
		})
	}
}

// TestReadCancellation stops in-flight reads and preserves the context error.
func TestReadCancellation(t *testing.T) {
	received := make(chan struct{})
	stopped := make(chan struct{})
	release := make(chan struct{})
	client := fixtureClient(t, "github.com", func(w http.ResponseWriter, r *http.Request) {
		close(received)
		select {
		case <-r.Context().Done():
			close(stopped)
		case <-release:
		}
	})
	defer close(release)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waitContext, stopWaiting := context.WithTimeout(t.Context(), 5*time.Second)
	defer stopWaiting()
	result := make(chan error, 1)
	go func() {
		_, err := client.Repository(ctx, fixtureRepo().Target)
		result <- err
	}()
	select {
	case <-received:
	case err := <-result:
		t.Fatalf("read returned before reaching the server: %v", err)
	case <-waitContext.Done():
		t.Fatal("timed out waiting for read to reach the server")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation not preserved: %v", err)
		}
	case <-waitContext.Done():
		t.Fatal("read did not return after cancellation")
	}
	select {
	case <-stopped:
	case <-waitContext.Done():
		t.Fatal("server request did not inherit cancellation")
	}
}

// TestTransportFailureDoesNotExposeCredentials checks safe non-HTTP diagnostics.
func TestTransportFailureDoesNotExposeCredentials(t *testing.T) {
	t.Setenv("GH_CONFIG_DIR", t.TempDir())
	client, err := NewClient(api.ClientOptions{
		Host: "github.com", AuthToken: "fixture-secret",
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("network failed with fixture-secret")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Repository(context.Background(), fixtureRepo().Target)
	if err == nil || strings.Contains(err.Error(), "fixture-secret") || !strings.Contains(err.Error(), "check network") {
		t.Fatalf("unsafe or missing transport diagnostic: %v", err)
	}
}

// TestPaginationLinks checks repeated headers, unquoted relations, and malformed links.
func TestPaginationLinks(t *testing.T) {
	for _, test := range []struct {
		name   string
		values []string
		want   int
		fail   bool
	}{
		{"end", nil, 0, false},
		{"repeated headers", []string{`<https://api.github.com/items?page=4>; rel="last"`, `<https://api.github.com/items?page=2>; rel="next"`}, 2, false},
		{"unquoted relation", []string{`<https://api.github.com/items?page=2>; rel=next`}, 2, false},
		{"untrusted address not followed", []string{`<https://untrusted.invalid/items?page=2>; rel="next"`}, 2, false},
		{"malformed", []string{`invalid`}, 0, true},
		{"missing relation", []string{`<https://api.github.com/items?page=2>`}, 0, true},
		{"invalid page", []string{`<https://api.github.com/items?page=invalid>; rel="next"`}, 0, true},
		{"jump", []string{`<https://api.github.com/items?page=3>; rel="next"`}, 0, true},
		{"cycle", []string{`<https://api.github.com/items?page=1>; rel="next"`}, 0, true},
		{"duplicate next", []string{`<https://api.github.com/items?page=2>; rel="next"`, `<https://api.github.com/items?page=2>; rel="next"`}, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := nextPage(http.Header{"Link": test.values}, 1)
			if got != test.want || (err != nil) != test.fail {
				t.Fatalf("page=%d err=%v; want %d fail=%t", got, err, test.want, test.fail)
			}
		})
	}
}

// TestAPIHostOverride keeps API routing separate from the repository's web host.
func TestAPIHostOverride(t *testing.T) {
	t.Setenv("GH_CONFIG_DIR", t.TempDir())
	calls := 0
	client, err := NewClient(api.ClientOptions{
		Host: "github.example.com", APIHost: "api.internal.example", AuthToken: "fixture-token",
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			if request.Method != http.MethodGet || request.URL.Host != "api.internal.example" ||
				request.URL.Path != "/api/v3/repos/owner/repo" || request.Header.Get("Authorization") != "token fixture-token" {
				t.Errorf("incorrect API-host routing or authentication")
			}
			return &http.Response{
				StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{"default_branch":"trunk","private":false}`)), Request: request,
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	target := repository.Target{Host: "github.example.com", Owner: "owner", Name: "repo"}
	repo, err := client.Repository(context.Background(), target)
	if err != nil || calls != 1 || repo.Target.WebURL() != "https://github.example.com/owner/repo" {
		t.Fatalf("repository=%+v calls=%d err=%v", repo, calls, err)
	}
	if _, err := NewClient(api.ClientOptions{Host: target.Host, APIHost: "https://invalid.example", AuthToken: "fixture-token"}); err == nil {
		t.Fatal("accepted malformed API host")
	}
}
