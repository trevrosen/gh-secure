package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"

	"github.com/GitHubSecurityLab/gh-secure/internal/github"
	"github.com/GitHubSecurityLab/gh-secure/internal/repository"
	"github.com/GitHubSecurityLab/gh-secure/internal/security"
	"github.com/GitHubSecurityLab/gh-secure/internal/ui"
)

const (
	fixtureAPI     = "/api/v3/repos/owner/repo"
	protectionPath = fixtureAPI + "/branches/release%2Ftest/protection"
	pvrPath        = fixtureAPI + "/private-vulnerability-reporting"
	alertsPath     = fixtureAPI + "/vulnerability-alerts"
	fixesPath      = fixtureAPI + "/automated-security-fixes"
	codeQLPath     = fixtureAPI + "/code-scanning/default-setup"
	rulesetsPath   = fixtureAPI + "/rulesets"
	profilePath    = fixtureAPI + "/community/profile"
)

// Exact write requests, in canonical order, for each setting.
const (
	writeProtection = "PUT " + protectionPath
	writePVR        = "PUT " + pvrPath
	writePush       = "PATCH " + fixtureAPI
	writeAlerts     = "PUT " + alertsPath
	writeFixes      = "PUT " + fixesPath
	writeCodeQL     = "PATCH " + codeQLPath
)

var allWrites = []string{writeProtection, writePVR, writePush, writeAlerts, writeFixes, writeCodeQL}

// enableFixture serves one GHES repository through the real REST adapter.
// States are "enabled", "disabled", or "unknown" per setting.
type enableFixture struct {
	states      map[security.CheckID]string
	private     bool
	permissions string
	// rulesets lists active ruleset names; nil with rulesetsFail unset means none.
	rulesets     []string
	rulesetsFail bool
	// failWrites lists write requests answered with 403.
	failWrites map[string]bool
	// rejectWrites fails the test on any mutating request.
	rejectWrites bool
	runURL       string
	policy       string
	// afterRequest runs after each response is prepared, e.g. to cancel.
	afterRequest func(request string)
	requests     []string
}

func newEnableFixture(state string) *enableFixture {
	states := make(map[security.CheckID]string)
	for _, id := range []security.CheckID{
		security.LegacyProtection, security.PrivateReporting, security.PushProtection,
		security.DependabotAlerts, security.DependabotUpdates, security.CodeQLSetup,
	} {
		states[id] = state
	}
	return &enableFixture{
		states:      states,
		permissions: `{"admin":true,"maintain":false}`,
		failWrites:  map[string]bool{},
		policy:      `{"files":{}}`,
	}
}

// enableRun captures one command execution.
type enableRun struct {
	code   int
	out    string
	errOut string
	// unread is input left unconsumed by prompts.
	unread string
}

func (f *enableFixture) run(t *testing.T, ctx context.Context, args []string, input io.Reader, canPrompt bool) enableRun {
	t.Helper()
	t.Setenv("GH_CONFIG_DIR", t.TempDir())
	target := repository.Target{Host: "github.example.com", Owner: "owner", Name: "repo"}
	var out, errOut bytes.Buffer
	streams := ui.Streams{In: input, Out: &out, ErrOut: &errOut, CanPrompt: canPrompt}
	handler := NewEnableHandler(streams, func(_ context.Context, explicit string) (repository.Target, error) {
		if explicit != "" && explicit != "owner/repo" {
			t.Errorf("explicit repository lost: %q", explicit)
		}
		return target, nil
	}, func(got repository.Target) (EnablementClient, error) {
		client, err := github.NewClient(api.ClientOptions{
			Host: got.Host, AuthToken: "fixture-token", Transport: fixtureTransport{t: t, fixture: f},
		})
		if err != nil {
			return nil, err
		}
		return knownDisabledClient{Client: client, fixture: f}, nil
	})
	code := Execute(ctx, args, "dev", streams, Dependencies{Enable: handler})
	run := enableRun{code: code, out: out.String(), errOut: errOut.String()}
	if reader, ok := input.(*strings.Reader); ok {
		rest, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		run.unread = string(rest)
	}
	return run
}

// writes returns the mutating requests in the order they were sent.
func (f *enableFixture) writes() []string {
	writes := []string{}
	for _, request := range f.requests {
		if !strings.HasPrefix(request, http.MethodGet+" ") {
			writes = append(writes, request)
		}
	}
	return writes
}

// knownDisabledClient supplies a known-disabled inspection for the two settings
// whose ambiguous 404 the real adapter must report as unknown. This lets tests
// exercise orchestration and the real write requests for those settings; it is
// not evidence that any live response establishes a disabled state.
type knownDisabledClient struct {
	*github.Client
	fixture *enableFixture
}

// Inspect overrides only known-disabled legacy protection and Dependabot alerts.
func (c knownDisabledClient) Inspect(ctx context.Context, repo repository.Repository, id security.CheckID) security.Inspection {
	if (id == security.LegacyProtection || id == security.DependabotAlerts) && c.fixture.states[id] == "disabled" {
		return security.Inspection{State: security.Disabled}
	}
	return c.Client.Inspect(ctx, repo, id)
}

type fixtureTransport struct {
	t       *testing.T
	fixture *enableFixture
}

// RoundTrip records each request and serves fixture state or write responses.
func (tr fixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	f := tr.fixture
	key := request.Method + " " + request.URL.EscapedPath()
	f.requests = append(f.requests, key)
	if f.afterRequest != nil {
		defer f.afterRequest(key)
	}
	if request.URL.Host != "github.example.com" {
		tr.t.Errorf("request sent to wrong host: %s", request.URL.Host)
	}
	if request.Method != http.MethodGet && f.rejectWrites {
		tr.t.Errorf("dry run sent a write: %s", key)
		return nil, errors.New("fixture transport rejects writes")
	}
	status, body := tr.respond(request.Method, request.URL.EscapedPath())
	if status == 0 {
		tr.t.Errorf("unexpected request: %s", key)
		return nil, errors.New("unexpected request")
	}
	return &http.Response{
		StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: request,
	}, nil
}

func (tr fixtureTransport) respond(method, path string) (int, string) {
	f := tr.fixture
	notFound := `{"message":"Not Found"}`
	if method != http.MethodGet {
		if f.failWrites[method+" "+path] {
			return http.StatusForbidden, `{"message":"Resource not accessible by integration"}`
		}
		switch method + " " + path {
		case writeProtection:
			return http.StatusOK, `{"url":"https://github.example.com/api/v3/protection"}`
		case writePVR, writeAlerts, writeFixes:
			return http.StatusNoContent, ""
		case writePush:
			return http.StatusOK, `{"default_branch":"release/test","private":false,"security_and_analysis":{"secret_scanning_push_protection":{"status":"enabled"}}}`
		case writeCodeQL:
			return http.StatusAccepted, fmt.Sprintf(`{"run_id":42,"run_url":%q}`, f.runURL)
		}
		return 0, ""
	}
	state := func(id security.CheckID) string { return f.states[id] }
	switch path {
	case fixtureAPI:
		push := ""
		if state(security.PushProtection) != "unknown" {
			push = fmt.Sprintf(`,"security_and_analysis":{"secret_scanning_push_protection":{"status":%q}}`, state(security.PushProtection))
		}
		permissions := ""
		if f.permissions != "" {
			permissions = `,"permissions":` + f.permissions
		}
		return http.StatusOK, fmt.Sprintf(`{"default_branch":"release/test","private":%t%s%s}`, f.private, permissions, push)
	case protectionPath:
		if state(security.LegacyProtection) == "enabled" {
			return http.StatusOK, `{"url":"https://github.example.com/api/v3/protection"}`
		}
		return http.StatusNotFound, notFound
	case rulesetsPath:
		if f.rulesetsFail {
			return http.StatusForbidden, `{"message":"Forbidden"}`
		}
		rulesets := make([]map[string]any, len(f.rulesets))
		for index, name := range f.rulesets {
			rulesets[index] = map[string]any{"id": index + 1, "name": name, "enforcement": "active"}
		}
		body, err := json.Marshal(rulesets)
		if err != nil {
			tr.t.Fatal(err)
		}
		return http.StatusOK, string(body)
	case pvrPath:
		return enabledBoolean(state(security.PrivateReporting), `{"enabled":%t}`)
	case alertsPath:
		if state(security.DependabotAlerts) == "enabled" {
			return http.StatusNoContent, ""
		}
		return http.StatusNotFound, notFound
	case fixesPath:
		return enabledBoolean(state(security.DependabotUpdates), `{"enabled":%t,"paused":false}`)
	case codeQLPath:
		switch state(security.CodeQLSetup) {
		case "enabled":
			return http.StatusOK, `{"state":"configured"}`
		case "disabled":
			return http.StatusOK, `{"state":"not-configured"}`
		}
		return http.StatusNotFound, notFound
	case profilePath:
		if f.policy == "" {
			return http.StatusInternalServerError, `{"message":"Server Error"}`
		}
		return http.StatusOK, f.policy
	}
	return 0, ""
}

func enabledBoolean(state, format string) (int, string) {
	if state == "unknown" {
		return http.StatusNotFound, `{"message":"Not Found"}`
	}
	return http.StatusOK, fmt.Sprintf(format, state == "enabled")
}

// summaryOutcomes parses "  <feature> <outcome>" lines from the final summary.
func summaryOutcomes(t *testing.T, out string) map[string]string {
	t.Helper()
	_, summary, found := strings.Cut(out, "summary for github.example.com/owner/repo")
	if !found {
		t.Fatalf("missing summary: %q", out)
	}
	outcomes := make(map[string]string)
	for _, line := range strings.Split(summary, "\n") {
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		feature, outcome, _ := strings.Cut(strings.TrimSpace(line), " ")
		outcomes[feature] = strings.TrimSpace(outcome)
	}
	return outcomes
}

// allOutcomes expects the same outcome for every supported feature.
func allOutcomes(outcome string) map[string]string {
	var features []security.Feature
	for _, definition := range security.Features() {
		features = append(features, definition.Name)
	}
	return uniformOutcomes(outcome, features...)
}

// uniformOutcomes expects the same outcome for every listed feature.
func uniformOutcomes(outcome string, features ...security.Feature) map[string]string {
	outcomes := make(map[string]string, len(features))
	for _, feature := range features {
		outcomes[string(feature)] = outcome
	}
	return outcomes
}

// assertLines checks that each wanted line appears exactly as a line of out.
func assertLines(t *testing.T, out string, want []string) {
	t.Helper()
	lines := strings.Split(out, "\n")
	for _, line := range want {
		if !slices.Contains(lines, line) {
			t.Errorf("missing line %q in:\n%s", line, out)
		}
	}
}

// cancelingInput cancels the command when a prompt starts reading.
type cancelingInput struct {
	cancel context.CancelFunc
}

// Read cancels and reports that no answer arrived.
func (c cancelingInput) Read([]byte) (int, error) {
	c.cancel()
	return 0, context.Canceled
}
